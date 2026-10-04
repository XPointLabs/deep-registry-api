#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Registry.Api.DirectoryPublication;

// One actual service-observer proof/network/time path shared by grant issuance
// and revocation renewal. Neither a caller projection nor an unsigned manifest.
internal sealed class DeepIdV2MailboxAuthorityContextSource(
    DeepIdV2DirectoryProofIssuer proofs, DeepIdV2XPointAuthoritySource roots,
    XPointNetworkClosureDistribution distribution, IContactResolveTrustedTimeContextSource timeSource,
    ParsedDid2 observer)
{
    internal async ValueTask<T> WithCurrentAsync<T>(Func<DeepIdV2MailboxAuthorityContext, CancellationToken, ValueTask<T>> action,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(action); cancellationToken.ThrowIfCancellationRequested();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(30)); var ct = deadline.Token;
        if (!distribution.TryEnter()) throw new IOException("Mailbox authority is busy.");
        try
        {
            await proofs.RequireReadyAsync(ct).ConfigureAwait(false);
            var observed = await timeSource.ReadAsync(ct).ConfigureAwait(false); observed.Validate();
            var root = roots.Read();
            var challenge = new byte[32];
            do RandomNumberGenerator.Fill(challenge); while (challenge.AsSpan().IndexOfAnyExcept((byte)0) < 0);
            var proof = await proofs.IssueAsync(new DeepIdV2DirectoryProofRequest(root.NetworkId.Span, challenge,
                observed.ServerBootId.Span, observed.ServerMonotonicSample,
                // The internal proof request takes the map leaf, not the
                // ADL1 wire lookup preimage. Keep their domain separation.
                DeepIdV2AccountDirectoryCodec.ComputeDirectoryLeafKey(root.NetworkId.Span, observer)), ct).ConfigureAwait(false);
            var freshness = proof.Freshness;
            if (freshness.CurrentCheckpoint is null) throw new CryptographicException("Mailbox observer has no current checkpoint.");
            var frame = await distribution.ReadAsync(ct).ConfigureAwait(false);
            var raw = XPointNetworkClosureWireCodec.DecodeResponse(frame);
            var time = new OnionTrustedTimeAuthority(new CurrentClock(timeSource));
            var network = await OnionNetworkContextVerifier.VerifyAsync(root, freshness, raw.ExactNetworkPolicyChain,
                raw.ExactViewChain, raw.ExactHeadChain, raw.ExactActiveNodeDescriptors,
                raw.ExactPlacementTopologyChain, null, time, ct).ConfigureAwait(false);
            var pmt = ContactCodec.Decode("PMT2", raw.ExactPlacementTopologyChain[^1].Span);
            var selectedPolicy = raw.ExactMailboxAuthorityChain.Where(bytes => Fixed(
                ContactCodec.Decode("PMA2", bytes.Span).CoreHash.Span, pmt.Field(4).Span[6..])).ToArray();
            if (selectedPolicy.Length != 1) throw new CryptographicException("Mailbox requires one exact current PMA2.");
            var host = await MailboxHostAuthorityV2Verifier.VerifyAsync(network, root, selectedPolicy[0], time, ct).ConfigureAwait(false);
            var context = new DeepIdV2MailboxAuthorityContext(proofs, roots, distribution, timeSource,
                freshness, frame, raw.ExactViewChain[^1], root, network, selectedPolicy[0], time, host);
            await context.RequireCurrentAsync(ct).ConfigureAwait(false);
            var result = await action(context, ct).ConfigureAwait(false);
            await context.RequireCurrentAsync(ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested(); return result;
        }
        finally { distribution.Exit(); }
    }

    private sealed class CurrentClock(IContactResolveTrustedTimeContextSource source) : IOnionMonotonicClock
    {
        public async ValueTask<OnionMonotonicReading> ReadAsync(CancellationToken ct)
        { var now = await source.ReadAsync(ct).ConfigureAwait(false); now.Validate(); return new(now.ServerBootId.Span, now.ServerMonotonicSample); }
    }
    private static bool Fixed(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) => a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
}

// Retaining this object is not retaining a trust boolean. Every use rechecks the
// actual proof/floor, complete source bytes, protected clock and closed host.
internal sealed class DeepIdV2MailboxAuthorityContext
{
    private readonly DeepIdV2DirectoryProofIssuer proofs;
    private readonly DeepIdV2XPointAuthoritySource roots;
    private readonly XPointNetworkClosureDistribution distribution;
    private readonly IContactResolveTrustedTimeContextSource timeSource;
    private readonly VerifiedDeepIdV2DirectoryFreshness freshness;
    private readonly byte[] frame, view, pma;
    internal VerifiedXPointNetworkAuthority Root { get; }
    internal VerifiedOnionNetworkContext Network { get; }
    internal VerifiedMailboxHostAuthorityV2 Host { get; }
    internal OnionTrustedTimeAuthority Time { get; }
    internal ReadOnlyMemory<byte> ExactPolicy => pma.ToArray();

    internal DeepIdV2MailboxAuthorityContext(DeepIdV2DirectoryProofIssuer proofs, DeepIdV2XPointAuthoritySource roots,
        XPointNetworkClosureDistribution distribution, IContactResolveTrustedTimeContextSource timeSource,
        VerifiedDeepIdV2DirectoryFreshness freshness, byte[] frame, ReadOnlyMemory<byte> view,
        VerifiedXPointNetworkAuthority root, VerifiedOnionNetworkContext network, ReadOnlyMemory<byte> pma,
        OnionTrustedTimeAuthority time, VerifiedMailboxHostAuthorityV2 host)
    {
        this.proofs = proofs; this.roots = roots; this.distribution = distribution; this.timeSource = timeSource;
        this.freshness = freshness; this.frame = frame.ToArray(); this.view = view.ToArray(); this.pma = pma.ToArray();
        Root = root; Network = network; Host = host; Time = time;
    }

    internal async ValueTask RequireCurrentAsync(CancellationToken ct)
    {
        await proofs.RequireStillCurrentAsync(freshness, view, ct).ConfigureAwait(false);
        var root = roots.Read(); var current = await distribution.ReadAsync(ct).ConfigureAwait(false);
        if (!Fixed(Root.AuthorityCoreReference.Span, root.AuthorityCoreReference.Span) ||
            !Fixed(Root.Dts1PolicyCoreReference.Span, root.Dts1PolicyCoreReference.Span) ||
            !Fixed(Root.TimeSourcePolicyHash.Span, root.TimeSourcePolicyHash.Span) || !Fixed(frame, current))
            throw new CryptographicException("Mailbox authority sources changed before release.");
        await Host.EnsureCurrentAsync(ct).ConfigureAwait(false);
    }

    internal async ValueTask<(VerifiedMailboxAuthorityV2 Policy, ulong Lower, ulong Upper)> ReadIntervalAsync(CancellationToken ct)
    {
        await RequireCurrentAsync(ct).ConfigureAwait(false);
        var reading = await timeSource.ReadAsync(ct).ConfigureAwait(false); reading.Validate();
        if (!freshness.IsCurrentAtMonotonic(reading.ServerBootId.Span, reading.ServerMonotonicSample))
            throw new CryptographicException("Mailbox observer time expired.");
        var elapsed = checked(reading.ServerMonotonicSample - freshness.MonotonicSample);
        var lower = checked(freshness.TrustedLowerUnixSeconds + elapsed);
        var upper = checked(freshness.TrustedUpperUnixSeconds + elapsed);
        var policy = MailboxAuthorityV2Verifier.Verify(Root, pma, lower, upper);
        await RequireCurrentAsync(ct).ConfigureAwait(false);
        return (policy, lower, upper);
    }

    internal IMailboxGrantIssuerSigner GuardSigner(IMailboxGrantIssuerSigner signer) => new SourceCheckedSigner(this, signer);
    private sealed class SourceCheckedSigner(DeepIdV2MailboxAuthorityContext context, IMailboxGrantIssuerSigner signer) : IMailboxGrantIssuerSigner
    {
        public ReadOnlyMemory<byte> Ed25519PublicKey => signer.Ed25519PublicKey.ToArray();
        public async ValueTask<ReadOnlyMemory<byte>> SignAsync(ReadOnlyMemory<byte> bytes, CancellationToken ct)
        {
            await context.RequireCurrentAsync(ct).ConfigureAwait(false);
            var signature = await signer.SignAsync(bytes, ct).ConfigureAwait(false);
            await context.RequireCurrentAsync(ct).ConfigureAwait(false);
            return signature.ToArray();
        }
    }
    private static bool Fixed(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) => a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
}
#endif
