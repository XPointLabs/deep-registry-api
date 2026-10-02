#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Registry.Api.DirectoryPublication;

internal sealed class DeepIdV2MailboxGrantInput
{
    internal DeepIdV2MailboxGrantInput(ReadOnlySpan<byte> exactXmg, ReadOnlySpan<byte> exactRoute,
        ulong effectiveExpiry, IReadOnlyList<DeepIdV2MailboxGrantReplicaEvidence> evidence,
        ReadOnlySpan<byte> forwarder, ulong admissionTime, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> signature)
    {
        if (exactXmg.Length != 435 || exactRoute.Length is < ContactRouteClosureCodec.MinimumEncodedBytes or > ContactRouteClosureCodec.MaximumEncodedBytes ||
            evidence.Count != 2 || forwarder.Length != 32 || nonce.Length != 32 || signature.Length != 64)
            throw new ArgumentException("Private grant inputs exceed their exact bounds.");
        Request = ContactCodec.Decode("XMG1", exactXmg); Route = ContactRouteClosureCodec.Decode(exactRoute);
        EffectiveExpiry = effectiveExpiry; Evidence = evidence.Select(item => new DeepIdV2MailboxGrantReplicaEvidence(item.NodeId.Span, item.Signature.Span)).ToArray();
        Forwarder = forwarder.ToArray(); AdmissionTime = admissionTime; Nonce = nonce.ToArray(); Signature = signature.ToArray();
    }
    internal ContactRecord Request { get; }
    internal ParsedContactRouteClosure Route { get; }
    internal ulong EffectiveExpiry { get; }
    internal DeepIdV2MailboxGrantReplicaEvidence[] Evidence { get; }
    internal byte[] Forwarder { get; }
    internal ulong AdmissionTime { get; }
    internal byte[] Nonce { get; }
    internal byte[] Signature { get; }
}

internal interface IDeepIdV2MailboxGrantSignerCustody
{
    IMailboxGrantIssuerSigner Resolve(VerifiedMailboxAuthorityV2 authority, MailboxCapabilityDomain domain);
}

internal sealed class DeepIdV2MailboxGrantReplayGuard
{
    private readonly object gate = new();
    private readonly Dictionary<string, ulong> accepted = new(StringComparer.Ordinal);
    internal bool TryAccept(ReadOnlySpan<byte> forwarder, ReadOnlySpan<byte> nonce, ulong lower, ulong upper)
    {
        lock (gate)
        {
            foreach (var item in accepted.Where(item => item.Value <= lower).ToArray()) accepted.Remove(item.Key);
            if (accepted.Count >= 4_096) return false;
            return accepted.TryAdd(Convert.ToHexString(forwarder) + Convert.ToHexString(nonce), checked(upper + 180));
        }
    }
}

internal sealed class DeepIdV2MailboxGrantIssuer(
    DeepIdV2DirectoryProofIssuer proofs, DeepIdV2XPointAuthoritySource roots,
    XPointNetworkClosureDistribution distribution, IContactResolveTrustedTimeContextSource timeSource,
    IDeepIdV2MailboxGrantJournal journal, IDeepIdV2MailboxGrantSignerCustody custody,
    DeepIdV2MailboxGrantReplayGuard replay, ParsedDid2 observer)
{
    internal async ValueTask<ReadOnlyMemory<byte>> IssueAsync(DeepIdV2MailboxGrantInput input, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(30)); var ct = timeout.Token;
        if (!distribution.TryEnter()) throw new IOException("Private grant authority is busy.");
        try
        {
            await proofs.RequireReadyAsync(ct).ConfigureAwait(false);
            var observed = await timeSource.ReadAsync(ct).ConfigureAwait(false); observed.Validate();
            var root = roots.Read();
            if (!Fixed(root.NetworkId.Span, input.Request.Field(1).Span)) throw new CryptographicException("Private grant network differs.");
            var challenge = new byte[32]; do RandomNumberGenerator.Fill(challenge); while (challenge.AsSpan().IndexOfAnyExcept((byte)0) < 0);
            // Operator-configured public service observer, never a caller/recipient query.
            var proof = await proofs.IssueAsync(new DeepIdV2DirectoryProofRequest(root.NetworkId.Span, challenge,
                observed.ServerBootId.Span, observed.ServerMonotonicSample,
                DeepIdV2AccountDirectoryCodec.ComputeDirectoryLookupKey(root.NetworkId.Span, observer)), ct).ConfigureAwait(false);
            var freshness = proof.Freshness;
            if (freshness.CurrentCheckpoint is null) throw new CryptographicException("Private grant observer has no current checkpoint.");
            var frame = await distribution.ReadAsync(ct).ConfigureAwait(false);
            var raw = XPointNetworkClosureWireCodec.DecodeResponse(frame);
            var time = new OnionTrustedTimeAuthority(new CurrentClock(timeSource));
            var network = await OnionNetworkContextVerifier.VerifyAsync(root, freshness, raw.ExactNetworkPolicyChain,
                raw.ExactViewChain, raw.ExactHeadChain, raw.ExactActiveNodeDescriptors,
                raw.ExactPlacementTopologyChain, null, time, ct).ConfigureAwait(false);
            var pmt = ContactCodec.Decode("PMT2", raw.ExactPlacementTopologyChain[^1].Span);
            var selectedPolicy = raw.ExactMailboxAuthorityChain.Where(bytes => Fixed(
                ContactCodec.Decode("PMA2", bytes.Span).CoreHash.Span,
                pmt.Field(4).Span[6..])).ToArray();
            if (selectedPolicy.Length != 1) throw new CryptographicException("Private grant requires one exact current PMA2.");
            var issuance = await DeepIdV2MailboxGrantIssuanceVerifier.VerifyAsync(network, root, selectedPolicy[0],
                input.Request.CanonicalBytes, input.Route.ExactBytes, input.EffectiveExpiry, input.Evidence, time, ct).ConfigureAwait(false);
            var clock = await timeSource.ReadAsync(ct).ConfigureAwait(false); clock.Validate();
            if (!freshness.IsCurrentAtMonotonic(clock.ServerBootId.Span, clock.ServerMonotonicSample))
                throw new CryptographicException("Private grant observer time expired.");
            var elapsed = checked(clock.ServerMonotonicSample - freshness.MonotonicSample);
            var lower = checked(freshness.TrustedLowerUnixSeconds + elapsed);
            var upper = checked(freshness.TrustedUpperUnixSeconds + elapsed);
            var selectedStores = ContactServicePlacementFactory.Create(network, ContactServiceRequestKind.ResolveInvite, input.Request.Field(3));
            var authBytes = MailboxGrantAuthorityAuthentication.GetSigningBytes(input.Request.CanonicalBytes.Span,
                MailboxGrantAcquisitionResultCode.Success, input.Route.ExactBytes.Span,
                U64(input.Request.Field(10).Span), input.Forwarder, input.AdmissionTime, input.Nonce);
            if (!selectedStores.RankedReplicaNodeIds.Any(id => Fixed(id.Span, input.Forwarder)) ||
                input.AdmissionTime > checked(upper + 60) || checked(input.AdmissionTime + 60) < lower ||
                !PublicKeyAuth.VerifyDetached(input.Signature, authBytes, network.ResolveNodeIdentityPublicKey(input.Forwarder).ToArray()) ||
                !replay.TryAccept(input.Forwarder, input.Nonce, lower, upper))
                throw new UnauthorizedAccessException("Private grant admission rejected.");
            var policy = MailboxAuthorityV2Verifier.Verify(root, selectedPolicy[0].Span, lower, upper);
            var evidenceTuple = MailboxGrantRouteEvidenceAuthentication.CreateTuple(SHA256.HashData(input.Request.CanonicalBytes.Span),
                input.Request.Field(3).Span, MailboxGrantCapabilityDigest.Compute(input.Request.Field(4).Span, issuance.Domain),
                (byte)issuance.Domain, 1, input.Route.ExactHash.Span, input.EffectiveExpiry);
            var scopeHash = SHA256.HashData([.. "Deep/Registry/DID2/grant-journal-scope"u8, 0, .. evidenceTuple, .. policy.CoreHash.Span]);
            await RequireSourcesAsync(freshness, frame, raw.ExactViewChain[^1], root, issuance, ct).ConfigureAwait(false);
            var winner = await journal.GetOrIssueAsync(input.Request.CanonicalBytes, scopeHash, async token =>
            {
                await RequireSourcesAsync(freshness, frame, raw.ExactViewChain[^1], root, issuance, token).ConfigureAwait(false);
                var exact = await issuance.AuthorSuccessAsync(custody.Resolve(policy, issuance.Domain), token).ConfigureAwait(false);
                await issuance.VerifySuccessAsync(exact, token).ConfigureAwait(false);
                await RequireSourcesAsync(freshness, frame, raw.ExactViewChain[^1], root, issuance, token).ConfigureAwait(false);
                return exact;
            }, ct).ConfigureAwait(false);
            await issuance.VerifySuccessAsync(winner, ct).ConfigureAwait(false);
            await RequireSourcesAsync(freshness, frame, raw.ExactViewChain[^1], root, issuance, ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested(); return winner;
        }
        finally { distribution.Exit(); }
    }

    private async ValueTask RequireSourcesAsync(VerifiedDeepIdV2DirectoryFreshness proof, byte[] frame,
        ReadOnlyMemory<byte> view, VerifiedXPointNetworkAuthority root, VerifiedDeepIdV2MailboxGrantIssuance issuance, CancellationToken ct)
    {
        await proofs.RequireStillCurrentAsync(proof, view, ct).ConfigureAwait(false);
        var currentRoot = roots.Read();
        var currentFrame = await distribution.ReadAsync(ct).ConfigureAwait(false);
        if (!Fixed(root.AuthorityCoreReference.Span, currentRoot.AuthorityCoreReference.Span) ||
            !Fixed(root.Dts1PolicyCoreReference.Span, currentRoot.Dts1PolicyCoreReference.Span) ||
            !Fixed(root.TimeSourcePolicyHash.Span, currentRoot.TimeSourcePolicyHash.Span) ||
            !Fixed(frame, currentFrame))
            throw new CryptographicException("Private grant sources changed before release.");
        await issuance.EnsureCurrentAsync(ct).ConfigureAwait(false);
    }
    private sealed class CurrentClock(IContactResolveTrustedTimeContextSource source) : IOnionMonotonicClock
    {
        public async ValueTask<OnionMonotonicReading> ReadAsync(CancellationToken ct)
        { var now = await source.ReadAsync(ct).ConfigureAwait(false); now.Validate(); return new(now.ServerBootId.Span, now.ServerMonotonicSample); }
    }
    private static bool Fixed(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) => a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
    private static ulong U64(ReadOnlySpan<byte> value) => BinaryPrimitives.ReadUInt64BigEndian(value);
}
#endif
