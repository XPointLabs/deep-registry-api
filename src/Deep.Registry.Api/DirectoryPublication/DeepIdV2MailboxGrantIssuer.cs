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

internal enum DeepIdV2MailboxGrantEvidenceKind : ushort
{
    CurrentRoute = 1,
    RetainedRead = 2
}

internal sealed class DeepIdV2MailboxGrantInput
{
    internal DeepIdV2MailboxGrantInput(ReadOnlySpan<byte> exactXmg, ReadOnlySpan<byte> exactRoute,
        DeepIdV2MailboxGrantEvidenceKind evidenceKind, ulong readUntil, ulong effectiveExpiry,
        IReadOnlyList<DeepIdV2MailboxGrantReplicaEvidence> evidence,
        ReadOnlySpan<byte> forwarder, ulong admissionTime, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> signature)
    {
        if (exactXmg.Length != 435 || exactRoute.Length is < ContactRouteClosureCodec.MinimumEncodedBytes or > ContactRouteClosureCodec.MaximumEncodedBytes ||
            evidence.Count != 2 || forwarder.Length != 32 || nonce.Length != 32 || signature.Length != 64)
            throw new ArgumentException("Private grant inputs exceed their exact bounds.");
        Request = ContactCodec.Decode("XMG2", exactXmg); Route = ContactRouteClosureCodec.Decode(exactRoute);
        if (evidenceKind is not (DeepIdV2MailboxGrantEvidenceKind.CurrentRoute or DeepIdV2MailboxGrantEvidenceKind.RetainedRead) ||
            (evidenceKind == DeepIdV2MailboxGrantEvidenceKind.CurrentRoute && (readUntil != 0 || effectiveExpiry == 0)) ||
            (evidenceKind == DeepIdV2MailboxGrantEvidenceKind.RetainedRead && (readUntil == 0 || effectiveExpiry != 0 || Request.Field(6).Span[0] != 2)))
            throw new ArgumentException("Private grant evidence kind/role/horizon fields differ.");
        EvidenceKind = evidenceKind; ReadUntil = readUntil;
        EffectiveExpiry = effectiveExpiry; Evidence = evidence.Select(item => new DeepIdV2MailboxGrantReplicaEvidence(item.NodeId.Span, item.Signature.Span)).ToArray();
        Forwarder = forwarder.ToArray(); AdmissionTime = admissionTime; Nonce = nonce.ToArray(); Signature = signature.ToArray();
    }
    internal ContactRecord Request { get; }
    internal ParsedContactRouteClosure Route { get; }
    internal DeepIdV2MailboxGrantEvidenceKind EvidenceKind { get; }
    internal ulong ReadUntil { get; }
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
    DeepIdV2MailboxAuthorityContextSource contexts,
    IDeepIdV2MailboxGrantJournal journal, IDeepIdV2MailboxGrantSignerCustody custody,
    DeepIdV2MailboxGrantReplayGuard replay)
{
    internal ValueTask<ReadOnlyMemory<byte>> IssueAsync(DeepIdV2MailboxGrantInput input, CancellationToken cancellationToken) =>
        contexts.WithCurrentAsync<ReadOnlyMemory<byte>>(async (context, ct) =>
        {
            var root = context.Root; var network = context.Network; var time = context.Time;
            if (!Fixed(root.NetworkId.Span, input.Request.Field(1).Span)) throw new CryptographicException("Private grant network differs.");
            Func<CancellationToken, ValueTask> requireIssuance;
            Func<IMailboxGrantIssuerSigner, CancellationToken, ValueTask<ReadOnlyMemory<byte>>> author;
            Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask> verify;
            MailboxCapabilityDomain domain;
            byte[] evidenceTuple;
            byte[] authBytes;
            // Both branches mint closed Protocol capabilities from the actual
            // current Registry context before admission or permanent reservation.
            switch (input.EvidenceKind)
            {
                case DeepIdV2MailboxGrantEvidenceKind.CurrentRoute:
                    var current = await DeepIdV2MailboxGrantIssuanceVerifier.VerifyAsync(network, root, context.ExactPolicy,
                        input.Request.CanonicalBytes, input.Route.ExactBytes, input.EffectiveExpiry, input.Evidence, time, ct).ConfigureAwait(false);
                    domain = current.Domain; requireIssuance = current.EnsureCurrentAsync;
                    author = current.AuthorSuccessAsync; verify = current.VerifySuccessAsync;
                    evidenceTuple = MailboxGrantRouteEvidenceAuthentication.CreateTuple(SHA256.HashData(input.Request.CanonicalBytes.Span),
                        input.Request.Field(3).Span, MailboxGrantCapabilityDigest.Compute(input.Request.Field(4).Span, domain),
                        (byte)domain, 1, input.Route.ExactHash.Span, input.EffectiveExpiry);
                    authBytes = MailboxGrantAuthorityAuthentication.GetSigningBytes(input.Request.CanonicalBytes.Span,
                        MailboxGrantAcquisitionResultCode.Success, input.Route.ExactBytes.Span,
                        U64(input.Request.Field(10).Span), input.Forwarder, input.AdmissionTime, input.Nonce);
                    break;
                case DeepIdV2MailboxGrantEvidenceKind.RetainedRead:
                    var retained = await context.Host.VerifyRetainedReadIssuanceAsync(input.Request.CanonicalBytes,
                        input.Route.ExactBytes, input.ReadUntil, input.Evidence, ct).ConfigureAwait(false);
                    domain = MailboxCapabilityDomain.Retrieve; requireIssuance = retained.EnsureCurrentAsync;
                    author = retained.AuthorSuccessAsync; verify = retained.VerifySuccessAsync;
                    evidenceTuple = MailboxRetainedReadEvidenceAuthentication.CreateTuple(SHA256.HashData(input.Request.CanonicalBytes.Span),
                        input.Request.Field(3).Span, MailboxGrantCapabilityDigest.Compute(input.Request.Field(4).Span, domain),
                        input.Route.ExactHash.Span, input.ReadUntil);
                    authBytes = MailboxRetainedReadAuthorityAuthentication.GetSigningBytes(input.Request.CanonicalBytes.Span,
                        input.Route.ExactBytes.Span, input.ReadUntil, U64(input.Request.Field(10).Span),
                        input.Forwarder, input.AdmissionTime, input.Nonce);
                    break;
                default: throw new CryptographicException("Unknown private grant evidence kind.");
            }
            var (policy, lower, upper) = await context.ReadIntervalAsync(ct).ConfigureAwait(false);
            var selectedStores = ContactServicePlacementFactory.Create(network, ContactServiceRequestKind.ResolveInvite, input.Request.Field(3));
            if (!selectedStores.RankedReplicaNodeIds.Any(id => Fixed(id.Span, input.Forwarder)) ||
                input.AdmissionTime > checked(upper + 60) || checked(input.AdmissionTime + 60) < lower ||
                !PublicKeyAuth.VerifyDetached(input.Signature, authBytes, network.ResolveNodeIdentityPublicKey(input.Forwarder).ToArray()) ||
                !replay.TryAccept(input.Forwarder, input.Nonce, lower, upper))
                throw new UnauthorizedAccessException("Private grant admission rejected.");
            var scopeHash = ScopeHash(input, evidenceTuple, policy, context);
            await context.RequireCurrentAsync(ct).ConfigureAwait(false);
            await requireIssuance(ct).ConfigureAwait(false);
            var winner = await journal.GetOrIssueAsync(input.Request.CanonicalBytes, scopeHash, async token =>
            {
                await context.RequireCurrentAsync(token).ConfigureAwait(false);
                await requireIssuance(token).ConfigureAwait(false);
                var exact = await author(context.GuardSigner(custody.Resolve(policy, domain)), token).ConfigureAwait(false);
                await verify(exact, token).ConfigureAwait(false);
                await context.RequireCurrentAsync(token).ConfigureAwait(false);
                await requireIssuance(token).ConfigureAwait(false);
                return exact;
            }, ct).ConfigureAwait(false);
            await verify(winner, ct).ConfigureAwait(false);
            await context.RequireCurrentAsync(ct).ConfigureAwait(false);
            await requireIssuance(ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested(); return winner;
        }, cancellationToken);
    private static byte[] ScopeHash(DeepIdV2MailboxGrantInput input, byte[] tuple,
        VerifiedMailboxAuthorityV2 policy, DeepIdV2MailboxAuthorityContext context)
    {
        Span<byte> kindAndHorizon = stackalloc byte[10];
        BinaryPrimitives.WriteUInt16BigEndian(kindAndHorizon, (ushort)input.EvidenceKind);
        BinaryPrimitives.WriteUInt64BigEndian(kindAndHorizon[2..], input.ReadUntil);
        return SHA256.HashData([.. "Deep/Registry/DID2/grant-journal-scope"u8, 0, .. kindAndHorizon,
            .. tuple, .. policy.CoreHash.Span, .. context.Root.AuthorityCoreReference.Span,
            .. context.Root.Dts1PolicyCoreReference.Span, .. context.Root.TimeSourcePolicyHash.Span,
            .. SHA256.HashData(OnionNetworkProtectedHistoryCodec.Encode(context.Network))]);
    }
    private static bool Fixed(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) => a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
    private static ulong U64(ReadOnlySpan<byte> value) => BinaryPrimitives.ReadUInt64BigEndian(value);
}
#endif
