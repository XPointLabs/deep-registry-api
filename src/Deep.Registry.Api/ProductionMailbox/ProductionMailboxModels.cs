using Deep.Protocol.DeepExtension.MailboxAuthority;

namespace Deep.Registry.Api.ProductionMailbox;

public sealed record ProductionMailboxChallengeResponse(
    string ChallengeId,
    string Challenge,
    int LeadingZeroBits,
    ulong ExpiresAtUnixSeconds);

public sealed record ProductionMailboxIssueRequest(
    string HolderEd25519PublicKey,
    string MailboxOwnerEd25519PublicKey,
    ProductionMailboxIssuanceIntent Intent,
    ProductionMailboxClientPlatform Platform,
    string SigningCertificateSha256,
    string BuildArtifactSha256,
    string IdempotencyKey,
    string EntitlementCommitment,
    string BlindedMailboxId,
    string BlindedPlacementId,
    string SelectionInputCommitment,
    string ChallengeId,
    string Challenge,
    ulong ProofOfWorkNonce,
    string HolderProofSignature,
    string? OwnerProofSignature = null,
    string? OpaqueEntitlement = null);

public sealed record ProductionMailboxArtifactReference(
    string FileName,
    string MediaType,
    string Sha256,
    string ETag,
    string ContentPath,
    string CanonicalBase64Url);

public sealed record ProductionMailboxReplicaEnvelope(
    string ReplicaId,
    string HttpsEndpoint,
    string CurrentSpkiSha256,
    string NextSpkiSha256);

public sealed record ProductionMailboxSelectionEnvelope(
    ulong Epoch,
    ulong Generation,
    string FileName,
    string MediaType,
    string Sha256,
    string CanonicalBase64Url,
    IReadOnlyList<ProductionMailboxReplicaEnvelope> Replicas);

public sealed record ProductionMailboxGrantEnvelope(
    string Domain,
    ulong Epoch,
    ulong Generation,
    string FileName,
    string MediaType,
    string Sha256,
    string CanonicalBase64Url);

public sealed record ProductionMailboxServiceLimits(
    ulong StoredBytes,
    uint StoredMessages,
    uint RetentionSeconds,
    uint RequestsPerHour,
    bool Entitled);

public sealed record ProductionMailboxCredentialBundle(
    string Schema,
    string IdempotencyKey,
    string HolderEd25519PublicKey,
    string MailboxOwnerEd25519PublicKey,
    ProductionMailboxIssuanceIntent Intent,
    string BlindedMailboxId,
    string BlindedPlacementId,
    string SelectionInputCommitment,
    ProductionMailboxArtifactReference Authority,
    ProductionMailboxArtifactReference Revocation,
    ProductionMailboxArtifactReference Topology,
    IReadOnlyList<ProductionMailboxSelectionEnvelope> Selections,
    IReadOnlyList<ProductionMailboxGrantEnvelope> Grants,
    ProductionMailboxServiceLimits Limits,
    ulong IssuedAtUnixSeconds,
    ulong ExpiresAtUnixSeconds);

public sealed record ProductionMailboxRuntimeCounters(
    long ChallengesCreated,
    long ChallengesRejected,
    long BundlesIssued,
    long BundlesReplayed,
    long RequestsRejected,
    long RevocationsApplied);

public sealed class ProductionMailboxMetrics
{
    private long challengesCreated;
    private long challengesRejected;
    private long bundlesIssued;
    private long bundlesReplayed;
    private long requestsRejected;
    private long revocationsApplied;

    public void ChallengeCreated() => Interlocked.Increment(ref challengesCreated);
    public void ChallengeRejected() => Interlocked.Increment(ref challengesRejected);
    public void BundleIssued() => Interlocked.Increment(ref bundlesIssued);
    public void BundleReplayed() => Interlocked.Increment(ref bundlesReplayed);
    public void RequestRejected() => Interlocked.Increment(ref requestsRejected);
    public void RevocationApplied() => Interlocked.Increment(ref revocationsApplied);
    public ProductionMailboxRuntimeCounters Snapshot() => new(
        Interlocked.Read(ref challengesCreated), Interlocked.Read(ref challengesRejected),
        Interlocked.Read(ref bundlesIssued), Interlocked.Read(ref bundlesReplayed),
        Interlocked.Read(ref requestsRejected), Interlocked.Read(ref revocationsApplied));
}
