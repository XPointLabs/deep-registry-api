using System.Data;
using System.Text.Json;
using Npgsql;

namespace Deep.Registry.Api.ProductionMailbox;

public sealed record ProductionMailboxChallengeState(
    byte[] ChallengeId,
    byte[] Challenge,
    byte[] ArtifactClosureHash,
    ulong ExpiresAtUnixSeconds);

public sealed record ProductionMailboxIssuanceState(
    byte[] IdempotencyKey,
    byte[] CanonicalResponse,
    bool Replayed);

public sealed record ProductionMailboxRouteEnrollmentState(
    byte[] IdempotencyKey,
    byte[] CanonicalResponse,
    bool Replayed);

public enum ProductionMailboxIssueCommitStatus
{
    Accepted,
    Replayed,
    InvalidChallenge,
    EnrollmentMismatch,
    AdvertisementRollback,
    AdvertisementConflict,
    IssuanceConflict,
    PromotionInProgress
}

public sealed record ProductionMailboxIssueCommitResult(
    ProductionMailboxIssueCommitStatus Status,
    byte[]? CanonicalResponse);

public sealed record ProductionMailboxPreparedIssue(
    byte[] CanonicalResponse,
    byte[] OwnerRouteStateKey,
    byte[] PublicationStateKey,
    IReadOnlyList<ProductionMailboxPublicationItem> PublicationItems);

public sealed record ProductionMailboxPublicationItem(
    byte[] TargetStateKey,
    byte[] TargetReplicaId,
    string Endpoint,
    byte[] CurrentSpkiSha256,
    byte[] NextSpkiSha256,
    IReadOnlyList<byte[]> AuthorizedLegacyReplicaIds,
    byte[] CanonicalEnvelope,
    byte[] EnvelopeSha256,
    byte[] ReservationCohortId,
    byte[]? LastAttemptSha256 = null,
    ulong? LastAttemptAtUnixSeconds = null,
    bool Acknowledged = false);

public sealed record ProductionMailboxPublicationState(
    byte[] PublicationStateKey,
    byte[] CanonicalResponseSha256,
    IReadOnlyList<ProductionMailboxPublicationItem> Items,
    bool Completed);

public sealed record ProductionMailboxOwnerBundleRecord(
    long Sequence,
    byte[] RouteStateKey,
    byte[] CanonicalBundle);

public sealed record ProductionMailboxArtifactPromotionState(
    byte[] PromotionStateKey,
    byte[] OldArtifactClosureHash,
    byte[] NewArtifactClosureHash,
    long OwnerWatermark,
    long Cursor,
    bool SweepCompleted,
    bool Published,
    bool CapacityReleaseCompleted);

public sealed record ProductionMailboxCapacityTargetState(
    byte[] TargetReplicaId,
    string Endpoint,
    byte[] CurrentSpkiSha256,
    byte[] NextSpkiSha256,
    uint ReservedClosureCount,
    ulong ReservedBytes,
    ulong Revision,
    ulong? ReceiptExpiresAtUnixSeconds,
    byte[]? LastCommandSha256,
    byte[]? CanonicalReceipt,
    byte[]? PendingCanonicalCommand,
    ulong? PendingRevision,
    bool Released);

public sealed record ProductionMailboxCapacityPlanState(
    byte[] PromotionStateKey,
    long Cursor,
    bool Completed,
    IReadOnlyList<ProductionMailboxCapacityTargetState> Targets);

internal static class ProductionMailboxCapacityRevisionPolicy
{
    internal const ulong MaximumStoredRevision = (ulong)long.MaxValue;

    internal static bool CanIssueSuccessor(
        ulong currentRevision,
        ProductionMailboxCapacityOperation operation) => operation switch
    {
        ProductionMailboxCapacityOperation.ReserveOrRenew =>
            currentRevision < MaximumStoredRevision - 1,
        ProductionMailboxCapacityOperation.Release =>
            currentRevision < MaximumStoredRevision,
        _ => false
    };

    internal static bool IsStorableReceipt(
        ProductionMailboxCapacityReceipt receipt) =>
        receipt.Revision <= MaximumStoredRevision
        && (receipt.Operation == ProductionMailboxCapacityOperation.Release
            || receipt.Revision < MaximumStoredRevision);
}

public enum ProductionMailboxRouteAdvertisementAcceptance
{
    Accepted,
    ExactReplay,
    Rollback,
    Conflict
}

public interface IProductionMailboxStateStore
{
    ValueTask<ProductionMailboxChallengeState?> CreateChallengeAsync(
        ulong nowUnixSeconds,
        ulong expiresAtUnixSeconds,
        ReadOnlyMemory<byte> artifactClosureHash,
        int maximumChallenges,
        ulong windowStartUnixSeconds,
        CancellationToken cancellationToken);

    ValueTask<ProductionMailboxIssuanceState?> ConsumeChallengeAndIssueAsync(
        ReadOnlyMemory<byte> challengeId,
        ReadOnlyMemory<byte> expectedChallenge,
        ulong nowUnixSeconds,
        ulong issuanceExpiresAtUnixSeconds,
        ReadOnlyMemory<byte> expectedArtifactClosureHash,
        ReadOnlyMemory<byte> idempotencyKey,
        Func<CancellationToken, ValueTask<byte[]>> createCanonicalResponse,
        CancellationToken cancellationToken);

    ValueTask<ProductionMailboxRouteEnrollmentState?> ConsumeChallengeAndEnrollAsync(
        ReadOnlyMemory<byte> challengeId,
        ReadOnlyMemory<byte> expectedChallenge,
        ulong nowUnixSeconds,
        ulong enrollmentExpiresAtUnixSeconds,
        ReadOnlyMemory<byte> expectedArtifactClosureHash,
        ReadOnlyMemory<byte> enrollmentStateKey,
        ReadOnlyMemory<byte> idempotencyKey,
        Func<CancellationToken, ValueTask<byte[]>> createCanonicalResponse,
        CancellationToken cancellationToken);

    ValueTask<byte[]?> GetRouteEnrollmentAsync(
        ReadOnlyMemory<byte> enrollmentStateKey,
        CancellationToken cancellationToken);

    ValueTask<ProductionMailboxIssueCommitResult> ConsumeChallengeAcceptAdvertisementAndIssueAsync(
        ReadOnlyMemory<byte> challengeId,
        ReadOnlyMemory<byte> expectedChallenge,
        ulong nowUnixSeconds,
        ulong issuanceExpiresAtUnixSeconds,
        ReadOnlyMemory<byte> expectedArtifactClosureHash,
        ReadOnlyMemory<byte> idempotencyKey,
        ReadOnlyMemory<byte> requiredEnrollmentStateKey,
        ReadOnlyMemory<byte> routeDomainHash,
        ulong advertisementSequence,
        ReadOnlyMemory<byte> advertisementHash,
        Func<CancellationToken, ValueTask<ProductionMailboxPreparedIssue>> createPreparedIssue,
        CancellationToken cancellationToken);

    ValueTask<ProductionMailboxPublicationState> PreparePublicationAsync(
        ReadOnlyMemory<byte> publicationStateKey,
        ReadOnlyMemory<byte> canonicalResponseSha256,
        IReadOnlyList<ProductionMailboxPublicationItem> items,
        CancellationToken cancellationToken);

    ValueTask<ProductionMailboxPublicationState?> GetPublicationAsync(
        ReadOnlyMemory<byte> publicationStateKey,
        CancellationToken cancellationToken);

    ValueTask<IReadOnlyList<byte[]>> ListPendingPublicationKeysAsync(
        int maximumCount,
        CancellationToken cancellationToken);

    ValueTask<bool> RecordPublicationAttemptAsync(
        ReadOnlyMemory<byte> publicationStateKey,
        ReadOnlyMemory<byte> targetStateKey,
        ReadOnlyMemory<byte> envelopeSha256,
        ReadOnlyMemory<byte> attemptSha256,
        ulong attemptedAtUnixSeconds,
        CancellationToken cancellationToken);

    ValueTask<bool> AcknowledgePublicationAsync(
        ReadOnlyMemory<byte> publicationStateKey,
        ReadOnlyMemory<byte> targetStateKey,
        ReadOnlyMemory<byte> envelopeSha256,
        ReadOnlyMemory<byte> attemptSha256,
        CancellationToken cancellationToken);

    ValueTask<ProductionMailboxArtifactPromotionState> BeginArtifactPromotionAsync(
        ReadOnlyMemory<byte> promotionStateKey,
        ReadOnlyMemory<byte> oldArtifactClosureHash,
        ReadOnlyMemory<byte> newArtifactClosureHash,
        CancellationToken cancellationToken);
    ValueTask<ProductionMailboxArtifactPromotionState?> GetArtifactPromotionAsync(
        ReadOnlyMemory<byte> promotionStateKey,
        CancellationToken cancellationToken);
    ValueTask<ProductionMailboxArtifactPromotionState?> GetActiveArtifactPromotionAsync(
        CancellationToken cancellationToken);
    ValueTask<byte[]> GetOrInitializePublishedArtifactClosureAsync(
        ReadOnlyMemory<byte> initialArtifactClosureHash,
        CancellationToken cancellationToken);
    ValueTask<IReadOnlyList<ProductionMailboxOwnerBundleRecord>>
        ListOwnerBundlesForPromotionAsync(
            ReadOnlyMemory<byte> promotionStateKey,
            int maximumCount,
            CancellationToken cancellationToken);
    ValueTask<IReadOnlyList<ProductionMailboxOwnerBundleRecord>>
        ListOwnerBundlesForCapacityPlanningAsync(
            ReadOnlyMemory<byte> promotionStateKey,
            int maximumCount,
            CancellationToken cancellationToken);
    ValueTask<bool> CommitCapacityPlannedOwnerAsync(
        ReadOnlyMemory<byte> promotionStateKey,
        ProductionMailboxOwnerBundleRecord expectedOwner,
        IReadOnlyList<ProductionMailboxPublicationItem> publicationItems,
        ulong perScheduleOverheadBytes,
        CancellationToken cancellationToken);
    ValueTask<bool> CompleteCapacityPlanAsync(
        ReadOnlyMemory<byte> promotionStateKey,
        CancellationToken cancellationToken);
    ValueTask<ProductionMailboxCapacityPlanState?> GetCapacityPlanAsync(
        ReadOnlyMemory<byte> promotionStateKey,
        CancellationToken cancellationToken);
    ValueTask<bool> RecordCapacityReceiptAsync(
        ReadOnlyMemory<byte> promotionStateKey,
        ReadOnlyMemory<byte> targetReplicaId,
        ulong expectedPreviousRevision,
        ProductionMailboxCapacityReceipt receipt,
        ReadOnlyMemory<byte> canonicalReceipt,
        CancellationToken cancellationToken);
    ValueTask<bool> RecordCapacityReconciliationReceiptAsync(
        ReadOnlyMemory<byte> promotionStateKey,
        ReadOnlyMemory<byte> targetReplicaId,
        ulong expectedRevision,
        ReadOnlyMemory<byte> expectedPendingReleaseCommand,
        ProductionMailboxCapacityReconciliationReceipt receipt,
        ReadOnlyMemory<byte> canonicalReceipt,
        CancellationToken cancellationToken);
    ValueTask<byte[]?> GetOrRecordCapacityAttemptAsync(
        ReadOnlyMemory<byte> promotionStateKey,
        ReadOnlyMemory<byte> targetReplicaId,
        ulong expectedPreviousRevision,
        ulong attemptRevision,
        ReadOnlyMemory<byte> canonicalCommand,
        CancellationToken cancellationToken);
    ValueTask<bool> CommitPromotedOwnerAsync(
        ReadOnlyMemory<byte> promotionStateKey,
        ProductionMailboxOwnerBundleRecord expectedOwner,
        ProductionMailboxPreparedIssue preparedIssue,
        ulong updatedAtUnixSeconds,
        uint capacityRenewalMarginSeconds,
        CancellationToken cancellationToken);
    ValueTask<bool> CompleteArtifactPromotionSweepAsync(
        ReadOnlyMemory<byte> promotionStateKey,
        CancellationToken cancellationToken);
    ValueTask<bool> MarkArtifactPromotionPublishedAsync(
        ReadOnlyMemory<byte> promotionStateKey,
        CancellationToken cancellationToken);
    ValueTask<bool> MarkArtifactPromotionCapacityReleasedAsync(
        ReadOnlyMemory<byte> promotionStateKey,
        CancellationToken cancellationToken);

    ValueTask<bool> IsHolderRevokedAsync(ReadOnlyMemory<byte> holderHash, CancellationToken cancellationToken);
    ValueTask RevokeHolderAsync(ReadOnlyMemory<byte> holderHash, ulong nowUnixSeconds, CancellationToken cancellationToken);
    ValueTask<ProductionMailboxRouteAdvertisementAcceptance> AcceptRouteAdvertisementAsync(
        ReadOnlyMemory<byte> routeDomainHash,
        ulong sequence,
        ReadOnlyMemory<byte> advertisementHash,
        CancellationToken cancellationToken);
    ValueTask<byte[]?> GetLatestOwnerBundleAsync(
        ReadOnlyMemory<byte> routeStateKey,
        CancellationToken cancellationToken);
    ValueTask StoreLatestOwnerBundleAsync(
        ReadOnlyMemory<byte> routeStateKey,
        ReadOnlyMemory<byte> canonicalBundle,
        ulong updatedAtUnixSeconds,
        CancellationToken cancellationToken);
}

public sealed partial class InMemoryProductionMailboxStateStore : IProductionMailboxStateStore,
    IProductionMailboxRouteContinuityStateStore
{
    private readonly TimeProvider timeProvider;
    private int throwAfterIssueCommitOnce;
    private int throwAfterPromotedOwnerCommitOnce;
    private int throwBeforePromotionPublishedOnce;
    private int throwBeforeCapacityReleasedOnce;
    private readonly SemaphoreSlim gate = new(1, 1);
    private readonly Dictionary<string, ChallengeRecord> challenges = new(StringComparer.Ordinal);
    private readonly Dictionary<string, IssuanceRecord> issuances = new(StringComparer.Ordinal);
    private readonly Dictionary<string, EnrollmentRecord> enrollmentsByIdempotency =
        new(StringComparer.Ordinal);
    private readonly Dictionary<string, EnrollmentRecord> enrollmentsByStateKey =
        new(StringComparer.Ordinal);
    private readonly HashSet<string> revokedHolders = new(StringComparer.Ordinal);
    private readonly Dictionary<string, RouteAdvertisementRecord> routeAdvertisements =
        new(StringComparer.Ordinal);
    private readonly Dictionary<string, MutableOwnerBundleRecord> ownerBundles = new(StringComparer.Ordinal);
    private readonly Dictionary<string, PublicationRecord> publications =
        new(StringComparer.Ordinal);
    private readonly Dictionary<string, MutablePromotionRecord> promotions =
        new(StringComparer.Ordinal);
    private byte[]? publishedArtifactClosureHash;
    private readonly List<ulong> challengeTimes = [];
    private long nextOwnerSequence;

    public InMemoryProductionMailboxStateStore(TimeProvider? timeProvider = null) =>
        this.timeProvider = timeProvider ?? TimeProvider.System;

    internal IReadOnlyList<byte[]> SnapshotOwnerRouteStateKeys() =>
        ownerBundles.Keys.Select(Convert.FromHexString).ToArray();

    internal IReadOnlyList<byte[]> SnapshotAdvertisementStateKeys() =>
        routeAdvertisements.Keys.Select(Convert.FromHexString).ToArray();

    internal bool ThrowAfterIssueCommitOnce
    {
        set => Interlocked.Exchange(ref throwAfterIssueCommitOnce, value ? 1 : 0);
    }

    internal bool ThrowAfterPromotedOwnerCommitOnce
    {
        set => Interlocked.Exchange(ref throwAfterPromotedOwnerCommitOnce, value ? 1 : 0);
    }

    internal bool ThrowBeforePromotionPublishedOnce
    {
        set => Interlocked.Exchange(ref throwBeforePromotionPublishedOnce, value ? 1 : 0);
    }

    internal bool ThrowBeforeCapacityReleasedOnce
    {
        set => Interlocked.Exchange(ref throwBeforeCapacityReleasedOnce, value ? 1 : 0);
    }

    internal Action? AfterPromotionPublishedForTests { get; set; }

    public async ValueTask<ProductionMailboxChallengeState?> CreateChallengeAsync(
        ulong nowUnixSeconds, ulong expiresAtUnixSeconds,
        ReadOnlyMemory<byte> artifactClosureHash, int maximumChallenges,
        ulong windowStartUnixSeconds, CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try
        {
            challengeTimes.RemoveAll(value => value < windowStartUnixSeconds);
            if (challengeTimes.Count >= maximumChallenges) return null;
            var id = System.Security.Cryptography.RandomNumberGenerator.GetBytes(16);
            var challenge = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
            challenges[Convert.ToHexString(id)] = new ChallengeRecord(
                challenge, artifactClosureHash.ToArray(), expiresAtUnixSeconds, false);
            challengeTimes.Add(nowUnixSeconds);
            return new(id, challenge, artifactClosureHash.ToArray(), expiresAtUnixSeconds);
        }
        finally { gate.Release(); }
    }

    public async ValueTask<ProductionMailboxIssuanceState?> ConsumeChallengeAndIssueAsync(
        ReadOnlyMemory<byte> challengeId, ReadOnlyMemory<byte> expectedChallenge,
        ulong nowUnixSeconds, ulong issuanceExpiresAtUnixSeconds,
        ReadOnlyMemory<byte> expectedArtifactClosureHash, ReadOnlyMemory<byte> idempotencyKey,
        Func<CancellationToken, ValueTask<byte[]>> createCanonicalResponse,
        CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try
        {
            var challengeKey = Convert.ToHexString(challengeId.Span);
            if (!challenges.TryGetValue(challengeKey, out var challenge) || challenge.Used ||
                challenge.ExpiresAtUnixSeconds < nowUnixSeconds ||
                !System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(
                    challenge.ArtifactClosureHash, expectedArtifactClosureHash.Span) ||
                !System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(
                    challenge.Challenge, expectedChallenge.Span)) return null;
            challenges[challengeKey] = challenge with { Used = true };
            var key = Convert.ToHexString(idempotencyKey.Span);
            if (issuances.TryGetValue(key, out var existing) && existing.ExpiresAtUnixSeconds >= nowUnixSeconds)
                return new(idempotencyKey.ToArray(), existing.Response.ToArray(), true);
            var created = await createCanonicalResponse(cancellationToken);
            issuances[key] = new(created.ToArray(), issuanceExpiresAtUnixSeconds);
            return new(idempotencyKey.ToArray(), created, false);
        }
        finally { gate.Release(); }
    }

    public async ValueTask<ProductionMailboxRouteEnrollmentState?> ConsumeChallengeAndEnrollAsync(
        ReadOnlyMemory<byte> challengeId, ReadOnlyMemory<byte> expectedChallenge,
        ulong nowUnixSeconds, ulong enrollmentExpiresAtUnixSeconds,
        ReadOnlyMemory<byte> expectedArtifactClosureHash,
        ReadOnlyMemory<byte> enrollmentStateKey, ReadOnlyMemory<byte> idempotencyKey,
        Func<CancellationToken, ValueTask<byte[]>> createCanonicalResponse,
        CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try
        {
            if (promotions.Values.Any(static promotion => !promotion.Published))
                return null;
            if (!TryGetLiveChallenge(challengeId, expectedChallenge, nowUnixSeconds,
                    expectedArtifactClosureHash, out var challengeKey, out var challenge))
                return null;
            var idempotency = Convert.ToHexString(idempotencyKey.Span);
            var stateKey = Convert.ToHexString(enrollmentStateKey.Span);
            if (enrollmentsByIdempotency.TryGetValue(idempotency, out var existing)
                && existing.ExpiresAtUnixSeconds >= nowUnixSeconds)
            {
                if (!CryptographicEqual(existing.StateKey, enrollmentStateKey.Span))
                    return null;
                challenges[challengeKey] = challenge with { Used = true };
                return new(idempotencyKey.ToArray(), existing.Response.ToArray(), true);
            }
            if (enrollmentsByStateKey.TryGetValue(stateKey, out var collision)
                && !CryptographicEqual(collision.IdempotencyKey, idempotencyKey.Span))
                return null;
            var created = await createCanonicalResponse(cancellationToken);
            var record = new EnrollmentRecord(
                enrollmentStateKey.ToArray(), idempotencyKey.ToArray(), created.ToArray(),
                enrollmentExpiresAtUnixSeconds);
            enrollmentsByIdempotency[idempotency] = record;
            enrollmentsByStateKey[stateKey] = record;
            challenges[challengeKey] = challenge with { Used = true };
            return new(idempotencyKey.ToArray(), created, false);
        }
        finally { gate.Release(); }
    }

    public async ValueTask<byte[]?> GetRouteEnrollmentAsync(
        ReadOnlyMemory<byte> enrollmentStateKey, CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try
        {
            return enrollmentsByStateKey.TryGetValue(
                    Convert.ToHexString(enrollmentStateKey.Span), out var record)
                ? record.Response.ToArray()
                : null;
        }
        finally { gate.Release(); }
    }

    public async ValueTask<ProductionMailboxIssueCommitResult>
        ConsumeChallengeAcceptAdvertisementAndIssueAsync(
            ReadOnlyMemory<byte> challengeId, ReadOnlyMemory<byte> expectedChallenge,
            ulong nowUnixSeconds, ulong issuanceExpiresAtUnixSeconds,
            ReadOnlyMemory<byte> expectedArtifactClosureHash, ReadOnlyMemory<byte> idempotencyKey,
            ReadOnlyMemory<byte> requiredEnrollmentStateKey, ReadOnlyMemory<byte> routeDomainHash,
            ulong advertisementSequence, ReadOnlyMemory<byte> advertisementHash,
            Func<CancellationToken, ValueTask<ProductionMailboxPreparedIssue>> createPreparedIssue,
            CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try
        {
            if (!TryGetLiveChallenge(challengeId, expectedChallenge, nowUnixSeconds,
                    expectedArtifactClosureHash, out var challengeKey, out var challenge))
                return new(ProductionMailboxIssueCommitStatus.InvalidChallenge, null);
            if (promotions.Values.Any(static promotion => !promotion.Published))
                return new(ProductionMailboxIssueCommitStatus.PromotionInProgress, null);
            if (!requiredEnrollmentStateKey.IsEmpty
                && (!enrollmentsByStateKey.TryGetValue(
                        Convert.ToHexString(requiredEnrollmentStateKey.Span),
                        out var requiredEnrollment)
                    || requiredEnrollment.ExpiresAtUnixSeconds < nowUnixSeconds))
                return new(ProductionMailboxIssueCommitStatus.EnrollmentMismatch, null);
            var issuanceKey = Convert.ToHexString(idempotencyKey.Span);
            if (issuances.TryGetValue(issuanceKey, out var existing)
                && existing.ExpiresAtUnixSeconds >= nowUnixSeconds)
            {
                challenges[challengeKey] = challenge with { Used = true };
                if (!CryptographicEqual(existing.EnrollmentStateKey,
                        requiredEnrollmentStateKey.Span)
                    || !CryptographicEqual(existing.AdvertisementHash,
                        advertisementHash.Span))
                    return new(ProductionMailboxIssueCommitStatus.IssuanceConflict, null);
                return new(ProductionMailboxIssueCommitStatus.Replayed,
                    existing.Response.ToArray());
            }
            var routeKey = Convert.ToHexString(routeDomainHash.Span);
            if (!routeAdvertisements.TryGetValue(routeKey, out var current)
                && advertisementSequence != 1)
                return new(ProductionMailboxIssueCommitStatus.AdvertisementConflict, null);
            if (current is not null)
            {
                if (advertisementSequence < current.Sequence)
                    return new(ProductionMailboxIssueCommitStatus.AdvertisementRollback, null);
                if (advertisementSequence == current.Sequence
                    && !CryptographicEqual(current.AdvertisementHash,
                        advertisementHash.Span))
                    return new(ProductionMailboxIssueCommitStatus.AdvertisementConflict, null);
            }
            var prepared = await createPreparedIssue(cancellationToken);
            routeAdvertisements[routeKey] = new(
                advertisementSequence, advertisementHash.ToArray());
            issuances[issuanceKey] = new(
                prepared.CanonicalResponse.ToArray(), issuanceExpiresAtUnixSeconds,
                requiredEnrollmentStateKey.ToArray(), advertisementHash.ToArray());
            if (prepared.OwnerRouteStateKey.Length != 0)
                SetOwnerBundle(prepared.OwnerRouteStateKey,
                    prepared.CanonicalResponse);
            if (prepared.PublicationItems.Count != 0)
            {
                var publicationKey = Convert.ToHexString(prepared.PublicationStateKey);
                var publication = new PublicationRecord(
                    System.Security.Cryptography.SHA256.HashData(
                        prepared.CanonicalResponse),
                    FreezeItems(prepared.PublicationItems));
                if (publications.ContainsKey(publicationKey))
                    throw new InvalidDataException(
                        "Production mailbox publication state already exists for a new issuance.");
                publications[publicationKey] = publication;
            }
            challenges[challengeKey] = challenge with { Used = true };
            if (Interlocked.Exchange(ref throwAfterIssueCommitOnce, 0) == 1)
                throw new IOException(
                    "Injected provider failure after atomic issuance commit.");
            return new(ProductionMailboxIssueCommitStatus.Accepted,
                prepared.CanonicalResponse);
        }
        finally { gate.Release(); }
    }

    public async ValueTask<ProductionMailboxPublicationState> PreparePublicationAsync(
        ReadOnlyMemory<byte> publicationStateKey,
        ReadOnlyMemory<byte> canonicalResponseSha256,
        IReadOnlyList<ProductionMailboxPublicationItem> items,
        CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try
        {
            var key = Convert.ToHexString(publicationStateKey.Span);
            if (publications.TryGetValue(key, out var existing))
            {
                if (!CryptographicEqual(existing.CanonicalResponseSha256,
                        canonicalResponseSha256.Span)
                    || !ExactItems(existing.Items, items))
                    throw new InvalidDataException(
                        "Production mailbox publication replay conflicts with durable outbox state.");
                return Snapshot(publicationStateKey.Span, existing);
            }
            var frozen = FreezeItems(items);
            var record = new PublicationRecord(
                canonicalResponseSha256.ToArray(), frozen);
            publications[key] = record;
            return Snapshot(publicationStateKey.Span, record);
        }
        finally { gate.Release(); }
    }

    public async ValueTask<ProductionMailboxPublicationState?> GetPublicationAsync(
        ReadOnlyMemory<byte> publicationStateKey,
        CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try
        {
            return publications.TryGetValue(
                    Convert.ToHexString(publicationStateKey.Span), out var record)
                ? Snapshot(publicationStateKey.Span, record)
                : null;
        }
        finally { gate.Release(); }
    }

    public async ValueTask<IReadOnlyList<byte[]>> ListPendingPublicationKeysAsync(
        int maximumCount, CancellationToken cancellationToken)
    {
        if (maximumCount is < 1 or > 256) throw new ArgumentOutOfRangeException(nameof(maximumCount));
        await gate.WaitAsync(cancellationToken);
        try
        {
            return publications
                .Where(static pair => pair.Value.Items.Any(static item => !item.Acknowledged))
                .OrderBy(static pair => pair.Key, StringComparer.Ordinal)
                .Take(maximumCount)
                .Select(static pair => Convert.FromHexString(pair.Key))
                .ToArray();
        }
        finally { gate.Release(); }
    }

    public async ValueTask<bool> RecordPublicationAttemptAsync(
        ReadOnlyMemory<byte> publicationStateKey,
        ReadOnlyMemory<byte> targetStateKey,
        ReadOnlyMemory<byte> envelopeSha256,
        ReadOnlyMemory<byte> attemptSha256,
        ulong attemptedAtUnixSeconds,
        CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try
        {
            if (!publications.TryGetValue(
                    Convert.ToHexString(publicationStateKey.Span), out var publication))
                return false;
            var item = publication.Items.SingleOrDefault(value =>
                CryptographicEqual(value.TargetStateKey, targetStateKey.Span));
            if (item is null || item.Acknowledged
                || !CryptographicEqual(item.EnvelopeSha256, envelopeSha256.Span)
                || attemptSha256.Length != 32)
                return false;
            item.LastAttemptSha256 = attemptSha256.ToArray();
            item.LastAttemptAtUnixSeconds = attemptedAtUnixSeconds;
            return true;
        }
        finally { gate.Release(); }
    }

    public async ValueTask<bool> AcknowledgePublicationAsync(
        ReadOnlyMemory<byte> publicationStateKey,
        ReadOnlyMemory<byte> targetStateKey,
        ReadOnlyMemory<byte> envelopeSha256,
        ReadOnlyMemory<byte> attemptSha256,
        CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try
        {
            if (!publications.TryGetValue(
                    Convert.ToHexString(publicationStateKey.Span), out var publication))
                return false;
            var item = publication.Items.SingleOrDefault(value =>
                CryptographicEqual(value.TargetStateKey, targetStateKey.Span));
            if (item is null
                || !CryptographicEqual(item.EnvelopeSha256, envelopeSha256.Span)
                || item.LastAttemptSha256 is null
                || !CryptographicEqual(item.LastAttemptSha256, attemptSha256.Span))
                return false;
            item.Acknowledged = true;
            return publication.Items.All(static value => value.Acknowledged);
        }
        finally { gate.Release(); }
    }

    public async ValueTask<ProductionMailboxArtifactPromotionState>
        BeginArtifactPromotionAsync(
            ReadOnlyMemory<byte> promotionStateKey,
            ReadOnlyMemory<byte> oldArtifactClosureHash,
            ReadOnlyMemory<byte> newArtifactClosureHash,
            CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try
        {
            var key = Convert.ToHexString(promotionStateKey.Span);
            if (promotions.TryGetValue(key, out var existing))
            {
                if (!CryptographicEqual(existing.OldArtifactClosureHash,
                        oldArtifactClosureHash.Span)
                    || !CryptographicEqual(existing.NewArtifactClosureHash,
                        newArtifactClosureHash.Span))
                    throw new InvalidDataException(
                        "Production mailbox artifact promotion replay conflicts.");
                return Snapshot(promotionStateKey.Span, existing);
            }
            if (promotions.Values.Any(static value =>
                    !value.Published || !value.CapacityReleaseCompleted))
                throw new InvalidOperationException(
                    "Another production mailbox artifact promotion is active.");
            publishedArtifactClosureHash ??= oldArtifactClosureHash.ToArray();
            if (!CryptographicEqual(
                    publishedArtifactClosureHash, oldArtifactClosureHash.Span))
                throw new InvalidOperationException(
                    "Artifact promotion old closure is not the durable published closure.");
            var created = new MutablePromotionRecord(
                oldArtifactClosureHash.ToArray(), newArtifactClosureHash.ToArray(),
                nextOwnerSequence, 0, false, false, false, []);
            promotions[key] = created;
            return Snapshot(promotionStateKey.Span, created);
        }
        finally { gate.Release(); }
    }

    public async ValueTask<ProductionMailboxArtifactPromotionState?>
        GetArtifactPromotionAsync(
            ReadOnlyMemory<byte> promotionStateKey,
            CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try
        {
            return promotions.TryGetValue(
                    Convert.ToHexString(promotionStateKey.Span), out var value)
                ? Snapshot(promotionStateKey.Span, value) : null;
        }
        finally { gate.Release(); }
    }

    public async ValueTask<ProductionMailboxArtifactPromotionState?>
        GetActiveArtifactPromotionAsync(CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try
        {
            var active = promotions.SingleOrDefault(static pair =>
                !pair.Value.Published || !pair.Value.CapacityReleaseCompleted);
            return active.Value is null
                ? null
                : Snapshot(Convert.FromHexString(active.Key), active.Value);
        }
        finally { gate.Release(); }
    }

    public async ValueTask<byte[]> GetOrInitializePublishedArtifactClosureAsync(
        ReadOnlyMemory<byte> initialArtifactClosureHash,
        CancellationToken cancellationToken)
    {
        if (initialArtifactClosureHash.Length != 32)
            throw new ArgumentException("Artifact closure hash must be 32 bytes.");
        await gate.WaitAsync(cancellationToken);
        try
        {
            publishedArtifactClosureHash ??= initialArtifactClosureHash.ToArray();
            return publishedArtifactClosureHash.ToArray();
        }
        finally { gate.Release(); }
    }

    public async ValueTask<IReadOnlyList<ProductionMailboxOwnerBundleRecord>>
        ListOwnerBundlesForPromotionAsync(
            ReadOnlyMemory<byte> promotionStateKey,
            int maximumCount,
            CancellationToken cancellationToken)
    {
        if (maximumCount is < 1 or > 256) throw new ArgumentOutOfRangeException(nameof(maximumCount));
        await gate.WaitAsync(cancellationToken);
        try
        {
            if (!promotions.TryGetValue(
                    Convert.ToHexString(promotionStateKey.Span), out var promotion)
                || promotion.Published)
                return [];
            return ownerBundles.Values
                .Where(owner => owner.Sequence > promotion.Cursor
                    && owner.Sequence <= promotion.OwnerWatermark)
                .OrderBy(static owner => owner.Sequence)
                .Take(maximumCount)
                .Select(static owner => new ProductionMailboxOwnerBundleRecord(
                    owner.Sequence, owner.RouteStateKey.ToArray(),
                    owner.CanonicalBundle.ToArray()))
                .ToArray();
        }
        finally { gate.Release(); }
    }

    public async ValueTask<IReadOnlyList<ProductionMailboxOwnerBundleRecord>>
        ListOwnerBundlesForCapacityPlanningAsync(
            ReadOnlyMemory<byte> promotionStateKey,
            int maximumCount,
            CancellationToken cancellationToken)
    {
        if (maximumCount is < 1 or > 256)
            throw new ArgumentOutOfRangeException(nameof(maximumCount));
        await gate.WaitAsync(cancellationToken);
        try
        {
            if (!promotions.TryGetValue(
                    Convert.ToHexString(promotionStateKey.Span), out var promotion)
                || promotion.Published || promotion.CapacityPlanCompleted)
                return [];
            return ownerBundles.Values
                .Where(owner => owner.Sequence > promotion.CapacityCursor
                    && owner.Sequence <= promotion.OwnerWatermark)
                .OrderBy(static owner => owner.Sequence)
                .Take(maximumCount)
                .Select(static owner => new ProductionMailboxOwnerBundleRecord(
                    owner.Sequence, owner.RouteStateKey.ToArray(),
                    owner.CanonicalBundle.ToArray()))
                .ToArray();
        }
        finally { gate.Release(); }
    }

    public async ValueTask<bool> CommitCapacityPlannedOwnerAsync(
        ReadOnlyMemory<byte> promotionStateKey,
        ProductionMailboxOwnerBundleRecord expectedOwner,
        IReadOnlyList<ProductionMailboxPublicationItem> publicationItems,
        ulong perScheduleOverheadBytes,
        CancellationToken cancellationToken)
    {
        var frozen = FreezeItems(publicationItems);
        await gate.WaitAsync(cancellationToken);
        try
        {
            if (!promotions.TryGetValue(
                    Convert.ToHexString(promotionStateKey.Span), out var promotion)
                || promotion.Published || promotion.CapacityPlanCompleted
                || expectedOwner.Sequence != promotion.CapacityCursor + 1
                || expectedOwner.Sequence > promotion.OwnerWatermark)
                return false;
            var ownerKey = Convert.ToHexString(expectedOwner.RouteStateKey);
            if (!ownerBundles.TryGetValue(ownerKey, out var owner)
                || owner.Sequence != expectedOwner.Sequence
                || !CryptographicEqual(owner.CanonicalBundle,
                    expectedOwner.CanonicalBundle))
                return false;
            foreach (var item in frozen)
            {
                if (!CryptographicEqual(item.ReservationCohortId,
                        promotionStateKey.Span))
                    return false;
                var targetKey = Convert.ToHexString(item.TargetReplicaId);
                var charge = checked((ulong)item.CanonicalEnvelope.Length
                    + 12UL + perScheduleOverheadBytes);
                if (!promotion.CapacityTargets.TryGetValue(
                        targetKey, out var target))
                {
                    target = new MutableCapacityTarget(
                        item.TargetReplicaId.ToArray(), item.Endpoint,
                        item.CurrentSpkiSha256.ToArray(),
                        item.NextSpkiSha256.ToArray());
                    promotion.CapacityTargets.Add(targetKey, target);
                }
                else if (target.Endpoint != item.Endpoint
                    || !CryptographicEqual(target.CurrentSpkiSha256,
                        item.CurrentSpkiSha256)
                    || !CryptographicEqual(target.NextSpkiSha256,
                        item.NextSpkiSha256))
                    return false;
                target.ReservedClosureCount = checked(
                    target.ReservedClosureCount + 1);
                target.ReservedBytes = checked(target.ReservedBytes + charge);
            }
            promotion.CapacityCursor = expectedOwner.Sequence;
            return true;
        }
        finally { gate.Release(); }
    }

    public async ValueTask<bool> CompleteCapacityPlanAsync(
        ReadOnlyMemory<byte> promotionStateKey,
        CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try
        {
            if (!promotions.TryGetValue(
                    Convert.ToHexString(promotionStateKey.Span), out var promotion)
                || promotion.Published
                || promotion.CapacityCursor < promotion.OwnerWatermark)
                return false;
            promotion.CapacityPlanCompleted = true;
            return true;
        }
        finally { gate.Release(); }
    }

    public async ValueTask<ProductionMailboxCapacityPlanState?> GetCapacityPlanAsync(
        ReadOnlyMemory<byte> promotionStateKey,
        CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try
        {
            return promotions.TryGetValue(
                    Convert.ToHexString(promotionStateKey.Span), out var promotion)
                ? SnapshotCapacityPlan(promotionStateKey.Span, promotion) : null;
        }
        finally { gate.Release(); }
    }

    public async ValueTask<bool> RecordCapacityReceiptAsync(
        ReadOnlyMemory<byte> promotionStateKey,
        ReadOnlyMemory<byte> targetReplicaId,
        ulong expectedPreviousRevision,
        ProductionMailboxCapacityReceipt receipt,
        ReadOnlyMemory<byte> canonicalReceipt,
        CancellationToken cancellationToken)
    {
        var receiptBytes = canonicalReceipt.ToArray();
        try
        {
            receipt = ProductionMailboxCapacityReceiptCodec.DecodeAndVerify(
                receiptBytes, targetReplicaId.Span);
        }
        catch (InvalidDataException)
        {
            return false;
        }
        if (!ProductionMailboxCapacityRevisionPolicy.IsStorableReceipt(receipt))
            return false;
        await gate.WaitAsync(cancellationToken);
        try
        {
            if (!promotions.TryGetValue(
                    Convert.ToHexString(promotionStateKey.Span), out var promotion)
                || !promotion.CapacityPlanCompleted
                || !promotion.CapacityTargets.TryGetValue(
                    Convert.ToHexString(targetReplicaId.Span), out var target)
                || target.Released
                || target.Revision != expectedPreviousRevision
                || receipt.Revision != checked(expectedPreviousRevision + 1)
                || target.PendingRevision != receipt.Revision
                || target.PendingCanonicalCommand is null
                || !CryptographicEqual(
                    System.Security.Cryptography.SHA256.HashData(
                        target.PendingCanonicalCommand), receipt.CommandSha256)
                || !CryptographicEqual(receipt.CohortId, promotionStateKey.Span)
                || !CryptographicEqual(receipt.TargetReplicaId,
                    targetReplicaId.Span)
                || receipt.Operation == ProductionMailboxCapacityOperation.ReserveOrRenew
                    && (receipt.ReservedClosureCount != target.ReservedClosureCount
                        || receipt.ReservedBytes != target.ReservedBytes)
                || receipt.Operation == ProductionMailboxCapacityOperation.Release
                    && (receipt.ReservedClosureCount > target.ReservedClosureCount
                        || receipt.ReservedBytes > target.ReservedBytes))
                return false;
            target.Revision = receipt.Revision;
            target.ReceiptExpiresAtUnixSeconds = receipt.ExpiresAtUnixSeconds;
            target.LastCommandSha256 = receipt.CommandSha256.ToArray();
            target.CanonicalReceipt = receiptBytes;
            target.PendingCanonicalCommand = null;
            target.PendingRevision = null;
            target.Released = receipt.Operation
                == ProductionMailboxCapacityOperation.Release;
            return true;
        }
        finally { gate.Release(); }
    }

    public async ValueTask<bool> RecordCapacityReconciliationReceiptAsync(
        ReadOnlyMemory<byte> promotionStateKey,
        ReadOnlyMemory<byte> targetReplicaId,
        ulong expectedRevision,
        ReadOnlyMemory<byte> expectedPendingReleaseCommand,
        ProductionMailboxCapacityReconciliationReceipt receipt,
        ReadOnlyMemory<byte> canonicalReceipt,
        CancellationToken cancellationToken)
    {
        var receiptBytes = canonicalReceipt.ToArray();
        try
        {
            receipt = ProductionMailboxCapacityReconciliationReceiptCodec.DecodeAndVerify(
                receiptBytes, targetReplicaId.Span);
        }
        catch (InvalidDataException)
        {
            return false;
        }
        await gate.WaitAsync(cancellationToken);
        try
        {
            if (!promotions.TryGetValue(
                    Convert.ToHexString(promotionStateKey.Span), out var promotion)
                || !promotion.CapacityPlanCompleted
                || !promotion.CapacityTargets.TryGetValue(
                    Convert.ToHexString(targetReplicaId.Span), out var target)
                || target.Released || target.Revision != expectedRevision
                || target.CanonicalReceipt is null || target.LastCommandSha256 is null
                || target.PendingCanonicalCommand is null
                || !CryptographicEqual(target.PendingCanonicalCommand,
                    expectedPendingReleaseCommand.Span)
                || target.PendingRevision != checked(expectedRevision + 1)
                || receipt.Status
                    != ProductionMailboxCapacityReconciliationStatus.AbsentTerminal
                || receipt.LastKnownRevision != expectedRevision
                || !CryptographicEqual(receipt.CohortId, promotionStateKey.Span)
                || !CryptographicEqual(receipt.TargetReplicaId, targetReplicaId.Span)
                || !CryptographicEqual(receipt.LastReceiptSha256,
                    System.Security.Cryptography.SHA256.HashData(target.CanonicalReceipt))
                || !CryptographicEqual(
                    receipt.LastCommandSha256, target.LastCommandSha256))
                return false;
            target.ReleaseReconciliationReceipt = receiptBytes;
            target.PendingCanonicalCommand = null;
            target.PendingRevision = null;
            target.Released = true;
            return true;
        }
        finally { gate.Release(); }
    }

    public async ValueTask<byte[]?> GetOrRecordCapacityAttemptAsync(
        ReadOnlyMemory<byte> promotionStateKey,
        ReadOnlyMemory<byte> targetReplicaId,
        ulong expectedPreviousRevision,
        ulong attemptRevision,
        ReadOnlyMemory<byte> canonicalCommand,
        CancellationToken cancellationToken)
    {
        if (attemptRevision > ProductionMailboxCapacityRevisionPolicy.MaximumStoredRevision)
            return null;
        await gate.WaitAsync(cancellationToken);
        try
        {
            if (!promotions.TryGetValue(
                    Convert.ToHexString(promotionStateKey.Span), out var promotion)
                || !promotion.CapacityPlanCompleted
                || !promotion.CapacityTargets.TryGetValue(
                    Convert.ToHexString(targetReplicaId.Span), out var target)
                || target.Released
                || target.Revision != expectedPreviousRevision
                || attemptRevision != checked(expectedPreviousRevision + 1))
                return null;
            if (target.PendingCanonicalCommand is not null)
                return target.PendingRevision == attemptRevision
                    ? target.PendingCanonicalCommand.ToArray()
                    : throw new InvalidDataException(
                        "Production mailbox capacity pending attempt is corrupt.");
            target.PendingCanonicalCommand = canonicalCommand.ToArray();
            target.PendingRevision = attemptRevision;
            return target.PendingCanonicalCommand.ToArray();
        }
        finally { gate.Release(); }
    }

    public async ValueTask<bool> CommitPromotedOwnerAsync(
        ReadOnlyMemory<byte> promotionStateKey,
        ProductionMailboxOwnerBundleRecord expectedOwner,
        ProductionMailboxPreparedIssue preparedIssue,
        ulong updatedAtUnixSeconds,
        uint capacityRenewalMarginSeconds,
        CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try
        {
            var capacitySafeUntil = checked((ulong)timeProvider.GetUtcNow()
                .ToUnixTimeSeconds() + capacityRenewalMarginSeconds);
            if (!promotions.TryGetValue(
                    Convert.ToHexString(promotionStateKey.Span), out var promotion)
                || promotion.Published || expectedOwner.Sequence <= promotion.Cursor
                || expectedOwner.Sequence > promotion.OwnerWatermark
                || !promotion.CapacityPlanCompleted
                || promotion.CapacityTargets.Values.Any(target => target.Released
                    || target.CanonicalReceipt is null
                    || target.PendingCanonicalCommand is not null
                    || target.PendingRevision is not null
                    || target.ReceiptExpiresAtUnixSeconds is null
                    || target.ReceiptExpiresAtUnixSeconds.Value
                        < capacitySafeUntil))
                return false;
            var ownerKey = Convert.ToHexString(expectedOwner.RouteStateKey);
            if (!ownerBundles.TryGetValue(ownerKey, out var owner)
                || owner.Sequence != expectedOwner.Sequence
                || !CryptographicEqual(owner.CanonicalBundle,
                    expectedOwner.CanonicalBundle)
                || !CryptographicEqual(preparedIssue.OwnerRouteStateKey,
                    expectedOwner.RouteStateKey))
                return false;
            var publicationKey = Convert.ToHexString(preparedIssue.PublicationStateKey);
            if (preparedIssue.PublicationItems.Count == 0
                || publications.ContainsKey(publicationKey))
                return false;
            owner.CanonicalBundle = preparedIssue.CanonicalResponse.ToArray();
            publications[publicationKey] = new PublicationRecord(
                System.Security.Cryptography.SHA256.HashData(
                    preparedIssue.CanonicalResponse),
                FreezeItems(preparedIssue.PublicationItems));
            promotion.PublicationStateKeys.Add(preparedIssue.PublicationStateKey.ToArray());
            promotion.Cursor = expectedOwner.Sequence;
            if (Interlocked.Exchange(ref throwAfterPromotedOwnerCommitOnce, 0) == 1)
                throw new IOException(
                    "Injected provider failure after atomic promoted-owner commit.");
            return true;
        }
        finally { gate.Release(); }
    }

    public async ValueTask<bool> CompleteArtifactPromotionSweepAsync(
        ReadOnlyMemory<byte> promotionStateKey,
        CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try
        {
            if (!promotions.TryGetValue(
                    Convert.ToHexString(promotionStateKey.Span), out var promotion)
                || promotion.Published || promotion.Cursor < promotion.OwnerWatermark
                || promotion.PublicationStateKeys.Any(key =>
                    !publications.TryGetValue(Convert.ToHexString(key), out var publication)
                    || publication.Items.Any(static item => !item.Acknowledged)))
                return false;
            promotion.SweepCompleted = true;
            return true;
        }
        finally { gate.Release(); }
    }

    public async ValueTask<bool> MarkArtifactPromotionPublishedAsync(
        ReadOnlyMemory<byte> promotionStateKey,
        CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try
        {
            if (!promotions.TryGetValue(
                    Convert.ToHexString(promotionStateKey.Span), out var promotion)
                || !promotion.SweepCompleted)
                return false;
            if (Interlocked.Exchange(ref throwBeforePromotionPublishedOnce, 0) == 1)
                throw new IOException(
                    "Injected provider failure before promotion published marker.");
            if (publishedArtifactClosureHash is null
                || !CryptographicEqual(publishedArtifactClosureHash,
                    promotion.OldArtifactClosureHash))
                return false;
            publishedArtifactClosureHash = promotion.NewArtifactClosureHash.ToArray();
            promotion.Published = true;
            AfterPromotionPublishedForTests?.Invoke();
            return true;
        }
        finally { gate.Release(); }
    }

    public async ValueTask<bool> MarkArtifactPromotionCapacityReleasedAsync(
        ReadOnlyMemory<byte> promotionStateKey,
        CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try
        {
            if (!promotions.TryGetValue(
                    Convert.ToHexString(promotionStateKey.Span), out var promotion)
                || !promotion.Published
                || promotion.CapacityTargets.Values.Any(static target => !target.Released))
                return false;
            if (Interlocked.Exchange(ref throwBeforeCapacityReleasedOnce, 0) == 1)
                throw new IOException(
                    "Injected failure before promotion capacity release marker.");
            promotion.CapacityReleaseCompleted = true;
            return true;
        }
        finally { gate.Release(); }
    }

    public async ValueTask<bool> IsHolderRevokedAsync(ReadOnlyMemory<byte> holderHash, CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try { return revokedHolders.Contains(Convert.ToHexString(holderHash.Span)); }
        finally { gate.Release(); }
    }

    public async ValueTask RevokeHolderAsync(ReadOnlyMemory<byte> holderHash, ulong nowUnixSeconds, CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try { revokedHolders.Add(Convert.ToHexString(holderHash.Span)); }
        finally { gate.Release(); }
    }

    public async ValueTask<ProductionMailboxRouteAdvertisementAcceptance> AcceptRouteAdvertisementAsync(
        ReadOnlyMemory<byte> routeDomainHash, ulong sequence,
        ReadOnlyMemory<byte> advertisementHash, CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try
        {
            var key = Convert.ToHexString(routeDomainHash.Span);
            if (!routeAdvertisements.TryGetValue(key, out var current))
            {
                routeAdvertisements[key] = new(sequence, advertisementHash.ToArray());
                return ProductionMailboxRouteAdvertisementAcceptance.Accepted;
            }
            if (sequence < current.Sequence)
                return ProductionMailboxRouteAdvertisementAcceptance.Rollback;
            if (sequence == current.Sequence)
                return System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(
                    current.AdvertisementHash, advertisementHash.Span)
                    ? ProductionMailboxRouteAdvertisementAcceptance.ExactReplay
                    : ProductionMailboxRouteAdvertisementAcceptance.Conflict;
            routeAdvertisements[key] = new(sequence, advertisementHash.ToArray());
            return ProductionMailboxRouteAdvertisementAcceptance.Accepted;
        }
        finally { gate.Release(); }
    }

    public async ValueTask<byte[]?> GetLatestOwnerBundleAsync(
        ReadOnlyMemory<byte> routeStateKey, CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try
        {
            return ownerBundles.TryGetValue(Convert.ToHexString(routeStateKey.Span), out var value)
                ? value.CanonicalBundle.ToArray() : null;
        }
        finally { gate.Release(); }
    }

    public async ValueTask StoreLatestOwnerBundleAsync(
        ReadOnlyMemory<byte> routeStateKey, ReadOnlyMemory<byte> canonicalBundle,
        ulong updatedAtUnixSeconds, CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try { SetOwnerBundle(routeStateKey.Span, canonicalBundle.Span); }
        finally { gate.Release(); }
    }

    private void SetOwnerBundle(ReadOnlySpan<byte> routeStateKey,
        ReadOnlySpan<byte> canonicalBundle)
    {
        var key = Convert.ToHexString(routeStateKey);
        if (ownerBundles.TryGetValue(key, out var existing))
        {
            existing.CanonicalBundle = canonicalBundle.ToArray();
            return;
        }
        var sequence = checked(++nextOwnerSequence);
        ownerBundles[key] = new MutableOwnerBundleRecord(
            sequence, routeStateKey.ToArray(), canonicalBundle.ToArray());
    }

    private static ProductionMailboxArtifactPromotionState Snapshot(
        ReadOnlySpan<byte> promotionStateKey, MutablePromotionRecord record) => new(
        promotionStateKey.ToArray(), record.OldArtifactClosureHash.ToArray(),
        record.NewArtifactClosureHash.ToArray(), record.OwnerWatermark,
        record.Cursor, record.SweepCompleted, record.Published,
        record.CapacityReleaseCompleted);

    private static ProductionMailboxCapacityPlanState SnapshotCapacityPlan(
        ReadOnlySpan<byte> promotionStateKey, MutablePromotionRecord record) => new(
        promotionStateKey.ToArray(), record.CapacityCursor,
        record.CapacityPlanCompleted,
        record.CapacityTargets.Values
            .OrderBy(static target => Convert.ToHexString(target.TargetReplicaId),
                StringComparer.Ordinal)
            .Select(static target => new ProductionMailboxCapacityTargetState(
                target.TargetReplicaId.ToArray(), target.Endpoint,
                target.CurrentSpkiSha256.ToArray(), target.NextSpkiSha256.ToArray(),
                target.ReservedClosureCount, target.ReservedBytes,
                target.Revision, target.ReceiptExpiresAtUnixSeconds,
                target.LastCommandSha256?.ToArray(),
                target.CanonicalReceipt?.ToArray(),
                target.PendingCanonicalCommand?.ToArray(), target.PendingRevision,
                target.Released))
            .ToArray());

    private sealed record ChallengeRecord(
        byte[] Challenge, byte[] ArtifactClosureHash, ulong ExpiresAtUnixSeconds, bool Used);
    private bool TryGetLiveChallenge(
        ReadOnlyMemory<byte> challengeId, ReadOnlyMemory<byte> expectedChallenge,
        ulong nowUnixSeconds, ReadOnlyMemory<byte> expectedArtifactClosureHash,
        out string challengeKey, out ChallengeRecord challenge)
    {
        challengeKey = Convert.ToHexString(challengeId.Span);
        return challenges.TryGetValue(challengeKey, out challenge!) && !challenge.Used
            && challenge.ExpiresAtUnixSeconds >= nowUnixSeconds
            && CryptographicEqual(challenge.ArtifactClosureHash,
                expectedArtifactClosureHash.Span)
            && CryptographicEqual(challenge.Challenge, expectedChallenge.Span);
    }

    private static bool CryptographicEqual(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length
        && System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(left, right);

    private static List<MutablePublicationItem> FreezeItems(
        IReadOnlyList<ProductionMailboxPublicationItem> items)
    {
        if (items.Count is < 1 or > 8)
            throw new InvalidDataException("Production mailbox publication target count is invalid.");
        var frozen = items.Select(item => new MutablePublicationItem(
                item.TargetStateKey.ToArray(), item.TargetReplicaId.ToArray(), item.Endpoint,
                item.CurrentSpkiSha256.ToArray(), item.NextSpkiSha256.ToArray(),
                item.AuthorizedLegacyReplicaIds.Select(static value => value.ToArray()).ToArray(),
                item.CanonicalEnvelope.ToArray(), item.EnvelopeSha256.ToArray(),
                item.ReservationCohortId.ToArray(),
                item.LastAttemptSha256?.ToArray(), item.LastAttemptAtUnixSeconds,
                item.Acknowledged))
            .OrderBy(static item => Convert.ToHexString(item.TargetStateKey),
                StringComparer.Ordinal)
            .ToList();
        if (frozen.Any(item => item.TargetStateKey.Length != 32
                || item.TargetReplicaId.Length != 32
                || item.CurrentSpkiSha256.Length != 32
                || item.NextSpkiSha256.Length != 32
                || item.EnvelopeSha256.Length != 32
                || item.ReservationCohortId.Length != 32
                || item.CanonicalEnvelope.Length == 0
                || !CryptographicEqual(System.Security.Cryptography.SHA256.HashData(
                    item.CanonicalEnvelope), item.EnvelopeSha256)
                || item.AuthorizedLegacyReplicaIds.Count > 2
                || item.AuthorizedLegacyReplicaIds.Any(static value => value.Length != 32)
                || item.LastAttemptSha256 is { Length: not 32 }
                || !Uri.TryCreate(item.Endpoint, UriKind.Absolute, out var endpoint)
                || endpoint.Scheme != Uri.UriSchemeHttps || endpoint.PathAndQuery != "/")
            || frozen.Zip(frozen.Skip(1), (left, right) =>
                    CryptographicEqual(left.TargetStateKey, right.TargetStateKey))
                .Any(static duplicate => duplicate))
            throw new InvalidDataException("Production mailbox publication target is invalid.");
        return frozen;
    }

    private static bool ExactItems(
        IReadOnlyList<MutablePublicationItem> existing,
        IReadOnlyList<ProductionMailboxPublicationItem> candidate)
    {
        var frozen = FreezeItems(candidate);
        return existing.Count == frozen.Count && existing.Zip(frozen).All(pair =>
            CryptographicEqual(pair.First.TargetStateKey, pair.Second.TargetStateKey)
            && pair.First.Endpoint == pair.Second.Endpoint
            && CryptographicEqual(pair.First.TargetReplicaId, pair.Second.TargetReplicaId)
            && CryptographicEqual(pair.First.CurrentSpkiSha256,
                pair.Second.CurrentSpkiSha256)
            && CryptographicEqual(pair.First.NextSpkiSha256,
                pair.Second.NextSpkiSha256)
            && ExactByteLists(pair.First.AuthorizedLegacyReplicaIds,
                pair.Second.AuthorizedLegacyReplicaIds)
            && CryptographicEqual(pair.First.CanonicalEnvelope, pair.Second.CanonicalEnvelope)
            && CryptographicEqual(pair.First.EnvelopeSha256, pair.Second.EnvelopeSha256)
            && CryptographicEqual(pair.First.ReservationCohortId,
                pair.Second.ReservationCohortId));
    }

    private static ProductionMailboxPublicationState Snapshot(
        ReadOnlySpan<byte> publicationStateKey, PublicationRecord record) => new(
        publicationStateKey.ToArray(), record.CanonicalResponseSha256.ToArray(),
        record.Items.Select(item => new ProductionMailboxPublicationItem(
            item.TargetStateKey.ToArray(), item.TargetReplicaId.ToArray(), item.Endpoint,
            item.CurrentSpkiSha256.ToArray(), item.NextSpkiSha256.ToArray(),
            item.AuthorizedLegacyReplicaIds.Select(static value => value.ToArray()).ToArray(),
            item.CanonicalEnvelope.ToArray(), item.EnvelopeSha256.ToArray(),
            item.ReservationCohortId.ToArray(),
            item.LastAttemptSha256?.ToArray(), item.LastAttemptAtUnixSeconds,
            item.Acknowledged)).ToArray(),
        record.Items.All(static item => item.Acknowledged));

    private static bool ExactByteLists(
        IReadOnlyList<byte[]> left, IReadOnlyList<byte[]> right) =>
        left.Count == right.Count && left.Zip(right).All(pair =>
            CryptographicEqual(pair.First, pair.Second));

    private sealed record IssuanceRecord(
        byte[] Response, ulong ExpiresAtUnixSeconds,
        byte[] EnrollmentStateKey, byte[] AdvertisementHash)
    {
        public IssuanceRecord(byte[] response, ulong expiresAtUnixSeconds)
            : this(response, expiresAtUnixSeconds, [], []) { }
    }
    private sealed record EnrollmentRecord(
        byte[] StateKey, byte[] IdempotencyKey, byte[] Response,
        ulong ExpiresAtUnixSeconds);
    private sealed record PublicationRecord(
        byte[] CanonicalResponseSha256, List<MutablePublicationItem> Items);
    private sealed class MutableOwnerBundleRecord(
        long sequence, byte[] routeStateKey, byte[] canonicalBundle)
    {
        public long Sequence { get; } = sequence;
        public byte[] RouteStateKey { get; } = routeStateKey;
        public byte[] CanonicalBundle { get; set; } = canonicalBundle;
    }
    private sealed class MutablePromotionRecord(
        byte[] oldArtifactClosureHash, byte[] newArtifactClosureHash,
        long ownerWatermark, long cursor, bool sweepCompleted, bool published,
        bool capacityReleaseCompleted,
        List<byte[]> publicationStateKeys)
    {
        public byte[] OldArtifactClosureHash { get; } = oldArtifactClosureHash;
        public byte[] NewArtifactClosureHash { get; } = newArtifactClosureHash;
        public long OwnerWatermark { get; } = ownerWatermark;
        public long Cursor { get; set; } = cursor;
        public bool SweepCompleted { get; set; } = sweepCompleted;
        public bool Published { get; set; } = published;
        public bool CapacityReleaseCompleted { get; set; } = capacityReleaseCompleted;
        public List<byte[]> PublicationStateKeys { get; } = publicationStateKeys;
        public long CapacityCursor { get; set; }
        public bool CapacityPlanCompleted { get; set; }
        public Dictionary<string, MutableCapacityTarget> CapacityTargets { get; } =
            new(StringComparer.Ordinal);
    }
    private sealed class MutableCapacityTarget(
        byte[] targetReplicaId, string endpoint,
        byte[] currentSpkiSha256, byte[] nextSpkiSha256)
    {
        public byte[] TargetReplicaId { get; } = targetReplicaId;
        public string Endpoint { get; } = endpoint;
        public byte[] CurrentSpkiSha256 { get; } = currentSpkiSha256;
        public byte[] NextSpkiSha256 { get; } = nextSpkiSha256;
        public uint ReservedClosureCount { get; set; }
        public ulong ReservedBytes { get; set; }
        public ulong Revision { get; set; }
        public ulong? ReceiptExpiresAtUnixSeconds { get; set; }
        public byte[]? LastCommandSha256 { get; set; }
        public byte[]? CanonicalReceipt { get; set; }
        public byte[]? ReleaseReconciliationReceipt { get; set; }
        public byte[]? PendingCanonicalCommand { get; set; }
        public ulong? PendingRevision { get; set; }
        public bool Released { get; set; }
    }
    private sealed class MutablePublicationItem(
        byte[] targetStateKey, byte[] targetReplicaId, string endpoint,
        byte[] currentSpkiSha256, byte[] nextSpkiSha256,
        IReadOnlyList<byte[]> authorizedLegacyReplicaIds, byte[] canonicalEnvelope,
        byte[] envelopeSha256, byte[] reservationCohortId,
        byte[]? lastAttemptSha256,
        ulong? lastAttemptAtUnixSeconds, bool acknowledged)
    {
        public byte[] TargetStateKey { get; } = targetStateKey;
        public byte[] TargetReplicaId { get; } = targetReplicaId;
        public string Endpoint { get; } = endpoint;
        public byte[] CurrentSpkiSha256 { get; } = currentSpkiSha256;
        public byte[] NextSpkiSha256 { get; } = nextSpkiSha256;
        public IReadOnlyList<byte[]> AuthorizedLegacyReplicaIds { get; } = authorizedLegacyReplicaIds;
        public byte[] CanonicalEnvelope { get; } = canonicalEnvelope;
        public byte[] EnvelopeSha256 { get; } = envelopeSha256;
        public byte[] ReservationCohortId { get; } = reservationCohortId;
        public byte[]? LastAttemptSha256 { get; set; } = lastAttemptSha256;
        public ulong? LastAttemptAtUnixSeconds { get; set; } = lastAttemptAtUnixSeconds;
        public bool Acknowledged { get; set; } = acknowledged;
    }
    private sealed record RouteAdvertisementRecord(ulong Sequence, byte[] AdvertisementHash);
}

public sealed partial class PostgreSqlProductionMailboxStateStore(string connectionString)
    : IProductionMailboxStateStore, IProductionMailboxRouteContinuityStateStore
{
    private readonly SemaphoreSlim initializeGate = new(1, 1);
    private volatile bool initialized;
    internal TimeSpan CommitPromotedOwnerDelayBeforeFinalCapacityCheck { get; set; }

    public async ValueTask<ProductionMailboxChallengeState?> CreateChallengeAsync(
        ulong nowUnixSeconds, ulong expiresAtUnixSeconds,
        ReadOnlyMemory<byte> artifactClosureHash, int maximumChallenges,
        ulong windowStartUnixSeconds, CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken);
        await using (var cleanup = new NpgsqlCommand(
            "DELETE FROM production_mailbox_challenges WHERE expires_at < @now", connection, transaction))
        {
            cleanup.Parameters.AddWithValue("now", checked((long)nowUnixSeconds));
            await cleanup.ExecuteNonQueryAsync(cancellationToken);
        }
        await using var count = new NpgsqlCommand(
            "SELECT count(*) FROM production_mailbox_challenges WHERE created_at >= @window", connection, transaction);
        count.Parameters.AddWithValue("window", checked((long)windowStartUnixSeconds));
        if ((long)(await count.ExecuteScalarAsync(cancellationToken) ?? 0L) >= maximumChallenges) return null;
        var id = System.Security.Cryptography.RandomNumberGenerator.GetBytes(16);
        var challenge = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
        await using var insert = new NpgsqlCommand(
            "INSERT INTO production_mailbox_challenges(challenge_id, challenge, artifact_closure_hash, created_at, expires_at, used) VALUES(@id,@challenge,@closure,@now,@expires,false)",
            connection, transaction);
        insert.Parameters.AddWithValue("id", id); insert.Parameters.AddWithValue("challenge", challenge);
        insert.Parameters.AddWithValue("closure", artifactClosureHash.ToArray());
        insert.Parameters.AddWithValue("now", checked((long)nowUnixSeconds));
        insert.Parameters.AddWithValue("expires", checked((long)expiresAtUnixSeconds));
        await insert.ExecuteNonQueryAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return new(id, challenge, artifactClosureHash.ToArray(), expiresAtUnixSeconds);
    }

    public async ValueTask<ProductionMailboxIssuanceState?> ConsumeChallengeAndIssueAsync(
        ReadOnlyMemory<byte> challengeId, ReadOnlyMemory<byte> expectedChallenge,
        ulong nowUnixSeconds, ulong issuanceExpiresAtUnixSeconds,
        ReadOnlyMemory<byte> expectedArtifactClosureHash, ReadOnlyMemory<byte> idempotencyKey,
        Func<CancellationToken, ValueTask<byte[]>> createCanonicalResponse,
        CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken);
        await using (var cleanup = new NpgsqlCommand(
            "DELETE FROM production_mailbox_issuances WHERE expires_at < @now; DELETE FROM production_mailbox_challenges WHERE expires_at < @now",
            connection, transaction))
        {
            cleanup.Parameters.AddWithValue("now", checked((long)nowUnixSeconds));
            await cleanup.ExecuteNonQueryAsync(cancellationToken);
        }
        await using var consume = new NpgsqlCommand(
            "UPDATE production_mailbox_challenges SET used=true WHERE challenge_id=@id AND challenge=@challenge AND artifact_closure_hash=@closure AND used=false AND expires_at>=@now",
            connection, transaction);
        consume.Parameters.AddWithValue("id", challengeId.ToArray());
        consume.Parameters.AddWithValue("challenge", expectedChallenge.ToArray());
        consume.Parameters.AddWithValue("closure", expectedArtifactClosureHash.ToArray());
        consume.Parameters.AddWithValue("now", checked((long)nowUnixSeconds));
        if (await consume.ExecuteNonQueryAsync(cancellationToken) != 1) return null;
        await using var issuanceLock = new NpgsqlCommand(
            "SELECT pg_advisory_xact_lock(hashtextextended(encode(@key,'hex'),0))", connection, transaction);
        issuanceLock.Parameters.AddWithValue("key", idempotencyKey.ToArray());
        await issuanceLock.ExecuteNonQueryAsync(cancellationToken);
        await using var select = new NpgsqlCommand(
            "SELECT response FROM production_mailbox_issuances WHERE idempotency_key=@key", connection, transaction);
        select.Parameters.AddWithValue("key", idempotencyKey.ToArray());
        var existing = await select.ExecuteScalarAsync(cancellationToken) as byte[];
        if (existing is not null)
        {
            await transaction.CommitAsync(cancellationToken);
            return new(idempotencyKey.ToArray(), existing, true);
        }
        var created = await createCanonicalResponse(cancellationToken);
        await using var insert = new NpgsqlCommand(
            "INSERT INTO production_mailbox_issuances(idempotency_key,response,issued_at,expires_at) VALUES(@key,@response,@now,@expires)",
            connection, transaction);
        insert.Parameters.AddWithValue("key", idempotencyKey.ToArray());
        insert.Parameters.AddWithValue("response", created);
        insert.Parameters.AddWithValue("now", checked((long)nowUnixSeconds));
        insert.Parameters.AddWithValue("expires", checked((long)issuanceExpiresAtUnixSeconds));
        await insert.ExecuteNonQueryAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return new(idempotencyKey.ToArray(), created, false);
    }

    public async ValueTask<ProductionMailboxRouteEnrollmentState?> ConsumeChallengeAndEnrollAsync(
        ReadOnlyMemory<byte> challengeId, ReadOnlyMemory<byte> expectedChallenge,
        ulong nowUnixSeconds, ulong enrollmentExpiresAtUnixSeconds,
        ReadOnlyMemory<byte> expectedArtifactClosureHash,
        ReadOnlyMemory<byte> enrollmentStateKey, ReadOnlyMemory<byte> idempotencyKey,
        Func<CancellationToken, ValueTask<byte[]>> createCanonicalResponse,
        CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(
            IsolationLevel.ReadCommitted, cancellationToken);
        await PromotionGateLockAsync(connection, transaction, cancellationToken);
        await using (var activePromotion = new NpgsqlCommand(
            "SELECT EXISTS(SELECT 1 FROM production_mailbox_artifact_promotions WHERE published=false)",
            connection, transaction))
        {
            if ((bool)(await activePromotion.ExecuteScalarAsync(cancellationToken) ?? false))
            {
                await transaction.CommitAsync(cancellationToken);
                return null;
            }
        }
        if (!await ConsumeChallengeAsync(connection, transaction, challengeId,
                expectedChallenge, expectedArtifactClosureHash, nowUnixSeconds,
                cancellationToken))
            return null;
        await AdvisoryLocksAsync(connection, transaction,
            enrollmentStateKey, idempotencyKey, cancellationToken);
        var replaceExpiredEnrollment = false;
        await using (var select = new NpgsqlCommand(
            "SELECT enrollment_state_key,idempotency_key,response,expires_at FROM production_mailbox_route_enrollments WHERE idempotency_key=@key OR enrollment_state_key=@state ORDER BY enrollment_state_key FOR UPDATE",
            connection, transaction))
        {
            select.Parameters.AddWithValue("key", idempotencyKey.ToArray());
            select.Parameters.AddWithValue("state", enrollmentStateKey.ToArray());
            await using var reader = await select.ExecuteReaderAsync(cancellationToken);
            if (await reader.ReadAsync(cancellationToken))
            {
                var existingStateKey = reader.GetFieldValue<byte[]>(0);
                var existingIdempotencyKey = reader.GetFieldValue<byte[]>(1);
                var existingResponse = reader.GetFieldValue<byte[]>(2);
                var expiresAt = checked((ulong)reader.GetInt64(3));
                var exact = Fixed(existingStateKey, enrollmentStateKey.Span)
                    && Fixed(existingIdempotencyKey, idempotencyKey.Span);
                if (await reader.ReadAsync(cancellationToken) || !exact)
                    return null;
                if (expiresAt < nowUnixSeconds)
                {
                    replaceExpiredEnrollment = true;
                }
                else
                {
                    await reader.DisposeAsync();
                    await transaction.CommitAsync(cancellationToken);
                    return new(idempotencyKey.ToArray(), existingResponse, true);
                }
            }
        }
        if (replaceExpiredEnrollment)
        {
            await using var delete = new NpgsqlCommand(
                "DELETE FROM production_mailbox_route_enrollments WHERE enrollment_state_key=@state AND idempotency_key=@key AND expires_at<@now",
                connection, transaction);
            delete.Parameters.AddWithValue("state", enrollmentStateKey.ToArray());
            delete.Parameters.AddWithValue("key", idempotencyKey.ToArray());
            delete.Parameters.AddWithValue("now", checked((long)nowUnixSeconds));
            if (await delete.ExecuteNonQueryAsync(cancellationToken) != 1) return null;
        }
        var created = await createCanonicalResponse(cancellationToken);
        await using (var insert = new NpgsqlCommand(
            "INSERT INTO production_mailbox_route_enrollments(enrollment_state_key,idempotency_key,response,issued_at,expires_at) VALUES(@state,@key,@response,@now,@expires)",
            connection, transaction))
        {
            insert.Parameters.AddWithValue("state", enrollmentStateKey.ToArray());
            insert.Parameters.AddWithValue("key", idempotencyKey.ToArray());
            insert.Parameters.AddWithValue("response", created);
            insert.Parameters.AddWithValue("now", checked((long)nowUnixSeconds));
            insert.Parameters.AddWithValue("expires", checked((long)enrollmentExpiresAtUnixSeconds));
            await insert.ExecuteNonQueryAsync(cancellationToken);
        }
        await transaction.CommitAsync(cancellationToken);
        return new(idempotencyKey.ToArray(), created, false);
    }

    public async ValueTask<byte[]?> GetRouteEnrollmentAsync(
        ReadOnlyMemory<byte> enrollmentStateKey, CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = new NpgsqlCommand(
            "SELECT response FROM production_mailbox_route_enrollments WHERE enrollment_state_key=@key",
            connection);
        command.Parameters.AddWithValue("key", enrollmentStateKey.ToArray());
        return await command.ExecuteScalarAsync(cancellationToken) as byte[];
    }

    public async ValueTask<ProductionMailboxIssueCommitResult>
        ConsumeChallengeAcceptAdvertisementAndIssueAsync(
            ReadOnlyMemory<byte> challengeId, ReadOnlyMemory<byte> expectedChallenge,
            ulong nowUnixSeconds, ulong issuanceExpiresAtUnixSeconds,
            ReadOnlyMemory<byte> expectedArtifactClosureHash, ReadOnlyMemory<byte> idempotencyKey,
            ReadOnlyMemory<byte> requiredEnrollmentStateKey, ReadOnlyMemory<byte> routeDomainHash,
            ulong advertisementSequence, ReadOnlyMemory<byte> advertisementHash,
            Func<CancellationToken, ValueTask<ProductionMailboxPreparedIssue>> createPreparedIssue,
            CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(
            IsolationLevel.ReadCommitted, cancellationToken);
        await PromotionGateLockAsync(connection, transaction, cancellationToken);
        await using (var activePromotion = new NpgsqlCommand(
            "SELECT EXISTS(SELECT 1 FROM production_mailbox_artifact_promotions WHERE published=false)",
            connection, transaction))
        {
            if ((bool)(await activePromotion.ExecuteScalarAsync(cancellationToken) ?? false))
            {
                await transaction.CommitAsync(cancellationToken);
                return new(ProductionMailboxIssueCommitStatus.PromotionInProgress, null);
            }
        }
        if (!await ConsumeChallengeAsync(connection, transaction, challengeId,
                expectedChallenge, expectedArtifactClosureHash, nowUnixSeconds,
                cancellationToken))
            return new(ProductionMailboxIssueCommitStatus.InvalidChallenge, null);
        if (!requiredEnrollmentStateKey.IsEmpty)
        {
            await using var enrollment = new NpgsqlCommand(
                "SELECT EXISTS(SELECT 1 FROM production_mailbox_route_enrollments WHERE enrollment_state_key=@key AND expires_at>=@now)",
                connection, transaction);
            enrollment.Parameters.AddWithValue("key", requiredEnrollmentStateKey.ToArray());
            enrollment.Parameters.AddWithValue("now", checked((long)nowUnixSeconds));
            if (!(bool)(await enrollment.ExecuteScalarAsync(cancellationToken) ?? false))
            {
                await transaction.CommitAsync(cancellationToken);
                return new(ProductionMailboxIssueCommitStatus.EnrollmentMismatch, null);
            }
        }
        await AdvisoryLockAsync(connection, transaction, idempotencyKey, cancellationToken);
        var replaceExpiredIssue = false;
        byte[]? expiredAdvertisementHash = null;
        await using (var selectIssue = new NpgsqlCommand(
            "SELECT response,enrollment_state_key,advertisement_hash,expires_at FROM production_mailbox_issuances_v2 WHERE idempotency_key=@key FOR UPDATE",
            connection, transaction))
        {
            selectIssue.Parameters.AddWithValue("key", idempotencyKey.ToArray());
            await using var reader = await selectIssue.ExecuteReaderAsync(cancellationToken);
            if (await reader.ReadAsync(cancellationToken))
            {
                var response = reader.GetFieldValue<byte[]>(0);
                var enrollmentKey = reader.GetFieldValue<byte[]>(1);
                var acceptedAdvertisementHash = reader.GetFieldValue<byte[]>(2);
                var expiresAt = checked((ulong)reader.GetInt64(3));
                if (!Fixed(enrollmentKey, requiredEnrollmentStateKey.Span))
                    return new(ProductionMailboxIssueCommitStatus.IssuanceConflict, null);
                if (expiresAt < nowUnixSeconds)
                {
                    replaceExpiredIssue = true;
                    expiredAdvertisementHash = acceptedAdvertisementHash;
                }
                else
                {
                    if (!Fixed(acceptedAdvertisementHash, advertisementHash.Span))
                        return new(ProductionMailboxIssueCommitStatus.IssuanceConflict, null);
                    await reader.DisposeAsync();
                    await transaction.CommitAsync(cancellationToken);
                    return new(ProductionMailboxIssueCommitStatus.Replayed, response);
                }
            }
        }
        if (replaceExpiredIssue)
        {
            await using var delete = new NpgsqlCommand(
                "DELETE FROM production_mailbox_issuances_v2 WHERE idempotency_key=@key AND enrollment_state_key=@enrollment AND advertisement_hash=@advertisement AND expires_at<@now",
                connection, transaction);
            delete.Parameters.AddWithValue("key", idempotencyKey.ToArray());
            delete.Parameters.AddWithValue("enrollment", requiredEnrollmentStateKey.ToArray());
            delete.Parameters.AddWithValue("advertisement",
                expiredAdvertisementHash ?? throw new InvalidDataException(
                    "Expired production mailbox issuance lost its advertisement binding."));
            delete.Parameters.AddWithValue("now", checked((long)nowUnixSeconds));
            if (await delete.ExecuteNonQueryAsync(cancellationToken) != 1)
                return new(ProductionMailboxIssueCommitStatus.IssuanceConflict, null);
        }

        ulong? currentSequence = null;
        byte[]? currentHash = null;
        await using (var selectRoute = new NpgsqlCommand(
            "SELECT sequence_bytes,advertisement_hash FROM production_mailbox_route_advertisements WHERE route_domain_hash=@route FOR UPDATE",
            connection, transaction))
        {
            selectRoute.Parameters.AddWithValue("route", routeDomainHash.ToArray());
            await using var reader = await selectRoute.ExecuteReaderAsync(cancellationToken);
            if (await reader.ReadAsync(cancellationToken))
            {
                currentSequence = System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(
                    reader.GetFieldValue<byte[]>(0));
                currentHash = reader.GetFieldValue<byte[]>(1);
            }
        }
        if (!currentSequence.HasValue && advertisementSequence != 1)
        {
            await transaction.CommitAsync(cancellationToken);
            return new(ProductionMailboxIssueCommitStatus.AdvertisementConflict, null);
        }
        if (currentSequence.HasValue && advertisementSequence < currentSequence.Value)
        {
            await transaction.CommitAsync(cancellationToken);
            return new(ProductionMailboxIssueCommitStatus.AdvertisementRollback, null);
        }
        if (currentSequence == advertisementSequence && !Fixed(currentHash!, advertisementHash.Span))
        {
            await transaction.CommitAsync(cancellationToken);
            return new(ProductionMailboxIssueCommitStatus.AdvertisementConflict, null);
        }
        var prepared = await createPreparedIssue(cancellationToken);
        if (!currentSequence.HasValue)
        {
            await using var insertRoute = new NpgsqlCommand(
                "INSERT INTO production_mailbox_route_advertisements(route_domain_hash,sequence_bytes,advertisement_hash) VALUES(@route,@sequence,@hash)",
                connection, transaction);
            insertRoute.Parameters.AddWithValue("route", routeDomainHash.ToArray());
            insertRoute.Parameters.AddWithValue("sequence", U64(advertisementSequence));
            insertRoute.Parameters.AddWithValue("hash", advertisementHash.ToArray());
            await insertRoute.ExecuteNonQueryAsync(cancellationToken);
        }
        else if (advertisementSequence > currentSequence.Value)
        {
            await using var updateRoute = new NpgsqlCommand(
                "UPDATE production_mailbox_route_advertisements SET sequence_bytes=@sequence,advertisement_hash=@hash WHERE route_domain_hash=@route",
                connection, transaction);
            updateRoute.Parameters.AddWithValue("route", routeDomainHash.ToArray());
            updateRoute.Parameters.AddWithValue("sequence", U64(advertisementSequence));
            updateRoute.Parameters.AddWithValue("hash", advertisementHash.ToArray());
            await updateRoute.ExecuteNonQueryAsync(cancellationToken);
        }
        await using (var insertIssue = new NpgsqlCommand(
            "INSERT INTO production_mailbox_issuances_v2(idempotency_key,enrollment_state_key,advertisement_hash,response,issued_at,expires_at) VALUES(@key,@enrollment,@advertisement,@response,@now,@expires)",
            connection, transaction))
        {
            insertIssue.Parameters.AddWithValue("key", idempotencyKey.ToArray());
            insertIssue.Parameters.AddWithValue("enrollment", requiredEnrollmentStateKey.ToArray());
            insertIssue.Parameters.AddWithValue("advertisement", advertisementHash.ToArray());
            insertIssue.Parameters.AddWithValue("response", prepared.CanonicalResponse);
            insertIssue.Parameters.AddWithValue("now", checked((long)nowUnixSeconds));
            insertIssue.Parameters.AddWithValue("expires", checked((long)issuanceExpiresAtUnixSeconds));
            await insertIssue.ExecuteNonQueryAsync(cancellationToken);
        }
        if (prepared.OwnerRouteStateKey.Length != 0)
        {
            await using var ownerState = new NpgsqlCommand(
                "INSERT INTO production_mailbox_owner_route_state(route_state_key,canonical_bundle,updated_at) VALUES(@key,@bundle,@now) ON CONFLICT(route_state_key) DO UPDATE SET canonical_bundle=EXCLUDED.canonical_bundle,updated_at=EXCLUDED.updated_at",
                connection, transaction);
            ownerState.Parameters.AddWithValue("key", prepared.OwnerRouteStateKey);
            ownerState.Parameters.AddWithValue("bundle", prepared.CanonicalResponse);
            ownerState.Parameters.AddWithValue("now", checked((long)nowUnixSeconds));
            await ownerState.ExecuteNonQueryAsync(cancellationToken);
        }
        if (prepared.PublicationItems.Count != 0)
            await InsertPublicationAsync(
                connection, transaction, prepared.PublicationStateKey,
                System.Security.Cryptography.SHA256.HashData(prepared.CanonicalResponse),
                prepared.PublicationItems, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return new(ProductionMailboxIssueCommitStatus.Accepted,
            prepared.CanonicalResponse);
    }

    public async ValueTask<ProductionMailboxArtifactPromotionState>
        BeginArtifactPromotionAsync(
            ReadOnlyMemory<byte> promotionStateKey,
            ReadOnlyMemory<byte> oldArtifactClosureHash,
            ReadOnlyMemory<byte> newArtifactClosureHash,
            CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(
            IsolationLevel.Serializable, cancellationToken);
        await PromotionGateLockAsync(connection, transaction, cancellationToken);
        var publishedClosure = await EnsurePublishedArtifactClosureAsync(
            connection, transaction, oldArtifactClosureHash, cancellationToken);
        if (!Fixed(publishedClosure, oldArtifactClosureHash.Span))
            throw new InvalidOperationException(
                "Artifact promotion old closure is not the durable published closure.");
        var existing = await ReadPromotionAsync(
            connection, transaction, promotionStateKey, true, cancellationToken);
        if (existing is not null)
        {
            if (!Fixed(existing.OldArtifactClosureHash, oldArtifactClosureHash.Span)
                || !Fixed(existing.NewArtifactClosureHash, newArtifactClosureHash.Span))
                throw new InvalidDataException(
                    "Production mailbox artifact promotion replay conflicts.");
            await transaction.CommitAsync(cancellationToken);
            return existing;
        }
        await using (var active = new NpgsqlCommand(
            "SELECT EXISTS(SELECT 1 FROM production_mailbox_artifact_promotions WHERE published=false OR capacity_release_completed=false)",
            connection, transaction))
        {
            if ((bool)(await active.ExecuteScalarAsync(cancellationToken) ?? false))
                throw new InvalidOperationException(
                    "Another production mailbox artifact promotion is active.");
        }
        long watermark;
        await using (var ownerWatermark = new NpgsqlCommand(
            "SELECT COALESCE(max(owner_sequence),0) FROM production_mailbox_owner_route_state",
            connection, transaction))
            watermark = (long)(await ownerWatermark.ExecuteScalarAsync(cancellationToken) ?? 0L);
        await using (var insert = new NpgsqlCommand(
            "INSERT INTO production_mailbox_artifact_promotions(promotion_state_key,old_artifact_closure_hash,new_artifact_closure_hash,owner_watermark,cursor,sweep_completed,published,capacity_release_completed) VALUES(@key,@old,@new,@watermark,0,false,false,false)",
            connection, transaction))
        {
            insert.Parameters.AddWithValue("key", promotionStateKey.ToArray());
            insert.Parameters.AddWithValue("old", oldArtifactClosureHash.ToArray());
            insert.Parameters.AddWithValue("new", newArtifactClosureHash.ToArray());
            insert.Parameters.AddWithValue("watermark", watermark);
            await insert.ExecuteNonQueryAsync(cancellationToken);
        }
        await using (var capacity = new NpgsqlCommand(
            "INSERT INTO production_mailbox_capacity_plans(promotion_state_key,cursor,completed) VALUES(@key,0,false)",
            connection, transaction))
        {
            capacity.Parameters.AddWithValue("key", promotionStateKey.ToArray());
            await capacity.ExecuteNonQueryAsync(cancellationToken);
        }
        await transaction.CommitAsync(cancellationToken);
        return new(promotionStateKey.ToArray(), oldArtifactClosureHash.ToArray(),
            newArtifactClosureHash.ToArray(), watermark, 0, false, false, false);
    }

    public async ValueTask<ProductionMailboxArtifactPromotionState?>
        GetArtifactPromotionAsync(
            ReadOnlyMemory<byte> promotionStateKey,
            CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        return await ReadPromotionAsync(
            connection, null, promotionStateKey, false, cancellationToken);
    }

    public async ValueTask<ProductionMailboxArtifactPromotionState?>
        GetActiveArtifactPromotionAsync(CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = new NpgsqlCommand(
            "SELECT promotion_state_key,old_artifact_closure_hash,new_artifact_closure_hash,owner_watermark,cursor,sweep_completed,published,capacity_release_completed FROM production_mailbox_artifact_promotions WHERE published=false OR capacity_release_completed=false ORDER BY promotion_state_key LIMIT 2",
            connection);
        ProductionMailboxArtifactPromotionState? result = null;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            if (result is not null)
                throw new InvalidDataException(
                    "Multiple active production mailbox artifact promotions exist.");
            result = new(reader.GetFieldValue<byte[]>(0), reader.GetFieldValue<byte[]>(1),
                reader.GetFieldValue<byte[]>(2), reader.GetInt64(3), reader.GetInt64(4),
                reader.GetBoolean(5), reader.GetBoolean(6), reader.GetBoolean(7));
        }
        return result;
    }

    public async ValueTask<byte[]> GetOrInitializePublishedArtifactClosureAsync(
        ReadOnlyMemory<byte> initialArtifactClosureHash,
        CancellationToken cancellationToken)
    {
        if (initialArtifactClosureHash.Length != 32)
            throw new ArgumentException("Artifact closure hash must be 32 bytes.");
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(
            IsolationLevel.Serializable, cancellationToken);
        await PromotionGateLockAsync(connection, transaction, cancellationToken);
        var published = await EnsurePublishedArtifactClosureAsync(
            connection, transaction, initialArtifactClosureHash, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return published;
    }

    public async ValueTask<IReadOnlyList<ProductionMailboxOwnerBundleRecord>>
        ListOwnerBundlesForPromotionAsync(
            ReadOnlyMemory<byte> promotionStateKey,
            int maximumCount,
            CancellationToken cancellationToken)
    {
        if (maximumCount is < 1 or > 256)
            throw new ArgumentOutOfRangeException(nameof(maximumCount));
        await using var connection = await OpenAsync(cancellationToken);
        var promotion = await ReadPromotionAsync(
            connection, null, promotionStateKey, false, cancellationToken);
        if (promotion is null || promotion.Published) return [];
        await using var command = new NpgsqlCommand(
            "SELECT owner_sequence,route_state_key,canonical_bundle FROM production_mailbox_owner_route_state WHERE owner_sequence>@cursor AND owner_sequence<=@watermark ORDER BY owner_sequence LIMIT @limit",
            connection);
        command.Parameters.AddWithValue("cursor", promotion.Cursor);
        command.Parameters.AddWithValue("watermark", promotion.OwnerWatermark);
        command.Parameters.AddWithValue("limit", maximumCount);
        var output = new List<ProductionMailboxOwnerBundleRecord>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
            output.Add(new(reader.GetInt64(0), reader.GetFieldValue<byte[]>(1),
                reader.GetFieldValue<byte[]>(2)));
        return output;
    }

    public async ValueTask<IReadOnlyList<ProductionMailboxOwnerBundleRecord>>
        ListOwnerBundlesForCapacityPlanningAsync(
            ReadOnlyMemory<byte> promotionStateKey,
            int maximumCount,
            CancellationToken cancellationToken)
    {
        if (maximumCount is < 1 or > 256)
            throw new ArgumentOutOfRangeException(nameof(maximumCount));
        await using var connection = await OpenAsync(cancellationToken);
        long cursor;
        bool completed;
        await using (var plan = new NpgsqlCommand(
            "SELECT cursor,completed FROM production_mailbox_capacity_plans WHERE promotion_state_key=@key",
            connection))
        {
            plan.Parameters.AddWithValue("key", promotionStateKey.ToArray());
            await using var reader = await plan.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken)) return [];
            cursor = reader.GetInt64(0);
            completed = reader.GetBoolean(1);
        }
        if (completed) return [];
        var promotion = await ReadPromotionAsync(
            connection, null, promotionStateKey, false, cancellationToken);
        if (promotion is null || promotion.Published) return [];
        await using var command = new NpgsqlCommand(
            "SELECT owner_sequence,route_state_key,canonical_bundle FROM production_mailbox_owner_route_state WHERE owner_sequence>@cursor AND owner_sequence<=@watermark ORDER BY owner_sequence LIMIT @limit",
            connection);
        command.Parameters.AddWithValue("cursor", cursor);
        command.Parameters.AddWithValue("watermark", promotion.OwnerWatermark);
        command.Parameters.AddWithValue("limit", maximumCount);
        var output = new List<ProductionMailboxOwnerBundleRecord>();
        await using var owners = await command.ExecuteReaderAsync(cancellationToken);
        while (await owners.ReadAsync(cancellationToken))
            output.Add(new(owners.GetInt64(0), owners.GetFieldValue<byte[]>(1),
                owners.GetFieldValue<byte[]>(2)));
        return output;
    }

    public async ValueTask<bool> CommitCapacityPlannedOwnerAsync(
        ReadOnlyMemory<byte> promotionStateKey,
        ProductionMailboxOwnerBundleRecord expectedOwner,
        IReadOnlyList<ProductionMailboxPublicationItem> publicationItems,
        ulong perScheduleOverheadBytes,
        CancellationToken cancellationToken)
    {
        ValidatePublicationItems(publicationItems);
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(
            IsolationLevel.Serializable, cancellationToken);
        await PromotionGateLockAsync(connection, transaction, cancellationToken);
        var promotion = await ReadPromotionAsync(
            connection, transaction, promotionStateKey, true, cancellationToken);
        if (promotion is null || promotion.Published) return false;
        long cursor;
        bool completed;
        await using (var plan = new NpgsqlCommand(
            "SELECT cursor,completed FROM production_mailbox_capacity_plans WHERE promotion_state_key=@key FOR UPDATE",
            connection, transaction))
        {
            plan.Parameters.AddWithValue("key", promotionStateKey.ToArray());
            await using var reader = await plan.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken)) return false;
            cursor = reader.GetInt64(0);
            completed = reader.GetBoolean(1);
        }
        if (completed || expectedOwner.Sequence != cursor + 1
            || expectedOwner.Sequence > promotion.OwnerWatermark)
            return false;
        await using (var owner = new NpgsqlCommand(
            "SELECT route_state_key,canonical_bundle FROM production_mailbox_owner_route_state WHERE owner_sequence=@sequence FOR UPDATE",
            connection, transaction))
        {
            owner.Parameters.AddWithValue("sequence", expectedOwner.Sequence);
            await using var reader = await owner.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken)
                || !Fixed(reader.GetFieldValue<byte[]>(0), expectedOwner.RouteStateKey)
                || !Fixed(reader.GetFieldValue<byte[]>(1), expectedOwner.CanonicalBundle))
                return false;
        }
        foreach (var item in publicationItems)
        {
            if (!Fixed(item.ReservationCohortId, promotionStateKey.Span))
                return false;
            var charge = checked((ulong)item.CanonicalEnvelope.Length
                + 12UL + perScheduleOverheadBytes);
            if (charge > long.MaxValue) return false;
            long? existingCount = null;
            long? existingBytes = null;
            string? endpoint = null;
            byte[]? currentPin = null;
            byte[]? nextPin = null;
            await using (var select = new NpgsqlCommand(
                "SELECT endpoint,current_spki_sha256,next_spki_sha256,reserved_closure_count,reserved_bytes FROM production_mailbox_capacity_targets WHERE promotion_state_key=@promotion AND target_replica_id=@target FOR UPDATE",
                connection, transaction))
            {
                select.Parameters.AddWithValue("promotion", promotionStateKey.ToArray());
                select.Parameters.AddWithValue("target", item.TargetReplicaId);
                await using var reader = await select.ExecuteReaderAsync(cancellationToken);
                if (await reader.ReadAsync(cancellationToken))
                {
                    endpoint = reader.GetString(0);
                    currentPin = reader.GetFieldValue<byte[]>(1);
                    nextPin = reader.GetFieldValue<byte[]>(2);
                    existingCount = reader.GetInt64(3);
                    existingBytes = reader.GetInt64(4);
                }
            }
            if (existingCount.HasValue)
            {
                if (endpoint != item.Endpoint || !Fixed(currentPin!, item.CurrentSpkiSha256)
                    || !Fixed(nextPin!, item.NextSpkiSha256))
                    return false;
                var nextCount = checked(existingCount.Value + 1);
                var nextBytes = checked(existingBytes!.Value + checked((long)charge));
                await using var update = new NpgsqlCommand(
                    "UPDATE production_mailbox_capacity_targets SET reserved_closure_count=@count,reserved_bytes=@bytes WHERE promotion_state_key=@promotion AND target_replica_id=@target",
                    connection, transaction);
                update.Parameters.AddWithValue("count", nextCount);
                update.Parameters.AddWithValue("bytes", nextBytes);
                update.Parameters.AddWithValue("promotion", promotionStateKey.ToArray());
                update.Parameters.AddWithValue("target", item.TargetReplicaId);
                if (await update.ExecuteNonQueryAsync(cancellationToken) != 1)
                    return false;
            }
            else
            {
                await using var insert = new NpgsqlCommand(
                    "INSERT INTO production_mailbox_capacity_targets(promotion_state_key,target_replica_id,endpoint,current_spki_sha256,next_spki_sha256,reserved_closure_count,reserved_bytes,revision,receipt_expires_at,last_command_sha256,canonical_receipt,pending_canonical_command,pending_command_sha256,pending_revision,released) VALUES(@promotion,@target,@endpoint,@current,@next,1,@bytes,0,NULL,NULL,NULL,NULL,NULL,NULL,false)",
                    connection, transaction);
                insert.Parameters.AddWithValue("promotion", promotionStateKey.ToArray());
                insert.Parameters.AddWithValue("target", item.TargetReplicaId);
                insert.Parameters.AddWithValue("endpoint", item.Endpoint);
                insert.Parameters.AddWithValue("current", item.CurrentSpkiSha256);
                insert.Parameters.AddWithValue("next", item.NextSpkiSha256);
                insert.Parameters.AddWithValue("bytes", checked((long)charge));
                await insert.ExecuteNonQueryAsync(cancellationToken);
            }
        }
        await using (var updatePlan = new NpgsqlCommand(
            "UPDATE production_mailbox_capacity_plans SET cursor=@cursor WHERE promotion_state_key=@key AND cursor=@previous AND completed=false",
            connection, transaction))
        {
            updatePlan.Parameters.AddWithValue("cursor", expectedOwner.Sequence);
            updatePlan.Parameters.AddWithValue("key", promotionStateKey.ToArray());
            updatePlan.Parameters.AddWithValue("previous", cursor);
            if (await updatePlan.ExecuteNonQueryAsync(cancellationToken) != 1)
                return false;
        }
        await transaction.CommitAsync(cancellationToken);
        return true;
    }

    public async ValueTask<bool> CompleteCapacityPlanAsync(
        ReadOnlyMemory<byte> promotionStateKey,
        CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(
            IsolationLevel.Serializable, cancellationToken);
        await PromotionGateLockAsync(connection, transaction, cancellationToken);
        await using var update = new NpgsqlCommand(
            "UPDATE production_mailbox_capacity_plans p SET completed=true FROM production_mailbox_artifact_promotions a WHERE p.promotion_state_key=@key AND a.promotion_state_key=p.promotion_state_key AND a.published=false AND p.completed=false AND p.cursor>=a.owner_watermark",
            connection, transaction);
        update.Parameters.AddWithValue("key", promotionStateKey.ToArray());
        var changed = await update.ExecuteNonQueryAsync(cancellationToken) == 1;
        if (changed) await transaction.CommitAsync(cancellationToken);
        return changed;
    }

    public async ValueTask<bool> MarkArtifactPromotionCapacityReleasedAsync(
        ReadOnlyMemory<byte> promotionStateKey,
        CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(
            IsolationLevel.Serializable, cancellationToken);
        await PromotionGateLockAsync(connection, transaction, cancellationToken);
        await using var update = new NpgsqlCommand(
            "UPDATE production_mailbox_artifact_promotions a SET capacity_release_completed=true WHERE a.promotion_state_key=@key AND a.published=true AND a.capacity_release_completed=false AND NOT EXISTS(SELECT 1 FROM production_mailbox_capacity_targets t WHERE t.promotion_state_key=a.promotion_state_key AND t.released=false)",
            connection, transaction);
        update.Parameters.AddWithValue("key", promotionStateKey.ToArray());
        var changed = await update.ExecuteNonQueryAsync(cancellationToken) == 1;
        if (changed) await transaction.CommitAsync(cancellationToken);
        return changed;
    }

    public async ValueTask<ProductionMailboxCapacityPlanState?> GetCapacityPlanAsync(
        ReadOnlyMemory<byte> promotionStateKey,
        CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        long cursor;
        bool completed;
        await using (var plan = new NpgsqlCommand(
            "SELECT cursor,completed FROM production_mailbox_capacity_plans WHERE promotion_state_key=@key",
            connection))
        {
            plan.Parameters.AddWithValue("key", promotionStateKey.ToArray());
            await using var reader = await plan.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken)) return null;
            cursor = reader.GetInt64(0);
            completed = reader.GetBoolean(1);
        }
        var targets = new List<ProductionMailboxCapacityTargetState>();
        await using (var command = new NpgsqlCommand(
            "SELECT target_replica_id,endpoint,current_spki_sha256,next_spki_sha256,reserved_closure_count,reserved_bytes,revision,receipt_expires_at,last_command_sha256,canonical_receipt,pending_canonical_command,pending_revision,released FROM production_mailbox_capacity_targets WHERE promotion_state_key=@key ORDER BY target_replica_id",
            connection))
        {
            command.Parameters.AddWithValue("key", promotionStateKey.ToArray());
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
                targets.Add(new(reader.GetFieldValue<byte[]>(0), reader.GetString(1),
                    reader.GetFieldValue<byte[]>(2), reader.GetFieldValue<byte[]>(3),
                    checked((uint)reader.GetInt64(4)), checked((ulong)reader.GetInt64(5)),
                    checked((ulong)reader.GetInt64(6)), reader.IsDBNull(7) ? null
                        : checked((ulong)reader.GetInt64(7)),
                    reader.IsDBNull(8) ? null : reader.GetFieldValue<byte[]>(8),
                    reader.IsDBNull(9) ? null : reader.GetFieldValue<byte[]>(9),
                    reader.IsDBNull(10) ? null : reader.GetFieldValue<byte[]>(10),
                    reader.IsDBNull(11) ? null : checked((ulong)reader.GetInt64(11)),
                    reader.GetBoolean(12)));
        }
        return new(promotionStateKey.ToArray(), cursor, completed, targets);
    }

    public async ValueTask<bool> RecordCapacityReceiptAsync(
        ReadOnlyMemory<byte> promotionStateKey,
        ReadOnlyMemory<byte> targetReplicaId,
        ulong expectedPreviousRevision,
        ProductionMailboxCapacityReceipt receipt,
        ReadOnlyMemory<byte> canonicalReceipt,
        CancellationToken cancellationToken)
    {
        var receiptBytes = canonicalReceipt.ToArray();
        try
        {
            receipt = ProductionMailboxCapacityReceiptCodec.DecodeAndVerify(
                receiptBytes, targetReplicaId.Span);
        }
        catch (InvalidDataException)
        {
            return false;
        }
        if (!ProductionMailboxCapacityRevisionPolicy.IsStorableReceipt(receipt))
            return false;
        if (receipt.Revision != checked(expectedPreviousRevision + 1)
            || !Fixed(receipt.CohortId, promotionStateKey.Span)
            || !Fixed(receipt.TargetReplicaId, targetReplicaId.Span))
            return false;
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(
            IsolationLevel.Serializable, cancellationToken);
        await PromotionGateLockAsync(connection, transaction, cancellationToken);
        await using var update = new NpgsqlCommand(
            "UPDATE production_mailbox_capacity_targets t SET revision=@revision,receipt_expires_at=@expires,last_command_sha256=@command,canonical_receipt=@receipt,pending_canonical_command=NULL,pending_command_sha256=NULL,pending_revision=NULL,released=@released FROM production_mailbox_capacity_plans p WHERE t.promotion_state_key=@promotion AND p.promotion_state_key=t.promotion_state_key AND p.completed=true AND t.released=false AND t.target_replica_id=@target AND t.revision=@previous AND t.pending_revision=@revision AND t.pending_command_sha256=@command AND ((NOT @released AND t.reserved_closure_count=@count AND t.reserved_bytes=@bytes) OR (@released AND @count<=t.reserved_closure_count AND @bytes<=t.reserved_bytes))",
            connection, transaction);
        update.Parameters.AddWithValue("revision", checked((long)receipt.Revision));
        update.Parameters.AddWithValue("expires", checked((long)receipt.ExpiresAtUnixSeconds));
        update.Parameters.AddWithValue("command", receipt.CommandSha256);
        update.Parameters.AddWithValue("receipt", receiptBytes);
        update.Parameters.AddWithValue("released",
            receipt.Operation == ProductionMailboxCapacityOperation.Release);
        update.Parameters.AddWithValue("promotion", promotionStateKey.ToArray());
        update.Parameters.AddWithValue("target", targetReplicaId.ToArray());
        update.Parameters.AddWithValue("previous", checked((long)expectedPreviousRevision));
        update.Parameters.AddWithValue("count", checked((long)receipt.ReservedClosureCount));
        update.Parameters.AddWithValue("bytes", checked((long)receipt.ReservedBytes));
        var changed = await update.ExecuteNonQueryAsync(cancellationToken) == 1;
        if (changed) await transaction.CommitAsync(cancellationToken);
        return changed;
    }

    public async ValueTask<bool> RecordCapacityReconciliationReceiptAsync(
        ReadOnlyMemory<byte> promotionStateKey,
        ReadOnlyMemory<byte> targetReplicaId,
        ulong expectedRevision,
        ReadOnlyMemory<byte> expectedPendingReleaseCommand,
        ProductionMailboxCapacityReconciliationReceipt receipt,
        ReadOnlyMemory<byte> canonicalReceipt,
        CancellationToken cancellationToken)
    {
        var receiptBytes = canonicalReceipt.ToArray();
        try
        {
            receipt = ProductionMailboxCapacityReconciliationReceiptCodec.DecodeAndVerify(
                receiptBytes, targetReplicaId.Span);
        }
        catch (InvalidDataException)
        {
            return false;
        }
        if (receipt.Status != ProductionMailboxCapacityReconciliationStatus.AbsentTerminal
            || receipt.LastKnownRevision != expectedRevision
            || !Fixed(receipt.CohortId, promotionStateKey.Span)
            || !Fixed(receipt.TargetReplicaId, targetReplicaId.Span))
            return false;
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(
            IsolationLevel.Serializable, cancellationToken);
        await PromotionGateLockAsync(connection, transaction, cancellationToken);
        byte[]? priorCanonicalReceipt = null;
        byte[]? priorCommandHash = null;
        byte[]? pendingCanonicalCommand = null;
        long? currentRevision = null;
        long? pendingRevision = null;
        bool released = false;
        bool completed = false;
        await using (var select = new NpgsqlCommand(
            "SELECT t.canonical_receipt,t.last_command_sha256,t.revision,t.pending_revision,t.released,p.completed,t.pending_canonical_command FROM production_mailbox_capacity_targets t JOIN production_mailbox_capacity_plans p ON p.promotion_state_key=t.promotion_state_key WHERE t.promotion_state_key=@promotion AND t.target_replica_id=@target FOR UPDATE",
            connection, transaction))
        {
            select.Parameters.AddWithValue("promotion", promotionStateKey.ToArray());
            select.Parameters.AddWithValue("target", targetReplicaId.ToArray());
            await using var reader = await select.ExecuteReaderAsync(cancellationToken);
            if (await reader.ReadAsync(cancellationToken))
            {
                priorCanonicalReceipt = reader.IsDBNull(0)
                    ? null : reader.GetFieldValue<byte[]>(0);
                priorCommandHash = reader.IsDBNull(1)
                    ? null : reader.GetFieldValue<byte[]>(1);
                currentRevision = reader.GetInt64(2);
                pendingRevision = reader.IsDBNull(3) ? null : reader.GetInt64(3);
                released = reader.GetBoolean(4);
                completed = reader.GetBoolean(5);
                pendingCanonicalCommand = reader.IsDBNull(6)
                    ? null : reader.GetFieldValue<byte[]>(6);
            }
        }
        if (!completed || released
            || currentRevision != checked((long)expectedRevision)
            || pendingRevision != checked((long)(expectedRevision + 1))
            || pendingCanonicalCommand is null
            || !Fixed(pendingCanonicalCommand,
                expectedPendingReleaseCommand.Span)
            || priorCanonicalReceipt is null || priorCommandHash is null
            || !Fixed(receipt.LastReceiptSha256,
                System.Security.Cryptography.SHA256.HashData(priorCanonicalReceipt))
            || !Fixed(receipt.LastCommandSha256, priorCommandHash))
            return false;
        await using var update = new NpgsqlCommand(
            "UPDATE production_mailbox_capacity_targets SET release_reconciliation_receipt=@receipt,pending_canonical_command=NULL,pending_command_sha256=NULL,pending_revision=NULL,released=true WHERE promotion_state_key=@promotion AND target_replica_id=@target AND released=false AND revision=@revision AND pending_revision=@pending AND pending_canonical_command IS NOT NULL",
            connection, transaction);
        update.Parameters.AddWithValue("receipt", receiptBytes);
        update.Parameters.AddWithValue("promotion", promotionStateKey.ToArray());
        update.Parameters.AddWithValue("target", targetReplicaId.ToArray());
        update.Parameters.AddWithValue("revision", checked((long)expectedRevision));
        update.Parameters.AddWithValue("pending", checked((long)(expectedRevision + 1)));
        var changed = await update.ExecuteNonQueryAsync(cancellationToken) == 1;
        if (changed) await transaction.CommitAsync(cancellationToken);
        return changed;
    }

    public async ValueTask<byte[]?> GetOrRecordCapacityAttemptAsync(
        ReadOnlyMemory<byte> promotionStateKey,
        ReadOnlyMemory<byte> targetReplicaId,
        ulong expectedPreviousRevision,
        ulong attemptRevision,
        ReadOnlyMemory<byte> canonicalCommand,
        CancellationToken cancellationToken)
    {
        if (attemptRevision != checked(expectedPreviousRevision + 1)
            || attemptRevision
                > ProductionMailboxCapacityRevisionPolicy.MaximumStoredRevision)
            return null;
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(
            IsolationLevel.Serializable, cancellationToken);
        await PromotionGateLockAsync(connection, transaction, cancellationToken);
        byte[]? pending = null;
        long? pendingRevision = null;
        long? currentRevision = null;
        await using (var select = new NpgsqlCommand(
            "SELECT t.revision,t.pending_revision,t.pending_canonical_command FROM production_mailbox_capacity_targets t JOIN production_mailbox_capacity_plans p ON p.promotion_state_key=t.promotion_state_key WHERE t.promotion_state_key=@promotion AND t.target_replica_id=@target AND p.completed=true AND t.released=false FOR UPDATE",
            connection, transaction))
        {
            select.Parameters.AddWithValue("promotion", promotionStateKey.ToArray());
            select.Parameters.AddWithValue("target", targetReplicaId.ToArray());
            await using var reader = await select.ExecuteReaderAsync(cancellationToken);
            if (await reader.ReadAsync(cancellationToken))
            {
                currentRevision = reader.GetInt64(0);
                pendingRevision = reader.IsDBNull(1) ? null : reader.GetInt64(1);
                pending = reader.IsDBNull(2) ? null : reader.GetFieldValue<byte[]>(2);
            }
        }
        if (currentRevision != checked((long)expectedPreviousRevision)) return null;
        if (pending is not null)
        {
            if (pendingRevision != checked((long)attemptRevision))
                throw new InvalidDataException(
                    "Production mailbox capacity pending attempt is corrupt.");
            await transaction.CommitAsync(cancellationToken);
            return pending;
        }
        await using var update = new NpgsqlCommand(
            "UPDATE production_mailbox_capacity_targets SET pending_canonical_command=@command,pending_command_sha256=@hash,pending_revision=@revision WHERE promotion_state_key=@promotion AND target_replica_id=@target AND revision=@previous AND released=false AND pending_canonical_command IS NULL AND pending_revision IS NULL",
            connection, transaction);
        update.Parameters.AddWithValue("command", canonicalCommand.ToArray());
        update.Parameters.AddWithValue("hash",
            System.Security.Cryptography.SHA256.HashData(canonicalCommand.Span));
        update.Parameters.AddWithValue("revision", checked((long)attemptRevision));
        update.Parameters.AddWithValue("promotion", promotionStateKey.ToArray());
        update.Parameters.AddWithValue("target", targetReplicaId.ToArray());
        update.Parameters.AddWithValue("previous", checked((long)expectedPreviousRevision));
        if (await update.ExecuteNonQueryAsync(cancellationToken) != 1) return null;
        await transaction.CommitAsync(cancellationToken);
        return canonicalCommand.ToArray();
    }

    public async ValueTask<bool> CommitPromotedOwnerAsync(
        ReadOnlyMemory<byte> promotionStateKey,
        ProductionMailboxOwnerBundleRecord expectedOwner,
        ProductionMailboxPreparedIssue preparedIssue,
        ulong updatedAtUnixSeconds,
        uint capacityRenewalMarginSeconds,
        CancellationToken cancellationToken)
    {
        if (preparedIssue.PublicationItems.Count == 0
            || !Fixed(preparedIssue.OwnerRouteStateKey, expectedOwner.RouteStateKey))
            return false;
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(
            IsolationLevel.Serializable, cancellationToken);
        var capacityTransactionTimeoutMilliseconds = checked((int)Math.Max(1UL,
            Math.Min((ulong)int.MaxValue,
                (ulong)capacityRenewalMarginSeconds * 750UL)));
        await using (var timeout = new NpgsqlCommand(
            "SELECT set_config('statement_timeout',@timeout,true),set_config('lock_timeout',@timeout,true),set_config('idle_in_transaction_session_timeout',@timeout,true)",
            connection, transaction))
        {
            timeout.Parameters.AddWithValue("timeout",
                $"{capacityTransactionTimeoutMilliseconds}ms");
            await timeout.ExecuteNonQueryAsync(cancellationToken);
        }
        await PromotionGateLockAsync(connection, transaction, cancellationToken);
        var promotion = await ReadPromotionAsync(
            connection, transaction, promotionStateKey, true, cancellationToken);
        if (promotion is null || promotion.Published
            || expectedOwner.Sequence <= promotion.Cursor
            || expectedOwner.Sequence > promotion.OwnerWatermark)
            return false;
        await using (var capacity = new NpgsqlCommand(
            "SELECT p.completed AND NOT EXISTS(SELECT 1 FROM production_mailbox_capacity_targets t WHERE t.promotion_state_key=p.promotion_state_key AND (t.released OR t.canonical_receipt IS NULL OR t.pending_canonical_command IS NOT NULL OR t.pending_revision IS NOT NULL OR t.receipt_expires_at IS NULL OR t.receipt_expires_at<CAST(extract(epoch from clock_timestamp()) AS bigint)+@margin)) FROM production_mailbox_capacity_plans p WHERE p.promotion_state_key=@key FOR UPDATE",
            connection, transaction))
        {
            capacity.Parameters.AddWithValue("margin",
                checked((long)capacityRenewalMarginSeconds));
            capacity.Parameters.AddWithValue("key", promotionStateKey.ToArray());
            if (!(bool)(await capacity.ExecuteScalarAsync(cancellationToken) ?? false))
                return false;
        }
        long? nextSequence;
        byte[]? routeStateKey;
        byte[]? canonicalBundle;
        await using (var owner = new NpgsqlCommand(
            "SELECT owner_sequence,route_state_key,canonical_bundle FROM production_mailbox_owner_route_state WHERE owner_sequence>@cursor AND owner_sequence<=@watermark ORDER BY owner_sequence LIMIT 1 FOR UPDATE",
            connection, transaction))
        {
            owner.Parameters.AddWithValue("cursor", promotion.Cursor);
            owner.Parameters.AddWithValue("watermark", promotion.OwnerWatermark);
            await using var reader = await owner.ExecuteReaderAsync(cancellationToken);
            if (await reader.ReadAsync(cancellationToken))
            {
                nextSequence = reader.GetInt64(0);
                routeStateKey = reader.GetFieldValue<byte[]>(1);
                canonicalBundle = reader.GetFieldValue<byte[]>(2);
            }
            else
            {
                nextSequence = null;
                routeStateKey = null;
                canonicalBundle = null;
            }
        }
        if (nextSequence != expectedOwner.Sequence
            || !Fixed(routeStateKey!, expectedOwner.RouteStateKey)
            || !Fixed(canonicalBundle!, expectedOwner.CanonicalBundle))
            return false;
        await using (var updateOwner = new NpgsqlCommand(
            "UPDATE production_mailbox_owner_route_state SET canonical_bundle=@bundle,updated_at=@now WHERE owner_sequence=@sequence AND route_state_key=@key",
            connection, transaction))
        {
            updateOwner.Parameters.AddWithValue("bundle", preparedIssue.CanonicalResponse);
            updateOwner.Parameters.AddWithValue("now", checked((long)updatedAtUnixSeconds));
            updateOwner.Parameters.AddWithValue("sequence", expectedOwner.Sequence);
            updateOwner.Parameters.AddWithValue("key", expectedOwner.RouteStateKey);
            if (await updateOwner.ExecuteNonQueryAsync(cancellationToken) != 1) return false;
        }
        await InsertPublicationAsync(connection, transaction,
            preparedIssue.PublicationStateKey,
            System.Security.Cryptography.SHA256.HashData(preparedIssue.CanonicalResponse),
            preparedIssue.PublicationItems, cancellationToken);
        await using (var link = new NpgsqlCommand(
            "INSERT INTO production_mailbox_artifact_promotion_publications(promotion_state_key,publication_state_key) VALUES(@promotion,@publication)",
            connection, transaction))
        {
            link.Parameters.AddWithValue("promotion", promotionStateKey.ToArray());
            link.Parameters.AddWithValue("publication", preparedIssue.PublicationStateKey);
            await link.ExecuteNonQueryAsync(cancellationToken);
        }
        if (CommitPromotedOwnerDelayBeforeFinalCapacityCheck > TimeSpan.Zero)
            await Task.Delay(CommitPromotedOwnerDelayBeforeFinalCapacityCheck,
                cancellationToken);
        await using (var cursor = new NpgsqlCommand(
            "UPDATE production_mailbox_artifact_promotions a SET cursor=@cursor WHERE a.promotion_state_key=@key AND a.cursor=@oldCursor AND a.published=false AND EXISTS(SELECT 1 FROM production_mailbox_capacity_plans p WHERE p.promotion_state_key=a.promotion_state_key AND p.completed=true AND NOT EXISTS(SELECT 1 FROM production_mailbox_capacity_targets t WHERE t.promotion_state_key=p.promotion_state_key AND (t.released OR t.canonical_receipt IS NULL OR t.pending_canonical_command IS NOT NULL OR t.pending_revision IS NOT NULL OR t.receipt_expires_at IS NULL OR t.receipt_expires_at<CAST(extract(epoch from clock_timestamp()) AS bigint)+@margin)))",
            connection, transaction))
        {
            cursor.Parameters.AddWithValue("cursor", expectedOwner.Sequence);
            cursor.Parameters.AddWithValue("key", promotionStateKey.ToArray());
            cursor.Parameters.AddWithValue("oldCursor", promotion.Cursor);
            cursor.Parameters.AddWithValue("margin",
                checked((long)capacityRenewalMarginSeconds));
            if (await cursor.ExecuteNonQueryAsync(cancellationToken) != 1) return false;
        }
        await transaction.CommitAsync(cancellationToken);
        return true;
    }

    public async ValueTask<bool> CompleteArtifactPromotionSweepAsync(
        ReadOnlyMemory<byte> promotionStateKey,
        CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(
            IsolationLevel.Serializable, cancellationToken);
        await PromotionGateLockAsync(connection, transaction, cancellationToken);
        var promotion = await ReadPromotionAsync(
            connection, transaction, promotionStateKey, true, cancellationToken);
        if (promotion is null || promotion.Published) return false;
        await using var ready = new NpgsqlCommand(
            "SELECT NOT EXISTS(SELECT 1 FROM production_mailbox_owner_route_state WHERE owner_sequence>@cursor AND owner_sequence<=@watermark) AND NOT EXISTS(SELECT 1 FROM production_mailbox_artifact_promotion_publications m JOIN production_mailbox_publications p ON p.publication_state_key=m.publication_state_key WHERE m.promotion_state_key=@key AND p.completed=false)",
            connection, transaction);
        ready.Parameters.AddWithValue("cursor", promotion.Cursor);
        ready.Parameters.AddWithValue("watermark", promotion.OwnerWatermark);
        ready.Parameters.AddWithValue("key", promotionStateKey.ToArray());
        if (!(bool)(await ready.ExecuteScalarAsync(cancellationToken) ?? false)) return false;
        await using var update = new NpgsqlCommand(
            "UPDATE production_mailbox_artifact_promotions SET sweep_completed=true WHERE promotion_state_key=@key AND published=false",
            connection, transaction);
        update.Parameters.AddWithValue("key", promotionStateKey.ToArray());
        if (await update.ExecuteNonQueryAsync(cancellationToken) != 1) return false;
        await transaction.CommitAsync(cancellationToken);
        return true;
    }

    public async ValueTask<bool> MarkArtifactPromotionPublishedAsync(
        ReadOnlyMemory<byte> promotionStateKey,
        CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(
            IsolationLevel.Serializable, cancellationToken);
        await PromotionGateLockAsync(connection, transaction, cancellationToken);
        var promotion = await ReadPromotionAsync(
            connection, transaction, promotionStateKey, true, cancellationToken);
        if (promotion is null || !promotion.SweepCompleted) return false;
        await using (var active = new NpgsqlCommand(
            "UPDATE production_mailbox_artifact_active SET closure_hash=@new WHERE singleton=true AND closure_hash=@old",
            connection, transaction))
        {
            active.Parameters.AddWithValue("new", promotion.NewArtifactClosureHash);
            active.Parameters.AddWithValue("old", promotion.OldArtifactClosureHash);
            if (await active.ExecuteNonQueryAsync(cancellationToken) != 1) return false;
        }
        await using var update = new NpgsqlCommand(
            "UPDATE production_mailbox_artifact_promotions SET published=true WHERE promotion_state_key=@key AND sweep_completed=true AND published=false",
            connection, transaction);
        update.Parameters.AddWithValue("key", promotionStateKey.ToArray());
        var changed = await update.ExecuteNonQueryAsync(cancellationToken) == 1;
        if (changed) await transaction.CommitAsync(cancellationToken);
        return changed;
    }

    public async ValueTask<bool> IsHolderRevokedAsync(ReadOnlyMemory<byte> holderHash, CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = new NpgsqlCommand(
            "SELECT EXISTS(SELECT 1 FROM production_mailbox_revoked_holders WHERE holder_hash=@hash)", connection);
        command.Parameters.AddWithValue("hash", holderHash.ToArray());
        return (bool)(await command.ExecuteScalarAsync(cancellationToken) ?? false);
    }

    public async ValueTask RevokeHolderAsync(ReadOnlyMemory<byte> holderHash, ulong nowUnixSeconds, CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = new NpgsqlCommand(
            "INSERT INTO production_mailbox_revoked_holders(holder_hash,revoked_at) VALUES(@hash,@now) ON CONFLICT(holder_hash) DO NOTHING", connection);
        command.Parameters.AddWithValue("hash", holderHash.ToArray());
        command.Parameters.AddWithValue("now", checked((long)nowUnixSeconds));
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async ValueTask<ProductionMailboxPublicationState> PreparePublicationAsync(
        ReadOnlyMemory<byte> publicationStateKey,
        ReadOnlyMemory<byte> canonicalResponseSha256,
        IReadOnlyList<ProductionMailboxPublicationItem> items,
        CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(
            IsolationLevel.Serializable, cancellationToken);
        var existing = await ReadPublicationAsync(
            connection, transaction, publicationStateKey, cancellationToken);
        if (existing is not null)
        {
            if (!Fixed(existing.CanonicalResponseSha256, canonicalResponseSha256.Span)
                || !ExactPublicationItems(existing.Items, items))
                throw new InvalidDataException(
                    "Production mailbox publication replay conflicts with durable outbox state.");
            await transaction.CommitAsync(cancellationToken);
            return existing;
        }
        await InsertPublicationAsync(connection, transaction,
            publicationStateKey.ToArray(), canonicalResponseSha256.ToArray(), items,
            cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return await GetPublicationAsync(publicationStateKey, cancellationToken)
            ?? throw new InvalidOperationException(
                "Production mailbox publication was not durably stored.");
    }

    public async ValueTask<ProductionMailboxPublicationState?> GetPublicationAsync(
        ReadOnlyMemory<byte> publicationStateKey,
        CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        return await ReadPublicationAsync(
            connection, null, publicationStateKey, cancellationToken);
    }

    public async ValueTask<IReadOnlyList<byte[]>> ListPendingPublicationKeysAsync(
        int maximumCount, CancellationToken cancellationToken)
    {
        if (maximumCount is < 1 or > 256) throw new ArgumentOutOfRangeException(nameof(maximumCount));
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = new NpgsqlCommand(
            "SELECT publication_state_key FROM production_mailbox_publications WHERE completed=false ORDER BY publication_state_key LIMIT @limit",
            connection);
        command.Parameters.AddWithValue("limit", maximumCount);
        var keys = new List<byte[]>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
            keys.Add(reader.GetFieldValue<byte[]>(0));
        return keys;
    }

    public async ValueTask<bool> RecordPublicationAttemptAsync(
        ReadOnlyMemory<byte> publicationStateKey,
        ReadOnlyMemory<byte> targetStateKey,
        ReadOnlyMemory<byte> envelopeSha256,
        ReadOnlyMemory<byte> attemptSha256,
        ulong attemptedAtUnixSeconds,
        CancellationToken cancellationToken)
    {
        if (attemptSha256.Length != 32) return false;
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = new NpgsqlCommand(
            "UPDATE production_mailbox_publication_items SET last_attempt_sha256=@attempt,last_attempt_at=@now WHERE publication_state_key=@publication AND target_state_key=@target AND envelope_sha256=@envelope AND acknowledged=false",
            connection);
        command.Parameters.AddWithValue("attempt", attemptSha256.ToArray());
        command.Parameters.AddWithValue("now", checked((long)attemptedAtUnixSeconds));
        command.Parameters.AddWithValue("publication", publicationStateKey.ToArray());
        command.Parameters.AddWithValue("target", targetStateKey.ToArray());
        command.Parameters.AddWithValue("envelope", envelopeSha256.ToArray());
        return await command.ExecuteNonQueryAsync(cancellationToken) == 1;
    }

    public async ValueTask<bool> AcknowledgePublicationAsync(
        ReadOnlyMemory<byte> publicationStateKey,
        ReadOnlyMemory<byte> targetStateKey,
        ReadOnlyMemory<byte> envelopeSha256,
        ReadOnlyMemory<byte> attemptSha256,
        CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(
            IsolationLevel.Serializable, cancellationToken);
        await using var update = new NpgsqlCommand(
            "UPDATE production_mailbox_publication_items SET acknowledged=true WHERE publication_state_key=@publication AND target_state_key=@target AND envelope_sha256=@envelope AND last_attempt_sha256=@attempt AND acknowledged=false",
            connection, transaction);
        update.Parameters.AddWithValue("publication", publicationStateKey.ToArray());
        update.Parameters.AddWithValue("target", targetStateKey.ToArray());
        update.Parameters.AddWithValue("envelope", envelopeSha256.ToArray());
        update.Parameters.AddWithValue("attempt", attemptSha256.ToArray());
        if (await update.ExecuteNonQueryAsync(cancellationToken) != 1)
            return false;
        await using var pending = new NpgsqlCommand(
            "SELECT count(*) FROM production_mailbox_publication_items WHERE publication_state_key=@publication AND acknowledged=false",
            connection, transaction);
        pending.Parameters.AddWithValue("publication", publicationStateKey.ToArray());
        var completed = (long)(await pending.ExecuteScalarAsync(cancellationToken) ?? 1L) == 0;
        if (completed)
        {
            await using var mark = new NpgsqlCommand(
                "UPDATE production_mailbox_publications SET completed=true WHERE publication_state_key=@publication",
                connection, transaction);
            mark.Parameters.AddWithValue("publication", publicationStateKey.ToArray());
            await mark.ExecuteNonQueryAsync(cancellationToken);
        }
        await transaction.CommitAsync(cancellationToken);
        return completed;
    }

    public async ValueTask<ProductionMailboxRouteAdvertisementAcceptance> AcceptRouteAdvertisementAsync(
        ReadOnlyMemory<byte> routeDomainHash, ulong sequence,
        ReadOnlyMemory<byte> advertisementHash, CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(
            IsolationLevel.Serializable, cancellationToken);
        await using var select = new NpgsqlCommand(
            "SELECT sequence_bytes, advertisement_hash FROM production_mailbox_route_advertisements WHERE route_domain_hash=@route FOR UPDATE",
            connection, transaction);
        select.Parameters.AddWithValue("route", routeDomainHash.ToArray());
        byte[]? sequenceBytes = null;
        byte[]? currentHash = null;
        await using (var reader = await select.ExecuteReaderAsync(cancellationToken))
        {
            if (await reader.ReadAsync(cancellationToken))
            {
                sequenceBytes = reader.GetFieldValue<byte[]>(0);
                currentHash = reader.GetFieldValue<byte[]>(1);
            }
        }
        if (sequenceBytes is not null)
        {
            var currentSequence = System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(sequenceBytes);
            if (sequence < currentSequence)
                return ProductionMailboxRouteAdvertisementAcceptance.Rollback;
            if (sequence == currentSequence)
                return System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(
                    currentHash!, advertisementHash.Span)
                    ? ProductionMailboxRouteAdvertisementAcceptance.ExactReplay
                    : ProductionMailboxRouteAdvertisementAcceptance.Conflict;
            await using var update = new NpgsqlCommand(
                "UPDATE production_mailbox_route_advertisements SET sequence_bytes=@sequence, advertisement_hash=@hash WHERE route_domain_hash=@route",
                connection, transaction);
            update.Parameters.AddWithValue("route", routeDomainHash.ToArray());
            update.Parameters.AddWithValue("sequence", U64(sequence));
            update.Parameters.AddWithValue("hash", advertisementHash.ToArray());
            await update.ExecuteNonQueryAsync(cancellationToken);
        }
        else
        {
            await using var insert = new NpgsqlCommand(
                "INSERT INTO production_mailbox_route_advertisements(route_domain_hash,sequence_bytes,advertisement_hash) VALUES(@route,@sequence,@hash)",
                connection, transaction);
            insert.Parameters.AddWithValue("route", routeDomainHash.ToArray());
            insert.Parameters.AddWithValue("sequence", U64(sequence));
            insert.Parameters.AddWithValue("hash", advertisementHash.ToArray());
            await insert.ExecuteNonQueryAsync(cancellationToken);
        }
        await transaction.CommitAsync(cancellationToken);
        return ProductionMailboxRouteAdvertisementAcceptance.Accepted;
    }

    public async ValueTask<byte[]?> GetLatestOwnerBundleAsync(
        ReadOnlyMemory<byte> routeStateKey, CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = new NpgsqlCommand(
            "SELECT canonical_bundle FROM production_mailbox_owner_route_state WHERE route_state_key=@key",
            connection);
        command.Parameters.AddWithValue("key", routeStateKey.ToArray());
        return await command.ExecuteScalarAsync(cancellationToken) as byte[];
    }

    public async ValueTask StoreLatestOwnerBundleAsync(
        ReadOnlyMemory<byte> routeStateKey, ReadOnlyMemory<byte> canonicalBundle,
        ulong updatedAtUnixSeconds, CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = new NpgsqlCommand(
            "INSERT INTO production_mailbox_owner_route_state(route_state_key,canonical_bundle,updated_at) VALUES(@key,@bundle,@now) ON CONFLICT(route_state_key) DO UPDATE SET canonical_bundle=EXCLUDED.canonical_bundle,updated_at=EXCLUDED.updated_at",
            connection);
        command.Parameters.AddWithValue("key", routeStateKey.ToArray());
        command.Parameters.AddWithValue("bundle", canonicalBundle.ToArray());
        command.Parameters.AddWithValue("now", checked((long)updatedAtUnixSeconds));
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private async ValueTask<NpgsqlConnection> OpenAsync(CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(connectionString))
            throw new InvalidOperationException("Production mailbox PostgreSQL connection string is missing.");
        var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync(cancellationToken);
        if (!initialized) await InitializeAsync(connection, cancellationToken);
        return connection;
    }

    private async Task InitializeAsync(NpgsqlConnection connection, CancellationToken cancellationToken)
    {
        await initializeGate.WaitAsync(cancellationToken);
        try
        {
            if (initialized) return;
            const string sql = """
                CREATE TABLE IF NOT EXISTS production_mailbox_challenges(
                    challenge_id bytea PRIMARY KEY, challenge bytea NOT NULL, created_at bigint NOT NULL,
                    artifact_closure_hash bytea NOT NULL, expires_at bigint NOT NULL, used boolean NOT NULL);
                CREATE INDEX IF NOT EXISTS ix_production_mailbox_challenges_created_at
                    ON production_mailbox_challenges(created_at);
                CREATE TABLE IF NOT EXISTS production_mailbox_issuances(
                    idempotency_key bytea PRIMARY KEY, response bytea NOT NULL, issued_at bigint NOT NULL,
                    expires_at bigint NOT NULL);
                CREATE TABLE IF NOT EXISTS production_mailbox_route_enrollments(
                    enrollment_state_key bytea PRIMARY KEY, idempotency_key bytea UNIQUE NOT NULL,
                    response bytea NOT NULL, issued_at bigint NOT NULL, expires_at bigint NOT NULL);
                CREATE INDEX IF NOT EXISTS ix_production_mailbox_route_enrollments_expires_at
                    ON production_mailbox_route_enrollments(expires_at);
                CREATE TABLE IF NOT EXISTS production_mailbox_issuances_v2(
                    idempotency_key bytea PRIMARY KEY, enrollment_state_key bytea NOT NULL,
                    advertisement_hash bytea NOT NULL, response bytea NOT NULL,
                    issued_at bigint NOT NULL, expires_at bigint NOT NULL);
                CREATE TABLE IF NOT EXISTS production_mailbox_revoked_holders(
                    holder_hash bytea PRIMARY KEY, revoked_at bigint NOT NULL);
                CREATE TABLE IF NOT EXISTS production_mailbox_route_advertisements(
                    route_domain_hash bytea PRIMARY KEY, sequence_bytes bytea NOT NULL,
                    advertisement_hash bytea NOT NULL);
                CREATE SEQUENCE IF NOT EXISTS production_mailbox_owner_sequence;
                CREATE TABLE IF NOT EXISTS production_mailbox_owner_route_state(
                    route_state_key bytea PRIMARY KEY, canonical_bundle bytea NOT NULL,
                    owner_sequence bigint UNIQUE NOT NULL
                        DEFAULT nextval('production_mailbox_owner_sequence'),
                    updated_at bigint NOT NULL);
                ALTER TABLE production_mailbox_owner_route_state
                    ADD COLUMN IF NOT EXISTS owner_sequence bigint;
                ALTER TABLE production_mailbox_owner_route_state
                    ALTER COLUMN owner_sequence SET DEFAULT nextval('production_mailbox_owner_sequence');
                UPDATE production_mailbox_owner_route_state
                    SET owner_sequence=nextval('production_mailbox_owner_sequence')
                    WHERE owner_sequence IS NULL;
                ALTER TABLE production_mailbox_owner_route_state
                    ALTER COLUMN owner_sequence SET NOT NULL;
                CREATE UNIQUE INDEX IF NOT EXISTS ux_production_mailbox_owner_sequence
                    ON production_mailbox_owner_route_state(owner_sequence);
                CREATE TABLE IF NOT EXISTS production_mailbox_publications(
                    publication_state_key bytea PRIMARY KEY, response_sha256 bytea NOT NULL,
                    completed boolean NOT NULL);
                CREATE TABLE IF NOT EXISTS production_mailbox_publication_items(
                    publication_state_key bytea NOT NULL REFERENCES production_mailbox_publications(publication_state_key),
                    target_state_key bytea NOT NULL, target_replica_id bytea NOT NULL, endpoint text NOT NULL,
                    current_spki_sha256 bytea NOT NULL, next_spki_sha256 bytea NOT NULL,
                    authorized_legacy_replica_ids bytea NOT NULL,
                    canonical_envelope bytea NOT NULL, envelope_sha256 bytea NOT NULL,
                    reservation_cohort_id bytea NOT NULL,
                    last_attempt_sha256 bytea NULL, last_attempt_at bigint NULL,
                    acknowledged boolean NOT NULL,
                    PRIMARY KEY(publication_state_key,target_state_key));
                ALTER TABLE production_mailbox_publication_items
                    ADD COLUMN IF NOT EXISTS reservation_cohort_id bytea;
                UPDATE production_mailbox_publication_items
                    SET reservation_cohort_id=decode(repeat('00',32),'hex')
                    WHERE reservation_cohort_id IS NULL;
                ALTER TABLE production_mailbox_publication_items
                    ALTER COLUMN reservation_cohort_id SET NOT NULL;
                CREATE TABLE IF NOT EXISTS production_mailbox_artifact_promotions(
                    promotion_state_key bytea PRIMARY KEY,
                    old_artifact_closure_hash bytea NOT NULL,
                    new_artifact_closure_hash bytea NOT NULL,
                    owner_watermark bigint NOT NULL,
                    cursor bigint NOT NULL,
                    sweep_completed boolean NOT NULL,
                    published boolean NOT NULL,
                    capacity_release_completed boolean NOT NULL DEFAULT false);
                ALTER TABLE production_mailbox_artifact_promotions
                    ADD COLUMN IF NOT EXISTS capacity_release_completed boolean NOT NULL DEFAULT false;
                CREATE TABLE IF NOT EXISTS production_mailbox_capacity_plans(
                    promotion_state_key bytea PRIMARY KEY
                        REFERENCES production_mailbox_artifact_promotions(promotion_state_key),
                    cursor bigint NOT NULL,
                    completed boolean NOT NULL);
                CREATE TABLE IF NOT EXISTS production_mailbox_capacity_targets(
                    promotion_state_key bytea NOT NULL
                        REFERENCES production_mailbox_capacity_plans(promotion_state_key),
                    target_replica_id bytea NOT NULL,
                    endpoint text NOT NULL,
                    current_spki_sha256 bytea NOT NULL,
                    next_spki_sha256 bytea NOT NULL,
                    reserved_closure_count bigint NOT NULL,
                    reserved_bytes bigint NOT NULL,
                    revision bigint NOT NULL,
                    receipt_expires_at bigint NULL,
                    last_command_sha256 bytea NULL,
                    canonical_receipt bytea NULL,
                    pending_canonical_command bytea NULL,
                    pending_command_sha256 bytea NULL,
                    pending_revision bigint NULL,
                    release_reconciliation_receipt bytea NULL,
                    released boolean NOT NULL,
                    PRIMARY KEY(promotion_state_key,target_replica_id));
                ALTER TABLE production_mailbox_capacity_targets
                    ADD COLUMN IF NOT EXISTS release_reconciliation_receipt bytea NULL;
                CREATE INDEX IF NOT EXISTS ix_production_mailbox_artifact_promotions_active
                    ON production_mailbox_artifact_promotions(published,capacity_release_completed);
                CREATE TABLE IF NOT EXISTS production_mailbox_artifact_active(
                    singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
                    closure_hash bytea NOT NULL CHECK(octet_length(closure_hash)=32));
                CREATE TABLE IF NOT EXISTS production_mailbox_artifact_promotion_publications(
                    promotion_state_key bytea NOT NULL REFERENCES production_mailbox_artifact_promotions(promotion_state_key),
                    publication_state_key bytea NOT NULL REFERENCES production_mailbox_publications(publication_state_key),
                    PRIMARY KEY(promotion_state_key,publication_state_key));
                """;
            await using var command = new NpgsqlCommand(sql, connection);
            await command.ExecuteNonQueryAsync(cancellationToken);
            initialized = true;
        }
        finally { initializeGate.Release(); }
    }

    private static async ValueTask<bool> ConsumeChallengeAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction,
        ReadOnlyMemory<byte> challengeId, ReadOnlyMemory<byte> expectedChallenge,
        ReadOnlyMemory<byte> expectedArtifactClosureHash, ulong nowUnixSeconds,
        CancellationToken cancellationToken)
    {
        await using var consume = new NpgsqlCommand(
            "UPDATE production_mailbox_challenges SET used=true WHERE challenge_id=@id AND challenge=@challenge AND artifact_closure_hash=@closure AND used=false AND expires_at>=@now",
            connection, transaction);
        consume.Parameters.AddWithValue("id", challengeId.ToArray());
        consume.Parameters.AddWithValue("challenge", expectedChallenge.ToArray());
        consume.Parameters.AddWithValue("closure", expectedArtifactClosureHash.ToArray());
        consume.Parameters.AddWithValue("now", checked((long)nowUnixSeconds));
        return await consume.ExecuteNonQueryAsync(cancellationToken) == 1;
    }

    private static async ValueTask PromotionGateLockAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction,
        CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand(
            "SELECT pg_advisory_xact_lock(6075994319133652301)",
            connection, transaction);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async ValueTask<byte[]> EnsurePublishedArtifactClosureAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        ReadOnlyMemory<byte> initialArtifactClosureHash,
        CancellationToken cancellationToken)
    {
        await using (var insert = new NpgsqlCommand(
            "INSERT INTO production_mailbox_artifact_active(singleton,closure_hash) VALUES(true,@hash) ON CONFLICT(singleton) DO NOTHING",
            connection, transaction))
        {
            insert.Parameters.AddWithValue("hash", initialArtifactClosureHash.ToArray());
            await insert.ExecuteNonQueryAsync(cancellationToken);
        }
        await using var select = new NpgsqlCommand(
            "SELECT closure_hash FROM production_mailbox_artifact_active WHERE singleton=true FOR UPDATE",
            connection, transaction);
        return await select.ExecuteScalarAsync(cancellationToken) as byte[]
            ?? throw new InvalidDataException(
                "Published production mailbox artifact closure state is unavailable.");
    }

    private static async ValueTask<ProductionMailboxArtifactPromotionState?>
        ReadPromotionAsync(
            NpgsqlConnection connection, NpgsqlTransaction? transaction,
            ReadOnlyMemory<byte> promotionStateKey, bool forUpdate,
            CancellationToken cancellationToken)
    {
        var sql = "SELECT old_artifact_closure_hash,new_artifact_closure_hash,owner_watermark,cursor,sweep_completed,published,capacity_release_completed FROM production_mailbox_artifact_promotions WHERE promotion_state_key=@key"
            + (forUpdate ? " FOR UPDATE" : string.Empty);
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue("key", promotionStateKey.ToArray());
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken)) return null;
        return new(promotionStateKey.ToArray(), reader.GetFieldValue<byte[]>(0),
            reader.GetFieldValue<byte[]>(1), reader.GetInt64(2), reader.GetInt64(3),
            reader.GetBoolean(4), reader.GetBoolean(5), reader.GetBoolean(6));
    }

    private static async ValueTask AdvisoryLockAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction,
        ReadOnlyMemory<byte> idempotencyKey, CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand(
            "SELECT pg_advisory_xact_lock(hashtextextended(encode(@key,'hex'),0))",
            connection, transaction);
        command.Parameters.AddWithValue("key", idempotencyKey.ToArray());
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async ValueTask AdvisoryLocksAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction,
        ReadOnlyMemory<byte> firstKey, ReadOnlyMemory<byte> secondKey,
        CancellationToken cancellationToken)
    {
        var keys = new[] { firstKey.ToArray(), secondKey.ToArray() }
            .Distinct(ByteArrayComparer.Instance)
            .OrderBy(static key => Convert.ToHexString(key), StringComparer.Ordinal);
        foreach (var key in keys)
            await AdvisoryLockAsync(connection, transaction, key, cancellationToken);
    }

    private sealed class ByteArrayComparer : IEqualityComparer<byte[]>
    {
        internal static ByteArrayComparer Instance { get; } = new();

        public bool Equals(byte[]? left, byte[]? right) =>
            ReferenceEquals(left, right)
            || left is not null && right is not null && Fixed(left, right);

        public int GetHashCode(byte[] value)
        {
            var hash = new HashCode();
            hash.AddBytes(value);
            return hash.ToHashCode();
        }
    }

    private static async ValueTask InsertPublicationAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction,
        byte[] publicationStateKey, byte[] canonicalResponseSha256,
        IReadOnlyList<ProductionMailboxPublicationItem> items,
        CancellationToken cancellationToken)
    {
        ValidatePublicationItems(items);
        await using (var publication = new NpgsqlCommand(
            "INSERT INTO production_mailbox_publications(publication_state_key,response_sha256,completed) VALUES(@key,@hash,false)",
            connection, transaction))
        {
            publication.Parameters.AddWithValue("key", publicationStateKey);
            publication.Parameters.AddWithValue("hash", canonicalResponseSha256);
            await publication.ExecuteNonQueryAsync(cancellationToken);
        }
        foreach (var item in items)
        {
            await using var insert = new NpgsqlCommand(
                "INSERT INTO production_mailbox_publication_items(publication_state_key,target_state_key,target_replica_id,endpoint,current_spki_sha256,next_spki_sha256,authorized_legacy_replica_ids,canonical_envelope,envelope_sha256,reservation_cohort_id,last_attempt_sha256,last_attempt_at,acknowledged) VALUES(@publication,@target,@replica,@endpoint,@currentSpki,@nextSpki,@legacy,@envelope,@envelopeHash,@cohort,@attempt,@attemptAt,@acknowledged)",
                connection, transaction);
            insert.Parameters.AddWithValue("publication", publicationStateKey);
            insert.Parameters.AddWithValue("target", item.TargetStateKey);
            insert.Parameters.AddWithValue("replica", item.TargetReplicaId);
            insert.Parameters.AddWithValue("endpoint", item.Endpoint);
            insert.Parameters.AddWithValue("currentSpki", item.CurrentSpkiSha256);
            insert.Parameters.AddWithValue("nextSpki", item.NextSpkiSha256);
            insert.Parameters.AddWithValue("legacy", Flatten(item.AuthorizedLegacyReplicaIds));
            insert.Parameters.AddWithValue("envelope", item.CanonicalEnvelope);
            insert.Parameters.AddWithValue("envelopeHash", item.EnvelopeSha256);
            insert.Parameters.AddWithValue("cohort", item.ReservationCohortId);
            insert.Parameters.AddWithValue("attempt", (object?)item.LastAttemptSha256 ?? DBNull.Value);
            insert.Parameters.AddWithValue("attemptAt", item.LastAttemptAtUnixSeconds.HasValue
                ? checked((long)item.LastAttemptAtUnixSeconds.Value) : DBNull.Value);
            insert.Parameters.AddWithValue("acknowledged", item.Acknowledged);
            await insert.ExecuteNonQueryAsync(cancellationToken);
        }
    }

    private static async ValueTask<ProductionMailboxPublicationState?> ReadPublicationAsync(
        NpgsqlConnection connection, NpgsqlTransaction? transaction,
        ReadOnlyMemory<byte> publicationStateKey,
        CancellationToken cancellationToken)
    {
        byte[]? responseHash = null;
        var completed = false;
        await using (var publication = new NpgsqlCommand(
            "SELECT response_sha256,completed FROM production_mailbox_publications WHERE publication_state_key=@key",
            connection, transaction))
        {
            publication.Parameters.AddWithValue("key", publicationStateKey.ToArray());
            await using var reader = await publication.ExecuteReaderAsync(cancellationToken);
            if (await reader.ReadAsync(cancellationToken))
            {
                responseHash = reader.GetFieldValue<byte[]>(0);
                completed = reader.GetBoolean(1);
            }
        }
        if (responseHash is null) return null;
        var items = new List<ProductionMailboxPublicationItem>();
        await using (var command = new NpgsqlCommand(
            "SELECT target_state_key,target_replica_id,endpoint,current_spki_sha256,next_spki_sha256,authorized_legacy_replica_ids,canonical_envelope,envelope_sha256,reservation_cohort_id,last_attempt_sha256,last_attempt_at,acknowledged FROM production_mailbox_publication_items WHERE publication_state_key=@key ORDER BY target_state_key",
            connection, transaction))
        {
            command.Parameters.AddWithValue("key", publicationStateKey.ToArray());
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
                items.Add(new(
                    reader.GetFieldValue<byte[]>(0), reader.GetFieldValue<byte[]>(1),
                    reader.GetString(2), reader.GetFieldValue<byte[]>(3),
                    reader.GetFieldValue<byte[]>(4), Split(reader.GetFieldValue<byte[]>(5)),
                    reader.GetFieldValue<byte[]>(6), reader.GetFieldValue<byte[]>(7),
                    reader.GetFieldValue<byte[]>(8),
                    reader.IsDBNull(9) ? null : reader.GetFieldValue<byte[]>(9),
                    reader.IsDBNull(10) ? null : checked((ulong)reader.GetInt64(10)),
                    reader.GetBoolean(11)));
        }
        return new(publicationStateKey.ToArray(), responseHash, items, completed);
    }

    private static bool ExactPublicationItems(
        IReadOnlyList<ProductionMailboxPublicationItem> left,
        IReadOnlyList<ProductionMailboxPublicationItem> right)
    {
        ValidatePublicationItems(right);
        var ordered = right.OrderBy(
            static item => Convert.ToHexString(item.TargetStateKey),
            StringComparer.Ordinal).ToArray();
        return left.Count == ordered.Length && left.Zip(ordered).All(pair =>
            Fixed(pair.First.TargetStateKey, pair.Second.TargetStateKey)
            && Fixed(pair.First.TargetReplicaId, pair.Second.TargetReplicaId)
            && pair.First.Endpoint == pair.Second.Endpoint
            && Fixed(pair.First.CurrentSpkiSha256, pair.Second.CurrentSpkiSha256)
            && Fixed(pair.First.NextSpkiSha256, pair.Second.NextSpkiSha256)
            && ExactByteLists(pair.First.AuthorizedLegacyReplicaIds,
                pair.Second.AuthorizedLegacyReplicaIds)
            && Fixed(pair.First.CanonicalEnvelope, pair.Second.CanonicalEnvelope)
            && Fixed(pair.First.EnvelopeSha256, pair.Second.EnvelopeSha256)
            && Fixed(pair.First.ReservationCohortId,
                pair.Second.ReservationCohortId));
    }

    private static void ValidatePublicationItems(
        IReadOnlyList<ProductionMailboxPublicationItem> items)
    {
        if (items.Count is < 1 or > 8
            || items.Any(item => item.TargetStateKey.Length != 32
                || item.TargetReplicaId.Length != 32
                || item.CurrentSpkiSha256.Length != 32
                || item.NextSpkiSha256.Length != 32
                || item.EnvelopeSha256.Length != 32
                || item.ReservationCohortId.Length != 32
                || item.CanonicalEnvelope.Length == 0
                || !Fixed(System.Security.Cryptography.SHA256.HashData(
                    item.CanonicalEnvelope), item.EnvelopeSha256)
                || item.AuthorizedLegacyReplicaIds.Count > 2
                || item.AuthorizedLegacyReplicaIds.Any(static value => value.Length != 32)
                || item.LastAttemptSha256 is { Length: not 32 }
                || !Uri.TryCreate(item.Endpoint, UriKind.Absolute, out var endpoint)
                || endpoint.Scheme != Uri.UriSchemeHttps || endpoint.PathAndQuery != "/")
            || items.Select(item => Convert.ToHexString(item.TargetStateKey))
                .Distinct(StringComparer.Ordinal).Count() != items.Count)
            throw new InvalidDataException(
                "Production mailbox publication target is invalid.");
    }

    private static bool ExactByteLists(
        IReadOnlyList<byte[]> left, IReadOnlyList<byte[]> right) =>
        left.Count == right.Count && left.Zip(right).All(pair =>
            Fixed(pair.First, pair.Second));

    private static byte[] Flatten(IReadOnlyList<byte[]> values)
    {
        if (values.Count > 2 || values.Any(static value => value.Length != 32))
            throw new InvalidDataException("Production mailbox legacy replica list is invalid.");
        var output = new byte[values.Count * 32];
        for (var index = 0; index < values.Count; index++)
            values[index].CopyTo(output.AsSpan(index * 32));
        return output;
    }

    private static IReadOnlyList<byte[]> Split(byte[] value)
    {
        if (value.Length % 32 != 0 || value.Length > 64)
            throw new InvalidDataException("Stored production mailbox legacy replica list is invalid.");
        return Enumerable.Range(0, value.Length / 32)
            .Select(index => value.AsSpan(index * 32, 32).ToArray()).ToArray();
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length
        && System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(left, right);

    private static byte[] U64(ulong value)
    {
        var bytes = new byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(bytes, value);
        return bytes;
    }
}
