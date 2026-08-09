using System.Buffers.Binary;
using System.Data;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxTopology;
using Npgsql;
using Sodium;

namespace Deep.Registry.Api.ProductionMailbox;

internal enum ProductionMailboxV2ActivationCommitStatus
{
    Accepted,
    ExactReplay,
    MissingSource,
    SourceChanged,
    Conflict,
    Expired,
    Incomplete,
    Published
}

internal sealed class ProductionMailboxV2ActivationPlan
{
    private readonly byte[] activationStateKey;
    private readonly byte[] promotionStateKey;
    private readonly byte[] cohortId;
    private readonly byte[] routeStateKey;
    private readonly byte[] publisherPublicKey;

    private ProductionMailboxV2ActivationPlan(
        byte[] activationStateKey, byte[] promotionStateKey, byte[] cohortId,
        byte[] routeStateKey, byte[] publisherPublicKey,
        ProductionMailboxV2PreparedCache verifiedCache)
    {
        this.activationStateKey = activationStateKey;
        this.promotionStateKey = promotionStateKey;
        this.cohortId = cohortId;
        this.routeStateKey = routeStateKey;
        this.publisherPublicKey = publisherPublicKey;
        VerifiedCache = verifiedCache;
    }

    internal static ProductionMailboxV2ActivationPlan Create(
        ReadOnlyMemory<byte> activationStateKey,
        ReadOnlyMemory<byte> promotionStateKey,
        ReadOnlyMemory<byte> cohortId,
        ReadOnlyMemory<byte> publisherPublicKey,
        ProductionMailboxRouteContinuityStateSnapshot source,
        ProductionMailboxV2PreparedCache verifiedCache)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(verifiedCache);
        static byte[] Key(ReadOnlyMemory<byte> value, string name)
        {
            if (value.Length != 32 || value.Span.IndexOfAnyExcept((byte)0) < 0)
                throw new InvalidDataException($"PMC2 {name} is invalid.");
            return value.ToArray();
        }
        var routeStateKey = Key(source.RouteStateKey, "route-state key");
        if (!Fixed(ProductionMailboxV2SourceFingerprint.Compute(source),
                verifiedCache.SourceFingerprint.Span))
            throw new InvalidDataException("PMC2 source snapshot changed during verification.");
        if (verifiedCache.CacheExpiresAtUnixSeconds <= verifiedCache.VerifiedAtUnixSeconds)
            throw new InvalidDataException("PMC2 verified cache window is invalid.");
        var activation = Key(activationStateKey, "activation key");
        var promotion = Key(promotionStateKey, "promotion key");
        var cohort = Key(cohortId, "cohort ID");
        var publisher = Key(publisherPublicKey, "publisher public key");
        return new(activation, promotion, cohort, routeStateKey, publisher, verifiedCache);
    }

    internal ReadOnlyMemory<byte> ActivationStateKey => activationStateKey.ToArray();
    internal ReadOnlyMemory<byte> PromotionStateKey => promotionStateKey.ToArray();
    internal ReadOnlyMemory<byte> CohortId => cohortId.ToArray();
    internal ReadOnlyMemory<byte> RouteStateKey => routeStateKey.ToArray();
    internal ReadOnlyMemory<byte> PublisherPublicKey => publisherPublicKey.ToArray();
    internal ProductionMailboxV2PreparedCache VerifiedCache { get; }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

}

internal sealed class ProductionMailboxV2ActivationState
{
    private readonly byte[] activationStateKey;
    private readonly byte[] promotionStateKey;
    private readonly byte[] cohortId;
    private readonly byte[] routeStateKey;
    private readonly byte[] sourceFingerprint;
    private readonly byte[] routeOriginLkgHash;
    private readonly byte[] routeHistoryCheckpointHash;
    private readonly byte[] transitionTranscriptHash;
    private readonly byte[] publisherPublicKey;
    private readonly byte[] verifiedPlanSignature;
    private readonly byte[] preparedIntegrityTag;
    private readonly byte[] phaseIntegrityTag;
    private readonly byte[] cacheSalt;
    private readonly byte[] cacheTranscriptHash;
    private readonly byte[] canonicalEnvelope;
    private readonly byte[] envelopeSha256;
    private readonly byte[] lineageCommitment;
    private readonly byte[] selectionInputCommitment;
    private readonly byte[] durableOldSelectionHash;
    private readonly ProductionMailboxV2ActivationTargetState[] targets;

    internal ProductionMailboxV2ActivationState(
        byte[] activationStateKey, byte[] promotionStateKey, byte[] cohortId,
        byte[] routeStateKey, byte[] sourceFingerprint, ulong sourceLocalCommitGeneration,
        byte[] routeOriginLkgHash, byte[] routeHistoryCheckpointHash,
        byte[] transitionTranscriptHash, byte[] publisherPublicKey,
        byte[] verifiedPlanSignature, byte[] preparedIntegrityTag,
        byte[] phaseIntegrityTag,
        byte[] cacheSalt, byte[] cacheTranscriptHash,
        ulong verifiedAtUnixSeconds, ulong cacheExpiresAtUnixSeconds,
        ProductionMailboxSelectionSuccessorMode mode,
        ProductionMailboxRouteAuthorizationKind authorizationKind,
        byte[] canonicalEnvelope, byte[] envelopeSha256, byte[] lineageCommitment,
        byte[] selectionInputCommitment, byte[] durableOldSelectionHash,
        IReadOnlyList<ProductionMailboxV2ActivationTargetState> targets, bool published)
    {
        this.activationStateKey = activationStateKey.ToArray();
        this.promotionStateKey = promotionStateKey.ToArray();
        this.cohortId = cohortId.ToArray();
        this.routeStateKey = routeStateKey.ToArray();
        this.sourceFingerprint = sourceFingerprint.ToArray();
        SourceLocalCommitGeneration = sourceLocalCommitGeneration;
        this.routeOriginLkgHash = routeOriginLkgHash.ToArray();
        this.routeHistoryCheckpointHash = routeHistoryCheckpointHash.ToArray();
        this.transitionTranscriptHash = transitionTranscriptHash.ToArray();
        this.publisherPublicKey = publisherPublicKey.ToArray();
        this.verifiedPlanSignature = verifiedPlanSignature.ToArray();
        this.preparedIntegrityTag = preparedIntegrityTag.ToArray();
        this.phaseIntegrityTag = phaseIntegrityTag.ToArray();
        this.cacheSalt = cacheSalt.ToArray();
        this.cacheTranscriptHash = cacheTranscriptHash.ToArray();
        VerifiedAtUnixSeconds = verifiedAtUnixSeconds;
        CacheExpiresAtUnixSeconds = cacheExpiresAtUnixSeconds;
        Mode = mode;
        AuthorizationKind = authorizationKind;
        this.canonicalEnvelope = canonicalEnvelope.ToArray();
        this.envelopeSha256 = envelopeSha256.ToArray();
        this.lineageCommitment = lineageCommitment.ToArray();
        this.selectionInputCommitment = selectionInputCommitment.ToArray();
        this.durableOldSelectionHash = durableOldSelectionHash.ToArray();
        this.targets = targets.Select(static target => target.Snapshot()).ToArray();
        Published = published;
    }

    internal ReadOnlyMemory<byte> ActivationStateKey => activationStateKey.ToArray();
    internal ReadOnlyMemory<byte> PromotionStateKey => promotionStateKey.ToArray();
    internal ReadOnlyMemory<byte> CohortId => cohortId.ToArray();
    internal ReadOnlyMemory<byte> RouteStateKey => routeStateKey.ToArray();
    internal ReadOnlyMemory<byte> SourceFingerprint => sourceFingerprint.ToArray();
    internal ulong SourceLocalCommitGeneration { get; }
    internal ReadOnlyMemory<byte> RouteOriginLkgHash => routeOriginLkgHash.ToArray();
    internal ReadOnlyMemory<byte> RouteHistoryCheckpointHash =>
        routeHistoryCheckpointHash.ToArray();
    internal ReadOnlyMemory<byte> TransitionTranscriptHash =>
        transitionTranscriptHash.ToArray();
    internal ReadOnlyMemory<byte> PublisherPublicKey => publisherPublicKey.ToArray();
    internal ReadOnlyMemory<byte> VerifiedPlanSignature => verifiedPlanSignature.ToArray();
    internal ReadOnlyMemory<byte> PreparedIntegrityTag => preparedIntegrityTag.ToArray();
    internal ReadOnlyMemory<byte> PhaseIntegrityTag => phaseIntegrityTag.ToArray();
    internal ReadOnlyMemory<byte> CacheSalt => cacheSalt.ToArray();
    internal ReadOnlyMemory<byte> CacheTranscriptHash => cacheTranscriptHash.ToArray();
    internal ulong VerifiedAtUnixSeconds { get; }
    internal ulong CacheExpiresAtUnixSeconds { get; }
    internal ProductionMailboxSelectionSuccessorMode Mode { get; }
    internal ProductionMailboxRouteAuthorizationKind AuthorizationKind { get; }
    internal ReadOnlyMemory<byte> CanonicalEnvelope => canonicalEnvelope.ToArray();
    internal ReadOnlyMemory<byte> EnvelopeSha256 => envelopeSha256.ToArray();
    internal ReadOnlyMemory<byte> LineageCommitment => lineageCommitment.ToArray();
    internal ReadOnlyMemory<byte> SelectionInputCommitment =>
        selectionInputCommitment.ToArray();
    internal ReadOnlyMemory<byte> DurableOldSelectionHash => durableOldSelectionHash.ToArray();
    internal IReadOnlyList<ProductionMailboxV2ActivationTargetState> Targets =>
        targets.Select(static target => target.Snapshot()).ToArray();
    internal bool Published { get; }
}

internal sealed class ProductionMailboxV2ActivationTargetState
{
    private readonly byte[] replicaId;
    private readonly byte[] currentSpkiSha256;
    private readonly byte[] nextSpkiSha256;
    private readonly byte[]? canonicalAttempt;
    private readonly byte[]? attemptSha256;

    internal ProductionMailboxV2ActivationTargetState(byte[] replicaId, string endpoint,
        byte[] currentSpkiSha256, byte[] nextSpkiSha256, byte[]? canonicalAttempt = null,
        byte[]? attemptSha256 = null, ulong? attemptedAtUnixSeconds = null,
        bool acknowledged = false)
    {
        this.replicaId = replicaId.ToArray();
        Endpoint = endpoint;
        this.currentSpkiSha256 = currentSpkiSha256.ToArray();
        this.nextSpkiSha256 = nextSpkiSha256.ToArray();
        this.canonicalAttempt = canonicalAttempt?.ToArray();
        this.attemptSha256 = attemptSha256?.ToArray();
        AttemptedAtUnixSeconds = attemptedAtUnixSeconds;
        Acknowledged = acknowledged;
    }

    internal ReadOnlyMemory<byte> ReplicaId => replicaId.ToArray();
    internal string Endpoint { get; }
    internal ReadOnlyMemory<byte> CurrentSpkiSha256 => currentSpkiSha256.ToArray();
    internal ReadOnlyMemory<byte> NextSpkiSha256 => nextSpkiSha256.ToArray();
    internal ReadOnlyMemory<byte>? CanonicalAttempt => canonicalAttempt is null
        ? null : new ReadOnlyMemory<byte>(canonicalAttempt.ToArray());
    internal ReadOnlyMemory<byte>? AttemptSha256 => attemptSha256 is null
        ? null : new ReadOnlyMemory<byte>(attemptSha256.ToArray());
    internal ulong? AttemptedAtUnixSeconds { get; }
    internal bool Acknowledged { get; }
    internal ProductionMailboxV2ActivationTargetState Snapshot() => new(replicaId, Endpoint,
        currentSpkiSha256, nextSpkiSha256, canonicalAttempt, attemptSha256,
        AttemptedAtUnixSeconds, Acknowledged);
}

internal sealed record ProductionMailboxV2ActivationCommitResult(
    ProductionMailboxV2ActivationCommitStatus Status,
    ProductionMailboxV2ActivationState? State);

internal interface IProductionMailboxV2PublicationStateStore
{
    ValueTask<ProductionMailboxV2ActivationCommitResult> TryCreateV2ActivationAsync(
        ProductionMailboxV2ActivationPlan plan,
        CancellationToken cancellationToken);
    ValueTask<ProductionMailboxV2ActivationCommitResult> RecordV2ActivationAttestationAsync(
        ReadOnlyMemory<byte> activationStateKey,
        ReadOnlyMemory<byte> verifiedPlanSignature,
        CancellationToken cancellationToken);
    ValueTask<ProductionMailboxV2ActivationState?> GetV2ActivationAsync(
        ReadOnlyMemory<byte> activationStateKey,
        CancellationToken cancellationToken);
    ValueTask<ProductionMailboxV2ActivationCommitResult>
        GetCurrentV2ActivationForPublicationAsync(
            ReadOnlyMemory<byte> activationStateKey,
            uint minimumRemainingSeconds,
            CancellationToken cancellationToken);
    ValueTask<IReadOnlyList<byte[]>> ListPendingV2ActivationKeysAsync(
        int maximumCount,
        CancellationToken cancellationToken);
    ValueTask<bool> RecordV2PublicationAttemptAsync(
        ReadOnlyMemory<byte> activationStateKey,
        ReadOnlyMemory<byte> targetReplicaId,
        ReadOnlyMemory<byte> canonicalCommand,
        uint maximumSkewSeconds,
        uint minimumRemainingSeconds,
        CancellationToken cancellationToken);
    ValueTask<bool> AcknowledgeV2PublicationAttemptAsync(
        ReadOnlyMemory<byte> activationStateKey,
        ReadOnlyMemory<byte> targetReplicaId,
        ReadOnlyMemory<byte> attemptSha256,
        CancellationToken cancellationToken);
    ValueTask<ProductionMailboxV2ActivationCommitStatus> TryFinalizeV2ActivationAsync(
        ReadOnlyMemory<byte> activationStateKey,
        uint capacityRenewalMarginSeconds,
        CancellationToken cancellationToken);
}

internal static class ProductionMailboxV2PreparedIntegrity
{
    private static ReadOnlySpan<byte> Domain =>
        "Deep/Registry/production-mailbox-v2-prepared-integrity/v1"u8;

    internal static byte[] ReadProtectedKey(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            throw new InvalidOperationException(
                "Production mailbox state-integrity key path is missing.");
        var fullPath = Path.GetFullPath(path);
        var value = ProductionMailboxProtectedFile.ReadStable(fullPath, 32, 32,
            () => ProductionMailboxArtifactProvider.EnsureNoReparseAncestors(fullPath));
        if (value.AsSpan().IndexOfAnyExcept((byte)0) < 0)
            throw new InvalidOperationException(
                "Production mailbox state-integrity key is invalid.");
        return value;
    }

    internal static byte[] FreezeKey(ReadOnlyMemory<byte> value)
    {
        if (value.Length != 32 || value.Span.IndexOfAnyExcept((byte)0) < 0)
            throw new InvalidOperationException(
                "Production mailbox V2 prepared-state integrity key is invalid.");
        return value.ToArray();
    }

    internal static byte[] Compute(ProductionMailboxV2ActivationState value,
        ReadOnlySpan<byte> key)
    {
        if (key.Length != 32 || key.IndexOfAnyExcept((byte)0) < 0)
            throw new InvalidOperationException(
                "Production mailbox V2 prepared-state integrity key is invalid.");
        using var hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, key);
        hmac.AppendData(Domain);
        hmac.AppendData(ProductionMailboxV2ActivationAttestation.GetSigningBytes(value));
        return hmac.GetHashAndReset();
    }

    internal static void Verify(ProductionMailboxV2ActivationState value,
        ReadOnlySpan<byte> key)
    {
        if (value.PreparedIntegrityTag.Length != 32
            || !CryptographicOperations.FixedTimeEquals(
                Compute(value, key), value.PreparedIntegrityTag.Span))
            throw new InvalidDataException("Stored PMC2 prepared-state integrity is invalid.");
        if (value.VerifiedPlanSignature.Length == 64
            && !PublicKeyAuth.VerifyDetached(value.VerifiedPlanSignature.ToArray(),
                ProductionMailboxV2ActivationAttestation.GetSigningBytes(value),
                value.PublisherPublicKey.ToArray()))
            throw new InvalidDataException("Stored PMC2 activation attestation is invalid.");
    }
}

internal static class ProductionMailboxV2PhaseIntegrity
{
    private static ReadOnlySpan<byte> Domain =>
        "Deep/Registry/production-mailbox-v2-phase-integrity/v1"u8;

    internal static byte[] Compute(ProductionMailboxV2ActivationState value,
        ReadOnlySpan<byte> key,
        ReadOnlyMemory<byte>? preparedIntegrityOverride = null,
        ReadOnlyMemory<byte>? signatureOverride = null,
        IReadOnlyList<ProductionMailboxV2ActivationTargetState>? targetsOverride = null,
        bool? publishedOverride = null)
    {
        var signature = signatureOverride ?? value.VerifiedPlanSignature;
        var targets = targetsOverride ?? value.Targets;
        using var hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, key);
        hmac.AppendData(Domain);
        hmac.AppendData((preparedIntegrityOverride ?? value.PreparedIntegrityTag).Span);
        Span<byte> scalar = stackalloc byte[4];
        BinaryPrimitives.WriteUInt16BigEndian(scalar, checked((ushort)signature.Length));
        scalar[2] = (publishedOverride ?? value.Published) ? (byte)1 : (byte)0;
        scalar[3] = checked((byte)targets.Count);
        hmac.AppendData(scalar); hmac.AppendData(signature.Span);
        Span<byte> lengths = stackalloc byte[7];
        Span<byte> timestamp = stackalloc byte[8];
        foreach (var target in targets)
        {
            hmac.AppendData(target.ReplicaId.Span);
            var command = target.CanonicalAttempt?.ToArray() ?? [];
            var hash = target.AttemptSha256?.ToArray() ?? [];
            lengths.Clear();
            BinaryPrimitives.WriteUInt32BigEndian(lengths,
                checked((uint)command.Length));
            lengths[4] = checked((byte)hash.Length);
            lengths[5] = target.AttemptedAtUnixSeconds.HasValue ? (byte)1 : (byte)0;
            lengths[6] = target.Acknowledged ? (byte)1 : (byte)0;
            hmac.AppendData(lengths); hmac.AppendData(command); hmac.AppendData(hash);
            if (target.AttemptedAtUnixSeconds is { } attemptedAt)
            {
                timestamp.Clear();
                BinaryPrimitives.WriteUInt64BigEndian(timestamp, attemptedAt);
                hmac.AppendData(timestamp);
            }
        }
        return hmac.GetHashAndReset();
    }

    internal static void Verify(ProductionMailboxV2ActivationState value,
        ReadOnlySpan<byte> key)
    {
        if (value.PhaseIntegrityTag.Length != 32
            || !CryptographicOperations.FixedTimeEquals(
                Compute(value, key), value.PhaseIntegrityTag.Span))
            throw new InvalidDataException("Stored PMC2 phase integrity is invalid.");
    }
}

public sealed partial class InMemoryProductionMailboxStateStore :
    IProductionMailboxV2PublicationStateStore
{
    private readonly byte[] v2PublicationIntegrityKey = RandomNumberGenerator.GetBytes(32);
    private readonly Dictionary<string, MutableV2Activation> v2Activations =
        new(StringComparer.Ordinal);

    async ValueTask<ProductionMailboxV2ActivationCommitResult>
        IProductionMailboxV2PublicationStateStore.TryCreateV2ActivationAsync(
            ProductionMailboxV2ActivationPlan plan, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);
        await gate.WaitAsync(cancellationToken);
        try
        {
            var key = Convert.ToHexString(plan.ActivationStateKey.Span);
            if (v2Activations.TryGetValue(key, out var existing))
                return ExistingResult(existing, plan);
            if (!routeContinuityStates.TryGetValue(
                    Convert.ToHexString(plan.RouteStateKey.Span), out var source))
                return new(ProductionMailboxV2ActivationCommitStatus.MissingSource, null);
            if (!Fixed(ProductionMailboxV2SourceFingerprint.Compute(source),
                    plan.VerifiedCache.SourceFingerprint.Span))
                return new(ProductionMailboxV2ActivationCommitStatus.SourceChanged, null);
            var now = checked((ulong)timeProvider.GetUtcNow().ToUnixTimeSeconds());
            foreach (var expiredKey in v2Activations.Where(pair =>
                    pair.Value.CacheExpiresAtUnixSeconds <= now)
                .Select(static pair => pair.Key).ToArray())
                v2Activations.Remove(expiredKey);
            var lineage = v2Activations.Values.Where(candidate =>
                Fixed(candidate.SelectionInputCommitment,
                    plan.VerifiedCache.SelectionInputCommitment.Span)
                && Fixed(candidate.DurableOldSelectionHash,
                    plan.VerifiedCache.DurableOldSelectionHash.Span)).ToArray();
            if (lineage.Any(candidate => Fixed(candidate.SourceFingerprint,
                    plan.VerifiedCache.SourceFingerprint.Span)) || lineage.Length >= 2)
                return new(ProductionMailboxV2ActivationCommitStatus.Conflict, null);
            var materialized = plan.VerifiedCache.Materialize();
            var record = MutableV2Activation.Create(plan, source, materialized);
            record.PreparedIntegrityTag = ProductionMailboxV2PreparedIntegrity.Compute(
                record.Snapshot(), v2PublicationIntegrityKey);
            record.PhaseIntegrityTag = ProductionMailboxV2PhaseIntegrity.Compute(
                record.Snapshot(), v2PublicationIntegrityKey);
            v2Activations.Add(key, record);
            return new(ProductionMailboxV2ActivationCommitStatus.Accepted,
                VerifiedSnapshot(record));
        }
        finally { gate.Release(); }
    }

    async ValueTask<ProductionMailboxV2ActivationCommitResult>
        IProductionMailboxV2PublicationStateStore.RecordV2ActivationAttestationAsync(
            ReadOnlyMemory<byte> activationStateKey,
            ReadOnlyMemory<byte> verifiedPlanSignature,
            CancellationToken cancellationToken)
    {
        var key = ProductionMailboxRouteContinuityStateGuard.FreezeKey(activationStateKey);
        var signature = FreezeAttestationSignature(verifiedPlanSignature);
        await gate.WaitAsync(cancellationToken);
        try
        {
            if (!v2Activations.TryGetValue(Convert.ToHexString(key), out var activation))
                return new(ProductionMailboxV2ActivationCommitStatus.MissingSource, null);
            _ = VerifiedSnapshot(activation);
            if (activation.VerifiedPlanSignature.Length != 0)
            {
                var exact = Fixed(activation.VerifiedPlanSignature, signature);
                return new(exact ? ProductionMailboxV2ActivationCommitStatus.ExactReplay
                    : ProductionMailboxV2ActivationCommitStatus.Conflict,
                    exact ? VerifiedSnapshot(activation) : null);
            }
            var snapshot = VerifiedSnapshot(activation);
            if (!PublicKeyAuth.VerifyDetached(signature,
                    ProductionMailboxV2ActivationAttestation.GetSigningBytes(snapshot),
                    activation.PublisherPublicKey))
                return new(ProductionMailboxV2ActivationCommitStatus.Conflict, null);
            activation.VerifiedPlanSignature = signature;
            RefreshPhaseIntegrity(activation);
            return new(ProductionMailboxV2ActivationCommitStatus.Accepted,
                VerifiedSnapshot(activation));
        }
        finally { gate.Release(); }
    }

    async ValueTask<ProductionMailboxV2ActivationState?>
        IProductionMailboxV2PublicationStateStore.GetV2ActivationAsync(
            ReadOnlyMemory<byte> activationStateKey, CancellationToken cancellationToken)
    {
        var key = ProductionMailboxRouteContinuityStateGuard.FreezeKey(activationStateKey);
        await gate.WaitAsync(cancellationToken);
        try
        {
            return v2Activations.TryGetValue(Convert.ToHexString(key), out var record)
                ? VerifiedSnapshot(record) : null;
        }
        finally { gate.Release(); }
    }

    async ValueTask<ProductionMailboxV2ActivationCommitResult>
        IProductionMailboxV2PublicationStateStore.GetCurrentV2ActivationForPublicationAsync(
            ReadOnlyMemory<byte> activationStateKey, uint minimumRemainingSeconds,
            CancellationToken cancellationToken)
    {
        var key = ProductionMailboxRouteContinuityStateGuard.FreezeKey(activationStateKey);
        await gate.WaitAsync(cancellationToken);
        try
        {
            if (!v2Activations.TryGetValue(Convert.ToHexString(key), out var activation))
                return new(ProductionMailboxV2ActivationCommitStatus.MissingSource, null);
            if (activation.Published)
                return new(ProductionMailboxV2ActivationCommitStatus.Published,
                    VerifiedSnapshot(activation));
            if (activation.VerifiedPlanSignature.Length != 64)
                return new(ProductionMailboxV2ActivationCommitStatus.Incomplete, null);
            if (!routeContinuityStates.TryGetValue(Convert.ToHexString(activation.RouteStateKey),
                    out var source) || !Fixed(ProductionMailboxV2SourceFingerprint.Compute(source),
                    activation.SourceFingerprint))
                return new(ProductionMailboxV2ActivationCommitStatus.SourceChanged, null);
            var now = checked((ulong)timeProvider.GetUtcNow().ToUnixTimeSeconds());
            if (activation.CacheExpiresAtUnixSeconds < checked(now + minimumRemainingSeconds))
                return new(ProductionMailboxV2ActivationCommitStatus.Expired, null);
            return new(ProductionMailboxV2ActivationCommitStatus.Accepted,
                VerifiedSnapshot(activation));
        }
        finally { gate.Release(); }
    }

    async ValueTask<IReadOnlyList<byte[]>>
        IProductionMailboxV2PublicationStateStore.ListPendingV2ActivationKeysAsync(
            int maximumCount, CancellationToken cancellationToken)
    {
        if (maximumCount is < 1 or > 1024) throw new ArgumentOutOfRangeException(nameof(maximumCount));
        await gate.WaitAsync(cancellationToken);
        try
        {
            var now = checked((ulong)timeProvider.GetUtcNow().ToUnixTimeSeconds());
            return v2Activations.Where(pair =>
                {
                    _ = VerifiedSnapshot(pair.Value);
                    return !pair.Value.Published
                    && pair.Value.VerifiedPlanSignature.Length == 64
                    && pair.Value.CacheExpiresAtUnixSeconds > now;
                })
                .OrderBy(static pair => pair.Key, StringComparer.Ordinal)
                .Take(maximumCount).Select(static pair => Convert.FromHexString(pair.Key))
                .ToArray();
        }
        finally { gate.Release(); }
    }

    async ValueTask<bool>
        IProductionMailboxV2PublicationStateStore.RecordV2PublicationAttemptAsync(
            ReadOnlyMemory<byte> activationStateKey, ReadOnlyMemory<byte> targetReplicaId,
            ReadOnlyMemory<byte> canonicalCommand, uint maximumSkewSeconds,
            uint minimumRemainingSeconds,
            CancellationToken cancellationToken)
    {
        var key = ProductionMailboxRouteContinuityStateGuard.FreezeKey(activationStateKey);
        var replica = ProductionMailboxRouteContinuityStateGuard.FreezeKey(targetReplicaId);
        var command = ProductionMailboxV2AttemptGuard.FreezeAndInspect(canonicalCommand);
        await gate.WaitAsync(cancellationToken);
        try
        {
            if (!v2Activations.TryGetValue(Convert.ToHexString(key), out var activation)
                || activation.Published || activation.VerifiedPlanSignature.Length != 64)
                return false;
            _ = VerifiedSnapshot(activation);
            var target = activation.Targets.SingleOrDefault(candidate =>
                Fixed(candidate.ReplicaId, replica));
            if (target is null || !ProductionMailboxV2AttemptGuard.Matches(command,
                    activation.EnvelopeSha256, activation.CohortId, target.ReplicaId,
                    activation.PublisherPublicKey)) return false;
            var hash = SHA256.HashData(command.CanonicalBytes);
            if (target.AttemptSha256 is not null && Fixed(target.AttemptSha256, hash))
                return true;
            var now = checked((ulong)timeProvider.GetUtcNow().ToUnixTimeSeconds());
            if (activation.CacheExpiresAtUnixSeconds < checked(now + minimumRemainingSeconds))
                return false;
            if (target.AttemptedAtUnixSeconds is not null
                && now <= checked(target.AttemptedAtUnixSeconds.Value + maximumSkewSeconds))
                return false;
            if (!ProductionMailboxV2AttemptGuard.IsFresh(command.TimestampUnixSeconds,
                    now, maximumSkewSeconds)) return false;
            target.SetAttempt(command.CanonicalBytes, hash, command.TimestampUnixSeconds);
            RefreshPhaseIntegrity(activation);
            return true;
        }
        finally { gate.Release(); }
    }

    async ValueTask<bool>
        IProductionMailboxV2PublicationStateStore.AcknowledgeV2PublicationAttemptAsync(
            ReadOnlyMemory<byte> activationStateKey, ReadOnlyMemory<byte> targetReplicaId,
            ReadOnlyMemory<byte> attemptSha256, CancellationToken cancellationToken)
    {
        var key = ProductionMailboxRouteContinuityStateGuard.FreezeKey(activationStateKey);
        var replica = ProductionMailboxRouteContinuityStateGuard.FreezeKey(targetReplicaId);
        var attempt = ProductionMailboxRouteContinuityStateGuard.FreezeKey(attemptSha256);
        await gate.WaitAsync(cancellationToken);
        try
        {
            if (!v2Activations.TryGetValue(Convert.ToHexString(key), out var activation)
                || activation.Published || activation.VerifiedPlanSignature.Length != 64)
                return false;
            _ = VerifiedSnapshot(activation);
            var target = activation.Targets.SingleOrDefault(candidate =>
                Fixed(candidate.ReplicaId, replica));
            if (target?.AttemptSha256 is null || !Fixed(target.AttemptSha256, attempt))
                return false;
            target.Acknowledged = true;
            RefreshPhaseIntegrity(activation);
            return true;
        }
        finally { gate.Release(); }
    }

    async ValueTask<ProductionMailboxV2ActivationCommitStatus>
        IProductionMailboxV2PublicationStateStore.TryFinalizeV2ActivationAsync(
            ReadOnlyMemory<byte> activationStateKey, uint capacityRenewalMarginSeconds,
            CancellationToken cancellationToken)
    {
        var key = ProductionMailboxRouteContinuityStateGuard.FreezeKey(activationStateKey);
        if (capacityRenewalMarginSeconds == 0)
            throw new ArgumentOutOfRangeException(nameof(capacityRenewalMarginSeconds));
        await gate.WaitAsync(cancellationToken);
        try
        {
            if (!v2Activations.TryGetValue(Convert.ToHexString(key), out var activation))
                return ProductionMailboxV2ActivationCommitStatus.MissingSource;
            _ = VerifiedSnapshot(activation);
            if (activation.Published) return ProductionMailboxV2ActivationCommitStatus.Published;
            if (activation.VerifiedPlanSignature.Length != 64)
                return ProductionMailboxV2ActivationCommitStatus.Incomplete;
            if (!routeContinuityStates.TryGetValue(Convert.ToHexString(activation.RouteStateKey),
                    out var source)
                || !Fixed(ProductionMailboxV2SourceFingerprint.Compute(source),
                    activation.SourceFingerprint))
                return ProductionMailboxV2ActivationCommitStatus.SourceChanged;
            var now = checked((ulong)timeProvider.GetUtcNow().ToUnixTimeSeconds());
            var safeUntil = checked(now + capacityRenewalMarginSeconds);
            if (activation.CacheExpiresAtUnixSeconds < safeUntil)
                return ProductionMailboxV2ActivationCommitStatus.Expired;
            if (activation.Targets.Any(static target => !target.Acknowledged
                    || target.AttemptSha256 is null || target.CanonicalAttempt is null
                    || !Fixed(SHA256.HashData(target.CanonicalAttempt),
                        target.AttemptSha256)))
                return ProductionMailboxV2ActivationCommitStatus.Incomplete;
            if (!promotions.TryGetValue(Convert.ToHexString(activation.PromotionStateKey),
                    out var promotion) || !promotion.CapacityPlanCompleted
                || !CapacitySafe(activation, promotion, safeUntil))
                return ProductionMailboxV2ActivationCommitStatus.Incomplete;
            // Same gate is the authoritative route-state lock. Recheck immediately before commit.
            if (!routeContinuityStates.TryGetValue(Convert.ToHexString(activation.RouteStateKey),
                    out source) || !Fixed(ProductionMailboxV2SourceFingerprint.Compute(source),
                    activation.SourceFingerprint))
                return ProductionMailboxV2ActivationCommitStatus.SourceChanged;
            activation.Published = true;
            RefreshPhaseIntegrity(activation);
            return ProductionMailboxV2ActivationCommitStatus.Published;
        }
        finally { gate.Release(); }
    }

    private static bool CapacitySafe(MutableV2Activation activation,
        MutablePromotionRecord promotion, ulong safeUntil)
    {
        foreach (var target in activation.Targets)
        {
            if (!promotion.CapacityTargets.TryGetValue(Convert.ToHexString(target.ReplicaId),
                    out var capacity) || capacity.Released || capacity.CanonicalReceipt is null
                || capacity.LastCommandSha256 is null || capacity.PendingCanonicalCommand is not null
                || capacity.PendingRevision is not null || capacity.ReceiptExpiresAtUnixSeconds is null
                || capacity.ReceiptExpiresAtUnixSeconds.Value < safeUntil)
                return false;
            ProductionMailboxCapacityReceipt receipt;
            try
            {
                receipt = ProductionMailboxCapacityReceiptCodec.DecodeAndVerify(
                    capacity.CanonicalReceipt, capacity.TargetReplicaId);
            }
            catch (InvalidDataException) { return false; }
            if (receipt.Operation != ProductionMailboxCapacityOperation.ReserveOrRenew
                || receipt.Revision != capacity.Revision
                || receipt.ExpiresAtUnixSeconds != capacity.ReceiptExpiresAtUnixSeconds
                || receipt.ReservedClosureCount != capacity.ReservedClosureCount
                || receipt.ReservedBytes != capacity.ReservedBytes
                || !Fixed(receipt.CohortId, activation.CohortId)
                || !Fixed(receipt.CommandSha256, capacity.LastCommandSha256)) return false;
        }
        return true;
    }

    private ProductionMailboxV2ActivationCommitResult ExistingResult(
        MutableV2Activation existing, ProductionMailboxV2ActivationPlan plan)
    {
        var cache = plan.VerifiedCache;
        var exact = Fixed(existing.PromotionStateKey, plan.PromotionStateKey.Span)
            && Fixed(existing.CohortId, plan.CohortId.Span)
            && Fixed(existing.RouteStateKey, plan.RouteStateKey.Span)
            && Fixed(existing.PublisherPublicKey, plan.PublisherPublicKey.Span)
            && Fixed(existing.SourceFingerprint, cache.SourceFingerprint.Span)
            && Fixed(existing.CacheTranscriptHash, cache.CacheTranscriptHash.Span)
            && Fixed(existing.SelectionInputCommitment, cache.SelectionInputCommitment.Span)
            && Fixed(existing.DurableOldSelectionHash, cache.DurableOldSelectionHash.Span)
            && existing.VerifiedAtUnixSeconds == cache.VerifiedAtUnixSeconds
            && existing.CacheExpiresAtUnixSeconds == cache.CacheExpiresAtUnixSeconds
            && existing.Mode == cache.Mode && existing.AuthorizationKind == cache.AuthorizationKind
            && ExactTargets(existing.Targets, cache.Targets);
        return new(exact ? ProductionMailboxV2ActivationCommitStatus.ExactReplay
            : ProductionMailboxV2ActivationCommitStatus.Conflict,
            exact ? VerifiedSnapshot(existing) : null);
    }

    private ProductionMailboxV2ActivationState VerifiedSnapshot(
        MutableV2Activation value)
    {
        var snapshot = value.Snapshot();
        ProductionMailboxV2PreparedIntegrity.Verify(snapshot,
            v2PublicationIntegrityKey);
        ProductionMailboxV2PhaseIntegrity.Verify(snapshot,
            v2PublicationIntegrityKey);
        return snapshot;
    }

    private void RefreshPhaseIntegrity(MutableV2Activation value)
    {
        value.PhaseIntegrityTag = ProductionMailboxV2PhaseIntegrity.Compute(
            value.Snapshot(), v2PublicationIntegrityKey);
    }

    private static byte[] FreezeAttestationSignature(ReadOnlyMemory<byte> value)
    {
        if (value.Length != 64)
            throw new InvalidDataException("PMC2 activation attestation is invalid.");
        return value.ToArray();
    }

    private static bool ExactTargets(IReadOnlyList<MutableV2Target> existing,
        IReadOnlyList<ProductionMailboxV2Target> candidate) => existing.Count == candidate.Count
        && existing.Zip(candidate).All(pair => Fixed(pair.First.ReplicaId,
                pair.Second.ReplicaId.Span)
            && pair.First.Endpoint == pair.Second.Endpoint
            && Fixed(pair.First.CurrentSpkiSha256, pair.Second.CurrentSpkiSha256.Span)
            && Fixed(pair.First.NextSpkiSha256, pair.Second.NextSpkiSha256.Span));

    private sealed class MutableV2Activation
    {
        internal required byte[] ActivationStateKey { get; init; }
        internal required byte[] PromotionStateKey { get; init; }
        internal required byte[] CohortId { get; init; }
        internal required byte[] RouteStateKey { get; init; }
        internal required byte[] SourceFingerprint { get; init; }
        internal required ulong SourceLocalCommitGeneration { get; init; }
        internal required byte[] RouteOriginLkgHash { get; init; }
        internal required byte[] RouteHistoryCheckpointHash { get; init; }
        internal required byte[] TransitionTranscriptHash { get; init; }
        internal required byte[] PublisherPublicKey { get; init; }
        internal required byte[] VerifiedPlanSignature { get; set; }
        internal required byte[] PreparedIntegrityTag { get; set; }
        internal required byte[] PhaseIntegrityTag { get; set; }
        internal required byte[] CacheSalt { get; init; }
        internal required byte[] CacheTranscriptHash { get; init; }
        internal required ulong VerifiedAtUnixSeconds { get; init; }
        internal required ulong CacheExpiresAtUnixSeconds { get; init; }
        internal required ProductionMailboxSelectionSuccessorMode Mode { get; init; }
        internal required ProductionMailboxRouteAuthorizationKind AuthorizationKind { get; init; }
        internal required byte[] CanonicalEnvelope { get; init; }
        internal required byte[] EnvelopeSha256 { get; init; }
        internal required byte[] LineageCommitment { get; init; }
        internal required byte[] SelectionInputCommitment { get; init; }
        internal required byte[] DurableOldSelectionHash { get; init; }
        internal required List<MutableV2Target> Targets { get; init; }
        internal bool Published { get; set; }

        internal static MutableV2Activation Create(ProductionMailboxV2ActivationPlan plan,
            ProductionMailboxRouteContinuityStateSnapshot source,
            ProductionMailboxV2MaterializedCache materialized)
        {
            var history = source.History;
            return new()
            {
                ActivationStateKey = plan.ActivationStateKey.ToArray(),
                PromotionStateKey = plan.PromotionStateKey.ToArray(),
                CohortId = plan.CohortId.ToArray(),
                RouteStateKey = plan.RouteStateKey.ToArray(),
                SourceFingerprint = plan.VerifiedCache.SourceFingerprint.ToArray(),
                SourceLocalCommitGeneration = source.LocalCommitGeneration,
                RouteOriginLkgHash = source.RouteOriginLkgHash.ToArray(),
                RouteHistoryCheckpointHash = history?.CanonicalCheckpointHash.ToArray()
                    ?? new byte[32],
                TransitionTranscriptHash = source.TransitionTranscriptHash.ToArray(),
                PublisherPublicKey = plan.PublisherPublicKey.ToArray(),
                VerifiedPlanSignature = [],
                PreparedIntegrityTag = new byte[32],
                PhaseIntegrityTag = new byte[32],
                CacheSalt = materialized.CacheSalt.ToArray(),
                CacheTranscriptHash = plan.VerifiedCache.CacheTranscriptHash.ToArray(),
                VerifiedAtUnixSeconds = plan.VerifiedCache.VerifiedAtUnixSeconds,
                CacheExpiresAtUnixSeconds = plan.VerifiedCache.CacheExpiresAtUnixSeconds,
                Mode = plan.VerifiedCache.Mode,
                AuthorizationKind = plan.VerifiedCache.AuthorizationKind,
                CanonicalEnvelope = materialized.CanonicalEnvelope.ToArray(),
                EnvelopeSha256 = materialized.EnvelopeSha256.ToArray(),
                LineageCommitment = materialized.LineageCommitment.ToArray(),
                SelectionInputCommitment =
                    plan.VerifiedCache.SelectionInputCommitment.ToArray(),
                DurableOldSelectionHash =
                    plan.VerifiedCache.DurableOldSelectionHash.ToArray(),
                Targets = plan.VerifiedCache.Targets.Select(static target =>
                    new MutableV2Target(target)).ToList()
            };
        }

        internal ProductionMailboxV2ActivationState Snapshot() => new(ActivationStateKey,
            PromotionStateKey, CohortId, RouteStateKey, SourceFingerprint,
            SourceLocalCommitGeneration, RouteOriginLkgHash, RouteHistoryCheckpointHash,
            TransitionTranscriptHash, PublisherPublicKey, VerifiedPlanSignature,
            PreparedIntegrityTag, PhaseIntegrityTag,
            CacheSalt, CacheTranscriptHash,
            VerifiedAtUnixSeconds, CacheExpiresAtUnixSeconds, Mode, AuthorizationKind,
            CanonicalEnvelope, EnvelopeSha256, LineageCommitment, SelectionInputCommitment,
            DurableOldSelectionHash, Targets.Select(static target => target.Snapshot()).ToArray(),
            Published);
    }

    private sealed class MutableV2Target(ProductionMailboxV2Target value)
    {
        internal byte[] ReplicaId { get; } = value.ReplicaId.ToArray();
        internal string Endpoint { get; } = value.Endpoint;
        internal byte[] CurrentSpkiSha256 { get; } = value.CurrentSpkiSha256.ToArray();
        internal byte[] NextSpkiSha256 { get; } = value.NextSpkiSha256.ToArray();
        internal byte[]? CanonicalAttempt { get; private set; }
        internal byte[]? AttemptSha256 { get; private set; }
        internal ulong? AttemptedAtUnixSeconds { get; private set; }
        internal bool Acknowledged { get; set; }
        internal void SetAttempt(byte[] command, byte[] hash, ulong timestamp)
        {
            CanonicalAttempt = command.ToArray(); AttemptSha256 = hash.ToArray();
            AttemptedAtUnixSeconds = timestamp; Acknowledged = false;
        }
        internal ProductionMailboxV2ActivationTargetState Snapshot() => new(ReplicaId,
            Endpoint, CurrentSpkiSha256, NextSpkiSha256, CanonicalAttempt,
            AttemptSha256, AttemptedAtUnixSeconds, Acknowledged);
    }

}

internal sealed record ProductionMailboxV2InspectedCommand(
    byte[] CanonicalBytes, ulong TimestampUnixSeconds, byte[] EnvelopeSha256,
    byte[] TargetReplicaId, byte[] CohortId);

internal static class ProductionMailboxV2AttemptGuard
{
    internal static ProductionMailboxV2InspectedCommand FreezeAndInspect(
        ReadOnlyMemory<byte> canonical)
    {
        if (canonical.Length is < ProductionMailboxV2WireCodec.CommandHeaderLength
            or > ProductionMailboxV2WireCodec.MaximumCommandBytes)
            throw new InvalidDataException("PMP2 command length is invalid.");
        var frozen = canonical.ToArray();
        if (!frozen.AsSpan(0, 4).SequenceEqual("PMP2"u8) || frozen[4] != 2
            || frozen[5] != 0 || frozen.AsSpan(6, 2).IndexOfAnyExcept((byte)0) >= 0
            || frozen.AsSpan(112, 64).IndexOfAnyExcept((byte)0) >= 0
            || frozen.AsSpan(276, 4).IndexOfAnyExcept((byte)0) >= 0)
            throw new InvalidDataException("PMP2 command framing is invalid.");
        var envelopeLength = BinaryPrimitives.ReadUInt32BigEndian(frozen.AsSpan(272, 4));
        if (envelopeLength > int.MaxValue
            || frozen.Length - ProductionMailboxV2WireCodec.CommandHeaderLength
                != (int)envelopeLength)
            throw new InvalidDataException("PMP2 envelope length is invalid.");
        return new(frozen, BinaryPrimitives.ReadUInt64BigEndian(frozen.AsSpan(8, 8)),
            frozen.AsSpan(48, 32).ToArray(), frozen.AsSpan(80, 32).ToArray(),
            frozen.AsSpan(240, 32).ToArray());
    }

    internal static bool Matches(ProductionMailboxV2InspectedCommand command,
        ReadOnlySpan<byte> expectedEnvelopeHash, ReadOnlySpan<byte> expectedCohort,
        ReadOnlySpan<byte> expectedTarget, ReadOnlySpan<byte> publisherPublicKey) =>
        Fixed(command.EnvelopeSha256, expectedEnvelopeHash)
        && Fixed(command.CohortId, expectedCohort)
        && Fixed(command.TargetReplicaId, expectedTarget)
        && ProductionMailboxV2WireCodec.VerifyCanonicalCommand(
            command.CanonicalBytes, publisherPublicKey);

    internal static bool IsFresh(ulong timestamp, ulong now, uint skew) => timestamp > now
        ? timestamp - now <= skew : now - timestamp <= skew;

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

}

public sealed partial class PostgreSqlProductionMailboxStateStore :
    IProductionMailboxV2PublicationStateStore
{
    private readonly byte[] v2PreparedIntegrityKey = v2PublicationIntegrityKey.IsEmpty
        ? [] : ProductionMailboxV2PreparedIntegrity.FreezeKey(v2PublicationIntegrityKey);
    private readonly SemaphoreSlim v2PublicationInitializeGate = new(1, 1);
    private volatile bool v2PublicationInitialized;

    private ReadOnlySpan<byte> V2PreparedIntegrityKey => v2PreparedIntegrityKey.Length == 32
        ? v2PreparedIntegrityKey
        : throw new InvalidOperationException(
            "Production mailbox V2 prepared-state integrity key is not configured.");

    async ValueTask<ProductionMailboxV2ActivationCommitResult>
        IProductionMailboxV2PublicationStateStore.TryCreateV2ActivationAsync(
            ProductionMailboxV2ActivationPlan plan, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);
        await using var connection = await OpenAsync(cancellationToken);
        await EnsureV2PublicationSchemaAsync(connection, cancellationToken);
        await EnsureRouteContinuitySchemaAsync(connection, cancellationToken);
        // The canonical route, activation, and lineage-group advisory locks below
        // serialize every predicate used by this insert. Read Committed avoids a
        // stale Serializable snapshot after a contender waits on the group lock.
        await using var transaction = await connection.BeginTransactionAsync(
            IsolationLevel.ReadCommitted, cancellationToken);
        var groupKey = ProductionMailboxV2ActivationAttestation.ComputeLineageGroupKey(
            plan.VerifiedCache.SelectionInputCommitment.Span,
            plan.VerifiedCache.DurableOldSelectionHash.Span);
        await V2AdvisoryLocksAsync(connection, transaction, cancellationToken,
            plan.RouteStateKey, plan.ActivationStateKey, groupKey);
        var existing = await ReadV2ActivationAsync(connection, transaction,
            plan.ActivationStateKey, true, cancellationToken);
        if (existing is not null)
        {
            var status = ExactLogical(existing, plan)
                ? ProductionMailboxV2ActivationCommitStatus.ExactReplay
                : ProductionMailboxV2ActivationCommitStatus.Conflict;
            await transaction.CommitAsync(cancellationToken);
            return new(status, status == ProductionMailboxV2ActivationCommitStatus.ExactReplay
                ? existing : null);
        }
        var source = await ReadRouteContinuityAsync(connection, transaction,
            plan.RouteStateKey.ToArray(), true, cancellationToken);
        if (source is null)
        {
            await transaction.RollbackAsync(cancellationToken);
            return new(ProductionMailboxV2ActivationCommitStatus.MissingSource, null);
        }
        if (!Fixed(ProductionMailboxV2SourceFingerprint.Compute(source),
                plan.VerifiedCache.SourceFingerprint.Span))
        {
            await transaction.RollbackAsync(cancellationToken);
            return new(ProductionMailboxV2ActivationCommitStatus.SourceChanged, null);
        }
        var now = await ReadDatabaseNowAsync(connection, transaction, cancellationToken);
        var lineageKeys = new List<byte[]>();
        await using (var command = new NpgsqlCommand(
            "SELECT activation_state_key FROM production_mailbox_v2_activations WHERE selection_input_commitment=@selection AND durable_old_selection_hash=@old AND octet_length(activation_state_key)=32 ORDER BY activation_state_key LIMIT 3 FOR UPDATE",
            connection, transaction))
        {
            command.Parameters.AddWithValue("selection",
                plan.VerifiedCache.SelectionInputCommitment.ToArray());
            command.Parameters.AddWithValue("old",
                plan.VerifiedCache.DurableOldSelectionHash.ToArray());
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
                lineageKeys.Add(reader.GetFieldValue<byte[]>(0));
        }
        if (lineageKeys.Count > 2)
            throw new InvalidDataException("Stored PMC2 lineage cap is corrupt.");
        var lineage = new List<ProductionMailboxV2ActivationState>();
        foreach (var lineageKey in lineageKeys)
        {
            var value = await ReadV2ActivationAsync(connection, transaction, lineageKey,
                true, cancellationToken)
                ?? throw new InvalidDataException("Stored PMC2 lineage disappeared.");
            if (value.CacheExpiresAtUnixSeconds > now) lineage.Add(value);
            else
            {
                await using var removeTargets = new NpgsqlCommand(
                    "DELETE FROM production_mailbox_v2_activation_targets WHERE activation_state_key=@key",
                    connection, transaction);
                removeTargets.Parameters.AddWithValue("key", lineageKey);
                await removeTargets.ExecuteNonQueryAsync(cancellationToken);
                await using var remove = new NpgsqlCommand(
                    "DELETE FROM production_mailbox_v2_activations WHERE activation_state_key=@key",
                    connection, transaction);
                remove.Parameters.AddWithValue("key", lineageKey);
                await remove.ExecuteNonQueryAsync(cancellationToken);
            }
        }
        if (lineage.Any(value => Fixed(value.SourceFingerprint.Span,
                plan.VerifiedCache.SourceFingerprint.Span)) || lineage.Count >= 2)
        {
            await transaction.RollbackAsync(cancellationToken);
            return new(ProductionMailboxV2ActivationCommitStatus.Conflict, null);
        }
        var materialized = plan.VerifiedCache.Materialize();
        var history = source.History;
        var preparedWithoutTag = new ProductionMailboxV2ActivationState(
            plan.ActivationStateKey.ToArray(), plan.PromotionStateKey.ToArray(),
            plan.CohortId.ToArray(), plan.RouteStateKey.ToArray(),
            plan.VerifiedCache.SourceFingerprint.ToArray(), source.LocalCommitGeneration,
            source.RouteOriginLkgHash.ToArray(),
            history?.CanonicalCheckpointHash.ToArray() ?? new byte[32],
            source.TransitionTranscriptHash.ToArray(), plan.PublisherPublicKey.ToArray(),
            [], new byte[32], new byte[32], materialized.CacheSalt.ToArray(),
            plan.VerifiedCache.CacheTranscriptHash.ToArray(),
            plan.VerifiedCache.VerifiedAtUnixSeconds,
            plan.VerifiedCache.CacheExpiresAtUnixSeconds, plan.VerifiedCache.Mode,
            plan.VerifiedCache.AuthorizationKind, materialized.CanonicalEnvelope.ToArray(),
            materialized.EnvelopeSha256.ToArray(),
            materialized.LineageCommitment.ToArray(),
            plan.VerifiedCache.SelectionInputCommitment.ToArray(),
            plan.VerifiedCache.DurableOldSelectionHash.ToArray(),
            plan.VerifiedCache.Targets.Select(static target =>
                new ProductionMailboxV2ActivationTargetState(target.ReplicaId.ToArray(),
                    target.Endpoint, target.CurrentSpkiSha256.ToArray(),
                    target.NextSpkiSha256.ToArray())).ToArray(), false);
        var preparedIntegrityTag = ProductionMailboxV2PreparedIntegrity.Compute(
            preparedWithoutTag, V2PreparedIntegrityKey);
        var phaseIntegrityTag = ProductionMailboxV2PhaseIntegrity.Compute(
            preparedWithoutTag, V2PreparedIntegrityKey,
            preparedIntegrityOverride: preparedIntegrityTag);
        await using (var insert = new NpgsqlCommand(
            """
            INSERT INTO production_mailbox_v2_activations(
                activation_state_key,promotion_state_key,cohort_id,route_state_key,
                source_fingerprint,source_local_commit_generation,route_origin_lkg_hash,
                route_history_checkpoint_hash,transition_transcript_hash,publisher_public_key,
                verified_plan_signature,prepared_integrity_tag,phase_integrity_tag,cache_salt,cache_transcript_hash,verified_at,
                cache_expires_at,mode,authorization_kind,
                canonical_envelope,envelope_sha256,lineage_commitment,selection_input_commitment,
                durable_old_selection_hash,published)
            VALUES(@activation,@promotion,@cohort,@route,@source,@local,@rol,@rhc,@transcript,
                @publisher,NULL,@preparedIntegrity,@phaseIntegrity,@salt,@cacheTranscript,@verified,@expires,@mode,@authorization,
                @envelope,@envelopeHash,@lineage,@selection,@oldSelection,false)
            """, connection, transaction))
        {
            insert.Parameters.AddWithValue("activation", plan.ActivationStateKey.ToArray());
            insert.Parameters.AddWithValue("promotion", plan.PromotionStateKey.ToArray());
            insert.Parameters.AddWithValue("cohort", plan.CohortId.ToArray());
            insert.Parameters.AddWithValue("route", plan.RouteStateKey.ToArray());
            insert.Parameters.AddWithValue("source", plan.VerifiedCache.SourceFingerprint.ToArray());
            insert.Parameters.AddWithValue("local", U64(source.LocalCommitGeneration));
            insert.Parameters.AddWithValue("rol", source.RouteOriginLkgHash.ToArray());
            insert.Parameters.AddWithValue("rhc", history?.CanonicalCheckpointHash.ToArray()
                ?? new byte[32]);
            insert.Parameters.AddWithValue("transcript", source.TransitionTranscriptHash.ToArray());
            insert.Parameters.AddWithValue("publisher", plan.PublisherPublicKey.ToArray());
            insert.Parameters.AddWithValue("preparedIntegrity", preparedIntegrityTag);
            insert.Parameters.AddWithValue("phaseIntegrity", phaseIntegrityTag);
            insert.Parameters.AddWithValue("salt", materialized.CacheSalt.ToArray());
            insert.Parameters.AddWithValue("cacheTranscript",
                plan.VerifiedCache.CacheTranscriptHash.ToArray());
            insert.Parameters.AddWithValue("verified", U64(plan.VerifiedCache.VerifiedAtUnixSeconds));
            insert.Parameters.AddWithValue("expires", U64(plan.VerifiedCache.CacheExpiresAtUnixSeconds));
            insert.Parameters.AddWithValue("mode", (short)plan.VerifiedCache.Mode);
            insert.Parameters.AddWithValue("authorization",
                (short)plan.VerifiedCache.AuthorizationKind);
            insert.Parameters.AddWithValue("envelope", materialized.CanonicalEnvelope.ToArray());
            insert.Parameters.AddWithValue("envelopeHash", materialized.EnvelopeSha256.ToArray());
            insert.Parameters.AddWithValue("lineage", materialized.LineageCommitment.ToArray());
            insert.Parameters.AddWithValue("selection",
                plan.VerifiedCache.SelectionInputCommitment.ToArray());
            insert.Parameters.AddWithValue("oldSelection",
                plan.VerifiedCache.DurableOldSelectionHash.ToArray());
            await insert.ExecuteNonQueryAsync(cancellationToken);
        }
        foreach (var target in plan.VerifiedCache.Targets)
        {
            await using var insert = new NpgsqlCommand(
                """
                INSERT INTO production_mailbox_v2_activation_targets(
                    activation_state_key,target_replica_id,endpoint,current_spki_sha256,
                    next_spki_sha256,canonical_attempt,attempt_sha256,attempted_at,acknowledged)
                VALUES(@activation,@target,@endpoint,@current,@next,NULL,NULL,NULL,false)
                """, connection, transaction);
            insert.Parameters.AddWithValue("activation", plan.ActivationStateKey.ToArray());
            insert.Parameters.AddWithValue("target", target.ReplicaId.ToArray());
            insert.Parameters.AddWithValue("endpoint", target.Endpoint);
            insert.Parameters.AddWithValue("current", target.CurrentSpkiSha256.ToArray());
            insert.Parameters.AddWithValue("next", target.NextSpkiSha256.ToArray());
            await insert.ExecuteNonQueryAsync(cancellationToken);
        }
        await transaction.CommitAsync(cancellationToken);
        var created = await ((IProductionMailboxV2PublicationStateStore)this)
            .GetV2ActivationAsync(plan.ActivationStateKey, cancellationToken)
            ?? throw new InvalidDataException("Committed PMC2 activation disappeared.");
        return new(ProductionMailboxV2ActivationCommitStatus.Accepted, created);
    }

    async ValueTask<ProductionMailboxV2ActivationCommitResult>
        IProductionMailboxV2PublicationStateStore.RecordV2ActivationAttestationAsync(
            ReadOnlyMemory<byte> activationStateKey,
            ReadOnlyMemory<byte> verifiedPlanSignature,
            CancellationToken cancellationToken)
    {
        var key = ProductionMailboxRouteContinuityStateGuard.FreezeKey(activationStateKey);
        if (verifiedPlanSignature.Length != 64)
            throw new InvalidDataException("PMC2 activation attestation is invalid.");
        var signature = verifiedPlanSignature.ToArray();
        await using var connection = await OpenAsync(cancellationToken);
        await EnsureV2PublicationSchemaAsync(connection, cancellationToken);
        await EnsureRouteContinuitySchemaAsync(connection, cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(
            IsolationLevel.ReadCommitted, cancellationToken);
        byte[] routeKey;
        await using (var probe = new NpgsqlCommand(
            "SELECT route_state_key FROM production_mailbox_v2_activations WHERE activation_state_key=@key AND octet_length(route_state_key)=32",
            connection, transaction))
        {
            probe.Parameters.AddWithValue("key", key);
            var value = await probe.ExecuteScalarAsync(cancellationToken);
            if (value is not byte[] bytes)
            {
                await transaction.RollbackAsync(cancellationToken);
                return new(ProductionMailboxV2ActivationCommitStatus.MissingSource, null);
            }
            routeKey = bytes;
        }
        await V2AdvisoryLocksAsync(connection, transaction, cancellationToken, routeKey, key);
        var activation = await ReadV2ActivationAsync(connection, transaction, key, true,
            cancellationToken);
        if (activation is null)
        {
            await transaction.RollbackAsync(cancellationToken);
            return new(ProductionMailboxV2ActivationCommitStatus.MissingSource, null);
        }
        if (activation.VerifiedPlanSignature.Length != 0)
        {
            var exact = Fixed(activation.VerifiedPlanSignature.Span, signature);
            await transaction.CommitAsync(cancellationToken);
            return new(exact ? ProductionMailboxV2ActivationCommitStatus.ExactReplay
                : ProductionMailboxV2ActivationCommitStatus.Conflict,
                exact ? activation : null);
        }
        var source = await ReadRouteContinuityAsync(connection, transaction, routeKey, true,
            cancellationToken);
        if (source is null || !Fixed(ProductionMailboxV2SourceFingerprint.Compute(source),
                activation.SourceFingerprint.Span))
        {
            await transaction.RollbackAsync(cancellationToken);
            return new(ProductionMailboxV2ActivationCommitStatus.SourceChanged, null);
        }
        if (!PublicKeyAuth.VerifyDetached(signature,
                ProductionMailboxV2ActivationAttestation.GetSigningBytes(activation),
                activation.PublisherPublicKey.ToArray()))
        {
            await transaction.RollbackAsync(cancellationToken);
            return new(ProductionMailboxV2ActivationCommitStatus.Conflict, null);
        }
        var phaseIntegrityTag = ProductionMailboxV2PhaseIntegrity.Compute(
            activation, V2PreparedIntegrityKey, signatureOverride: signature);
        await using (var update = new NpgsqlCommand(
            "UPDATE production_mailbox_v2_activations SET verified_plan_signature=@signature,phase_integrity_tag=@phase WHERE activation_state_key=@key AND verified_plan_signature IS NULL",
            connection, transaction))
        {
            update.Parameters.AddWithValue("signature", signature);
            update.Parameters.AddWithValue("phase", phaseIntegrityTag);
            update.Parameters.AddWithValue("key", key);
            if (await update.ExecuteNonQueryAsync(cancellationToken) != 1)
                throw new InvalidDataException("PMC2 activation attestation CAS failed.");
        }
        await transaction.CommitAsync(cancellationToken);
        var attested = await ((IProductionMailboxV2PublicationStateStore)this)
            .GetV2ActivationAsync(key, cancellationToken)
            ?? throw new InvalidDataException("Attested PMC2 activation disappeared.");
        return new(ProductionMailboxV2ActivationCommitStatus.Accepted, attested);
    }

    async ValueTask<ProductionMailboxV2ActivationState?>
        IProductionMailboxV2PublicationStateStore.GetV2ActivationAsync(
            ReadOnlyMemory<byte> activationStateKey, CancellationToken cancellationToken)
    {
        var key = ProductionMailboxRouteContinuityStateGuard.FreezeKey(activationStateKey);
        await using var connection = await OpenAsync(cancellationToken);
        await EnsureV2PublicationSchemaAsync(connection, cancellationToken);
        return await ReadV2ActivationAsync(connection, null, key, false, cancellationToken);
    }

    async ValueTask<ProductionMailboxV2ActivationCommitResult>
        IProductionMailboxV2PublicationStateStore.GetCurrentV2ActivationForPublicationAsync(
            ReadOnlyMemory<byte> activationStateKey, uint minimumRemainingSeconds,
            CancellationToken cancellationToken)
    {
        var key = ProductionMailboxRouteContinuityStateGuard.FreezeKey(activationStateKey);
        await using var connection = await OpenAsync(cancellationToken);
        await EnsureV2PublicationSchemaAsync(connection, cancellationToken);
        await EnsureRouteContinuitySchemaAsync(connection, cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(
            IsolationLevel.Serializable, cancellationToken);
        byte[] routeKey;
        await using (var probe = new NpgsqlCommand(
            "SELECT route_state_key FROM production_mailbox_v2_activations WHERE activation_state_key=@key AND octet_length(route_state_key)=32",
            connection, transaction))
        {
            probe.Parameters.AddWithValue("key", key);
            routeKey = await probe.ExecuteScalarAsync(cancellationToken) as byte[] ?? [];
        }
        if (routeKey.Length != 32)
        {
            await transaction.RollbackAsync(cancellationToken);
            return new(ProductionMailboxV2ActivationCommitStatus.MissingSource, null);
        }
        await AdvisoryLocksAsync(connection, transaction, routeKey, key, cancellationToken);
        var activation = await ReadV2ActivationAsync(connection, transaction, key, true,
            cancellationToken);
        if (activation is null)
        {
            await transaction.RollbackAsync(cancellationToken);
            return new(ProductionMailboxV2ActivationCommitStatus.MissingSource, null);
        }
        if (activation.Published)
        {
            await transaction.CommitAsync(cancellationToken);
            return new(ProductionMailboxV2ActivationCommitStatus.Published, activation);
        }
        if (activation.VerifiedPlanSignature.Length != 64)
        {
            await transaction.CommitAsync(cancellationToken);
            return new(ProductionMailboxV2ActivationCommitStatus.Incomplete, null);
        }
        var source = await ReadRouteContinuityAsync(connection, transaction,
            routeKey, true, cancellationToken);
        if (source is null || !Fixed(ProductionMailboxV2SourceFingerprint.Compute(source),
                activation.SourceFingerprint.Span))
        {
            await transaction.RollbackAsync(cancellationToken);
            return new(ProductionMailboxV2ActivationCommitStatus.SourceChanged, null);
        }
        var now = await ReadDatabaseNowAsync(connection, transaction, cancellationToken);
        if (activation.CacheExpiresAtUnixSeconds < checked(now + minimumRemainingSeconds))
        {
            await transaction.CommitAsync(cancellationToken);
            return new(ProductionMailboxV2ActivationCommitStatus.Expired, null);
        }
        await transaction.CommitAsync(cancellationToken);
        return new(ProductionMailboxV2ActivationCommitStatus.Accepted, activation);
    }

    async ValueTask<IReadOnlyList<byte[]>>
        IProductionMailboxV2PublicationStateStore.ListPendingV2ActivationKeysAsync(
            int maximumCount, CancellationToken cancellationToken)
    {
        if (maximumCount is < 1 or > 1024) throw new ArgumentOutOfRangeException(nameof(maximumCount));
        await using var connection = await OpenAsync(cancellationToken);
        await EnsureV2PublicationSchemaAsync(connection, cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(
            IsolationLevel.Serializable, cancellationToken);
        await using var command = new NpgsqlCommand(
            "SELECT activation_state_key FROM production_mailbox_v2_activations WHERE published=false AND octet_length(activation_state_key)=32 ORDER BY activation_state_key LIMIT @limit FOR UPDATE",
            connection, transaction);
        command.Parameters.AddWithValue("limit", checked(maximumCount * 4));
        var values = new List<byte[]>();
        var candidates = new List<byte[]>();
        var now = await ReadDatabaseNowAsync(connection, transaction, cancellationToken);
        await using (var reader = await command.ExecuteReaderAsync(cancellationToken))
        {
            while (await reader.ReadAsync(cancellationToken))
                candidates.Add(reader.GetFieldValue<byte[]>(0));
        }
        foreach (var key in candidates)
        {
            var activation = await ReadV2ActivationAsync(connection, transaction, key,
                true, cancellationToken)
                ?? throw new InvalidDataException("Stored PMC2 pending activation disappeared.");
            if (activation.CacheExpiresAtUnixSeconds > now)
            {
                if (activation.VerifiedPlanSignature.Length == 64
                    && values.Count < maximumCount) values.Add(key);
                continue;
            }
            await using var removeTargets = new NpgsqlCommand(
                "DELETE FROM production_mailbox_v2_activation_targets WHERE activation_state_key=@key",
                connection, transaction);
            removeTargets.Parameters.AddWithValue("key", key);
            await removeTargets.ExecuteNonQueryAsync(cancellationToken);
            await using var remove = new NpgsqlCommand(
                "DELETE FROM production_mailbox_v2_activations WHERE activation_state_key=@key AND published=false",
                connection, transaction);
            remove.Parameters.AddWithValue("key", key);
            await remove.ExecuteNonQueryAsync(cancellationToken);
        }
        await transaction.CommitAsync(cancellationToken);
        return values;
    }

    async ValueTask<bool>
        IProductionMailboxV2PublicationStateStore.RecordV2PublicationAttemptAsync(
            ReadOnlyMemory<byte> activationStateKey, ReadOnlyMemory<byte> targetReplicaId,
            ReadOnlyMemory<byte> canonicalCommand, uint maximumSkewSeconds,
            uint minimumRemainingSeconds,
            CancellationToken cancellationToken)
    {
        var key = ProductionMailboxRouteContinuityStateGuard.FreezeKey(activationStateKey);
        var replica = ProductionMailboxRouteContinuityStateGuard.FreezeKey(targetReplicaId);
        var inspected = ProductionMailboxV2AttemptGuard.FreezeAndInspect(canonicalCommand);
        await using var connection = await OpenAsync(cancellationToken);
        await EnsureV2PublicationSchemaAsync(connection, cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(
            IsolationLevel.Serializable, cancellationToken);
        await AdvisoryLocksAsync(connection, transaction, key, replica, cancellationToken);
        var activation = await ReadV2ActivationAsync(connection, transaction, key, true,
            cancellationToken);
        if (activation is null || activation.Published
            || activation.VerifiedPlanSignature.Length != 64)
        {
            await transaction.RollbackAsync(cancellationToken); return false;
        }
        var target = activation.Targets.SingleOrDefault(candidate =>
            Fixed(candidate.ReplicaId.Span, replica));
        if (target is null || !ProductionMailboxV2AttemptGuard.Matches(inspected,
                activation.EnvelopeSha256.Span, activation.CohortId.Span, replica,
                activation.PublisherPublicKey.Span))
        {
            await transaction.RollbackAsync(cancellationToken); return false;
        }
        var hash = SHA256.HashData(inspected.CanonicalBytes);
        if (target.AttemptSha256 is { } exact && Fixed(exact.Span, hash))
        {
            await transaction.CommitAsync(cancellationToken); return true;
        }
        var now = await ReadDatabaseNowAsync(connection, transaction, cancellationToken);
        if (activation.CacheExpiresAtUnixSeconds < checked(now + minimumRemainingSeconds))
        {
            await transaction.RollbackAsync(cancellationToken); return false;
        }
        if (target.AttemptedAtUnixSeconds is not null
            && now <= checked(target.AttemptedAtUnixSeconds.Value + maximumSkewSeconds)
            || !ProductionMailboxV2AttemptGuard.IsFresh(
                inspected.TimestampUnixSeconds, now, maximumSkewSeconds))
        {
            await transaction.RollbackAsync(cancellationToken); return false;
        }
        var changedTargets = activation.Targets.Select(candidate =>
            Fixed(candidate.ReplicaId.Span, replica)
                ? new ProductionMailboxV2ActivationTargetState(
                    candidate.ReplicaId.ToArray(), candidate.Endpoint,
                    candidate.CurrentSpkiSha256.ToArray(),
                    candidate.NextSpkiSha256.ToArray(), inspected.CanonicalBytes,
                    hash, inspected.TimestampUnixSeconds, false)
                : candidate).ToArray();
        var phaseIntegrityTag = ProductionMailboxV2PhaseIntegrity.Compute(
            activation, V2PreparedIntegrityKey, targetsOverride: changedTargets);
        await using var update = new NpgsqlCommand(
            """
            UPDATE production_mailbox_v2_activation_targets
            SET canonical_attempt=@command,attempt_sha256=@hash,attempted_at=@attempted,
                acknowledged=false
            WHERE activation_state_key=@activation AND target_replica_id=@target
            """, connection, transaction);
        update.Parameters.AddWithValue("command", inspected.CanonicalBytes);
        update.Parameters.AddWithValue("hash", hash);
        update.Parameters.AddWithValue("attempted", U64(inspected.TimestampUnixSeconds));
        update.Parameters.AddWithValue("activation", key);
        update.Parameters.AddWithValue("target", replica);
        var changed = await update.ExecuteNonQueryAsync(cancellationToken) == 1;
        if (changed)
        {
            await using var updatePhase = new NpgsqlCommand(
                "UPDATE production_mailbox_v2_activations SET phase_integrity_tag=@phase WHERE activation_state_key=@key",
                connection, transaction);
            updatePhase.Parameters.AddWithValue("phase", phaseIntegrityTag);
            updatePhase.Parameters.AddWithValue("key", key);
            changed = await updatePhase.ExecuteNonQueryAsync(cancellationToken) == 1;
        }
        if (changed) await transaction.CommitAsync(cancellationToken);
        else await transaction.RollbackAsync(cancellationToken);
        return changed;
    }

    async ValueTask<bool>
        IProductionMailboxV2PublicationStateStore.AcknowledgeV2PublicationAttemptAsync(
            ReadOnlyMemory<byte> activationStateKey, ReadOnlyMemory<byte> targetReplicaId,
            ReadOnlyMemory<byte> attemptSha256, CancellationToken cancellationToken)
    {
        var key = ProductionMailboxRouteContinuityStateGuard.FreezeKey(activationStateKey);
        var replica = ProductionMailboxRouteContinuityStateGuard.FreezeKey(targetReplicaId);
        var attempt = ProductionMailboxRouteContinuityStateGuard.FreezeKey(attemptSha256);
        await using var connection = await OpenAsync(cancellationToken);
        await EnsureV2PublicationSchemaAsync(connection, cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(
            IsolationLevel.Serializable, cancellationToken);
        await AdvisoryLocksAsync(connection, transaction, key, replica, cancellationToken);
        var activation = await ReadV2ActivationAsync(connection, transaction, key, true,
            cancellationToken);
        if (activation is null || activation.Published
            || activation.VerifiedPlanSignature.Length != 64)
        {
            await transaction.RollbackAsync(cancellationToken); return false;
        }
        var target = activation.Targets.SingleOrDefault(candidate =>
            Fixed(candidate.ReplicaId.Span, replica));
        if (target?.AttemptSha256 is not { } storedAttempt
            || !Fixed(storedAttempt.Span, attempt))
        {
            await transaction.RollbackAsync(cancellationToken); return false;
        }
        if (target.Acknowledged)
        {
            await transaction.CommitAsync(cancellationToken); return true;
        }
        var changedTargets = activation.Targets.Select(candidate =>
            Fixed(candidate.ReplicaId.Span, replica)
                ? new ProductionMailboxV2ActivationTargetState(
                    candidate.ReplicaId.ToArray(), candidate.Endpoint,
                    candidate.CurrentSpkiSha256.ToArray(),
                    candidate.NextSpkiSha256.ToArray(),
                    candidate.CanonicalAttempt?.ToArray(), candidate.AttemptSha256?.ToArray(),
                    candidate.AttemptedAtUnixSeconds, true)
                : candidate).ToArray();
        var phaseIntegrityTag = ProductionMailboxV2PhaseIntegrity.Compute(
            activation, V2PreparedIntegrityKey, targetsOverride: changedTargets);
        await using var update = new NpgsqlCommand(
            "UPDATE production_mailbox_v2_activation_targets SET acknowledged=true WHERE activation_state_key=@activation AND target_replica_id=@target AND attempt_sha256=@attempt",
            connection, transaction);
        update.Parameters.AddWithValue("activation", key);
        update.Parameters.AddWithValue("target", replica);
        update.Parameters.AddWithValue("attempt", attempt);
        var changed = await update.ExecuteNonQueryAsync(cancellationToken) == 1;
        if (changed)
        {
            await using var updatePhase = new NpgsqlCommand(
                "UPDATE production_mailbox_v2_activations SET phase_integrity_tag=@phase WHERE activation_state_key=@key",
                connection, transaction);
            updatePhase.Parameters.AddWithValue("phase", phaseIntegrityTag);
            updatePhase.Parameters.AddWithValue("key", key);
            changed = await updatePhase.ExecuteNonQueryAsync(cancellationToken) == 1;
        }
        if (changed) await transaction.CommitAsync(cancellationToken);
        else await transaction.RollbackAsync(cancellationToken);
        return changed;
    }

    async ValueTask<ProductionMailboxV2ActivationCommitStatus>
        IProductionMailboxV2PublicationStateStore.TryFinalizeV2ActivationAsync(
            ReadOnlyMemory<byte> activationStateKey, uint capacityRenewalMarginSeconds,
            CancellationToken cancellationToken)
    {
        var key = ProductionMailboxRouteContinuityStateGuard.FreezeKey(activationStateKey);
        if (capacityRenewalMarginSeconds == 0)
            throw new ArgumentOutOfRangeException(nameof(capacityRenewalMarginSeconds));
        await using var connection = await OpenAsync(cancellationToken);
        await EnsureV2PublicationSchemaAsync(connection, cancellationToken);
        await EnsureRouteContinuitySchemaAsync(connection, cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(
            IsolationLevel.Serializable, cancellationToken);
        await using (var timeout = new NpgsqlCommand(
            "SELECT set_config('statement_timeout',@timeout,true)", connection, transaction))
        {
            var milliseconds = Math.Max(1UL,
                Math.Min(30_000UL, checked((ulong)capacityRenewalMarginSeconds * 500UL)));
            timeout.Parameters.AddWithValue("timeout", $"{milliseconds}ms");
            await timeout.ExecuteNonQueryAsync(cancellationToken);
        }
        byte[] routeProbe;
        await using (var probe = new NpgsqlCommand(
            "SELECT route_state_key FROM production_mailbox_v2_activations WHERE activation_state_key=@key",
            connection, transaction))
        {
            probe.Parameters.AddWithValue("key", key);
            routeProbe = await probe.ExecuteScalarAsync(cancellationToken) as byte[] ?? [];
        }
        if (routeProbe.Length != 32)
        {
            await transaction.RollbackAsync(cancellationToken);
            return ProductionMailboxV2ActivationCommitStatus.MissingSource;
        }
        await AdvisoryLocksAsync(connection, transaction, routeProbe, key,
            cancellationToken);
        var activation = await ReadV2ActivationAsync(connection, transaction, key, true,
            cancellationToken);
        if (activation is null || !Fixed(activation.RouteStateKey.Span, routeProbe))
        {
            await transaction.RollbackAsync(cancellationToken);
            return ProductionMailboxV2ActivationCommitStatus.SourceChanged;
        }
        if (activation.Published)
        {
            await transaction.CommitAsync(cancellationToken);
            return ProductionMailboxV2ActivationCommitStatus.Published;
        }
        if (activation.VerifiedPlanSignature.Length != 64)
        {
            await transaction.RollbackAsync(cancellationToken);
            return ProductionMailboxV2ActivationCommitStatus.Incomplete;
        }
        var source = await ReadRouteContinuityAsync(connection, transaction,
            activation.RouteStateKey.ToArray(), true, cancellationToken);
        if (source is null || !Fixed(ProductionMailboxV2SourceFingerprint.Compute(source),
                activation.SourceFingerprint.Span))
        {
            await transaction.RollbackAsync(cancellationToken);
            return ProductionMailboxV2ActivationCommitStatus.SourceChanged;
        }
        if (activation.Targets.Any(static target => !target.Acknowledged
                || target.CanonicalAttempt is null || target.AttemptSha256 is null
                || !Fixed(SHA256.HashData(target.CanonicalAttempt.Value.Span),
                    target.AttemptSha256.Value.Span))
            || activation.Targets.Any(target =>
                !ProductionMailboxV2AttemptGuard.Matches(
                    ProductionMailboxV2AttemptGuard.FreezeAndInspect(
                        target.CanonicalAttempt!.Value), activation.EnvelopeSha256.Span,
                    activation.CohortId.Span, target.ReplicaId.Span,
                    activation.PublisherPublicKey.Span)))
        {
            await transaction.RollbackAsync(cancellationToken);
            return ProductionMailboxV2ActivationCommitStatus.Incomplete;
        }
        var capacity = await ReadCapacityTargetsForFinalizationAsync(connection, transaction,
            activation.PromotionStateKey, cancellationToken);
        if (!capacity.Completed)
        {
            await transaction.RollbackAsync(cancellationToken);
            return ProductionMailboxV2ActivationCommitStatus.Incomplete;
        }
        var now = await ReadDatabaseNowAsync(connection, transaction, cancellationToken);
        var safeUntil = checked(now + capacityRenewalMarginSeconds);
        if (activation.CacheExpiresAtUnixSeconds < safeUntil
            || !CapacitySafe(activation, capacity.Targets, safeUntil))
        {
            await transaction.RollbackAsync(cancellationToken);
            return activation.CacheExpiresAtUnixSeconds < safeUntil
                ? ProductionMailboxV2ActivationCommitStatus.Expired
                : ProductionMailboxV2ActivationCommitStatus.Incomplete;
        }
        // Re-evaluate source and time at the final write boundary while all rows stay locked.
        source = await ReadRouteContinuityAsync(connection, transaction,
            activation.RouteStateKey.ToArray(), true, cancellationToken);
        now = await ReadDatabaseNowAsync(connection, transaction, cancellationToken);
        safeUntil = checked(now + capacityRenewalMarginSeconds);
        if (source is null || !Fixed(ProductionMailboxV2SourceFingerprint.Compute(source),
                activation.SourceFingerprint.Span))
        {
            await transaction.RollbackAsync(cancellationToken);
            return ProductionMailboxV2ActivationCommitStatus.SourceChanged;
        }
        if (activation.CacheExpiresAtUnixSeconds < safeUntil
            || !CapacitySafe(activation, capacity.Targets, safeUntil))
        {
            await transaction.RollbackAsync(cancellationToken);
            return ProductionMailboxV2ActivationCommitStatus.Incomplete;
        }
        var phaseIntegrityTag = ProductionMailboxV2PhaseIntegrity.Compute(
            activation, V2PreparedIntegrityKey, publishedOverride: true);
        await using var update = new NpgsqlCommand(
            "UPDATE production_mailbox_v2_activations SET published=true,phase_integrity_tag=@phase WHERE activation_state_key=@key AND published=false",
            connection, transaction);
        update.Parameters.AddWithValue("key", key);
        update.Parameters.AddWithValue("phase", phaseIntegrityTag);
        if (await update.ExecuteNonQueryAsync(cancellationToken) != 1)
        {
            await transaction.RollbackAsync(cancellationToken);
            return ProductionMailboxV2ActivationCommitStatus.Conflict;
        }
        await transaction.CommitAsync(cancellationToken);
        return ProductionMailboxV2ActivationCommitStatus.Published;
    }

    private async ValueTask EnsureV2PublicationSchemaAsync(
        NpgsqlConnection connection, CancellationToken cancellationToken)
    {
        if (v2PublicationInitialized) return;
        await v2PublicationInitializeGate.WaitAsync(cancellationToken);
        try
        {
            if (v2PublicationInitialized) return;
            const string sql = """
                CREATE TABLE IF NOT EXISTS production_mailbox_v2_activations(
                    activation_state_key bytea PRIMARY KEY CHECK(octet_length(activation_state_key)=32),
                    promotion_state_key bytea NOT NULL CHECK(octet_length(promotion_state_key)=32) REFERENCES production_mailbox_artifact_promotions(promotion_state_key),
                    cohort_id bytea NOT NULL CHECK(octet_length(cohort_id)=32),
                    route_state_key bytea NOT NULL CHECK(octet_length(route_state_key)=32),
                    source_fingerprint bytea NOT NULL CHECK(octet_length(source_fingerprint)=32),
                    source_local_commit_generation bytea NOT NULL CHECK(octet_length(source_local_commit_generation)=8),
                    route_origin_lkg_hash bytea NOT NULL CHECK(octet_length(route_origin_lkg_hash)=32),
                    route_history_checkpoint_hash bytea NOT NULL CHECK(octet_length(route_history_checkpoint_hash)=32),
                    transition_transcript_hash bytea NOT NULL CHECK(octet_length(transition_transcript_hash)=32),
                    publisher_public_key bytea NOT NULL CHECK(octet_length(publisher_public_key)=32),
                    verified_plan_signature bytea NULL CHECK(verified_plan_signature IS NULL OR octet_length(verified_plan_signature)=64),
                    prepared_integrity_tag bytea NOT NULL CHECK(octet_length(prepared_integrity_tag)=32),
                    phase_integrity_tag bytea NOT NULL CHECK(octet_length(phase_integrity_tag)=32),
                    cache_salt bytea NOT NULL CHECK(octet_length(cache_salt)=32),
                    cache_transcript_hash bytea NOT NULL CHECK(octet_length(cache_transcript_hash)=32),
                    verified_at bytea NOT NULL CHECK(octet_length(verified_at)=8),
                    cache_expires_at bytea NOT NULL CHECK(octet_length(cache_expires_at)=8),
                    mode smallint NOT NULL CHECK(mode IN (1,2)),
                    authorization_kind smallint NOT NULL CHECK(authorization_kind IN (1,2)),
                    canonical_envelope bytea NOT NULL CHECK(octet_length(canonical_envelope) BETWEEN 112 AND 8388720),
                    envelope_sha256 bytea NOT NULL CHECK(octet_length(envelope_sha256)=32),
                    lineage_commitment bytea NOT NULL CHECK(octet_length(lineage_commitment)=32),
                    selection_input_commitment bytea NOT NULL CHECK(octet_length(selection_input_commitment)=32),
                    durable_old_selection_hash bytea NOT NULL CHECK(octet_length(durable_old_selection_hash)=32),
                    published boolean NOT NULL);
                CREATE TABLE IF NOT EXISTS production_mailbox_v2_activation_targets(
                    activation_state_key bytea NOT NULL REFERENCES production_mailbox_v2_activations(activation_state_key),
                    target_replica_id bytea NOT NULL CHECK(octet_length(target_replica_id)=32),
                    endpoint text NOT NULL CHECK(octet_length(endpoint) BETWEEN 1 AND 512),
                    current_spki_sha256 bytea NOT NULL CHECK(octet_length(current_spki_sha256)=32),
                    next_spki_sha256 bytea NOT NULL CHECK(octet_length(next_spki_sha256)=32),
                    canonical_attempt bytea NULL CHECK(canonical_attempt IS NULL OR octet_length(canonical_attempt) BETWEEN 280 AND 8389000),
                    attempt_sha256 bytea NULL CHECK(attempt_sha256 IS NULL OR octet_length(attempt_sha256)=32),
                    attempted_at bytea NULL CHECK(attempted_at IS NULL OR octet_length(attempted_at)=8),
                    acknowledged boolean NOT NULL,
                    PRIMARY KEY(activation_state_key,target_replica_id));
                CREATE INDEX IF NOT EXISTS ix_production_mailbox_v2_activations_pending
                    ON production_mailbox_v2_activations(published,activation_state_key);
                CREATE INDEX IF NOT EXISTS ix_production_mailbox_v2_lineage
                    ON production_mailbox_v2_activations(
                        selection_input_commitment,durable_old_selection_hash,activation_state_key);
                """;
            await using var command = new NpgsqlCommand(sql, connection);
            await command.ExecuteNonQueryAsync(cancellationToken);
            v2PublicationInitialized = true;
        }
        finally { v2PublicationInitializeGate.Release(); }
    }

    private async ValueTask<ProductionMailboxV2ActivationState?> ReadV2ActivationAsync(
        NpgsqlConnection connection, NpgsqlTransaction? transaction,
        ReadOnlyMemory<byte> activationStateKey, bool forUpdate,
        CancellationToken cancellationToken)
    {
        var sql = "SELECT promotion_state_key,cohort_id,route_state_key,source_fingerprint,source_local_commit_generation,route_origin_lkg_hash,route_history_checkpoint_hash,transition_transcript_hash,publisher_public_key,verified_plan_signature,prepared_integrity_tag,phase_integrity_tag,cache_salt,cache_transcript_hash,verified_at,cache_expires_at,mode,authorization_kind,canonical_envelope,envelope_sha256,lineage_commitment,selection_input_commitment,durable_old_selection_hash,published FROM production_mailbox_v2_activations WHERE activation_state_key=@key AND octet_length(promotion_state_key)=32 AND octet_length(cohort_id)=32 AND octet_length(route_state_key)=32 AND octet_length(source_fingerprint)=32 AND octet_length(source_local_commit_generation)=8 AND octet_length(route_origin_lkg_hash)=32 AND octet_length(route_history_checkpoint_hash)=32 AND octet_length(transition_transcript_hash)=32 AND octet_length(publisher_public_key)=32 AND (verified_plan_signature IS NULL OR octet_length(verified_plan_signature)=64) AND octet_length(prepared_integrity_tag)=32 AND octet_length(phase_integrity_tag)=32 AND octet_length(cache_salt)=32 AND octet_length(cache_transcript_hash)=32 AND octet_length(verified_at)=8 AND octet_length(cache_expires_at)=8 AND octet_length(canonical_envelope) BETWEEN 112 AND 8388720 AND octet_length(envelope_sha256)=32 AND octet_length(lineage_commitment)=32 AND octet_length(selection_input_commitment)=32 AND octet_length(durable_old_selection_hash)=32"
            + (forUpdate ? " FOR UPDATE" : string.Empty);
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue("key", activationStateKey.ToArray());
        byte[] promotion; byte[] cohort; byte[] route; byte[] source; ulong local;
        byte[] rol; byte[] rhc; byte[] transcript; byte[] publisher; byte[] planSignature;
        byte[] preparedIntegrityTag; byte[] phaseIntegrityTag;
        byte[] salt;
        byte[] cacheTranscript; ulong verified; ulong expires; short mode; short authorization;
        byte[] envelope; byte[] envelopeHash; byte[] lineage; byte[] selection; byte[] oldSelection;
        bool published;
        await using (var reader = await command.ExecuteReaderAsync(cancellationToken))
        {
            if (!await reader.ReadAsync(cancellationToken)) return null;
            promotion = reader.GetFieldValue<byte[]>(0); cohort = reader.GetFieldValue<byte[]>(1);
            route = reader.GetFieldValue<byte[]>(2); source = reader.GetFieldValue<byte[]>(3);
            local = ReadU64(reader.GetFieldValue<byte[]>(4)); rol = reader.GetFieldValue<byte[]>(5);
            rhc = reader.GetFieldValue<byte[]>(6); transcript = reader.GetFieldValue<byte[]>(7);
            publisher = reader.GetFieldValue<byte[]>(8);
            planSignature = reader.IsDBNull(9) ? [] : reader.GetFieldValue<byte[]>(9);
            preparedIntegrityTag = reader.GetFieldValue<byte[]>(10);
            phaseIntegrityTag = reader.GetFieldValue<byte[]>(11);
            salt = reader.GetFieldValue<byte[]>(12); cacheTranscript = reader.GetFieldValue<byte[]>(13);
            verified = ReadU64(reader.GetFieldValue<byte[]>(14));
            expires = ReadU64(reader.GetFieldValue<byte[]>(15)); mode = reader.GetInt16(16);
            authorization = reader.GetInt16(17); envelope = reader.GetFieldValue<byte[]>(18);
            envelopeHash = reader.GetFieldValue<byte[]>(19); lineage = reader.GetFieldValue<byte[]>(20);
            selection = reader.GetFieldValue<byte[]>(21); oldSelection = reader.GetFieldValue<byte[]>(22);
            published = reader.GetBoolean(23);
        }
        var targets = new List<ProductionMailboxV2ActivationTargetState>();
        await using var targetCommand = new NpgsqlCommand(
            "SELECT target_replica_id,endpoint,current_spki_sha256,next_spki_sha256,canonical_attempt,attempt_sha256,attempted_at,acknowledged FROM production_mailbox_v2_activation_targets WHERE activation_state_key=@key AND octet_length(target_replica_id)=32 AND octet_length(endpoint) BETWEEN 1 AND 512 AND octet_length(current_spki_sha256)=32 AND octet_length(next_spki_sha256)=32 AND (canonical_attempt IS NULL OR octet_length(canonical_attempt) BETWEEN 280 AND 8389000) AND (attempt_sha256 IS NULL OR octet_length(attempt_sha256)=32) AND (attempted_at IS NULL OR octet_length(attempted_at)=8) ORDER BY target_replica_id LIMIT 7"
            + (forUpdate ? " FOR UPDATE" : string.Empty), connection, transaction);
        targetCommand.Parameters.AddWithValue("key", activationStateKey.ToArray());
        await using var targetReader = await targetCommand.ExecuteReaderAsync(cancellationToken);
        while (await targetReader.ReadAsync(cancellationToken))
            targets.Add(new(targetReader.GetFieldValue<byte[]>(0), targetReader.GetString(1),
                targetReader.GetFieldValue<byte[]>(2), targetReader.GetFieldValue<byte[]>(3),
                targetReader.IsDBNull(4) ? null : targetReader.GetFieldValue<byte[]>(4),
                targetReader.IsDBNull(5) ? null : targetReader.GetFieldValue<byte[]>(5),
                targetReader.IsDBNull(6) ? null : ReadU64(targetReader.GetFieldValue<byte[]>(6)),
                targetReader.GetBoolean(7)));
        if (targets.Count > 6)
            throw new InvalidDataException("Stored PMC2 activation target count is invalid.");
        var state = new ProductionMailboxV2ActivationState(activationStateKey.ToArray(),
            promotion, cohort, route, source, local, rol, rhc, transcript, publisher,
            planSignature, preparedIntegrityTag, phaseIntegrityTag, salt,
            cacheTranscript, verified, expires, (ProductionMailboxSelectionSuccessorMode)mode,
            (ProductionMailboxRouteAuthorizationKind)authorization, envelope, envelopeHash,
            lineage, selection, oldSelection, targets, published);
        ValidateStoredV2Activation(state);
        ProductionMailboxV2PreparedIntegrity.Verify(state, V2PreparedIntegrityKey);
        ProductionMailboxV2PhaseIntegrity.Verify(state, V2PreparedIntegrityKey);
        return state;
    }

    private static async ValueTask<(bool Completed,
        IReadOnlyList<ProductionMailboxCapacityTargetState> Targets)>
        ReadCapacityTargetsForFinalizationAsync(NpgsqlConnection connection,
            NpgsqlTransaction transaction, ReadOnlyMemory<byte> promotionStateKey,
            CancellationToken cancellationToken)
    {
        bool completed;
        await using (var plan = new NpgsqlCommand(
            "SELECT completed FROM production_mailbox_capacity_plans WHERE promotion_state_key=@key FOR UPDATE",
            connection, transaction))
        {
            plan.Parameters.AddWithValue("key", promotionStateKey.ToArray());
            var value = await plan.ExecuteScalarAsync(cancellationToken);
            if (value is not bool result) return (false, []);
            completed = result;
        }
        var targets = new List<ProductionMailboxCapacityTargetState>();
        await using var command = new NpgsqlCommand(
            "SELECT target_replica_id,endpoint,current_spki_sha256,next_spki_sha256,reserved_closure_count,reserved_bytes,revision,receipt_expires_at,last_command_sha256,canonical_receipt,pending_canonical_command,pending_revision,released FROM production_mailbox_capacity_targets WHERE promotion_state_key=@key ORDER BY target_replica_id FOR UPDATE",
            connection, transaction);
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
        return (completed, targets);
    }

    private static async ValueTask<ulong> ReadDatabaseNowAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand(
            "SELECT CAST(extract(epoch from clock_timestamp()) AS bigint)",
            connection, transaction);
        return checked((ulong)(long)(await command.ExecuteScalarAsync(cancellationToken)
            ?? throw new InvalidDataException("PostgreSQL clock is unavailable.")));
    }

    private static bool ExactLogical(ProductionMailboxV2ActivationState existing,
        ProductionMailboxV2ActivationPlan plan)
    {
        var cache = plan.VerifiedCache;
        return Fixed(existing.PromotionStateKey.Span, plan.PromotionStateKey.Span)
            && Fixed(existing.CohortId.Span, plan.CohortId.Span)
            && Fixed(existing.RouteStateKey.Span, plan.RouteStateKey.Span)
            && Fixed(existing.PublisherPublicKey.Span, plan.PublisherPublicKey.Span)
            && Fixed(existing.SourceFingerprint.Span, cache.SourceFingerprint.Span)
            && Fixed(existing.CacheTranscriptHash.Span, cache.CacheTranscriptHash.Span)
            && Fixed(existing.SelectionInputCommitment.Span,
                cache.SelectionInputCommitment.Span)
            && Fixed(existing.DurableOldSelectionHash.Span,
                cache.DurableOldSelectionHash.Span)
            && existing.VerifiedAtUnixSeconds == cache.VerifiedAtUnixSeconds
            && existing.CacheExpiresAtUnixSeconds == cache.CacheExpiresAtUnixSeconds
            && existing.Mode == cache.Mode && existing.AuthorizationKind == cache.AuthorizationKind
            && ExactTargets(existing.Targets, cache.Targets);
    }

    private static bool ExactTargets(
        IReadOnlyList<ProductionMailboxV2ActivationTargetState> existing,
        IReadOnlyList<ProductionMailboxV2Target> candidate) => existing.Count == candidate.Count
        && existing.Zip(candidate).All(pair => Fixed(pair.First.ReplicaId.Span,
                pair.Second.ReplicaId.Span) && pair.First.Endpoint == pair.Second.Endpoint
            && Fixed(pair.First.CurrentSpkiSha256.Span,
                pair.Second.CurrentSpkiSha256.Span)
            && Fixed(pair.First.NextSpkiSha256.Span, pair.Second.NextSpkiSha256.Span));

    private static bool CapacitySafe(ProductionMailboxV2ActivationState activation,
        IReadOnlyList<ProductionMailboxCapacityTargetState> targets, ulong safeUntil)
    {
        foreach (var activationTarget in activation.Targets)
        {
            var target = targets.SingleOrDefault(candidate =>
                Fixed(candidate.TargetReplicaId, activationTarget.ReplicaId.Span));
            if (target is null || target.Released || target.CanonicalReceipt is null
                || target.LastCommandSha256 is null || target.PendingCanonicalCommand is not null
                || target.PendingRevision is not null || target.ReceiptExpiresAtUnixSeconds is null
                || target.ReceiptExpiresAtUnixSeconds.Value < safeUntil) return false;
            ProductionMailboxCapacityReceipt receipt;
            try
            {
                receipt = ProductionMailboxCapacityReceiptCodec.DecodeAndVerify(
                    target.CanonicalReceipt, target.TargetReplicaId);
            }
            catch (InvalidDataException) { return false; }
            if (receipt.Operation != ProductionMailboxCapacityOperation.ReserveOrRenew
                || receipt.Revision != target.Revision
                || receipt.ExpiresAtUnixSeconds != target.ReceiptExpiresAtUnixSeconds.Value
                || receipt.ReservedClosureCount != target.ReservedClosureCount
                || receipt.ReservedBytes != target.ReservedBytes
                || !Fixed(receipt.CohortId, activation.CohortId.Span)
                || !Fixed(receipt.CommandSha256, target.LastCommandSha256)) return false;
        }
        return true;
    }

    private static void ValidateStoredV2Activation(ProductionMailboxV2ActivationState value)
    {
        if (value.ActivationStateKey.Length != 32 || value.PromotionStateKey.Length != 32
            || value.CohortId.Length != 32 || value.RouteStateKey.Length != 32
            || value.SourceFingerprint.Length != 32 || value.RouteOriginLkgHash.Length != 32
            || value.RouteHistoryCheckpointHash.Length != 32
            || value.TransitionTranscriptHash.Length != 32 || value.PublisherPublicKey.Length != 32
            || value.VerifiedPlanSignature.Length is not (0 or 64)
            || value.PreparedIntegrityTag.Length != 32
            || value.PhaseIntegrityTag.Length != 32
            || value.CacheSalt.Length != 32 || value.CacheTranscriptHash.Length != 32
            || value.EnvelopeSha256.Length != 32 || value.LineageCommitment.Length != 32
            || value.SelectionInputCommitment.Length != 32
            || value.DurableOldSelectionHash.Length != 32)
            throw new InvalidDataException("Stored PMC2 activation fixed fields are invalid.");
        if (value.CanonicalEnvelope.Length is < ProductionMailboxV2WireCodec.EnvelopeHeaderLength
                or > ProductionMailboxV2WireCodec.MaximumEnvelopeBytes
            || !Fixed(SHA256.HashData(value.CanonicalEnvelope.Span), value.EnvelopeSha256.Span))
            throw new InvalidDataException("Stored PMC2 activation envelope is invalid.");
        if (!Fixed(value.CanonicalEnvelope.Span.Slice(8, 32), value.CacheSalt.Span)
            || !Fixed(value.CanonicalEnvelope.Span.Slice(40, 32), value.LineageCommitment.Span))
            throw new InvalidDataException("Stored PMC2 activation commitment is invalid.");
        ProductionMailboxV2ClosureEnvelope envelope;
        try { envelope = ProductionMailboxV2WireCodec.DecodeEnvelope(value.CanonicalEnvelope.Span); }
        catch (Exception exception) when (exception is InvalidDataException or OverflowException)
        { throw new InvalidDataException("Stored PMC2 activation envelope is invalid.", exception); }
        var artifacts = new ProductionMailboxNodeCacheArtifacts
        {
            AuthorizationKind = envelope.AuthorizationKind,
            CanonicalAuthority = envelope.Authority,
            CanonicalRevocations = envelope.Revocations,
            CanonicalTopology = envelope.Topology,
            CanonicalCurrentSelection = envelope.CurrentSelection,
            CanonicalNextSelection = envelope.NextSelection,
            CanonicalSelectionSuccessorV2 = envelope.SelectionSuccessorV2,
            CanonicalRouteCertificate = envelope.RouteCertificate,
            CanonicalTransitionContext = envelope.TransitionContext,
            CanonicalRouteAuthorization = envelope.RouteAuthorization,
            CanonicalRevocationCheckpoint = envelope.RevocationCheckpoint
        };
        var pss = ProductionMailboxSelectionSuccessorV2Codec.Decode(
            envelope.SelectionSuccessorV2.Span);
        if (envelope.AuthorizationKind != value.AuthorizationKind
            || pss.NewAuthorizationKind != value.AuthorizationKind
            || pss.Selection.Mode != value.Mode
            || !Fixed(pss.Selection.SelectionInputCommitment.Span,
                value.SelectionInputCommitment.Span)
            || !Fixed(pss.Selection.OldCanonicalSelectionHash.Span,
                value.DurableOldSelectionHash.Span)
            || !Fixed(ProductionMailboxV2ActivationAttestation.ComputeCacheTranscriptHash(
                    artifacts), value.CacheTranscriptHash.Span))
            throw new InvalidDataException("Stored PMC2 verified transcript is invalid.");
        if (value.Targets.Count is < 1 or > 6)
            throw new InvalidDataException("Stored PMC2 activation target set is invalid.");
        byte[]? previousReplica = null;
        foreach (var target in value.Targets)
        {
            var hasCommand = target.CanonicalAttempt is { } command && !command.IsEmpty;
            var hasHash = target.AttemptSha256 is { } attempt && !attempt.IsEmpty;
            var hasTime = target.AttemptedAtUnixSeconds is not null;
            var endpointBytes = System.Text.Encoding.UTF8.GetByteCount(target.Endpoint);
            if (target.ReplicaId.Length != 32 || target.ReplicaId.Span.IndexOfAnyExcept((byte)0) < 0
                || target.CurrentSpkiSha256.Length != 32
                || target.NextSpkiSha256.Length != 32 || hasCommand != hasHash
                || target.CurrentSpkiSha256.Span.IndexOfAnyExcept((byte)0) < 0
                || target.NextSpkiSha256.Span.IndexOfAnyExcept((byte)0) < 0
                || endpointBytes is < 1 or > ProductionMailboxTopologyConstants.MaximumEndpointBytes
                || !Uri.TryCreate(target.Endpoint, UriKind.Absolute, out var endpoint)
                || endpoint.Scheme != Uri.UriSchemeHttps || endpoint.PathAndQuery != "/"
                || endpoint.UserInfo.Length != 0 || endpoint.Fragment.Length != 0
                || string.IsNullOrWhiteSpace(endpoint.Host)
                || endpoint.AbsoluteUri != target.Endpoint || hasCommand != hasTime
                || target.Acknowledged && !hasHash
                || previousReplica is not null && previousReplica.AsSpan()
                    .SequenceCompareTo(target.ReplicaId.Span) >= 0)
                throw new InvalidDataException("Stored PMC2 activation target row is invalid.");
            previousReplica = target.ReplicaId.ToArray();
        }
        if (value.VerifiedPlanSignature.Length == 64
            && !PublicKeyAuth.VerifyDetached(value.VerifiedPlanSignature.ToArray(),
                ProductionMailboxV2ActivationAttestation.GetSigningBytes(value),
                value.PublisherPublicKey.ToArray()))
            throw new InvalidDataException("Stored PMC2 activation attestation is invalid.");
    }

    private static async ValueTask V2AdvisoryLocksAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, CancellationToken cancellationToken,
        params ReadOnlyMemory<byte>[] keys)
    {
        foreach (var key in keys.Select(static value => value.ToArray())
            .Distinct(V2ByteArrayComparer.Instance)
            .OrderBy(static value => Convert.ToHexString(value), StringComparer.Ordinal))
            await AdvisoryLockAsync(connection, transaction, key, cancellationToken);
    }

    private sealed class V2ByteArrayComparer : IEqualityComparer<byte[]>
    {
        internal static V2ByteArrayComparer Instance { get; } = new();
        public bool Equals(byte[]? left, byte[]? right) => ReferenceEquals(left, right)
            || left is not null && right is not null && Fixed(left, right);
        public int GetHashCode(byte[] value)
        {
            var hash = new HashCode(); hash.AddBytes(value); return hash.ToHashCode();
        }
    }
}
