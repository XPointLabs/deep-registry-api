using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxTopology;

namespace Deep.Registry.Api.ProductionMailbox;

internal sealed class ProductionMailboxRouteHistoryStateSnapshot
{
    internal const int ProtectedEncodingLength = 860;
    private readonly byte[] canonicalCheckpoint;
    private readonly byte[] canonicalCheckpointHash;
    private readonly byte[] lastCommittedBatchHash;
    private readonly byte[] currentRouteOriginLkgHash;
    private readonly byte[] enrollmentCanonicalDelegationHash;
    private readonly byte[] enrollmentCanonicalAcceptanceHash;
    private readonly byte[] networkId;
    private readonly byte[] routeDomainHash;
    private readonly byte[] delegationHistoryBinding;
    private readonly byte[] pinnedMrXPublicKeySha256;
    private readonly byte[] currentCanonicalAuthorityHash;
    private readonly byte[] currentRevocationHeadHash;
    private readonly byte[] currentRevocationSnapshotHash;

    internal ProductionMailboxRouteHistoryStateSnapshot(
        ProductionMailboxRouteHistoryProtectedRestoreContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        canonicalCheckpoint = context.CanonicalCheckpoint.ToArray();
        canonicalCheckpointHash = context.CanonicalCheckpointHash.ToArray();
        LastCommittedBatchSequence = context.LastCommittedBatchSequence;
        lastCommittedBatchHash = context.LastCommittedBatchHash.ToArray();
        currentRouteOriginLkgHash = context.CurrentRouteOriginLkgHash.ToArray();
        enrollmentCanonicalDelegationHash =
            context.EnrollmentCanonicalDelegationHash.ToArray();
        enrollmentCanonicalAcceptanceHash =
            context.EnrollmentCanonicalAcceptanceHash.ToArray();
        networkId = context.NetworkId.ToArray();
        routeDomainHash = context.RouteDomainHash.ToArray();
        delegationHistoryBinding = context.DelegationHistoryBinding.ToArray();
        pinnedMrXPublicKeySha256 = context.PinnedMrXPublicKeySha256.ToArray();
        CurrentAuthorityGeneration = context.CurrentAuthorityGeneration;
        currentCanonicalAuthorityHash = context.CurrentCanonicalAuthorityHash.ToArray();
        CurrentRevocationGeneration = context.CurrentRevocationGeneration;
        currentRevocationHeadHash = context.CurrentRevocationHeadHash.ToArray();
        currentRevocationSnapshotHash = context.CurrentRevocationSnapshotHash.ToArray();

        // The public constructor is the protocol-owned fixed-layout and scalar validator.
        _ = ToProtectedRestoreContext();
    }

    internal ReadOnlyMemory<byte> CanonicalCheckpoint => canonicalCheckpoint.ToArray();
    internal ReadOnlyMemory<byte> CanonicalCheckpointHash => canonicalCheckpointHash.ToArray();
    internal ulong LastCommittedBatchSequence { get; }
    internal ReadOnlyMemory<byte> LastCommittedBatchHash => lastCommittedBatchHash.ToArray();
    internal ReadOnlyMemory<byte> CurrentRouteOriginLkgHash => currentRouteOriginLkgHash.ToArray();
    internal ReadOnlyMemory<byte> EnrollmentCanonicalDelegationHash =>
        enrollmentCanonicalDelegationHash.ToArray();
    internal ReadOnlyMemory<byte> EnrollmentCanonicalAcceptanceHash =>
        enrollmentCanonicalAcceptanceHash.ToArray();
    internal ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    internal ReadOnlyMemory<byte> RouteDomainHash => routeDomainHash.ToArray();
    internal ReadOnlyMemory<byte> DelegationHistoryBinding => delegationHistoryBinding.ToArray();
    internal ReadOnlyMemory<byte> PinnedMrXPublicKeySha256 => pinnedMrXPublicKeySha256.ToArray();
    internal ulong CurrentAuthorityGeneration { get; }
    internal ReadOnlyMemory<byte> CurrentCanonicalAuthorityHash =>
        currentCanonicalAuthorityHash.ToArray();
    internal ulong CurrentRevocationGeneration { get; }
    internal ReadOnlyMemory<byte> CurrentRevocationHeadHash => currentRevocationHeadHash.ToArray();
    internal ReadOnlyMemory<byte> CurrentRevocationSnapshotHash =>
        currentRevocationSnapshotHash.ToArray();

    internal ProductionMailboxRouteHistoryStateSnapshot Clone() =>
        new(ToProtectedRestoreContext());

    internal ProductionMailboxRouteHistoryProtectedRestoreContext ToProtectedRestoreContext() =>
        new(canonicalCheckpoint, canonicalCheckpointHash, LastCommittedBatchSequence,
            lastCommittedBatchHash, currentRouteOriginLkgHash,
            enrollmentCanonicalDelegationHash, enrollmentCanonicalAcceptanceHash, networkId,
            routeDomainHash, delegationHistoryBinding, pinnedMrXPublicKeySha256,
            CurrentAuthorityGeneration, currentCanonicalAuthorityHash,
            CurrentRevocationGeneration, currentRevocationHeadHash,
            currentRevocationSnapshotHash);

    internal byte[] EncodeProtected()
    {
        var encoded = new byte[ProtectedEncodingLength];
        "RHS1"u8.CopyTo(encoded);
        var offset = 4;
        Put(canonicalCheckpoint); Put(canonicalCheckpointHash);
        BinaryPrimitives.WriteUInt64BigEndian(encoded.AsSpan(offset, 8),
            LastCommittedBatchSequence); offset += 8;
        Put(lastCommittedBatchHash); Put(currentRouteOriginLkgHash);
        Put(enrollmentCanonicalDelegationHash); Put(enrollmentCanonicalAcceptanceHash);
        Put(networkId); Put(routeDomainHash); Put(delegationHistoryBinding);
        Put(pinnedMrXPublicKeySha256);
        BinaryPrimitives.WriteUInt64BigEndian(encoded.AsSpan(offset, 8),
            CurrentAuthorityGeneration); offset += 8;
        Put(currentCanonicalAuthorityHash);
        BinaryPrimitives.WriteUInt64BigEndian(encoded.AsSpan(offset, 8),
            CurrentRevocationGeneration); offset += 8;
        Put(currentRevocationHeadHash); Put(currentRevocationSnapshotHash);
        if (offset != encoded.Length)
            throw new InvalidDataException("Protected RHC1 encoding length is inconsistent.");
        return encoded;

        void Put(ReadOnlySpan<byte> value)
        {
            value.CopyTo(encoded.AsSpan(offset, value.Length));
            offset += value.Length;
        }
    }

    internal static ProductionMailboxRouteHistoryStateSnapshot DecodeProtected(
        ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length != ProtectedEncodingLength ||
            !encoded[..4].SequenceEqual("RHS1"u8))
            throw new InvalidDataException("Protected RHC1 encoding is invalid.");
        var owned = encoded.ToArray();
        var offset = 4;
        byte[] Take(int length)
        {
            var value = owned.AsSpan(offset, length).ToArray();
            offset += length;
            return value;
        }
        var checkpoint = Take(ProductionMailboxRouteContinuityConstants
            .CanonicalRouteHistoryCheckpointLength);
        var checkpointHash = Take(32);
        var sequence = BinaryPrimitives.ReadUInt64BigEndian(owned.AsSpan(offset, 8));
        offset += 8;
        var lastHash = Take(32); var rolHash = Take(32); var delegationHash = Take(32);
        var acceptanceHash = Take(32); var network = Take(16); var route = Take(32);
        var binding = Take(32); var mrx = Take(32);
        var authorityGeneration = BinaryPrimitives.ReadUInt64BigEndian(
            owned.AsSpan(offset, 8)); offset += 8;
        var authorityHash = Take(32);
        var revocationGeneration = BinaryPrimitives.ReadUInt64BigEndian(
            owned.AsSpan(offset, 8)); offset += 8;
        var revocationHead = Take(32); var revocationSnapshot = Take(32);
        if (offset != encoded.Length)
            throw new InvalidDataException("Protected RHC1 encoding has trailing bytes.");
        return new(new ProductionMailboxRouteHistoryProtectedRestoreContext(
            checkpoint, checkpointHash, sequence, lastHash, rolHash, delegationHash,
            acceptanceHash, network, route, binding, mrx, authorityGeneration,
            authorityHash, revocationGeneration, revocationHead, revocationSnapshot));
    }

    internal bool Exact(ProductionMailboxRouteHistoryStateSnapshot other) =>
        other is not null && LastCommittedBatchSequence == other.LastCommittedBatchSequence &&
        CurrentAuthorityGeneration == other.CurrentAuthorityGeneration &&
        CurrentRevocationGeneration == other.CurrentRevocationGeneration &&
        Fixed(canonicalCheckpoint, other.canonicalCheckpoint) &&
        Fixed(canonicalCheckpointHash, other.canonicalCheckpointHash) &&
        Fixed(lastCommittedBatchHash, other.lastCommittedBatchHash) &&
        Fixed(currentRouteOriginLkgHash, other.currentRouteOriginLkgHash) &&
        Fixed(enrollmentCanonicalDelegationHash, other.enrollmentCanonicalDelegationHash) &&
        Fixed(enrollmentCanonicalAcceptanceHash, other.enrollmentCanonicalAcceptanceHash) &&
        Fixed(networkId, other.networkId) && Fixed(routeDomainHash, other.routeDomainHash) &&
        Fixed(delegationHistoryBinding, other.delegationHistoryBinding) &&
        Fixed(pinnedMrXPublicKeySha256, other.pinnedMrXPublicKeySha256) &&
        Fixed(currentCanonicalAuthorityHash, other.currentCanonicalAuthorityHash) &&
        Fixed(currentRevocationHeadHash, other.currentRevocationHeadHash) &&
        Fixed(currentRevocationSnapshotHash, other.currentRevocationSnapshotHash);

    internal void ValidateAgainst(ProductionMailboxRouteContinuityStateSnapshot state)
    {
        _ = ToProtectedRestoreContext();
        if (!Fixed(ComputeCheckpointHash(canonicalCheckpoint), canonicalCheckpointHash))
            throw new InvalidDataException("Stored RHC1 checkpoint hash is inconsistent.");
        if (state.DelegationSequence == 0 ||
            !Fixed(enrollmentCanonicalDelegationHash, state.CanonicalDelegationHash.Span) ||
            !Fixed(enrollmentCanonicalAcceptanceHash,
                state.CanonicalDelegationAcceptanceHash.Span))
            throw new InvalidDataException("Stored RHC1 is not bound to the enrolled RCD1/RDA1.");
        var delegation = ProductionMailboxRouteContinuityCodec.DecodeDelegation(
            state.CanonicalDelegation.Span);
        var expectedBinding = ComputeDelegationHistoryBinding(
            state.CanonicalDelegationHash.Span,
            state.CanonicalDelegationAcceptanceHash.Span);
        if (!Fixed(networkId, delegation.NetworkId.Span) ||
            !Fixed(routeDomainHash, delegation.RouteDomainHash.Span) ||
            !Fixed(delegationHistoryBinding, expectedBinding) ||
            !Fixed(pinnedMrXPublicKeySha256, delegation.PinnedMrXPublicKeySha256.Span))
            throw new InvalidDataException("Stored RHC1 enrollment closure is inconsistent.");
    }

    private static byte[] ComputeDelegationHistoryBinding(
        ReadOnlySpan<byte> delegationHash, ReadOnlySpan<byte> acceptanceHash)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("Deep/production-mailbox/route-history-delegation/v1"u8);
        hash.AppendData(delegationHash);
        hash.AppendData(acceptanceHash);
        return hash.GetHashAndReset();
    }

    private static byte[] ComputeCheckpointHash(ReadOnlySpan<byte> canonical)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("Deep/production-mailbox/route-history-checkpoint-hash/v1"u8);
        hash.AppendData(canonical);
        return hash.GetHashAndReset();
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

}

internal sealed class ProductionMailboxFrozenOwnerRevocation
{
    private ProductionMailboxFrozenOwnerRevocation() { }

    internal required byte[] CanonicalBytes { get; init; }
    internal required byte[] CanonicalHash { get; init; }
    internal required ProductionMailboxRouteContinuityRevocation Revocation { get; init; }

    internal static ProductionMailboxFrozenOwnerRevocation Freeze(
        VerifiedProductionMailboxRouteContinuityRevocation verified)
    {
        ArgumentNullException.ThrowIfNull(verified);
        var bytes = verified.CanonicalBytes.ToArray();
        var hash = verified.CanonicalHash.ToArray();
        if (bytes.Length != ProductionMailboxRouteContinuityConstants.CanonicalRevocationLength ||
            hash.Length != 32 || !Fixed(SHA256.HashData(bytes), hash))
            throw new InvalidDataException("Verified RCR1 capability is internally inconsistent.");
        var decoded = ProductionMailboxRouteContinuityCodec.DecodeRevocation(bytes);
        var reencoded = ProductionMailboxRouteContinuityCodec.EncodeRevocation(decoded);
        if (!Fixed(bytes, reencoded))
            throw new InvalidDataException("Verified RCR1 bytes are non-canonical.");
        return new() { CanonicalBytes = bytes, CanonicalHash = hash, Revocation = decoded };
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}

internal sealed class ProductionMailboxFrozenHistoryBatch
{
    internal const int MinimumBatchBytes = 64;
    internal const int MaximumBatchBytes = 8_394_304;

    private ProductionMailboxFrozenHistoryBatch() { }

    internal required byte[] CanonicalBatch { get; init; }
    internal required byte[] CanonicalBatchHash { get; init; }
    internal required byte[] PlanHash { get; init; }
    internal required ProductionMailboxRouteHistoryStateSnapshot ExpectedCurrent { get; init; }
    internal required ProductionMailboxRouteHistoryStateSnapshot Next { get; init; }
    internal required ulong CumulativeVerifiedRouteLinkCount { get; init; }
    internal required ulong CumulativeCanonicalPayloadBytes { get; init; }
    internal required bool IsTerminal { get; init; }
    internal required ProductionMailboxRouteHistoryDurableRouteState NextDurableRouteState
    { get; init; }
    internal required ProductionMailboxRouteHistoryFinalArtifacts FinalArtifacts { get; init; }

    internal static ProductionMailboxFrozenHistoryBatch Freeze(
        VerifiedProductionMailboxRouteHistoryCursor expectedCurrent,
        ProductionMailboxRouteHistoryBatchCommitPlan plan)
    {
        ArgumentNullException.ThrowIfNull(expectedCurrent);
        ArgumentNullException.ThrowIfNull(plan);
        var sourceBatch = plan.CanonicalBatch;
        if (sourceBatch.Length is < MinimumBatchBytes or > MaximumBatchBytes)
            throw new InvalidDataException("RHB1 length is outside its strict bound.");
        var expected = new ProductionMailboxRouteHistoryStateSnapshot(
            expectedCurrent.ToProtectedRestoreContext());
        var plannedExpected = new ProductionMailboxRouteHistoryStateSnapshot(
            plan.ToExpectedCurrentProtectedRestoreContext());
        var plannedNext = new ProductionMailboxRouteHistoryStateSnapshot(
            plan.ToProtectedRestoreContext());
        var verifiedPlan = ProductionMailboxRouteHistoryAuthoring.VerifyNextBatchForCommit(
            expectedCurrent, sourceBatch.Span);
        var verifiedExpected = new ProductionMailboxRouteHistoryStateSnapshot(
            verifiedPlan.ToExpectedCurrentProtectedRestoreContext());
        var verifiedNextState = new ProductionMailboxRouteHistoryStateSnapshot(
            verifiedPlan.ToProtectedRestoreContext());
        if (!expected.Exact(plannedExpected) || !expected.Exact(verifiedExpected) ||
            !plannedNext.Exact(verifiedNextState) ||
            !Fixed(plan.PlanHash.Span, verifiedPlan.PlanHash.Span))
            throw new InvalidDataException("RHB1 plan result differs from protocol verification.");
        var batch = sourceBatch.ToArray();
        var hash = plan.CanonicalBatchHash.ToArray();
        if (hash.Length != 32 || !Fixed(SHA256.HashData(batch), hash) ||
            !Fixed(hash, plannedNext.LastCommittedBatchHash.Span))
            throw new InvalidDataException("RHB1 plan hash is internally inconsistent.");
        return new()
        {
            CanonicalBatch = batch,
            CanonicalBatchHash = hash,
            PlanHash = verifiedPlan.PlanHash.ToArray(),
            ExpectedCurrent = expected,
            Next = plannedNext,
            CumulativeVerifiedRouteLinkCount =
                verifiedPlan.NextCumulativeState.CumulativeVerifiedRouteLinkCount,
            CumulativeCanonicalPayloadBytes =
                verifiedPlan.NextCumulativeState.CumulativeCanonicalPayloadBytes,
            IsTerminal = verifiedPlan.NextCumulativeState.CumulativeCommittedBatchCount ==
                    ProductionMailboxRouteContinuityConstants.MaximumHistoryBatchCount ||
                verifiedPlan.NextCumulativeState.CumulativeVerifiedRouteLinkCount ==
                    ProductionMailboxRouteContinuityConstants.MaximumHistoryRouteLinkCount ||
                verifiedPlan.NextCumulativeState.CumulativeCanonicalPayloadBytes ==
                    ProductionMailboxRouteContinuityConstants.MaximumHistoryPayloadBytes,
            NextDurableRouteState = verifiedPlan.NextDurableRouteState,
            FinalArtifacts = verifiedPlan.FinalArtifacts
        };
    }

    internal static (byte[] Hash, ulong Sequence) FreezeReplay(
        ulong sequence, ReadOnlyMemory<byte> canonicalBatch)
    {
        if (sequence is 0 ||
            sequence > ProductionMailboxRouteContinuityConstants.MaximumHistoryBatchCount ||
            canonicalBatch.Length is < MinimumBatchBytes or > MaximumBatchBytes)
            throw new InvalidDataException("RHB1 replay request is outside its strict bounds.");
        var frozen = canonicalBatch.ToArray();
        return (SHA256.HashData(frozen), sequence);
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}

public sealed partial class InMemoryProductionMailboxStateStore
{
    async ValueTask<ProductionMailboxRouteContinuityCommitResult>
        IProductionMailboxRouteContinuityStateStore.CommitVerifiedOwnerRevocationAsync(
            ReadOnlyMemory<byte> routeStateKey,
            VerifiedProductionMailboxRouteContinuityRevocation revocation,
            CancellationToken cancellationToken)
    {
        var keyBytes = ProductionMailboxRouteContinuityStateGuard.FreezeKey(routeStateKey);
        var frozen = ProductionMailboxFrozenOwnerRevocation.Freeze(revocation);
        await gate.WaitAsync(cancellationToken);
        try
        {
            var key = Convert.ToHexString(keyBytes);
            routeContinuityStates.TryGetValue(key, out var current);
            if (current?.History is not null)
                _ = RestoreHistoryCatalog(keyBytes, current);
            var status = ValidateOwnerRevocationPredecessor(current, frozen);
            if (status != ProductionMailboxRouteContinuityCommitStatus.Accepted)
                return new(status, current is null ? null : Clone(current));
            var next = FromOwnerRevocation(current!, frozen);
            routeContinuityStates[key] = next;
            return new(ProductionMailboxRouteContinuityCommitStatus.Accepted, Clone(next));
        }
        finally { gate.Release(); }
    }

    async ValueTask<ProductionMailboxRouteContinuityCommitResult>
        IProductionMailboxRouteContinuityStateStore.CommitVerifiedHistoryBatchAsync(
            ReadOnlyMemory<byte> routeStateKey,
            VerifiedProductionMailboxRouteHistoryCursor expectedCurrent,
            ProductionMailboxRouteHistoryBatchCommitPlan plan,
            CancellationToken cancellationToken)
    {
        var keyBytes = ProductionMailboxRouteContinuityStateGuard.FreezeKey(routeStateKey);
        var frozen = ProductionMailboxFrozenHistoryBatch.Freeze(expectedCurrent, plan);
        await gate.WaitAsync(cancellationToken);
        try
        {
            var key = Convert.ToHexString(keyBytes);
            routeContinuityStates.TryGetValue(key, out var current);
            ProductionMailboxRestoredHistoryCatalog? restored = null;
            if (current?.History is not null)
                restored = RestoreHistoryCatalog(keyBytes, current);
            var status = ValidateHistoryPredecessor(current, frozen);
            if (status == ProductionMailboxRouteContinuityCommitStatus.Accepted &&
                restored?.Manifest.Terminal == true)
                status = ProductionMailboxRouteContinuityCommitStatus.Terminal;
            if (status != ProductionMailboxRouteContinuityCommitStatus.Accepted)
                return new(status, current is null ? null : Clone(current));
            if (restored is null)
                throw new InvalidDataException("Route-history genesis catalog is missing.");
            var next = FromHistory(current!, frozen);
            AppendHistoryCatalog(keyBytes, restored, frozen);
            routeContinuityStates[key] = next;
            return new(ProductionMailboxRouteContinuityCommitStatus.Accepted, Clone(next));
        }
        finally { gate.Release(); }
    }

    async ValueTask<ProductionMailboxRouteContinuityCommitResult>
        IProductionMailboxRouteContinuityStateStore.CheckHistoryBatchReplayAsync(
            ReadOnlyMemory<byte> routeStateKey,
            ulong batchSequence,
            ReadOnlyMemory<byte> canonicalBatch,
            CancellationToken cancellationToken)
    {
        var keyBytes = ProductionMailboxRouteContinuityStateGuard.FreezeKey(routeStateKey);
        var replay = ProductionMailboxFrozenHistoryBatch.FreezeReplay(batchSequence, canonicalBatch);
        await gate.WaitAsync(cancellationToken);
        try
        {
            routeContinuityStates.TryGetValue(Convert.ToHexString(keyBytes), out var current);
            if (current?.History is not null)
                _ = RestoreHistoryCatalog(keyBytes, current);
            return ReplayResult(current, replay.Sequence, replay.Hash);
        }
        finally { gate.Release(); }
    }

    internal static ProductionMailboxRouteContinuityCommitStatus ValidateOwnerRevocationPredecessor(
        ProductionMailboxRouteContinuityStateSnapshot? current,
        ProductionMailboxFrozenOwnerRevocation value)
    {
        if (current is null || current.DelegationSequence == 0)
            return ProductionMailboxRouteContinuityCommitStatus.MissingState;
        if (current.OwnerRevocationGeneration != 0)
            return Fixed(current.CanonicalOwnerRevocationHash.Span, value.CanonicalHash) &&
                   Fixed(current.CanonicalOwnerRevocation.Span, value.CanonicalBytes)
                ? ProductionMailboxRouteContinuityCommitStatus.ExactReplay
                : ProductionMailboxRouteContinuityCommitStatus.Conflict;
        var delegation = ProductionMailboxRouteContinuityCodec.DecodeDelegation(
            current.CanonicalDelegation.Span);
        var revocation = value.Revocation;
        if (!Fixed(revocation.NetworkId.Span, delegation.NetworkId.Span) ||
            !Fixed(revocation.RouteDomainHash.Span, delegation.RouteDomainHash.Span) ||
            !Fixed(revocation.TargetDelegationSerial.Span, delegation.DelegationSerial.Span) ||
            !Fixed(revocation.TargetCanonicalDelegationHash.Span,
                current.CanonicalDelegationHash.Span))
            return ProductionMailboxRouteContinuityCommitStatus.PredecessorMismatch;
        return revocation.RevocationGeneration == 1 &&
               revocation.PreviousCanonicalRevocationHash.Span.IndexOfAnyExcept((byte)0) < 0
            ? ProductionMailboxRouteContinuityCommitStatus.Accepted
            : ProductionMailboxRouteContinuityCommitStatus.Terminal;
    }

    internal static ProductionMailboxRouteContinuityCommitStatus ValidateHistoryPredecessor(
        ProductionMailboxRouteContinuityStateSnapshot? current,
        ProductionMailboxFrozenHistoryBatch value)
    {
        if (current is null || current.DelegationSequence == 0)
            return ProductionMailboxRouteContinuityCommitStatus.MissingState;
        try
        {
            value.ExpectedCurrent.ValidateAgainst(current);
            value.Next.ValidateAgainst(current);
        }
        catch (InvalidDataException)
        {
            return ProductionMailboxRouteContinuityCommitStatus.PredecessorMismatch;
        }
        var durable = current.History;
        if (durable is not null &&
            value.Next.LastCommittedBatchSequence == durable.LastCommittedBatchSequence)
            return Fixed(value.CanonicalBatchHash, durable.LastCommittedBatchHash.Span) &&
                   value.Next.Exact(durable)
                ? ProductionMailboxRouteContinuityCommitStatus.ExactReplay
                : ProductionMailboxRouteContinuityCommitStatus.Conflict;
        if (current.OwnerRevocationGeneration != 0)
            return ProductionMailboxRouteContinuityCommitStatus.Revoked;
        if (durable is null)
        {
            if (value.ExpectedCurrent.LastCommittedBatchSequence != 0 ||
                !Fixed(value.ExpectedCurrent.CurrentRouteOriginLkgHash.Span,
                    current.RouteOriginLkgHash.Span))
                return ProductionMailboxRouteContinuityCommitStatus.PredecessorMismatch;
            return value.Next.LastCommittedBatchSequence == 1
                ? ProductionMailboxRouteContinuityCommitStatus.Accepted
                : ProductionMailboxRouteContinuityCommitStatus.PredecessorMismatch;
        }
        if (value.Next.LastCommittedBatchSequence < durable.LastCommittedBatchSequence)
            return ProductionMailboxRouteContinuityCommitStatus.Rollback;
        if (durable.LastCommittedBatchSequence >=
            ProductionMailboxRouteContinuityConstants.MaximumHistoryBatchCount)
            return ProductionMailboxRouteContinuityCommitStatus.Terminal;
        if (!durable.Exact(value.ExpectedCurrent) ||
            value.Next.LastCommittedBatchSequence != durable.LastCommittedBatchSequence + 1)
            return ProductionMailboxRouteContinuityCommitStatus.PredecessorMismatch;
        return ProductionMailboxRouteContinuityCommitStatus.Accepted;
    }

    internal static ProductionMailboxRouteContinuityStateSnapshot FromOwnerRevocation(
        ProductionMailboxRouteContinuityStateSnapshot current,
        ProductionMailboxFrozenOwnerRevocation value) => CopyWith(current,
            ownerRevocationGeneration: value.Revocation.RevocationGeneration,
            canonicalOwnerRevocation: value.CanonicalBytes,
            canonicalOwnerRevocationHash: value.CanonicalHash,
            history: current.History);

    internal static ProductionMailboxRouteContinuityStateSnapshot FromHistory(
        ProductionMailboxRouteContinuityStateSnapshot current,
        ProductionMailboxFrozenHistoryBatch batch)
    {
        var durable = batch.NextDurableRouteState;
        var artifacts = batch.FinalArtifacts;
        var authorization = durable.AuthorizationKind ==
            ProductionMailboxRouteAuthorizationKind.OwnerPRA2
            ? artifacts.CanonicalOwnerAdvertisement.ToArray()
            : artifacts.CanonicalContinuityActivation.ToArray();
        return new(current.RouteStateKey.ToArray(), durable.CanonicalRouteOriginLkg.ToArray(),
            durable.CanonicalRouteOriginLkgHash.ToArray(), durable.LocalCommitGeneration,
            durable.AuthorizationKind, durable.CanonicalAuthorizationHash.ToArray(),
            durable.AuthorizationSequence, artifacts.CanonicalRouteCertificate.ToArray(),
            authorization, artifacts.CanonicalRevocationCheckpoint.ToArray(),
            artifacts.CanonicalTransitionContext.ToArray(),
            current.CanonicalSelectionSuccessor.ToArray(),
            current.CanonicalTransitionTranscript.ToArray(),
            current.TransitionTranscriptHash.ToArray(), current.DelegationSequence,
            current.CanonicalDelegation.ToArray(), current.CanonicalDelegationHash.ToArray(),
            current.CanonicalDelegationAcceptance.ToArray(),
            current.CanonicalDelegationAcceptanceHash.ToArray(),
            current.OwnerRevocationGeneration, current.CanonicalOwnerRevocation.ToArray(),
            current.CanonicalOwnerRevocationHash.ToArray(), batch.Next);
    }

    internal static ProductionMailboxRouteContinuityCommitResult ReplayResult(
        ProductionMailboxRouteContinuityStateSnapshot? current, ulong sequence,
        ReadOnlySpan<byte> batchHash)
    {
        var history = current?.History;
        if (history is null)
            return new(ProductionMailboxRouteContinuityCommitStatus.MissingState, current);
        var status = sequence == history.LastCommittedBatchSequence
            ? Fixed(batchHash, history.LastCommittedBatchHash.Span)
                ? ProductionMailboxRouteContinuityCommitStatus.ExactReplay
                : ProductionMailboxRouteContinuityCommitStatus.Conflict
            : sequence < history.LastCommittedBatchSequence
                ? ProductionMailboxRouteContinuityCommitStatus.Rollback
                : ProductionMailboxRouteContinuityCommitStatus.PredecessorMismatch;
        return new(status, current is null ? null : Clone(current));
    }

    private static ProductionMailboxRouteContinuityStateSnapshot CopyWith(
        ProductionMailboxRouteContinuityStateSnapshot current,
        ulong ownerRevocationGeneration,
        byte[] canonicalOwnerRevocation,
        byte[] canonicalOwnerRevocationHash,
        ProductionMailboxRouteHistoryStateSnapshot? history) => new(
            current.RouteStateKey.ToArray(), current.CanonicalRouteOriginLkg.ToArray(),
            current.RouteOriginLkgHash.ToArray(), current.LocalCommitGeneration,
            current.CurrentAuthorizationKind, current.CurrentAuthorizationHash.ToArray(),
            current.CurrentAuthorizationSequence, current.CanonicalRouteCertificate.ToArray(),
            current.CanonicalRouteAuthorization.ToArray(),
            current.CanonicalRevocationCheckpoint.ToArray(),
            current.CanonicalTransitionContext.ToArray(),
            current.CanonicalSelectionSuccessor.ToArray(),
            current.CanonicalTransitionTranscript.ToArray(),
            current.TransitionTranscriptHash.ToArray(), current.DelegationSequence,
            current.CanonicalDelegation.ToArray(), current.CanonicalDelegationHash.ToArray(),
            current.CanonicalDelegationAcceptance.ToArray(),
            current.CanonicalDelegationAcceptanceHash.ToArray(), ownerRevocationGeneration,
            canonicalOwnerRevocation, canonicalOwnerRevocationHash, history);

}

public sealed partial class PostgreSqlProductionMailboxStateStore
{
    async ValueTask<ProductionMailboxRouteContinuityCommitResult>
        IProductionMailboxRouteContinuityStateStore.CommitVerifiedOwnerRevocationAsync(
            ReadOnlyMemory<byte> routeStateKey,
            VerifiedProductionMailboxRouteContinuityRevocation revocation,
            CancellationToken cancellationToken)
    {
        var key = ProductionMailboxRouteContinuityStateGuard.FreezeKey(routeStateKey);
        var frozen = ProductionMailboxFrozenOwnerRevocation.Freeze(revocation);
        return await MutateAdvancedAsync(key, current =>
        {
            var status = InMemoryProductionMailboxStateStore
                .ValidateOwnerRevocationPredecessor(current, frozen);
            return (status, status == ProductionMailboxRouteContinuityCommitStatus.Accepted
                ? InMemoryProductionMailboxStateStore.FromOwnerRevocation(current!, frozen) : current);
        }, cancellationToken);
    }

    async ValueTask<ProductionMailboxRouteContinuityCommitResult>
        IProductionMailboxRouteContinuityStateStore.CommitVerifiedHistoryBatchAsync(
            ReadOnlyMemory<byte> routeStateKey,
            VerifiedProductionMailboxRouteHistoryCursor expectedCurrent,
            ProductionMailboxRouteHistoryBatchCommitPlan plan,
            CancellationToken cancellationToken)
    {
        var key = ProductionMailboxRouteContinuityStateGuard.FreezeKey(routeStateKey);
        var frozen = ProductionMailboxFrozenHistoryBatch.Freeze(expectedCurrent, plan);
        await using var connection = await OpenAsync(cancellationToken);
        await EnsureRouteContinuitySchemaAsync(connection, cancellationToken);
        await EnsureOwnerControlSchemaAsync(connection, cancellationToken);
        await EnsureRouteHistorySchemaAsync(connection, cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(
            System.Data.IsolationLevel.ReadCommitted, cancellationToken);
        await ConfigureOwnerControlTransactionAsync(connection, transaction, cancellationToken);
        await AdvisoryLockAsync(connection, transaction, key, cancellationToken);
        var current = await ReadRouteContinuityRowAsync(connection, transaction, key, true,
            cancellationToken);
        ProductionMailboxRestoredHistoryCatalog? restored = null;
        if (current?.History is not null)
            restored = await ReadHistoryCatalogAsync(connection, transaction, key, current,
                cancellationToken);
        var status = InMemoryProductionMailboxStateStore.ValidateHistoryPredecessor(
            current, frozen);
        if (status == ProductionMailboxRouteContinuityCommitStatus.Accepted &&
            restored?.Manifest.Terminal == true)
            status = ProductionMailboxRouteContinuityCommitStatus.Terminal;
        if (status != ProductionMailboxRouteContinuityCommitStatus.Accepted)
        {
            await transaction.CommitAsync(cancellationToken);
            return new(status, current);
        }
        if (restored is null)
            throw new InvalidDataException("Route-history genesis catalog is missing.");
        var next = InMemoryProductionMailboxStateStore.FromHistory(current!, frozen);
        await AppendHistoryCatalogAsync(connection, transaction, key, restored, frozen,
            cancellationToken);
        await UpsertRouteContinuityAsync(connection, transaction, next, cancellationToken);
        ThrowRouteHistoryCommitFault(
            ProductionMailboxRouteHistoryCommitFaultPoint.AfterRouteState);
        await transaction.CommitAsync(cancellationToken);
        return new(ProductionMailboxRouteContinuityCommitStatus.Accepted, next);
    }

    async ValueTask<ProductionMailboxRouteContinuityCommitResult>
        IProductionMailboxRouteContinuityStateStore.CheckHistoryBatchReplayAsync(
            ReadOnlyMemory<byte> routeStateKey,
            ulong batchSequence,
            ReadOnlyMemory<byte> canonicalBatch,
            CancellationToken cancellationToken)
    {
        var key = ProductionMailboxRouteContinuityStateGuard.FreezeKey(routeStateKey);
        var replay = ProductionMailboxFrozenHistoryBatch.FreezeReplay(batchSequence, canonicalBatch);
        await using var connection = await OpenAsync(cancellationToken);
        await EnsureRouteContinuitySchemaAsync(connection, cancellationToken);
        await EnsureOwnerControlSchemaAsync(connection, cancellationToken);
        await EnsureRouteHistorySchemaAsync(connection, cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(
            System.Data.IsolationLevel.ReadCommitted, cancellationToken);
        await ConfigureOwnerControlTransactionAsync(connection, transaction, cancellationToken);
        await AdvisoryLockAsync(connection, transaction, key, cancellationToken);
        var current = await ReadRouteContinuityAsync(connection, transaction, key, true,
            cancellationToken);
        var result = InMemoryProductionMailboxStateStore.ReplayResult(
            current, replay.Sequence, replay.Hash);
        await transaction.CommitAsync(cancellationToken);
        return result;
    }

    private async ValueTask<ProductionMailboxRouteContinuityCommitResult> MutateAdvancedAsync(
        byte[] routeStateKey,
        Func<ProductionMailboxRouteContinuityStateSnapshot?,
            (ProductionMailboxRouteContinuityCommitStatus Status,
                ProductionMailboxRouteContinuityStateSnapshot? Next)> mutation,
        CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        await EnsureRouteContinuitySchemaAsync(connection, cancellationToken);
        await EnsureOwnerControlSchemaAsync(connection, cancellationToken);
        await EnsureRouteHistorySchemaAsync(connection, cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(
            System.Data.IsolationLevel.ReadCommitted, cancellationToken);
        await ConfigureOwnerControlTransactionAsync(connection, transaction, cancellationToken);
        await AdvisoryLockAsync(connection, transaction, routeStateKey, cancellationToken);
        var current = await ReadRouteContinuityAsync(connection, transaction, routeStateKey,
            true, cancellationToken);
        var outcome = mutation(current);
        if (outcome.Status == ProductionMailboxRouteContinuityCommitStatus.Accepted)
            await UpsertRouteContinuityAsync(connection, transaction, outcome.Next!, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return new(outcome.Status, outcome.Next);
    }
}
