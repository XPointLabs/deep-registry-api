using System.Buffers.Binary;
using System.Data;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxTopology;
using Npgsql;
using NpgsqlTypes;

namespace Deep.Registry.Api.ProductionMailbox;

internal enum ProductionMailboxRouteContinuityCommitStatus
{
    Accepted,
    ExactReplay,
    MissingState,
    PredecessorMismatch,
    Rollback,
    Conflict,
    Revoked,
    Terminal
}

internal sealed class ProductionMailboxRouteContinuityStateSnapshot
{
    private readonly byte[] routeStateKey;
    private readonly byte[] canonicalRouteOriginLkg;
    private readonly byte[] routeOriginLkgHash;
    private readonly byte[] currentAuthorizationHash;
    private readonly byte[] canonicalRouteCertificate;
    private readonly byte[] canonicalRouteAuthorization;
    private readonly byte[] canonicalRevocationCheckpoint;
    private readonly byte[] canonicalTransitionContext;
    private readonly byte[] canonicalSelectionSuccessor;
    private readonly byte[] canonicalTransitionTranscript;
    private readonly byte[] transitionTranscriptHash;
    private readonly byte[] canonicalDelegation;
    private readonly byte[] canonicalDelegationHash;
    private readonly byte[] canonicalDelegationAcceptance;
    private readonly byte[] canonicalDelegationAcceptanceHash;
    private readonly byte[] canonicalOwnerRevocation;
    private readonly byte[] canonicalOwnerRevocationHash;
    private readonly ProductionMailboxRouteHistoryStateSnapshot? history;

    internal ProductionMailboxRouteContinuityStateSnapshot(
        byte[] routeStateKey,
        byte[] canonicalRouteOriginLkg,
        byte[] routeOriginLkgHash,
        ulong localCommitGeneration,
        ProductionMailboxRouteAuthorizationKind currentAuthorizationKind,
        byte[] currentAuthorizationHash,
        ulong currentAuthorizationSequence,
        byte[] canonicalRouteCertificate,
        byte[] canonicalRouteAuthorization,
        byte[] canonicalRevocationCheckpoint,
        byte[] canonicalTransitionContext,
        byte[] canonicalSelectionSuccessor,
        byte[] canonicalTransitionTranscript,
        byte[] transitionTranscriptHash,
        ulong delegationSequence,
        byte[] canonicalDelegation,
        byte[] canonicalDelegationHash,
        byte[] canonicalDelegationAcceptance,
        byte[] canonicalDelegationAcceptanceHash,
        ulong ownerRevocationGeneration,
        byte[] canonicalOwnerRevocation,
        byte[] canonicalOwnerRevocationHash,
        ProductionMailboxRouteHistoryStateSnapshot? history = null)
    {
        this.routeStateKey = routeStateKey.ToArray();
        this.canonicalRouteOriginLkg = canonicalRouteOriginLkg.ToArray();
        this.routeOriginLkgHash = routeOriginLkgHash.ToArray();
        LocalCommitGeneration = localCommitGeneration;
        CurrentAuthorizationKind = currentAuthorizationKind;
        this.currentAuthorizationHash = currentAuthorizationHash.ToArray();
        CurrentAuthorizationSequence = currentAuthorizationSequence;
        this.canonicalRouteCertificate = canonicalRouteCertificate.ToArray();
        this.canonicalRouteAuthorization = canonicalRouteAuthorization.ToArray();
        this.canonicalRevocationCheckpoint = canonicalRevocationCheckpoint.ToArray();
        this.canonicalTransitionContext = canonicalTransitionContext.ToArray();
        this.canonicalSelectionSuccessor = canonicalSelectionSuccessor.ToArray();
        this.canonicalTransitionTranscript = canonicalTransitionTranscript.ToArray();
        this.transitionTranscriptHash = transitionTranscriptHash.ToArray();
        DelegationSequence = delegationSequence;
        this.canonicalDelegation = canonicalDelegation.ToArray();
        this.canonicalDelegationHash = canonicalDelegationHash.ToArray();
        this.canonicalDelegationAcceptance = canonicalDelegationAcceptance.ToArray();
        this.canonicalDelegationAcceptanceHash = canonicalDelegationAcceptanceHash.ToArray();
        OwnerRevocationGeneration = ownerRevocationGeneration;
        this.canonicalOwnerRevocation = canonicalOwnerRevocation.ToArray();
        this.canonicalOwnerRevocationHash = canonicalOwnerRevocationHash.ToArray();
        this.history = history?.Clone();
    }

    internal ReadOnlyMemory<byte> RouteStateKey => routeStateKey.ToArray();
    internal ReadOnlyMemory<byte> CanonicalRouteOriginLkg => canonicalRouteOriginLkg.ToArray();
    internal ReadOnlyMemory<byte> RouteOriginLkgHash => routeOriginLkgHash.ToArray();
    internal ulong LocalCommitGeneration { get; }
    internal ProductionMailboxRouteAuthorizationKind CurrentAuthorizationKind { get; }
    internal ReadOnlyMemory<byte> CurrentAuthorizationHash => currentAuthorizationHash.ToArray();
    internal ulong CurrentAuthorizationSequence { get; }
    internal ReadOnlyMemory<byte> CanonicalRouteCertificate => canonicalRouteCertificate.ToArray();
    internal ReadOnlyMemory<byte> CanonicalRouteAuthorization => canonicalRouteAuthorization.ToArray();
    internal ReadOnlyMemory<byte> CanonicalRevocationCheckpoint => canonicalRevocationCheckpoint.ToArray();
    internal ReadOnlyMemory<byte> CanonicalTransitionContext => canonicalTransitionContext.ToArray();
    internal ReadOnlyMemory<byte> CanonicalSelectionSuccessor => canonicalSelectionSuccessor.ToArray();
    internal ReadOnlyMemory<byte> CanonicalTransitionTranscript =>
        canonicalTransitionTranscript.ToArray();
    internal ReadOnlyMemory<byte> TransitionTranscriptHash => transitionTranscriptHash.ToArray();
    internal ulong DelegationSequence { get; }
    internal ReadOnlyMemory<byte> CanonicalDelegation => canonicalDelegation.ToArray();
    internal ReadOnlyMemory<byte> CanonicalDelegationHash => canonicalDelegationHash.ToArray();
    internal ReadOnlyMemory<byte> CanonicalDelegationAcceptance => canonicalDelegationAcceptance.ToArray();
    internal ReadOnlyMemory<byte> CanonicalDelegationAcceptanceHash =>
        canonicalDelegationAcceptanceHash.ToArray();
    internal ulong OwnerRevocationGeneration { get; }
    internal ReadOnlyMemory<byte> CanonicalOwnerRevocation => canonicalOwnerRevocation.ToArray();
    internal ReadOnlyMemory<byte> CanonicalOwnerRevocationHash => canonicalOwnerRevocationHash.ToArray();
    internal ProductionMailboxRouteHistoryStateSnapshot? History => history?.Clone();
}

internal sealed record ProductionMailboxRouteContinuityCommitResult(
    ProductionMailboxRouteContinuityCommitStatus Status,
    ProductionMailboxRouteContinuityStateSnapshot? State);

internal enum ProductionMailboxRouteHistoryLookupStatus
{
    History,
    HeadNoChange,
    MissingState,
    Ahead,
    PredecessorMismatch,
    Revoked,
    Terminal
}

internal sealed record ProductionMailboxRouteHistoryLookupResult(
    ProductionMailboxRouteHistoryLookupStatus Status,
    ProductionMailboxRouteHistoryLookup? Lookup);

internal interface IProductionMailboxRouteContinuityStateStore
{
    ValueTask<ProductionMailboxRouteContinuityCommitResult> CommitVerifiedTransitionAsync(
        ReadOnlyMemory<byte> routeStateKey,
        ReadOnlyMemory<byte> expectedCanonicalOldRouteOriginLkg,
        VerifiedProductionMailboxRouteSelectionTransition transition,
        CancellationToken cancellationToken);

    ValueTask<ProductionMailboxRouteContinuityCommitResult> CommitVerifiedOwnerRevocationAsync(
        ReadOnlyMemory<byte> routeStateKey,
        VerifiedProductionMailboxRouteContinuityRevocation revocation,
        CancellationToken cancellationToken);

    ValueTask<ProductionMailboxRouteContinuityCommitResult> CommitVerifiedHistoryBatchAsync(
        ReadOnlyMemory<byte> routeStateKey,
        VerifiedProductionMailboxRouteHistoryCursor expectedCurrent,
        ProductionMailboxRouteHistoryBatchCommitPlan plan,
        CancellationToken cancellationToken);

    ValueTask<ProductionMailboxRouteContinuityCommitResult> CheckHistoryBatchReplayAsync(
        ReadOnlyMemory<byte> routeStateKey,
        ulong batchSequence,
        ReadOnlyMemory<byte> canonicalBatch,
        CancellationToken cancellationToken);

    ValueTask<ProductionMailboxRouteContinuityStateSnapshot?> GetRouteContinuityStateAsync(
        ReadOnlyMemory<byte> routeStateKey,
        CancellationToken cancellationToken);

    ValueTask<ProductionMailboxRestoredGenesis?> GetRestoredGenesisAsync(
        ReadOnlyMemory<byte> routeStateKey,
        CancellationToken cancellationToken);

    ValueTask<ProductionMailboxRouteHistoryLookupResult> LookupRouteHistoryAsync(
        ReadOnlyMemory<byte> routeStateKey,
        ProductionMailboxRouteHistoryLookupRequest request,
        CancellationToken cancellationToken);
}

internal static class ProductionMailboxRouteContinuityStateGuard
{
    private static ReadOnlySpan<byte> RouteOriginHashDomain =>
        "Deep/production-mailbox/route-origin-lkg/v1"u8;

    internal static byte[] FreezeKey(ReadOnlyMemory<byte> key)
    {
        if (key.Length != 32 || key.Span.IndexOfAnyExcept((byte)0) < 0)
            throw new InvalidDataException("Route continuity state key is invalid.");
        return key.ToArray();
    }

    internal static byte[] ComputeRouteOriginLkgHash(ReadOnlySpan<byte> canonical)
    {
        if (canonical.Length !=
            ProductionMailboxRouteContinuityConstants.CanonicalRouteOriginLkgLength)
            throw new InvalidDataException("ROL1 canonical length is invalid.");
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(RouteOriginHashDomain);
        hash.AppendData(canonical);
        return hash.GetHashAndReset();
    }
}

internal sealed class ProductionMailboxFrozenRouteTransition
{
    private ProductionMailboxFrozenRouteTransition() { }

    internal required byte[] ExpectedOldRouteOriginLkg { get; init; }
    internal required byte[] ExpectedOldRouteOriginLkgHash { get; init; }
    internal required ulong ExpectedOldLocalCommitGeneration { get; init; }
    internal required ProductionMailboxRouteAuthorizationKind PredecessorAuthorizationKind { get; init; }
    internal required byte[] PredecessorAuthorizationHash { get; init; }
    internal required ulong PredecessorAuthorizationSequence { get; init; }
    internal required ProductionMailboxRouteAuthorizationKind NewAuthorizationKind { get; init; }
    internal required byte[] NewAuthorizationHash { get; init; }
    internal required ulong NewAuthorizationSequence { get; init; }
    internal required byte[] CanonicalNewRouteOriginLkg { get; init; }
    internal required byte[] NewRouteOriginLkgHash { get; init; }
    internal required byte[] CanonicalRouteCertificate { get; init; }
    internal required byte[] CanonicalRouteAuthorization { get; init; }
    internal required byte[] CanonicalRevocationCheckpoint { get; init; }
    internal required byte[] CanonicalTransitionContext { get; init; }
    internal required byte[] CanonicalSelectionSuccessor { get; init; }
    internal required byte[] CanonicalTransitionTranscript { get; init; }
    internal required byte[] TransitionTranscriptHash { get; init; }

    internal static ProductionMailboxFrozenRouteTransition Freeze(
        ReadOnlyMemory<byte> expectedCanonicalOldRouteOriginLkg,
        VerifiedProductionMailboxRouteSelectionTransition transition)
    {
        ArgumentNullException.ThrowIfNull(transition);
        if (expectedCanonicalOldRouteOriginLkg.Length !=
            ProductionMailboxRouteContinuityConstants.CanonicalRouteOriginLkgLength)
            throw new InvalidDataException("Expected ROL1 length is invalid.");
        var expectedOld = expectedCanonicalOldRouteOriginLkg.ToArray();
        var oldHash = ProductionMailboxRouteContinuityStateGuard
            .ComputeRouteOriginLkgHash(expectedOld);
        var successor = transition.CanonicalSuccessor.ToArray();
        var proof = ProductionMailboxSelectionSuccessorV2Codec.Decode(successor);
        var contextBytes = transition.CanonicalTransitionContext.ToArray();
        var context = ProductionMailboxRouteAuthorizationCodec.DecodeTransitionContext(contextBytes);
        var certificate = transition.CanonicalRouteCertificate.ToArray();
        var authorization = transition.CanonicalRouteAuthorization.ToArray();
        var checkpoint = transition.CanonicalRevocationCheckpoint.ToArray();
        var nextRol = transition.CanonicalNextRouteOriginLkg.ToArray();
        var nextRolHash = transition.NextRouteOriginLkgHash.ToArray();
        var transcript = transition.CanonicalTranscript.ToArray();
        var transcriptHash = transition.TranscriptHash.ToArray();
        if (!Fixed(oldHash, context.SealedOldRouteOriginLkgHash.Span)
            || proof.PredecessorAuthorizationKind != context.PredecessorAuthorizationKind
            || proof.PredecessorRouteAuthorizationSequence !=
                context.PredecessorRouteAuthorizationSequence
            || !Fixed(proof.PredecessorCanonicalRouteAuthorizationHash.Span,
                context.PredecessorCanonicalRouteAuthorizationHash.Span)
            || proof.NewAuthorizationKind != transition.AuthorizationKind
            || proof.NewRouteAuthorizationSequence != transition.AuthorizationSequence
            || !Fixed(proof.NewCanonicalRouteAuthorizationHash.Span,
                SHA256.HashData(authorization))
            || !Fixed(proof.FreshCanonicalRouteCertificateHash.Span,
                SHA256.HashData(certificate))
            || !Fixed(proof.CanonicalRevocationCheckpointHash.Span,
                checkpoint.Length == 0 ? new byte[32] : SHA256.HashData(checkpoint))
            || !Fixed(proof.CanonicalTransitionContextHash.Span,
                SHA256.HashData(contextBytes))
            || nextRol.Length != ProductionMailboxRouteContinuityConstants.CanonicalRouteOriginLkgLength
            || nextRolHash.Length != 32
            || !Fixed(nextRolHash, ProductionMailboxRouteContinuityStateGuard
                .ComputeRouteOriginLkgHash(nextRol))
            || transcriptHash.Length != 32
            || !Fixed(transcriptHash, SHA256.HashData(transcript))
            || context.OldLocalRouteCommitGeneration == ulong.MaxValue
            || proof.PredecessorRouteAuthorizationSequence == ulong.MaxValue
            || proof.NewRouteAuthorizationSequence !=
                proof.PredecessorRouteAuthorizationSequence + 1
            || proof.NewRouteAuthorizationSequence == ulong.MaxValue)
            throw new InvalidDataException("Verified PSS2 transition observations are inconsistent.");

        return new()
        {
            ExpectedOldRouteOriginLkg = expectedOld,
            ExpectedOldRouteOriginLkgHash = oldHash,
            ExpectedOldLocalCommitGeneration = context.OldLocalRouteCommitGeneration,
            PredecessorAuthorizationKind = proof.PredecessorAuthorizationKind,
            PredecessorAuthorizationHash = proof.PredecessorCanonicalRouteAuthorizationHash.ToArray(),
            PredecessorAuthorizationSequence = proof.PredecessorRouteAuthorizationSequence,
            NewAuthorizationKind = proof.NewAuthorizationKind,
            NewAuthorizationHash = proof.NewCanonicalRouteAuthorizationHash.ToArray(),
            NewAuthorizationSequence = proof.NewRouteAuthorizationSequence,
            CanonicalNewRouteOriginLkg = nextRol,
            NewRouteOriginLkgHash = nextRolHash,
            CanonicalRouteCertificate = certificate,
            CanonicalRouteAuthorization = authorization,
            CanonicalRevocationCheckpoint = checkpoint,
            CanonicalTransitionContext = contextBytes,
            CanonicalSelectionSuccessor = successor,
            CanonicalTransitionTranscript = transcript,
            TransitionTranscriptHash = transcriptHash
        };
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}

internal sealed class ProductionMailboxFrozenEnrollment
{
    private ProductionMailboxFrozenEnrollment() { }

    internal required byte[] ExpectedOldRouteOriginLkg { get; init; }
    internal required byte[] ExpectedOldRouteOriginLkgHash { get; init; }
    internal required ulong ExpectedOldLocalCommitGeneration { get; init; }
    internal required ulong ExpectedPreviousDelegationSequence { get; init; }
    internal required byte[] ExpectedPreviousDelegationHash { get; init; }
    internal required byte[] CanonicalDelegation { get; init; }
    internal required byte[] CanonicalDelegationHash { get; init; }
    internal required byte[] CanonicalAcceptance { get; init; }
    internal required byte[] CanonicalAcceptanceHash { get; init; }
    internal required byte[] CanonicalEnrolledRouteOriginLkg { get; init; }
    internal required byte[] EnrolledRouteOriginLkgHash { get; init; }
    internal required byte[] CanonicalAnchorRouteCertificate { get; init; }
    internal required byte[] CanonicalAnchorRouteAuthorization { get; init; }
    internal required ProductionMailboxRouteHistoryStateSnapshot InitialHistory { get; init; }

    internal static ProductionMailboxFrozenEnrollment Freeze(
        ProductionMailboxRouteContinuityGenesisCommitPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        var value = new ProductionMailboxFrozenEnrollment
        {
            ExpectedOldRouteOriginLkg = plan.ExpectedPreDelegationRouteOriginLkg.ToArray(),
            ExpectedOldRouteOriginLkgHash = plan.ExpectedPreDelegationRouteOriginLkgHash.ToArray(),
            ExpectedOldLocalCommitGeneration = plan.ExpectedPreDelegationLocalCommitGeneration,
            ExpectedPreviousDelegationSequence = plan.ExpectedPreviousDelegationSequence,
            ExpectedPreviousDelegationHash = plan.ExpectedPreviousDelegationHash.ToArray(),
            CanonicalDelegation = plan.CanonicalDelegation.ToArray(),
            CanonicalDelegationHash = plan.CanonicalDelegationHash.ToArray(),
            CanonicalAcceptance = plan.CanonicalAcceptance.ToArray(),
            CanonicalAcceptanceHash = plan.CanonicalAcceptanceHash.ToArray(),
            CanonicalEnrolledRouteOriginLkg = plan.CanonicalEnrolledRouteOriginLkg.ToArray(),
            EnrolledRouteOriginLkgHash = plan.EnrolledRouteOriginLkgHash.ToArray(),
            CanonicalAnchorRouteCertificate = plan.CanonicalAnchorRouteCertificate.ToArray(),
            CanonicalAnchorRouteAuthorization = plan.CanonicalAnchorRouteAuthorization.ToArray(),
            InitialHistory = new ProductionMailboxRouteHistoryStateSnapshot(
                plan.ToProtectedRouteHistoryRestoreContext())
        };
        if (value.ExpectedOldRouteOriginLkg.Length !=
                ProductionMailboxRouteContinuityConstants.CanonicalRouteOriginLkgLength
            || value.CanonicalEnrolledRouteOriginLkg.Length !=
                ProductionMailboxRouteContinuityConstants.CanonicalRouteOriginLkgLength
            || value.CanonicalDelegation.Length !=
                ProductionMailboxRouteContinuityConstants.CanonicalDelegationLength
            || value.CanonicalAcceptance.Length !=
                ProductionMailboxRouteContinuityConstants.CanonicalDelegationAcceptanceLength
            || value.ExpectedOldRouteOriginLkgHash.Length != 32
            || value.ExpectedPreviousDelegationHash.Length != 32
            || value.CanonicalDelegationHash.Length != 32
            || value.CanonicalAcceptanceHash.Length != 32
            || value.EnrolledRouteOriginLkgHash.Length != 32
            || value.CanonicalAnchorRouteCertificate.Length !=
                ProductionMailboxRouteAdvertisementConstants.CanonicalCertificateLength
            || value.CanonicalAnchorRouteAuthorization.Length !=
                ProductionMailboxRouteAuthorizationConstants.CanonicalAdvertisementV2Length
            || !Fixed(ProductionMailboxRouteContinuityStateGuard.ComputeRouteOriginLkgHash(
                    value.ExpectedOldRouteOriginLkg),
                value.ExpectedOldRouteOriginLkgHash)
            || !Fixed(SHA256.HashData(value.CanonicalDelegation), value.CanonicalDelegationHash)
            || !Fixed(SHA256.HashData(value.CanonicalAcceptance), value.CanonicalAcceptanceHash)
            || !Fixed(ProductionMailboxRouteContinuityStateGuard.ComputeRouteOriginLkgHash(
                    value.CanonicalEnrolledRouteOriginLkg),
                value.EnrolledRouteOriginLkgHash)
            || value.ExpectedOldLocalCommitGeneration == ulong.MaxValue
            || value.ExpectedPreviousDelegationSequence == ulong.MaxValue)
            throw new InvalidDataException("RCD1 enrollment commit plan is inconsistent.");
        var delegation = ProductionMailboxRouteContinuityCodec.DecodeDelegation(
            value.CanonicalDelegation);
        var acceptance = ProductionMailboxRouteContinuityCodec.DecodeDelegationAcceptance(
            value.CanonicalAcceptance);
        if (delegation.DelegationSequence != value.ExpectedPreviousDelegationSequence + 1
            || !Fixed(delegation.PreviousCanonicalDelegationHash.Span,
                value.ExpectedPreviousDelegationHash)
            || !Fixed(acceptance.CanonicalDelegationHash.Span,
                value.CanonicalDelegationHash))
            throw new InvalidDataException("RCD1 enrollment lineage is inconsistent.");
        return value;
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}

public sealed partial class InMemoryProductionMailboxStateStore
{
    private readonly Dictionary<string, ProductionMailboxRouteContinuityStateSnapshot>
        routeContinuityStates = new(StringComparer.Ordinal);

    async ValueTask<ProductionMailboxRouteContinuityCommitResult>
        IProductionMailboxRouteContinuityStateStore.CommitVerifiedTransitionAsync(
            ReadOnlyMemory<byte> routeStateKey,
            ReadOnlyMemory<byte> expectedCanonicalOldRouteOriginLkg,
            VerifiedProductionMailboxRouteSelectionTransition transition,
            CancellationToken cancellationToken)
    {
        var frozenRouteStateKey = ProductionMailboxRouteContinuityStateGuard.FreezeKey(routeStateKey);
        var frozen = ProductionMailboxFrozenRouteTransition.Freeze(
            expectedCanonicalOldRouteOriginLkg, transition);
        await gate.WaitAsync(cancellationToken);
        try
        {
            var key = Convert.ToHexString(frozenRouteStateKey);
            if (HasRouteHistoryTombstone(frozenRouteStateKey))
                return new(ProductionMailboxRouteContinuityCommitStatus.Terminal, null);
            routeContinuityStates.TryGetValue(key, out var current);
            var status = ValidateTransitionPredecessor(current, frozen);
            if (status != ProductionMailboxRouteContinuityCommitStatus.Accepted)
                return new(status, current);
            var next = FromTransition(frozenRouteStateKey, current, frozen);
            routeContinuityStates[key] = next;
            return new(ProductionMailboxRouteContinuityCommitStatus.Accepted, next);
        }
        finally { gate.Release(); }
    }

    async ValueTask<ProductionMailboxRouteContinuityStateSnapshot?>
        IProductionMailboxRouteContinuityStateStore.GetRouteContinuityStateAsync(
            ReadOnlyMemory<byte> routeStateKey,
            CancellationToken cancellationToken)
    {
        var frozenRouteStateKey = ProductionMailboxRouteContinuityStateGuard.FreezeKey(routeStateKey);
        await gate.WaitAsync(cancellationToken);
        try
        {
            if (!routeContinuityStates.TryGetValue(Convert.ToHexString(frozenRouteStateKey),
                    out var value))
            {
                _ = HasRouteHistoryTombstone(frozenRouteStateKey);
                return null;
            }
            if (value.History is not null && value.DelegationSequence != 0)
                _ = RestoreHistoryCatalog(frozenRouteStateKey, value);
            return Clone(value);
        }
        finally { gate.Release(); }
    }

    async ValueTask<ProductionMailboxRestoredGenesis?>
        IProductionMailboxRouteContinuityStateStore.GetRestoredGenesisAsync(
        ReadOnlyMemory<byte> routeStateKey, CancellationToken cancellationToken)
    {
        var key = ProductionMailboxRouteContinuityStateGuard.FreezeKey(routeStateKey);
        await gate.WaitAsync(cancellationToken);
        try
        {
            if (!genesisCatalogs.TryGetValue(Convert.ToHexString(key), out var value)) return null;
            return ProductionMailboxProtectedGenesisCatalog.Restore(
                value.Payload, value.IntegrityTag, v2PublicationIntegrityKey).RestoreProtocol();
        }
        finally { gate.Release(); }
    }

    private static ProductionMailboxRouteContinuityStateSnapshot Clone(
        ProductionMailboxRouteContinuityStateSnapshot value) => new(
            value.RouteStateKey.ToArray(), value.CanonicalRouteOriginLkg.ToArray(),
            value.RouteOriginLkgHash.ToArray(), value.LocalCommitGeneration,
            value.CurrentAuthorizationKind, value.CurrentAuthorizationHash.ToArray(),
            value.CurrentAuthorizationSequence, value.CanonicalRouteCertificate.ToArray(),
            value.CanonicalRouteAuthorization.ToArray(), value.CanonicalRevocationCheckpoint.ToArray(),
            value.CanonicalTransitionContext.ToArray(), value.CanonicalSelectionSuccessor.ToArray(),
            value.CanonicalTransitionTranscript.ToArray(),
            value.TransitionTranscriptHash.ToArray(), value.DelegationSequence,
            value.CanonicalDelegation.ToArray(), value.CanonicalDelegationHash.ToArray(),
            value.CanonicalDelegationAcceptance.ToArray(),
            value.CanonicalDelegationAcceptanceHash.ToArray(), value.OwnerRevocationGeneration,
            value.CanonicalOwnerRevocation.ToArray(), value.CanonicalOwnerRevocationHash.ToArray(),
            value.History);

    internal static ProductionMailboxRouteContinuityCommitStatus ValidateTransitionPredecessor(
        ProductionMailboxRouteContinuityStateSnapshot? current,
        ProductionMailboxFrozenRouteTransition value)
    {
        if (current is not null && Fixed(current.TransitionTranscriptHash.Span,
                value.TransitionTranscriptHash))
            return ExactTransition(current, value)
                ? ProductionMailboxRouteContinuityCommitStatus.ExactReplay
                : ProductionMailboxRouteContinuityCommitStatus.Conflict;
        if (current is null)
            return value.NewAuthorizationKind ==
                ProductionMailboxRouteAuthorizationKind.OwnerPRA2
                ? ProductionMailboxRouteContinuityCommitStatus.Accepted
                : ProductionMailboxRouteContinuityCommitStatus.MissingState;
        if (current.History is not null)
            return ProductionMailboxRouteContinuityCommitStatus.Terminal;
        if (value.NewAuthorizationKind ==
                ProductionMailboxRouteAuthorizationKind.DelegatedRCA1
            && (current.DelegationSequence == 0
                || current.CanonicalDelegation.Length !=
                    ProductionMailboxRouteContinuityConstants.CanonicalDelegationLength
                || current.CanonicalDelegationAcceptance.Length !=
                    ProductionMailboxRouteContinuityConstants.CanonicalDelegationAcceptanceLength))
            return ProductionMailboxRouteContinuityCommitStatus.MissingState;
        if (current.OwnerRevocationGeneration != 0 &&
            value.NewAuthorizationKind == ProductionMailboxRouteAuthorizationKind.DelegatedRCA1)
            return ProductionMailboxRouteContinuityCommitStatus.Revoked;
        if (value.NewAuthorizationSequence <= current.CurrentAuthorizationSequence)
            return value.NewAuthorizationSequence == current.CurrentAuthorizationSequence
                ? ProductionMailboxRouteContinuityCommitStatus.Conflict
                : ProductionMailboxRouteContinuityCommitStatus.Rollback;
        if (!Fixed(current.CanonicalRouteOriginLkg.Span, value.ExpectedOldRouteOriginLkg)
            || !Fixed(current.RouteOriginLkgHash.Span, value.ExpectedOldRouteOriginLkgHash)
            || current.LocalCommitGeneration != value.ExpectedOldLocalCommitGeneration
            || current.CurrentAuthorizationKind != value.PredecessorAuthorizationKind
            || !Fixed(current.CurrentAuthorizationHash.Span, value.PredecessorAuthorizationHash)
            || current.CurrentAuthorizationSequence != value.PredecessorAuthorizationSequence)
            return ProductionMailboxRouteContinuityCommitStatus.PredecessorMismatch;
        return current.CurrentAuthorizationSequence == ulong.MaxValue
            ? ProductionMailboxRouteContinuityCommitStatus.Terminal
            : ProductionMailboxRouteContinuityCommitStatus.Accepted;
    }

    internal static ProductionMailboxRouteContinuityCommitStatus ValidateEnrollmentPredecessor(
        ProductionMailboxRouteContinuityStateSnapshot? current,
        ProductionMailboxFrozenEnrollment value)
    {
        if (current is null)
            return value.ExpectedPreviousDelegationSequence == 0
                && value.ExpectedPreviousDelegationHash.AsSpan().IndexOfAnyExcept((byte)0) < 0
                ? ProductionMailboxRouteContinuityCommitStatus.Accepted
                : ProductionMailboxRouteContinuityCommitStatus.MissingState;
        if (Fixed(current.CanonicalDelegationHash.Span, value.CanonicalDelegationHash))
            return ExactEnrollment(current, value)
                ? ProductionMailboxRouteContinuityCommitStatus.ExactReplay
                : ProductionMailboxRouteContinuityCommitStatus.Conflict;
        if (current.History is not null)
            return ProductionMailboxRouteContinuityCommitStatus.Terminal;
        if (current.DelegationSequence > value.ExpectedPreviousDelegationSequence)
            return ProductionMailboxRouteContinuityCommitStatus.Rollback;
        if (!Fixed(current.CanonicalRouteOriginLkg.Span, value.ExpectedOldRouteOriginLkg)
            || !Fixed(current.RouteOriginLkgHash.Span, value.ExpectedOldRouteOriginLkgHash)
            || current.LocalCommitGeneration != value.ExpectedOldLocalCommitGeneration
            || current.DelegationSequence != value.ExpectedPreviousDelegationSequence
            || !Fixed(current.CanonicalDelegationHash.Span, value.ExpectedPreviousDelegationHash))
            return ProductionMailboxRouteContinuityCommitStatus.PredecessorMismatch;
        return current.OwnerRevocationGeneration == 0
            ? ProductionMailboxRouteContinuityCommitStatus.Accepted
            : ProductionMailboxRouteContinuityCommitStatus.Revoked;
    }

    private static bool ExactTransition(ProductionMailboxRouteContinuityStateSnapshot current,
        ProductionMailboxFrozenRouteTransition value) =>
        Fixed(current.CanonicalRouteOriginLkg.Span, value.CanonicalNewRouteOriginLkg)
        && Fixed(current.RouteOriginLkgHash.Span, value.NewRouteOriginLkgHash)
        && current.CurrentAuthorizationKind == value.NewAuthorizationKind
        && Fixed(current.CurrentAuthorizationHash.Span, value.NewAuthorizationHash)
        && current.CurrentAuthorizationSequence == value.NewAuthorizationSequence
        && Fixed(current.CanonicalRouteCertificate.Span, value.CanonicalRouteCertificate)
        && Fixed(current.CanonicalRouteAuthorization.Span, value.CanonicalRouteAuthorization)
        && Fixed(current.CanonicalRevocationCheckpoint.Span, value.CanonicalRevocationCheckpoint)
        && Fixed(current.CanonicalTransitionContext.Span, value.CanonicalTransitionContext)
        && Fixed(current.CanonicalSelectionSuccessor.Span, value.CanonicalSelectionSuccessor)
        && Fixed(current.CanonicalTransitionTranscript.Span,
            value.CanonicalTransitionTranscript);

    private static bool ExactEnrollment(ProductionMailboxRouteContinuityStateSnapshot current,
        ProductionMailboxFrozenEnrollment value) =>
        Fixed(current.CanonicalDelegation.Span, value.CanonicalDelegation)
        && Fixed(current.CanonicalDelegationAcceptance.Span, value.CanonicalAcceptance)
        && Fixed(current.CanonicalDelegationAcceptanceHash.Span, value.CanonicalAcceptanceHash)
        && Fixed(current.CanonicalRouteOriginLkg.Span, value.CanonicalEnrolledRouteOriginLkg)
        && Fixed(current.RouteOriginLkgHash.Span, value.EnrolledRouteOriginLkgHash)
        && current.DelegationSequence == value.ExpectedPreviousDelegationSequence + 1;

    internal static ProductionMailboxRouteContinuityStateSnapshot FromTransition(
        ReadOnlySpan<byte> routeStateKey,
        ProductionMailboxRouteContinuityStateSnapshot? current,
        ProductionMailboxFrozenRouteTransition value) => new(
            routeStateKey.ToArray(), value.CanonicalNewRouteOriginLkg,
            value.NewRouteOriginLkgHash, value.ExpectedOldLocalCommitGeneration + 1,
            value.NewAuthorizationKind, value.NewAuthorizationHash,
            value.NewAuthorizationSequence, value.CanonicalRouteCertificate,
            value.CanonicalRouteAuthorization, value.CanonicalRevocationCheckpoint,
            value.CanonicalTransitionContext, value.CanonicalSelectionSuccessor,
            value.CanonicalTransitionTranscript,
            value.TransitionTranscriptHash, current?.DelegationSequence ?? 0,
            current?.CanonicalDelegation.ToArray() ?? [],
            current?.CanonicalDelegationHash.ToArray() ?? new byte[32],
            current?.CanonicalDelegationAcceptance.ToArray() ?? [],
            current?.CanonicalDelegationAcceptanceHash.ToArray() ?? new byte[32],
            current?.OwnerRevocationGeneration ?? 0,
            current?.CanonicalOwnerRevocation.ToArray() ?? [],
            current?.CanonicalOwnerRevocationHash.ToArray() ?? new byte[32],
            current?.History);

    internal static ProductionMailboxRouteContinuityStateSnapshot FromEnrollment(
        ReadOnlySpan<byte> routeStateKey,
        ProductionMailboxRouteContinuityStateSnapshot? current,
        ProductionMailboxFrozenEnrollment value)
    {
        var delegation = ProductionMailboxRouteContinuityCodec.DecodeDelegation(
            value.CanonicalDelegation);
        return new(
            routeStateKey.ToArray(), value.CanonicalEnrolledRouteOriginLkg,
            value.EnrolledRouteOriginLkgHash, value.ExpectedOldLocalCommitGeneration + 1,
            current?.CurrentAuthorizationKind ?? delegation.AnchorAuthorizationKind,
            current?.CurrentAuthorizationHash.ToArray() ??
                delegation.AnchorCanonicalRouteAuthorizationHash.ToArray(),
            current?.CurrentAuthorizationSequence ?? delegation.AnchorRouteAuthorizationSequence,
            current?.CanonicalRouteCertificate.ToArray() ?? value.CanonicalAnchorRouteCertificate,
            current?.CanonicalRouteAuthorization.ToArray() ?? value.CanonicalAnchorRouteAuthorization,
            current?.CanonicalRevocationCheckpoint.ToArray() ?? [],
            current?.CanonicalTransitionContext.ToArray() ?? [],
            current?.CanonicalSelectionSuccessor.ToArray() ?? [],
            current?.CanonicalTransitionTranscript.ToArray() ?? [],
            current?.TransitionTranscriptHash.ToArray() ?? new byte[32],
            value.ExpectedPreviousDelegationSequence + 1,
            value.CanonicalDelegation, value.CanonicalDelegationHash, value.CanonicalAcceptance,
            value.CanonicalAcceptanceHash, 0, [], new byte[32], value.InitialHistory);
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}

public sealed partial class PostgreSqlProductionMailboxStateStore
{
    private readonly SemaphoreSlim routeContinuityInitializeGate = new(1, 1);
    private volatile bool routeContinuityInitialized;

    async ValueTask<ProductionMailboxRouteContinuityCommitResult>
        IProductionMailboxRouteContinuityStateStore.CommitVerifiedTransitionAsync(
            ReadOnlyMemory<byte> routeStateKey,
            ReadOnlyMemory<byte> expectedCanonicalOldRouteOriginLkg,
            VerifiedProductionMailboxRouteSelectionTransition transition,
            CancellationToken cancellationToken)
    {
        var frozenRouteStateKey = ProductionMailboxRouteContinuityStateGuard.FreezeKey(routeStateKey);
        var frozen = ProductionMailboxFrozenRouteTransition.Freeze(
            expectedCanonicalOldRouteOriginLkg, transition);
        await using var connection = await OpenAsync(cancellationToken);
        await EnsureRouteContinuitySchemaAsync(connection, cancellationToken);
        await EnsureRouteHistorySchemaAsync(connection, cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(
            IsolationLevel.ReadCommitted, cancellationToken);
        await ConfigureOwnerControlTransactionAsync(connection, transaction, cancellationToken);
        await AdvisoryLockAsync(connection, transaction, frozenRouteStateKey, cancellationToken);
        if (await HasRouteHistoryTombstoneAsync(connection, transaction,
                frozenRouteStateKey, cancellationToken))
        {
            await transaction.CommitAsync(cancellationToken);
            return new(ProductionMailboxRouteContinuityCommitStatus.Terminal, null);
        }
        var current = await ReadRouteContinuityAsync(connection, transaction, frozenRouteStateKey,
            true, cancellationToken);
        var status = ValidateTransitionPredecessor(current, frozen);
        if (status != ProductionMailboxRouteContinuityCommitStatus.Accepted)
        {
            await transaction.CommitAsync(cancellationToken);
            return new(status, current);
        }
        var next = FromTransition(frozenRouteStateKey, current, frozen);
        await UpsertRouteContinuityAsync(connection, transaction, next, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return new(ProductionMailboxRouteContinuityCommitStatus.Accepted, next);
    }

    async ValueTask<ProductionMailboxRouteContinuityStateSnapshot?>
        IProductionMailboxRouteContinuityStateStore.GetRouteContinuityStateAsync(
            ReadOnlyMemory<byte> routeStateKey,
            CancellationToken cancellationToken)
    {
        var frozenRouteStateKey = ProductionMailboxRouteContinuityStateGuard.FreezeKey(routeStateKey);
        await using var connection = await OpenAsync(cancellationToken);
        await EnsureRouteContinuitySchemaAsync(connection, cancellationToken);
        await EnsureRouteHistorySchemaAsync(connection, cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(
            IsolationLevel.ReadCommitted, cancellationToken);
        await ConfigureOwnerControlTransactionAsync(connection, transaction, cancellationToken);
        await AdvisoryLockAsync(connection, transaction, frozenRouteStateKey, cancellationToken);
        var current = await ReadRouteContinuityAsync(connection, transaction,
            frozenRouteStateKey, true, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return current;
    }

    async ValueTask<ProductionMailboxRestoredGenesis?>
        IProductionMailboxRouteContinuityStateStore.GetRestoredGenesisAsync(
        ReadOnlyMemory<byte> routeStateKey, CancellationToken cancellationToken)
    {
        var key = ProductionMailboxRouteContinuityStateGuard.FreezeKey(routeStateKey);
        await using var connection = await OpenAsync(cancellationToken);
        await EnsureOwnerControlSchemaAsync(connection, cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(
            IsolationLevel.ReadCommitted, cancellationToken);
        await ConfigureOwnerControlTransactionAsync(connection, transaction, cancellationToken);
        await AdvisoryLockAsync(connection, transaction, key, cancellationToken);
        var catalog = await ReadGenesisCatalogAsync(connection, transaction, key,
            v2PreparedIntegrityKey, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return catalog?.RestoreProtocol();
    }

    private async ValueTask EnsureRouteContinuitySchemaAsync(
        NpgsqlConnection connection, CancellationToken cancellationToken)
    {
        if (routeContinuityInitialized) return;
        await routeContinuityInitializeGate.WaitAsync(cancellationToken);
        try
        {
            if (routeContinuityInitialized) return;
            const string sql = """
                CREATE TABLE IF NOT EXISTS production_mailbox_route_continuity_v2(
                    route_state_key bytea PRIMARY KEY CHECK(octet_length(route_state_key)=32),
                    canonical_route_origin bytea NOT NULL CHECK(octet_length(canonical_route_origin)=224),
                    route_origin_hash bytea NOT NULL CHECK(octet_length(route_origin_hash)=32),
                    local_commit_generation bytea NOT NULL CHECK(octet_length(local_commit_generation)=8),
                    current_authorization_kind smallint NOT NULL,
                    current_authorization_hash bytea NOT NULL CHECK(octet_length(current_authorization_hash)=32),
                    current_authorization_sequence bytea NOT NULL CHECK(octet_length(current_authorization_sequence)=8),
                    canonical_route_certificate bytea NOT NULL CHECK(octet_length(canonical_route_certificate) IN (0,304)),
                    canonical_route_authorization bytea NOT NULL CHECK(octet_length(canonical_route_authorization) IN (0,448,496)),
                    canonical_revocation_checkpoint bytea NOT NULL CHECK(octet_length(canonical_revocation_checkpoint) IN (0,320)),
                    canonical_transition_context bytea NOT NULL CHECK(octet_length(canonical_transition_context) IN (0,408)),
                    canonical_selection_successor bytea NOT NULL CHECK(octet_length(canonical_selection_successor)=0 OR octet_length(canonical_selection_successor) BETWEEN 728 AND 50376),
                    canonical_transition_transcript bytea NOT NULL CHECK(octet_length(canonical_transition_transcript) BETWEEN 0 AND 65536),
                    transition_transcript_hash bytea NOT NULL CHECK(octet_length(transition_transcript_hash)=32),
                    delegation_sequence bytea NOT NULL CHECK(octet_length(delegation_sequence)=8),
                    canonical_delegation bytea NOT NULL CHECK(octet_length(canonical_delegation) IN (0,552)),
                    canonical_delegation_hash bytea NOT NULL CHECK(octet_length(canonical_delegation_hash)=32),
                    canonical_delegation_acceptance bytea NOT NULL CHECK(octet_length(canonical_delegation_acceptance) IN (0,320)),
                    canonical_delegation_acceptance_hash bytea NOT NULL CHECK(octet_length(canonical_delegation_acceptance_hash)=32),
                    owner_revocation_generation bytea NOT NULL CHECK(octet_length(owner_revocation_generation)=8),
                    canonical_owner_revocation bytea NOT NULL CHECK(octet_length(canonical_owner_revocation) IN (0,224)),
                    canonical_owner_revocation_hash bytea NOT NULL CHECK(octet_length(canonical_owner_revocation_hash)=32),
                    canonical_history_checkpoint bytea NULL CHECK(canonical_history_checkpoint IS NULL OR octet_length(canonical_history_checkpoint)=464),
                    history_checkpoint_hash bytea NULL CHECK(history_checkpoint_hash IS NULL OR octet_length(history_checkpoint_hash)=32),
                    last_history_batch_sequence bytea NULL CHECK(last_history_batch_sequence IS NULL OR octet_length(last_history_batch_sequence)=8),
                    last_history_batch_hash bytea NULL CHECK(last_history_batch_hash IS NULL OR octet_length(last_history_batch_hash)=32),
                    history_current_route_origin_hash bytea NULL CHECK(history_current_route_origin_hash IS NULL OR octet_length(history_current_route_origin_hash)=32),
                    history_enrollment_delegation_hash bytea NULL CHECK(history_enrollment_delegation_hash IS NULL OR octet_length(history_enrollment_delegation_hash)=32),
                    history_enrollment_acceptance_hash bytea NULL CHECK(history_enrollment_acceptance_hash IS NULL OR octet_length(history_enrollment_acceptance_hash)=32),
                    history_network_id bytea NULL CHECK(history_network_id IS NULL OR octet_length(history_network_id)=16),
                    history_route_domain_hash bytea NULL CHECK(history_route_domain_hash IS NULL OR octet_length(history_route_domain_hash)=32),
                    history_delegation_binding bytea NULL CHECK(history_delegation_binding IS NULL OR octet_length(history_delegation_binding)=32),
                    history_pinned_mrx_hash bytea NULL CHECK(history_pinned_mrx_hash IS NULL OR octet_length(history_pinned_mrx_hash)=32),
                    history_current_authority_generation bytea NULL CHECK(history_current_authority_generation IS NULL OR octet_length(history_current_authority_generation)=8),
                    history_current_authority_hash bytea NULL CHECK(history_current_authority_hash IS NULL OR octet_length(history_current_authority_hash)=32),
                    history_current_revocation_generation bytea NULL CHECK(history_current_revocation_generation IS NULL OR octet_length(history_current_revocation_generation)=8),
                    history_current_revocation_head_hash bytea NULL CHECK(history_current_revocation_head_hash IS NULL OR octet_length(history_current_revocation_head_hash)=32),
                    history_current_revocation_snapshot_hash bytea NULL CHECK(history_current_revocation_snapshot_hash IS NULL OR octet_length(history_current_revocation_snapshot_hash)=32)
                );
                ALTER TABLE production_mailbox_route_continuity_v2
                    ADD COLUMN IF NOT EXISTS history_current_route_origin_hash bytea NULL CHECK(history_current_route_origin_hash IS NULL OR octet_length(history_current_route_origin_hash)=32),
                    ADD COLUMN IF NOT EXISTS history_enrollment_delegation_hash bytea NULL CHECK(history_enrollment_delegation_hash IS NULL OR octet_length(history_enrollment_delegation_hash)=32),
                    ADD COLUMN IF NOT EXISTS history_enrollment_acceptance_hash bytea NULL CHECK(history_enrollment_acceptance_hash IS NULL OR octet_length(history_enrollment_acceptance_hash)=32),
                    ADD COLUMN IF NOT EXISTS history_network_id bytea NULL CHECK(history_network_id IS NULL OR octet_length(history_network_id)=16),
                    ADD COLUMN IF NOT EXISTS history_route_domain_hash bytea NULL CHECK(history_route_domain_hash IS NULL OR octet_length(history_route_domain_hash)=32),
                    ADD COLUMN IF NOT EXISTS history_delegation_binding bytea NULL CHECK(history_delegation_binding IS NULL OR octet_length(history_delegation_binding)=32),
                    ADD COLUMN IF NOT EXISTS history_pinned_mrx_hash bytea NULL CHECK(history_pinned_mrx_hash IS NULL OR octet_length(history_pinned_mrx_hash)=32),
                    ADD COLUMN IF NOT EXISTS history_current_authority_generation bytea NULL CHECK(history_current_authority_generation IS NULL OR octet_length(history_current_authority_generation)=8),
                    ADD COLUMN IF NOT EXISTS history_current_authority_hash bytea NULL CHECK(history_current_authority_hash IS NULL OR octet_length(history_current_authority_hash)=32),
                    ADD COLUMN IF NOT EXISTS history_current_revocation_generation bytea NULL CHECK(history_current_revocation_generation IS NULL OR octet_length(history_current_revocation_generation)=8),
                    ADD COLUMN IF NOT EXISTS history_current_revocation_head_hash bytea NULL CHECK(history_current_revocation_head_hash IS NULL OR octet_length(history_current_revocation_head_hash)=32),
                    ADD COLUMN IF NOT EXISTS history_current_revocation_snapshot_hash bytea NULL CHECK(history_current_revocation_snapshot_hash IS NULL OR octet_length(history_current_revocation_snapshot_hash)=32);
                """;
            await using var command = new NpgsqlCommand(sql, connection);
            await command.ExecuteNonQueryAsync(cancellationToken);
            routeContinuityInitialized = true;
        }
        finally { routeContinuityInitializeGate.Release(); }
    }

    private async ValueTask<ProductionMailboxRouteContinuityStateSnapshot?>
        ReadRouteContinuityAsync(
            NpgsqlConnection connection,
            NpgsqlTransaction transaction,
            ReadOnlyMemory<byte> routeStateKey,
            bool forUpdate,
            CancellationToken cancellationToken)
    {
        var result = await ReadRouteContinuityRowAsync(connection, transaction,
            routeStateKey, forUpdate, cancellationToken);
        if (result is null)
        {
            _ = await HasRouteHistoryTombstoneAsync(connection, transaction, routeStateKey,
                cancellationToken);
            return null;
        }
        if (result?.History is not null)
            _ = await ReadHistoryCatalogAsync(connection, transaction, routeStateKey,
                result, cancellationToken);
        return result;
    }

    private static async ValueTask<ProductionMailboxRouteContinuityStateSnapshot?>
        ReadRouteContinuityRowAsync(
            NpgsqlConnection connection,
            NpgsqlTransaction transaction,
            ReadOnlyMemory<byte> routeStateKey,
            bool forUpdate,
            CancellationToken cancellationToken)
    {
        var sql = "SELECT canonical_route_origin,route_origin_hash,local_commit_generation,current_authorization_kind,current_authorization_hash,current_authorization_sequence,canonical_route_certificate,canonical_route_authorization,canonical_revocation_checkpoint,canonical_transition_context,canonical_selection_successor,canonical_transition_transcript,transition_transcript_hash,delegation_sequence,canonical_delegation,canonical_delegation_hash,canonical_delegation_acceptance,canonical_delegation_acceptance_hash,owner_revocation_generation,canonical_owner_revocation,canonical_owner_revocation_hash,canonical_history_checkpoint,history_checkpoint_hash,last_history_batch_sequence,last_history_batch_hash,history_current_route_origin_hash,history_enrollment_delegation_hash,history_enrollment_acceptance_hash,history_network_id,history_route_domain_hash,history_delegation_binding,history_pinned_mrx_hash,history_current_authority_generation,history_current_authority_hash,history_current_revocation_generation,history_current_revocation_head_hash,history_current_revocation_snapshot_hash FROM production_mailbox_route_continuity_v2 WHERE route_state_key=@key" +
            (forUpdate ? " FOR UPDATE" : string.Empty);
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue("key", routeStateKey.ToArray());
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken)) return null;
        var historyNulls = Enumerable.Range(21, 16).Select(reader.IsDBNull).ToArray();
        if (historyNulls.Any(static value => value) && historyNulls.Any(static value => !value))
            throw new InvalidDataException("Stored route-history state is split.");
        ProductionMailboxRouteHistoryStateSnapshot? history = null;
        if (!historyNulls[0])
        {
            history = new ProductionMailboxRouteHistoryStateSnapshot(
                new ProductionMailboxRouteHistoryProtectedRestoreContext(
                    reader.GetFieldValue<byte[]>(21), reader.GetFieldValue<byte[]>(22),
                    ReadU64(reader.GetFieldValue<byte[]>(23)), reader.GetFieldValue<byte[]>(24),
                    reader.GetFieldValue<byte[]>(25), reader.GetFieldValue<byte[]>(26),
                    reader.GetFieldValue<byte[]>(27), reader.GetFieldValue<byte[]>(28),
                    reader.GetFieldValue<byte[]>(29), reader.GetFieldValue<byte[]>(30),
                    reader.GetFieldValue<byte[]>(31), ReadU64(reader.GetFieldValue<byte[]>(32)),
                    reader.GetFieldValue<byte[]>(33), ReadU64(reader.GetFieldValue<byte[]>(34)),
                    reader.GetFieldValue<byte[]>(35), reader.GetFieldValue<byte[]>(36)));
        }
        var result = new ProductionMailboxRouteContinuityStateSnapshot(
            routeStateKey.ToArray(), reader.GetFieldValue<byte[]>(0),
            reader.GetFieldValue<byte[]>(1), ReadU64(reader.GetFieldValue<byte[]>(2)),
            (ProductionMailboxRouteAuthorizationKind)reader.GetInt16(3),
            reader.GetFieldValue<byte[]>(4), ReadU64(reader.GetFieldValue<byte[]>(5)),
            reader.GetFieldValue<byte[]>(6), reader.GetFieldValue<byte[]>(7),
            reader.GetFieldValue<byte[]>(8), reader.GetFieldValue<byte[]>(9),
            reader.GetFieldValue<byte[]>(10), reader.GetFieldValue<byte[]>(11),
            reader.GetFieldValue<byte[]>(12), ReadU64(reader.GetFieldValue<byte[]>(13)),
            reader.GetFieldValue<byte[]>(14), reader.GetFieldValue<byte[]>(15),
            reader.GetFieldValue<byte[]>(16), reader.GetFieldValue<byte[]>(17),
            ReadU64(reader.GetFieldValue<byte[]>(18)), reader.GetFieldValue<byte[]>(19),
            reader.GetFieldValue<byte[]>(20), history);
        ValidateStoredState(result);
        return result;
    }

    private static async ValueTask UpsertRouteContinuityAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        ProductionMailboxRouteContinuityStateSnapshot value,
        CancellationToken cancellationToken)
    {
        const string sql = """
            INSERT INTO production_mailbox_route_continuity_v2(
                route_state_key,canonical_route_origin,route_origin_hash,local_commit_generation,
                current_authorization_kind,current_authorization_hash,current_authorization_sequence,
                canonical_route_certificate,canonical_route_authorization,canonical_revocation_checkpoint,
                canonical_transition_context,canonical_selection_successor,
                canonical_transition_transcript,transition_transcript_hash,
                delegation_sequence,canonical_delegation,canonical_delegation_hash,
                canonical_delegation_acceptance,canonical_delegation_acceptance_hash,
                owner_revocation_generation,canonical_owner_revocation,canonical_owner_revocation_hash,
                canonical_history_checkpoint,history_checkpoint_hash,last_history_batch_sequence,
                last_history_batch_hash,history_current_route_origin_hash,
                history_enrollment_delegation_hash,history_enrollment_acceptance_hash,
                history_network_id,history_route_domain_hash,history_delegation_binding,
                history_pinned_mrx_hash,history_current_authority_generation,
                history_current_authority_hash,history_current_revocation_generation,
                history_current_revocation_head_hash,history_current_revocation_snapshot_hash)
            VALUES(@key,@origin,@originHash,@local,@kind,@authHash,@authSequence,@certificate,
                @authorization,@rch,@rtc,@pss,@transcriptBytes,@transcript,@delegationSequence,@delegation,
                @delegationHash,@acceptance,@acceptanceHash,@revocationGeneration,@revocation,
                @revocationHash,@historyCheckpoint,@historyCheckpointHash,@historyBatchSequence,
                @historyBatchHash,@historyRolHash,@historyDelegationHash,@historyAcceptanceHash,
                @historyNetwork,@historyRouteDomain,@historyDelegationBinding,@historyMrX,
                @historyAuthorityGeneration,@historyAuthorityHash,@historyRevocationGeneration,
                @historyRevocationHead,@historyRevocationSnapshot)
            ON CONFLICT(route_state_key) DO UPDATE SET
                canonical_route_origin=EXCLUDED.canonical_route_origin,
                route_origin_hash=EXCLUDED.route_origin_hash,
                local_commit_generation=EXCLUDED.local_commit_generation,
                current_authorization_kind=EXCLUDED.current_authorization_kind,
                current_authorization_hash=EXCLUDED.current_authorization_hash,
                current_authorization_sequence=EXCLUDED.current_authorization_sequence,
                canonical_route_certificate=EXCLUDED.canonical_route_certificate,
                canonical_route_authorization=EXCLUDED.canonical_route_authorization,
                canonical_revocation_checkpoint=EXCLUDED.canonical_revocation_checkpoint,
                canonical_transition_context=EXCLUDED.canonical_transition_context,
                canonical_selection_successor=EXCLUDED.canonical_selection_successor,
                canonical_transition_transcript=EXCLUDED.canonical_transition_transcript,
                transition_transcript_hash=EXCLUDED.transition_transcript_hash,
                delegation_sequence=EXCLUDED.delegation_sequence,
                canonical_delegation=EXCLUDED.canonical_delegation,
                canonical_delegation_hash=EXCLUDED.canonical_delegation_hash,
                canonical_delegation_acceptance=EXCLUDED.canonical_delegation_acceptance,
                canonical_delegation_acceptance_hash=EXCLUDED.canonical_delegation_acceptance_hash,
                owner_revocation_generation=EXCLUDED.owner_revocation_generation,
                canonical_owner_revocation=EXCLUDED.canonical_owner_revocation,
                canonical_owner_revocation_hash=EXCLUDED.canonical_owner_revocation_hash,
                canonical_history_checkpoint=EXCLUDED.canonical_history_checkpoint,
                history_checkpoint_hash=EXCLUDED.history_checkpoint_hash,
                last_history_batch_sequence=EXCLUDED.last_history_batch_sequence,
                last_history_batch_hash=EXCLUDED.last_history_batch_hash,
                history_current_route_origin_hash=EXCLUDED.history_current_route_origin_hash,
                history_enrollment_delegation_hash=EXCLUDED.history_enrollment_delegation_hash,
                history_enrollment_acceptance_hash=EXCLUDED.history_enrollment_acceptance_hash,
                history_network_id=EXCLUDED.history_network_id,
                history_route_domain_hash=EXCLUDED.history_route_domain_hash,
                history_delegation_binding=EXCLUDED.history_delegation_binding,
                history_pinned_mrx_hash=EXCLUDED.history_pinned_mrx_hash,
                history_current_authority_generation=EXCLUDED.history_current_authority_generation,
                history_current_authority_hash=EXCLUDED.history_current_authority_hash,
                history_current_revocation_generation=EXCLUDED.history_current_revocation_generation,
                history_current_revocation_head_hash=EXCLUDED.history_current_revocation_head_hash,
                history_current_revocation_snapshot_hash=EXCLUDED.history_current_revocation_snapshot_hash
            """;
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue("key", value.RouteStateKey.ToArray());
        command.Parameters.AddWithValue("origin", value.CanonicalRouteOriginLkg.ToArray());
        command.Parameters.AddWithValue("originHash", value.RouteOriginLkgHash.ToArray());
        command.Parameters.AddWithValue("local", U64(value.LocalCommitGeneration));
        command.Parameters.AddWithValue("kind", (short)value.CurrentAuthorizationKind);
        command.Parameters.AddWithValue("authHash", value.CurrentAuthorizationHash.ToArray());
        command.Parameters.AddWithValue("authSequence", U64(value.CurrentAuthorizationSequence));
        command.Parameters.AddWithValue("certificate", value.CanonicalRouteCertificate.ToArray());
        command.Parameters.AddWithValue("authorization", value.CanonicalRouteAuthorization.ToArray());
        command.Parameters.AddWithValue("rch", value.CanonicalRevocationCheckpoint.ToArray());
        command.Parameters.AddWithValue("rtc", value.CanonicalTransitionContext.ToArray());
        command.Parameters.AddWithValue("pss", value.CanonicalSelectionSuccessor.ToArray());
        command.Parameters.AddWithValue("transcriptBytes", value.CanonicalTransitionTranscript.ToArray());
        command.Parameters.AddWithValue("transcript", value.TransitionTranscriptHash.ToArray());
        command.Parameters.AddWithValue("delegationSequence", U64(value.DelegationSequence));
        command.Parameters.AddWithValue("delegation", value.CanonicalDelegation.ToArray());
        command.Parameters.AddWithValue("delegationHash", value.CanonicalDelegationHash.ToArray());
        command.Parameters.AddWithValue("acceptance", value.CanonicalDelegationAcceptance.ToArray());
        command.Parameters.AddWithValue("acceptanceHash", value.CanonicalDelegationAcceptanceHash.ToArray());
        command.Parameters.AddWithValue("revocationGeneration", U64(value.OwnerRevocationGeneration));
        command.Parameters.AddWithValue("revocation", value.CanonicalOwnerRevocation.ToArray());
        command.Parameters.AddWithValue("revocationHash", value.CanonicalOwnerRevocationHash.ToArray());
        var history = value.History;
        AddOptionalBytea("historyCheckpoint", history?.CanonicalCheckpoint);
        AddOptionalBytea("historyCheckpointHash", history?.CanonicalCheckpointHash);
        AddOptionalBytea("historyBatchSequence", history is null
            ? (ReadOnlyMemory<byte>?)null : U64(history.LastCommittedBatchSequence));
        AddOptionalBytea("historyBatchHash", history?.LastCommittedBatchHash);
        AddOptionalBytea("historyRolHash", history?.CurrentRouteOriginLkgHash);
        AddOptionalBytea("historyDelegationHash", history?.EnrollmentCanonicalDelegationHash);
        AddOptionalBytea("historyAcceptanceHash", history?.EnrollmentCanonicalAcceptanceHash);
        AddOptionalBytea("historyNetwork", history?.NetworkId);
        AddOptionalBytea("historyRouteDomain", history?.RouteDomainHash);
        AddOptionalBytea("historyDelegationBinding", history?.DelegationHistoryBinding);
        AddOptionalBytea("historyMrX", history?.PinnedMrXPublicKeySha256);
        AddOptionalBytea("historyAuthorityGeneration",
            history is null ? (ReadOnlyMemory<byte>?)null : U64(history.CurrentAuthorityGeneration));
        AddOptionalBytea("historyAuthorityHash", history?.CurrentCanonicalAuthorityHash);
        AddOptionalBytea("historyRevocationGeneration",
            history is null ? (ReadOnlyMemory<byte>?)null : U64(history.CurrentRevocationGeneration));
        AddOptionalBytea("historyRevocationHead", history?.CurrentRevocationHeadHash);
        AddOptionalBytea("historyRevocationSnapshot", history?.CurrentRevocationSnapshotHash);
        await command.ExecuteNonQueryAsync(cancellationToken);

        void AddOptionalBytea(string name, ReadOnlyMemory<byte>? bytes)
        {
            var parameter = command.Parameters.Add(name, NpgsqlDbType.Bytea);
            parameter.Value = bytes.HasValue ? bytes.Value.ToArray() : DBNull.Value;
        }
    }

    private static ProductionMailboxRouteContinuityCommitStatus ValidateTransitionPredecessor(
        ProductionMailboxRouteContinuityStateSnapshot? current,
        ProductionMailboxFrozenRouteTransition value) =>
        InMemoryProductionMailboxStateStore.ValidateTransitionPredecessor(current, value);

    private static ProductionMailboxRouteContinuityCommitStatus ValidateEnrollmentPredecessor(
        ProductionMailboxRouteContinuityStateSnapshot? current,
        ProductionMailboxFrozenEnrollment value) =>
        InMemoryProductionMailboxStateStore.ValidateEnrollmentPredecessor(current, value);

    private static ProductionMailboxRouteContinuityStateSnapshot FromTransition(
        ReadOnlySpan<byte> routeStateKey,
        ProductionMailboxRouteContinuityStateSnapshot? current,
        ProductionMailboxFrozenRouteTransition value) =>
        InMemoryProductionMailboxStateStore.FromTransition(routeStateKey, current, value);

    private static ProductionMailboxRouteContinuityStateSnapshot FromEnrollment(
        ReadOnlySpan<byte> routeStateKey,
        ProductionMailboxRouteContinuityStateSnapshot? current,
        ProductionMailboxFrozenEnrollment value) =>
        InMemoryProductionMailboxStateStore.FromEnrollment(routeStateKey, current, value);

    private static ulong ReadU64(byte[] value)
    {
        if (value.Length != 8) throw new InvalidDataException("Stored u64 is invalid.");
        return BinaryPrimitives.ReadUInt64BigEndian(value);
    }

    internal static void ValidateStoredState(ProductionMailboxRouteContinuityStateSnapshot value)
    {
        if (value.CanonicalRouteOriginLkg.Length !=
                ProductionMailboxRouteContinuityConstants.CanonicalRouteOriginLkgLength
            || value.RouteOriginLkgHash.Length != 32
            || !Fixed(ProductionMailboxRouteContinuityStateGuard.ComputeRouteOriginLkgHash(
                    value.CanonicalRouteOriginLkg.Span),
                value.RouteOriginLkgHash.Span)
            || value.LocalCommitGeneration == ulong.MaxValue
            || !Enum.IsDefined(value.CurrentAuthorizationKind)
            || value.CurrentAuthorizationKind == ProductionMailboxRouteAuthorizationKind.None
            || value.CurrentAuthorizationHash.Length != 32
            || value.CurrentAuthorizationHash.Span.IndexOfAnyExcept((byte)0) < 0
            || value.CurrentAuthorizationSequence is 0 or ulong.MaxValue
            || value.TransitionTranscriptHash.Length != 32)
            throw new InvalidDataException("Stored route-continuity state is invalid.");

        if (value.DelegationSequence == 0)
        {
            if (value.CanonicalDelegation.Length != 0
                || value.CanonicalDelegationAcceptance.Length != 0
                || value.CanonicalDelegationHash.Span.IndexOfAnyExcept((byte)0) >= 0
                || value.CanonicalDelegationAcceptanceHash.Span.IndexOfAnyExcept((byte)0) >= 0)
                throw new InvalidDataException("Stored route-continuity enrollment is invalid.");
        }
        else
        {
            if (value.DelegationSequence == ulong.MaxValue
                || value.CanonicalDelegation.Length !=
                    ProductionMailboxRouteContinuityConstants.CanonicalDelegationLength
                || value.CanonicalDelegationAcceptance.Length !=
                    ProductionMailboxRouteContinuityConstants.CanonicalDelegationAcceptanceLength
                || !Fixed(SHA256.HashData(value.CanonicalDelegation.Span),
                    value.CanonicalDelegationHash.Span)
                || !Fixed(SHA256.HashData(value.CanonicalDelegationAcceptance.Span),
                    value.CanonicalDelegationAcceptanceHash.Span))
                throw new InvalidDataException("Stored route-continuity enrollment hashes are invalid.");
            var delegation = ProductionMailboxRouteContinuityCodec.DecodeDelegation(
                value.CanonicalDelegation.Span);
            var acceptance = ProductionMailboxRouteContinuityCodec.DecodeDelegationAcceptance(
                value.CanonicalDelegationAcceptance.Span);
            if (delegation.DelegationSequence != value.DelegationSequence
                || !Fixed(acceptance.CanonicalDelegationHash.Span,
                    value.CanonicalDelegationHash.Span))
                throw new InvalidDataException("Stored route-continuity enrollment lineage is invalid.");
        }

        ValidateStoredOwnerRevocation(value);
        var history = value.History;
        history?.ValidateAgainst(value);

        if (history is not null && history.LastCommittedBatchSequence != 0)
        {
            if (!Fixed(history.CurrentRouteOriginLkgHash.Span,
                    value.RouteOriginLkgHash.Span) ||
                value.CanonicalRouteCertificate.Length !=
                    ProductionMailboxRouteAdvertisementConstants.CanonicalCertificateLength ||
                !Fixed(SHA256.HashData(value.CanonicalRouteAuthorization.Span),
                    value.CurrentAuthorizationHash.Span))
                throw new InvalidDataException(
                    "Stored historical route authorization is inconsistent.");
            _ = ProductionMailboxRouteAdvertisementCodec.DecodeCertificate(
                value.CanonicalRouteCertificate.Span);
            if (value.CurrentAuthorizationKind ==
                ProductionMailboxRouteAuthorizationKind.OwnerPRA2)
            {
                _ = ProductionMailboxRouteAuthorizationCodec.DecodeAdvertisementV2(
                    value.CanonicalRouteAuthorization.Span);
                if (value.CanonicalRevocationCheckpoint.Length != 0 ||
                    value.CanonicalTransitionContext.Length != 0)
                    throw new InvalidDataException(
                        "Stored historical owner authorization carries delegated artifacts.");
            }
            else
            {
                _ = ProductionMailboxRouteAuthorizationCodec.DecodeContinuityActivation(
                    value.CanonicalRouteAuthorization.Span);
                _ = ProductionMailboxRouteContinuityCodec.DecodeRevocationCheckpoint(
                    value.CanonicalRevocationCheckpoint.Span);
                _ = ProductionMailboxRouteAuthorizationCodec.DecodeTransitionContext(
                    value.CanonicalTransitionContext.Span);
            }
            if (value.CanonicalSelectionSuccessor.Length != 0)
                _ = ProductionMailboxSelectionSuccessorV2Codec.Decode(
                    value.CanonicalSelectionSuccessor.Span);
            if (value.CanonicalTransitionTranscript.Length == 0
                ? value.TransitionTranscriptHash.Span.IndexOfAnyExcept((byte)0) >= 0
                : !Fixed(SHA256.HashData(value.CanonicalTransitionTranscript.Span),
                    value.TransitionTranscriptHash.Span))
                throw new InvalidDataException(
                    "Stored selection/publication transcript is inconsistent.");
            return;
        }

        var hasTransition = value.CanonicalSelectionSuccessor.Length != 0;
        if (!hasTransition)
        {
            if (value.CanonicalRevocationCheckpoint.Length != 0
                || value.CanonicalTransitionContext.Length != 0
                || value.CanonicalTransitionTranscript.Length != 0
                || value.TransitionTranscriptHash.Span.IndexOfAnyExcept((byte)0) >= 0)
                throw new InvalidDataException("Stored bootstrap route state is inconsistent.");
            if (value.DelegationSequence == 0)
            {
                if (value.CanonicalRouteCertificate.Length != 0
                    || value.CanonicalRouteAuthorization.Length != 0
                    || value.History is not null)
                    throw new InvalidDataException(
                        "Stored owner bootstrap contains a continuity genesis closure.");
                return;
            }
            if (value.History is null
                || value.CurrentAuthorizationKind !=
                    ProductionMailboxRouteAuthorizationKind.OwnerPRA2
                || value.CanonicalRouteCertificate.Length !=
                    ProductionMailboxRouteAdvertisementConstants.CanonicalCertificateLength
                || value.CanonicalRouteAuthorization.Length !=
                    ProductionMailboxRouteAuthorizationConstants.CanonicalAdvertisementV2Length)
                throw new InvalidDataException(
                    "Stored continuity genesis closure is incomplete.");
            _ = ProductionMailboxRouteAdvertisementCodec.DecodeCertificate(
                value.CanonicalRouteCertificate.Span);
            var anchor = ProductionMailboxRouteAuthorizationCodec.DecodeAdvertisementV2(
                value.CanonicalRouteAuthorization.Span);
            if (!Fixed(SHA256.HashData(value.CanonicalRouteAuthorization.Span),
                    value.CurrentAuthorizationHash.Span)
                || anchor.Sequence != value.CurrentAuthorizationSequence)
                throw new InvalidDataException(
                    "Stored continuity genesis authorization is inconsistent.");
            return;
        }

        _ = ProductionMailboxRouteAdvertisementCodec.DecodeCertificate(
            value.CanonicalRouteCertificate.Span);
        if (value.CurrentAuthorizationKind == ProductionMailboxRouteAuthorizationKind.OwnerPRA2)
        {
            _ = ProductionMailboxRouteAuthorizationCodec.DecodeAdvertisementV2(
                value.CanonicalRouteAuthorization.Span);
            if (value.CanonicalRevocationCheckpoint.Length != 0)
                throw new InvalidDataException("Stored owner route transition contains RCH1.");
        }
        else
        {
            if (value.DelegationSequence == 0)
                throw new InvalidDataException(
                    "Stored delegated route transition has no continuity enrollment.");
            _ = ProductionMailboxRouteAuthorizationCodec.DecodeContinuityActivation(
                value.CanonicalRouteAuthorization.Span);
            _ = ProductionMailboxRouteContinuityCodec.DecodeRevocationCheckpoint(
                value.CanonicalRevocationCheckpoint.Span);
        }
        var context = ProductionMailboxRouteAuthorizationCodec.DecodeTransitionContext(
            value.CanonicalTransitionContext.Span);
        var successor = ProductionMailboxSelectionSuccessorV2Codec.Decode(
            value.CanonicalSelectionSuccessor.Span);
        if (!Fixed(SHA256.HashData(value.CanonicalRouteAuthorization.Span),
                value.CurrentAuthorizationHash.Span)
            || !Fixed(SHA256.HashData(value.CanonicalTransitionTranscript.Span),
                value.TransitionTranscriptHash.Span)
            || successor.NewAuthorizationKind != value.CurrentAuthorizationKind
            || successor.NewRouteAuthorizationSequence != value.CurrentAuthorizationSequence
            || !Fixed(successor.NewCanonicalRouteAuthorizationHash.Span,
                value.CurrentAuthorizationHash.Span)
            || !Fixed(successor.CanonicalTransitionContextHash.Span,
                SHA256.HashData(value.CanonicalTransitionContext.Span))
            || context.NewAuthorizationKind != value.CurrentAuthorizationKind
            || context.NewRouteAuthorizationSequence != value.CurrentAuthorizationSequence)
            throw new InvalidDataException("Stored route transition is internally inconsistent.");
    }

    private static void ValidateStoredOwnerRevocation(
        ProductionMailboxRouteContinuityStateSnapshot value)
    {
        if (value.CanonicalOwnerRevocationHash.Length != 32)
            throw new InvalidDataException("Stored owner-revocation hash length is invalid.");
        if (value.OwnerRevocationGeneration == 0)
        {
            if (value.CanonicalOwnerRevocation.Length != 0 ||
                value.CanonicalOwnerRevocationHash.Span.IndexOfAnyExcept((byte)0) >= 0)
                throw new InvalidDataException("Stored active owner-revocation state is invalid.");
            return;
        }
        if (value.OwnerRevocationGeneration != 1 || value.DelegationSequence == 0 ||
            value.CanonicalOwnerRevocation.Length !=
                ProductionMailboxRouteContinuityConstants.CanonicalRevocationLength ||
            value.CanonicalOwnerRevocationHash.Span.IndexOfAnyExcept((byte)0) < 0 ||
            !Fixed(SHA256.HashData(value.CanonicalOwnerRevocation.Span),
                value.CanonicalOwnerRevocationHash.Span))
            throw new InvalidDataException("Stored terminal owner-revocation state is invalid.");
        var revocation = ProductionMailboxRouteContinuityCodec.DecodeRevocation(
            value.CanonicalOwnerRevocation.Span);
        var delegation = ProductionMailboxRouteContinuityCodec.DecodeDelegation(
            value.CanonicalDelegation.Span);
        if (revocation.RevocationGeneration != 1 ||
            revocation.PreviousCanonicalRevocationHash.Span.IndexOfAnyExcept((byte)0) >= 0 ||
            !Fixed(revocation.NetworkId.Span, delegation.NetworkId.Span) ||
            !Fixed(revocation.RouteDomainHash.Span, delegation.RouteDomainHash.Span) ||
            !Fixed(revocation.TargetDelegationSerial.Span, delegation.DelegationSerial.Span) ||
            !Fixed(revocation.TargetCanonicalDelegationHash.Span,
                value.CanonicalDelegationHash.Span))
            throw new InvalidDataException("Stored terminal owner revocation is misbound.");
    }
}
