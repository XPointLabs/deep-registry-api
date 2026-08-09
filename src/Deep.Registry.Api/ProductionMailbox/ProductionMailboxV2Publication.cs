using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.DeepExtension.MailboxAuthority;
using Deep.Protocol.DeepExtension.MailboxTopology;
using Sodium;

namespace Deep.Registry.Api.ProductionMailbox;

internal sealed record ProductionMailboxV2ControlPlaneInput
{
    internal required ReadOnlyMemory<byte> CanonicalAuthority { get; init; }
    internal required ReadOnlyMemory<byte> CanonicalRevocations { get; init; }
    internal required ReadOnlyMemory<byte> CanonicalTopology { get; init; }
    internal required ReadOnlyMemory<byte> CanonicalCurrentSelection { get; init; }
    internal required ReadOnlyMemory<byte> CanonicalNextSelection { get; init; }
    internal required ProductionMailboxNodeCacheVerificationContext VerificationContext
    { get; init; }
}

internal sealed class ProductionMailboxV2ControlPlaneClosure
{
    private readonly ProductionMailboxNodeCacheArtifacts artifacts;
    private readonly ProductionMailboxNodeCacheVerificationContext context;

    private ProductionMailboxV2ControlPlaneClosure(
        ProductionMailboxNodeCacheArtifacts artifacts,
        ProductionMailboxNodeCacheVerificationContext context)
    {
        this.artifacts = artifacts;
        this.context = context;
    }

    internal static ProductionMailboxV2ControlPlaneClosure Freeze(
        ProductionMailboxV2ControlPlaneInput value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var context = value.VerificationContext;
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(context.ControlPlane);
        static byte[] Field(ReadOnlyMemory<byte> field, int minimum, int maximum, string name)
        {
            if (field.Length < minimum || field.Length > maximum)
                throw new InvalidDataException($"PMC2 {name} length is invalid.");
            return field.ToArray();
        }
        static byte[] Exact(ReadOnlyMemory<byte> field, int length, string name)
        {
            if (field.Length != length)
                throw new InvalidDataException($"PMC2 {name} length is invalid.");
            return field.ToArray();
        }

        var aggregate = (long)value.CanonicalAuthority.Length
            + value.CanonicalRevocations.Length + value.CanonicalTopology.Length
            + value.CanonicalCurrentSelection.Length + value.CanonicalNextSelection.Length;
        if (aggregate > ProductionMailboxNodeCacheVerifier.MaximumAggregateBytes)
            throw new InvalidDataException("PMC2 aggregate exceeds the protocol bound.");

        var frozenArtifacts = new ProductionMailboxNodeCacheArtifacts
        {
            // The authorization kind and all route-specific artifacts come only from the
            // one durable route-state snapshot in Bind.
            AuthorizationKind = ProductionMailboxRouteAuthorizationKind.OwnerPRA2,
            CanonicalAuthority = Field(value.CanonicalAuthority, 1,
                ProductionMailboxAuthorityConstants.MaximumArtifactBytes, "PMA1"),
            CanonicalRevocations = Field(value.CanonicalRevocations, 1,
                ProductionMailboxRevocationSnapshotConstants.MaximumArtifactBytes, "PMR1"),
            CanonicalTopology = Field(value.CanonicalTopology, 1,
                ProductionMailboxTopologyConstants.MaximumTopologyArtifactBytes, "PMT1"),
            CanonicalCurrentSelection = Field(value.CanonicalCurrentSelection, 1,
                ProductionMailboxTopologyConstants.MaximumSelectionArtifactBytes, "current PMS1"),
            CanonicalNextSelection = Field(value.CanonicalNextSelection, 1,
                ProductionMailboxTopologyConstants.MaximumSelectionArtifactBytes, "next PMS1"),
            // Route-specific values are replaced from the one durable route-state snapshot.
            CanonicalSelectionSuccessorV2 = ReadOnlyMemory<byte>.Empty,
            CanonicalRouteCertificate = ReadOnlyMemory<byte>.Empty,
            CanonicalTransitionContext = ReadOnlyMemory<byte>.Empty,
            CanonicalRouteAuthorization = ReadOnlyMemory<byte>.Empty,
            CanonicalRevocationCheckpoint = ReadOnlyMemory<byte>.Empty
        };
        var control = context.ControlPlane;
        var frozenContext = new ProductionMailboxNodeCacheVerificationContext
        {
            ExpectedRouteDomainHash = Exact(context.ExpectedRouteDomainHash, 32, "route domain"),
            ControlPlane = new ProductionMailboxNodeCacheControlPlaneContext
            {
                ExpectedNetworkId = Exact(control.ExpectedNetworkId, 16, "network"),
                ExpectedMailboxOwnerEd25519PublicKey = Exact(
                    control.ExpectedMailboxOwnerEd25519PublicKey, 32, "owner"),
                ExpectedBlindedMailboxId = Exact(control.ExpectedBlindedMailboxId, 32, "mailbox"),
                ExpectedBlindedPlacementId = Exact(control.ExpectedBlindedPlacementId, 32, "placement"),
                ExpectedSelectionInputCommitment = Exact(
                    control.ExpectedSelectionInputCommitment, 32, "selection commitment"),
                PinnedMrXPublicKeySha256 = Exact(control.PinnedMrXPublicKeySha256, 32, "Mr. X pin"),
                ExpectedOldAuthorityGeneration = control.ExpectedOldAuthorityGeneration,
                ExpectedOldCanonicalAuthorityHash = Exact(
                    control.ExpectedOldCanonicalAuthorityHash, 32, "old PMA1 hash"),
                ExpectedOldRevocationGeneration = control.ExpectedOldRevocationGeneration,
                ExpectedOldRevocationHeadHash = Exact(
                    control.ExpectedOldRevocationHeadHash, 32, "old PMR1 head"),
                ExpectedOldRevocationSnapshotHash = Exact(
                    control.ExpectedOldRevocationSnapshotHash, 32, "old PMR1 hash"),
                ExpectedOldTopologyGeneration = control.ExpectedOldTopologyGeneration,
                ExpectedOldCanonicalTopologyHash = Exact(
                    control.ExpectedOldCanonicalTopologyHash, 32, "old PMT1 hash"),
                ExpectedOldCanonicalSelectionHash = Exact(
                    control.ExpectedOldCanonicalSelectionHash, 32, "old PMS1 hash"),
                VerifiedAtUnixSeconds = control.VerifiedAtUnixSeconds,
                ClockSkewSeconds = control.ClockSkewSeconds
            }
        };
        return new(frozenArtifacts, frozenContext);
    }

    internal ProductionMailboxNodeCacheArtifacts Bind(
        ProductionMailboxRouteContinuityStateSnapshot routeState)
    {
        ArgumentNullException.ThrowIfNull(routeState);
        var authorization = routeState.CanonicalRouteAuthorization.ToArray();
        var kind = routeState.CurrentAuthorizationKind;
        if (authorization.Length == 0
            || routeState.CanonicalSelectionSuccessor.Length == 0
            || routeState.CanonicalRouteCertificate.Length == 0
            || routeState.CanonicalTransitionContext.Length == 0)
            throw new InvalidDataException("Durable route state is not a publishable PMC2 transition.");
        var checkpoint = routeState.CanonicalRevocationCheckpoint.ToArray();
        if ((kind == ProductionMailboxRouteAuthorizationKind.OwnerPRA2 && checkpoint.Length != 0)
            || (kind == ProductionMailboxRouteAuthorizationKind.DelegatedRCA1
                && checkpoint.Length != ProductionMailboxRouteContinuityConstants
                    .CanonicalRevocationCheckpointLength))
            throw new InvalidDataException("Durable route-state authorization shape is invalid.");
        return artifacts with
        {
            AuthorizationKind = kind,
            CanonicalSelectionSuccessorV2 = routeState.CanonicalSelectionSuccessor.ToArray(),
            CanonicalRouteCertificate = routeState.CanonicalRouteCertificate.ToArray(),
            CanonicalTransitionContext = routeState.CanonicalTransitionContext.ToArray(),
            CanonicalRouteAuthorization = authorization,
            CanonicalRevocationCheckpoint = checkpoint
        };
    }

    internal ProductionMailboxNodeCacheVerificationContext Context => new()
    {
        ExpectedRouteDomainHash = context.ExpectedRouteDomainHash.ToArray(),
        ControlPlane = context.ControlPlane with
        {
            ExpectedNetworkId = context.ControlPlane.ExpectedNetworkId.ToArray(),
            ExpectedMailboxOwnerEd25519PublicKey =
                context.ControlPlane.ExpectedMailboxOwnerEd25519PublicKey.ToArray(),
            ExpectedBlindedMailboxId = context.ControlPlane.ExpectedBlindedMailboxId.ToArray(),
            ExpectedBlindedPlacementId = context.ControlPlane.ExpectedBlindedPlacementId.ToArray(),
            ExpectedSelectionInputCommitment =
                context.ControlPlane.ExpectedSelectionInputCommitment.ToArray(),
            PinnedMrXPublicKeySha256 = context.ControlPlane.PinnedMrXPublicKeySha256.ToArray(),
            ExpectedOldCanonicalAuthorityHash =
                context.ControlPlane.ExpectedOldCanonicalAuthorityHash.ToArray(),
            ExpectedOldRevocationHeadHash =
                context.ControlPlane.ExpectedOldRevocationHeadHash.ToArray(),
            ExpectedOldRevocationSnapshotHash =
                context.ControlPlane.ExpectedOldRevocationSnapshotHash.ToArray(),
            ExpectedOldCanonicalTopologyHash =
                context.ControlPlane.ExpectedOldCanonicalTopologyHash.ToArray(),
            ExpectedOldCanonicalSelectionHash =
                context.ControlPlane.ExpectedOldCanonicalSelectionHash.ToArray()
        }
    };
}

internal sealed class ProductionMailboxV2PreparedCache
{
    private readonly ProductionMailboxNodeCacheArtifacts artifacts;
    private readonly byte[] cacheTranscriptHash;
    private readonly byte[] selectionInputCommitment;
    private readonly byte[] durableOldSelectionHash;
    private readonly byte[] sourceFingerprint;
    private readonly ProductionMailboxV2Target[] targets;

    internal ProductionMailboxV2PreparedCache(
        ProductionMailboxNodeCacheArtifacts artifacts, byte[] cacheTranscriptHash,
        byte[] selectionInputCommitment, byte[] durableOldSelectionHash,
        byte[] sourceFingerprint, ulong verifiedAtUnixSeconds,
        ulong cacheExpiresAtUnixSeconds, ProductionMailboxSelectionSuccessorMode mode,
        ProductionMailboxRouteAuthorizationKind authorizationKind,
        IReadOnlyList<ProductionMailboxV2Target> targets)
    {
        this.artifacts = new ProductionMailboxNodeCacheArtifacts
        {
            AuthorizationKind = artifacts.AuthorizationKind,
            CanonicalAuthority = artifacts.CanonicalAuthority.ToArray(),
            CanonicalRevocations = artifacts.CanonicalRevocations.ToArray(),
            CanonicalTopology = artifacts.CanonicalTopology.ToArray(),
            CanonicalCurrentSelection = artifacts.CanonicalCurrentSelection.ToArray(),
            CanonicalNextSelection = artifacts.CanonicalNextSelection.ToArray(),
            CanonicalSelectionSuccessorV2 = artifacts.CanonicalSelectionSuccessorV2.ToArray(),
            CanonicalRouteCertificate = artifacts.CanonicalRouteCertificate.ToArray(),
            CanonicalTransitionContext = artifacts.CanonicalTransitionContext.ToArray(),
            CanonicalRouteAuthorization = artifacts.CanonicalRouteAuthorization.ToArray(),
            CanonicalRevocationCheckpoint = artifacts.CanonicalRevocationCheckpoint.ToArray()
        };
        this.cacheTranscriptHash = cacheTranscriptHash.ToArray();
        this.selectionInputCommitment = selectionInputCommitment.ToArray();
        this.durableOldSelectionHash = durableOldSelectionHash.ToArray();
        this.sourceFingerprint = sourceFingerprint.ToArray();
        this.targets = targets.Select(static target => target.Snapshot()).ToArray();
        VerifiedAtUnixSeconds = verifiedAtUnixSeconds;
        CacheExpiresAtUnixSeconds = cacheExpiresAtUnixSeconds;
        Mode = mode;
        AuthorizationKind = authorizationKind;
    }

    internal ReadOnlyMemory<byte> CacheTranscriptHash => cacheTranscriptHash.ToArray();
    internal ReadOnlyMemory<byte> SelectionInputCommitment =>
        selectionInputCommitment.ToArray();
    internal ReadOnlyMemory<byte> DurableOldSelectionHash => durableOldSelectionHash.ToArray();
    internal ReadOnlyMemory<byte> SourceFingerprint => sourceFingerprint.ToArray();
    internal IReadOnlyList<ProductionMailboxV2Target> Targets =>
        targets.Select(static target => target.Snapshot()).ToArray();
    internal ulong VerifiedAtUnixSeconds { get; }
    internal ulong CacheExpiresAtUnixSeconds { get; }
    internal ProductionMailboxSelectionSuccessorMode Mode { get; }
    internal ProductionMailboxRouteAuthorizationKind AuthorizationKind { get; }

    internal ProductionMailboxNodeCacheArtifacts CanonicalArtifacts => artifacts with
    {
        CanonicalAuthority = artifacts.CanonicalAuthority.ToArray(),
        CanonicalRevocations = artifacts.CanonicalRevocations.ToArray(),
        CanonicalTopology = artifacts.CanonicalTopology.ToArray(),
        CanonicalCurrentSelection = artifacts.CanonicalCurrentSelection.ToArray(),
        CanonicalNextSelection = artifacts.CanonicalNextSelection.ToArray(),
        CanonicalSelectionSuccessorV2 = artifacts.CanonicalSelectionSuccessorV2.ToArray(),
        CanonicalRouteCertificate = artifacts.CanonicalRouteCertificate.ToArray(),
        CanonicalTransitionContext = artifacts.CanonicalTransitionContext.ToArray(),
        CanonicalRouteAuthorization = artifacts.CanonicalRouteAuthorization.ToArray(),
        CanonicalRevocationCheckpoint = artifacts.CanonicalRevocationCheckpoint.ToArray()
    };

    internal ProductionMailboxV2MaterializedCache Materialize(Func<byte[]>? createSalt = null)
    {
        var salt = (createSalt ?? (() => RandomNumberGenerator.GetBytes(32)))();
        if (salt.Length != 32 || salt.AsSpan().IndexOfAnyExcept((byte)0) < 0)
            throw new InvalidDataException("PMC2 cache salt is invalid.");
        var draft = new ProductionMailboxV2ClosureEnvelope(
            AuthorizationKind, salt, new byte[32], artifacts.CanonicalAuthority,
            artifacts.CanonicalRevocations, artifacts.CanonicalTopology,
            artifacts.CanonicalCurrentSelection, artifacts.CanonicalNextSelection,
            artifacts.CanonicalSelectionSuccessorV2, artifacts.CanonicalRouteCertificate,
            artifacts.CanonicalTransitionContext, artifacts.CanonicalRouteAuthorization,
            artifacts.CanonicalRevocationCheckpoint);
        var commitment = ProductionMailboxV2WireCodec.ComputeLineageCommitment(draft);
        var canonical = ProductionMailboxV2WireCodec.EncodeEnvelope(
            draft with { LineageCommitment = commitment });
        return new(canonical, SHA256.HashData(canonical), commitment, salt);
    }
}

internal sealed class ProductionMailboxV2MaterializedCache
{
    private readonly byte[] envelope;
    private readonly byte[] envelopeHash;
    private readonly byte[] lineageCommitment;
    private readonly byte[] cacheSalt;

    internal ProductionMailboxV2MaterializedCache(byte[] envelope, byte[] envelopeHash,
        byte[] lineageCommitment, byte[] cacheSalt)
    {
        this.envelope = envelope.ToArray();
        this.envelopeHash = envelopeHash.ToArray();
        this.lineageCommitment = lineageCommitment.ToArray();
        this.cacheSalt = cacheSalt.ToArray();
    }

    internal ReadOnlyMemory<byte> CanonicalEnvelope => envelope.ToArray();
    internal ReadOnlyMemory<byte> EnvelopeSha256 => envelopeHash.ToArray();
    internal ReadOnlyMemory<byte> LineageCommitment => lineageCommitment.ToArray();
    internal ReadOnlyMemory<byte> CacheSalt => cacheSalt.ToArray();
}

internal sealed record ProductionMailboxV2Target(
    ReadOnlyMemory<byte> ReplicaId,
    string Endpoint,
    ReadOnlyMemory<byte> CurrentSpkiSha256,
    ReadOnlyMemory<byte> NextSpkiSha256)
{
    internal ProductionMailboxV2Target Snapshot() => new(ReplicaId.ToArray(), Endpoint,
        CurrentSpkiSha256.ToArray(), NextSpkiSha256.ToArray());
}

internal static class ProductionMailboxV2ActivationAttestation
{
    private static ReadOnlySpan<byte> Domain =>
        "Deep/Registry/production-mailbox-v2-activation-plan/v1"u8;

    internal static byte[] ComputeLineageGroupKey(ReadOnlySpan<byte> selection,
        ReadOnlySpan<byte> durableOldSelectionHash)
    {
        if (selection.Length != 32 || durableOldSelectionHash.Length != 32)
            throw new InvalidDataException("PMC2 lineage group is invalid.");
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("Deep/Registry/production-mailbox-v2-lineage-group/v1"u8);
        hash.AppendData(selection); hash.AppendData(durableOldSelectionHash);
        return hash.GetHashAndReset();
    }

    internal static byte[] GetSigningBytes(ReadOnlySpan<byte> activationStateKey,
        ReadOnlySpan<byte> promotionStateKey, ReadOnlySpan<byte> cohortId,
        ReadOnlySpan<byte> routeStateKey, ReadOnlySpan<byte> publisherPublicKey,
        ReadOnlySpan<byte> sourceFingerprint, ulong sourceLocalCommitGeneration,
        ReadOnlySpan<byte> routeOriginLkgHash,
        ReadOnlySpan<byte> routeHistoryCheckpointHash,
        ReadOnlySpan<byte> transitionTranscriptHash, ulong verifiedAtUnixSeconds,
        ulong cacheExpiresAtUnixSeconds, ProductionMailboxSelectionSuccessorMode mode,
        ProductionMailboxRouteAuthorizationKind authorizationKind,
        ReadOnlySpan<byte> cacheTranscriptHash, ReadOnlySpan<byte> selectionInputCommitment,
        ReadOnlySpan<byte> durableOldSelectionHash, ReadOnlySpan<byte> cacheSalt,
        ReadOnlySpan<byte> lineageCommitment, ReadOnlySpan<byte> envelopeSha256,
        uint envelopeLength, ProductionMailboxNodeCacheArtifacts artifacts,
        IReadOnlyList<ProductionMailboxV2Target> targets)
    {
        ArgumentNullException.ThrowIfNull(artifacts);
        ArgumentNullException.ThrowIfNull(targets);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(Domain);
        Hash(hash, activationStateKey); Hash(hash, promotionStateKey); Hash(hash, cohortId);
        Hash(hash, routeStateKey); Hash(hash, publisherPublicKey); Hash(hash, sourceFingerprint);
        Hash(hash, routeOriginLkgHash); Hash(hash, routeHistoryCheckpointHash);
        Hash(hash, transitionTranscriptHash);
        Span<byte> scalar = stackalloc byte[26];
        BinaryPrimitives.WriteUInt64BigEndian(scalar, sourceLocalCommitGeneration);
        BinaryPrimitives.WriteUInt64BigEndian(scalar[8..], verifiedAtUnixSeconds);
        BinaryPrimitives.WriteUInt64BigEndian(scalar[16..], cacheExpiresAtUnixSeconds);
        scalar[24] = (byte)mode; scalar[25] = (byte)authorizationKind;
        hash.AppendData(scalar);
        Hash(hash, cacheTranscriptHash); Hash(hash, selectionInputCommitment);
        Hash(hash, durableOldSelectionHash); Hash(hash, cacheSalt);
        Hash(hash, lineageCommitment); Hash(hash, envelopeSha256);
        Span<byte> envelopeLengthBytes = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(envelopeLengthBytes, envelopeLength);
        hash.AppendData(envelopeLengthBytes);
        foreach (var field in ArtifactFields(artifacts)) Hash(hash, field.Span);
        Span<byte> count = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(count, checked((ushort)targets.Count));
        hash.AppendData(count);
        foreach (var target in targets)
        {
            Hash(hash, target.ReplicaId.Span);
            var endpoint = Encoding.UTF8.GetBytes(target.Endpoint);
            Hash(hash, endpoint);
            Hash(hash, target.CurrentSpkiSha256.Span);
            Hash(hash, target.NextSpkiSha256.Span);
        }
        var digest = hash.GetHashAndReset();
        var signing = new byte[checked(Domain.Length + digest.Length)];
        Domain.CopyTo(signing); digest.CopyTo(signing, Domain.Length);
        return signing;
    }

    internal static byte[] GetSigningBytes(ProductionMailboxV2ActivationState value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var envelope = ProductionMailboxV2WireCodec.DecodeEnvelope(
            value.CanonicalEnvelope.Span);
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
        return GetSigningBytes(value.ActivationStateKey.Span,
            value.PromotionStateKey.Span, value.CohortId.Span,
            value.RouteStateKey.Span, value.PublisherPublicKey.Span,
            value.SourceFingerprint.Span, value.SourceLocalCommitGeneration,
            value.RouteOriginLkgHash.Span, value.RouteHistoryCheckpointHash.Span,
            value.TransitionTranscriptHash.Span, value.VerifiedAtUnixSeconds,
            value.CacheExpiresAtUnixSeconds, value.Mode, value.AuthorizationKind,
            value.CacheTranscriptHash.Span, value.SelectionInputCommitment.Span,
            value.DurableOldSelectionHash.Span, value.CacheSalt.Span,
            value.LineageCommitment.Span, value.EnvelopeSha256.Span,
            checked((uint)value.CanonicalEnvelope.Length), artifacts,
            value.Targets.Select(static target => new ProductionMailboxV2Target(
                target.ReplicaId, target.Endpoint, target.CurrentSpkiSha256,
                target.NextSpkiSha256)).ToArray());
    }

    internal static byte[] ComputeCacheTranscriptHash(
        ProductionMailboxNodeCacheArtifacts artifacts)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("Deep/production-mailbox/node-cache-transcript/v2"u8);
        hash.AppendData([(byte)artifacts.AuthorizationKind]);
        foreach (var field in ArtifactFields(artifacts))
            hash.AppendData(SHA256.HashData(field.Span));
        return hash.GetHashAndReset();
    }

    private static IEnumerable<ReadOnlyMemory<byte>> ArtifactFields(
        ProductionMailboxNodeCacheArtifacts value)
    {
        yield return value.CanonicalAuthority; yield return value.CanonicalRevocations;
        yield return value.CanonicalTopology; yield return value.CanonicalCurrentSelection;
        yield return value.CanonicalNextSelection; yield return value.CanonicalSelectionSuccessorV2;
        yield return value.CanonicalRouteCertificate; yield return value.CanonicalTransitionContext;
        yield return value.CanonicalRouteAuthorization; yield return value.CanonicalRevocationCheckpoint;
    }

    private static void Hash(IncrementalHash hash, ReadOnlySpan<byte> value)
    {
        Span<byte> length = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)value.Length));
        hash.AppendData(length); hash.AppendData(value);
    }
}

internal static class ProductionMailboxV2CacheBuilder
{
    internal static ProductionMailboxV2PreparedCache Create(
        ProductionMailboxRouteContinuityStateSnapshot routeState,
        ProductionMailboxV2ControlPlaneClosure controlPlane)
    {
        ArgumentNullException.ThrowIfNull(routeState);
        ArgumentNullException.ThrowIfNull(controlPlane);
        var verified = ProductionMailboxNodeCacheVerifier.Verify(
            controlPlane.Bind(routeState), controlPlane.Context);
        var artifacts = verified.CanonicalArtifacts;
        var pss = ProductionMailboxSelectionSuccessorV2Codec.Decode(
            artifacts.CanonicalSelectionSuccessorV2.Span);
        var targets = DeriveTargets(artifacts, pss);
        return new(artifacts, verified.CacheTranscriptHash.ToArray(),
            pss.Selection.SelectionInputCommitment.ToArray(),
            pss.Selection.OldCanonicalSelectionHash.ToArray(),
            ProductionMailboxV2SourceFingerprint.Compute(routeState),
            controlPlane.Context.ControlPlane.VerifiedAtUnixSeconds,
            verified.CacheExpiresAtUnixSeconds, verified.Mode,
            verified.AuthorizationKind, targets);
    }

    internal static IReadOnlyList<ProductionMailboxV2Target> DeriveTargets(
        ProductionMailboxNodeCacheArtifacts artifacts,
        ProductionMailboxSelectionSuccessorV2Proof pss)
    {
        var topology = ProductionMailboxTopologyCodec.Decode(artifacts.CanonicalTopology.Span);
        var current = ProductionMailboxTopologyCodec.DecodeSelection(
            artifacts.CanonicalCurrentSelection.Span);
        var old = ProductionMailboxTopologyCodec.DecodeSelection(
            pss.Selection.OldCanonicalSelection.Span);
        var nodes = topology.CurrentEpoch.Nodes.Concat(topology.NextEpoch.Nodes)
            .GroupBy(static node => Convert.ToHexString(node.NodeId.Span), StringComparer.Ordinal)
            .ToDictionary(static group => group.Key, static group => group.First(),
                StringComparer.Ordinal);
        // XNode authorizes PMP2 only for the exact PSS2 old and new/current selections.
        // The mandatory next PMS1 is cache material, not a publication target by itself.
        var ids = old.Replicas.Concat(current.Replicas)
            .Select(static replica => replica.ReplicaId.ToArray())
            .Distinct(ByteArrayEqualityComparer.Instance)
            .OrderBy(static id => Convert.ToHexString(id), StringComparer.Ordinal)
            .ToArray();
        var result = new List<ProductionMailboxV2Target>(ids.Length);
        foreach (var id in ids)
        {
            if (!nodes.TryGetValue(Convert.ToHexString(id), out var node))
                throw new InvalidDataException(
                    "PMC2 target is absent from the verified successor topology.");
            result.Add(new(id, node.HttpsEndpoint, node.CurrentSpkiSha256.ToArray(),
                node.NextSpkiSha256.ToArray()));
        }
        return result;
    }

    private sealed class ByteArrayEqualityComparer : IEqualityComparer<byte[]>
    {
        internal static ByteArrayEqualityComparer Instance { get; } = new();
        public bool Equals(byte[]? left, byte[]? right) => ReferenceEquals(left, right)
            || left is not null && right is not null && left.AsSpan().SequenceEqual(right);
        public int GetHashCode(byte[] value)
        {
            var hash = new HashCode();
            hash.AddBytes(value);
            return hash.ToHashCode();
        }
    }
}

internal static class ProductionMailboxV2SourceFingerprint
{
    private static ReadOnlySpan<byte> Domain =>
        "Deep/Registry/production-mailbox-v2-source-state/v1"u8;

    internal static byte[] Compute(ProductionMailboxRouteContinuityStateSnapshot state)
    {
        ArgumentNullException.ThrowIfNull(state);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(Domain);
        hash.AppendData(state.RouteStateKey.Span);
        Append(hash, state.LocalCommitGeneration);
        hash.AppendData(state.RouteOriginLkgHash.Span);
        hash.AppendData(stackalloc byte[] { (byte)state.CurrentAuthorizationKind });
        hash.AppendData(state.CurrentAuthorizationHash.Span);
        Append(hash, state.CurrentAuthorizationSequence);
        hash.AppendData(state.TransitionTranscriptHash.Span);
        hash.AppendData(SHA256.HashData(state.CanonicalSelectionSuccessor.Span));
        hash.AppendData(SHA256.HashData(state.CanonicalRouteCertificate.Span));
        hash.AppendData(SHA256.HashData(state.CanonicalRouteAuthorization.Span));
        hash.AppendData(SHA256.HashData(state.CanonicalRevocationCheckpoint.Span));
        hash.AppendData(SHA256.HashData(state.CanonicalTransitionContext.Span));
        Append(hash, state.DelegationSequence);
        hash.AppendData(state.CanonicalDelegationHash.Span);
        hash.AppendData(state.CanonicalDelegationAcceptanceHash.Span);
        Append(hash, state.OwnerRevocationGeneration);
        hash.AppendData(state.CanonicalOwnerRevocationHash.Span);
        var history = state.History;
        if (history is null)
        {
            hash.AppendData(new byte[32]);
            Append(hash, 0);
            hash.AppendData(new byte[32]);
        }
        else
        {
            hash.AppendData(history.CanonicalCheckpointHash.Span);
            Append(hash, history.LastCommittedBatchSequence);
            hash.AppendData(history.LastCommittedBatchHash.Span);
        }
        return hash.GetHashAndReset();
    }

    private static void Append(IncrementalHash hash, ulong value)
    {
        Span<byte> bytes = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(bytes, value);
        hash.AppendData(bytes);
    }
}

internal sealed record ProductionMailboxV2ClosureEnvelope(
    ProductionMailboxRouteAuthorizationKind AuthorizationKind,
    ReadOnlyMemory<byte> CacheSalt,
    ReadOnlyMemory<byte> LineageCommitment,
    ReadOnlyMemory<byte> Authority,
    ReadOnlyMemory<byte> Revocations,
    ReadOnlyMemory<byte> Topology,
    ReadOnlyMemory<byte> CurrentSelection,
    ReadOnlyMemory<byte> NextSelection,
    ReadOnlyMemory<byte> SelectionSuccessorV2,
    ReadOnlyMemory<byte> RouteCertificate,
    ReadOnlyMemory<byte> TransitionContext,
    ReadOnlyMemory<byte> RouteAuthorization,
    ReadOnlyMemory<byte> RevocationCheckpoint);

internal sealed record ProductionMailboxV2PrepositionCommand(
    ulong TimestampUnixSeconds,
    ReadOnlyMemory<byte> Nonce,
    ReadOnlyMemory<byte> EnvelopeSha256,
    ReadOnlyMemory<byte> TargetReplicaId,
    ReadOnlyMemory<byte> PublisherSignature,
    ReadOnlyMemory<byte> CanonicalEnvelope,
    ReadOnlyMemory<byte> ReservationCohortId);

internal static class ProductionMailboxV2WireCodec
{
    private static ReadOnlySpan<byte> EnvelopeMagic => "PMC2"u8;
    private static ReadOnlySpan<byte> CommandMagic => "PMP2"u8;
    private static ReadOnlySpan<byte> CommitmentDomain =>
        "Deep/XNode/production-mailbox-route-lineage-commitment/v2"u8;
    private static ReadOnlySpan<byte> SignatureDomain => "Deep/PMP2/preposition/v2"u8;
    internal const int EnvelopeHeaderLength = 112;
    internal const int CommandHeaderLength = 280;
    internal const int MaximumEnvelopeBytes = EnvelopeHeaderLength
        + ProductionMailboxNodeCacheVerifier.MaximumAggregateBytes;
    internal const int MaximumCommandBytes = CommandHeaderLength + MaximumEnvelopeBytes;

    internal static byte[] EncodeEnvelope(ProductionMailboxV2ClosureEnvelope value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var fields = Fields(value).Select(static field => field.ToArray()).ToArray();
        var total = fields.Aggregate(EnvelopeHeaderLength,
            static (sum, field) => checked(sum + field.Length));
        ValidateEnvelopeShape(value.AuthorizationKind, value.CacheSalt.Span,
            value.LineageCommitment.Span, fields.Select(static field => field.Length).ToArray(),
            total, allowZeroCommitment: false);
        if (!CryptographicOperations.FixedTimeEquals(
                ComputeLineageCommitment(value), value.LineageCommitment.Span))
            throw new InvalidDataException("PMC2 lineage commitment is invalid.");
        var bytes = new byte[total];
        EnvelopeMagic.CopyTo(bytes); bytes[4] = 2; bytes[5] = (byte)value.AuthorizationKind;
        value.CacheSalt.Span.CopyTo(bytes.AsSpan(8));
        value.LineageCommitment.Span.CopyTo(bytes.AsSpan(40));
        for (var index = 0; index < fields.Length; index++)
            BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(72 + index * 4),
                checked((uint)fields[index].Length));
        var offset = EnvelopeHeaderLength;
        foreach (var field in fields)
        {
            field.CopyTo(bytes, offset);
            offset += field.Length;
        }
        return bytes;
    }

    internal static ProductionMailboxV2ClosureEnvelope DecodeEnvelope(
        ReadOnlySpan<byte> canonical)
    {
        if (canonical.Length is < EnvelopeHeaderLength or > MaximumEnvelopeBytes
            || !canonical[..4].SequenceEqual(EnvelopeMagic) || canonical[4] != 2
            || canonical.Slice(6, 2).IndexOfAnyExcept((byte)0) >= 0)
            throw new InvalidDataException("PMC2 envelope header is invalid.");
        var lengths = new int[10];
        var total = EnvelopeHeaderLength;
        for (var index = 0; index < lengths.Length; index++)
        {
            var raw = BinaryPrimitives.ReadUInt32BigEndian(canonical.Slice(72 + index * 4, 4));
            if (raw > int.MaxValue) throw new InvalidDataException("PMC2 length is invalid.");
            lengths[index] = (int)raw; total = checked(total + lengths[index]);
        }
        var kind = (ProductionMailboxRouteAuthorizationKind)canonical[5];
        ValidateEnvelopeShape(kind, canonical.Slice(8, 32), canonical.Slice(40, 32),
            lengths, total, allowZeroCommitment: false);
        if (total != canonical.Length)
            throw new InvalidDataException("PMC2 envelope length is invalid.");
        var fields = new byte[10][]; var offset = EnvelopeHeaderLength;
        for (var index = 0; index < fields.Length; index++)
        {
            fields[index] = canonical.Slice(offset, lengths[index]).ToArray();
            offset += lengths[index];
        }
        var value = new ProductionMailboxV2ClosureEnvelope(kind,
            canonical.Slice(8, 32).ToArray(), canonical.Slice(40, 32).ToArray(),
            fields[0], fields[1], fields[2], fields[3], fields[4], fields[5],
            fields[6], fields[7], fields[9], fields[8]);
        if (!EncodeEnvelope(value).AsSpan().SequenceEqual(canonical))
            throw new InvalidDataException("PMC2 envelope is noncanonical.");
        return value;
    }

    internal static byte[] ComputeLineageCommitment(ProductionMailboxV2ClosureEnvelope value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var fields = Fields(value);
        var total = fields.Aggregate(EnvelopeHeaderLength,
            static (sum, field) => checked(sum + field.Length));
        ValidateEnvelopeShape(value.AuthorizationKind, value.CacheSalt.Span, new byte[32],
            fields.Select(static field => field.Length).ToArray(), total,
            allowZeroCommitment: true);
        var pss = ProductionMailboxSelectionSuccessorV2Codec.Decode(
            value.SelectionSuccessorV2.Span);
        var rtc = ProductionMailboxRouteAuthorizationCodec.DecodeTransitionContext(
            value.TransitionContext.Span);
        if (pss.Selection.Mode != rtc.Mode || pss.NewAuthorizationKind != value.AuthorizationKind)
            throw new InvalidDataException("PMC2 transition tags differ.");
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(CommitmentDomain);
        hash.AppendData(pss.Selection.NetworkId.Span);
        hash.AppendData(pss.Selection.MailboxOwnerEd25519PublicKey.Span);
        hash.AppendData(pss.Selection.SelectionInputCommitment.Span);
        hash.AppendData(pss.Selection.OldCanonicalSelectionHash.Span);
        hash.AppendData(rtc.SealedOldRouteOriginLkgHash.Span);
        hash.AppendData(stackalloc byte[] { (byte)rtc.Mode, (byte)value.AuthorizationKind });
        hash.AppendData(SHA256.HashData(value.TransitionContext.Span));
        hash.AppendData(SHA256.HashData(value.SelectionSuccessorV2.Span));
        hash.AppendData(value.CacheSalt.Span);
        return hash.GetHashAndReset();
    }

    internal static async ValueTask<byte[]> CreateCommandAsync(
        ProductionMailboxV2MaterializedCache cache,
        ReadOnlyMemory<byte> targetReplicaId,
        ReadOnlyMemory<byte> cohortId,
        ulong timestampUnixSeconds,
        IProductionMailboxClosurePublisherSigner signer,
        ReadOnlyMemory<byte> publisherPublicKey,
        CancellationToken cancellationToken,
        Func<byte[]>? createNonce = null,
        Action<byte[]>? afterSignatureSnapshotForTests = null)
    {
        ArgumentNullException.ThrowIfNull(cache);
        ArgumentNullException.ThrowIfNull(signer);
        if (targetReplicaId.Length != 32 || cohortId.Length != 32
            || publisherPublicKey.Length != 32 || timestampUnixSeconds == 0)
            throw new InvalidDataException("PMP2 command context is invalid.");
        var nonce = (createNonce ?? (() => RandomNumberGenerator.GetBytes(32)))();
        var unsigned = new ProductionMailboxV2PrepositionCommand(timestampUnixSeconds,
            nonce, cache.EnvelopeSha256, targetReplicaId.ToArray(), new byte[64],
            cache.CanonicalEnvelope, cohortId.ToArray());
        var signingBytes = GetCommandSigningBytes(unsigned);
        var returnedSignature = await signer.SignAsync(signingBytes, cancellationToken);
        if (returnedSignature.Length != 64)
            throw new InvalidDataException("PMP2 publisher signature is invalid.");
        var signature = returnedSignature.ToArray();
        afterSignatureSnapshotForTests?.Invoke(returnedSignature);
        if (!PublicKeyAuth.VerifyDetached(signature,
                signingBytes, publisherPublicKey.ToArray()))
            throw new InvalidDataException("PMP2 publisher signature is invalid.");
        return EncodeCommand(unsigned with { PublisherSignature = signature });
    }

    internal static byte[] EncodeCommand(ProductionMailboxV2PrepositionCommand value)
    {
        var frozen = FreezeCommand(value);
        ValidateCommand(frozen, allowZeroSignature: false);
        var bytes = new byte[checked(CommandHeaderLength + frozen.CanonicalEnvelope.Length)];
        CommandMagic.CopyTo(bytes); bytes[4] = 2;
        BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(8), frozen.TimestampUnixSeconds);
        frozen.Nonce.Span.CopyTo(bytes.AsSpan(16));
        frozen.EnvelopeSha256.Span.CopyTo(bytes.AsSpan(48));
        frozen.TargetReplicaId.Span.CopyTo(bytes.AsSpan(80));
        frozen.PublisherSignature.Span.CopyTo(bytes.AsSpan(176));
        frozen.ReservationCohortId.Span.CopyTo(bytes.AsSpan(240));
        BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(272),
            checked((uint)frozen.CanonicalEnvelope.Length));
        frozen.CanonicalEnvelope.Span.CopyTo(bytes.AsSpan(CommandHeaderLength));
        return bytes;
    }

    internal static byte[] GetCommandSigningBytes(ProductionMailboxV2PrepositionCommand value)
    {
        var frozen = FreezeCommand(value);
        ValidateCommand(frozen, allowZeroSignature: true);
        var pss = ProductionMailboxSelectionSuccessorV2Codec.Decode(
            TakeEnvelopeField(frozen.CanonicalEnvelope.Span, 5));
        var commitment = frozen.CanonicalEnvelope.Slice(40, 32);
        var bytes = new byte[SignatureDomain.Length + 234];
        SignatureDomain.CopyTo(bytes); var offset = SignatureDomain.Length;
        BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(offset), frozen.TimestampUnixSeconds);
        offset += 8;
        frozen.Nonce.Span.CopyTo(bytes.AsSpan(offset)); offset += 32;
        frozen.EnvelopeSha256.Span.CopyTo(bytes.AsSpan(offset)); offset += 32;
        frozen.TargetReplicaId.Span.CopyTo(bytes.AsSpan(offset)); offset += 32;
        offset += 65;
        frozen.ReservationCohortId.Span.CopyTo(bytes.AsSpan(offset)); offset += 32;
        bytes[offset++] = (byte)pss.Selection.Mode;
        commitment.Span.CopyTo(bytes.AsSpan(offset));
        return bytes;
    }

    internal static bool VerifyCanonicalCommand(ReadOnlySpan<byte> canonical,
        ReadOnlySpan<byte> publisherPublicKey)
    {
        if (publisherPublicKey.Length != 32
            || canonical.Length is < CommandHeaderLength or > MaximumCommandBytes)
            return false;
        try
        {
            var envelopeLengthValue = BinaryPrimitives.ReadUInt32BigEndian(canonical[272..]);
            if (envelopeLengthValue > int.MaxValue
                || canonical.Length - CommandHeaderLength != (int)envelopeLengthValue)
                return false;
            var value = new ProductionMailboxV2PrepositionCommand(
                BinaryPrimitives.ReadUInt64BigEndian(canonical[8..]),
                canonical.Slice(16, 32).ToArray(), canonical.Slice(48, 32).ToArray(),
                canonical.Slice(80, 32).ToArray(), canonical.Slice(176, 64).ToArray(),
                canonical[CommandHeaderLength..].ToArray(),
                canonical.Slice(240, 32).ToArray());
            var frozen = FreezeCommand(value);
            ValidateCommand(frozen, allowZeroSignature: false);
            return EncodeCommand(frozen).AsSpan().SequenceEqual(canonical)
                && PublicKeyAuth.VerifyDetached(frozen.PublisherSignature.ToArray(),
                    GetCommandSigningBytes(frozen), publisherPublicKey.ToArray());
        }
        catch (Exception exception) when (exception is InvalidDataException
            or ArgumentException or CryptographicException or OverflowException)
        {
            return false;
        }
    }

    private static ProductionMailboxV2PrepositionCommand FreezeCommand(
        ProductionMailboxV2PrepositionCommand value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.CanonicalEnvelope.Length is < EnvelopeHeaderLength or > MaximumEnvelopeBytes
            || value.Nonce.Length != 32 || value.EnvelopeSha256.Length != 32
            || value.TargetReplicaId.Length != 32 || value.PublisherSignature.Length != 64
            || value.ReservationCohortId.Length != 32)
            throw new InvalidDataException("PMP2 fields are invalid.");
        return value with
        {
            Nonce = value.Nonce.ToArray(),
            EnvelopeSha256 = value.EnvelopeSha256.ToArray(),
            TargetReplicaId = value.TargetReplicaId.ToArray(),
            PublisherSignature = value.PublisherSignature.ToArray(),
            CanonicalEnvelope = value.CanonicalEnvelope.ToArray(),
            ReservationCohortId = value.ReservationCohortId.ToArray()
        };
    }

    private static void ValidateCommand(ProductionMailboxV2PrepositionCommand value,
        bool allowZeroSignature)
    {
        if (value.TimestampUnixSeconds == 0 || Invalid(value.Nonce, 32)
            || Invalid(value.EnvelopeSha256, 32) || Invalid(value.TargetReplicaId, 32)
            || value.ReservationCohortId.Length != 32 || value.PublisherSignature.Length != 64
            || (!allowZeroSignature && value.PublisherSignature.Span.IndexOfAnyExcept((byte)0) < 0)
            || !CryptographicOperations.FixedTimeEquals(value.EnvelopeSha256.Span,
                SHA256.HashData(value.CanonicalEnvelope.Span)))
            throw new InvalidDataException("PMP2 fields are invalid.");
    }

    private static void ValidateEnvelopeShape(ProductionMailboxRouteAuthorizationKind kind,
        ReadOnlySpan<byte> salt, ReadOnlySpan<byte> commitment, ReadOnlySpan<int> lengths,
        int total, bool allowZeroCommitment)
    {
        var tagged = kind switch
        {
            ProductionMailboxRouteAuthorizationKind.OwnerPRA2 => lengths[8] == 0
                && lengths[9] == ProductionMailboxRouteAuthorizationConstants
                    .CanonicalAdvertisementV2Length,
            ProductionMailboxRouteAuthorizationKind.DelegatedRCA1 =>
                lengths[8] == ProductionMailboxRouteContinuityConstants
                    .CanonicalRevocationCheckpointLength
                && lengths[9] == ProductionMailboxRouteAuthorizationConstants
                    .CanonicalContinuityActivationLength,
            _ => false
        };
        if (lengths.Length != 10 || salt.Length != 32
            || salt.IndexOfAnyExcept((byte)0) < 0 || commitment.Length != 32
            || (!allowZeroCommitment && commitment.IndexOfAnyExcept((byte)0) < 0)
            || total > MaximumEnvelopeBytes || !tagged
            || lengths[0] is < 1 or > ProductionMailboxAuthorityConstants.MaximumArtifactBytes
            || lengths[1] is < 1 or > ProductionMailboxRevocationSnapshotConstants.MaximumArtifactBytes
            || lengths[2] is < 1 or > ProductionMailboxTopologyConstants.MaximumTopologyArtifactBytes
            || lengths[3] is < 1 or > ProductionMailboxTopologyConstants.MaximumSelectionArtifactBytes
            || lengths[4] is < 1 or > ProductionMailboxTopologyConstants.MaximumSelectionArtifactBytes
            || lengths[5] is < 1 or > ProductionMailboxSelectionSuccessorV2Constants.MaximumArtifactBytes
            || lengths[6] != ProductionMailboxRouteAdvertisementConstants.CanonicalCertificateLength
            || lengths[7] != ProductionMailboxRouteAuthorizationConstants.CanonicalTransitionContextLength)
            throw new InvalidDataException("PMC2 shape is invalid.");
    }

    private static ReadOnlyMemory<byte>[] Fields(ProductionMailboxV2ClosureEnvelope value) =>
    [
        value.Authority, value.Revocations, value.Topology, value.CurrentSelection,
        value.NextSelection, value.SelectionSuccessorV2, value.RouteCertificate,
        value.TransitionContext, value.RevocationCheckpoint, value.RouteAuthorization
    ];

    private static ReadOnlySpan<byte> TakeEnvelopeField(ReadOnlySpan<byte> envelope, int index)
    {
        if (envelope.Length < EnvelopeHeaderLength || index is < 0 or > 9
            || !envelope[..4].SequenceEqual(EnvelopeMagic) || envelope[4] != 2)
            throw new InvalidDataException("PMC2 envelope framing is invalid.");
        var offset = EnvelopeHeaderLength;
        for (var current = 0; current <= index; current++)
        {
            var lengthValue = BinaryPrimitives.ReadUInt32BigEndian(
                envelope.Slice(72 + current * 4, 4));
            if (lengthValue > int.MaxValue) throw new InvalidDataException("PMC2 length is invalid.");
            var length = (int)lengthValue;
            if (offset > envelope.Length - length)
                throw new InvalidDataException("PMC2 length is invalid.");
            if (current == index) return envelope.Slice(offset, length);
            offset += length;
        }
        throw new InvalidDataException("PMC2 field is unavailable.");
    }

    private static bool Invalid(ReadOnlyMemory<byte> value, int length) =>
        value.Length != length || value.Span.IndexOfAnyExcept((byte)0) < 0;
}
