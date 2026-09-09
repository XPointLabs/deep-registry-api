using System.Buffers.Binary;
using System.Security.Cryptography;

#if DEEP_PROTOCOL_DIRECTORY_V1
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.XPointNetworkV1;
#endif

namespace Deep.Registry.Api.DirectoryPublication;

internal sealed class DirectoryCatalogCompactionSource
{
    private readonly byte[] protectedLkgFingerprint;
    private readonly byte[] sourceSpecificProofHash;

    internal DirectoryCatalogCompactionSource(
        ulong generation,
        ReadOnlySpan<byte> protectedLkgFingerprint,
        ReadOnlySpan<byte> sourceSpecificProofHash)
    {
        if (protectedLkgFingerprint.Length != DirectoryPublicationCatalog.HashBytes ||
            protectedLkgFingerprint.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException("A non-zero source protected-LKG fingerprint is required.", nameof(protectedLkgFingerprint));
        }
        if (sourceSpecificProofHash.Length != DirectoryPublicationCatalog.HashBytes ||
            sourceSpecificProofHash.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException("A non-zero source-specific NFP1 hash is required.", nameof(sourceSpecificProofHash));
        }
        Generation = generation;
        this.protectedLkgFingerprint = protectedLkgFingerprint.ToArray();
        this.sourceSpecificProofHash = sourceSpecificProofHash.ToArray();
    }

    internal ulong Generation { get; }
    internal ReadOnlyMemory<byte> ProtectedLkgFingerprint => protectedLkgFingerprint.ToArray();
    internal ReadOnlyMemory<byte> SourceSpecificProofHash => sourceSpecificProofHash.ToArray();
}

/// <summary>
/// Closed, non-serializable authority for one catalog prefix transition. Production
/// construction requires Protocol-minted forward-checkpoint results; callers cannot
/// authorize deletion with a Boolean, file timestamp, raw key, or common proof.
/// </summary>
internal sealed class DirectoryCatalogCompactionCapability
{
    private static readonly byte[] HashDomain =
        "Deep/Registry/DirectoryCatalog/V1/checkpoint-compaction-capability"u8.ToArray();
    private readonly byte[] networkId;
    private readonly byte[] targetProtectedLkgFingerprint;
    private readonly DirectoryCatalogCompactionSource[] sources;
    private readonly byte[] capabilityHash;

    private DirectoryCatalogCompactionCapability(
        ReadOnlySpan<byte> networkId,
        ulong currentTrustedLowerUnixSeconds,
        ulong targetGeneration,
        ReadOnlySpan<byte> targetProtectedLkgFingerprint,
        IReadOnlyList<DirectoryCatalogCompactionSource> sources)
    {
        if (networkId.Length != DirectoryPublicationCatalog.NetworkIdBytes ||
            networkId.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException("A non-zero network ID is required.", nameof(networkId));
        }
        if (currentTrustedLowerUnixSeconds == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(currentTrustedLowerUnixSeconds));
        }
        if (targetProtectedLkgFingerprint.Length != DirectoryPublicationCatalog.HashBytes ||
            targetProtectedLkgFingerprint.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException("A non-zero target protected-LKG fingerprint is required.", nameof(targetProtectedLkgFingerprint));
        }
        ArgumentNullException.ThrowIfNull(sources);
        if (sources.Count is < 1 or > DirectoryCatalogLimits.MaximumCompactionSourceProofs)
        {
            throw new ArgumentOutOfRangeException(nameof(sources));
        }

        ulong? prior = null;
        foreach (var source in sources)
        {
            ArgumentNullException.ThrowIfNull(source);
            if (source.Generation >= targetGeneration ||
                prior.HasValue && (prior == ulong.MaxValue || source.Generation != prior + 1))
            {
                throw new ArgumentException(
                    "Compaction sources must be the exact contiguous prefix before the retained target.",
                    nameof(sources));
            }
            prior = source.Generation;
        }
        if (!prior.HasValue || prior == ulong.MaxValue || prior + 1 != targetGeneration)
        {
            throw new ArgumentException(
                "Compaction source coverage must end immediately before the retained target.",
                nameof(sources));
        }

        this.networkId = networkId.ToArray();
        CurrentTrustedLowerUnixSeconds = currentTrustedLowerUnixSeconds;
        TargetGeneration = targetGeneration;
        this.targetProtectedLkgFingerprint = targetProtectedLkgFingerprint.ToArray();
        this.sources = sources.Select(static source => new DirectoryCatalogCompactionSource(
            source.Generation,
            source.ProtectedLkgFingerprint.Span,
            source.SourceSpecificProofHash.Span)).ToArray();
        capabilityHash = ComputeHash();
    }

    internal ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    internal ulong CurrentTrustedLowerUnixSeconds { get; }
    internal ulong TargetGeneration { get; }
    internal ReadOnlyMemory<byte> TargetProtectedLkgFingerprint =>
        targetProtectedLkgFingerprint.ToArray();
    internal IReadOnlyList<DirectoryCatalogCompactionSource> Sources =>
        Array.AsReadOnly(sources.Select(static source => new DirectoryCatalogCompactionSource(
            source.Generation,
            source.ProtectedLkgFingerprint.Span,
            source.SourceSpecificProofHash.Span)).ToArray());
    internal ReadOnlyMemory<byte> CapabilityHash => capabilityHash.ToArray();

#if DEEP_PROTOCOL_DIRECTORY_V1
    internal static DirectoryCatalogCompactionCapability MintFromVerifiedProtocol(
        VerifiedAccountDirectoryFreshness currentFreshness,
        IReadOnlyList<VerifiedXPointNetworkForwardCheckpoint> sourceSpecificProofs)
    {
        ArgumentNullException.ThrowIfNull(currentFreshness);
        ArgumentNullException.ThrowIfNull(sourceSpecificProofs);
        if (sourceSpecificProofs.Count == 0)
        {
            throw new ArgumentException("At least one source-specific verified NFP1 is required.", nameof(sourceSpecificProofs));
        }

        foreach (var proof in sourceSpecificProofs)
        {
            ArgumentNullException.ThrowIfNull(proof);
        }

        var network = currentFreshness.NetworkId.ToArray();
        ulong? targetGeneration = null;
        byte[]? targetFingerprint = null;
        var sources = new List<DirectoryCatalogCompactionSource>(sourceSpecificProofs.Count);
        foreach (var proof in sourceSpecificProofs.OrderBy(static value => value.PriorProtectedLkg.ViewGeneration))
        {
            proof.EnsureCurrent();
            if (!CryptographicOperations.FixedTimeEquals(proof.NextProtectedLkg.NetworkId.Span, network) ||
                !CryptographicOperations.FixedTimeEquals(proof.PriorProtectedLkg.NetworkId.Span, network))
            {
                throw new CryptographicException("A verified compaction proof belongs to another network.");
            }

            var nextFingerprint = DirectoryPublicationProtectedLkgFingerprint.Compute(proof.NextProtectedLkg);
            targetGeneration ??= proof.TargetViewGeneration;
            targetFingerprint ??= nextFingerprint;
            if (proof.TargetViewGeneration != targetGeneration ||
                !CryptographicOperations.FixedTimeEquals(targetFingerprint, nextFingerprint))
            {
                throw new CryptographicException("Verified compaction proofs do not share one exact retained target.");
            }
            sources.Add(new DirectoryCatalogCompactionSource(
                proof.PriorProtectedLkg.ViewGeneration,
                DirectoryPublicationProtectedLkgFingerprint.Compute(proof.PriorProtectedLkg),
                SHA256.HashData(proof.ExactNfp1.Span)));
        }

        return new DirectoryCatalogCompactionCapability(
            network,
            currentFreshness.TrustedLowerUnixSeconds,
            targetGeneration!.Value,
            targetFingerprint!,
            sources);
    }
#endif

#if DEEP_DIRECTORY_COMPACTION_TEST_SEAM
    internal static DirectoryCatalogCompactionCapability CreateForTests(
        ReadOnlySpan<byte> networkId,
        ulong currentTrustedLowerUnixSeconds,
        ulong targetGeneration,
        ReadOnlySpan<byte> targetProtectedLkgFingerprint,
        IReadOnlyList<DirectoryCatalogCompactionSource> sources) =>
        new(networkId, currentTrustedLowerUnixSeconds, targetGeneration,
            targetProtectedLkgFingerprint, sources);
#endif

    private byte[] ComputeHash()
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(HashDomain);
        hash.AppendData(networkId);
        Span<byte> scalar = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(scalar, TargetGeneration);
        hash.AppendData(scalar);
        hash.AppendData(targetProtectedLkgFingerprint);
        BinaryPrimitives.WriteUInt64BigEndian(scalar, checked((ulong)sources.Length));
        hash.AppendData(scalar);
        foreach (var source in sources)
        {
            BinaryPrimitives.WriteUInt64BigEndian(scalar, source.Generation);
            hash.AppendData(scalar);
            hash.AppendData(source.ProtectedLkgFingerprint.Span);
            hash.AppendData(source.SourceSpecificProofHash.Span);
        }
        return hash.GetHashAndReset();
    }
}

internal static class DirectoryPublicationProtectedLkgFingerprint
{
    private static readonly byte[] Domain =
        "Deep/Registry/DirectoryCatalog/V1/protected-network-lkg"u8.ToArray();

    internal static byte[] Compute(DirectoryPublicationProtectedNetworkLkg value) => Compute(
        value.NetworkId.Span,
        value.HeadCoreReference.Span,
        value.HeadTreeSize,
        value.HeadRoot.Span,
        value.ViewCoreReference.Span,
        value.ViewGeneration,
        value.AuthorityCoreReference.Span,
        value.LastForwardCheckpointCoreReference.Span,
        value.LastForwardCheckpointGeneration);

#if DEEP_PROTOCOL_DIRECTORY_V1
    internal static byte[] Compute(XPointNetworkProtectedLkg value) => Compute(
        value.NetworkId.Span,
        value.HeadCoreReference.Span,
        value.HeadTreeSize,
        value.HeadRoot.Span,
        value.ViewCoreReference.Span,
        value.ViewGeneration,
        value.AuthorityCoreReference.Span,
        value.LastForwardCheckpointCoreReference.Span,
        value.LastForwardCheckpointGeneration);

    internal static DirectoryPublicationRetentionAuthority RetentionFromVerifiedProtocol(
        VerifiedAccountDirectoryFreshness freshness,
        XPointNetworkProtectedLkg value) => new(
            freshness.TrustedUpperUnixSeconds,
            Compute(value));
#endif

    private static byte[] Compute(
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> headReference,
        ulong headTreeSize,
        ReadOnlySpan<byte> headRoot,
        ReadOnlySpan<byte> viewReference,
        ulong viewGeneration,
        ReadOnlySpan<byte> authorityReference,
        ReadOnlySpan<byte> lastCheckpointReference,
        ulong? lastCheckpointGeneration)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(Domain);
        hash.AppendData(networkId);
        hash.AppendData(headReference);
        Span<byte> scalar = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(scalar, headTreeSize);
        hash.AppendData(scalar);
        hash.AppendData(headRoot);
        hash.AppendData(viewReference);
        BinaryPrimitives.WriteUInt64BigEndian(scalar, viewGeneration);
        hash.AppendData(scalar);
        hash.AppendData(authorityReference);
        hash.AppendData([lastCheckpointGeneration.HasValue ? (byte)1 : (byte)0]);
        if (lastCheckpointGeneration.HasValue)
        {
            hash.AppendData(lastCheckpointReference);
            BinaryPrimitives.WriteUInt64BigEndian(scalar, lastCheckpointGeneration.Value);
            hash.AppendData(scalar);
        }
        return hash.GetHashAndReset();
    }
}
