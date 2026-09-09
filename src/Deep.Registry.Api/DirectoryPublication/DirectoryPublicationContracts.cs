using System.Security.Cryptography;

namespace Deep.Registry.Api.DirectoryPublication;

internal enum DirectoryArtifactKind : byte
{
    CurrentNetworkView = 1,
    CurrentNetworkViewHead = 2,
    CurrentMailboxTopology = 3,
    NetworkForwardCheckpoint = 4,
    NetworkForwardProof = 5
}

internal sealed class DirectoryPublicationCandidate
{
    private readonly byte[] currentNetworkView;
    private readonly byte[] currentNetworkViewHead;
    private readonly byte[] currentMailboxTopology;
    private readonly DirectoryPublicationVerificationClosure verificationClosure;
    private readonly byte[]? networkForwardCheckpoint;
    private readonly byte[]? networkForwardProof;

    public DirectoryPublicationCandidate(
        ReadOnlySpan<byte> currentNetworkView,
        ReadOnlySpan<byte> currentNetworkViewHead,
        ReadOnlySpan<byte> currentMailboxTopology,
        DirectoryPublicationVerificationClosure verificationClosure,
        ReadOnlySpan<byte> networkForwardCheckpoint = default,
        ReadOnlySpan<byte> networkForwardProof = default)
    {
        // Absolute admission happens before any ToArray/allocation.
        ValidateAbsoluteArtifact(currentNetworkView, nameof(currentNetworkView));
        ValidateAbsoluteArtifact(currentNetworkViewHead, nameof(currentNetworkViewHead));
        ValidateAbsoluteArtifact(currentMailboxTopology, nameof(currentMailboxTopology));
        ArgumentNullException.ThrowIfNull(verificationClosure);
        if (networkForwardCheckpoint.IsEmpty != networkForwardProof.IsEmpty)
        {
            throw new ArgumentException(
                "XNF1 and NFP1 must be supplied together as one verified reset closure.");
        }

        if (!networkForwardCheckpoint.IsEmpty)
        {
            ValidateAbsoluteArtifact(networkForwardCheckpoint, nameof(networkForwardCheckpoint));
            ValidateAbsoluteArtifact(networkForwardProof, nameof(networkForwardProof));
        }

        var resetChain = verificationClosure.NetworkForwardCheckpointChain;
        if (networkForwardCheckpoint.IsEmpty != (resetChain.Count == 0) ||
            !networkForwardCheckpoint.IsEmpty &&
            (!networkForwardCheckpoint.SequenceEqual(resetChain[^1].Span) ||
             verificationClosure.ResetAuthorityChain.Count == 0))
        {
            throw new ArgumentException(
                "The distributable XNF1/NFP1 pair must match a complete reset verification closure.");
        }
        if (!currentNetworkView.SequenceEqual(verificationClosure.NetworkViewChain[^1].Span) ||
            !currentNetworkViewHead.SequenceEqual(verificationClosure.NetworkViewHeadChain[^1].Span) ||
            !currentMailboxTopology.SequenceEqual(verificationClosure.MailboxTopologyChain[^1].Span))
        {
            throw new ArgumentException(
                "The distributable XNV1/XNH1/PMT2 artifacts must be the terminal exact verification closure.");
        }

        currentNetworkView.CopyTo(this.currentNetworkView = new byte[currentNetworkView.Length]);
        currentNetworkViewHead.CopyTo(
            this.currentNetworkViewHead = new byte[currentNetworkViewHead.Length]);
        currentMailboxTopology.CopyTo(
            this.currentMailboxTopology = new byte[currentMailboxTopology.Length]);
        this.verificationClosure = verificationClosure;
        if (!networkForwardCheckpoint.IsEmpty)
        {
            networkForwardCheckpoint.CopyTo(
                this.networkForwardCheckpoint = new byte[networkForwardCheckpoint.Length]);
            networkForwardProof.CopyTo(
                this.networkForwardProof = new byte[networkForwardProof.Length]);
        }
    }

    public ReadOnlyMemory<byte> CurrentNetworkView => currentNetworkView.ToArray();
    public ReadOnlyMemory<byte> CurrentNetworkViewHead => currentNetworkViewHead.ToArray();
    public ReadOnlyMemory<byte> CurrentMailboxTopology => currentMailboxTopology.ToArray();
    internal DirectoryPublicationVerificationClosure VerificationClosure => verificationClosure;
    public ReadOnlyMemory<byte>? NetworkForwardCheckpoint => Copy(networkForwardCheckpoint);
    public ReadOnlyMemory<byte>? NetworkForwardProof => Copy(networkForwardProof);

    internal FrozenDirectoryPublicationCandidate Freeze() => new(
        currentNetworkView,
        currentNetworkViewHead,
        currentMailboxTopology,
        verificationClosure.Freeze(),
        networkForwardCheckpoint,
        networkForwardProof);

    private static void ValidateAbsoluteArtifact(ReadOnlySpan<byte> value, string parameterName)
    {
        if (value.IsEmpty || value.Length > DirectoryCatalogLimits.AbsoluteMaximumArtifactBytes)
        {
            throw new ArgumentOutOfRangeException(
                parameterName,
                $"A directory artifact must contain 1..{DirectoryCatalogLimits.AbsoluteMaximumArtifactBytes} bytes.");
        }
    }

    private static ReadOnlyMemory<byte>? Copy(byte[]? value) =>
        value is null ? null : value.ToArray();
}

internal sealed class FrozenDirectoryPublicationCandidate
{
    private readonly byte[] currentNetworkView;
    private readonly byte[] currentNetworkViewHead;
    private readonly byte[] currentMailboxTopology;
    private readonly FrozenDirectoryPublicationVerificationClosure verificationClosure;
    private readonly byte[]? networkForwardCheckpoint;
    private readonly byte[]? networkForwardProof;

    internal FrozenDirectoryPublicationCandidate(
        byte[] currentNetworkView,
        byte[] currentNetworkViewHead,
        byte[] currentMailboxTopology,
        FrozenDirectoryPublicationVerificationClosure verificationClosure,
        byte[]? networkForwardCheckpoint,
        byte[]? networkForwardProof)
    {
        // Keep the verifier-facing snapshot isolated from the reusable candidate.
        // Every copy remains below the absolute admission bound.
        this.currentNetworkView = currentNetworkView.ToArray();
        this.currentNetworkViewHead = currentNetworkViewHead.ToArray();
        this.currentMailboxTopology = currentMailboxTopology.ToArray();
        this.verificationClosure = verificationClosure;
        this.networkForwardCheckpoint = networkForwardCheckpoint?.ToArray();
        this.networkForwardProof = networkForwardProof?.ToArray();
    }

    public ReadOnlyMemory<byte> CurrentNetworkView => currentNetworkView.ToArray();
    public ReadOnlyMemory<byte> CurrentNetworkViewHead => currentNetworkViewHead.ToArray();
    public ReadOnlyMemory<byte> CurrentMailboxTopology => currentMailboxTopology.ToArray();
    internal FrozenDirectoryPublicationVerificationClosure VerificationClosure => verificationClosure;
    public ReadOnlyMemory<byte>? NetworkForwardCheckpoint => Copy(networkForwardCheckpoint);
    public ReadOnlyMemory<byte>? NetworkForwardProof => Copy(networkForwardProof);
    internal bool HasNetworkForwardReset => networkForwardCheckpoint is not null;

    internal IReadOnlyList<(DirectoryArtifactKind Kind, ReadOnlyMemory<byte> Bytes)> Artifacts()
    {
        if (networkForwardCheckpoint is null)
        {
            return
            [
                (DirectoryArtifactKind.CurrentNetworkView, currentNetworkView.ToArray()),
                (DirectoryArtifactKind.CurrentNetworkViewHead, currentNetworkViewHead.ToArray()),
                (DirectoryArtifactKind.CurrentMailboxTopology, currentMailboxTopology.ToArray())
            ];
        }

        return
        [
            (DirectoryArtifactKind.CurrentNetworkView, currentNetworkView.ToArray()),
            (DirectoryArtifactKind.CurrentNetworkViewHead, currentNetworkViewHead.ToArray()),
            (DirectoryArtifactKind.CurrentMailboxTopology, currentMailboxTopology.ToArray()),
            (DirectoryArtifactKind.NetworkForwardCheckpoint, networkForwardCheckpoint.ToArray()),
            (DirectoryArtifactKind.NetworkForwardProof, networkForwardProof!.ToArray())
        ];
    }

    private static ReadOnlyMemory<byte>? Copy(byte[]? value) =>
        value is null ? null : value.ToArray();
}

/// <summary>
/// The future Deep.Protocol adapter must decode and verify the complete closure and
/// return this typed result. A Boolean or caller-supplied "verified" flag cannot
/// cross this boundary.
/// </summary>
internal interface IDirectoryCanonicalPublicationVerifier
{
    ValueTask<VerifiedDirectoryPublication> VerifyAsync(
        FrozenDirectoryPublicationCandidate candidate,
        CancellationToken cancellationToken);
}

internal sealed class VerifiedDirectoryArtifact
{
    private readonly byte[] canonicalBytes;
    private readonly byte[] artifactHash;
    private readonly byte[] coreHash;

    internal VerifiedDirectoryArtifact(
        DirectoryArtifactKind kind,
        ReadOnlySpan<byte> canonicalBytes,
        ReadOnlySpan<byte> coreHash)
    {
        if (canonicalBytes.IsEmpty ||
            canonicalBytes.Length > DirectoryCatalogLimits.AbsoluteMaximumArtifactBytes)
        {
            throw new ArgumentOutOfRangeException(
                nameof(canonicalBytes),
                "Canonical artifact bytes exceed the absolute admission bound.");
        }

        if (coreHash.Length != DirectoryPublicationCatalog.HashBytes ||
            coreHash.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException("The protocol core hash must be 32 non-zero bytes.", nameof(coreHash));
        }

        Kind = kind;
        canonicalBytes.CopyTo(this.canonicalBytes = new byte[canonicalBytes.Length]);
        artifactHash = SHA256.HashData(canonicalBytes);
        coreHash.CopyTo(this.coreHash = new byte[coreHash.Length]);
    }

    public DirectoryArtifactKind Kind { get; }
    public ReadOnlyMemory<byte> CanonicalBytes => canonicalBytes.ToArray();
    public ReadOnlyMemory<byte> ArtifactHash => artifactHash.ToArray();
    public ReadOnlyMemory<byte> CoreHash => coreHash.ToArray();

    internal StoredDirectoryArtifact ToStored() =>
        new(Kind, canonicalBytes, artifactHash, coreHash);
}

internal sealed class DirectoryPublicationRetentionAuthority
{
    private readonly byte[] protectedLkgFingerprint;

    internal DirectoryPublicationRetentionAuthority(
        ulong retentionStartedAtTrustedUnixSeconds,
        ReadOnlySpan<byte> protectedLkgFingerprint)
    {
        if (retentionStartedAtTrustedUnixSeconds == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(retentionStartedAtTrustedUnixSeconds));
        }
        if (protectedLkgFingerprint.Length != DirectoryPublicationCatalog.HashBytes ||
            protectedLkgFingerprint.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException(
                "A non-zero protected-LKG fingerprint is required.",
                nameof(protectedLkgFingerprint));
        }
        RetentionStartedAtTrustedUnixSeconds = retentionStartedAtTrustedUnixSeconds;
        this.protectedLkgFingerprint = protectedLkgFingerprint.ToArray();
    }

    internal ulong RetentionStartedAtTrustedUnixSeconds { get; }
    internal ReadOnlyMemory<byte> ProtectedLkgFingerprint => protectedLkgFingerprint.ToArray();
}

internal sealed class VerifiedDirectoryPublication
{
    private readonly byte[] networkId;
    private readonly VerifiedDirectoryArtifact[] artifacts;

    internal VerifiedDirectoryPublication(
        ReadOnlySpan<byte> networkId,
        ulong generation,
        DirectoryPublicationRetentionAuthority retentionAuthority,
        VerifiedDirectoryArtifact currentNetworkView,
        VerifiedDirectoryArtifact currentNetworkViewHead,
        VerifiedDirectoryArtifact currentMailboxTopology,
        VerifiedDirectoryArtifact? networkForwardCheckpoint = null,
        VerifiedDirectoryArtifact? networkForwardProof = null)
    {
        if (networkId.Length != DirectoryPublicationCatalog.NetworkIdBytes)
        {
            throw new ArgumentException("The XPoint network ID must be 16 bytes.", nameof(networkId));
        }

        ArgumentNullException.ThrowIfNull(currentNetworkView);
        ArgumentNullException.ThrowIfNull(currentNetworkViewHead);
        ArgumentNullException.ThrowIfNull(currentMailboxTopology);
        ArgumentNullException.ThrowIfNull(retentionAuthority);
        if ((networkForwardCheckpoint is null) != (networkForwardProof is null))
        {
            throw new ArgumentException("Verified XNF1 and NFP1 must be supplied together.");
        }

        RequireKind(currentNetworkView, DirectoryArtifactKind.CurrentNetworkView);
        RequireKind(currentNetworkViewHead, DirectoryArtifactKind.CurrentNetworkViewHead);
        RequireKind(currentMailboxTopology, DirectoryArtifactKind.CurrentMailboxTopology);
        if (networkForwardCheckpoint is not null && networkForwardProof is not null)
        {
            RequireKind(networkForwardCheckpoint, DirectoryArtifactKind.NetworkForwardCheckpoint);
            RequireKind(networkForwardProof, DirectoryArtifactKind.NetworkForwardProof);
        }

        networkId.CopyTo(this.networkId = new byte[networkId.Length]);
        Generation = generation;
        RetentionAuthority = retentionAuthority;
        artifacts = networkForwardCheckpoint is null
            ? [currentNetworkView, currentNetworkViewHead, currentMailboxTopology]
            : [
                currentNetworkView,
                currentNetworkViewHead,
                currentMailboxTopology,
                networkForwardCheckpoint,
                networkForwardProof!
            ];
    }

    public ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    public ulong Generation { get; }
    internal DirectoryPublicationRetentionAuthority RetentionAuthority { get; }
    public IReadOnlyList<VerifiedDirectoryArtifact> Artifacts =>
        Array.AsReadOnly(artifacts.ToArray());

    internal StoredDirectoryPublication ToStored() => new(
        Generation,
        RetentionAuthority.RetentionStartedAtTrustedUnixSeconds,
        RetentionAuthority.ProtectedLkgFingerprint.Span,
        artifacts.Select(static artifact => artifact.ToStored()).ToArray());

    private static void RequireKind(
        VerifiedDirectoryArtifact artifact,
        DirectoryArtifactKind expected)
    {
        if (artifact.Kind != expected)
        {
            throw new ArgumentException($"Expected verified {expected}, got {artifact.Kind}.");
        }
    }
}

internal sealed class DirectoryCatalogArtifact
{
    private readonly byte[] canonicalBytes;
    private readonly byte[] artifactHash;
    private readonly byte[] coreHash;

    internal DirectoryCatalogArtifact(StoredDirectoryArtifact value)
    {
        Kind = value.Kind;
        canonicalBytes = value.CanonicalBytes.ToArray();
        artifactHash = value.ArtifactHash.ToArray();
        coreHash = value.CoreHash.ToArray();
    }

    public DirectoryArtifactKind Kind { get; }
    public ReadOnlyMemory<byte> CanonicalBytes => canonicalBytes.ToArray();
    public ReadOnlyMemory<byte> ArtifactHash => artifactHash.ToArray();
    public ReadOnlyMemory<byte> CoreHash => coreHash.ToArray();
}

internal sealed class DirectoryCatalogPublication
{
    private readonly DirectoryCatalogArtifact[] artifacts;
    private readonly byte[] publicationHash;

    internal DirectoryCatalogPublication(StoredDirectoryPublication value)
    {
        Generation = value.Generation;
        artifacts = value.Artifacts
            .Select(static artifact => new DirectoryCatalogArtifact(artifact))
            .ToArray();
        publicationHash = value.PublicationHash.ToArray();
    }

    public ulong Generation { get; }
    public ReadOnlyMemory<byte> PublicationHash => publicationHash.ToArray();
    public IReadOnlyList<DirectoryCatalogArtifact> Artifacts =>
        Array.AsReadOnly(artifacts.ToArray());

    public DirectoryCatalogArtifact GetArtifact(DirectoryArtifactKind kind)
    {
        var artifact = artifacts.SingleOrDefault(value => value.Kind == kind);
        if (artifact is null)
        {
            throw new KeyNotFoundException($"Generation {Generation} does not contain {kind}.");
        }

        return artifact;
    }
}

internal readonly struct DirectoryCatalogAnchor : IEquatable<DirectoryCatalogAnchor>
{
    private readonly byte[]? publicationHash;

    internal DirectoryCatalogAnchor(ulong generation, ReadOnlySpan<byte> publicationHash)
    {
        if (publicationHash.Length != DirectoryPublicationCatalog.HashBytes)
        {
            throw new ArgumentException("The publication hash must be 32 bytes.", nameof(publicationHash));
        }

        Generation = generation;
        publicationHash.CopyTo(this.publicationHash = new byte[publicationHash.Length]);
    }

    public static DirectoryCatalogAnchor Empty => default;
    public bool IsEmpty => publicationHash is null;
    public ulong Generation { get; }
    public ReadOnlyMemory<byte> PublicationHash =>
        publicationHash?.ToArray() ?? ReadOnlyMemory<byte>.Empty;

    public bool Equals(DirectoryCatalogAnchor other)
    {
        if (IsEmpty || other.IsEmpty)
        {
            return IsEmpty == other.IsEmpty;
        }

        return Generation == other.Generation &&
            CryptographicOperations.FixedTimeEquals(publicationHash!, other.publicationHash!);
    }

    public override bool Equals(object? obj) =>
        obj is DirectoryCatalogAnchor other && Equals(other);

    public override int GetHashCode() =>
        IsEmpty ? 0 : HashCode.Combine(Generation, publicationHash![0]);

    public static bool operator ==(DirectoryCatalogAnchor left, DirectoryCatalogAnchor right) =>
        left.Equals(right);

    public static bool operator !=(DirectoryCatalogAnchor left, DirectoryCatalogAnchor right) =>
        !left.Equals(right);
}

internal enum DirectoryCatalogPublishStatus
{
    Published,
    ExactReplay
}

internal enum DirectoryCatalogCompactionStatus
{
    Compacted,
    ExactReplay
}

internal sealed record DirectoryCatalogCompactionResult(
    DirectoryCatalogCompactionStatus Status,
    DirectoryCatalogAnchor CurrentAnchor,
    ulong FirstRetainedGeneration,
    int RetainedGenerationCount);

internal sealed record DirectoryCatalogPublishResult(
    DirectoryCatalogPublishStatus Status,
    DirectoryCatalogAnchor CurrentAnchor);

internal sealed class DirectoryMirrorArtifact
{
    private readonly byte[] bytes;
    private readonly byte[] sha256;

    internal DirectoryMirrorArtifact(ReadOnlySpan<byte> bytes, ReadOnlySpan<byte> sha256)
    {
        if (bytes.IsEmpty)
        {
            throw new ArgumentException("A mirror artifact cannot be empty.", nameof(bytes));
        }
        if (sha256.Length != DirectoryPublicationCatalog.HashBytes ||
            !CryptographicOperations.FixedTimeEquals(SHA256.HashData(bytes), sha256))
        {
            throw new ArgumentException("The mirror artifact hash is invalid.", nameof(sha256));
        }

        this.bytes = bytes.ToArray();
        this.sha256 = sha256.ToArray();
    }

    internal ReadOnlyMemory<byte> Bytes => bytes.ToArray();
    internal ReadOnlyMemory<byte> Sha256 => sha256.ToArray();
}

internal enum DirectoryCatalogError
{
    BoundsExceeded,
    CanonicalVerificationFailed,
    VerificationMismatch,
    WrongNetwork,
    CompareExchangeMismatch,
    GenerationGap,
    Rollback,
    ForkLatched,
    CorruptStateQuarantined,
    HistoryCapacityReached,
    CompactionNotAuthorized,
    CompactionPremature,
    CompactionCoverageMismatch,
    CompactionTargetMismatch
}

internal sealed class DirectoryCatalogException : InvalidOperationException
{
    internal DirectoryCatalogException(
        DirectoryCatalogError error,
        string message,
        Exception? innerException = null)
        : base(message, innerException)
    {
        Error = error;
    }

    public DirectoryCatalogError Error { get; }
}

internal sealed record DirectoryCatalogLimits
{
    public const int AbsoluteMaximumArtifactBytes = 65_535;
    public const int RequiredMinimumHistoryEntries = 2_048;
    public const int AbsoluteMaximumHistoryEntries = 4_096;
    public const int MaximumCompactionSourceProofs =
        AbsoluteMaximumHistoryEntries - RequiredMinimumHistoryEntries;
    public const ulong RequiredRetentionSeconds = 400UL * 24 * 60 * 60;
    public const int AbsoluteMaximumManifestBytes = 512 * 1024;
    public const long AbsoluteMaximumRetainedSegmentBytes = 1536L * 1024 * 1024;

    public int MaximumArtifactBytes { get; init; } = AbsoluteMaximumArtifactBytes;
    public int MaximumHistoryEntries { get; init; } = AbsoluteMaximumHistoryEntries;
    public int MaximumManifestBytes { get; init; } = AbsoluteMaximumManifestBytes;
    public long MaximumRetainedSegmentBytes { get; init; } =
        AbsoluteMaximumRetainedSegmentBytes;

    internal int MaximumSegmentBytes => DirectoryCatalogSegmentCodec.GetMaximumEncodedBytes(
        MaximumArtifactBytes,
        maximumArtifacts: 5);

    internal long MaximumTotalOnDiskBytes => checked(
        MaximumRetainedSegmentBytes +
        (2L * MaximumManifestBytes) +
        (2L * MaximumSegmentBytes) +
        DirectoryCatalogPendingCodec.MaximumEncodedBytes +
        DirectoryCatalogCompactionPendingCodec.MaximumEncodedBytes +
        DirectoryCatalogForkCodec.MaximumEncodedBytes +
        512);

    internal void Validate()
    {
        if (MaximumArtifactBytes is < 1 or > AbsoluteMaximumArtifactBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(MaximumArtifactBytes));
        }

        if (MaximumHistoryEntries is < RequiredMinimumHistoryEntries or > AbsoluteMaximumHistoryEntries)
        {
            throw new ArgumentOutOfRangeException(nameof(MaximumHistoryEntries));
        }

        var requiredManifestBytes = DirectoryCatalogManifestCodec.GetMaximumEncodedBytes(
            MaximumHistoryEntries);
        if (MaximumManifestBytes < requiredManifestBytes ||
            MaximumManifestBytes > AbsoluteMaximumManifestBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(MaximumManifestBytes));
        }

        var requiredRetentionBytes = checked(
            (long)MaximumSegmentBytes * RequiredMinimumHistoryEntries);
        if (MaximumRetainedSegmentBytes < requiredRetentionBytes ||
            MaximumRetainedSegmentBytes > AbsoluteMaximumRetainedSegmentBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(MaximumRetainedSegmentBytes));
        }
    }
}

internal sealed record StoredDirectoryArtifact
{
    internal StoredDirectoryArtifact(
        DirectoryArtifactKind kind,
        ReadOnlySpan<byte> canonicalBytes,
        ReadOnlySpan<byte> artifactHash,
        ReadOnlySpan<byte> coreHash)
    {
        if (canonicalBytes.IsEmpty ||
            canonicalBytes.Length > DirectoryCatalogLimits.AbsoluteMaximumArtifactBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(canonicalBytes));
        }

        if (artifactHash.Length != DirectoryPublicationCatalog.HashBytes ||
            coreHash.Length != DirectoryPublicationCatalog.HashBytes ||
            artifactHash.IndexOfAnyExcept((byte)0) < 0 ||
            coreHash.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException("Directory artifact hashes must be 32 bytes.");
        }

        Kind = kind;
        CanonicalBytes = canonicalBytes.ToArray();
        ArtifactHash = artifactHash.ToArray();
        CoreHash = coreHash.ToArray();
    }

    internal DirectoryArtifactKind Kind { get; }
    internal byte[] CanonicalBytes { get; }
    internal byte[] ArtifactHash { get; }
    internal byte[] CoreHash { get; }
}

internal sealed record StoredDirectoryPublication
{
    internal StoredDirectoryPublication(
        ulong generation,
        ulong retentionStartedAtTrustedUnixSeconds,
        ReadOnlySpan<byte> protectedLkgFingerprint,
        IReadOnlyList<StoredDirectoryArtifact> artifacts)
    {
        if (artifacts.Count is not (3 or 5))
        {
            throw new ArgumentException(
                "A stored publication must contain three or five artifacts.",
                nameof(artifacts));
        }
        if (retentionStartedAtTrustedUnixSeconds == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(retentionStartedAtTrustedUnixSeconds));
        }
        if (protectedLkgFingerprint.Length != DirectoryPublicationCatalog.HashBytes ||
            protectedLkgFingerprint.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException(
                "A non-zero protected-LKG fingerprint is required.",
                nameof(protectedLkgFingerprint));
        }

        Generation = generation;
        RetentionStartedAtTrustedUnixSeconds = retentionStartedAtTrustedUnixSeconds;
        ProtectedLkgFingerprint = protectedLkgFingerprint.ToArray();
        Artifacts = artifacts.ToArray();
        PublicationHash = DirectoryPublicationHash.Compute(
            generation,
            retentionStartedAtTrustedUnixSeconds,
            protectedLkgFingerprint,
            Artifacts);
    }

    internal ulong Generation { get; }
    internal ulong RetentionStartedAtTrustedUnixSeconds { get; }
    internal byte[] ProtectedLkgFingerprint { get; }
    internal IReadOnlyList<StoredDirectoryArtifact> Artifacts { get; }
    internal byte[] PublicationHash { get; }
}

internal sealed record DirectoryForkEvidence(
    ulong Generation,
    byte[] FirstPublicationHash,
    byte[] SecondPublicationHash);

internal sealed class DirectoryCatalogCompactionReceipt
{
    internal DirectoryCatalogCompactionReceipt(
        ulong firstRemovedGeneration,
        ulong retainedTargetGeneration,
        DirectoryCatalogAnchor priorHead,
        ReadOnlySpan<byte> capabilityHash)
    {
        if (retainedTargetGeneration <= firstRemovedGeneration || priorHead.IsEmpty ||
            retainedTargetGeneration > priorHead.Generation)
        {
            throw new ArgumentException("The compaction receipt generation range is invalid.");
        }
        if (capabilityHash.Length != DirectoryPublicationCatalog.HashBytes ||
            capabilityHash.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException("The compaction capability hash is invalid.", nameof(capabilityHash));
        }
        FirstRemovedGeneration = firstRemovedGeneration;
        RetainedTargetGeneration = retainedTargetGeneration;
        PriorHead = priorHead;
        CapabilityHash = capabilityHash.ToArray();
    }

    internal ulong FirstRemovedGeneration { get; }
    internal ulong RetainedTargetGeneration { get; }
    internal DirectoryCatalogAnchor PriorHead { get; }
    internal byte[] CapabilityHash { get; }
}

internal sealed class DirectoryCatalogCompactionPlan
{
    internal DirectoryCatalogCompactionPlan(
        int removeCount,
        ulong retainedTargetGeneration,
        ReadOnlySpan<byte> capabilityHash)
    {
        if (removeCount is < 1 or > DirectoryCatalogLimits.MaximumCompactionSourceProofs)
        {
            throw new ArgumentOutOfRangeException(nameof(removeCount));
        }
        if (capabilityHash.Length != DirectoryPublicationCatalog.HashBytes ||
            capabilityHash.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException("The compaction capability hash is invalid.", nameof(capabilityHash));
        }
        RemoveCount = removeCount;
        RetainedTargetGeneration = retainedTargetGeneration;
        CapabilityHash = capabilityHash.ToArray();
    }

    internal int RemoveCount { get; }
    internal ulong RetainedTargetGeneration { get; }
    internal byte[] CapabilityHash { get; }
}

internal sealed record DirectoryCatalogSegmentEntry(
    ulong Generation,
    int EncodedLength,
    byte[] SegmentHash,
    byte[] PublicationHash);

internal sealed record DirectoryCatalogState(
    byte[] NetworkId,
    IReadOnlyList<DirectoryCatalogSegmentEntry> Segments,
    long TotalSegmentBytes,
    DirectoryCatalogCompactionReceipt? LastCompaction,
    DirectoryForkEvidence? ForkEvidence)
{
    internal static DirectoryCatalogState Empty(ReadOnlySpan<byte> networkId) =>
        new(networkId.ToArray(), [], 0, null, null);
}

internal readonly record struct DirectoryCatalogIoMetrics(
    long ManifestBytesRead,
    long SegmentBytesRead,
    int SegmentsRead,
    long ManifestBytesWritten,
    long SegmentBytesWritten,
    int SegmentsWritten);

internal enum DirectoryCatalogCommitStage
{
    AfterPendingRecordDurable,
    AfterSegmentDurable,
    AfterManifestDurable,
    AfterCompactionPendingDurable,
    AfterCompactionManifestDurable,
    AfterCompactionSegmentDelete
}

internal interface IDirectoryCatalogCommitObserver
{
    void OnStage(DirectoryCatalogCommitStage stage);
}
