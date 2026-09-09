using System.Buffers.Binary;
using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;

namespace Deep.Registry.Api.DirectoryPublication;

internal interface IDirectoryCatalogPersistence
{
    DirectoryCatalogState LoadAndRecover(
        ReadOnlySpan<byte> expectedNetworkId,
        DirectoryCatalogLimits limits);

    StoredDirectoryPublication ReadPublication(
        DirectoryCatalogSegmentEntry entry,
        ReadOnlySpan<byte> expectedNetworkId,
        DirectoryCatalogLimits limits);

    DirectoryCatalogState Append(
        DirectoryCatalogState current,
        StoredDirectoryPublication publication,
        ReadOnlySpan<byte> expectedNetworkId,
        DirectoryCatalogLimits limits);

    DirectoryCatalogState LatchFork(
        DirectoryCatalogState current,
        DirectoryForkEvidence evidence,
        DirectoryCatalogLimits limits);

    DirectoryCatalogState Compact(
        DirectoryCatalogState current,
        DirectoryCatalogCompactionPlan plan,
        ReadOnlySpan<byte> expectedNetworkId,
        DirectoryCatalogLimits limits);

    bool IsQuarantined { get; }
    DirectoryCatalogIoMetrics IoMetrics { get; }
    void Quarantine();
    IDisposable AcquireExclusiveLease(CancellationToken cancellationToken = default);
}

internal sealed class FileDirectoryCatalogPersistence : IDirectoryCatalogPersistence
{
    private static readonly byte[] QuarantineMarker =
        "deep.registry.directory-catalog.quarantined.v2\n"u8.ToArray();

    private readonly string manifestPath;
    private readonly string segmentDirectoryPath;
    private readonly IDirectoryCatalogCommitObserver? commitObserver;
    private long manifestBytesRead;
    private long segmentBytesRead;
    private int segmentsRead;
    private long manifestBytesWritten;
    private long segmentBytesWritten;
    private int segmentsWritten;

    internal FileDirectoryCatalogPersistence(
        string statePath,
        IDirectoryCatalogCommitObserver? commitObserver = null)
    {
        if (string.IsNullOrWhiteSpace(statePath))
        {
            throw new ArgumentException("A state path is required.", nameof(statePath));
        }

        manifestPath = Path.GetFullPath(statePath);
        segmentDirectoryPath = $"{manifestPath}.segments";
        this.commitObserver = commitObserver;
    }

    public bool IsQuarantined => File.Exists(QuarantinePath);

    public DirectoryCatalogIoMetrics IoMetrics => new(
        Interlocked.Read(ref manifestBytesRead),
        Interlocked.Read(ref segmentBytesRead),
        Volatile.Read(ref segmentsRead),
        Interlocked.Read(ref manifestBytesWritten),
        Interlocked.Read(ref segmentBytesWritten),
        Volatile.Read(ref segmentsWritten));

    public DirectoryCatalogState LoadAndRecover(
        ReadOnlySpan<byte> expectedNetworkId,
        DirectoryCatalogLimits limits)
    {
        if (IsQuarantined)
        {
            throw new InvalidDataException("The directory catalog is quarantined.");
        }

        DeleteIfExists(ManifestWritingPath);
        DeleteIfExists(CompactionPendingWritingPath);
        var state = File.Exists(manifestPath)
            ? ReadManifest(expectedNetworkId, limits)
            : DirectoryCatalogState.Empty(expectedNetworkId);

        state = RecoverPending(state, expectedNetworkId, limits);
        state = RecoverCompaction(state, expectedNetworkId, limits);
        var forkEvidence = ReadForkEvidence(state, expectedNetworkId);
        state = state with { ForkEvidence = forkEvidence };

        // The authenticated manifest binds every retained segment hash. Opening
        // validates only the head segment; older segments remain lazy and are
        // checked against their manifest entry when requested.
        if (state.Segments.Count > 0)
        {
            _ = ReadPublication(state.Segments[^1], expectedNetworkId, limits);
        }

        return state;
    }

    public StoredDirectoryPublication ReadPublication(
        DirectoryCatalogSegmentEntry entry,
        ReadOnlySpan<byte> expectedNetworkId,
        DirectoryCatalogLimits limits)
    {
        var path = GetSegmentPath(entry.Generation);
        var encoded = ReadBoundedFile(path, entry.EncodedLength, limits.MaximumSegmentBytes);
        Interlocked.Add(ref segmentBytesRead, encoded.Length);
        Interlocked.Increment(ref segmentsRead);
        return DirectoryCatalogSegmentCodec.Decode(encoded, expectedNetworkId, entry, limits);
    }

    public DirectoryCatalogState Append(
        DirectoryCatalogState current,
        StoredDirectoryPublication publication,
        ReadOnlySpan<byte> expectedNetworkId,
        DirectoryCatalogLimits limits)
    {
        var encodedSegment = DirectoryCatalogSegmentCodec.Encode(
            expectedNetworkId,
            publication,
            limits);
        var entry = new DirectoryCatalogSegmentEntry(
            publication.Generation,
            encodedSegment.Length,
            SHA256.HashData(encodedSegment),
            publication.PublicationHash.ToArray());
        var next = AppendEntry(current, entry, limits);
        var pending = new DirectoryCatalogPendingAppend(AnchorOf(current), entry);

        WriteAtomic(PendingPath, DirectoryCatalogPendingCodec.Encode(expectedNetworkId, pending));
        commitObserver?.OnStage(DirectoryCatalogCommitStage.AfterPendingRecordDurable);

        var targetPath = GetSegmentPath(entry.Generation);
        if (File.Exists(targetPath))
        {
            throw new InvalidDataException("An unreferenced directory segment already exists.");
        }

        Directory.CreateDirectory(segmentDirectoryPath);
        WriteNewSegment(targetPath, encodedSegment);
        Interlocked.Add(ref segmentBytesWritten, encodedSegment.Length);
        Interlocked.Increment(ref segmentsWritten);
        commitObserver?.OnStage(DirectoryCatalogCommitStage.AfterSegmentDurable);

        WriteManifest(next, limits);
        commitObserver?.OnStage(DirectoryCatalogCommitStage.AfterManifestDurable);
        DeleteIfExists(PendingPath);
        DeleteIfExists(PendingWritingPath);
        return next;
    }

    public DirectoryCatalogState LatchFork(
        DirectoryCatalogState current,
        DirectoryForkEvidence evidence,
        DirectoryCatalogLimits limits)
    {
        _ = limits;
        if (current.ForkEvidence is not null)
        {
            return current;
        }

        WriteAtomic(ForkPath, DirectoryCatalogForkCodec.Encode(current.NetworkId, evidence));
        return current with { ForkEvidence = evidence };
    }

    public DirectoryCatalogState Compact(
        DirectoryCatalogState current,
        DirectoryCatalogCompactionPlan plan,
        ReadOnlySpan<byte> expectedNetworkId,
        DirectoryCatalogLimits limits)
    {
        ArgumentNullException.ThrowIfNull(plan);
        if (File.Exists(PendingPath))
        {
            throw new InvalidDataException("Append and compaction journals cannot coexist.");
        }

        var first = current.Segments.FirstOrDefault() ??
            throw new InvalidDataException("An empty directory catalog cannot be compacted.");
        var pending = new DirectoryCatalogPendingCompaction(
            AnchorOf(current),
            first.Generation,
            plan.RetainedTargetGeneration,
            plan.RemoveCount,
            plan.CapabilityHash);
        WriteAtomic(
            CompactionPendingPath,
            DirectoryCatalogCompactionPendingCodec.Encode(expectedNetworkId, pending));
        commitObserver?.OnStage(DirectoryCatalogCommitStage.AfterCompactionPendingDurable);

        var next = ApplyCompaction(current, pending, limits);
        WriteManifest(next, limits);
        commitObserver?.OnStage(DirectoryCatalogCommitStage.AfterCompactionManifestDurable);

        DeleteCompactedSegments(pending, notifyObserver: true);
        DeleteIfExists(CompactionPendingPath);
        DeleteIfExists(CompactionPendingWritingPath);
        return next;
    }

    public void Quarantine()
    {
        WriteAtomic(QuarantinePath, QuarantineMarker);
    }

    public IDisposable AcquireExclusiveLease(CancellationToken cancellationToken = default)
    {
        var directory = Path.GetDirectoryName(manifestPath);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var stopwatch = Stopwatch.StartNew();
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                return new FileStream(
                    LockPath,
                    FileMode.OpenOrCreate,
                    FileAccess.ReadWrite,
                    FileShare.None,
                    bufferSize: 1,
                    FileOptions.WriteThrough);
            }
            catch (IOException exception) when (
                IsSharingViolation(exception) && stopwatch.Elapsed < TimeSpan.FromSeconds(5))
            {
                Thread.Sleep(10);
            }
        }
    }

    private DirectoryCatalogState RecoverPending(
        DirectoryCatalogState current,
        ReadOnlySpan<byte> expectedNetworkId,
        DirectoryCatalogLimits limits)
    {
        if (!File.Exists(PendingPath))
        {
            DeleteIfExists(PendingWritingPath);
            DeleteIfExists(SegmentWritingPath);
            return current;
        }

        var encodedPending = ReadBoundedFile(
            PendingPath,
            expectedLength: null,
            DirectoryCatalogPendingCodec.MaximumEncodedBytes);
        Interlocked.Add(ref manifestBytesRead, encodedPending.Length);
        var pending = DirectoryCatalogPendingCodec.Decode(encodedPending, expectedNetworkId);
        var existing = current.Segments.SingleOrDefault(
            value => value.Generation == pending.Entry.Generation);
        if (existing is not null)
        {
            if (!EntryEquals(existing, pending.Entry))
            {
                throw new InvalidDataException("Pending append conflicts with the durable manifest.");
            }

            _ = ReadPublication(existing, expectedNetworkId, limits);
            DeleteIfExists(PendingPath);
            DeleteIfExists(PendingWritingPath);
            DeleteIfExists(SegmentWritingPath);
            return current;
        }

        if (AnchorOf(current) != pending.ExpectedCurrent)
        {
            throw new InvalidDataException("Pending append has a stale durable predecessor.");
        }

        var segmentPath = GetSegmentPath(pending.Entry.Generation);
        if (!File.Exists(segmentPath))
        {
            // Crash before the immutable segment rename: no catalog mutation
            // occurred. Fixed-name staging files can be removed without a scan.
            DeleteIfExists(SegmentWritingPath);
            DeleteIfExists(PendingPath);
            DeleteIfExists(PendingWritingPath);
            return current;
        }

        _ = ReadPublication(pending.Entry, expectedNetworkId, limits);
        var recovered = AppendEntry(current, pending.Entry, limits);
        WriteManifest(recovered, limits);
        DeleteIfExists(PendingPath);
        DeleteIfExists(PendingWritingPath);
        DeleteIfExists(SegmentWritingPath);
        return recovered;
    }

    private DirectoryCatalogState RecoverCompaction(
        DirectoryCatalogState current,
        ReadOnlySpan<byte> expectedNetworkId,
        DirectoryCatalogLimits limits)
    {
        if (!File.Exists(CompactionPendingPath))
        {
            DeleteIfExists(CompactionPendingWritingPath);
            return current;
        }
        if (File.Exists(PendingPath))
        {
            throw new InvalidDataException("Append and compaction journals cannot coexist.");
        }

        var encoded = ReadBoundedFile(
            CompactionPendingPath,
            expectedLength: null,
            DirectoryCatalogCompactionPendingCodec.MaximumEncodedBytes);
        var pending = DirectoryCatalogCompactionPendingCodec.Decode(encoded, expectedNetworkId);

        if (AnchorOf(current) == pending.ExpectedCurrent &&
            current.Segments.Count > pending.RemoveCount &&
            current.Segments[0].Generation == pending.FirstRemovedGeneration &&
            current.Segments[pending.RemoveCount].Generation == pending.RetainedTargetGeneration)
        {
            // No logical deletion was committed. A capability is non-serializable,
            // so recovery rolls back this prepared transaction and requires the
            // verified caller to retry rather than trusting journal bytes as authority.
            DeleteIfExists(CompactionPendingPath);
            DeleteIfExists(CompactionPendingWritingPath);
            return current;
        }

        var receipt = current.LastCompaction;
        if (receipt is null || current.Segments.Count == 0 ||
            current.Segments[0].Generation != pending.RetainedTargetGeneration ||
            receipt.FirstRemovedGeneration != pending.FirstRemovedGeneration ||
            receipt.RetainedTargetGeneration != pending.RetainedTargetGeneration ||
            receipt.PriorHead != pending.ExpectedCurrent ||
            !CryptographicOperations.FixedTimeEquals(
                receipt.CapabilityHash,
                pending.CapabilityHash))
        {
            throw new InvalidDataException("The compaction journal does not match old or committed catalog state.");
        }

        DeleteCompactedSegments(pending, notifyObserver: false);
        DeleteIfExists(CompactionPendingPath);
        DeleteIfExists(CompactionPendingWritingPath);
        return current;
    }

    private DirectoryCatalogState ApplyCompaction(
        DirectoryCatalogState current,
        DirectoryCatalogPendingCompaction pending,
        DirectoryCatalogLimits limits)
    {
        if (pending.RemoveCount is < 1 or > DirectoryCatalogLimits.MaximumCompactionSourceProofs ||
            current.Segments.Count - pending.RemoveCount < DirectoryCatalogLimits.RequiredMinimumHistoryEntries ||
            current.Segments[0].Generation != pending.FirstRemovedGeneration ||
            current.Segments[pending.RemoveCount].Generation != pending.RetainedTargetGeneration ||
            AnchorOf(current) != pending.ExpectedCurrent)
        {
            throw new InvalidDataException("The compaction plan does not match the durable catalog.");
        }

        var retained = current.Segments.Skip(pending.RemoveCount).ToArray();
        var retainedBytes = retained.Sum(static entry => (long)entry.EncodedLength);
        if (retainedBytes > limits.MaximumRetainedSegmentBytes)
        {
            throw new InvalidDataException("The compacted segment total exceeds its hard limit.");
        }
        return new DirectoryCatalogState(
            current.NetworkId.ToArray(),
            retained,
            retainedBytes,
            new DirectoryCatalogCompactionReceipt(
                pending.FirstRemovedGeneration,
                pending.RetainedTargetGeneration,
                pending.ExpectedCurrent,
                pending.CapabilityHash),
            current.ForkEvidence);
    }

    private void DeleteCompactedSegments(
        DirectoryCatalogPendingCompaction pending,
        bool notifyObserver)
    {
        for (var index = 0; index < pending.RemoveCount; index++)
        {
            var generation = checked(pending.FirstRemovedGeneration + (ulong)index);
            DeleteIfExists(GetSegmentPath(generation));
            if (notifyObserver)
            {
                commitObserver?.OnStage(DirectoryCatalogCommitStage.AfterCompactionSegmentDelete);
            }
        }
    }

    private DirectoryCatalogState ReadManifest(
        ReadOnlySpan<byte> expectedNetworkId,
        DirectoryCatalogLimits limits)
    {
        var encoded = ReadBoundedFile(manifestPath, expectedLength: null, limits.MaximumManifestBytes);
        Interlocked.Add(ref manifestBytesRead, encoded.Length);
        return DirectoryCatalogManifestCodec.Decode(encoded, expectedNetworkId, limits);
    }

    private DirectoryForkEvidence? ReadForkEvidence(
        DirectoryCatalogState current,
        ReadOnlySpan<byte> expectedNetworkId)
    {
        if (!File.Exists(ForkPath))
        {
            DeleteIfExists(ForkWritingPath);
            return null;
        }

        var encoded = ReadBoundedFile(
            ForkPath,
            expectedLength: null,
            DirectoryCatalogForkCodec.MaximumEncodedBytes);
        Interlocked.Add(ref manifestBytesRead, encoded.Length);
        var evidence = DirectoryCatalogForkCodec.Decode(encoded, expectedNetworkId);
        var first = current.Segments.SingleOrDefault(
            value => value.Generation == evidence.Generation);
        if (first is null ||
            !CryptographicOperations.FixedTimeEquals(
                first.PublicationHash,
                evidence.FirstPublicationHash))
        {
            throw new InvalidDataException("The durable fork latch is not bound to retained history.");
        }

        return evidence;
    }

    private void WriteManifest(DirectoryCatalogState state, DirectoryCatalogLimits limits)
    {
        var encoded = DirectoryCatalogManifestCodec.Encode(state, limits);
        WriteAtomic(manifestPath, encoded);
        Interlocked.Add(ref manifestBytesWritten, encoded.Length);
    }

    private void WriteNewSegment(string targetPath, ReadOnlySpan<byte> encoded)
    {
        DeleteIfExists(SegmentWritingPath);
        using (var stream = new FileStream(
                   SegmentWritingPath,
                   FileMode.CreateNew,
                   FileAccess.Write,
                   FileShare.None,
                   bufferSize: 16 * 1024,
                   FileOptions.WriteThrough))
        {
            stream.Write(encoded);
            stream.Flush(flushToDisk: true);
        }

        File.Move(SegmentWritingPath, targetPath);
    }

    private string GetSegmentPath(ulong generation) => Path.Combine(
        segmentDirectoryPath,
        $"{generation.ToString("x16", CultureInfo.InvariantCulture)}.dps");

    private static DirectoryCatalogState AppendEntry(
        DirectoryCatalogState current,
        DirectoryCatalogSegmentEntry entry,
        DirectoryCatalogLimits limits)
    {
        if (current.Segments.Count >= limits.MaximumHistoryEntries)
        {
            throw new DirectoryCatalogException(
                DirectoryCatalogError.HistoryCapacityReached,
                "Directory publication history reached its configured hard limit.");
        }

        var prior = current.Segments.LastOrDefault();
        if (prior is not null &&
            (prior.Generation == ulong.MaxValue || entry.Generation != prior.Generation + 1))
        {
            throw new InvalidDataException("Pending directory generations are not contiguous.");
        }

        if (entry.EncodedLength <= 0 || entry.EncodedLength > limits.MaximumSegmentBytes ||
            entry.SegmentHash.Length != DirectoryPublicationCatalog.HashBytes ||
            entry.PublicationHash.Length != DirectoryPublicationCatalog.HashBytes)
        {
            throw new InvalidDataException("Pending directory segment metadata is invalid.");
        }

        var total = checked(current.TotalSegmentBytes + entry.EncodedLength);
        if (total > limits.MaximumRetainedSegmentBytes)
        {
            throw new DirectoryCatalogException(
                DirectoryCatalogError.HistoryCapacityReached,
                "Directory publication segments reached the retained-byte hard limit.");
        }

        return new DirectoryCatalogState(
            current.NetworkId.ToArray(),
            current.Segments.Append(entry).ToArray(),
            total,
            current.LastCompaction,
            current.ForkEvidence);
    }

    private static DirectoryCatalogAnchor AnchorOf(DirectoryCatalogState state)
    {
        var current = state.Segments.LastOrDefault();
        return current is null
            ? DirectoryCatalogAnchor.Empty
            : new DirectoryCatalogAnchor(current.Generation, current.PublicationHash);
    }

    private static bool EntryEquals(
        DirectoryCatalogSegmentEntry left,
        DirectoryCatalogSegmentEntry right) =>
        left.Generation == right.Generation &&
        left.EncodedLength == right.EncodedLength &&
        CryptographicOperations.FixedTimeEquals(left.SegmentHash, right.SegmentHash) &&
        CryptographicOperations.FixedTimeEquals(left.PublicationHash, right.PublicationHash);

    private static byte[] ReadBoundedFile(string path, int? expectedLength, int maximumLength)
    {
        using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 16 * 1024,
            FileOptions.SequentialScan);
        if (stream.Length <= 0 || stream.Length > maximumLength || stream.Length > int.MaxValue ||
            (expectedLength.HasValue && stream.Length != expectedLength.Value))
        {
            throw new InvalidDataException("A persisted directory catalog file has an invalid length.");
        }

        var bytes = GC.AllocateUninitializedArray<byte>(checked((int)stream.Length));
        stream.ReadExactly(bytes);
        return bytes;
    }

    private static bool IsSharingViolation(IOException exception) =>
        (exception.HResult & 0xffff) is 11 or 32 or 33;

    private static void WriteAtomic(string path, ReadOnlySpan<byte> bytes)
    {
        var directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var temporaryPath = $"{path}.writing";
        DeleteIfExists(temporaryPath);
        try
        {
            using (var stream = new FileStream(
                       temporaryPath,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       bufferSize: 16 * 1024,
                       FileOptions.WriteThrough))
            {
                stream.Write(bytes);
                stream.Flush(flushToDisk: true);
            }

            if (File.Exists(path))
            {
                File.Replace(temporaryPath, path, null);
            }
            else
            {
                File.Move(temporaryPath, path);
            }
        }
        finally
        {
            DeleteIfExists(temporaryPath);
        }
    }

    private static void DeleteIfExists(string path)
    {
        if (File.Exists(path))
        {
            File.Delete(path);
        }
    }

    private string PendingPath => $"{manifestPath}.pending";
    private string PendingWritingPath => $"{PendingPath}.writing";
    private string SegmentWritingPath => $"{manifestPath}.segment.writing";
    private string ManifestWritingPath => $"{manifestPath}.writing";
    private string ForkPath => $"{manifestPath}.fork";
    private string ForkWritingPath => $"{ForkPath}.writing";
    private string QuarantinePath => $"{manifestPath}.quarantine";
    private string CompactionPendingPath => $"{manifestPath}.compaction.pending";
    private string CompactionPendingWritingPath => $"{CompactionPendingPath}.writing";
    private string LockPath => $"{manifestPath}.lock";
}

internal static class DirectoryPublicationHash
{
    private static readonly byte[] Domain =
        "Deep/Registry/DirectoryCatalog/V3/publication"u8.ToArray();

    internal static byte[] Compute(
        ulong generation,
        ulong retentionStartedAtTrustedUnixSeconds,
        ReadOnlySpan<byte> protectedLkgFingerprint,
        IReadOnlyList<StoredDirectoryArtifact> artifacts)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(Domain);
        Span<byte> scalar = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(scalar, generation);
        hash.AppendData(scalar);
        BinaryPrimitives.WriteUInt64BigEndian(scalar, retentionStartedAtTrustedUnixSeconds);
        hash.AppendData(scalar);
        hash.AppendData(protectedLkgFingerprint);
        hash.AppendData([(byte)artifacts.Count]);
        foreach (var artifact in artifacts)
        {
            hash.AppendData([(byte)artifact.Kind]);
            BinaryPrimitives.WriteUInt64BigEndian(
                scalar,
                checked((ulong)artifact.CanonicalBytes.Length));
            hash.AppendData(scalar);
            hash.AppendData(artifact.ArtifactHash);
            hash.AppendData(artifact.CoreHash);
        }

        return hash.GetHashAndReset();
    }
}

internal static class DirectoryCatalogSegmentCodec
{
    private static readonly byte[] Magic = "DRCSEG3\0"u8.ToArray();
    private static readonly byte[] IntegrityDomain =
        "Deep/Registry/DirectoryCatalog/V3/segment-integrity"u8.ToArray();
    private const ushort SchemaVersion = 3;
    private const int IntegrityBytes = 32;

    internal static int GetMaximumEncodedBytes(int maximumArtifactBytes, int maximumArtifacts) =>
        checked(8 + 2 + DirectoryPublicationCatalog.NetworkIdBytes + 8 + 8 + 32 + 1 +
            (maximumArtifacts * (1 + 4 + 32 + 32 + maximumArtifactBytes)) +
            DirectoryPublicationCatalog.HashBytes + IntegrityBytes);

    internal static byte[] Encode(
        ReadOnlySpan<byte> networkId,
        StoredDirectoryPublication publication,
        DirectoryCatalogLimits limits)
    {
        using var stream = new MemoryStream(capacity: Math.Min(limits.MaximumSegmentBytes, 64 * 1024));
        stream.Write(Magic);
        BinaryCodec.WriteUInt16(stream, SchemaVersion);
        stream.Write(networkId);
        BinaryCodec.WriteUInt64(stream, publication.Generation);
        BinaryCodec.WriteUInt64(stream, publication.RetentionStartedAtTrustedUnixSeconds);
        stream.Write(publication.ProtectedLkgFingerprint);
        stream.WriteByte(checked((byte)publication.Artifacts.Count));
        foreach (var artifact in publication.Artifacts)
        {
            if (artifact.CanonicalBytes.Length > limits.MaximumArtifactBytes)
            {
                throw new DirectoryCatalogException(
                    DirectoryCatalogError.BoundsExceeded,
                    "A verified directory artifact exceeds the configured byte limit.");
            }

            stream.WriteByte((byte)artifact.Kind);
            BinaryCodec.WriteUInt32(stream, checked((uint)artifact.CanonicalBytes.Length));
            stream.Write(artifact.ArtifactHash);
            stream.Write(artifact.CoreHash);
            stream.Write(artifact.CanonicalBytes);
        }

        stream.Write(publication.PublicationHash);
        if (stream.Length + IntegrityBytes > limits.MaximumSegmentBytes)
        {
            throw new DirectoryCatalogException(
                DirectoryCatalogError.BoundsExceeded,
                "A directory publication segment exceeds its hard limit.");
        }

        var body = stream.ToArray();
        stream.Write(BinaryCodec.Hash(IntegrityDomain, body));
        return stream.ToArray();
    }

    internal static StoredDirectoryPublication Decode(
        ReadOnlySpan<byte> encoded,
        ReadOnlySpan<byte> expectedNetworkId,
        DirectoryCatalogSegmentEntry expectedEntry,
        DirectoryCatalogLimits limits)
    {
        if (encoded.Length != expectedEntry.EncodedLength ||
            encoded.Length > limits.MaximumSegmentBytes ||
            !CryptographicOperations.FixedTimeEquals(
                SHA256.HashData(encoded),
                expectedEntry.SegmentHash))
        {
            throw new InvalidDataException("Directory segment hash or length is invalid.");
        }

        var body = encoded[..^IntegrityBytes];
        if (!CryptographicOperations.FixedTimeEquals(
                encoded[^IntegrityBytes..],
                BinaryCodec.Hash(IntegrityDomain, body)))
        {
            throw new InvalidDataException("Directory segment integrity hash is invalid.");
        }

        var reader = new BinarySpanReader(body);
        reader.RequireBytes(Magic);
        if (reader.ReadUInt16() != SchemaVersion)
        {
            throw new InvalidDataException("Directory segment schema is unsupported.");
        }

        reader.RequireBytes(expectedNetworkId);
        var generation = reader.ReadUInt64();
        if (generation != expectedEntry.Generation)
        {
            throw new InvalidDataException("Directory segment generation is invalid.");
        }

        var retentionStartedAt = reader.ReadUInt64();
        if (retentionStartedAt == 0)
        {
            throw new InvalidDataException("Directory segment trusted retention origin is invalid.");
        }
        var protectedLkgFingerprint = reader.ReadBytes(DirectoryPublicationCatalog.HashBytes);
        if (protectedLkgFingerprint.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new InvalidDataException("Directory segment protected-LKG fingerprint is invalid.");
        }

        var artifactCount = reader.ReadByte();
        if (artifactCount is not (3 or 5))
        {
            throw new InvalidDataException("Directory segment closure cardinality is invalid.");
        }

        var artifacts = new StoredDirectoryArtifact[artifactCount];
        for (var index = 0; index < artifacts.Length; index++)
        {
            var kind = (DirectoryArtifactKind)reader.ReadByte();
            if (kind != (DirectoryArtifactKind)(index + 1))
            {
                throw new InvalidDataException("Directory segment artifact order is invalid.");
            }

            var length = reader.ReadUInt32();
            if (length is 0 || length > limits.MaximumArtifactBytes || length > int.MaxValue)
            {
                throw new InvalidDataException("Directory segment artifact length is invalid.");
            }

            var artifactHash = reader.ReadBytes(DirectoryPublicationCatalog.HashBytes);
            var coreHash = reader.ReadBytes(DirectoryPublicationCatalog.HashBytes);
            var canonical = reader.ReadBytes(checked((int)length));
            if (coreHash.IndexOfAnyExcept((byte)0) < 0 ||
                !CryptographicOperations.FixedTimeEquals(
                    artifactHash,
                    SHA256.HashData(canonical)))
            {
                throw new InvalidDataException("Directory segment artifact hash is invalid.");
            }

            artifacts[index] = new StoredDirectoryArtifact(
                kind,
                canonical,
                artifactHash,
                coreHash);
        }

        var storedPublicationHash = reader.ReadBytes(DirectoryPublicationCatalog.HashBytes);
        reader.EnsureComplete();
        var publication = new StoredDirectoryPublication(
            generation,
            retentionStartedAt,
            protectedLkgFingerprint,
            artifacts);
        if (!CryptographicOperations.FixedTimeEquals(
                storedPublicationHash,
                publication.PublicationHash) ||
            !CryptographicOperations.FixedTimeEquals(
                storedPublicationHash,
                expectedEntry.PublicationHash))
        {
            throw new InvalidDataException("Directory segment publication hash is invalid.");
        }

        return publication;
    }
}

internal static class DirectoryCatalogManifestCodec
{
    private static readonly byte[] Magic = "DRCMAN3\0"u8.ToArray();
    private static readonly byte[] IntegrityDomain =
        "Deep/Registry/DirectoryCatalog/V3/manifest-head-integrity"u8.ToArray();
    private const ushort SchemaVersion = 3;
    private const int EntryBytes = 8 + 4 + 32 + 32;
    private const int CompactionReceiptBytes = 1 + 8 + 8 + 8 + 32 + 32;
    private const int FixedBodyBytes =
        8 + 2 + 16 + 2 + 8 + 1 + 8 + 32 + 32 + CompactionReceiptBytes;
    private const int IntegrityBytes = 32;

    internal static int GetMaximumEncodedBytes(int maximumHistoryEntries) =>
        checked(FixedBodyBytes + (maximumHistoryEntries * EntryBytes) + IntegrityBytes);

    internal static byte[] Encode(DirectoryCatalogState state, DirectoryCatalogLimits limits)
    {
        if (state.Segments.Count > limits.MaximumHistoryEntries)
        {
            throw new DirectoryCatalogException(
                DirectoryCatalogError.HistoryCapacityReached,
                "Directory manifest history exceeds its hard limit.");
        }

        using var stream = new MemoryStream(GetMaximumEncodedBytes(state.Segments.Count));
        stream.Write(Magic);
        BinaryCodec.WriteUInt16(stream, SchemaVersion);
        stream.Write(state.NetworkId);
        BinaryCodec.WriteUInt16(stream, checked((ushort)state.Segments.Count));
        BinaryCodec.WriteUInt64(stream, checked((ulong)state.TotalSegmentBytes));
        var head = state.Segments.LastOrDefault();
        stream.WriteByte(head is null ? (byte)0 : (byte)1);
        BinaryCodec.WriteUInt64(stream, head?.Generation ?? 0);
        stream.Write(head?.PublicationHash ?? new byte[32]);
        stream.Write(head?.SegmentHash ?? new byte[32]);
        var receipt = state.LastCompaction;
        stream.WriteByte(receipt is null ? (byte)0 : (byte)1);
        BinaryCodec.WriteUInt64(stream, receipt?.FirstRemovedGeneration ?? 0);
        BinaryCodec.WriteUInt64(stream, receipt?.RetainedTargetGeneration ?? 0);
        BinaryCodec.WriteUInt64(stream, receipt?.PriorHead.Generation ?? 0);
        stream.Write(receipt?.PriorHead.PublicationHash.ToArray() ?? new byte[32]);
        stream.Write(receipt?.CapabilityHash ?? new byte[32]);
        foreach (var entry in state.Segments)
        {
            BinaryCodec.WriteUInt64(stream, entry.Generation);
            BinaryCodec.WriteUInt32(stream, checked((uint)entry.EncodedLength));
            stream.Write(entry.SegmentHash);
            stream.Write(entry.PublicationHash);
        }

        var body = stream.ToArray();
        stream.Write(BinaryCodec.Hash(IntegrityDomain, body));
        if (stream.Length > limits.MaximumManifestBytes)
        {
            throw new DirectoryCatalogException(
                DirectoryCatalogError.BoundsExceeded,
                "Directory manifest exceeds its hard limit.");
        }

        return stream.ToArray();
    }

    internal static DirectoryCatalogState Decode(
        ReadOnlySpan<byte> encoded,
        ReadOnlySpan<byte> expectedNetworkId,
        DirectoryCatalogLimits limits)
    {
        if (encoded.Length < FixedBodyBytes + IntegrityBytes ||
            encoded.Length > limits.MaximumManifestBytes)
        {
            throw new InvalidDataException("Directory manifest length is invalid.");
        }

        var body = encoded[..^IntegrityBytes];
        if (!CryptographicOperations.FixedTimeEquals(
                encoded[^IntegrityBytes..],
                BinaryCodec.Hash(IntegrityDomain, body)))
        {
            throw new InvalidDataException("Directory manifest integrity hash is invalid.");
        }

        var reader = new BinarySpanReader(body);
        reader.RequireBytes(Magic);
        if (reader.ReadUInt16() != SchemaVersion)
        {
            throw new InvalidDataException("Directory manifest schema is unsupported.");
        }

        reader.RequireBytes(expectedNetworkId);
        var count = reader.ReadUInt16();
        if (count > limits.MaximumHistoryEntries)
        {
            throw new InvalidDataException("Directory manifest history exceeds its hard limit.");
        }

        var storedTotal = reader.ReadUInt64();
        if (storedTotal > (ulong)limits.MaximumRetainedSegmentBytes)
        {
            throw new InvalidDataException("Directory manifest retained-byte total is invalid.");
        }

        var headFlag = reader.ReadByte();
        if (headFlag > 1 || (count == 0) != (headFlag == 0))
        {
            throw new InvalidDataException("Directory manifest head flag is invalid.");
        }

        var headGeneration = reader.ReadUInt64();
        var headPublicationHash = reader.ReadBytes(32);
        var headSegmentHash = reader.ReadBytes(32);
        var receiptFlag = reader.ReadByte();
        var firstRemovedGeneration = reader.ReadUInt64();
        var retainedTargetGeneration = reader.ReadUInt64();
        var priorHeadGeneration = reader.ReadUInt64();
        var priorHeadPublicationHash = reader.ReadBytes(32);
        var capabilityHash = reader.ReadBytes(32);
        if (receiptFlag > 1)
        {
            throw new InvalidDataException("Directory manifest compaction-receipt flag is invalid.");
        }
        DirectoryCatalogCompactionReceipt? receipt = null;
        if (receiptFlag == 0)
        {
            if (firstRemovedGeneration != 0 || retainedTargetGeneration != 0 ||
                priorHeadGeneration != 0 || !BinaryCodec.IsZero(priorHeadPublicationHash) ||
                !BinaryCodec.IsZero(capabilityHash))
            {
                throw new InvalidDataException("Directory manifest has non-canonical empty compaction state.");
            }
        }
        else
        {
            try
            {
                receipt = new DirectoryCatalogCompactionReceipt(
                    firstRemovedGeneration,
                    retainedTargetGeneration,
                    new DirectoryCatalogAnchor(priorHeadGeneration, priorHeadPublicationHash),
                    capabilityHash);
            }
            catch (ArgumentException exception)
            {
                throw new InvalidDataException("Directory manifest compaction receipt is invalid.", exception);
            }
        }
        var entries = new DirectoryCatalogSegmentEntry[count];
        long computedTotal = 0;
        ulong previousGeneration = 0;
        for (var index = 0; index < entries.Length; index++)
        {
            var generation = reader.ReadUInt64();
            if (index > 0 &&
                (previousGeneration == ulong.MaxValue || generation != previousGeneration + 1))
            {
                throw new InvalidDataException("Directory manifest generations are not contiguous.");
            }

            previousGeneration = generation;
            var encodedLength = reader.ReadUInt32();
            if (encodedLength is 0 || encodedLength > limits.MaximumSegmentBytes || encodedLength > int.MaxValue)
            {
                throw new InvalidDataException("Directory manifest segment length is invalid.");
            }

            var segmentHash = reader.ReadBytes(32).ToArray();
            var publicationHash = reader.ReadBytes(32).ToArray();
            computedTotal = checked(computedTotal + encodedLength);
            entries[index] = new DirectoryCatalogSegmentEntry(
                generation,
                checked((int)encodedLength),
                segmentHash,
                publicationHash);
        }

        reader.EnsureComplete();
        if ((ulong)computedTotal != storedTotal || computedTotal > limits.MaximumRetainedSegmentBytes)
        {
            throw new InvalidDataException("Directory manifest retained-byte total does not match its entries.");
        }

        var head = entries.LastOrDefault();
        if (head is null)
        {
            if (headGeneration != 0 || !BinaryCodec.IsZero(headPublicationHash) ||
                !BinaryCodec.IsZero(headSegmentHash))
            {
                throw new InvalidDataException("Empty directory manifest has a non-empty head.");
            }
        }
        else if (headGeneration != head.Generation ||
            !CryptographicOperations.FixedTimeEquals(headPublicationHash, head.PublicationHash) ||
            !CryptographicOperations.FixedTimeEquals(headSegmentHash, head.SegmentHash))
        {
            throw new InvalidDataException("Directory manifest head is not bound to its final segment.");
        }

        if (receipt is not null)
        {
            if (entries.Length == 0 || entries[0].Generation != receipt.RetainedTargetGeneration)
            {
                throw new InvalidDataException("Directory manifest compaction target is not the first retained generation.");
            }
            var priorHead = entries.SingleOrDefault(entry => entry.Generation == receipt.PriorHead.Generation);
            if (priorHead is null || !CryptographicOperations.FixedTimeEquals(
                    priorHead.PublicationHash,
                    receipt.PriorHead.PublicationHash.Span))
            {
                throw new InvalidDataException("Directory manifest compaction receipt is not bound to its prior head.");
            }
        }

        return new DirectoryCatalogState(
            expectedNetworkId.ToArray(),
            entries,
            computedTotal,
            receipt,
            null);
    }
}

internal sealed record DirectoryCatalogPendingAppend(
    DirectoryCatalogAnchor ExpectedCurrent,
    DirectoryCatalogSegmentEntry Entry);

internal static class DirectoryCatalogPendingCodec
{
    private static readonly byte[] Magic = "DRCPEN2\0"u8.ToArray();
    private static readonly byte[] IntegrityDomain =
        "Deep/Registry/DirectoryCatalog/V2/pending-integrity"u8.ToArray();
    private const ushort SchemaVersion = 2;
    internal const int MaximumEncodedBytes = 8 + 2 + 16 + 1 + 8 + 32 + 8 + 4 + 32 + 32 + 32;

    internal static byte[] Encode(
        ReadOnlySpan<byte> networkId,
        DirectoryCatalogPendingAppend pending)
    {
        using var stream = new MemoryStream(MaximumEncodedBytes);
        stream.Write(Magic);
        BinaryCodec.WriteUInt16(stream, SchemaVersion);
        stream.Write(networkId);
        stream.WriteByte(pending.ExpectedCurrent.IsEmpty ? (byte)0 : (byte)1);
        BinaryCodec.WriteUInt64(stream, pending.ExpectedCurrent.Generation);
        stream.Write(pending.ExpectedCurrent.IsEmpty
            ? new byte[32]
            : pending.ExpectedCurrent.PublicationHash.Span);
        WriteEntry(stream, pending.Entry);
        var body = stream.ToArray();
        stream.Write(BinaryCodec.Hash(IntegrityDomain, body));
        return stream.ToArray();
    }

    internal static DirectoryCatalogPendingAppend Decode(
        ReadOnlySpan<byte> encoded,
        ReadOnlySpan<byte> expectedNetworkId)
    {
        if (encoded.Length != MaximumEncodedBytes)
        {
            throw new InvalidDataException("Directory pending record length is invalid.");
        }

        var body = encoded[..^32];
        if (!CryptographicOperations.FixedTimeEquals(
                encoded[^32..],
                BinaryCodec.Hash(IntegrityDomain, body)))
        {
            throw new InvalidDataException("Directory pending record integrity is invalid.");
        }

        var reader = new BinarySpanReader(body);
        reader.RequireBytes(Magic);
        if (reader.ReadUInt16() != SchemaVersion)
        {
            throw new InvalidDataException("Directory pending schema is unsupported.");
        }

        reader.RequireBytes(expectedNetworkId);
        var anchorFlag = reader.ReadByte();
        if (anchorFlag > 1)
        {
            throw new InvalidDataException("Directory pending anchor flag is invalid.");
        }

        var anchorGeneration = reader.ReadUInt64();
        var anchorHash = reader.ReadBytes(32);
        var anchor = anchorFlag == 0
            ? DirectoryCatalogAnchor.Empty
            : new DirectoryCatalogAnchor(anchorGeneration, anchorHash);
        if (anchorFlag == 0 && (anchorGeneration != 0 || !BinaryCodec.IsZero(anchorHash)))
        {
            throw new InvalidDataException("Empty directory pending anchor is non-canonical.");
        }

        var entry = ReadEntry(ref reader);
        reader.EnsureComplete();
        return new DirectoryCatalogPendingAppend(anchor, entry);
    }

    private static void WriteEntry(Stream stream, DirectoryCatalogSegmentEntry entry)
    {
        BinaryCodec.WriteUInt64(stream, entry.Generation);
        BinaryCodec.WriteUInt32(stream, checked((uint)entry.EncodedLength));
        stream.Write(entry.SegmentHash);
        stream.Write(entry.PublicationHash);
    }

    private static DirectoryCatalogSegmentEntry ReadEntry(ref BinarySpanReader reader)
    {
        var generation = reader.ReadUInt64();
        var length = reader.ReadUInt32();
        if (length is 0 or > int.MaxValue)
        {
            throw new InvalidDataException("Directory pending segment length is invalid.");
        }

        return new DirectoryCatalogSegmentEntry(
            generation,
            checked((int)length),
            reader.ReadBytes(32).ToArray(),
            reader.ReadBytes(32).ToArray());
    }
}

internal sealed class DirectoryCatalogPendingCompaction
{
    internal DirectoryCatalogPendingCompaction(
        DirectoryCatalogAnchor expectedCurrent,
        ulong firstRemovedGeneration,
        ulong retainedTargetGeneration,
        int removeCount,
        ReadOnlySpan<byte> capabilityHash)
    {
        if (expectedCurrent.IsEmpty || removeCount is < 1 or > DirectoryCatalogLimits.MaximumCompactionSourceProofs ||
            firstRemovedGeneration > ulong.MaxValue - (ulong)removeCount ||
            retainedTargetGeneration != firstRemovedGeneration + (ulong)removeCount)
        {
            throw new ArgumentException("The pending compaction range is invalid.");
        }
        if (capabilityHash.Length != DirectoryPublicationCatalog.HashBytes ||
            capabilityHash.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException("The pending compaction capability hash is invalid.", nameof(capabilityHash));
        }
        ExpectedCurrent = expectedCurrent;
        FirstRemovedGeneration = firstRemovedGeneration;
        RetainedTargetGeneration = retainedTargetGeneration;
        RemoveCount = removeCount;
        CapabilityHash = capabilityHash.ToArray();
    }

    internal DirectoryCatalogAnchor ExpectedCurrent { get; }
    internal ulong FirstRemovedGeneration { get; }
    internal ulong RetainedTargetGeneration { get; }
    internal int RemoveCount { get; }
    internal byte[] CapabilityHash { get; }
}

internal static class DirectoryCatalogCompactionPendingCodec
{
    private static readonly byte[] Magic = "DRCCMP1\0"u8.ToArray();
    private static readonly byte[] IntegrityDomain =
        "Deep/Registry/DirectoryCatalog/V1/compaction-pending-integrity"u8.ToArray();
    private const ushort SchemaVersion = 1;
    internal const int MaximumEncodedBytes = 8 + 2 + 16 + 8 + 32 + 8 + 8 + 2 + 32 + 32;

    internal static byte[] Encode(
        ReadOnlySpan<byte> networkId,
        DirectoryCatalogPendingCompaction pending)
    {
        using var stream = new MemoryStream(MaximumEncodedBytes);
        stream.Write(Magic);
        BinaryCodec.WriteUInt16(stream, SchemaVersion);
        stream.Write(networkId);
        BinaryCodec.WriteUInt64(stream, pending.ExpectedCurrent.Generation);
        stream.Write(pending.ExpectedCurrent.PublicationHash.Span);
        BinaryCodec.WriteUInt64(stream, pending.FirstRemovedGeneration);
        BinaryCodec.WriteUInt64(stream, pending.RetainedTargetGeneration);
        BinaryCodec.WriteUInt16(stream, checked((ushort)pending.RemoveCount));
        stream.Write(pending.CapabilityHash);
        var body = stream.ToArray();
        stream.Write(BinaryCodec.Hash(IntegrityDomain, body));
        return stream.ToArray();
    }

    internal static DirectoryCatalogPendingCompaction Decode(
        ReadOnlySpan<byte> encoded,
        ReadOnlySpan<byte> expectedNetworkId)
    {
        if (encoded.Length != MaximumEncodedBytes)
        {
            throw new InvalidDataException("Directory compaction journal length is invalid.");
        }
        var body = encoded[..^32];
        if (!CryptographicOperations.FixedTimeEquals(
                encoded[^32..],
                BinaryCodec.Hash(IntegrityDomain, body)))
        {
            throw new InvalidDataException("Directory compaction journal integrity is invalid.");
        }
        var reader = new BinarySpanReader(body);
        reader.RequireBytes(Magic);
        if (reader.ReadUInt16() != SchemaVersion)
        {
            throw new InvalidDataException("Directory compaction journal schema is unsupported.");
        }
        reader.RequireBytes(expectedNetworkId);
        try
        {
            var pending = new DirectoryCatalogPendingCompaction(
                new DirectoryCatalogAnchor(reader.ReadUInt64(), reader.ReadBytes(32)),
                reader.ReadUInt64(),
                reader.ReadUInt64(),
                reader.ReadUInt16(),
                reader.ReadBytes(32));
            reader.EnsureComplete();
            return pending;
        }
        catch (ArgumentException exception)
        {
            throw new InvalidDataException("Directory compaction journal values are invalid.", exception);
        }
    }
}

internal static class DirectoryCatalogForkCodec
{
    private static readonly byte[] Magic = "DRCFOR2\0"u8.ToArray();
    private static readonly byte[] IntegrityDomain =
        "Deep/Registry/DirectoryCatalog/V2/fork-integrity"u8.ToArray();
    private const ushort SchemaVersion = 2;
    internal const int MaximumEncodedBytes = 8 + 2 + 16 + 8 + 32 + 32 + 32;

    internal static byte[] Encode(
        ReadOnlySpan<byte> networkId,
        DirectoryForkEvidence evidence)
    {
        using var stream = new MemoryStream(MaximumEncodedBytes);
        stream.Write(Magic);
        BinaryCodec.WriteUInt16(stream, SchemaVersion);
        stream.Write(networkId);
        BinaryCodec.WriteUInt64(stream, evidence.Generation);
        stream.Write(evidence.FirstPublicationHash);
        stream.Write(evidence.SecondPublicationHash);
        var body = stream.ToArray();
        stream.Write(BinaryCodec.Hash(IntegrityDomain, body));
        return stream.ToArray();
    }

    internal static DirectoryForkEvidence Decode(
        ReadOnlySpan<byte> encoded,
        ReadOnlySpan<byte> expectedNetworkId)
    {
        if (encoded.Length != MaximumEncodedBytes)
        {
            throw new InvalidDataException("Directory fork record length is invalid.");
        }

        var body = encoded[..^32];
        if (!CryptographicOperations.FixedTimeEquals(
                encoded[^32..],
                BinaryCodec.Hash(IntegrityDomain, body)))
        {
            throw new InvalidDataException("Directory fork record integrity is invalid.");
        }

        var reader = new BinarySpanReader(body);
        reader.RequireBytes(Magic);
        if (reader.ReadUInt16() != SchemaVersion)
        {
            throw new InvalidDataException("Directory fork schema is unsupported.");
        }

        reader.RequireBytes(expectedNetworkId);
        var evidence = new DirectoryForkEvidence(
            reader.ReadUInt64(),
            reader.ReadBytes(32).ToArray(),
            reader.ReadBytes(32).ToArray());
        reader.EnsureComplete();
        return evidence;
    }
}

internal static class BinaryCodec
{
    internal static void WriteUInt16(Stream stream, ushort value)
    {
        Span<byte> bytes = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(bytes, value);
        stream.Write(bytes);
    }

    internal static void WriteUInt32(Stream stream, uint value)
    {
        Span<byte> bytes = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, value);
        stream.Write(bytes);
    }

    internal static void WriteUInt64(Stream stream, ulong value)
    {
        Span<byte> bytes = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(bytes, value);
        stream.Write(bytes);
    }

    internal static byte[] Hash(ReadOnlySpan<byte> domain, ReadOnlySpan<byte> body)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(domain);
        hash.AppendData(body);
        return hash.GetHashAndReset();
    }

    internal static bool IsZero(ReadOnlySpan<byte> value)
    {
        var aggregate = 0;
        foreach (var item in value)
        {
            aggregate |= item;
        }

        return aggregate == 0;
    }
}

internal ref struct BinarySpanReader
{
    private readonly ReadOnlySpan<byte> bytes;
    private int offset;

    internal BinarySpanReader(ReadOnlySpan<byte> bytes)
    {
        this.bytes = bytes;
        offset = 0;
    }

    internal byte ReadByte() => ReadBytes(1)[0];
    internal ushort ReadUInt16() => BinaryPrimitives.ReadUInt16BigEndian(ReadBytes(2));
    internal uint ReadUInt32() => BinaryPrimitives.ReadUInt32BigEndian(ReadBytes(4));
    internal ulong ReadUInt64() => BinaryPrimitives.ReadUInt64BigEndian(ReadBytes(8));

    internal ReadOnlySpan<byte> ReadBytes(int count)
    {
        if (count < 0 || count > bytes.Length - offset)
        {
            throw new InvalidDataException("Persisted directory catalog data is truncated.");
        }

        var value = bytes.Slice(offset, count);
        offset += count;
        return value;
    }

    internal void RequireBytes(ReadOnlySpan<byte> expected)
    {
        if (!ReadBytes(expected.Length).SequenceEqual(expected))
        {
            throw new InvalidDataException("Persisted directory catalog magic/network is invalid.");
        }
    }

    internal void EnsureComplete()
    {
        if (offset != bytes.Length)
        {
            throw new InvalidDataException("Persisted directory catalog data has trailing bytes.");
        }
    }
}
