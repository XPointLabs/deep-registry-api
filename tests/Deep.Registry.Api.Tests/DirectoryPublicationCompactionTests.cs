#if DEEP_DIRECTORY_COMPACTION_TEST_SEAM
using System.Buffers.Binary;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using Deep.Registry.Api.DirectoryPublication;

namespace Deep.Registry.Api.Tests;

public sealed class DirectoryPublicationCompactionTests
{
    private const ulong Origin = 1_700_000_000;

    [Fact]
    public void Compaction_authority_has_no_public_constructor_or_factory()
    {
        var type = typeof(DirectoryCatalogCompactionCapability);

        Assert.Empty(type.GetConstructors(BindingFlags.Public | BindingFlags.Instance));
        Assert.DoesNotContain(
            type.GetMethods(BindingFlags.Public | BindingFlags.Static),
            method => method.ReturnType == type);
    }

    [Fact]
    public async Task Compaction_requires_400_days_for_every_removed_generation_and_retains_2048()
    {
        using var directory = new TemporaryDirectory();
        var network = Bytes(1, 16);
        var seeded = Seed(directory, network, 2_050, generation =>
            generation == 1 ? Origin + 10 : Origin);
        var catalog = Open(directory, network);

        var premature = Capability(
            network, seeded, targetGeneration: 2,
            Origin + 10 + DirectoryCatalogLimits.RequiredRetentionSeconds - 1);
        var exception = await Assert.ThrowsAsync<DirectoryCatalogException>(() =>
            catalog.CompactAsync(premature).AsTask());
        Assert.Equal(DirectoryCatalogError.CompactionPremature, exception.Error);
        Assert.Equal(2_050, catalog.HistoryCount);

        var mature = Capability(
            network, seeded, targetGeneration: 2,
            Origin + 10 + DirectoryCatalogLimits.RequiredRetentionSeconds);
        var result = await catalog.CompactAsync(mature);
        Assert.Equal(DirectoryCatalogCompactionStatus.Compacted, result.Status);
        Assert.Equal((ulong)2, result.FirstRetainedGeneration);
        Assert.Equal(2_048, result.RetainedGenerationCount);
        Assert.Null(catalog.Get(1));
        Assert.NotNull(catalog.Get(2));
    }

    [Fact]
    public async Task Capability_rejects_missing_source_proof_and_catalog_rejects_reused_common_proof()
    {
        using var directory = new TemporaryDirectory();
        var network = Bytes(2, 16);
        var seeded = Seed(directory, network, 2_050);

        Assert.Throws<ArgumentException>(() =>
            DirectoryCatalogCompactionCapability.CreateForTests(
                network,
                MatureNow,
                2,
                seeded[2].Fingerprint,
                [Source(seeded[0])]));

        var sharedProof = Hash("shared-proof", 0);
        var capability = DirectoryCatalogCompactionCapability.CreateForTests(
            network,
            MatureNow,
            2,
            seeded[2].Fingerprint,
            [
                new DirectoryCatalogCompactionSource(0, seeded[0].Fingerprint, sharedProof),
                new DirectoryCatalogCompactionSource(1, seeded[1].Fingerprint, sharedProof)
            ]);
        var exception = await Assert.ThrowsAsync<DirectoryCatalogException>(() =>
            Open(directory, network).CompactAsync(capability).AsTask());
        Assert.Equal(DirectoryCatalogError.CompactionCoverageMismatch, exception.Error);
    }

    [Fact]
    public async Task Wrong_network_source_root_or_retained_target_fail_closed_without_deletion()
    {
        using var directory = new TemporaryDirectory();
        var network = Bytes(3, 16);
        var seeded = Seed(directory, network, 2_049);
        var catalog = Open(directory, network);

        var wrongNetwork = Capability(Bytes(4, 16), seeded, 1, MatureNow);
        Assert.Equal(DirectoryCatalogError.CompactionNotAuthorized,
            (await Assert.ThrowsAsync<DirectoryCatalogException>(() =>
                catalog.CompactAsync(wrongNetwork).AsTask())).Error);

        var wrongSource = DirectoryCatalogCompactionCapability.CreateForTests(
            network, MatureNow, 1, seeded[1].Fingerprint,
            [new DirectoryCatalogCompactionSource(0, Hash("wrong-root", 0), Hash("proof", 0))]);
        Assert.Equal(DirectoryCatalogError.CompactionCoverageMismatch,
            (await Assert.ThrowsAsync<DirectoryCatalogException>(() =>
                catalog.CompactAsync(wrongSource).AsTask())).Error);

        var wrongTarget = DirectoryCatalogCompactionCapability.CreateForTests(
            network, MatureNow, 1, Hash("wrong-target", 0), [Source(seeded[0])]);
        Assert.Equal(DirectoryCatalogError.CompactionTargetMismatch,
            (await Assert.ThrowsAsync<DirectoryCatalogException>(() =>
                catalog.CompactAsync(wrongTarget).AsTask())).Error);
        Assert.Equal(2_049, catalog.HistoryCount);
    }

    [Fact]
    public async Task Two_process_instances_serialize_one_compaction_and_exact_replay()
    {
        using var directory = new TemporaryDirectory();
        var network = Bytes(5, 16);
        var seeded = Seed(directory, network, 2_049);
        var capability = Capability(network, seeded, 1, MatureNow);
        var first = Open(directory, network);
        var second = Open(directory, network);

        var results = await Task.WhenAll(
            first.CompactAsync(capability).AsTask(),
            second.CompactAsync(capability).AsTask());
        Assert.Single(results, result => result.Status == DirectoryCatalogCompactionStatus.Compacted);
        Assert.Single(results, result => result.Status == DirectoryCatalogCompactionStatus.ExactReplay);
        Assert.Equal(2_048, Open(directory, network).HistoryCount);
    }

    [Theory]
    [InlineData((int)DirectoryCatalogCommitStage.AfterCompactionPendingDurable, false)]
    [InlineData((int)DirectoryCatalogCommitStage.AfterCompactionManifestDurable, true)]
    [InlineData((int)DirectoryCatalogCommitStage.AfterCompactionSegmentDelete, true)]
    public async Task Crash_at_each_compaction_stage_recovers_old_or_new_atomic_state(
        int stageValue,
        bool committed)
    {
        var stage = (DirectoryCatalogCommitStage)stageValue;
        using var directory = new TemporaryDirectory();
        var network = Bytes((byte)(10 + stageValue), 16);
        var seeded = Seed(directory, network, 2_050);
        var capability = Capability(network, seeded, 2, MatureNow);
        var persistence = new FileDirectoryCatalogPersistence(
            directory.CatalogPath,
            new ThrowOnceObserver(stage));
        var crashing = new DirectoryPublicationCatalog(
            persistence, network, new SeedVerifier(network));

        await Assert.ThrowsAsync<InjectedCrashException>(() =>
            crashing.CompactAsync(capability).AsTask());

        var reopened = Open(directory, network);
        Assert.Equal(committed ? 2_048 : 2_050, reopened.HistoryCount);
        Assert.Equal(committed, reopened.Get(0) is null);
        var replay = await reopened.CompactAsync(capability);
        Assert.Equal(
            committed ? DirectoryCatalogCompactionStatus.ExactReplay : DirectoryCatalogCompactionStatus.Compacted,
            replay.Status);
        Assert.Equal(2_048, Open(directory, network).HistoryCount);
    }

    [Fact]
    public async Task Corrupt_compaction_journal_quarantines_and_fork_latch_blocks_transition()
    {
        using var corruptDirectory = new TemporaryDirectory();
        var network = Bytes(20, 16);
        _ = Seed(corruptDirectory, network, 2_049);
        File.WriteAllBytes(corruptDirectory.CatalogPath + ".compaction.pending", Bytes(0x55, 64));
        var corrupt = Open(corruptDirectory, network);
        Assert.True(corrupt.IsQuarantined);
        Assert.Throws<DirectoryCatalogException>(() => _ = corrupt.HistoryCount);

        using var forkDirectory = new TemporaryDirectory();
        var forkSeed = Seed(forkDirectory, network, 2_049);
        var fork = Open(forkDirectory, network);
        var current = fork.GetCurrent()!;
        var changed = Candidate(network, current.Generation, 0xfe);
        await Assert.ThrowsAsync<DirectoryCatalogException>(() =>
            fork.PublishAsync(changed, fork.CurrentAnchor).AsTask());
        Assert.True(fork.IsForkLatched);
        var capability = Capability(network, forkSeed, 1, MatureNow);
        var exception = await Assert.ThrowsAsync<DirectoryCatalogException>(() =>
            fork.CompactAsync(capability).AsTask());
        Assert.Equal(DirectoryCatalogError.ForkLatched, exception.Error);
    }

    [Fact]
    public async Task Hard_cap_remains_fail_closed_without_verified_compaction_capability()
    {
        using var directory = new TemporaryDirectory();
        var network = Bytes(21, 16);
        _ = Seed(directory, network, DirectoryCatalogLimits.AbsoluteMaximumHistoryEntries);
        var catalog = Open(directory, network);

        var exception = await Assert.ThrowsAsync<DirectoryCatalogException>(() =>
            catalog.PublishAsync(
                Candidate(network, DirectoryCatalogLimits.AbsoluteMaximumHistoryEntries, 0xaa),
                catalog.CurrentAnchor).AsTask());
        Assert.Equal(DirectoryCatalogError.HistoryCapacityReached, exception.Error);
        Assert.Equal(DirectoryCatalogLimits.AbsoluteMaximumHistoryEntries, catalog.HistoryCount);
        Assert.NotNull(catalog.Get(0));
    }

    private static ulong MatureNow => Origin + DirectoryCatalogLimits.RequiredRetentionSeconds;

    private static DirectoryPublicationCatalog Open(TemporaryDirectory directory, byte[] network) =>
        new(directory.CatalogPath, network, new SeedVerifier(network));

    private static DirectoryCatalogCompactionCapability Capability(
        byte[] network,
        IReadOnlyList<SeedEntry> seeded,
        ulong targetGeneration,
        ulong trustedNow)
    {
        var targetIndex = checked((int)targetGeneration);
        return DirectoryCatalogCompactionCapability.CreateForTests(
            network,
            trustedNow,
            targetGeneration,
            seeded[targetIndex].Fingerprint,
            seeded.Take(targetIndex).Select(Source).ToArray());
    }

    private static DirectoryCatalogCompactionSource Source(SeedEntry entry) =>
        new(entry.Generation, entry.Fingerprint, Hash("source-nfp", entry.Generation));

    private static IReadOnlyList<SeedEntry> Seed(
        TemporaryDirectory directory,
        byte[] network,
        int count,
        Func<ulong, ulong>? retentionOrigin = null)
    {
        retentionOrigin ??= static _ => Origin;
        Directory.CreateDirectory(directory.SegmentPath);
        var limits = new DirectoryCatalogLimits();
        var entries = new DirectoryCatalogSegmentEntry[count];
        var result = new SeedEntry[count];
        long total = 0;
        for (var index = 0; index < count; index++)
        {
            var generation = checked((ulong)index);
            var fingerprint = Hash("protected-lkg", generation);
            var publication = Stored(network, generation, retentionOrigin(generation), fingerprint);
            var encoded = DirectoryCatalogSegmentCodec.Encode(network, publication, limits);
            var segmentHash = SHA256.HashData(encoded);
            entries[index] = new DirectoryCatalogSegmentEntry(
                generation, encoded.Length, segmentHash, publication.PublicationHash);
            File.WriteAllBytes(Path.Combine(directory.SegmentPath, $"{generation:x16}.dps"), encoded);
            total += encoded.Length;
            result[index] = new SeedEntry(generation, fingerprint);
        }
        var state = new DirectoryCatalogState(network, entries, total, null, null);
        File.WriteAllBytes(directory.CatalogPath, DirectoryCatalogManifestCodec.Encode(state, limits));
        return result;
    }

    private static StoredDirectoryPublication Stored(
        byte[] network,
        ulong generation,
        ulong retentionOrigin,
        byte[] fingerprint)
    {
        var artifacts = new[]
        {
            StoredArtifact(DirectoryArtifactKind.CurrentNetworkView, Artifact("XNV1", network, generation, 1)),
            StoredArtifact(DirectoryArtifactKind.CurrentNetworkViewHead, Artifact("XNH1", network, generation, 2)),
            StoredArtifact(DirectoryArtifactKind.CurrentMailboxTopology, Artifact("PMT2", network, generation, 3))
        };
        return new StoredDirectoryPublication(generation, retentionOrigin, fingerprint, artifacts);
    }

    private static StoredDirectoryArtifact StoredArtifact(DirectoryArtifactKind kind, byte[] bytes)
    {
        var hash = SHA256.HashData(bytes);
        return new StoredDirectoryArtifact(kind, bytes, hash, hash);
    }

    private static DirectoryPublicationCandidate Candidate(byte[] network, ulong generation, byte marker)
    {
        var view = Artifact("XNV1", network, generation, marker);
        var head = Artifact("XNH1", network, generation, marker);
        var topology = Artifact("PMT2", network, generation, marker);
        var closure = new DirectoryPublicationVerificationClosure(
            [Artifact("XNA1", network, generation, 1)],
            [Artifact("DTS1", network, generation, 2)],
            [Artifact("XVP1", network, generation, 3)],
            [view], [head],
            [
                Artifact("XND1", network, generation, 4),
                Artifact("XND1", network, generation, 5),
                Artifact("XND1", network, generation, 6)
            ],
            [topology],
            Artifact("ADH1", network, generation, 7),
            Artifact("DTT1", network, generation, 8),
            Artifact("ADP1", network, generation, 9),
            Bytes(10, 32), Bytes(11, 32), Bytes(12, 16), 1, 2, 3, 1);
        return new DirectoryPublicationCandidate(view, head, topology, closure);
    }

    private static byte[] Artifact(
        string magic,
        byte[] network,
        ulong generation,
        byte marker)
    {
        var output = new byte[29];
        Encoding.ASCII.GetBytes(magic).CopyTo(output, 0);
        network.CopyTo(output, 4);
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(20), generation);
        output[28] = marker;
        return output;
    }

    private static byte[] Hash(string domain, ulong generation)
    {
        var domainBytes = Encoding.ASCII.GetBytes(domain);
        var input = new byte[domainBytes.Length + 8];
        domainBytes.CopyTo(input, 0);
        BinaryPrimitives.WriteUInt64BigEndian(input.AsSpan(domainBytes.Length), generation);
        return SHA256.HashData(input);
    }

    private static byte[] Bytes(byte value, int count) =>
        Enumerable.Repeat(value, count).ToArray();

    private sealed record SeedEntry(ulong Generation, byte[] Fingerprint);

    private sealed class SeedVerifier(byte[] network) : IDirectoryCanonicalPublicationVerifier
    {
        public ValueTask<VerifiedDirectoryPublication> VerifyAsync(
            FrozenDirectoryPublicationCandidate candidate,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var artifacts = candidate.Artifacts().Select(value => new VerifiedDirectoryArtifact(
                value.Kind, value.Bytes.Span, SHA256.HashData(value.Bytes.Span))).ToArray();
            var generation = BinaryPrimitives.ReadUInt64BigEndian(candidate.CurrentNetworkView.Span[20..]);
            return ValueTask.FromResult(new VerifiedDirectoryPublication(
                network,
                generation,
                new DirectoryPublicationRetentionAuthority(
                    Origin,
                    Hash("protected-lkg", generation)),
                artifacts[0], artifacts[1], artifacts[2],
                artifacts.Length == 5 ? artifacts[3] : null,
                artifacts.Length == 5 ? artifacts[4] : null));
        }
    }

    private sealed class ThrowOnceObserver(DirectoryCatalogCommitStage stage) : IDirectoryCatalogCommitObserver
    {
        private int thrown;
        public void OnStage(DirectoryCatalogCommitStage current)
        {
            if (current == stage && Interlocked.Exchange(ref thrown, 1) == 0)
                throw new InjectedCrashException(stage);
        }
    }

    private sealed class InjectedCrashException(DirectoryCatalogCommitStage stage)
        : Exception($"Injected crash at {stage}.");

    private sealed class TemporaryDirectory : IDisposable
    {
        internal TemporaryDirectory()
        {
            Path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                "deep-directory-compaction-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Path);
        }
        internal string Path { get; }
        internal string CatalogPath => System.IO.Path.Combine(Path, "catalog.bin");
        internal string SegmentPath => CatalogPath + ".segments";
        public void Dispose() => Directory.Delete(Path, recursive: true);
    }
}
#endif
