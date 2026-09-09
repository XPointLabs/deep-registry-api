using System.Buffers.Binary;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using Deep.Registry.Api.DirectoryPublication;

namespace Deep.Registry.Api.Tests;

public sealed class DirectoryPublicationCatalogTests
{
    [Fact]
    public async Task RestartPreservesExactBytesHashesAndExactReplay()
    {
        using var directory = new TemporaryDirectory();
        var network = Bytes(1, DirectoryPublicationCatalog.NetworkIdBytes);
        var verifier = new SyntheticCanonicalVerifier();
        var candidate = Candidate(network, 7, 11, includeForwardReset: true);
        var catalog = NewCatalog(directory.StatePath, network, verifier);

        var published = await catalog.PublishAsync(candidate, DirectoryCatalogAnchor.Empty);
        Assert.Equal(DirectoryCatalogPublishStatus.Published, published.Status);
        Assert.Equal(5, catalog.GetCurrent()!.Artifacts.Count);

        var restarted = NewCatalog(directory.StatePath, network, verifier);
        var restored = restarted.Get(7)!;
        Assert.Equal(candidate.CurrentNetworkView.ToArray(),
            restored.GetArtifact(DirectoryArtifactKind.CurrentNetworkView).CanonicalBytes.ToArray());
        Assert.Equal(
            SHA256.HashData(candidate.NetworkForwardProof!.Value.Span),
            restored.GetArtifact(DirectoryArtifactKind.NetworkForwardProof).ArtifactHash.ToArray());

        var replay = await restarted.PublishAsync(candidate, DirectoryCatalogAnchor.Empty);
        Assert.Equal(DirectoryCatalogPublishStatus.ExactReplay, replay.Status);
        Assert.Equal(published.CurrentAnchor, replay.CurrentAnchor);
        Assert.Equal(1, restarted.HistoryCount);
        Assert.True(Directory.Exists(directory.SegmentDirectoryPath));
        Assert.Single(Directory.GetFiles(directory.SegmentDirectoryPath, "*.dps"));
    }

    [Fact]
    public async Task GenerationCompareExchangeIsAtomicAcrossCatalogInstances()
    {
        using var directory = new TemporaryDirectory();
        var network = Bytes(2, DirectoryPublicationCatalog.NetworkIdBytes);
        var verifier = new SyntheticCanonicalVerifier();
        var first = NewCatalog(directory.StatePath, network, verifier);
        var initial = await first.PublishAsync(
            Candidate(network, 20, 1),
            DirectoryCatalogAnchor.Empty);

        var replicaA = NewCatalog(directory.StatePath, network, verifier);
        var replicaB = NewCatalog(directory.StatePath, network, verifier);
        var next = Candidate(network, 21, 2);
        var results = await Task.WhenAll(
            replicaA.PublishAsync(next, initial.CurrentAnchor).AsTask(),
            replicaB.PublishAsync(next, initial.CurrentAnchor).AsTask());

        Assert.Single(results, value => value.Status == DirectoryCatalogPublishStatus.Published);
        Assert.Single(results, value => value.Status == DirectoryCatalogPublishStatus.ExactReplay);

        var stale = await Assert.ThrowsAsync<DirectoryCatalogException>(() =>
            replicaA.PublishAsync(Candidate(network, 22, 3), initial.CurrentAnchor).AsTask());
        Assert.Equal(DirectoryCatalogError.CompareExchangeMismatch, stale.Error);

        var restarted = NewCatalog(directory.StatePath, network, verifier);
        Assert.Equal(2, restarted.HistoryCount);
        Assert.Equal((ulong)21, restarted.GetCurrent()!.Generation);
    }

    [Fact]
    public async Task SecondInstanceReadsHeadPublishedAfterItsInMemorySnapshot()
    {
        using var directory = new TemporaryDirectory();
        var network = Bytes(21, DirectoryPublicationCatalog.NetworkIdBytes);
        var verifier = new SyntheticCanonicalVerifier();
        var writer = NewCatalog(directory.StatePath, network, verifier);
        var first = await writer.PublishAsync(
            Candidate(network, 700, 1),
            DirectoryCatalogAnchor.Empty);
        var reader = NewCatalog(directory.StatePath, network, verifier);
        Assert.Equal((ulong)700, reader.GetCurrent()!.Generation);

        await writer.PublishAsync(Candidate(network, 701, 2), first.CurrentAnchor);

        Assert.Equal((ulong)701, reader.GetCurrent()!.Generation);
        Assert.Equal((ulong)701, reader.Get(701)!.Generation);
        Assert.Equal(2, reader.HistoryCount);
    }

    [Fact]
    public async Task SameGenerationDifferentCanonicalBytesLatchesForkAcrossRestart()
    {
        using var directory = new TemporaryDirectory();
        var network = Bytes(3, DirectoryPublicationCatalog.NetworkIdBytes);
        var verifier = new SyntheticCanonicalVerifier();
        var original = Candidate(network, 9, 4);
        var catalog = NewCatalog(directory.StatePath, network, verifier);
        var accepted = await catalog.PublishAsync(original, DirectoryCatalogAnchor.Empty);

        var fork = await Assert.ThrowsAsync<DirectoryCatalogException>(() =>
            catalog.PublishAsync(Candidate(network, 9, 5), accepted.CurrentAnchor).AsTask());
        Assert.Equal(DirectoryCatalogError.ForkLatched, fork.Error);
        Assert.True(catalog.IsForkLatched);

        var restarted = NewCatalog(directory.StatePath, network, verifier);
        Assert.True(restarted.IsForkLatched);
        var verifierCalls = verifier.Calls;
        var blocked = await Assert.ThrowsAsync<DirectoryCatalogException>(() =>
            restarted.PublishAsync(Candidate(network, 10, 6), restarted.CurrentAnchor).AsTask());
        Assert.Equal(DirectoryCatalogError.ForkLatched, blocked.Error);
        Assert.Equal(verifierCalls, verifier.Calls);
    }

    [Fact]
    public async Task CorruptManifestIsPersistentlyQuarantined()
    {
        using var directory = new TemporaryDirectory();
        var network = Bytes(4, DirectoryPublicationCatalog.NetworkIdBytes);
        var verifier = new SyntheticCanonicalVerifier();
        var catalog = NewCatalog(directory.StatePath, network, verifier);
        await catalog.PublishAsync(Candidate(network, 1, 7), DirectoryCatalogAnchor.Empty);
        FlipByte(directory.StatePath);

        var quarantined = NewCatalog(directory.StatePath, network, verifier);
        Assert.True(quarantined.IsQuarantined);
        Assert.True(File.Exists($"{directory.StatePath}.quarantine"));
        var fetch = Assert.Throws<DirectoryCatalogException>(() => quarantined.GetCurrent());
        Assert.Equal(DirectoryCatalogError.CorruptStateQuarantined, fetch.Error);

        var restarted = NewCatalog(directory.StatePath, network, verifier);
        Assert.True(restarted.IsQuarantined);
    }

    [Fact]
    public async Task CorruptHistoricalSegmentQuarantinesOnlyWhenLazyReadTouchesIt()
    {
        using var directory = new TemporaryDirectory();
        var network = Bytes(40, DirectoryPublicationCatalog.NetworkIdBytes);
        var catalog = NewCatalog(directory.StatePath, network, new SyntheticCanonicalVerifier());
        var first = await catalog.PublishAsync(
            Candidate(network, 100, 1),
            DirectoryCatalogAnchor.Empty);
        await catalog.PublishAsync(Candidate(network, 101, 2), first.CurrentAnchor);
        FlipByte(directory.SegmentPath(100));

        var restarted = NewCatalog(
            directory.StatePath,
            network,
            new SyntheticCanonicalVerifier());
        Assert.False(restarted.IsQuarantined);
        Assert.Equal((ulong)101, restarted.GetCurrent()!.Generation);

        var failure = Assert.Throws<DirectoryCatalogException>(() => restarted.Get(100));
        Assert.Equal(DirectoryCatalogError.CorruptStateQuarantined, failure.Error);
        Assert.True(restarted.IsQuarantined);
        Assert.True(File.Exists($"{directory.StatePath}.quarantine"));
    }

    [Fact]
    public void OversizedManifestIsQuarantinedBeforeDecodeAllocation()
    {
        using var directory = new TemporaryDirectory();
        var network = Bytes(41, DirectoryPublicationCatalog.NetworkIdBytes);
        var limits = SmallLimits();
        using (var stream = new FileStream(directory.StatePath, FileMode.CreateNew, FileAccess.Write))
        {
            stream.SetLength(limits.MaximumManifestBytes + 1L);
        }

        var catalog = NewCatalog(
            directory.StatePath,
            network,
            new SyntheticCanonicalVerifier(),
            limits);

        Assert.True(catalog.IsQuarantined);
        Assert.True(File.Exists($"{directory.StatePath}.quarantine"));
    }

    [Fact]
    public async Task ConfiguredArtifactBoundRejectsBeforeVerifierAndMutation()
    {
        using var directory = new TemporaryDirectory();
        var network = Bytes(5, DirectoryPublicationCatalog.NetworkIdBytes);
        var verifier = new SyntheticCanonicalVerifier();
        var limits = SmallLimits(maximumArtifactBytes: 64);
        var catalog = NewCatalog(directory.StatePath, network, verifier, limits);
        var oversized = CandidateFromArtifacts(
            network,
            1,
            Artifact("XNV1", network, 1, 1, length: 65),
            Artifact("XNH1", network, 1, 1),
            Artifact("PMT2", network, 1, 1));

        var rejected = await Assert.ThrowsAsync<DirectoryCatalogException>(() =>
            catalog.PublishAsync(oversized, DirectoryCatalogAnchor.Empty).AsTask());
        Assert.Equal(DirectoryCatalogError.BoundsExceeded, rejected.Error);
        Assert.Equal(0, verifier.Calls);
        Assert.Equal(0, catalog.HistoryCount);
        Assert.False(File.Exists(directory.StatePath));
    }

    [Fact]
    public void AbsoluteArtifactMaxPlusOneAndResetCardinalityRejectBeforeCopy()
    {
        var network = Bytes(50, DirectoryPublicationCatalog.NetworkIdBytes);
        var maximum = Artifact(
            "XNV1",
            network,
            1,
            1,
            DirectoryCatalogLimits.AbsoluteMaximumArtifactBytes);
        var tooLarge = new byte[DirectoryCatalogLimits.AbsoluteMaximumArtifactBytes + 1];

        var accepted = CandidateFromArtifacts(
            network,
            1,
            maximum,
            Artifact("XNH1", network, 1, 1),
            Artifact("PMT2", network, 1, 1));
        Assert.Equal(DirectoryCatalogLimits.AbsoluteMaximumArtifactBytes,
            accepted.CurrentNetworkView.Length);

        Assert.Throws<ArgumentOutOfRangeException>(() =>
            CandidateFromArtifacts(
                network,
                1,
                tooLarge,
                Artifact("XNH1", network, 1, 1),
                Artifact("PMT2", network, 1, 1)));
        Assert.Throws<ArgumentException>(() =>
            new DirectoryPublicationCandidate(
                Artifact("XNV1", network, 1, 1),
                Artifact("XNH1", network, 1, 1),
                Artifact("PMT2", network, 1, 1),
                SyntheticClosure(network, 1, 1),
                Artifact("XNF1", network, 1, 1)));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            CandidateFromArtifacts(
                network,
                1,
                [],
                Artifact("XNH1", network, 1, 1),
                Artifact("PMT2", network, 1, 1)));
    }

    [Fact]
    public async Task MaximumSizedFiveArtifactClosureFitsOneBoundedSegment()
    {
        using var directory = new TemporaryDirectory();
        var network = Bytes(53, DirectoryPublicationCatalog.NetworkIdBytes);
        var maximum = DirectoryCatalogLimits.AbsoluteMaximumArtifactBytes;
        var candidate = CandidateFromArtifacts(
            network,
            1,
            Artifact("XNV1", network, 1, 1, maximum),
            Artifact("XNH1", network, 1, 2, maximum),
            Artifact("PMT2", network, 1, 3, maximum),
            Artifact("XNF1", network, 1, 4, maximum),
            Artifact("NFP1", network, 1, 5, maximum));
        var catalog = NewCatalog(
            directory.StatePath,
            network,
            new SyntheticCanonicalVerifier());

        await catalog.PublishAsync(candidate, DirectoryCatalogAnchor.Empty);

        var segmentLength = new FileInfo(directory.SegmentPath(1)).Length;
        Assert.InRange(segmentLength, 1, new DirectoryCatalogLimits().MaximumSegmentBytes);
        Assert.Equal(maximum,
            catalog.GetCurrent()!
                .GetArtifact(DirectoryArtifactKind.NetworkForwardProof)
                .CanonicalBytes.Length);
    }

    [Fact]
    public void DefaultLimitsReserveWorstCaseBytesForTheMandatoryGenerationFloor()
    {
        var limits = new DirectoryCatalogLimits();
        limits.Validate();

        Assert.True(limits.MaximumHistoryEntries > 2_048);
        Assert.True(
            limits.MaximumRetainedSegmentBytes >=
            (long)limits.MaximumSegmentBytes *
            DirectoryCatalogLimits.RequiredMinimumHistoryEntries);
        Assert.True(
            limits.MaximumManifestBytes >=
            DirectoryCatalogManifestCodec.GetMaximumEncodedBytes(limits.MaximumHistoryEntries));
    }

    [Fact]
    public async Task DefaultRetentionAccepts2047_2048_And2049ContiguousGenerations()
    {
        using var directory = new TemporaryDirectory();
        var network = Bytes(51, DirectoryPublicationCatalog.NetworkIdBytes);
        var catalog = NewCatalog(
            directory.StatePath,
            network,
            new SyntheticCanonicalVerifier());
        var anchor = DirectoryCatalogAnchor.Empty;
        var stopwatch = Stopwatch.StartNew();

        for (ulong generation = 1; generation <= 2_049; generation++)
        {
            var result = await catalog.PublishAsync(
                Candidate(network, generation, checked((byte)((generation % 251) + 1))),
                anchor);
            anchor = result.CurrentAnchor;
            if (generation is 2_047 or 2_048 or 2_049)
            {
                Assert.Equal(checked((int)generation), catalog.HistoryCount);
                Assert.NotNull(catalog.Get(generation));
            }
        }

        stopwatch.Stop();
        Assert.Equal(2_049, catalog.HistoryCount);
        Assert.Equal((ulong)2_049, catalog.GetCurrent()!.Generation);
        Assert.Equal(2_049, Directory.GetFiles(directory.SegmentDirectoryPath, "*.dps").Length);
        Assert.True(DirectorySize(directory.Path) <= catalog.MaximumTotalOnDiskBytes);

        var measuredPersistence = new FileDirectoryCatalogPersistence(directory.StatePath);
        var reopened = new DirectoryPublicationCatalog(
            measuredPersistence,
            network,
            new SyntheticCanonicalVerifier());
        Assert.Equal(2_049, reopened.HistoryCount);
        Assert.Equal(1, measuredPersistence.IoMetrics.SegmentsRead);
        Console.WriteLine(
            $"2049 durable commits: {stopwatch.ElapsedMilliseconds} ms; " +
            $"reopen manifest={measuredPersistence.IoMetrics.ManifestBytesRead} " +
            $"segment={measuredPersistence.IoMetrics.SegmentBytesRead} " +
            $"segments={measuredPersistence.IoMetrics.SegmentsRead}");
    }

    [Fact]
    public async Task Configured2048GenerationCapacityRejectsOnlyThe2049thAppend()
    {
        using var directory = new TemporaryDirectory();
        var network = Bytes(52, DirectoryPublicationCatalog.NetworkIdBytes);
        var catalog = NewCatalog(
            directory.StatePath,
            network,
            new SyntheticCanonicalVerifier(),
            SmallLimits(maximumHistoryEntries: 2_048));
        var anchor = DirectoryCatalogAnchor.Empty;
        for (ulong generation = 10_000; generation < 12_048; generation++)
        {
            anchor = (await catalog.PublishAsync(
                Candidate(network, generation, checked((byte)((generation % 251) + 1))),
                anchor)).CurrentAnchor;
        }

        var rejected = await Assert.ThrowsAsync<DirectoryCatalogException>(() =>
            catalog.PublishAsync(Candidate(network, 12_048, 1), anchor).AsTask());
        Assert.Equal(DirectoryCatalogError.HistoryCapacityReached, rejected.Error);
        Assert.Equal(2_048, catalog.HistoryCount);
    }

    [Theory]
    [InlineData(0, false)]
    [InlineData(1, true)]
    [InlineData(2, true)]
    public async Task CrashRecoveryIsAtomicAtEveryCommitStage(
        int failpointValue,
        bool successorMustRecover)
    {
        var failpoint = (DirectoryCatalogCommitStage)failpointValue;
        using var directory = new TemporaryDirectory();
        var network = Bytes((byte)(60 + (int)failpoint), DirectoryPublicationCatalog.NetworkIdBytes);
        var verifier = new SyntheticCanonicalVerifier();
        var baseline = NewCatalog(directory.StatePath, network, verifier, SmallLimits());
        var first = await baseline.PublishAsync(
            Candidate(network, 500, 1),
            DirectoryCatalogAnchor.Empty);

        var observer = new ThrowOnceCommitObserver(failpoint);
        var persistence = new FileDirectoryCatalogPersistence(directory.StatePath, observer);
        var failing = new DirectoryPublicationCatalog(
            persistence,
            network,
            verifier,
            SmallLimits());
        await Assert.ThrowsAsync<InjectedCrashException>(() =>
            failing.PublishAsync(Candidate(network, 501, 2), first.CurrentAnchor).AsTask());

        var restarted = NewCatalog(directory.StatePath, network, verifier, SmallLimits());
        Assert.Equal(successorMustRecover ? 2 : 1, restarted.HistoryCount);
        if (successorMustRecover)
        {
            Assert.Equal((ulong)501, restarted.GetCurrent()!.Generation);
            var replay = await restarted.PublishAsync(
                Candidate(network, 501, 2),
                first.CurrentAnchor);
            Assert.Equal(DirectoryCatalogPublishStatus.ExactReplay, replay.Status);
        }
        else
        {
            var retried = await restarted.PublishAsync(
                Candidate(network, 501, 2),
                first.CurrentAnchor);
            Assert.Equal(DirectoryCatalogPublishStatus.Published, retried.Status);
        }

        Assert.False(File.Exists($"{directory.StatePath}.pending"));
        Assert.False(File.Exists($"{directory.StatePath}.segment.writing"));
    }

    [Fact]
    public async Task OpenAndCommitReadOnlyBoundedMetadataAndHeadSegment()
    {
        using var directory = new TemporaryDirectory();
        var network = Bytes(70, DirectoryPublicationCatalog.NetworkIdBytes);
        var limits = SmallLimits();
        var verifier = new SyntheticCanonicalVerifier();
        var catalog = NewCatalog(directory.StatePath, network, verifier, limits);
        var anchor = DirectoryCatalogAnchor.Empty;
        for (ulong generation = 1; generation <= 256; generation++)
        {
            anchor = (await catalog.PublishAsync(
                Candidate(network, generation, checked((byte)((generation % 251) + 1))),
                anchor)).CurrentAnchor;
        }

        // Unknown files are never enumerated or allocated by recovery.
        for (var index = 0; index < 128; index++)
        {
            File.WriteAllText(Path.Combine(directory.SegmentDirectoryPath, $"junk-{index:D3}"), "ignored");
        }

        var measuredPersistence = new FileDirectoryCatalogPersistence(directory.StatePath);
        var reopened = new DirectoryPublicationCatalog(
            measuredPersistence,
            network,
            verifier,
            limits);
        var open = measuredPersistence.IoMetrics;
        Assert.Equal(1, open.SegmentsRead);
        Assert.InRange(open.SegmentBytesRead, 1, limits.MaximumSegmentBytes);
        Assert.InRange(open.ManifestBytesRead, 1, limits.MaximumManifestBytes);

        var beforeCommit = measuredPersistence.IoMetrics;
        await reopened.PublishAsync(Candidate(network, 257, 3), reopened.CurrentAnchor);
        var afterCommit = measuredPersistence.IoMetrics;
        Assert.Equal(1, afterCommit.SegmentsWritten - beforeCommit.SegmentsWritten);
        Assert.InRange(
            afterCommit.SegmentBytesWritten - beforeCommit.SegmentBytesWritten,
            1,
            limits.MaximumSegmentBytes);
        Assert.InRange(
            afterCommit.ManifestBytesWritten - beforeCommit.ManifestBytesWritten,
            1,
            limits.MaximumManifestBytes);
        Assert.InRange(
            afterCommit.SegmentsRead - beforeCommit.SegmentsRead,
            1,
            2);
        Console.WriteLine(
            $"open manifest={open.ManifestBytesRead} segment={open.SegmentBytesRead} segments={open.SegmentsRead}; " +
            $"commit manifest={afterCommit.ManifestBytesWritten - beforeCommit.ManifestBytesWritten} " +
            $"segment={afterCommit.SegmentBytesWritten - beforeCommit.SegmentBytesWritten} " +
            $"segmentsRead={afterCommit.SegmentsRead - beforeCommit.SegmentsRead}");
    }

    [Fact]
    public async Task InputsOutputsAndAnchorsAreDefensiveCopies()
    {
        using var directory = new TemporaryDirectory();
        var network = Bytes(6, DirectoryPublicationCatalog.NetworkIdBytes);
        var verifier = new SyntheticCanonicalVerifier();
        var mutableView = Artifact("XNV1", network, 2, 10);
        var expectedView = mutableView.ToArray();
        var candidate = CandidateFromArtifacts(
            network,
            2,
            mutableView,
            Artifact("XNH1", network, 2, 10),
            Artifact("PMT2", network, 2, 10));
        mutableView[0] ^= 0xff;

        var catalog = NewCatalog(directory.StatePath, network, verifier);
        var result = await catalog.PublishAsync(candidate, DirectoryCatalogAnchor.Empty);
        var exposedBytes = catalog.GetCurrent()!
            .GetArtifact(DirectoryArtifactKind.CurrentNetworkView)
            .CanonicalBytes.ToArray();
        exposedBytes[0] ^= 0xff;
        var exposedHash = result.CurrentAnchor.PublicationHash.ToArray();
        exposedHash[0] ^= 0xff;

        Assert.Equal(
            expectedView,
            catalog.GetCurrent()!
                .GetArtifact(DirectoryArtifactKind.CurrentNetworkView)
                .CanonicalBytes.ToArray());
        Assert.Equal(result.CurrentAnchor, catalog.CurrentAnchor);
    }

    [Fact]
    public async Task WrongNetworkRejectsWithoutPersistenceMutation()
    {
        using var directory = new TemporaryDirectory();
        var expectedNetwork = Bytes(7, DirectoryPublicationCatalog.NetworkIdBytes);
        var wrongNetwork = Bytes(8, DirectoryPublicationCatalog.NetworkIdBytes);
        var verifier = new SyntheticCanonicalVerifier();
        var catalog = NewCatalog(directory.StatePath, expectedNetwork, verifier);

        var rejected = await Assert.ThrowsAsync<DirectoryCatalogException>(() =>
            catalog.PublishAsync(
                Candidate(wrongNetwork, 1, 1),
                DirectoryCatalogAnchor.Empty).AsTask());

        Assert.Equal(DirectoryCatalogError.WrongNetwork, rejected.Error);
        Assert.Equal(0, catalog.HistoryCount);
        Assert.False(File.Exists(directory.StatePath));
        Assert.False(catalog.IsForkLatched);
    }

    [Fact]
    public async Task TypedVerifierCannotSubstituteDifferentCanonicalBytes()
    {
        using var directory = new TemporaryDirectory();
        var network = Bytes(9, DirectoryPublicationCatalog.NetworkIdBytes);
        var verifier = new SyntheticCanonicalVerifier(substituteCanonicalBytes: true);
        var catalog = NewCatalog(directory.StatePath, network, verifier);

        var rejected = await Assert.ThrowsAsync<DirectoryCatalogException>(() =>
            catalog.PublishAsync(
                Candidate(network, 1, 1),
                DirectoryCatalogAnchor.Empty).AsTask());

        Assert.Equal(DirectoryCatalogError.VerificationMismatch, rejected.Error);
        Assert.Equal(0, catalog.HistoryCount);
        Assert.False(File.Exists(directory.StatePath));
    }

    [Fact]
    public void VerifierBoundaryReturnsTypedPublicationAndCannotBeBoolean()
    {
        var method = typeof(IDirectoryCanonicalPublicationVerifier)
            .GetMethod(nameof(IDirectoryCanonicalPublicationVerifier.VerifyAsync));
        Assert.NotNull(method);
        Assert.Equal(typeof(ValueTask<VerifiedDirectoryPublication>), method.ReturnType);
        Assert.NotEqual(typeof(bool), method.ReturnType);
        Assert.NotEqual(typeof(ValueTask<bool>), method.ReturnType);
    }

    private static DirectoryCatalogLimits SmallLimits(
        int maximumArtifactBytes = 64,
        int maximumHistoryEntries = DirectoryCatalogLimits.AbsoluteMaximumHistoryEntries) =>
        new()
        {
            MaximumArtifactBytes = maximumArtifactBytes,
            MaximumHistoryEntries = maximumHistoryEntries,
            MaximumManifestBytes = DirectoryCatalogLimits.AbsoluteMaximumManifestBytes,
            MaximumRetainedSegmentBytes = 16L * 1024 * 1024
        };

    private static DirectoryPublicationCatalog NewCatalog(
        string statePath,
        byte[] network,
        SyntheticCanonicalVerifier verifier,
        DirectoryCatalogLimits? limits = null) =>
        new(statePath, network, verifier, limits);

    private static DirectoryPublicationCandidate Candidate(
        byte[] network,
        ulong generation,
        byte marker,
        bool includeForwardReset = false)
    {
        var view = Artifact("XNV1", network, generation, marker);
        var head = Artifact("XNH1", network, generation, marker);
        var topology = Artifact("PMT2", network, generation, marker);
        return includeForwardReset
            ? CandidateFromArtifacts(
                network,
                generation,
                view,
                head,
                topology,
                Artifact("XNF1", network, generation, marker),
                Artifact("NFP1", network, generation, marker))
            : CandidateFromArtifacts(network, generation, view, head, topology);
    }

    private static DirectoryPublicationCandidate CandidateFromArtifacts(
        byte[] network,
        ulong generation,
        byte[] view,
        byte[] head,
        byte[] topology,
        byte[]? checkpoint = null,
        byte[]? proof = null) =>
        new(
            view,
            head,
            topology,
            SyntheticClosure(network, generation, view, head, topology, checkpoint),
            checkpoint ?? [],
            proof ?? []);

    private static DirectoryPublicationVerificationClosure SyntheticClosure(
        byte[] network,
        ulong generation,
        byte marker) =>
        SyntheticClosure(
            network,
            generation,
            Artifact("XNV1", network, generation, marker),
            Artifact("XNH1", network, generation, marker),
            Artifact("PMT2", network, generation, marker),
            null);

    private static DirectoryPublicationVerificationClosure SyntheticClosure(
        byte[] network,
        ulong generation,
        byte[] view,
        byte[] head,
        byte[] topology,
        byte[]? checkpoint) =>
        new(
            [Artifact("XNA1", network, generation, 1)],
            [Artifact("DTS1", network, generation, 2)],
            [Artifact("XVP1", network, generation, 3)],
            [view],
            [head],
            [
                Artifact("XND1", network, generation, 4),
                Artifact("XND1", network, generation, 5),
                Artifact("XND1", network, generation, 6)
            ],
            [topology],
            Artifact("ADH1", network, generation, 7),
            Artifact("DTT1", network, generation, 8),
            Artifact("ADP1", network, generation, 9),
            Bytes(10, 32),
            Bytes(11, 32),
            Bytes(12, 16),
            1,
            2,
            3,
            1,
            checkpoint is null ? [] : [Artifact("XNA1", network, generation, 10)],
            checkpoint is null ? [] : [checkpoint]);

    private static byte[] Artifact(
        string magic,
        byte[] network,
        ulong generation,
        byte marker,
        int length = 29)
    {
        if (length < 29)
        {
            throw new ArgumentOutOfRangeException(nameof(length));
        }

        var output = new byte[length];
        Encoding.ASCII.GetBytes(magic).CopyTo(output, 0);
        network.CopyTo(output, 4);
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(20), generation);
        output.AsSpan(28).Fill(marker);
        return output;
    }

    private static byte[] Bytes(byte value, int count) =>
        Enumerable.Repeat(value, count).ToArray();

    private static void FlipByte(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        stream.Position = stream.Length / 2;
        var value = stream.ReadByte();
        Assert.NotEqual(-1, value);
        stream.Position--;
        stream.WriteByte((byte)(value ^ 0x80));
        stream.Flush(flushToDisk: true);
    }

    private static long DirectorySize(string path)
    {
        long total = 0;
        foreach (var file in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories))
        {
            total = checked(total + new FileInfo(file).Length);
        }

        return total;
    }

    private sealed class SyntheticCanonicalVerifier : IDirectoryCanonicalPublicationVerifier
    {
        private int calls;
        private readonly bool substituteCanonicalBytes;

        internal SyntheticCanonicalVerifier(bool substituteCanonicalBytes = false)
        {
            this.substituteCanonicalBytes = substituteCanonicalBytes;
        }

        public int Calls => Volatile.Read(ref calls);

        public ValueTask<VerifiedDirectoryPublication> VerifyAsync(
            FrozenDirectoryPublicationCandidate candidate,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Interlocked.Increment(ref calls);
            var decoded = candidate.Artifacts()
                .Select(static value => Decode(value.Kind, value.Bytes.Span))
                .ToArray();
            var network = decoded[0].Network;
            var generation = decoded[0].Generation;
            if (decoded.Any(value =>
                    !value.Network.AsSpan().SequenceEqual(network) ||
                    value.Generation != generation))
            {
                throw new FormatException("Synthetic closure mismatch.");
            }

            if (substituteCanonicalBytes)
            {
                var replacement = decoded[0].Artifact.CanonicalBytes.ToArray();
                replacement[^1] ^= 0xff;
                decoded[0] = decoded[0] with
                {
                    Artifact = new VerifiedDirectoryArtifact(
                        DirectoryArtifactKind.CurrentNetworkView,
                        replacement,
                        decoded[0].Artifact.CoreHash.Span)
                };
            }

            return ValueTask.FromResult(new VerifiedDirectoryPublication(
                network,
                generation,
                new DirectoryPublicationRetentionAuthority(
                    1_000 + generation,
                    SHA256.HashData(decoded[0].Artifact.CanonicalBytes.Span)),
                decoded[0].Artifact,
                decoded[1].Artifact,
                decoded[2].Artifact,
                decoded.Length == 5 ? decoded[3].Artifact : null,
                decoded.Length == 5 ? decoded[4].Artifact : null));
        }

        private static DecodedArtifact Decode(
            DirectoryArtifactKind kind,
            ReadOnlySpan<byte> canonical)
        {
            if (canonical.Length < 29)
            {
                throw new FormatException("Synthetic canonical length is invalid.");
            }

            var expectedMagic = kind switch
            {
                DirectoryArtifactKind.CurrentNetworkView => "XNV1",
                DirectoryArtifactKind.CurrentNetworkViewHead => "XNH1",
                DirectoryArtifactKind.CurrentMailboxTopology => "PMT2",
                DirectoryArtifactKind.NetworkForwardCheckpoint => "XNF1",
                DirectoryArtifactKind.NetworkForwardProof => "NFP1",
                _ => throw new FormatException("Unknown synthetic artifact kind.")
            };
            if (!canonical[..4].SequenceEqual(Encoding.ASCII.GetBytes(expectedMagic)))
            {
                throw new FormatException("Synthetic canonical magic is invalid.");
            }

            var network = canonical.Slice(4, DirectoryPublicationCatalog.NetworkIdBytes).ToArray();
            var generation = BinaryPrimitives.ReadUInt64BigEndian(canonical.Slice(20, 8));
            var coreInput = new byte[canonical.Length + 1];
            coreInput[0] = (byte)kind;
            canonical.CopyTo(coreInput.AsSpan(1));
            return new DecodedArtifact(
                network,
                generation,
                new VerifiedDirectoryArtifact(kind, canonical, SHA256.HashData(coreInput)));
        }
    }

    private sealed record DecodedArtifact(
        byte[] Network,
        ulong Generation,
        VerifiedDirectoryArtifact Artifact);

    private sealed class ThrowOnceCommitObserver : IDirectoryCatalogCommitObserver
    {
        private readonly DirectoryCatalogCommitStage stage;
        private int thrown;

        internal ThrowOnceCommitObserver(DirectoryCatalogCommitStage stage)
        {
            this.stage = stage;
        }

        public void OnStage(DirectoryCatalogCommitStage currentStage)
        {
            if (currentStage == stage && Interlocked.Exchange(ref thrown, 1) == 0)
            {
                throw new InjectedCrashException(stage);
            }
        }
    }

    private sealed class InjectedCrashException : Exception
    {
        internal InjectedCrashException(DirectoryCatalogCommitStage stage)
            : base($"Injected directory catalog crash after {stage}.")
        {
        }
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        internal TemporaryDirectory()
        {
            Path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                $"deep-directory-01-{Guid.NewGuid():N}");
            Directory.CreateDirectory(Path);
        }

        internal string Path { get; }
        internal string StatePath => System.IO.Path.Combine(Path, "catalog.bin");
        internal string SegmentDirectoryPath => $"{StatePath}.segments";
        internal string SegmentPath(ulong generation) => System.IO.Path.Combine(
            SegmentDirectoryPath,
            $"{generation:x16}.dps");

        public void Dispose()
        {
            if (Directory.Exists(Path))
            {
                Directory.Delete(Path, recursive: true);
            }
        }
    }
}
