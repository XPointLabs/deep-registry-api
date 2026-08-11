using System.Buffers.Binary;
using System.Reflection;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxAuthority;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.MailboxTopology;
using Deep.Registry.Api.ProductionMailbox;
using Npgsql;
using Sodium;

namespace Deep.Registry.Api.Tests;

public sealed class ProductionMailboxRouteContinuityAdvancedStateTests
{
    [Fact]
    public async Task InMemory_HistoryLookupRetainsExactCursorPlanAndImmutableFingerprint()
    {
        var store = (IProductionMailboxRouteContinuityStateStore)
            new InMemoryProductionMailboxStateStore();
        var fixture = await AdvancedFixture.CreateAsync(store, 23);
        var genesisRequest = LookupRequest(fixture, fixture.InitialCursor, null);

        var genesisHead = await store.LookupRouteHistoryAsync(fixture.RouteKey,
            genesisRequest, CancellationToken.None);
        Assert.Equal(ProductionMailboxRouteHistoryLookupStatus.HeadNoChange,
            genesisHead.Status);
        Assert.NotNull(genesisHead.Lookup);
        Assert.Null(genesisHead.Lookup.NextPlan);
        Assert.Empty(genesisHead.Lookup.CanonicalNextBatch.ToArray());

        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.Accepted,
            (await store.CommitVerifiedHistoryBatchAsync(fixture.RouteKey,
                fixture.InitialCursor, fixture.FirstPlan, CancellationToken.None)).Status);
        var firstHistory = await store.LookupRouteHistoryAsync(fixture.RouteKey,
            genesisRequest, CancellationToken.None);
        Assert.Equal(ProductionMailboxRouteHistoryLookupStatus.History, firstHistory.Status);
        Assert.Equal(fixture.FirstPlan.PlanHash.ToArray(),
            firstHistory.Lookup!.NextPlan!.PlanHash.ToArray());
        Assert.Equal(fixture.FirstPlan.CanonicalBatch.ToArray(),
            firstHistory.Lookup.CanonicalNextBatch.ToArray());
        Assert.Equal(fixture.FirstPlan.NextCursor.CanonicalCheckpoint.ToArray(),
            firstHistory.Lookup.CanonicalNextCheckpoint.ToArray());
        Assert.NotEqual(genesisHead.Lookup.RouteLocalSourceFingerprint.ToArray(),
            firstHistory.Lookup.RouteLocalSourceFingerprint.ToArray());

        var responseReferenceKey = AdvancedFixture.Bytes(91, 32);
        var responseReference = ProductionMailboxProtectedHistoryResponseReference.Create(
            fixture.RouteKey, fixture.InitialCursor.CanonicalCheckpointHash.Span,
            firstHistory.Lookup, responseReferenceKey);
        Assert.Equal(ProductionMailboxProtectedHistoryResponseReference.CanonicalLength,
            responseReference.CanonicalBytes.Length);
        Assert.Equal(0UL, responseReference.CurrentBatchSequence);
        Assert.Equal(1UL, responseReference.NextBatchSequence);
        Assert.Equal(
            checked((uint)(fixture.FirstPlan.CanonicalBatch.Length +
                ProductionMailboxRouteContinuityConstants.CanonicalRouteHistoryCheckpointLength)),
            responseReference.PayloadLength);
        Assert.Equal(fixture.FirstPlan.CanonicalBatchHash.ToArray(),
            responseReference.CanonicalBatchHash.ToArray());
        Assert.Equal(fixture.FirstPlan.NextCursor.CanonicalCheckpointHash.ToArray(),
            responseReference.CanonicalNextCheckpointHash.ToArray());
        Assert.Equal(fixture.FirstPlan.PlanHash.ToArray(),
            responseReference.BatchCommitPlanHash.ToArray());
        var restoredReference = ProductionMailboxProtectedHistoryResponseReference.Restore(
            fixture.RouteKey, fixture.InitialCursor.CanonicalCheckpointHash.Span,
            responseReference.CanonicalBytes.Span, responseReference.IntegrityTag.Span,
            responseReferenceKey);
        Assert.True(responseReference.Exact(restoredReference));
        var referenceCopy = responseReference.CanonicalBytes.ToArray();
        referenceCopy[^1] ^= 1;
        Assert.NotEqual(referenceCopy, responseReference.CanonicalBytes.ToArray());
        var badTag = responseReference.IntegrityTag.ToArray();
        badTag[0] ^= 1;
        Assert.Throws<InvalidDataException>(() =>
            ProductionMailboxProtectedHistoryResponseReference.Restore(
                fixture.RouteKey, fixture.InitialCursor.CanonicalCheckpointHash.Span,
                responseReference.CanonicalBytes.Span, badTag, responseReferenceKey));
        foreach (var invalidCanonical in InvalidHistoryReferences(
                     responseReference.CanonicalBytes.ToArray()))
        {
            var matchingTag = HistoryReferenceTag(fixture.RouteKey,
                fixture.InitialCursor.CanonicalCheckpointHash.Span, invalidCanonical,
                responseReferenceKey);
            Assert.Throws<InvalidDataException>(() =>
                ProductionMailboxProtectedHistoryResponseReference.Restore(
                    fixture.RouteKey, fixture.InitialCursor.CanonicalCheckpointHash.Span,
                    invalidCanonical, matchingTag, responseReferenceKey));
        }

        var immutableFingerprint = firstHistory.Lookup.RouteLocalSourceFingerprint.ToArray();
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.Accepted,
            (await store.CommitVerifiedHistoryBatchAsync(fixture.RouteKey,
                fixture.FirstPlan.NextCursor, fixture.SecondPlan,
                CancellationToken.None)).Status);
        var afterLaterAppend = await store.LookupRouteHistoryAsync(fixture.RouteKey,
            genesisRequest, CancellationToken.None);
        Assert.Equal(immutableFingerprint,
            afterLaterAppend.Lookup!.RouteLocalSourceFingerprint.ToArray());

        var middle = await store.LookupRouteHistoryAsync(fixture.RouteKey,
            LookupRequest(fixture, fixture.FirstPlan.NextCursor, fixture.FirstPlan),
            CancellationToken.None);
        Assert.Equal(ProductionMailboxRouteHistoryLookupStatus.History, middle.Status);
        Assert.Equal(fixture.SecondPlan.PlanHash.ToArray(),
            middle.Lookup!.NextPlan!.PlanHash.ToArray());
        var head = await store.LookupRouteHistoryAsync(fixture.RouteKey,
            LookupRequest(fixture, fixture.SecondPlan.NextCursor, fixture.SecondPlan),
            CancellationToken.None);
        Assert.Equal(ProductionMailboxRouteHistoryLookupStatus.HeadNoChange, head.Status);

        var returned = afterLaterAppend.Lookup.CanonicalNextBatch.ToArray();
        returned[^1] ^= 1;
        Assert.Equal(fixture.FirstPlan.CanonicalBatch.ToArray(),
            afterLaterAppend.Lookup.CanonicalNextBatch.ToArray());
        var fingerprint = afterLaterAppend.Lookup.RouteLocalSourceFingerprint.ToArray();
        fingerprint[0] ^= 1;
        Assert.Equal(immutableFingerprint,
            afterLaterAppend.Lookup.RouteLocalSourceFingerprint.ToArray());
    }

    [Fact]
    public async Task InMemory_HistoryLookupAheadWrongTupleHighU64AndRevocationFailClosed()
    {
        var store = (IProductionMailboxRouteContinuityStateStore)
            new InMemoryProductionMailboxStateStore();
        var fixture = await AdvancedFixture.CreateAsync(store, 25);
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.Accepted,
            (await store.CommitVerifiedHistoryBatchAsync(fixture.RouteKey,
                fixture.InitialCursor, fixture.FirstPlan, CancellationToken.None)).Status);

        var ahead = await store.LookupRouteHistoryAsync(fixture.RouteKey,
            LookupRequest(fixture, fixture.FirstPlan.NextCursor, fixture.FirstPlan,
                batchSequence: 2), CancellationToken.None);
        Assert.Equal(ProductionMailboxRouteHistoryLookupStatus.Ahead, ahead.Status);
        Assert.Null(ahead.Lookup);

        foreach (var wrong in new[]
                 {
                     LookupRequest(fixture, fixture.InitialCursor, null,
                         checkpointHash: AdvancedFixture.Bytes(17, 32)),
                     LookupRequest(fixture, fixture.InitialCursor, null,
                         routeOriginHash: AdvancedFixture.Bytes(19, 32)),
                     LookupRequest(fixture, fixture.InitialCursor, null,
                         authorizationHash: AdvancedFixture.Bytes(21, 32)),
                     LookupRequest(fixture, fixture.InitialCursor, null,
                         authorizationSequence: 1UL << 63),
                     LookupRequest(fixture, fixture.InitialCursor, null,
                         networkId: AdvancedFixture.Bytes(27, 16)),
                     LookupRequest(fixture, fixture.InitialCursor, null,
                         selectionCommitment: AdvancedFixture.Bytes(29, 32))
                 })
        {
            var mismatch = await store.LookupRouteHistoryAsync(fixture.RouteKey, wrong,
                CancellationToken.None);
            Assert.Equal(ProductionMailboxRouteHistoryLookupStatus.PredecessorMismatch,
                mismatch.Status);
            Assert.Null(mismatch.Lookup);
        }
        Assert.Throws<InvalidDataException>(() => LookupRequest(fixture,
            fixture.InitialCursor, null, batchSequence: ulong.MaxValue));

        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.Accepted,
            (await store.CommitVerifiedOwnerRevocationAsync(fixture.RouteKey,
                fixture.VerifyRevocation(
                    ProductionMailboxRouteContinuityRevocationReason.OwnerRevoked),
                CancellationToken.None)).Status);
        var revoked = await store.LookupRouteHistoryAsync(fixture.RouteKey,
            LookupRequest(fixture, fixture.InitialCursor, null), CancellationToken.None);
        Assert.Equal(ProductionMailboxRouteHistoryLookupStatus.Revoked, revoked.Status);
    }

    [Fact]
    public async Task InMemory_HistoryLookupRejectsGapAndProtectedCorruption()
    {
        var concrete = new InMemoryProductionMailboxStateStore();
        var store = (IProductionMailboxRouteContinuityStateStore)concrete;
        var fixture = await AdvancedFixture.CreateAsync(store, 27);
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.Accepted,
            (await store.CommitVerifiedHistoryBatchAsync(fixture.RouteKey,
                fixture.InitialCursor, fixture.FirstPlan, CancellationToken.None)).Status);
        var all = (Dictionary<string, SortedDictionary<ulong,
            ProductionMailboxProtectedHistoryBatch>>)typeof(InMemoryProductionMailboxStateStore)
            .GetField("routeHistoryBatches", BindingFlags.Instance | BindingFlags.NonPublic)!
            .GetValue(concrete)!;
        var rows = all[Convert.ToHexString(fixture.RouteKey)];
        var original = rows[1]; rows.Remove(1);
        await Assert.ThrowsAsync<InvalidDataException>(() => store.LookupRouteHistoryAsync(
            fixture.RouteKey, LookupRequest(fixture, fixture.InitialCursor, null),
            CancellationToken.None).AsTask());
        rows[1] = original;
        var tag = original.IntegrityTag.ToArray(); tag[0] ^= 1;
        var ctor = typeof(ProductionMailboxProtectedHistoryBatch).GetConstructor(
            BindingFlags.Instance | BindingFlags.NonPublic, null,
            [typeof(byte[]), typeof(byte[])], null)!;
        rows[1] = (ProductionMailboxProtectedHistoryBatch)ctor.Invoke(
            [original.Payload.ToArray(), tag]);
        await Assert.ThrowsAsync<InvalidDataException>(() => store.LookupRouteHistoryAsync(
            fixture.RouteKey, LookupRequest(fixture, fixture.InitialCursor, null),
            CancellationToken.None).AsTask());
    }

    [Fact]
    public async Task InMemory_SealedHistoryAndRevocationCas_ReplayForkAndTerminalExactly()
    {
        var store = (IProductionMailboxRouteContinuityStateStore)
            new InMemoryProductionMailboxStateStore();
        var fixture = await AdvancedFixture.CreateAsync(store, 31);

        var accepted = await store.CommitVerifiedHistoryBatchAsync(
            fixture.RouteKey, fixture.InitialCursor, fixture.FirstPlan, CancellationToken.None);
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.Accepted, accepted.Status);
        Assert.Equal(1UL, accepted.State!.History!.LastCommittedBatchSequence);

        var lostResponseReplay = await store.CommitVerifiedHistoryBatchAsync(
            fixture.RouteKey, fixture.InitialCursor, fixture.FirstPlan, CancellationToken.None);
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.ExactReplay,
            lostResponseReplay.Status);
        var rawReplay = await store.CheckHistoryBatchReplayAsync(fixture.RouteKey, 1,
            fixture.FirstPlan.CanonicalBatch, CancellationToken.None);
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.ExactReplay, rawReplay.Status);

        var changed = fixture.FirstPlan.CanonicalBatch.ToArray();
        changed[^1] ^= 1;
        var fork = await store.CheckHistoryBatchReplayAsync(fixture.RouteKey, 1, changed,
            CancellationToken.None);
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.Conflict, fork.Status);
        var future = await store.CheckHistoryBatchReplayAsync(fixture.RouteKey, 2,
            fixture.FirstPlan.CanonicalBatch, CancellationToken.None);
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.PredecessorMismatch,
            future.Status);

        var verifiedRevocation = fixture.VerifyRevocation(ProductionMailboxRouteContinuityRevocationReason.OwnerRevoked);
        var revoked = await store.CommitVerifiedOwnerRevocationAsync(
            fixture.RouteKey, verifiedRevocation, CancellationToken.None);
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.Accepted, revoked.Status);
        Assert.Equal(1UL, revoked.State!.OwnerRevocationGeneration);
        var revocationReplay = await store.CommitVerifiedOwnerRevocationAsync(
            fixture.RouteKey, verifiedRevocation, CancellationToken.None);
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.ExactReplay,
            revocationReplay.Status);
        var committedHistoryReplayAfterRevocation =
            await store.CommitVerifiedHistoryBatchAsync(fixture.RouteKey,
                fixture.InitialCursor, fixture.FirstPlan, CancellationToken.None);
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.ExactReplay,
            committedHistoryReplayAfterRevocation.Status);
        var conflictingRevocation = fixture.VerifyRevocation(
            ProductionMailboxRouteContinuityRevocationReason.RouteReset);
        var revocationFork = await store.CommitVerifiedOwnerRevocationAsync(
            fixture.RouteKey, conflictingRevocation, CancellationToken.None);
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.Conflict,
            revocationFork.Status);
        var afterRevocation = await store.CommitVerifiedHistoryBatchAsync(
            fixture.RouteKey, fixture.FirstPlan.NextCursor, fixture.SecondPlan,
            CancellationToken.None);
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.Revoked,
            afterRevocation.Status);
    }

    [Fact]
    public async Task InMemory_HistoryAppendPreservesSelectionAndPublicationBytesExactly()
    {
        var concrete = new InMemoryProductionMailboxStateStore();
        var store = (IProductionMailboxRouteContinuityStateStore)concrete;
        var fixture = await AdvancedFixture.CreateAsync(store, 37);
        var current = (await store.GetRouteContinuityStateAsync(fixture.RouteKey,
            CancellationToken.None))!;
        var transition = ProductionMailboxRouteContinuityStateTests.Transition(
            current.CanonicalRouteOriginLkg.ToArray(), current.LocalCommitGeneration,
            current.CurrentAuthorizationHash.ToArray(), current.CurrentAuthorizationSequence,
            39);
        var selected = CopyWithSelection(current, transition.CanonicalSuccessor.ToArray(),
            transition.CanonicalTranscript.ToArray(), transition.TranscriptHash.ToArray());
        var states = (Dictionary<string, ProductionMailboxRouteContinuityStateSnapshot>)
            typeof(InMemoryProductionMailboxStateStore).GetField("routeContinuityStates",
                BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(concrete)!;
        states[Convert.ToHexString(fixture.RouteKey)] = selected;

        var accepted = await store.CommitVerifiedHistoryBatchAsync(fixture.RouteKey,
            fixture.InitialCursor, fixture.FirstPlan, CancellationToken.None);
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.Accepted, accepted.Status);
        Assert.Equal(selected.CanonicalSelectionSuccessor.ToArray(),
            accepted.State!.CanonicalSelectionSuccessor.ToArray());
        Assert.Equal(selected.CanonicalTransitionTranscript.ToArray(),
            accepted.State.CanonicalTransitionTranscript.ToArray());
        Assert.Equal(selected.TransitionTranscriptHash.ToArray(),
            accepted.State.TransitionTranscriptHash.ToArray());
        Assert.Equal(fixture.FirstPlan.FinalArtifacts.CanonicalRouteCertificate.ToArray(),
            accepted.State.CanonicalRouteCertificate.ToArray());
        Assert.Equal(fixture.FirstPlan.FinalArtifacts.CanonicalOwnerAdvertisement.ToArray(),
            accepted.State.CanonicalRouteAuthorization.ToArray());
    }

    [Fact]
    public async Task InMemory_HistoryCapacityRejectsWholeAppendWithoutPartialEviction()
    {
        var limits = new ProductionMailboxOwnerControlStoreLimits(
            MaximumEntriesPerRoute: 4, MaximumEntriesGlobal: 64);
        var store = (IProductionMailboxRouteContinuityStateStore)
            new InMemoryProductionMailboxStateStore(ownerControlLimits: limits);
        var fixture = await AdvancedFixture.CreateAsync(store, 43);
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.Accepted,
            (await store.CommitVerifiedHistoryBatchAsync(fixture.RouteKey,
                fixture.InitialCursor, fixture.FirstPlan, CancellationToken.None)).Status);
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            store.CommitVerifiedHistoryBatchAsync(fixture.RouteKey,
                fixture.FirstPlan.NextCursor, fixture.SecondPlan,
                CancellationToken.None).AsTask());
        var durable = await store.GetRouteContinuityStateAsync(fixture.RouteKey,
            CancellationToken.None);
        Assert.Equal(1UL, durable!.History!.LastCommittedBatchSequence);
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.ExactReplay,
            (await store.CheckHistoryBatchReplayAsync(fixture.RouteKey, 1,
                fixture.FirstPlan.CanonicalBatch, CancellationToken.None)).Status);
    }

    [Fact]
    public async Task InMemory_TerminalRouteGcRequiresHorizonAndNoLiveRefsThenTombstones()
    {
        const ulong now = 1_800_000_000;
        var clock = new MutableClock(DateTimeOffset.FromUnixTimeSeconds(checked((long)now)));
        var concrete = new InMemoryProductionMailboxStateStore(clock);
        var store = (IProductionMailboxRouteContinuityStateStore)concrete;
        var fixture = await AdvancedFixture.CreateAsync(store, 47, nowUnixSeconds: now);
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.Accepted,
            (await store.CommitVerifiedHistoryBatchAsync(fixture.RouteKey,
                fixture.InitialCursor, fixture.FirstPlan, CancellationToken.None)).Status);
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.Accepted,
            (await store.CommitVerifiedOwnerRevocationAsync(fixture.RouteKey,
                fixture.VerifyRevocation(
                    ProductionMailboxRouteContinuityRevocationReason.OwnerRevoked),
                CancellationToken.None)).Status);
        Assert.False(await concrete.TryCollectTerminalRouteAsync(fixture.RouteKey,
            CancellationToken.None));
        clock.Advance(TimeSpan.FromSeconds(400));
        await concrete.StoreLatestOwnerBundleAsync(fixture.RouteKey, new byte[] { 1 }, now,
            CancellationToken.None);
        Assert.False(await concrete.TryCollectTerminalRouteAsync(fixture.RouteKey,
            CancellationToken.None));
        var bundles = (System.Collections.IDictionary)typeof(InMemoryProductionMailboxStateStore)
            .GetField("ownerBundles", BindingFlags.Instance | BindingFlags.NonPublic)!
            .GetValue(concrete)!;
        bundles.Remove(Convert.ToHexString(fixture.RouteKey));

        var manifests = (Dictionary<string, ProductionMailboxProtectedHistoryManifest>)
            typeof(InMemoryProductionMailboxStateStore).GetField("routeHistoryManifests",
                BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(concrete)!;
        var routeKey = Convert.ToHexString(fixture.RouteKey);
        var original = manifests[routeKey];
        var corruptTag = original.IntegrityTag.ToArray(); corruptTag[0] ^= 1;
        var ctor = typeof(ProductionMailboxProtectedHistoryManifest).GetConstructor(
            BindingFlags.Instance | BindingFlags.NonPublic, null,
            [typeof(byte[]), typeof(byte[])], null)!;
        manifests[routeKey] = (ProductionMailboxProtectedHistoryManifest)ctor.Invoke(
            [original.Payload.ToArray(), corruptTag]);
        await Assert.ThrowsAsync<InvalidDataException>(() => concrete
            .TryCollectTerminalRouteAsync(fixture.RouteKey, CancellationToken.None).AsTask());
        var routeStates = (System.Collections.IDictionary)
            typeof(InMemoryProductionMailboxStateStore).GetField("routeContinuityStates",
                BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(concrete)!;
        Assert.True(routeStates.Contains(routeKey));
        manifests[routeKey] = original;

        Assert.True(await concrete.TryCollectTerminalRouteAsync(fixture.RouteKey,
            CancellationToken.None));
        Assert.Null(await store.GetRouteContinuityStateAsync(fixture.RouteKey,
            CancellationToken.None));
        Assert.Null(await store.GetRestoredGenesisAsync(fixture.RouteKey,
            CancellationToken.None));
        var owner = (IProductionMailboxOwnerControlStateStore)concrete;
        var replay = await owner.PrepareOwnerEnrollmentAsync(fixture.RouteKey,
            fixture.EnrollmentRequestId, fixture.EnrollmentRequestHash,
            fixture.GenesisPlan.CanonicalDelegationHash,
            fixture.GenesisIntentHash, fixture.SourceArtifactClosureHash,
            fixture.OwnerControlKeyToken, now + 401, CancellationToken.None);
        Assert.Equal(ProductionMailboxOwnerEnrollmentStatus.Revoked, replay.Status);

        var tombstones = (Dictionary<string, ProductionMailboxProtectedRouteTombstone>)
            typeof(InMemoryProductionMailboxStateStore).GetField("routeHistoryTombstones",
                BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(concrete)!;
        var tombstone = tombstones[routeKey];
        var badTombstoneTag = tombstone.IntegrityTag.ToArray(); badTombstoneTag[0] ^= 1;
        var tombstoneCtor = typeof(ProductionMailboxProtectedRouteTombstone).GetConstructor(
            BindingFlags.Instance | BindingFlags.NonPublic, null,
            [typeof(byte[]), typeof(byte[])], null)!;
        tombstones[routeKey] = (ProductionMailboxProtectedRouteTombstone)tombstoneCtor.Invoke(
            [tombstone.Payload.ToArray(), badTombstoneTag]);
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            store.GetRouteContinuityStateAsync(fixture.RouteKey,
                CancellationToken.None).AsTask());
    }

    [Fact]
    public async Task RawHistoryReplay_PreflightsBoundsBeforeAllocationOrStoreAccess()
    {
        var store = (IProductionMailboxRouteContinuityStateStore)
            new InMemoryProductionMailboxStateStore();
        var key = AdvancedFixture.Bytes(83, 32);
        var oversized = new byte[8_394_305];
        var before = GC.GetAllocatedBytesForCurrentThread();
        await Assert.ThrowsAsync<InvalidDataException>(() => store.CheckHistoryBatchReplayAsync(
            key, 1, oversized, CancellationToken.None).AsTask());
        Assert.InRange(GC.GetAllocatedBytesForCurrentThread() - before, 0, 512 * 1024);
        await Assert.ThrowsAsync<InvalidDataException>(() => store.CheckHistoryBatchReplayAsync(
            key, 0, new byte[64], CancellationToken.None).AsTask());
        await Assert.ThrowsAsync<InvalidDataException>(() => store.CheckHistoryBatchReplayAsync(
            key, ProductionMailboxRouteContinuityConstants.MaximumHistoryBatchCount + 1,
            new byte[64], CancellationToken.None).AsTask());
    }

    [Fact]
    public async Task InMemory_RawReplayFreezesKeyAndBatchBeforeWaiting()
    {
        var concrete = new InMemoryProductionMailboxStateStore();
        var store = (IProductionMailboxRouteContinuityStateStore)concrete;
        var fixture = await AdvancedFixture.CreateAsync(store, 71);
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.Accepted,
            (await store.CommitVerifiedHistoryBatchAsync(fixture.RouteKey,
                fixture.InitialCursor, fixture.FirstPlan, CancellationToken.None)).Status);
        var gate = (SemaphoreSlim)typeof(InMemoryProductionMailboxStateStore)
            .GetField("gate", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(concrete)!;
        await gate.WaitAsync();
        var key = fixture.RouteKey.ToArray();
        var batch = fixture.FirstPlan.CanonicalBatch.ToArray();
        var pending = store.CheckHistoryBatchReplayAsync(key, 1, batch,
            CancellationToken.None).AsTask();
        key[0] ^= 1;
        batch[^1] ^= 1;
        gate.Release();
        var result = await pending;
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.ExactReplay, result.Status);
    }

    [Fact]
    public async Task PostgreSql_HistoryLookupColdRestartAppendRaceGapAndCorruption()
    {
        var connectionString = Environment.GetEnvironmentVariable("DEEP_TEST_POSTGRES");
        if (string.IsNullOrWhiteSpace(connectionString)) return;
        await using var database = await PostgresTestDatabase.CreateAsync(connectionString);
        var integrityKey = AdvancedFixture.Bytes(238, 32);
        var firstStore = (IProductionMailboxRouteContinuityStateStore)
            new PostgreSqlProductionMailboxStateStore(database.ConnectionString, integrityKey);
        var fixture = await AdvancedFixture.CreateAsync(firstStore, 87,
            nowUnixSeconds: checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds()));
        var genesisRequest = LookupRequest(fixture, fixture.InitialCursor, null);

        var otherStore = (IProductionMailboxRouteContinuityStateStore)
            new PostgreSqlProductionMailboxStateStore(database.ConnectionString, integrityKey);
        var lookupTask = firstStore.LookupRouteHistoryAsync(fixture.RouteKey,
            genesisRequest, CancellationToken.None).AsTask();
        var appendTask = otherStore.CommitVerifiedHistoryBatchAsync(fixture.RouteKey,
            fixture.InitialCursor, fixture.FirstPlan, CancellationToken.None).AsTask();
        await Task.WhenAll(lookupTask, appendTask);
        var racedLookup = await lookupTask;
        var racedAppend = await appendTask;
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.Accepted,
            racedAppend.Status);
        Assert.Contains(racedLookup.Status, new[]
        {
            ProductionMailboxRouteHistoryLookupStatus.HeadNoChange,
            ProductionMailboxRouteHistoryLookupStatus.History
        });

        var restarted = (IProductionMailboxRouteContinuityStateStore)
            new PostgreSqlProductionMailboxStateStore(database.ConnectionString, integrityKey);
        var first = await restarted.LookupRouteHistoryAsync(fixture.RouteKey,
            genesisRequest, CancellationToken.None);
        Assert.Equal(ProductionMailboxRouteHistoryLookupStatus.History, first.Status);
        Assert.Equal(fixture.FirstPlan.PlanHash.ToArray(),
            first.Lookup!.NextPlan!.PlanHash.ToArray());
        var immutableFingerprint = first.Lookup.RouteLocalSourceFingerprint.ToArray();
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.Accepted,
            (await restarted.CommitVerifiedHistoryBatchAsync(fixture.RouteKey,
                fixture.FirstPlan.NextCursor, fixture.SecondPlan,
                CancellationToken.None)).Status);
        var afterAppend = await otherStore.LookupRouteHistoryAsync(fixture.RouteKey,
            genesisRequest, CancellationToken.None);
        Assert.Equal(immutableFingerprint,
            afterAppend.Lookup!.RouteLocalSourceFingerprint.ToArray());
        Assert.Equal(ProductionMailboxRouteHistoryLookupStatus.History,
            (await restarted.LookupRouteHistoryAsync(fixture.RouteKey,
                LookupRequest(fixture, fixture.FirstPlan.NextCursor, fixture.FirstPlan),
                CancellationToken.None)).Status);
        Assert.Equal(ProductionMailboxRouteHistoryLookupStatus.HeadNoChange,
            (await restarted.LookupRouteHistoryAsync(fixture.RouteKey,
                LookupRequest(fixture, fixture.SecondPlan.NextCursor, fixture.SecondPlan),
                CancellationToken.None)).Status);
        Assert.Equal(ProductionMailboxRouteHistoryLookupStatus.Ahead,
            (await restarted.LookupRouteHistoryAsync(fixture.RouteKey,
                LookupRequest(fixture, fixture.SecondPlan.NextCursor, fixture.SecondPlan,
                    batchSequence: 3), CancellationToken.None)).Status);
        Assert.Equal(ProductionMailboxRouteHistoryLookupStatus.PredecessorMismatch,
            (await restarted.LookupRouteHistoryAsync(fixture.RouteKey,
                LookupRequest(fixture, fixture.InitialCursor, null,
                    checkpointHash: AdvancedFixture.Bytes(85, 32)),
                CancellationToken.None)).Status);
        Assert.Equal(ProductionMailboxRouteHistoryLookupStatus.PredecessorMismatch,
            (await restarted.LookupRouteHistoryAsync(fixture.RouteKey,
                LookupRequest(fixture, fixture.InitialCursor, null,
                    authorizationSequence: (1UL << 63) + 7),
                CancellationToken.None)).Status);

        var sequence = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(sequence, 1);
        byte[] payload; byte[] tag;
        await using (var connection = new NpgsqlConnection(database.ConnectionString))
        {
            await connection.OpenAsync();
            await using (var read = new NpgsqlCommand("""
                SELECT protected_payload,integrity_tag
                FROM production_mailbox_route_history_batch_v1
                WHERE route_state_key=@route AND batch_sequence=@sequence
                """, connection))
            {
                read.Parameters.AddWithValue("route", fixture.RouteKey);
                read.Parameters.AddWithValue("sequence", sequence);
                await using var reader = await read.ExecuteReaderAsync();
                Assert.True(await reader.ReadAsync());
                payload = reader.GetFieldValue<byte[]>(0);
                tag = reader.GetFieldValue<byte[]>(1);
            }
            await using (var delete = new NpgsqlCommand("""
                DELETE FROM production_mailbox_route_history_batch_v1
                WHERE route_state_key=@route AND batch_sequence=@sequence
                """, connection))
            {
                delete.Parameters.AddWithValue("route", fixture.RouteKey);
                delete.Parameters.AddWithValue("sequence", sequence);
                Assert.Equal(1, await delete.ExecuteNonQueryAsync());
            }
        }
        await Assert.ThrowsAsync<InvalidDataException>(() => restarted.LookupRouteHistoryAsync(
            fixture.RouteKey, genesisRequest, CancellationToken.None).AsTask());
        await using (var connection = new NpgsqlConnection(database.ConnectionString))
        {
            await connection.OpenAsync();
            await using var insert = new NpgsqlCommand("""
                INSERT INTO production_mailbox_route_history_batch_v1(
                    route_state_key,batch_sequence,protected_payload,integrity_tag)
                VALUES(@route,@sequence,@payload,@tag)
                """, connection);
            insert.Parameters.AddWithValue("route", fixture.RouteKey);
            insert.Parameters.AddWithValue("sequence", sequence);
            insert.Parameters.AddWithValue("payload", payload);
            insert.Parameters.AddWithValue("tag", tag);
            Assert.Equal(1, await insert.ExecuteNonQueryAsync());
        }
        tag[0] ^= 1;
        await using (var connection = new NpgsqlConnection(database.ConnectionString))
        {
            await connection.OpenAsync();
            await using var update = new NpgsqlCommand("""
                UPDATE production_mailbox_route_history_batch_v1 SET integrity_tag=@tag
                WHERE route_state_key=@route AND batch_sequence=@sequence
                """, connection);
            update.Parameters.AddWithValue("tag", tag);
            update.Parameters.AddWithValue("route", fixture.RouteKey);
            update.Parameters.AddWithValue("sequence", sequence);
            Assert.Equal(1, await update.ExecuteNonQueryAsync());
        }
        await Assert.ThrowsAsync<InvalidDataException>(() => restarted.LookupRouteHistoryAsync(
            fixture.RouteKey, genesisRequest, CancellationToken.None).AsTask());
    }

    [Fact]
    public async Task PostgreSql_SealedHistoryAndRevocationSurviveRestartAndConcurrentForks()
    {
        var connectionString = Environment.GetEnvironmentVariable("DEEP_TEST_POSTGRES");
        if (string.IsNullOrWhiteSpace(connectionString)) return;
        await using var database = await PostgresTestDatabase.CreateAsync(connectionString);
        var store = (IProductionMailboxRouteContinuityStateStore)
            new PostgreSqlProductionMailboxStateStore(database.ConnectionString, AdvancedFixture.Bytes(240, 32));
        var fixture = await AdvancedFixture.CreateAsync(store, 91,
            nowUnixSeconds: checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds()));

        var accepted = await store.CommitVerifiedHistoryBatchAsync(
            fixture.RouteKey, fixture.InitialCursor, fixture.FirstPlan, CancellationToken.None);
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.Accepted, accepted.Status);

        var restarted = (IProductionMailboxRouteContinuityStateStore)
            new PostgreSqlProductionMailboxStateStore(database.ConnectionString, AdvancedFixture.Bytes(240, 32));
        var durable = await restarted.GetRouteContinuityStateAsync(
            fixture.RouteKey, CancellationToken.None);
        Assert.NotNull(durable?.History);
        Assert.Equal(fixture.FirstPlan.CanonicalBatchHash.ToArray(),
            durable.History!.LastCommittedBatchHash.ToArray());
        var rawReplay = await restarted.CheckHistoryBatchReplayAsync(fixture.RouteKey, 1,
            fixture.FirstPlan.CanonicalBatch, CancellationToken.None);
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.ExactReplay, rawReplay.Status);
        var planReplay = await restarted.CommitVerifiedHistoryBatchAsync(
            fixture.RouteKey, fixture.InitialCursor, fixture.FirstPlan, CancellationToken.None);
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.ExactReplay, planReplay.Status);

        var forkPlan = fixture.AuthorCompetingSecondPlan();
        var storeB = (IProductionMailboxRouteContinuityStateStore)
            new PostgreSqlProductionMailboxStateStore(database.ConnectionString, AdvancedFixture.Bytes(240, 32));
        var results = await Task.WhenAll(
            restarted.CommitVerifiedHistoryBatchAsync(fixture.RouteKey,
                fixture.FirstPlan.NextCursor, fixture.SecondPlan, CancellationToken.None).AsTask(),
            storeB.CommitVerifiedHistoryBatchAsync(fixture.RouteKey,
                fixture.FirstPlan.NextCursor, forkPlan, CancellationToken.None).AsTask());
        Assert.Single(results, static result =>
            result.Status == ProductionMailboxRouteContinuityCommitStatus.Accepted);
        Assert.Single(results, static result => result.Status is
            ProductionMailboxRouteContinuityCommitStatus.Conflict or
            ProductionMailboxRouteContinuityCommitStatus.PredecessorMismatch);

        var current = await restarted.GetRouteContinuityStateAsync(
            fixture.RouteKey, CancellationToken.None);
        Assert.Equal(2UL, current!.History!.LastCommittedBatchSequence);
        var oldReplay = await restarted.CheckHistoryBatchReplayAsync(fixture.RouteKey, 1,
            fixture.FirstPlan.CanonicalBatch, CancellationToken.None);
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.Rollback, oldReplay.Status);

        var revocation = fixture.VerifyRevocation(
            ProductionMailboxRouteContinuityRevocationReason.OwnerRevoked);
        var revoked = await restarted.CommitVerifiedOwnerRevocationAsync(
            fixture.RouteKey, revocation, CancellationToken.None);
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.Accepted, revoked.Status);
        var afterRestart = (IProductionMailboxRouteContinuityStateStore)
            new PostgreSqlProductionMailboxStateStore(database.ConnectionString, AdvancedFixture.Bytes(240, 32));
        var replay = await afterRestart.CommitVerifiedOwnerRevocationAsync(
            fixture.RouteKey, revocation, CancellationToken.None);
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.ExactReplay, replay.Status);

        var high = await AdvancedFixture.CreateAsync(restarted, 101, highCounters: true,
            nowUnixSeconds: fixture.NowUnixSeconds,
            sourceArtifactClosureHash: fixture.SourceArtifactClosureHash);
        var highAccepted = await restarted.CommitVerifiedHistoryBatchAsync(high.RouteKey,
            high.InitialCursor, high.FirstPlan, CancellationToken.None);
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.Accepted, highAccepted.Status);
        var highDurable = await restarted.GetRouteContinuityStateAsync(
            high.RouteKey, CancellationToken.None);
        Assert.True(highDurable!.History!.CurrentAuthorityGeneration > long.MaxValue);
        Assert.True(highDurable.History.CurrentRevocationGeneration > long.MaxValue);
    }

    [Fact]
    public async Task PostgreSql_HistorySplitOrCanonicalCorruptionFailsClosed()
    {
        var connectionString = Environment.GetEnvironmentVariable("DEEP_TEST_POSTGRES");
        if (string.IsNullOrWhiteSpace(connectionString)) return;
        await using var database = await PostgresTestDatabase.CreateAsync(connectionString);
        var store = (IProductionMailboxRouteContinuityStateStore)
            new PostgreSqlProductionMailboxStateStore(database.ConnectionString, AdvancedFixture.Bytes(240, 32));
        var fixture = await AdvancedFixture.CreateAsync(store, 141,
            nowUnixSeconds: checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds()));
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.Accepted,
            (await store.CommitVerifiedHistoryBatchAsync(fixture.RouteKey,
                fixture.InitialCursor, fixture.FirstPlan, CancellationToken.None)).Status);
        var durable = await store.GetRouteContinuityStateAsync(
            fixture.RouteKey, CancellationToken.None);

        await using (var connection = new NpgsqlConnection(database.ConnectionString))
        {
            await connection.OpenAsync();
            await using var command = new NpgsqlCommand(
                "UPDATE production_mailbox_route_continuity_v2 SET history_network_id=NULL WHERE route_state_key=@key",
                connection);
            command.Parameters.AddWithValue("key", fixture.RouteKey);
            Assert.Equal(1, await command.ExecuteNonQueryAsync());
        }
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            store.GetRouteContinuityStateAsync(fixture.RouteKey, CancellationToken.None).AsTask());

        var corruptedCheckpoint = durable!.History!.CanonicalCheckpoint.ToArray();
        corruptedCheckpoint[100] ^= 1;
        await using (var connection = new NpgsqlConnection(database.ConnectionString))
        {
            await connection.OpenAsync();
            await using var command = new NpgsqlCommand(
                "UPDATE production_mailbox_route_continuity_v2 SET history_network_id=@network,canonical_history_checkpoint=@checkpoint WHERE route_state_key=@key",
                connection);
            command.Parameters.AddWithValue("network", durable.History.NetworkId.ToArray());
            command.Parameters.AddWithValue("checkpoint", corruptedCheckpoint);
            command.Parameters.AddWithValue("key", fixture.RouteKey);
            Assert.Equal(1, await command.ExecuteNonQueryAsync());
        }
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            store.GetRouteContinuityStateAsync(fixture.RouteKey, CancellationToken.None).AsTask());
    }

    [Fact]
    public async Task PostgreSql_ColdCatalogAndCurrentRouteArtifactsRejectSplitWithValidSelection()
    {
        var connectionString = Environment.GetEnvironmentVariable("DEEP_TEST_POSTGRES");
        if (string.IsNullOrWhiteSpace(connectionString)) return;
        await using var database = await PostgresTestDatabase.CreateAsync(connectionString);
        var integrityKey = AdvancedFixture.Bytes(244, 32);
        var store = (IProductionMailboxRouteContinuityStateStore)
            new PostgreSqlProductionMailboxStateStore(database.ConnectionString, integrityKey);
        var fixture = await AdvancedFixture.CreateAsync(store, 151,
            nowUnixSeconds: checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds()));
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.Accepted,
            (await store.CommitVerifiedHistoryBatchAsync(fixture.RouteKey,
                fixture.InitialCursor, fixture.FirstPlan, CancellationToken.None)).Status);
        var durable = (await store.GetRouteContinuityStateAsync(fixture.RouteKey,
            CancellationToken.None))!;
        var transition = ProductionMailboxRouteContinuityStateTests.Transition(
            durable.CanonicalRouteOriginLkg.ToArray(), durable.LocalCommitGeneration,
            durable.CurrentAuthorizationHash.ToArray(), durable.CurrentAuthorizationSequence,
            157);
        var successor = transition.CanonicalSuccessor.ToArray();
        var transcript = transition.CanonicalTranscript.ToArray();
        var transcriptHash = transition.TranscriptHash.ToArray();

        await using var connection = new NpgsqlConnection(database.ConnectionString);
        await connection.OpenAsync();
        await ExecuteAsync("""
            UPDATE production_mailbox_route_continuity_v2
            SET canonical_selection_successor=@value,
                canonical_transition_transcript=@transcript,
                transition_transcript_hash=@transcriptHash
            WHERE route_state_key=@key
            """, successor, transcript, transcriptHash);
        var selected = await store.GetRouteContinuityStateAsync(fixture.RouteKey,
            CancellationToken.None);
        Assert.Equal(successor, selected!.CanonicalSelectionSuccessor.ToArray());

        foreach (var mutation in new[]
                 {
                     ("canonical_route_certificate", Flip(
                         durable.CanonicalRouteCertificate.ToArray())),
                     ("canonical_route_authorization", Flip(
                         durable.CanonicalRouteAuthorization.ToArray())),
                     ("canonical_revocation_checkpoint", AdvancedFixture.Bytes(161, 320)),
                     ("canonical_transition_context", AdvancedFixture.Bytes(163, 408))
                 })
        {
            await ExecuteColumnAsync(mutation.Item1, mutation.Item2);
            await Assert.ThrowsAsync<InvalidDataException>(() =>
                store.GetRouteContinuityStateAsync(fixture.RouteKey,
                    CancellationToken.None).AsTask());
            var restored = mutation.Item1 switch
            {
                "canonical_route_certificate" => durable.CanonicalRouteCertificate.ToArray(),
                "canonical_route_authorization" => durable.CanonicalRouteAuthorization.ToArray(),
                "canonical_revocation_checkpoint" => [],
                _ => []
            };
            await ExecuteColumnAsync(mutation.Item1, restored);
        }

        byte[] protectedBatch;
        await using (var read = new NpgsqlCommand("""
            SELECT protected_payload FROM production_mailbox_route_history_batch_v1
            WHERE route_state_key=@key
            """, connection))
        {
            read.Parameters.AddWithValue("key", fixture.RouteKey);
            protectedBatch = (byte[])(await read.ExecuteScalarAsync())!;
        }
        await using (var corrupt = new NpgsqlCommand("""
            UPDATE production_mailbox_route_history_batch_v1
            SET protected_payload=@payload WHERE route_state_key=@key
            """, connection))
        {
            corrupt.Parameters.AddWithValue("key", fixture.RouteKey);
            corrupt.Parameters.AddWithValue("payload", Flip(protectedBatch));
            Assert.Equal(1, await corrupt.ExecuteNonQueryAsync());
        }
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            store.GetRouteContinuityStateAsync(fixture.RouteKey,
                CancellationToken.None).AsTask());

        async ValueTask ExecuteColumnAsync(string column, byte[] value)
        {
            if (column is not ("canonical_route_certificate" or
                "canonical_route_authorization" or "canonical_revocation_checkpoint" or
                "canonical_transition_context"))
                throw new InvalidOperationException("Unexpected test column.");
            await using var command = new NpgsqlCommand($"""
                UPDATE production_mailbox_route_continuity_v2 SET {column}=@value
                WHERE route_state_key=@key
                """, connection);
            command.Parameters.AddWithValue("key", fixture.RouteKey);
            command.Parameters.AddWithValue("value", value);
            Assert.Equal(1, await command.ExecuteNonQueryAsync());
        }

        async ValueTask ExecuteAsync(string sql, byte[] value, byte[] transcriptBytes,
            byte[] transcriptHashBytes)
        {
            await using var command = new NpgsqlCommand(sql, connection);
            command.Parameters.AddWithValue("key", fixture.RouteKey);
            command.Parameters.AddWithValue("value", value);
            command.Parameters.AddWithValue("transcript", transcriptBytes);
            command.Parameters.AddWithValue("transcriptHash", transcriptHashBytes);
            Assert.Equal(1, await command.ExecuteNonQueryAsync());
        }

        static byte[] Flip(byte[] value)
        {
            value[^1] ^= 1;
            return value;
        }
    }

    [Fact]
    public async Task PostgreSql_HistoryCapacityRollsBackWholeAppendAndRetainsColdHead()
    {
        var connectionString = Environment.GetEnvironmentVariable("DEEP_TEST_POSTGRES");
        if (string.IsNullOrWhiteSpace(connectionString)) return;
        await using var database = await PostgresTestDatabase.CreateAsync(connectionString);
        var limits = new ProductionMailboxOwnerControlStoreLimits(
            MaximumEntriesPerRoute: 4, MaximumEntriesGlobal: 64);
        var integrityKey = AdvancedFixture.Bytes(246, 32);
        var store = (IProductionMailboxRouteContinuityStateStore)
            new PostgreSqlProductionMailboxStateStore(database.ConnectionString,
                integrityKey, limits);
        var fixture = await AdvancedFixture.CreateAsync(store, 171,
            nowUnixSeconds: checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds()));
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.Accepted,
            (await store.CommitVerifiedHistoryBatchAsync(fixture.RouteKey,
                fixture.InitialCursor, fixture.FirstPlan, CancellationToken.None)).Status);
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            store.CommitVerifiedHistoryBatchAsync(fixture.RouteKey,
                fixture.FirstPlan.NextCursor, fixture.SecondPlan,
                CancellationToken.None).AsTask());
        var restarted = (IProductionMailboxRouteContinuityStateStore)
            new PostgreSqlProductionMailboxStateStore(database.ConnectionString,
                integrityKey, limits);
        var durable = await restarted.GetRouteContinuityStateAsync(fixture.RouteKey,
            CancellationToken.None);
        Assert.Equal(1UL, durable!.History!.LastCommittedBatchSequence);
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.ExactReplay,
            (await restarted.CheckHistoryBatchReplayAsync(fixture.RouteKey, 1,
                fixture.FirstPlan.CanonicalBatch, CancellationToken.None)).Status);
    }

    [Fact]
    public async Task PostgreSql_HistoryCommitFaultsRollbackEveryDurableBoundary()
    {
        var connectionString = Environment.GetEnvironmentVariable("DEEP_TEST_POSTGRES");
        if (string.IsNullOrWhiteSpace(connectionString)) return;
        await using var database = await PostgresTestDatabase.CreateAsync(connectionString);
        var integrityKey = AdvancedFixture.Bytes(248, 32);
        byte[]? source = null;
        var variant = (byte)181;
        foreach (var point in Enum.GetValues<ProductionMailboxRouteHistoryCommitFaultPoint>()
                     .Where(value => value != ProductionMailboxRouteHistoryCommitFaultPoint.None))
        {
            var concrete = new PostgreSqlProductionMailboxStateStore(
                database.ConnectionString, integrityKey);
            var store = (IProductionMailboxRouteContinuityStateStore)concrete;
            var fixture = await AdvancedFixture.CreateAsync(store, variant++,
                nowUnixSeconds: checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds()),
                sourceArtifactClosureHash: source);
            source ??= fixture.SourceArtifactClosureHash;
            concrete.RouteHistoryCommitFaultPoint = point;
            await Assert.ThrowsAsync<IOException>(() =>
                store.CommitVerifiedHistoryBatchAsync(fixture.RouteKey,
                    fixture.InitialCursor, fixture.FirstPlan,
                    CancellationToken.None).AsTask());
            var restarted = (IProductionMailboxRouteContinuityStateStore)
                new PostgreSqlProductionMailboxStateStore(database.ConnectionString,
                    integrityKey);
            var durable = await restarted.GetRouteContinuityStateAsync(fixture.RouteKey,
                CancellationToken.None);
            Assert.Equal(0UL, durable!.History!.LastCommittedBatchSequence);
            await AssertHistoryRowsAsync(database.ConnectionString, fixture.RouteKey,
                batches: 0, checkpoints: 1);
            Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.Accepted,
                (await restarted.CommitVerifiedHistoryBatchAsync(fixture.RouteKey,
                    fixture.InitialCursor, fixture.FirstPlan,
                    CancellationToken.None)).Status);
        }
    }

    [Fact]
    public async Task PostgreSql_TerminalRouteGcRollsBackRestartsAndRejectsTamper()
    {
        var connectionString = Environment.GetEnvironmentVariable("DEEP_TEST_POSTGRES");
        if (string.IsNullOrWhiteSpace(connectionString)) return;
        await using var database = await PostgresTestDatabase.CreateAsync(connectionString);
        var integrityKey = AdvancedFixture.Bytes(250, 32);
        var concrete = new PostgreSqlProductionMailboxStateStore(
            database.ConnectionString, integrityKey);
        var store = (IProductionMailboxRouteContinuityStateStore)concrete;
        var now = checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        var fixture = await AdvancedFixture.CreateAsync(store, 201,
            nowUnixSeconds: now, delegationLifetimeSeconds: 4);
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.Accepted,
            (await store.CommitVerifiedHistoryBatchAsync(fixture.RouteKey,
                fixture.InitialCursor, fixture.FirstPlan, CancellationToken.None)).Status);
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.Accepted,
            (await store.CommitVerifiedOwnerRevocationAsync(fixture.RouteKey,
                fixture.VerifyRevocation(
                    ProductionMailboxRouteContinuityRevocationReason.OwnerRevoked),
                CancellationToken.None)).Status);
        Assert.False(await concrete.TryCollectTerminalRouteAsync(fixture.RouteKey,
            CancellationToken.None));
        await Task.Delay(TimeSpan.FromSeconds(5));
        await concrete.StoreLatestOwnerBundleAsync(fixture.RouteKey, new byte[] { 1 }, now,
            CancellationToken.None);
        Assert.False(await concrete.TryCollectTerminalRouteAsync(fixture.RouteKey,
            CancellationToken.None));
        await using (var connection = new NpgsqlConnection(database.ConnectionString))
        {
            await connection.OpenAsync();
            await using var delete = new NpgsqlCommand(
                "DELETE FROM production_mailbox_owner_route_state WHERE route_state_key=@route",
                connection);
            delete.Parameters.AddWithValue("route", fixture.RouteKey);
            Assert.Equal(1, await delete.ExecuteNonQueryAsync());
        }
        concrete.ThrowAfterRouteTombstoneInsertOnce = true;
        await Assert.ThrowsAsync<IOException>(() => concrete.TryCollectTerminalRouteAsync(
            fixture.RouteKey, CancellationToken.None).AsTask());
        var restarted = new PostgreSqlProductionMailboxStateStore(database.ConnectionString,
            integrityKey);
        var restartedState = (IProductionMailboxRouteContinuityStateStore)restarted;
        Assert.NotNull(await restartedState.GetRouteContinuityStateAsync(fixture.RouteKey,
            CancellationToken.None));
        Assert.True(await restarted.TryCollectTerminalRouteAsync(fixture.RouteKey,
            CancellationToken.None));
        Assert.Null(await restartedState.GetRouteContinuityStateAsync(fixture.RouteKey,
            CancellationToken.None));
        Assert.Null(await restartedState.GetRestoredGenesisAsync(fixture.RouteKey,
            CancellationToken.None));
        await AssertHistoryRowsAsync(database.ConnectionString, fixture.RouteKey,
            batches: 0, checkpoints: 0, manifests: 0, tombstones: 1);

        await using (var connection = new NpgsqlConnection(database.ConnectionString))
        {
            await connection.OpenAsync();
            await using var corrupt = new NpgsqlCommand("""
                UPDATE production_mailbox_route_history_tombstone_v1
                SET integrity_tag=set_byte(integrity_tag,0,get_byte(integrity_tag,0)#1)
                WHERE route_state_key=@route
                """, connection);
            corrupt.Parameters.AddWithValue("route", fixture.RouteKey);
            Assert.Equal(1, await corrupt.ExecuteNonQueryAsync());
        }
        var corruptRestart = (IProductionMailboxRouteContinuityStateStore)
            new PostgreSqlProductionMailboxStateStore(database.ConnectionString, integrityKey);
        await Assert.ThrowsAsync<InvalidDataException>(() => corruptRestart
            .GetRouteContinuityStateAsync(fixture.RouteKey, CancellationToken.None).AsTask());
    }

    private static async ValueTask AssertHistoryRowsAsync(string connectionString,
        byte[] route, int batches, int checkpoints, int manifests = 1, int tombstones = 0)
    {
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();
        foreach (var item in new[]
                 {
                     ("production_mailbox_route_history_manifest_v1", manifests),
                     ("production_mailbox_route_history_batch_v1", batches),
                     ("production_mailbox_route_history_checkpoint_v1", checkpoints),
                     ("production_mailbox_route_history_tombstone_v1", tombstones)
                 })
        {
            await using var command = new NpgsqlCommand(
                $"SELECT count(*) FROM {item.Item1} WHERE route_state_key=@route", connection);
            command.Parameters.AddWithValue("route", route);
            Assert.Equal(item.Item2, Convert.ToInt32(await command.ExecuteScalarAsync()));
        }
    }

    private sealed class MutableClock(DateTimeOffset value) : TimeProvider
    {
        private DateTimeOffset current = value;
        public override DateTimeOffset GetUtcNow() => current;
        internal void Advance(TimeSpan delta) => current += delta;
    }

    private static ProductionMailboxRouteContinuityStateSnapshot CopyWithSelection(
        ProductionMailboxRouteContinuityStateSnapshot current, byte[] successor,
        byte[] transcript, byte[] transcriptHash) => new(
            current.RouteStateKey.ToArray(), current.CanonicalRouteOriginLkg.ToArray(),
            current.RouteOriginLkgHash.ToArray(), current.LocalCommitGeneration,
            current.CurrentAuthorizationKind, current.CurrentAuthorizationHash.ToArray(),
            current.CurrentAuthorizationSequence, current.CanonicalRouteCertificate.ToArray(),
            current.CanonicalRouteAuthorization.ToArray(),
            current.CanonicalRevocationCheckpoint.ToArray(),
            current.CanonicalTransitionContext.ToArray(), successor, transcript, transcriptHash,
            current.DelegationSequence, current.CanonicalDelegation.ToArray(),
            current.CanonicalDelegationHash.ToArray(),
            current.CanonicalDelegationAcceptance.ToArray(),
            current.CanonicalDelegationAcceptanceHash.ToArray(),
            current.OwnerRevocationGeneration, current.CanonicalOwnerRevocation.ToArray(),
            current.CanonicalOwnerRevocationHash.ToArray(), current.History);

    private static ProductionMailboxRouteHistoryLookupRequest LookupRequest(
        AdvancedFixture fixture,
        VerifiedProductionMailboxRouteHistoryCursor cursor,
        ProductionMailboxRouteHistoryBatchCommitPlan? producingPlan,
        ulong? batchSequence = null,
        byte[]? checkpointHash = null,
        byte[]? routeOriginHash = null,
        ulong? authorizationSequence = null,
        byte[]? authorizationHash = null,
        byte[]? networkId = null,
        byte[]? selectionCommitment = null)
    {
        var delegation = fixture.Enrollment.Delegation;
        var durable = producingPlan?.NextDurableRouteState;
        return new(
            networkId ?? delegation.NetworkId.ToArray(),
            delegation.MailboxOwnerEd25519PublicKey,
            delegation.RouteDomainHash,
            selectionCommitment ?? delegation.SelectionInputCommitment.ToArray(),
            routeOriginHash ?? (durable?.CanonicalRouteOriginLkgHash.ToArray() ??
                cursor.ToProtectedRestoreContext().CurrentRouteOriginLkgHash.ToArray()),
            checkpointHash ?? cursor.CanonicalCheckpointHash.ToArray(),
            batchSequence ?? cursor.LastCommittedBatchSequence,
            durable?.AuthorizationKind ?? delegation.AnchorAuthorizationKind,
            authorizationSequence ?? (durable?.AuthorizationSequence ??
                delegation.AnchorRouteAuthorizationSequence),
            authorizationHash ?? (durable?.CanonicalAuthorizationHash.ToArray() ??
                delegation.AnchorCanonicalRouteAuthorizationHash.ToArray()));
    }

    private static IReadOnlyList<byte[]> InvalidHistoryReferences(byte[] valid)
    {
        var result = new List<byte[]>(5);
        var reserved = valid.ToArray();
        reserved[6] = 1;
        result.Add(reserved);

        var sameSequence = valid.ToArray();
        sameSequence.AsSpan(16, 8).Clear();
        result.Add(sameSequence);

        var shortPayload = valid.ToArray();
        BinaryPrimitives.WriteUInt32BigEndian(shortPayload.AsSpan(24, 4),
            ProductionMailboxProtectedHistoryResponseReference.MinimumPayloadLength - 1);
        result.Add(shortPayload);

        var longPayload = valid.ToArray();
        BinaryPrimitives.WriteUInt32BigEndian(longPayload.AsSpan(24, 4),
            ProductionMailboxProtectedHistoryResponseReference.MaximumPayloadLength + 1);
        result.Add(longPayload);

        var zeroPlanHash = valid.ToArray();
        zeroPlanHash.AsSpan(128, 32).Clear();
        result.Add(zeroPlanHash);
        return result;
    }

    private static byte[] HistoryReferenceTag(ReadOnlySpan<byte> routeStateKey,
        ReadOnlySpan<byte> currentCheckpointHash, ReadOnlySpan<byte> canonical,
        ReadOnlySpan<byte> integrityKey)
    {
        var input = new byte[
            "Deep/registry/production-mailbox/owner-control/history-response-reference/v1"u8
                .Length + routeStateKey.Length + currentCheckpointHash.Length + canonical.Length];
        var offset = 0;
        Append("Deep/registry/production-mailbox/owner-control/history-response-reference/v1"u8);
        Append(routeStateKey);
        Append(currentCheckpointHash);
        Append(canonical);
        try { return HMACSHA256.HashData(integrityKey, input); }
        finally { CryptographicOperations.ZeroMemory(input); }

        void Append(ReadOnlySpan<byte> value)
        {
            value.CopyTo(input.AsSpan(offset));
            offset += value.Length;
        }
    }

    internal sealed record AdvancedFixture(
        byte[] RouteKey,
        VerifiedProductionMailboxAuthority Authority,
        VerifiedProductionMailboxRevocationSnapshot Revocations,
        VerifiedProductionMailboxRouteCertificate Certificate,
        VerifiedProductionMailboxRouteAdvertisementV2 InitialAuthorization,
        VerifiedProductionMailboxRouteContinuityEnrollment Enrollment,
        VerifiedProductionMailboxRouteHistoryCursor InitialCursor,
        ProductionMailboxRouteContinuityGenesisCommitPlan GenesisPlan,
        ProductionMailboxRouteHistoryBatchCommitPlan FirstPlan,
        ProductionMailboxRouteHistoryBatchCommitPlan SecondPlan,
        ProductionMailboxRouteAdvertisementV2 SecondAuthorization,
        byte[] OwnerPrivateKey,
        byte[] ResponderPrivateKey,
        byte[] SourceArtifactClosureHash,
        byte[] EnrollmentRequestId,
        byte[] EnrollmentRequestHash,
        byte[] GenesisIntentHash,
        byte[] OwnerControlKeyToken,
        ulong NowUnixSeconds,
        byte Variant)
    {
        internal static async ValueTask<AdvancedFixture> CreateAsync(
            IProductionMailboxRouteContinuityStateStore store, byte variant,
            bool highCounters = false, ulong nowUnixSeconds = 1_800_000_000,
            byte[]? sourceArtifactClosureHash = null,
            ulong delegationLifetimeSeconds = 180)
        {
            var issuer = PublicKeyAuth.GenerateKeyPair(Bytes((byte)(20 + variant), 32));
            var mrX = PublicKeyAuth.GenerateKeyPair(Bytes((byte)(50 + variant), 32));
            var owner = PublicKeyAuth.GenerateKeyPair(Bytes((byte)(80 + variant), 32));
            var authorityValue = AuthorityValue(
                issuer.PublicKey, mrX.PublicKey, variant, highCounters, nowUnixSeconds);
            var unsignedPmr = new ProductionMailboxRevocationSnapshot
            {
                NetworkId = authorityValue.NetworkId,
                AuthorityGeneration = authorityValue.AuthorityGeneration,
                AuthorityBindingHash = ProductionMailboxRevocationSnapshotCodec
                    .ComputeAuthorityBindingHash(authorityValue),
                RevocationGeneration = authorityValue.Revocation.Generation,
                RevocationHeadHash = authorityValue.Revocation.HeadHash,
                PreviousRevocationHeadHash = authorityValue.Revocation.PreviousHeadHash,
                IssuedAtUnixSeconds = authorityValue.Revocation.IssuedAtUnixSeconds,
                ExpiresAtUnixSeconds = authorityValue.Revocation.ExpiresAtUnixSeconds,
                RevokedGrantSerials = [],
                IssuerSignature = new byte[64]
            };
            var pmr = unsignedPmr with
            {
                IssuerSignature = PublicKeyAuth.SignDetached(
                    ProductionMailboxRevocationSnapshotCodec.GetSigningBytes(unsignedPmr),
                    issuer.PrivateKey)
            };
            var pmrBytes = ProductionMailboxRevocationSnapshotCodec.Encode(pmr);
            authorityValue = authorityValue with
            {
                Revocation = authorityValue.Revocation with
                { SnapshotHash = SHA256.HashData(pmrBytes) }
            };
            authorityValue = SignAuthority(authorityValue, mrX.PrivateKey);
            var authority = ProductionMailboxAuthorityVerifier.Verify(authorityValue,
                new ProductionMailboxAuthorityVerificationContext
                {
                    PinnedMrXPublicKeySha256 = SHA256.HashData(mrX.PublicKey),
                    ExpectedNetworkId = authorityValue.NetworkId,
                    LastCommittedGeneration = authorityValue.AuthorityGeneration - 1,
                    LastCommittedAuthorityHash = authorityValue.PreviousAuthorityHash,
                    LastCommittedRevocationGeneration = authorityValue.Revocation.Generation - 1,
                    LastCommittedRevocationHeadHash = authorityValue.Revocation.PreviousHeadHash,
                    LastCommittedRevocationSnapshotHash = Bytes(23, 32),
                    NowUnixSeconds = nowUnixSeconds,
                    ClockSkewSeconds = 0
                }, new SodiumProductionMailboxAuthoritySignatureVerifier());
            var revocations = ProductionMailboxRevocationSnapshotVerifier.Verify(
                pmrBytes, authority, nowUnixSeconds, 0,
                new SodiumProductionMailboxRevocationSnapshotSignatureVerifier());
            var placement = new BlindedPlacementId(Bytes((byte)(121 + variant), 32));
            var certificateValue = new ProductionMailboxRouteCertificate
            {
                NetworkId = authorityValue.NetworkId,
                AuthorityGeneration = authorityValue.AuthorityGeneration,
                CanonicalAuthorityHash = authority.CanonicalAuthorityHash,
                IssuerEd25519PublicKey = issuer.PublicKey,
                MailboxOwnerEd25519PublicKey = owner.PublicKey,
                BlindedMailboxId = Bytes((byte)(111 + variant), 32),
                BlindedPlacementId = placement.Bytes,
                SelectionInputCommitment = ProductionMailboxReplicaSelection
                    .ComputeSelectionInputCommitment(placement),
                IssuedAtUnixSeconds = nowUnixSeconds - 10,
                ExpiresAtUnixSeconds = nowUnixSeconds + 300,
                IssuerSignature = new byte[64]
            };
            certificateValue = SignCertificate(certificateValue, issuer.PrivateKey);
            var certificate = ProductionMailboxRouteCertificateVerifier.Verify(
                ProductionMailboxRouteAdvertisementCodec.EncodeCertificate(certificateValue),
                authority, nowUnixSeconds, 0, new SodiumProductionMailboxRouteSignatureVerifier());
            var routeDomain = ProductionMailboxRouteAdvertisementCodec
                .ComputeRouteDomainHash(certificateValue);
            var praValue = SignPra(new ProductionMailboxRouteAdvertisementV2
            {
                Certificate = certificateValue,
                PredecessorAuthorizationKind = ProductionMailboxRouteAuthorizationKind.OwnerPRA2,
                PredecessorCanonicalRouteAuthorizationHash = Bytes((byte)(140 + variant), 32),
                PredecessorRouteAuthorizationSequence = 3,
                Sequence = 4,
                PublishedAtUnixSeconds = nowUnixSeconds - 5,
                ExpiresAtUnixSeconds = nowUnixSeconds + 200,
                OwnerSignature = new byte[64]
            }, owner.PrivateKey);
            var verifiedPra = VerifyPra(praValue, authority, routeDomain, nowUnixSeconds);
            var routeVerifiedAt = nowUnixSeconds - 20;
            var preRolBytes = EncodeRol(authorityValue.NetworkId.Span, routeDomain,
                ProductionMailboxRouteAuthorizationKind.OwnerPRA2,
                verifiedPra.CanonicalHash.Span, praValue.Sequence, new byte[32], new byte[32],
                0, new byte[32], routeVerifiedAt, 1);
            var delegation = SignDelegation(new ProductionMailboxRouteContinuityDelegation
            {
                NetworkId = authorityValue.NetworkId,
                PinnedMrXPublicKeySha256 = SHA256.HashData(mrX.PublicKey),
                RouteDomainHash = routeDomain,
                MailboxOwnerEd25519PublicKey = owner.PublicKey,
                BlindedMailboxId = certificateValue.BlindedMailboxId,
                BlindedPlacementId = certificateValue.BlindedPlacementId,
                SelectionInputCommitment = certificateValue.SelectionInputCommitment,
                AnchorAuthorityGeneration = authorityValue.AuthorityGeneration,
                AnchorCanonicalAuthorityHash = authority.CanonicalAuthorityHash,
                AnchorCanonicalRouteCertificateHash = certificate.CanonicalCertificateHash,
                AnchorAuthorizationKind = ProductionMailboxRouteAuthorizationKind.OwnerPRA2,
                AnchorCanonicalRouteAuthorizationHash = verifiedPra.CanonicalHash,
                AnchorRouteAuthorizationSequence = praValue.Sequence,
                PreDelegationRouteOriginLkgHash = HashRol(preRolBytes),
                RouteVerifiedAtUnixSeconds = routeVerifiedAt,
                Capability = ProductionMailboxRouteContinuityCapability.RouteContinuityOnly,
                DelegationSerial = Bytes((byte)(151 + variant), 16),
                DelegationSequence = 1,
                PreviousCanonicalDelegationHash = new byte[32],
                MaximumAuthorityGeneration = authorityValue.AuthorityGeneration + 1,
                FirstActivationSequence = 5,
                LastActivationSequence = 16,
                IssuedAtUnixSeconds = nowUnixSeconds - 4,
                NotBeforeUnixSeconds = nowUnixSeconds - 3,
                ExpiresAtUnixSeconds = checked(nowUnixSeconds + delegationLifetimeSeconds),
                OwnerSignature = new byte[64]
            }, owner.PrivateKey);
            var intent = ProductionMailboxRouteIssuerAuthoring.VerifyGenesisIntent(
                ProductionMailboxRouteContinuityCodec.EncodeDelegation(delegation),
                preRolBytes, authority, revocations, certificate, verifiedPra, nowUnixSeconds, 0);
            var responder = PublicKeyAuth.GenerateKeyPair(Bytes((byte)(190 + variant), 32));
            var routeKey = Bytes((byte)(201 + variant), 32);
            var ownerState = Assert.IsAssignableFrom<IProductionMailboxOwnerControlStateStore>(store);
            var requestId = Bytes((byte)(211 + variant), 16);
            var requestHash = SHA256.HashData([
                .. ProductionMailboxRouteContinuityCodec.EncodeDelegation(delegation),
                .. preRolBytes]);
            var sourceClosureHash = sourceArtifactClosureHash?.ToArray()
                ?? Bytes((byte)(221 + variant), 32);
            var keyToken = Bytes((byte)(231 + variant), 32);
            var prepared = await ownerState.PrepareOwnerEnrollmentAsync(routeKey, requestId,
                requestHash, intent.CanonicalDelegationHash, intent.IntentHash,
                sourceClosureHash, keyToken, nowUnixSeconds,
                CancellationToken.None);
            Assert.Equal(ProductionMailboxOwnerEnrollmentStatus.Prepared, prepared.Status);
            var enrollmentPlan = await ProductionMailboxRouteIssuerAuthoring.AuthorGenesisAsync(
                intent, prepared.AuthoritativeNowUnixSeconds,
                Math.Max(nowUnixSeconds, prepared.AuthoritativeNowUnixSeconds),
                responder.PublicKey, Math.Min(delegation.ExpiresAtUnixSeconds,
                    prepared.AuthoritativeNowUnixSeconds + 120),
                (request, destination, _) =>
                {
                    PublicKeyAuth.SignDetached(request.SigningBytes.ToArray(), issuer.PrivateKey)
                        .CopyTo(destination.Span);
                    return ValueTask.FromResult(64);
                }, (request, destination, _) =>
                {
                    PublicKeyAuth.SignDetached(request.SigningBytes.ToArray(), issuer.PrivateKey)
                        .CopyTo(destination.Span);
                    return ValueTask.FromResult(64);
                });
            var enrollmentResponse = ProductionMailboxOwnerControlHostCodec
                .EncodeEnrollmentResponse(enrollmentPlan);
            var enrollmentStatus = await ownerState.CommitOwnerEnrollmentAsync(routeKey,
                requestId, requestHash, intent.CanonicalDelegationHash, sourceClosureHash,
                enrollmentPlan, new(Bytes((byte)(231 + variant), 32), responder.PublicKey),
                enrollmentResponse, prepared.AuthoritativeNowUnixSeconds,
                CancellationToken.None);
            Assert.Equal(ProductionMailboxOwnerEnrollmentStatus.Prepared, enrollmentStatus);
            var verifiedEnrollment = ProductionMailboxRouteContinuityVerifier.VerifyEnrollment(
                enrollmentPlan.CanonicalDelegation.Span,
                enrollmentPlan.CanonicalAcceptance.Span, authority, revocations,
                certificate, verifiedPra,
                new ProductionMailboxRouteContinuityEnrollmentVerificationContext
                {
                    ExpectedNetworkId = delegation.NetworkId,
                    ExpectedPinnedMrXPublicKeySha256 =
                        delegation.PinnedMrXPublicKeySha256,
                    ExpectedRouteDomainHash = delegation.RouteDomainHash,
                    ExpectedMailboxOwnerEd25519PublicKey =
                        delegation.MailboxOwnerEd25519PublicKey,
                    ExpectedBlindedMailboxId = delegation.BlindedMailboxId,
                    ExpectedBlindedPlacementId = delegation.BlindedPlacementId,
                    ExpectedSelectionInputCommitment =
                        delegation.SelectionInputCommitment,
                    ExpectedPreDelegationRouteOriginLkgHash =
                        delegation.PreDelegationRouteOriginLkgHash,
                    ExpectedRouteVerifiedAtUnixSeconds = delegation.RouteVerifiedAtUnixSeconds,
                    LastDelegationSequence = 0,
                    LastCanonicalDelegationHash = new byte[32],
                    NowUnixSeconds = Math.Max(nowUnixSeconds,
                        prepared.AuthoritativeNowUnixSeconds),
                    ClockSkewSeconds = 0
                });
            var anchor = ProductionMailboxRouteIssuerAuthoring.RestoreHistoricalAnchor(
                enrollmentPlan.CanonicalDelegation, enrollmentPlan.CanonicalAcceptance,
                enrollmentPlan.ExpectedPreDelegationRouteOriginLkg,
                enrollmentPlan.CanonicalEnrolledRouteOriginLkg,
                enrollmentPlan.CanonicalOwnerControlResponderCertificate,
                authority, revocations, certificate, verifiedPra,
                enrollmentPlan.ToProtectedEnrollmentRestoreContext());
            var cursor = ProductionMailboxRouteHistoryAuthoring.RestoreCursor(
                enrollmentPlan.CanonicalInitialRouteHistoryCheckpoint.Span, anchor,
                enrollmentPlan.ToProtectedRouteHistoryRestoreContext());
            var firstPra = NextPra(praValue, verifiedPra.CanonicalHash.ToArray(),
                owner.PrivateKey, 1, nowUnixSeconds);
            var firstPlan = ProductionMailboxRouteHistoryAuthoring.AuthorNextBatch(cursor,
                [OwnerLink(authority, revocations, certificateValue, firstPra)]);
            var firstHash = SHA256.HashData(
                ProductionMailboxRouteAuthorizationCodec.EncodeAdvertisementV2(firstPra));
            var secondPra = NextPra(firstPra, firstHash, owner.PrivateKey, 2, nowUnixSeconds);
            var secondPlan = ProductionMailboxRouteHistoryAuthoring.AuthorNextBatch(
                firstPlan.NextCursor,
                [OwnerLink(authority, revocations, certificateValue, secondPra)]);
            return new(routeKey, authority, revocations, certificate, verifiedPra,
                verifiedEnrollment, cursor, enrollmentPlan, firstPlan, secondPlan, secondPra,
                owner.PrivateKey, responder.PrivateKey, sourceClosureHash, requestId,
                requestHash, intent.IntentHash.ToArray(), keyToken,
                Math.Max(nowUnixSeconds, prepared.AuthoritativeNowUnixSeconds), variant);
        }

        internal VerifiedProductionMailboxRouteContinuityRevocation VerifyRevocation(
            ProductionMailboxRouteContinuityRevocationReason reason)
        {
            var delegation = Enrollment.Delegation;
            var value = SignRevocation(new ProductionMailboxRouteContinuityRevocation
            {
                NetworkId = delegation.NetworkId,
                RouteDomainHash = delegation.RouteDomainHash,
                TargetDelegationSerial = delegation.DelegationSerial,
                TargetCanonicalDelegationHash = Enrollment.CanonicalDelegationHash,
                RevocationGeneration = 1,
                PreviousCanonicalRevocationHash = new byte[32],
                RevokedAtUnixSeconds = NowUnixSeconds,
                Reason = reason,
                OwnerSignature = new byte[64]
            }, OwnerPrivateKey);
            return ProductionMailboxRouteContinuityVerifier.VerifyOwnerRevocation(
                ProductionMailboxRouteContinuityCodec.EncodeRevocation(value),
                Enrollment, NowUnixSeconds, 0);
        }

        internal ProductionMailboxRouteHistoryBatchCommitPlan AuthorCompetingSecondPlan()
        {
            var competing = SecondAuthorization with
            {
                PublishedAtUnixSeconds = SecondAuthorization.PublishedAtUnixSeconds + 1,
                ExpiresAtUnixSeconds = SecondAuthorization.ExpiresAtUnixSeconds + 1,
                OwnerSignature = new byte[64]
            };
            competing = SignPra(competing, OwnerPrivateKey);
            return ProductionMailboxRouteHistoryAuthoring.AuthorNextBatch(
                FirstPlan.NextCursor,
                [OwnerLink(Authority, Revocations, Certificate.Certificate, competing)]);
        }

        internal static byte[] Bytes(byte seed, int length) => Enumerable.Range(0, length)
            .Select(index => unchecked((byte)(seed + index))).ToArray();

        private static ProductionMailboxRouteHistoryAuthoringLink OwnerLink(
            VerifiedProductionMailboxAuthority authority,
            VerifiedProductionMailboxRevocationSnapshot revocations,
            ProductionMailboxRouteCertificate certificate,
            ProductionMailboxRouteAdvertisementV2 authorization) => new()
            {
                AuthorizationKind = ProductionMailboxRouteAuthorizationKind.OwnerPRA2,
                CanonicalAuthority = ProductionMailboxAuthorityCodec.Encode(authority.Authority),
                CanonicalRevocations = ProductionMailboxRevocationSnapshotCodec.Encode(
                revocations.Snapshot),
                CanonicalRouteCertificate = ProductionMailboxRouteAdvertisementCodec
                .EncodeCertificate(certificate),
                CanonicalRevocationCheckpoint = ReadOnlyMemory<byte>.Empty,
                CanonicalTransitionContext = ReadOnlyMemory<byte>.Empty,
                CanonicalAuthorization = ProductionMailboxRouteAuthorizationCodec
                .EncodeAdvertisementV2(authorization)
            };

        private static ProductionMailboxRouteAdvertisementV2 NextPra(
            ProductionMailboxRouteAdvertisementV2 previous, byte[] previousHash,
            byte[] ownerPrivateKey, ulong step, ulong nowUnixSeconds) => SignPra(previous with
            {
                PredecessorAuthorizationKind = ProductionMailboxRouteAuthorizationKind.OwnerPRA2,
                PredecessorCanonicalRouteAuthorizationHash = previousHash,
                PredecessorRouteAuthorizationSequence = previous.Sequence,
                Sequence = previous.Sequence + 1,
                PublishedAtUnixSeconds = nowUnixSeconds + step,
                ExpiresAtUnixSeconds = nowUnixSeconds + 150 + step,
                OwnerSignature = new byte[64]
            }, ownerPrivateKey);

        private static VerifiedProductionMailboxRouteAdvertisementV2 VerifyPra(
            ProductionMailboxRouteAdvertisementV2 value,
            VerifiedProductionMailboxAuthority authority, byte[] routeDomain,
            ulong nowUnixSeconds) =>
            ProductionMailboxRouteAuthorizationVerifier.VerifyOwnerAuthorization(
                ProductionMailboxRouteAuthorizationCodec.EncodeAdvertisementV2(value), authority,
                new ProductionMailboxOwnerRouteAuthorizationVerificationContext
                {
                    ExpectedNetworkId = value.Certificate.NetworkId,
                    ExpectedRouteDomainHash = routeDomain,
                    ExpectedPredecessorKind = value.PredecessorAuthorizationKind,
                    ExpectedPredecessorHash = value.PredecessorCanonicalRouteAuthorizationHash,
                    ExpectedPredecessorSequence = value.PredecessorRouteAuthorizationSequence,
                    NowUnixSeconds = nowUnixSeconds,
                    ClockSkewSeconds = 0
                });

        private static ProductionMailboxRouteAdvertisementV2 SignPra(
            ProductionMailboxRouteAdvertisementV2 value, byte[] privateKey)
        {
            var unsigned = value with { OwnerSignature = Enumerable.Repeat((byte)0xA5, 64).ToArray() };
            var canonical = ProductionMailboxRouteAuthorizationCodec.EncodeAdvertisementV2(unsigned);
            return unsigned with
            {
                OwnerSignature = SignFixed(
                "Deep/production-mailbox/route-advertisement/v2"u8,
                canonical.AsSpan(0, 384), privateKey)
            };
        }

        private static ProductionMailboxRouteCertificate SignCertificate(
            ProductionMailboxRouteCertificate value, byte[] privateKey)
        {
            var unsigned = value with { IssuerSignature = new byte[64] };
            return unsigned with
            {
                IssuerSignature = PublicKeyAuth.SignDetached(
                ProductionMailboxRouteAdvertisementCodec.GetCertificateSigningBytes(unsigned),
                privateKey)
            };
        }

        private static ProductionMailboxRouteContinuityDelegation SignDelegation(
            ProductionMailboxRouteContinuityDelegation value, byte[] privateKey)
        {
            var unsigned = value with { OwnerSignature = Enumerable.Repeat((byte)0xA5, 64).ToArray() };
            var canonical = ProductionMailboxRouteContinuityCodec.EncodeDelegation(unsigned);
            return unsigned with
            {
                OwnerSignature = SignFixed(
                "Deep/production-mailbox/route-continuity-delegation/v1"u8,
                canonical.AsSpan(0, 488), privateKey)
            };
        }

        private static ProductionMailboxRouteContinuityRevocation SignRevocation(
            ProductionMailboxRouteContinuityRevocation value, byte[] privateKey)
        {
            var unsigned = value with { OwnerSignature = Enumerable.Repeat((byte)0xA5, 64).ToArray() };
            var canonical = ProductionMailboxRouteContinuityCodec.EncodeRevocation(unsigned);
            return unsigned with
            {
                OwnerSignature = SignFixed(
                "Deep/production-mailbox/route-continuity-revocation/v1"u8,
                canonical.AsSpan(0, 160), privateKey)
            };
        }

        private static byte[] SignFixed(ReadOnlySpan<byte> domain, ReadOnlySpan<byte> payload,
            byte[] privateKey)
        {
            var signing = new byte[domain.Length + payload.Length];
            domain.CopyTo(signing);
            payload.CopyTo(signing.AsSpan(domain.Length));
            return PublicKeyAuth.SignDetached(signing, privateKey);
        }

        private static byte[] EncodeRol(ReadOnlySpan<byte> networkId,
            ReadOnlySpan<byte> routeDomain,
            ProductionMailboxRouteAuthorizationKind authorizationKind,
            ReadOnlySpan<byte> authorizationHash, ulong authorizationSequence,
            ReadOnlySpan<byte> delegationHash, ReadOnlySpan<byte> acceptanceHash,
            ulong revocationGeneration, ReadOnlySpan<byte> revocationHead,
            ulong routeVerifiedAt, ulong localCommitGeneration)
        {
            var bytes = new byte[ProductionMailboxRouteContinuityConstants
                .CanonicalRouteOriginLkgLength];
            "ROL1"u8.CopyTo(bytes);
            bytes[4] = 1;
            networkId.CopyTo(bytes.AsSpan(8, 16));
            routeDomain.CopyTo(bytes.AsSpan(24, 32));
            bytes[56] = (byte)authorizationKind;
            authorizationHash.CopyTo(bytes.AsSpan(64, 32));
            BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(96, 8), authorizationSequence);
            delegationHash.CopyTo(bytes.AsSpan(104, 32));
            acceptanceHash.CopyTo(bytes.AsSpan(136, 32));
            BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(168, 8), revocationGeneration);
            revocationHead.CopyTo(bytes.AsSpan(176, 32));
            BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(208, 8), routeVerifiedAt);
            BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(216, 8), localCommitGeneration);
            return bytes;
        }

        private static byte[] HashRol(byte[] canonical)
        {
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            hash.AppendData("Deep/production-mailbox/route-origin-lkg/v1"u8);
            hash.AppendData(canonical);
            return hash.GetHashAndReset();
        }

        private static ProductionMailboxAuthority AuthorityValue(
            byte[] issuer, byte[] mrX, byte variant, bool highCounters, ulong nowUnixSeconds)
        {
            return new ProductionMailboxAuthority
            {
                DevelopmentOnly = false,
                Environment = ProductionMailboxAuthorityEnvironment.Production,
                Transport = ProductionMailboxAuthorityTransport.AuthenticatedMau2,
                Ownership = ProductionMailboxAuthorityOwnership.OfficialManaged,
                EndpointPolicy = ProductionMailboxAuthorityEndpointPolicy.PublicHttpsOnly,
                NetworkId = Bytes((byte)(1 + variant), 16),
                AuthorityGeneration = highCounters ? 0x8000_0000_0000_0007UL : 7,
                PreviousAuthorityHash = Bytes((byte)(2 + variant), 32),
                MailboxIssuerEd25519PublicKey = issuer,
                MrXApprovalEd25519PublicKey = mrX,
                Coordinator = Endpoint("https://coord.example.net/", 4),
                NodeIngress = Endpoint("https://ingress.example.net/mau2/", 6),
                CurrentEpoch = Epoch(9, 70, nowUnixSeconds - 100, nowUnixSeconds + 1_000, 8),
                NextEpoch = Epoch(10, 71, nowUnixSeconds + 100, nowUnixSeconds + 2_000, 10),
                Revocation = new ProductionMailboxAuthorityRevocation
                {
                    SnapshotHash = Bytes(12, 32),
                    HeadHash = Bytes(13, 32),
                    PreviousHeadHash = Bytes(22, 32),
                    Generation = highCounters ? 0x8000_0000_0000_0006UL : 6,
                    IssuedAtUnixSeconds = nowUnixSeconds - 20,
                    ExpiresAtUnixSeconds = nowUnixSeconds + 500
                },
                MrXApproval = new ProductionMailboxAuthorityApproval
                {
                    AuthorityPayloadHash = Bytes(14, 32),
                    AllowedAndroidSigningCertificateSha256 = [Bytes(15, 32)],
                    AllowedWindowsSigningCertificateSha256 = [Bytes(16, 32)],
                    AndroidReleaseBuildArtifactSha256 = [Bytes(17, 32)],
                    WindowsReleaseBuildArtifactSha256 = [Bytes(18, 32)],
                    RolloutNotBeforeUnixSeconds = nowUnixSeconds - 30,
                    RolloutNotAfterUnixSeconds = nowUnixSeconds + 500
                },
                Signature = new byte[64]
            };
        }

        private static ProductionMailboxAuthority SignAuthority(
            ProductionMailboxAuthority value, byte[] privateKey)
        {
            var bound = value with
            {
                MrXApproval = value.MrXApproval with
                { AuthorityPayloadHash = ProductionMailboxAuthorityCodec.ComputePayloadHash(value) },
                Signature = new byte[64]
            };
            return bound with
            {
                Signature = PublicKeyAuth.SignDetached(
                ProductionMailboxAuthorityCodec.GetSigningBytes(bound), privateKey)
            };
        }

        private static ProductionMailboxAuthorityEpoch Epoch(ulong epoch, ulong generation,
            ulong from, ulong until, byte seed) => new()
            {
                Epoch = epoch,
                Generation = generation,
                MembershipCommitment = Bytes(seed, 32),
                TopologyPlacementCommitment = Bytes((byte)(seed + 1), 32),
                NotBeforeUnixSeconds = from,
                NotAfterUnixSeconds = until
            };

        private static ProductionMailboxAuthorityEndpoint Endpoint(string uri, byte seed) => new()
        {
            Uri = uri,
            CurrentSpkiSha256 = Bytes(seed, 32),
            NextSpkiSha256 = Bytes((byte)(seed + 1), 32)
        };
    }

    internal sealed class PostgresTestDatabase : IAsyncDisposable
    {
        private readonly string administrativeConnectionString;
        private readonly string schema;

        private PostgresTestDatabase(string administrativeConnectionString,
            string schema, string connectionString)
        {
            this.administrativeConnectionString = administrativeConnectionString;
            this.schema = schema;
            ConnectionString = connectionString;
        }

        internal string ConnectionString { get; }

        internal static async ValueTask<PostgresTestDatabase> CreateAsync(string connectionString)
        {
            var schema = "deep_registry_route_v2_advanced_" +
                Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(8));
            var quoted = new NpgsqlCommandBuilder().QuoteIdentifier(schema);
            await using (var connection = new NpgsqlConnection(connectionString))
            {
                await connection.OpenAsync();
                await new NpgsqlCommand($"CREATE SCHEMA {quoted}", connection)
                    .ExecuteNonQueryAsync();
            }
            var isolated = new NpgsqlConnectionStringBuilder(connectionString)
            {
                SearchPath = schema,
                Pooling = false
            };
            return new(connectionString, schema, isolated.ConnectionString);
        }

        public async ValueTask DisposeAsync()
        {
            var quoted = new NpgsqlCommandBuilder().QuoteIdentifier(schema);
            await using var connection = new NpgsqlConnection(administrativeConnectionString);
            await connection.OpenAsync();
            await new NpgsqlCommand($"DROP SCHEMA IF EXISTS {quoted} CASCADE", connection)
                .ExecuteNonQueryAsync();
        }
    }
}
