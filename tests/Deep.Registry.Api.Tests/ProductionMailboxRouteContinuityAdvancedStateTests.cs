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
            byte[]? sourceArtifactClosureHash = null)
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
                ExpiresAtUnixSeconds = nowUnixSeconds + 180,
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
