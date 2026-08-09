using System.Buffers.Binary;
using System.Collections;
using System.Diagnostics;
using System.Reflection;
using Deep.Protocol.DeepExtension.MailboxAuthority;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.MailboxTopology;
using Deep.Registry.Api.ProductionMailbox;
using Sodium;
using Npgsql;

namespace Deep.Registry.Api.Tests;

public sealed class ProductionMailboxOwnerControlStateTests
{
    private const ulong Now = 1_800_000_000;

    [Fact]
    public async Task PostgreSqlNoChangeJournal_SurvivesEveryRestartBoundary()
    {
        var connectionString = Environment.GetEnvironmentVariable("DEEP_TEST_POSTGRES");
        if (string.IsNullOrWhiteSpace(connectionString)) return;
        await using var database = await ProductionMailboxRouteContinuityAdvancedStateTests
            .PostgresTestDatabase.CreateAsync(connectionString);
        var integrityKey = Bytes(240, 32);
        var concrete = new PostgreSqlProductionMailboxStateStore(database.ConnectionString,
            integrityKey);
        var continuity = (IProductionMailboxRouteContinuityStateStore)concrete;
        var pgNow = checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        var fixture = await ProductionMailboxRouteContinuityAdvancedStateTests.AdvancedFixture
            .CreateAsync(continuity, 40, nowUnixSeconds: pgNow);
        var restored = await continuity.GetRestoredGenesisAsync(fixture.RouteKey,
            CancellationToken.None);
        Assert.NotNull(restored);
        var request = await ProductionMailboxOwnerControlTransportCodec.AuthorOwnerDirectRequestAsync(
            restored.Anchor, restored.Cursor, Bytes(21, 32), pgNow, pgNow + 30,
            RequestSigner(fixture.OwnerPrivateKey));
        var scope = Bytes(22, 32);
        var state = (IProductionMailboxOwnerControlStateStore)concrete;
        Assert.Equal(ProductionMailboxOwnerRequestStatus.Prepared,
            (await state.PrepareNoChangeAsync(fixture.RouteKey, scope, request, pgNow,
                CancellationToken.None)).Status);

        state = new PostgreSqlProductionMailboxStateStore(database.ConnectionString, integrityKey);
        var planned = await state.PlanNoChangeAsync(fixture.RouteKey, scope, request,
            pgNow + 1, CancellationToken.None);
        Assert.Equal(ProductionMailboxOwnerRequestStatus.Prepared, planned.Status);
        state = new PostgreSqlProductionMailboxStateStore(database.ConnectionString, integrityKey);
        Assert.Equal(planned, await state.PlanNoChangeAsync(fixture.RouteKey, scope, request,
            pgNow + 2, CancellationToken.None));
        var response = await ProductionMailboxOwnerControlTransportCodec.AuthorNoChangeResponseAsync(
            request, restored.Anchor, planned.IssuedAtUnixSeconds,
            planned.ExpiresAtUnixSeconds, ResponseSigner(fixture.ResponderPrivateKey));

        state = new PostgreSqlProductionMailboxStateStore(database.ConnectionString, integrityKey);
        Assert.Equal(ProductionMailboxOwnerRequestStatus.Prepared,
            await state.RecordNoChangeAsync(fixture.RouteKey, scope, request, response,
                pgNow + 2, CancellationToken.None));
        state = new PostgreSqlProductionMailboxStateStore(database.ConnectionString, integrityKey);
        var authorized = await state.AuthorizeDeliveryAsync(fixture.RouteKey, scope,
            request.CanonicalHash, pgNow + 2, CancellationToken.None);
        Assert.Equal(ProductionMailboxOwnerRequestStatus.ExactReplay, authorized.Status);
        state = new PostgreSqlProductionMailboxStateStore(database.ConnectionString, integrityKey);
        var replay = await state.PrepareNoChangeAsync(fixture.RouteKey, scope, request,
            pgNow + 3, CancellationToken.None);
        Assert.Equal(ProductionMailboxOwnerRequestStatus.ExactReplay, replay.Status);
        Assert.Equal(response.CanonicalHeader.ToArray(), replay.CanonicalHeader);

        byte[] protectedCatalog;
        await using (var connection = new NpgsqlConnection(database.ConnectionString))
        {
            await connection.OpenAsync();
            await using var select = new NpgsqlCommand("""
                SELECT protected_payload FROM production_mailbox_route_genesis_v1
                WHERE route_state_key=@route
                """, connection);
            select.Parameters.AddWithValue("route", fixture.RouteKey);
            protectedCatalog = (byte[])(await select.ExecuteScalarAsync())!;
            var corrupted = protectedCatalog.ToArray(); corrupted[10] ^= 1;
            await using var update = new NpgsqlCommand("""
                UPDATE production_mailbox_route_genesis_v1 SET protected_payload=@payload
                WHERE route_state_key=@route
                """, connection);
            update.Parameters.AddWithValue("payload", corrupted);
            update.Parameters.AddWithValue("route", fixture.RouteKey);
            Assert.Equal(1, await update.ExecuteNonQueryAsync());
        }
        state = new PostgreSqlProductionMailboxStateStore(database.ConnectionString, integrityKey);
        await Assert.ThrowsAsync<InvalidDataException>(() => state.PrepareOwnerEnrollmentAsync(
            fixture.RouteKey, fixture.EnrollmentRequestId, fixture.EnrollmentRequestHash,
            fixture.Enrollment.CanonicalDelegationHash, fixture.GenesisIntentHash,
            fixture.SourceArtifactClosureHash, fixture.OwnerControlKeyToken, pgNow + 3,
            CancellationToken.None).AsTask());
        await using (var connection = new NpgsqlConnection(database.ConnectionString))
        {
            await connection.OpenAsync();
            await using var update = new NpgsqlCommand("""
                UPDATE production_mailbox_route_genesis_v1 SET protected_payload=@payload
                WHERE route_state_key=@route
                """, connection);
            update.Parameters.AddWithValue("payload", protectedCatalog);
            update.Parameters.AddWithValue("route", fixture.RouteKey);
            Assert.Equal(1, await update.ExecuteNonQueryAsync());
        }

        var revocation = fixture.VerifyRevocation(
            ProductionMailboxRouteContinuityRevocationReason.OwnerRevoked);
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.Accepted,
            (await state.CommitOwnerRevocationAndFenceAsync(fixture.RouteKey,
                Bytes(23, 16), revocation, CancellationToken.None)).Status);
        state = new PostgreSqlProductionMailboxStateStore(database.ConnectionString, integrityKey);
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.ExactReplay,
            (await state.CommitOwnerRevocationAndFenceAsync(fixture.RouteKey,
                Bytes(24, 16), revocation, CancellationToken.None)).Status);
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.Conflict,
            (await state.CommitOwnerRevocationAndFenceAsync(fixture.RouteKey,
                Bytes(23, 16), fixture.VerifyRevocation(
                    ProductionMailboxRouteContinuityRevocationReason.RouteReset),
                CancellationToken.None)).Status);
        Assert.Equal(ProductionMailboxOwnerRequestStatus.Revoked,
            (await state.PrepareNoChangeAsync(fixture.RouteKey, scope, request,
                pgNow + 4, CancellationToken.None)).Status);
    }

    [Fact]
    public async Task PostgreSqlAbandonedKey_ClaimsAcrossStores_AndCapacityIsAtomic()
    {
        var connectionString = Environment.GetEnvironmentVariable("DEEP_TEST_POSTGRES");
        if (string.IsNullOrWhiteSpace(connectionString)) return;
        await using var database = await ProductionMailboxRouteContinuityAdvancedStateTests
            .PostgresTestDatabase.CreateAsync(connectionString);
        var key = Bytes(201, 32);
        var limits = new ProductionMailboxOwnerControlStoreLimits(
            MaximumEntriesPerRoute: 7, MaximumEntriesGlobal: 7,
            MaximumStateBytes: 32 * 1024 * 1024);
        var first = (IProductionMailboxOwnerControlStateStore)
            new PostgreSqlProductionMailboxStateStore(database.ConnectionString, key, limits);
        var route = Bytes(202, 32); var source = Bytes(203, 32);
        var operation = Bytes(204, 32); var token = Bytes(205, 32);
        Assert.Equal(ProductionMailboxOwnerEnrollmentStatus.Prepared,
            (await first.PrepareOwnerEnrollmentAsync(route, Bytes(206, 16), Bytes(207, 32),
                operation, Bytes(208, 32), source, token, Now,
                CancellationToken.None)).Status);
        Assert.Equal(ProductionMailboxOwnerEnrollmentStatus.Prepared,
            (await first.PrepareOwnerEnrollmentAsync(route, Bytes(209, 16), Bytes(210, 32),
                Bytes(211, 32), Bytes(212, 32), source, Bytes(213, 32), Now,
                CancellationToken.None)).Status);
        Assert.Equal(ProductionMailboxOwnerEnrollmentStatus.CapacityExceeded,
            (await first.PrepareOwnerEnrollmentAsync(route, Bytes(214, 16), Bytes(215, 32),
                Bytes(216, 32), Bytes(217, 32), source, Bytes(218, 32), Now,
                CancellationToken.None)).Status);

        var expired = Now + ProductionMailboxOwnerControlConstants
            .MaximumResponderCertificateLifetimeSeconds;
        var claimed = await first.ClaimAbandonedOwnerKeyAsync(expired, expired + 10,
            CancellationToken.None);
        Assert.NotNull(claimed); Assert.Equal(token, claimed.KeyToken);
        var second = (IProductionMailboxOwnerControlStateStore)
            new PostgreSqlProductionMailboxStateStore(database.ConnectionString, key, limits);
        var secondClaim = await second.ClaimAbandonedOwnerKeyAsync(expired + 1, expired + 11,
            CancellationToken.None);
        Assert.NotNull(secondClaim); Assert.Equal(Bytes(213, 32), secondClaim.KeyToken);
        await second.CompleteAbandonedOwnerKeyAsync(secondClaim.RouteStateKey,
            secondClaim.OperationHash, secondClaim.KeyToken, CancellationToken.None);
        Assert.Null(await second.ClaimAbandonedOwnerKeyAsync(expired + 2, expired + 12,
            CancellationToken.None));
        var retried = await second.ClaimAbandonedOwnerKeyAsync(expired + 10, expired + 20,
            CancellationToken.None);
        Assert.NotNull(retried); Assert.Equal(token, retried.KeyToken);
        await second.CompleteAbandonedOwnerKeyAsync(route, operation, token,
            CancellationToken.None);
        Assert.Null(await first.ClaimAbandonedOwnerKeyAsync(expired + 21, expired + 31,
            CancellationToken.None));
    }

    [Fact]
    public async Task InMemoryNoChangeJournal_PlansBeforeSigning_AndReplaysExactly()
    {
        var concrete = new InMemoryProductionMailboxStateStore();
        var continuity = (IProductionMailboxRouteContinuityStateStore)concrete;
        var state = (IProductionMailboxOwnerControlStateStore)concrete;
        var fixture = await ProductionMailboxRouteContinuityAdvancedStateTests.AdvancedFixture
            .CreateAsync(continuity, 33);
        var restored = await continuity.GetRestoredGenesisAsync(fixture.RouteKey,
            CancellationToken.None);
        Assert.NotNull(restored);
        var request = await ProductionMailboxOwnerControlTransportCodec.AuthorOwnerDirectRequestAsync(
            restored.Anchor, restored.Cursor, Bytes(11, 32), Now, Now + 30,
            RequestSigner(fixture.OwnerPrivateKey));
        var scope = Bytes(12, 32);

        var prepared = await state.PrepareNoChangeAsync(fixture.RouteKey, scope, request,
            Now, CancellationToken.None);
        Assert.Equal(ProductionMailboxOwnerRequestStatus.Prepared, prepared.Status);
        var planned = await state.PlanNoChangeAsync(fixture.RouteKey, scope, request,
            Now + 1, CancellationToken.None);
        Assert.Equal(ProductionMailboxOwnerRequestStatus.Prepared, planned.Status);
        Assert.Equal(Now + 1, planned.IssuedAtUnixSeconds);
        Assert.Equal(Now + 30, planned.ExpiresAtUnixSeconds);
        var replayedPlan = await state.PlanNoChangeAsync(fixture.RouteKey, scope, request,
            Now + 2, CancellationToken.None);
        Assert.Equal(planned, replayedPlan);

        var response = await ProductionMailboxOwnerControlTransportCodec.AuthorNoChangeResponseAsync(
            request, restored.Anchor, planned.IssuedAtUnixSeconds,
            planned.ExpiresAtUnixSeconds, ResponseSigner(fixture.ResponderPrivateKey));
        var recorded = await state.RecordNoChangeAsync(fixture.RouteKey, scope, request,
            response, Now + 2, CancellationToken.None);
        Assert.Equal(ProductionMailboxOwnerRequestStatus.Prepared, recorded);
        var authorized = await state.AuthorizeDeliveryAsync(fixture.RouteKey, scope,
            request.CanonicalHash, Now + 2, CancellationToken.None);
        Assert.Equal(ProductionMailboxOwnerRequestStatus.ExactReplay, authorized.Status);
        Assert.Equal(response.CanonicalHeader.ToArray(), authorized.CanonicalHeader);

        var replay = await state.PrepareNoChangeAsync(fixture.RouteKey, scope, request,
            Now + 3, CancellationToken.None);
        Assert.Equal(ProductionMailboxOwnerRequestStatus.ExactReplay, replay.Status);
        Assert.Equal(response.CanonicalHeader.ToArray(), replay.CanonicalHeader);
    }

    [Fact]
    public async Task InMemoryAuthorizeDelivery_RejectsRouteSourceAdvanceAfterSigning()
    {
        var concrete = new InMemoryProductionMailboxStateStore();
        var continuity = (IProductionMailboxRouteContinuityStateStore)concrete;
        var state = (IProductionMailboxOwnerControlStateStore)concrete;
        var fixture = await ProductionMailboxRouteContinuityAdvancedStateTests.AdvancedFixture
            .CreateAsync(continuity, 45);
        var restored = await continuity.GetRestoredGenesisAsync(fixture.RouteKey,
            CancellationToken.None);
        Assert.NotNull(restored);
        var request = await ProductionMailboxOwnerControlTransportCodec.AuthorOwnerDirectRequestAsync(
            restored.Anchor, restored.Cursor, Bytes(46, 32), Now, Now + 30,
            RequestSigner(fixture.OwnerPrivateKey));
        var scope = Bytes(47, 32);
        Assert.Equal(ProductionMailboxOwnerRequestStatus.Prepared,
            (await state.PrepareNoChangeAsync(fixture.RouteKey, scope, request, Now,
                CancellationToken.None)).Status);
        var plan = await state.PlanNoChangeAsync(fixture.RouteKey, scope, request, Now + 1,
            CancellationToken.None);
        var response = await ProductionMailboxOwnerControlTransportCodec.AuthorNoChangeResponseAsync(
            request, restored.Anchor, plan.IssuedAtUnixSeconds, plan.ExpiresAtUnixSeconds,
            ResponseSigner(fixture.ResponderPrivateKey));
        Assert.Equal(ProductionMailboxOwnerRequestStatus.Prepared,
            await state.RecordNoChangeAsync(fixture.RouteKey, scope, request, response, Now + 2,
                CancellationToken.None));
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.Accepted,
            (await continuity.CommitVerifiedHistoryBatchAsync(fixture.RouteKey,
                fixture.InitialCursor, fixture.FirstPlan, CancellationToken.None)).Status);
        Assert.Equal(ProductionMailboxOwnerRequestStatus.Conflict,
            (await state.AuthorizeDeliveryAsync(fixture.RouteKey, scope, request.CanonicalHash,
                Now + 2, CancellationToken.None)).Status);
    }

    [Fact]
    public async Task InMemoryRevocation_FencesEveryPreDeliveryPhase_AndPreservesAuthorizedBoundary()
    {
        foreach (var phase in Enum.GetValues<JournalPhase>())
        {
            var concrete = new InMemoryProductionMailboxStateStore();
            var continuity = (IProductionMailboxRouteContinuityStateStore)concrete;
            var state = (IProductionMailboxOwnerControlStateStore)concrete;
            var fixture = await ProductionMailboxRouteContinuityAdvancedStateTests.AdvancedFixture
                .CreateAsync(continuity, (byte)(50 + (int)phase));
            var restored = await continuity.GetRestoredGenesisAsync(fixture.RouteKey,
                CancellationToken.None);
            Assert.NotNull(restored);
            var request = await ProductionMailboxOwnerControlTransportCodec.AuthorOwnerDirectRequestAsync(
                restored.Anchor, restored.Cursor, Bytes((byte)(80 + (int)phase), 32),
                Now, Now + 30, RequestSigner(fixture.OwnerPrivateKey));
            var scope = Bytes((byte)(100 + (int)phase), 32);
            await state.PrepareNoChangeAsync(fixture.RouteKey, scope, request, Now,
                CancellationToken.None);
            VerifiedProductionMailboxOwnerControlResponse? response = null;
            if (phase >= JournalPhase.Planned)
            {
                var plan = await state.PlanNoChangeAsync(fixture.RouteKey, scope, request,
                    Now + 1, CancellationToken.None);
                response = await ProductionMailboxOwnerControlTransportCodec
                    .AuthorNoChangeResponseAsync(request, restored.Anchor,
                        plan.IssuedAtUnixSeconds, plan.ExpiresAtUnixSeconds,
                        ResponseSigner(fixture.ResponderPrivateKey));
            }
            if (phase >= JournalPhase.Signed)
                await state.RecordNoChangeAsync(fixture.RouteKey, scope, request, response!,
                    Now + 2, CancellationToken.None);
            if (phase == JournalPhase.DeliveryAuthorized)
                await state.AuthorizeDeliveryAsync(fixture.RouteKey, scope,
                    request.CanonicalHash, Now + 2, CancellationToken.None);

            var revoked = await state.CommitOwnerRevocationAndFenceAsync(fixture.RouteKey,
                Bytes((byte)(120 + (int)phase), 16),
                fixture.VerifyRevocation(ProductionMailboxRouteContinuityRevocationReason.OwnerRevoked),
                CancellationToken.None);
            Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.Accepted, revoked.Status);
            var blocked = await state.PrepareNoChangeAsync(fixture.RouteKey, scope, request,
                Now + 3, CancellationToken.None);
            Assert.Equal(ProductionMailboxOwnerRequestStatus.Revoked, blocked.Status);
        }
    }

    [Fact]
    public async Task InMemoryRevocation_MetadataIdIsTombstoned_WhileArtifactHashIsOperationIdentity()
    {
        var concrete = new InMemoryProductionMailboxStateStore();
        var continuity = (IProductionMailboxRouteContinuityStateStore)concrete;
        var state = (IProductionMailboxOwnerControlStateStore)concrete;
        var fixture = await ProductionMailboxRouteContinuityAdvancedStateTests.AdvancedFixture
            .CreateAsync(continuity, 77);
        var id = Bytes(151, 16);
        var revocation = fixture.VerifyRevocation(
            ProductionMailboxRouteContinuityRevocationReason.OwnerRevoked);
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.Accepted,
            (await state.CommitOwnerRevocationAndFenceAsync(fixture.RouteKey, id,
                revocation, CancellationToken.None)).Status);
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.ExactReplay,
            (await state.CommitOwnerRevocationAndFenceAsync(fixture.RouteKey,
                Bytes(152, 16), revocation, CancellationToken.None)).Status);
        var changed = fixture.VerifyRevocation(
            ProductionMailboxRouteContinuityRevocationReason.OwnerKeyRotated);
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.Conflict,
            (await state.CommitOwnerRevocationAndFenceAsync(fixture.RouteKey, id,
                changed, CancellationToken.None)).Status);
    }

    [Fact]
    public async Task InMemoryRequestId_RemainsForkTombstoneAfterRequestExpiry()
    {
        var concrete = new InMemoryProductionMailboxStateStore();
        var continuity = (IProductionMailboxRouteContinuityStateStore)concrete;
        var state = (IProductionMailboxOwnerControlStateStore)concrete;
        var fixture = await ProductionMailboxRouteContinuityAdvancedStateTests.AdvancedFixture
            .CreateAsync(continuity, 91);
        var restored = await continuity.GetRestoredGenesisAsync(fixture.RouteKey,
            CancellationToken.None);
        Assert.NotNull(restored);
        var id = Bytes(92, 32);
        var first = await ProductionMailboxOwnerControlTransportCodec.AuthorOwnerDirectRequestAsync(
            restored.Anchor, restored.Cursor, id, Now, Now + 2,
            RequestSigner(fixture.OwnerPrivateKey));
        var changed = await ProductionMailboxOwnerControlTransportCodec.AuthorOwnerDirectRequestAsync(
            restored.Anchor, restored.Cursor, id, Now + 3, Now + 30,
            RequestSigner(fixture.OwnerPrivateKey));
        Assert.Equal(ProductionMailboxOwnerRequestStatus.Prepared,
            (await state.PrepareNoChangeAsync(fixture.RouteKey, Bytes(93, 32), first, Now,
                CancellationToken.None)).Status);
        Assert.Equal(ProductionMailboxOwnerRequestStatus.Conflict,
            (await state.PrepareNoChangeAsync(fixture.RouteKey, Bytes(94, 32), changed, Now + 3,
                CancellationToken.None)).Status);
    }

    [Fact]
    public async Task InMemoryAbandonedKey_ClaimsOnce_RetriesAfterLease_AndCompletes()
    {
        var state = (IProductionMailboxOwnerControlStateStore)
            new InMemoryProductionMailboxStateStore();
        var route = Bytes(101, 32); var operation = Bytes(102, 32);
        var token = Bytes(103, 32);
        var prepared = await state.PrepareOwnerEnrollmentAsync(route, Bytes(104, 16),
            Bytes(105, 32), operation, Bytes(106, 32), Bytes(107, 32), token, Now,
            CancellationToken.None);
        Assert.Equal(ProductionMailboxOwnerEnrollmentStatus.Prepared, prepared.Status);
        var expired = Now + ProductionMailboxOwnerControlConstants
            .MaximumResponderCertificateLifetimeSeconds;
        var first = await state.ClaimAbandonedOwnerKeyAsync(expired, expired + 10,
            CancellationToken.None);
        Assert.NotNull(first); Assert.Equal(token, first.KeyToken);
        Assert.Null(await state.ClaimAbandonedOwnerKeyAsync(expired + 1, expired + 11,
            CancellationToken.None));
        var retry = await state.ClaimAbandonedOwnerKeyAsync(expired + 10, expired + 20,
            CancellationToken.None);
        Assert.NotNull(retry); Assert.Equal(token, retry.KeyToken);
        await state.CompleteAbandonedOwnerKeyAsync(route, operation, token,
            CancellationToken.None);
        Assert.Null(await state.ClaimAbandonedOwnerKeyAsync(expired + 21, expired + 31,
            CancellationToken.None));
    }

    [Fact]
    public async Task InMemoryOwnerControlCapacity_FailsClosedBeforeThirdEnrollment()
    {
        var state = (IProductionMailboxOwnerControlStateStore)
            new InMemoryProductionMailboxStateStore(ownerControlLimits:
                new ProductionMailboxOwnerControlStoreLimits(
                    MaximumEntriesPerRoute: 7, MaximumEntriesGlobal: 7,
                    MaximumStateBytes: 32 * 1024 * 1024));
        var route = Bytes(111, 32); var source = Bytes(112, 32);
        for (var index = 0; index < 2; index++)
            Assert.Equal(ProductionMailboxOwnerEnrollmentStatus.Prepared,
                (await state.PrepareOwnerEnrollmentAsync(route,
                    Bytes((byte)(113 + index), 16), Bytes((byte)(115 + index), 32),
                    Bytes((byte)(117 + index), 32), Bytes((byte)(119 + index), 32),
                    source, Bytes((byte)(121 + index), 32), Now,
                    CancellationToken.None)).Status);
        Assert.Equal(ProductionMailboxOwnerEnrollmentStatus.CapacityExceeded,
            (await state.PrepareOwnerEnrollmentAsync(route, Bytes(123, 16), Bytes(124, 32),
                Bytes(125, 32), Bytes(126, 32), source, Bytes(127, 32), Now,
                CancellationToken.None)).Status);

        var capped = new InMemoryProductionMailboxStateStore(ownerControlLimits:
            new ProductionMailboxOwnerControlStoreLimits(
                MaximumEntriesPerRoute: 4, MaximumEntriesGlobal: 4,
                MaximumStateBytes: 32 * 1024 * 1024));
        var fixture = await ProductionMailboxRouteContinuityAdvancedStateTests.AdvancedFixture
            .CreateAsync(capped, 128);
        var cappedState = (IProductionMailboxOwnerControlStateStore)capped;
        Assert.Equal(ProductionMailboxOwnerEnrollmentStatus.CapacityExceeded,
            (await cappedState.PrepareOwnerEnrollmentAsync(fixture.RouteKey, Bytes(129, 16),
                Bytes(130, 32), fixture.Enrollment.CanonicalDelegationHash,
                fixture.GenesisIntentHash, fixture.SourceArtifactClosureHash,
                fixture.OwnerControlKeyToken, Now, CancellationToken.None)).Status);
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.Accepted,
            (await cappedState.CommitOwnerRevocationAndFenceAsync(fixture.RouteKey,
                Bytes(131, 16), fixture.VerifyRevocation(
                    ProductionMailboxRouteContinuityRevocationReason.OwnerRevoked),
                CancellationToken.None)).Status);
    }

    [Fact]
    public async Task InMemoryCapacity_VerifiesExpiryBeforeGc_AndConcurrentPrepareCanCommit()
    {
        var concrete = new InMemoryProductionMailboxStateStore();
        var continuity = (IProductionMailboxRouteContinuityStateStore)concrete;
        var state = (IProductionMailboxOwnerControlStateStore)concrete;
        var fixture = await ProductionMailboxRouteContinuityAdvancedStateTests.AdvancedFixture
            .CreateAsync(continuity, 131);
        var restored = await continuity.GetRestoredGenesisAsync(fixture.RouteKey,
            CancellationToken.None);
        Assert.NotNull(restored);
        var request = await ProductionMailboxOwnerControlTransportCodec.AuthorOwnerDirectRequestAsync(
            restored.Anchor, restored.Cursor, Bytes(132, 32), Now, Now + 30,
            RequestSigner(fixture.OwnerPrivateKey));
        Assert.Equal(ProductionMailboxOwnerRequestStatus.Prepared,
            (await state.PrepareNoChangeAsync(fixture.RouteKey, Bytes(133, 32), request, Now,
                CancellationToken.None)).Status);
        var requestsField = typeof(InMemoryProductionMailboxStateStore).GetField(
            "ownerControlRequests", BindingFlags.Instance | BindingFlags.NonPublic);
        var requests = Assert.IsAssignableFrom<IDictionary>(requestsField!.GetValue(concrete));
        var values = requests.Values.GetEnumerator(); Assert.True(values.MoveNext());
        var stored = values.Current!;
        var expiryField = stored.GetType().GetField("<ExpiresAtUnixSeconds>k__BackingField",
            BindingFlags.Instance | BindingFlags.NonPublic);
        expiryField!.SetValue(stored, Now - 1);
        await Assert.ThrowsAsync<InvalidDataException>(() => state.PrepareOwnerEnrollmentAsync(
            Bytes(134, 32), Bytes(135, 16), Bytes(136, 32), Bytes(137, 32), Bytes(138, 32),
            fixture.SourceArtifactClosureHash, Bytes(139, 32), Now,
            CancellationToken.None).AsTask());
        Assert.Single(requests.Values.Cast<object>());

        var seedStore = new InMemoryProductionMailboxStateStore();
        var seed = await ProductionMailboxRouteContinuityAdvancedStateTests.AdvancedFixture
            .CreateAsync(seedStore, 141);
        var target = new InMemoryProductionMailboxStateStore();
        var targetState = (IProductionMailboxOwnerControlStateStore)target;
        var prepares = await Task.WhenAll(Enumerable.Range(0, 2).Select(_ =>
            targetState.PrepareOwnerEnrollmentAsync(seed.RouteKey, seed.EnrollmentRequestId,
                seed.EnrollmentRequestHash, seed.Enrollment.CanonicalDelegationHash,
                seed.GenesisIntentHash, seed.SourceArtifactClosureHash,
                seed.OwnerControlKeyToken, Now, CancellationToken.None).AsTask()));
        Assert.All(prepares, value =>
            Assert.Equal(ProductionMailboxOwnerEnrollmentStatus.Prepared, value.Status));
        var ocr = ProductionMailboxOwnerControlTransportCodec.DecodeResponderCertificate(
            seed.GenesisPlan.CanonicalOwnerControlResponderCertificate.Span);
        var committed = await targetState.CommitOwnerEnrollmentAsync(seed.RouteKey,
            seed.EnrollmentRequestId, seed.EnrollmentRequestHash,
            seed.Enrollment.CanonicalDelegationHash, seed.SourceArtifactClosureHash,
            seed.GenesisPlan, new(seed.OwnerControlKeyToken,
                ocr.ResponderEd25519PublicKey.ToArray()),
            ProductionMailboxOwnerControlHostCodec.EncodeEnrollmentResponse(seed.GenesisPlan),
            Now, CancellationToken.None);
        Assert.Equal(ProductionMailboxOwnerEnrollmentStatus.Prepared, committed);
    }

    [Fact]
    public async Task InMemoryRequestAdmission_RecomputesAfterGc_AndExactReplayCostsZero()
    {
        async ValueTask<ProductionMailboxOwnerRequestStatus> RunAsync(int maximumEntries,
            byte variant)
        {
            var concrete = new InMemoryProductionMailboxStateStore(ownerControlLimits:
                new ProductionMailboxOwnerControlStoreLimits(
                    MaximumEntriesPerRoute: maximumEntries,
                    MaximumEntriesGlobal: maximumEntries,
                    MaximumStateBytes: 64 * 1024 * 1024));
            var continuity = (IProductionMailboxRouteContinuityStateStore)concrete;
            var state = (IProductionMailboxOwnerControlStateStore)concrete;
            var fixture = await ProductionMailboxRouteContinuityAdvancedStateTests.AdvancedFixture
                .CreateAsync(continuity, variant);
            var restored = await continuity.GetRestoredGenesisAsync(fixture.RouteKey,
                CancellationToken.None);
            Assert.NotNull(restored);
            var scope = Bytes((byte)(variant + 1), 32);
            var first = await ProductionMailboxOwnerControlTransportCodec
                .AuthorOwnerDirectRequestAsync(restored.Anchor, restored.Cursor,
                    Bytes((byte)(variant + 2), 32), Now, Now + 2,
                    RequestSigner(fixture.OwnerPrivateKey));
            Assert.Equal(ProductionMailboxOwnerRequestStatus.Prepared,
                (await state.PrepareNoChangeAsync(fixture.RouteKey, scope, first, Now,
                    CancellationToken.None)).Status);
            Assert.Equal(ProductionMailboxOwnerRequestStatus.Prepared,
                (await state.PrepareNoChangeAsync(fixture.RouteKey, scope, first, Now + 1,
                    CancellationToken.None)).Status);
            var plan = await state.PlanNoChangeAsync(fixture.RouteKey, scope, first, Now + 1,
                CancellationToken.None);
            var response = await ProductionMailboxOwnerControlTransportCodec
                .AuthorNoChangeResponseAsync(first, restored.Anchor,
                    plan.IssuedAtUnixSeconds, plan.ExpiresAtUnixSeconds,
                    ResponseSigner(fixture.ResponderPrivateKey));
            Assert.Equal(ProductionMailboxOwnerRequestStatus.Prepared,
                await state.RecordNoChangeAsync(fixture.RouteKey, scope, first, response,
                    Now + 1, CancellationToken.None));
            var replacement = await ProductionMailboxOwnerControlTransportCodec
                .AuthorOwnerDirectRequestAsync(restored.Anchor, restored.Cursor,
                    Bytes((byte)(variant + 3), 32), Now + 3, Now + 30,
                    RequestSigner(fixture.OwnerPrivateKey));
            return (await state.PrepareNoChangeAsync(fixture.RouteKey, scope, replacement,
                Now + 3, CancellationToken.None)).Status;
        }

        Assert.Equal(ProductionMailboxOwnerRequestStatus.Conflict,
            await RunAsync(6, 146));
        Assert.Equal(ProductionMailboxOwnerRequestStatus.Prepared,
            await RunAsync(7, 150));
    }

    [Fact]
    public async Task PostgreSqlRequestAndAliasBytes_AreReservedAtExactBoundary()
    {
        var connectionString = Environment.GetEnvironmentVariable("DEEP_TEST_POSTGRES");
        if (string.IsNullOrWhiteSpace(connectionString)) return;
        await using var database = await ProductionMailboxRouteContinuityAdvancedStateTests
            .PostgresTestDatabase.CreateAsync(connectionString);
        var key = Bytes(210, 32);
        var pgNow = checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        var highLimits = new ProductionMailboxOwnerControlStoreLimits(
            MaximumEntriesPerRoute: 100, MaximumEntriesGlobal: 100,
            MaximumStateBytes: 64 * 1024 * 1024);
        var high = new PostgreSqlProductionMailboxStateStore(database.ConnectionString,
            key, highLimits);
        var continuity = (IProductionMailboxRouteContinuityStateStore)high;
        var fixture = await ProductionMailboxRouteContinuityAdvancedStateTests.AdvancedFixture
            .CreateAsync(continuity, 211, nowUnixSeconds: pgNow);
        var state = (IProductionMailboxOwnerControlStateStore)high;
        for (var index = 0; index < 2; index++)
            Assert.Equal(ProductionMailboxOwnerEnrollmentStatus.Prepared,
                (await state.PrepareOwnerEnrollmentAsync(Bytes((byte)(212 + index), 32),
                    Bytes((byte)(214 + index), 16), Bytes((byte)(216 + index), 32),
                    Bytes((byte)(218 + index), 32), Bytes((byte)(220 + index), 32),
                    fixture.SourceArtifactClosureHash, Bytes((byte)(222 + index), 32), pgNow,
                    CancellationToken.None)).Status);
        int catalogLength;
        await using (var connection = new NpgsqlConnection(database.ConnectionString))
        {
            await connection.OpenAsync();
            await using var length = new NpgsqlCommand("""
                SELECT octet_length(protected_payload)
                FROM production_mailbox_route_genesis_v1 WHERE route_state_key=@route
                """, connection);
            length.Parameters.AddWithValue("route", fixture.RouteKey);
            catalogLength = (int)(await length.ExecuteScalarAsync())!;
        }
        var currentBytes = checked(
            ProductionMailboxOwnerControlAccounting.EnrollmentOperationMaximumBytes
            + ProductionMailboxOwnerControlAccounting.EnrollmentAliasBytes
            + ProductionMailboxOwnerControlAccounting.GenesisBytes(catalogLength)
            + 2 * (ProductionMailboxOwnerControlAccounting.EnrollmentOperationMaximumBytes
                + ProductionMailboxOwnerControlAccounting.EnrollmentAliasBytes
                + ProductionMailboxOwnerControlAccounting.GenesisBytes(
                    ProductionMailboxProtectedGenesisCatalog.MaximumPayloadBytes)));
        var requestLimit = checked(currentBytes
            + ProductionMailboxOwnerControlAccounting.TerminalReservationBytes
            + ProductionMailboxOwnerControlAccounting.NewOwnerRequestBytes);
        var restored = await continuity.GetRestoredGenesisAsync(fixture.RouteKey,
            CancellationToken.None);
        Assert.NotNull(restored);
        var scope = Bytes(224, 32);
        var first = await ProductionMailboxOwnerControlTransportCodec.AuthorOwnerDirectRequestAsync(
            restored.Anchor, restored.Cursor, Bytes(225, 32), pgNow, pgNow + 3,
            RequestSigner(fixture.OwnerPrivateKey));
        var below = (IProductionMailboxOwnerControlStateStore)
            new PostgreSqlProductionMailboxStateStore(database.ConnectionString, key,
                highLimits with { MaximumStateBytes = requestLimit - 1 });
        Assert.Equal(ProductionMailboxOwnerRequestStatus.Conflict,
            (await below.PrepareNoChangeAsync(fixture.RouteKey, scope, first, pgNow,
                CancellationToken.None)).Status);
        var exact = (IProductionMailboxOwnerControlStateStore)
            new PostgreSqlProductionMailboxStateStore(database.ConnectionString, key,
                highLimits with { MaximumStateBytes = requestLimit });
        Assert.Equal(ProductionMailboxOwnerRequestStatus.Prepared,
            (await exact.PrepareNoChangeAsync(fixture.RouteKey, scope, first, pgNow,
                CancellationToken.None)).Status);
        Assert.Equal(ProductionMailboxOwnerRequestStatus.Prepared,
            (await exact.PrepareNoChangeAsync(fixture.RouteKey, scope, first, pgNow + 1,
                CancellationToken.None)).Status);
        var plan = await exact.PlanNoChangeAsync(fixture.RouteKey, scope, first, pgNow + 1,
            CancellationToken.None);
        var response = await ProductionMailboxOwnerControlTransportCodec
            .AuthorNoChangeResponseAsync(first, restored.Anchor, plan.IssuedAtUnixSeconds,
                plan.ExpiresAtUnixSeconds, ResponseSigner(fixture.ResponderPrivateKey));
        Assert.Equal(ProductionMailboxOwnerRequestStatus.Prepared,
            await exact.RecordNoChangeAsync(fixture.RouteKey, scope, first, response,
                pgNow + 1, CancellationToken.None));

        var aliasLimit = checked(requestLimit
            + ProductionMailboxOwnerControlAccounting.EnrollmentAliasBytes);
        var aliasBelow = (IProductionMailboxOwnerControlStateStore)
            new PostgreSqlProductionMailboxStateStore(database.ConnectionString, key,
                highLimits with { MaximumStateBytes = aliasLimit - 1 });
        Assert.Equal(ProductionMailboxOwnerEnrollmentStatus.CapacityExceeded,
            (await aliasBelow.PrepareOwnerEnrollmentAsync(fixture.RouteKey, Bytes(226, 16),
                Bytes(227, 32), fixture.Enrollment.CanonicalDelegationHash,
                fixture.GenesisIntentHash, fixture.SourceArtifactClosureHash,
                fixture.OwnerControlKeyToken, pgNow + 1, CancellationToken.None)).Status);
        var aliasExact = (IProductionMailboxOwnerControlStateStore)
            new PostgreSqlProductionMailboxStateStore(database.ConnectionString, key,
                highLimits with { MaximumStateBytes = aliasLimit });
        Assert.Equal(ProductionMailboxOwnerEnrollmentStatus.ExactReplay,
            (await aliasExact.PrepareOwnerEnrollmentAsync(fixture.RouteKey, Bytes(226, 16),
                Bytes(227, 32), fixture.Enrollment.CanonicalDelegationHash,
                fixture.GenesisIntentHash, fixture.SourceArtifactClosureHash,
                fixture.OwnerControlKeyToken, pgNow + 1, CancellationToken.None)).Status);

        await Task.Delay(TimeSpan.FromSeconds(4));
        var replacementNow = checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        var replacement = await ProductionMailboxOwnerControlTransportCodec
            .AuthorOwnerDirectRequestAsync(restored.Anchor, restored.Cursor, Bytes(228, 32),
                replacementNow, replacementNow + 30,
                RequestSigner(fixture.OwnerPrivateKey));
        var replacementLimit = checked(aliasLimit
            + ProductionMailboxOwnerControlAccounting.OwnerRequestAliasBytes);
        var replacementBelow = (IProductionMailboxOwnerControlStateStore)
            new PostgreSqlProductionMailboxStateStore(database.ConnectionString, key,
                highLimits with { MaximumStateBytes = replacementLimit - 1 });
        Assert.Equal(ProductionMailboxOwnerRequestStatus.Conflict,
            (await replacementBelow.PrepareNoChangeAsync(fixture.RouteKey, scope, replacement,
                replacementNow, CancellationToken.None)).Status);
        var replacementExact = (IProductionMailboxOwnerControlStateStore)
            new PostgreSqlProductionMailboxStateStore(database.ConnectionString, key,
                highLimits with { MaximumStateBytes = replacementLimit });
        Assert.Equal(ProductionMailboxOwnerRequestStatus.Prepared,
            (await replacementExact.PrepareNoChangeAsync(fixture.RouteKey, scope, replacement,
                replacementNow, CancellationToken.None)).Status);
    }

    [Fact]
    public async Task PostgreSqlCapacity_AuthenticatesGc_ReservesRcr_AndIsMaxPlusOneBounded()
    {
        var connectionString = Environment.GetEnvironmentVariable("DEEP_TEST_POSTGRES");
        if (string.IsNullOrWhiteSpace(connectionString)) return;
        var pgNow = checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        await using (var database = await ProductionMailboxRouteContinuityAdvancedStateTests
                         .PostgresTestDatabase.CreateAsync(connectionString))
        {
            var key = Bytes(150, 32);
            var limits = new ProductionMailboxOwnerControlStoreLimits(
                MaximumEntriesPerRoute: 4, MaximumEntriesGlobal: 4,
                MaximumStateBytes: 32 * 1024 * 1024);
            var concrete = new PostgreSqlProductionMailboxStateStore(
                database.ConnectionString, key, limits);
            var fixture = await ProductionMailboxRouteContinuityAdvancedStateTests.AdvancedFixture
                .CreateAsync(concrete, 151, nowUnixSeconds: pgNow);
            var state = (IProductionMailboxOwnerControlStateStore)concrete;
            Assert.Equal(ProductionMailboxOwnerEnrollmentStatus.CapacityExceeded,
                (await state.PrepareOwnerEnrollmentAsync(fixture.RouteKey, Bytes(152, 16),
                    Bytes(153, 32), fixture.Enrollment.CanonicalDelegationHash,
                    fixture.GenesisIntentHash, fixture.SourceArtifactClosureHash,
                    fixture.OwnerControlKeyToken, pgNow, CancellationToken.None)).Status);
            Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.Accepted,
                (await state.CommitOwnerRevocationAndFenceAsync(fixture.RouteKey,
                    Bytes(154, 16), fixture.VerifyRevocation(
                        ProductionMailboxRouteContinuityRevocationReason.OwnerRevoked),
                    CancellationToken.None)).Status);
        }

        await using (var database = await ProductionMailboxRouteContinuityAdvancedStateTests
                         .PostgresTestDatabase.CreateAsync(connectionString))
        {
            var key = Bytes(160, 32);
            var concrete = new PostgreSqlProductionMailboxStateStore(database.ConnectionString,
                key);
            var continuity = (IProductionMailboxRouteContinuityStateStore)concrete;
            var fixture = await ProductionMailboxRouteContinuityAdvancedStateTests.AdvancedFixture
                .CreateAsync(continuity, 161, nowUnixSeconds: pgNow);
            var restored = await continuity.GetRestoredGenesisAsync(fixture.RouteKey,
                CancellationToken.None);
            Assert.NotNull(restored);
            var request = await ProductionMailboxOwnerControlTransportCodec
                .AuthorOwnerDirectRequestAsync(restored.Anchor, restored.Cursor, Bytes(162, 32),
                    pgNow, pgNow + 30, RequestSigner(fixture.OwnerPrivateKey));
            var scope = Bytes(163, 32);
            var state = (IProductionMailboxOwnerControlStateStore)concrete;
            Assert.Equal(ProductionMailboxOwnerRequestStatus.Prepared,
                (await state.PrepareNoChangeAsync(fixture.RouteKey, scope, request, pgNow,
                    CancellationToken.None)).Status);
            await using (var connection = new NpgsqlConnection(database.ConnectionString))
            {
                await connection.OpenAsync();
                await using var update = new NpgsqlCommand("""
                    UPDATE production_mailbox_owner_requests_v1 SET expires_at=@expires
                    WHERE active_scope=@scope
                    """, connection);
                update.Parameters.AddWithValue("expires", U64(pgNow - 1));
                update.Parameters.AddWithValue("scope", scope);
                Assert.Equal(1, await update.ExecuteNonQueryAsync());
            }
            await Assert.ThrowsAsync<InvalidDataException>(() =>
                state.PrepareOwnerEnrollmentAsync(Bytes(164, 32), Bytes(165, 16),
                    Bytes(166, 32), Bytes(167, 32), Bytes(168, 32),
                    fixture.SourceArtifactClosureHash, Bytes(169, 32), pgNow,
                    CancellationToken.None).AsTask());
            await using var verify = new NpgsqlConnection(database.ConnectionString);
            await verify.OpenAsync();
            await using var count = new NpgsqlCommand(
                "SELECT count(*) FROM production_mailbox_owner_requests_v1 WHERE active_scope=@scope",
                verify);
            count.Parameters.AddWithValue("scope", scope);
            Assert.Equal(1L, (long)(await count.ExecuteScalarAsync())!);
        }

        await using (var database = await ProductionMailboxRouteContinuityAdvancedStateTests
                         .PostgresTestDatabase.CreateAsync(connectionString))
        {
            var key = Bytes(170, 32);
            var high = (IProductionMailboxOwnerControlStateStore)
                new PostgreSqlProductionMailboxStateStore(database.ConnectionString, key,
                    new(MaximumEntriesPerRoute: 100, MaximumEntriesGlobal: 100,
                        MaximumStateBytes: 64 * 1024 * 1024));
            var source = Bytes(171, 32);
            for (var index = 0; index < 3; index++)
                Assert.Equal(ProductionMailboxOwnerEnrollmentStatus.Prepared,
                    (await high.PrepareOwnerEnrollmentAsync(Bytes((byte)(172 + index), 32),
                        Bytes((byte)(175 + index), 16), Bytes((byte)(178 + index), 32),
                        Bytes((byte)(181 + index), 32), Bytes((byte)(184 + index), 32), source,
                        Bytes((byte)(187 + index), 32), pgNow,
                        CancellationToken.None)).Status);
            var low = (IProductionMailboxOwnerControlStateStore)
                new PostgreSqlProductionMailboxStateStore(database.ConnectionString, key,
                    new(MaximumEntriesPerRoute: 4, MaximumEntriesGlobal: 4,
                        MaximumStateBytes: 64 * 1024 * 1024));
            Assert.Equal(ProductionMailboxOwnerEnrollmentStatus.CapacityExceeded,
                (await low.PrepareOwnerEnrollmentAsync(Bytes(190, 32), Bytes(191, 16),
                    Bytes(192, 32), Bytes(193, 32), Bytes(194, 32), source, Bytes(195, 32),
                    pgNow, CancellationToken.None)).Status);
        }
    }

    [Fact]
    public async Task PostgreSqlRestoredGenesis_UsesConfiguredRouteLockTimeout()
    {
        var connectionString = Environment.GetEnvironmentVariable("DEEP_TEST_POSTGRES");
        if (string.IsNullOrWhiteSpace(connectionString)) return;
        await using var database = await ProductionMailboxRouteContinuityAdvancedStateTests
            .PostgresTestDatabase.CreateAsync(connectionString);
        var key = Bytes(200, 32);
        var limits = new ProductionMailboxOwnerControlStoreLimits(
            LockTimeoutSeconds: 1, StatementTimeoutSeconds: 3,
            IdleTransactionTimeoutSeconds: 3);
        var concrete = new PostgreSqlProductionMailboxStateStore(database.ConnectionString,
            key, limits);
        var fixture = await ProductionMailboxRouteContinuityAdvancedStateTests.AdvancedFixture
            .CreateAsync(concrete, 201,
                nowUnixSeconds: checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds()));
        await using var blocker = new NpgsqlConnection(database.ConnectionString);
        await blocker.OpenAsync();
        await using var transaction = await blocker.BeginTransactionAsync();
        await using (var hold = new NpgsqlCommand(
                         "SELECT pg_advisory_xact_lock(hashtextextended(encode(@key,'hex'),0))",
                         blocker, transaction))
        {
            hold.Parameters.AddWithValue("key", fixture.RouteKey);
            await hold.ExecuteNonQueryAsync();
        }
        var elapsed = Stopwatch.StartNew();
        var error = await Assert.ThrowsAsync<PostgresException>(() =>
            ((IProductionMailboxRouteContinuityStateStore)concrete)
                .GetRestoredGenesisAsync(fixture.RouteKey, CancellationToken.None).AsTask());
        elapsed.Stop();
        Assert.Equal(PostgresErrorCodes.LockNotAvailable, error.SqlState);
        Assert.InRange(elapsed.Elapsed, TimeSpan.FromMilliseconds(500), TimeSpan.FromSeconds(3));
        await transaction.RollbackAsync();
    }

    private static ProductionMailboxOwnerControlRequestSigner RequestSigner(byte[] privateKey) =>
        (request, destination, _) =>
        {
            var signature = PublicKeyAuth.SignDetached(request.SigningBytes.ToArray(), privateKey);
            signature.CopyTo(destination.Span);
            return ValueTask.FromResult(signature.Length);
        };

    private static ProductionMailboxOwnerControlResponseSigner ResponseSigner(byte[] privateKey) =>
        (request, destination, _) =>
        {
            var signature = PublicKeyAuth.SignDetached(request.SigningBytes.ToArray(), privateKey);
            signature.CopyTo(destination.Span);
            return ValueTask.FromResult(signature.Length);
        };

    private static byte[] Bytes(byte value, int length) =>
        Enumerable.Repeat(value, length).Select(static item => (byte)item).ToArray();

    private static byte[] U64(ulong value)
    {
        var result = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(result, value);
        return result;
    }

    private enum JournalPhase { Prepared, Planned, Signed, DeliveryAuthorized }
}
