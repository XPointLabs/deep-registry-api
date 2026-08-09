extern alias xnode;

using System.Buffers.Binary;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxAuthority;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.MailboxTopology;
using Deep.Registry.Api.ProductionMailbox;
using Npgsql;
using Sodium;
using ActualXNode = xnode::XNode;

namespace Deep.Registry.Api.Tests;

public sealed class ProductionMailboxV2PublicationTests
{
    [Fact]
    public async Task InMemoryV2Activation_IsAtomicReplayableAndCapacityGated()
    {
        var now = checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        var clock = new ManualClock(DateTimeOffset.FromUnixTimeSeconds(checked((long)now)));
        var store = new InMemoryProductionMailboxStateStore(clock);
        await RunStateContractAsync(store, store, now, clock);
    }

    [Fact]
    public async Task PostgreSqlV2Activation_MatchesAcrossRestartAndConcurrentFinalize()
    {
        var connectionString = Environment.GetEnvironmentVariable("DEEP_TEST_POSTGRES");
        if (string.IsNullOrWhiteSpace(connectionString)) return;
        await using var database = await PostgresDatabase.CreateAsync(connectionString);
        var now = checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        var store = NewPostgresStore(database);
        var activationKey = await RunStateContractAsync(store, store, now, null);
        var restarted = (IProductionMailboxV2PublicationStateStore)
            NewPostgresStore(database);
        var snapshot = await restarted.GetV2ActivationAsync(activationKey,
            CancellationToken.None);
        Assert.NotNull(snapshot);
        Assert.True(snapshot.Published);
        var results = await Task.WhenAll(
            restarted.TryFinalizeV2ActivationAsync(activationKey, 60,
                CancellationToken.None).AsTask(),
            ((IProductionMailboxV2PublicationStateStore)
                NewPostgresStore(database))
                .TryFinalizeV2ActivationAsync(activationKey, 60,
                    CancellationToken.None).AsTask());
        Assert.All(results, static result =>
            Assert.Equal(ProductionMailboxV2ActivationCommitStatus.Published, result));
    }

    [Fact]
    public async Task PostgreSqlV2Activation_SourceRaceAndStoredCorruptionFailClosed()
    {
        var connectionString = Environment.GetEnvironmentVariable("DEEP_TEST_POSTGRES");
        if (string.IsNullOrWhiteSpace(connectionString)) return;
        await using var database = await PostgresDatabase.CreateAsync(connectionString);
        var now = checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        var store = NewPostgresStore(database);
        var fixture = await CreateActivationAsync(store, store, now);
        await SeedCapacityReceiptsAsync(store, fixture, now);
        await AcknowledgeAllTargetsAsync((IProductionMailboxV2PublicationStateStore)store,
            fixture, now);

        var routeStore = (IProductionMailboxRouteContinuityStateStore)store;
        var advanced = await routeStore.CommitVerifiedTransitionAsync(
            fixture.Source.RouteStateKey, fixture.Source.CanonicalRouteOriginLkg,
            CreateNextTransition(fixture.Source, 97), CancellationToken.None);
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.Accepted, advanced.Status);
        Assert.Equal(ProductionMailboxV2ActivationCommitStatus.SourceChanged,
            await ((IProductionMailboxV2PublicationStateStore)store)
                .TryFinalizeV2ActivationAsync(fixture.ActivationKey, 60,
                    CancellationToken.None));

        await using var connection = new NpgsqlConnection(database.ConnectionString);
        await connection.OpenAsync();
        await using (var corruptTarget = new NpgsqlCommand(
            "UPDATE production_mailbox_v2_activation_targets SET acknowledged=true,canonical_attempt=NULL,attempt_sha256=NULL,attempted_at=NULL WHERE activation_state_key=@key",
            connection))
        {
            corruptTarget.Parameters.AddWithValue("key", fixture.ActivationKey);
            Assert.True(await corruptTarget.ExecuteNonQueryAsync() > 0);
        }
        var restarted = (IProductionMailboxV2PublicationStateStore)
            NewPostgresStore(database);
        await Assert.ThrowsAsync<InvalidDataException>(() => restarted.GetV2ActivationAsync(
            fixture.ActivationKey, CancellationToken.None).AsTask());

        await using (var repairTarget = new NpgsqlCommand(
            "UPDATE production_mailbox_v2_activation_targets SET acknowledged=false WHERE activation_state_key=@key",
            connection))
        {
            repairTarget.Parameters.AddWithValue("key", fixture.ActivationKey);
            Assert.True(await repairTarget.ExecuteNonQueryAsync() > 0);
        }
        await using (var corruptSource = new NpgsqlCommand(
            "UPDATE production_mailbox_v2_activations SET source_fingerprint=@value WHERE activation_state_key=@key",
            connection))
        {
            corruptSource.Parameters.AddWithValue("value", Bytes(99, 32));
            corruptSource.Parameters.AddWithValue("key", fixture.ActivationKey);
            Assert.Equal(1, await corruptSource.ExecuteNonQueryAsync());
        }
        await Assert.ThrowsAsync<InvalidDataException>(() => restarted.GetV2ActivationAsync(
            fixture.ActivationKey, CancellationToken.None).AsTask());
    }

    [Theory]
    [InlineData("endpoint")]
    [InlineData("pin")]
    [InlineData("target")]
    [InlineData("envelope")]
    [InlineData("mode")]
    [InlineData("authorization")]
    [InlineData("transcript")]
    public async Task PostgreSqlReload_SemanticCorruptionPrecedesAllCallbacks(string mutation)
    {
        var connectionString = Environment.GetEnvironmentVariable("DEEP_TEST_POSTGRES");
        if (string.IsNullOrWhiteSpace(connectionString)) return;
        await using var database = await PostgresDatabase.CreateAsync(connectionString);
        var now = checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        var store = NewPostgresStore(database);
        var fixture = await CreateActivationAsync(store, store, now);
        var state = fixture.Created.State!; var target = state.Targets[0];
        await using var connection = new NpgsqlConnection(database.ConnectionString);
        await connection.OpenAsync();
        var (sql, name, value) = mutation switch
        {
            "endpoint" => ("UPDATE production_mailbox_v2_activation_targets SET endpoint=@value WHERE activation_state_key=@key AND target_replica_id=@target", "value", (object)"https://attacker.example.net/"),
            "pin" => ("UPDATE production_mailbox_v2_activation_targets SET current_spki_sha256=@value WHERE activation_state_key=@key AND target_replica_id=@target", "value", Bytes(110, 32)),
            "target" => ("UPDATE production_mailbox_v2_activation_targets SET target_replica_id=@value WHERE activation_state_key=@key AND target_replica_id=@target", "value", Bytes(111, 32)),
            "envelope" => ("UPDATE production_mailbox_v2_activations SET canonical_envelope=@value WHERE activation_state_key=@key", "value", Mutate(state.CanonicalEnvelope.ToArray())),
            "mode" => ("UPDATE production_mailbox_v2_activations SET mode=@value WHERE activation_state_key=@key", "value", (object)(short)(state.Mode == ProductionMailboxSelectionSuccessorMode.DirectPromotion ? 2 : 1)),
            "authorization" => ("UPDATE production_mailbox_v2_activations SET authorization_kind=@value WHERE activation_state_key=@key", "value", (object)(short)(state.AuthorizationKind == ProductionMailboxRouteAuthorizationKind.OwnerPRA2 ? 2 : 1)),
            _ => ("UPDATE production_mailbox_v2_activations SET cache_transcript_hash=@value WHERE activation_state_key=@key", "value", (object)Bytes(112, 32))
        };
        await using (var command = new NpgsqlCommand(sql, connection))
        {
            command.Parameters.AddWithValue(name, value);
            command.Parameters.AddWithValue("key", fixture.ActivationKey);
            if (sql.Contains("@target", StringComparison.Ordinal))
                command.Parameters.AddWithValue("target", target.ReplicaId.ToArray());
            Assert.True(await command.ExecuteNonQueryAsync() > 0);
        }
        var restarted = (IProductionMailboxV2PublicationStateStore)
            NewPostgresStore(database);
        var capacity = new RecordingCapacityGate(); var transport = new RecordingTransport();
        var signer = new CountingSigner(fixture.PublisherSigner);
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            new ProductionMailboxV2Publisher(restarted, capacity, transport, signer,
                fixture.PublisherPublicKey, TimeProvider.System, 300, 60)
                .PublishAsync(fixture.ActivationKey, CancellationToken.None).AsTask());
        Assert.Equal(0, capacity.Calls); Assert.Equal(0, signer.Calls);
        Assert.Empty(transport.Commands);
    }

    [Fact]
    public async Task PostgreSqlReload_BoundsRowsBeforeMaterializationAndCallbacks()
    {
        var connectionString = Environment.GetEnvironmentVariable("DEEP_TEST_POSTGRES");
        if (string.IsNullOrWhiteSpace(connectionString)) return;
        await using var database = await PostgresDatabase.CreateAsync(connectionString);
        var now = checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        var store = NewPostgresStore(database);
        var fixture = await CreateActivationAsync(store, store, now);
        await using var connection = new NpgsqlConnection(database.ConnectionString);
        await connection.OpenAsync();
        await Assert.ThrowsAsync<PostgresException>(async () =>
        {
            await using var oversized = new NpgsqlCommand(
                "UPDATE production_mailbox_v2_activations SET canonical_envelope=@value WHERE activation_state_key=@key",
                connection);
            oversized.Parameters.AddWithValue("value",
                new byte[ProductionMailboxV2WireCodec.MaximumEnvelopeBytes + 1]);
            oversized.Parameters.AddWithValue("key", fixture.ActivationKey);
            await oversized.ExecuteNonQueryAsync();
        });
        await Assert.ThrowsAsync<PostgresException>(async () =>
        {
            await using var oversized = new NpgsqlCommand(
                "UPDATE production_mailbox_v2_activation_targets SET endpoint=@value WHERE activation_state_key=@key",
                connection);
            oversized.Parameters.AddWithValue("value", "https://" + new string('a', 520) + "/");
            oversized.Parameters.AddWithValue("key", fixture.ActivationKey);
            await oversized.ExecuteNonQueryAsync();
        });
        for (var index = 0; index < 5; index++)
        {
            await using var insert = new NpgsqlCommand(
                "INSERT INTO production_mailbox_v2_activation_targets(activation_state_key,target_replica_id,endpoint,current_spki_sha256,next_spki_sha256,canonical_attempt,attempt_sha256,attempted_at,acknowledged) VALUES(@key,@target,@endpoint,@current,@next,NULL,NULL,NULL,false)",
                connection);
            insert.Parameters.AddWithValue("key", fixture.ActivationKey);
            insert.Parameters.AddWithValue("target", Bytes((byte)(120 + index), 32));
            insert.Parameters.AddWithValue("endpoint", $"https://extra-{index}.example.net/");
            insert.Parameters.AddWithValue("current", Bytes((byte)(130 + index), 32));
            insert.Parameters.AddWithValue("next", Bytes((byte)(140 + index), 32));
            await insert.ExecuteNonQueryAsync();
        }
        var capacity = new RecordingCapacityGate(); var transport = new RecordingTransport();
        var signer = new CountingSigner(fixture.PublisherSigner);
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            new ProductionMailboxV2Publisher(
                NewPostgresStore(database),
                capacity, transport, signer, fixture.PublisherPublicKey,
                TimeProvider.System, 300, 60)
                .PublishAsync(fixture.ActivationKey, CancellationToken.None).AsTask());
        Assert.Equal(0, capacity.Calls); Assert.Equal(0, signer.Calls);
        Assert.Empty(transport.Commands);
    }

    [Fact]
    public async Task PreparedActivation_AttestationCrashReplayPreservesExactIdentity()
    {
        var now = checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        var clock = new ManualClock(DateTimeOffset.FromUnixTimeSeconds(checked((long)now)));
        var store = new InMemoryProductionMailboxStateStore(clock);
        var fixture = await CreateActivationAsync(store, store, now, attest: false);
        var prepared = fixture.Created.State!;
        Assert.Empty(prepared.VerifiedPlanSignature.ToArray());
        var before = new[] { prepared.CacheSalt.ToArray(), prepared.LineageCommitment.ToArray(),
            prepared.EnvelopeSha256.ToArray(), prepared.CanonicalEnvelope.ToArray() };
        var capacity = new RecordingCapacityGate(); var transport = new RecordingTransport();
        var publisherSigner = new CountingSigner(fixture.PublisherSigner);
        Assert.Equal(ProductionMailboxV2ActivationCommitStatus.Incomplete,
            await new ProductionMailboxV2Publisher(store, capacity, transport,
                publisherSigner, fixture.PublisherPublicKey, clock, 300, 60)
                .PublishAsync(fixture.ActivationKey, CancellationToken.None));
        Assert.Equal(0, capacity.Calls); Assert.Equal(0, publisherSigner.Calls);
        Assert.Empty(transport.Commands);
        Assert.Empty(await ((IProductionMailboxV2PublicationStateStore)store)
            .ListPendingV2ActivationKeysAsync(16, CancellationToken.None));

        var signature = fixture.PublisherSigner.SignDirect(
            ProductionMailboxV2ActivationAttestation.GetSigningBytes(prepared));
        Assert.Equal(ProductionMailboxV2ActivationCommitStatus.Conflict,
            (await ((IProductionMailboxV2PublicationStateStore)store)
                .RecordV2ActivationAttestationAsync(fixture.ActivationKey,
                    Bytes(117, 64), CancellationToken.None)).Status);
        var accepted = await ((IProductionMailboxV2PublicationStateStore)store)
            .RecordV2ActivationAttestationAsync(fixture.ActivationKey, signature,
                CancellationToken.None);
        Assert.Equal(ProductionMailboxV2ActivationCommitStatus.Accepted, accepted.Status);
        var replay = await ((IProductionMailboxV2PublicationStateStore)store)
            .RecordV2ActivationAttestationAsync(fixture.ActivationKey, signature,
                CancellationToken.None);
        Assert.Equal(ProductionMailboxV2ActivationCommitStatus.ExactReplay, replay.Status);
        var after = replay.State!;
        Assert.Equal(before[0], after.CacheSalt.ToArray());
        Assert.Equal(before[1], after.LineageCommitment.ToArray());
        Assert.Equal(before[2], after.EnvelopeSha256.ToArray());
        Assert.Equal(before[3], after.CanonicalEnvelope.ToArray());
    }

    [Fact]
    public async Task PostgreSqlReload_MaterializedIdentityMutationPrecedesAllCallbacks()
    {
        var connectionString = Environment.GetEnvironmentVariable("DEEP_TEST_POSTGRES");
        if (string.IsNullOrWhiteSpace(connectionString)) return;
        await using var database = await PostgresDatabase.CreateAsync(connectionString);
        var now = checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        var store = NewPostgresStore(database);
        var fixture = await CreateActivationAsync(store, store, now);
        var replacement = fixture.Prepared.Materialize(() => Bytes(118, 32));
        await using (var connection = new NpgsqlConnection(database.ConnectionString))
        {
            await connection.OpenAsync();
            await using var command = new NpgsqlCommand(
                "UPDATE production_mailbox_v2_activations SET cache_salt=@salt,lineage_commitment=@lineage,canonical_envelope=@envelope,envelope_sha256=@hash WHERE activation_state_key=@key",
                connection);
            command.Parameters.AddWithValue("salt", replacement.CacheSalt.ToArray());
            command.Parameters.AddWithValue("lineage", replacement.LineageCommitment.ToArray());
            command.Parameters.AddWithValue("envelope", replacement.CanonicalEnvelope.ToArray());
            command.Parameters.AddWithValue("hash", replacement.EnvelopeSha256.ToArray());
            command.Parameters.AddWithValue("key", fixture.ActivationKey);
            Assert.Equal(1, await command.ExecuteNonQueryAsync());
        }
        var capacity = new RecordingCapacityGate(); var transport = new RecordingTransport();
        var signer = new CountingSigner(fixture.PublisherSigner);
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            new ProductionMailboxV2Publisher(
                NewPostgresStore(database),
                capacity, transport, signer, fixture.PublisherPublicKey,
                TimeProvider.System, 300, 60)
                .PublishAsync(fixture.ActivationKey, CancellationToken.None).AsTask());
        Assert.Equal(0, capacity.Calls); Assert.Equal(0, signer.Calls);
        Assert.Empty(transport.Commands);
    }

    [Fact]
    public async Task PostgreSqlPreparedAttestation_RecoversBeforeAndAfterRecord()
    {
        var connectionString = Environment.GetEnvironmentVariable("DEEP_TEST_POSTGRES");
        if (string.IsNullOrWhiteSpace(connectionString)) return;
        await using var database = await PostgresDatabase.CreateAsync(connectionString);
        var now = checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        var initial = NewPostgresStore(database);
        var fixture = await CreateActivationAsync(initial, initial, now, attest: false);
        var prepared = fixture.Created.State!;
        var identity = new[] { prepared.CacheSalt.ToArray(),
            prepared.LineageCommitment.ToArray(), prepared.EnvelopeSha256.ToArray(),
            prepared.CanonicalEnvelope.ToArray() };

        var beforeRecord = (IProductionMailboxV2PublicationStateStore)
            NewPostgresStore(database);
        var restartedPrepared = await beforeRecord.GetV2ActivationAsync(
            fixture.ActivationKey, CancellationToken.None);
        Assert.NotNull(restartedPrepared);
        Assert.Empty(restartedPrepared.VerifiedPlanSignature.ToArray());
        var signature = fixture.PublisherSigner.SignDirect(
            ProductionMailboxV2ActivationAttestation.GetSigningBytes(restartedPrepared));

        var afterSignerCrash = (IProductionMailboxV2PublicationStateStore)
            NewPostgresStore(database);
        var accepted = await afterSignerCrash.RecordV2ActivationAttestationAsync(
            fixture.ActivationKey, signature, CancellationToken.None);
        Assert.Equal(ProductionMailboxV2ActivationCommitStatus.Accepted, accepted.Status);
        var afterResponseLoss = (IProductionMailboxV2PublicationStateStore)
            NewPostgresStore(database);
        var replay = await afterResponseLoss.RecordV2ActivationAttestationAsync(
            fixture.ActivationKey, signature, CancellationToken.None);
        Assert.Equal(ProductionMailboxV2ActivationCommitStatus.ExactReplay, replay.Status);
        Assert.Equal(identity[0], replay.State!.CacheSalt.ToArray());
        Assert.Equal(identity[1], replay.State.LineageCommitment.ToArray());
        Assert.Equal(identity[2], replay.State.EnvelopeSha256.ToArray());
        Assert.Equal(identity[3], replay.State.CanonicalEnvelope.ToArray());
    }

    [Theory]
    [InlineData("materialized")]
    [InlineData("artifact")]
    [InlineData("target")]
    [InlineData("mac")]
    [InlineData("wrong-key")]
    public async Task PostgreSqlPreparedIntegrity_RejectsCorruptionBeforeSigner(
        string mutation)
    {
        var connectionString = Environment.GetEnvironmentVariable("DEEP_TEST_POSTGRES");
        if (string.IsNullOrWhiteSpace(connectionString)) return;
        await using var database = await PostgresDatabase.CreateAsync(connectionString);
        var now = checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        var initial = NewPostgresStore(database);
        var fixture = await CreateActivationAsync(initial, initial, now, attest: false);
        if (mutation != "wrong-key")
            await CorruptPreparedStateAsync(database, fixture, mutation);
        var restarted = mutation == "wrong-key"
            ? NewPostgresStore(database, Bytes(119, 32))
            : NewPostgresStore(database);
        var signer = new CountingSigner(fixture.PublisherSigner);
        var capacity = new RecordingCapacityGate(); var transport = new RecordingTransport();
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            ((IProductionMailboxV2PublicationStateStore)restarted)
                .GetV2ActivationAsync(fixture.ActivationKey, CancellationToken.None).AsTask());
        Assert.Equal(0, signer.Calls); Assert.Equal(0, capacity.Calls);
        Assert.Empty(transport.Commands);
    }

    [Fact]
    public async Task PostgreSqlPreparedIntegrity_RecordCasRejectsMutationAfterOwnedRead()
    {
        var connectionString = Environment.GetEnvironmentVariable("DEEP_TEST_POSTGRES");
        if (string.IsNullOrWhiteSpace(connectionString)) return;
        await using var database = await PostgresDatabase.CreateAsync(connectionString);
        var now = checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        var initial = NewPostgresStore(database);
        var fixture = await CreateActivationAsync(initial, initial, now, attest: false);
        var owned = await ((IProductionMailboxV2PublicationStateStore)initial)
            .GetV2ActivationAsync(fixture.ActivationKey, CancellationToken.None);
        Assert.NotNull(owned);
        var signature = fixture.PublisherSigner.SignDirect(
            ProductionMailboxV2ActivationAttestation.GetSigningBytes(owned));
        await CorruptPreparedStateAsync(database, fixture, "target");
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            ((IProductionMailboxV2PublicationStateStore)NewPostgresStore(database))
                .RecordV2ActivationAttestationAsync(fixture.ActivationKey, signature,
                    CancellationToken.None).AsTask());
    }

    [Theory]
    [InlineData("random-signature")]
    [InlineData("valid-other-signature")]
    [InlineData("published")]
    [InlineData("coherent-attempt-ack")]
    public async Task PostgreSqlPhaseIntegrity_RejectsCoherentStoredMutation(
        string mutation)
    {
        var connectionString = Environment.GetEnvironmentVariable("DEEP_TEST_POSTGRES");
        if (string.IsNullOrWhiteSpace(connectionString)) return;
        await using var database = await PostgresDatabase.CreateAsync(connectionString);
        var now = checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        var store = NewPostgresStore(database);
        var fixture = await CreateActivationAsync(store, store, now);
        var state = fixture.Created.State!;
        var target = state.Targets[0];
        await using var connection = new NpgsqlConnection(database.ConnectionString);
        await connection.OpenAsync();
        NpgsqlCommand command;
        if (mutation is "random-signature" or "valid-other-signature")
        {
            var signature = mutation == "random-signature" ? Bytes(122, 64)
                : fixture.PublisherSigner.SignDirect(Bytes(123, 96));
            command = new NpgsqlCommand(
                "UPDATE production_mailbox_v2_activations SET verified_plan_signature=@value WHERE activation_state_key=@key",
                connection);
            command.Parameters.AddWithValue("value", signature);
        }
        else if (mutation == "published")
        {
            command = new NpgsqlCommand(
                "UPDATE production_mailbox_v2_activations SET published=true WHERE activation_state_key=@key",
                connection);
        }
        else
        {
            var materialized = new ProductionMailboxV2MaterializedCache(
                state.CanonicalEnvelope.ToArray(), state.EnvelopeSha256.ToArray(),
                state.LineageCommitment.ToArray(), state.CacheSalt.ToArray());
            var attempt = await ProductionMailboxV2WireCodec.CreateCommandAsync(
                materialized, target.ReplicaId, state.CohortId, now,
                fixture.PublisherSigner, fixture.PublisherPublicKey,
                CancellationToken.None);
            command = new NpgsqlCommand(
                "UPDATE production_mailbox_v2_activation_targets SET canonical_attempt=@attempt,attempt_sha256=@hash,attempted_at=@time,acknowledged=true WHERE activation_state_key=@key AND target_replica_id=@target",
                connection);
            command.Parameters.AddWithValue("attempt", attempt);
            command.Parameters.AddWithValue("hash", SHA256.HashData(attempt));
            command.Parameters.AddWithValue("time", U64Bytes(now));
            command.Parameters.AddWithValue("target", target.ReplicaId.ToArray());
        }
        await using (command)
        {
            command.Parameters.AddWithValue("key", fixture.ActivationKey);
            Assert.True(await command.ExecuteNonQueryAsync() > 0);
        }
        var capacity = new RecordingCapacityGate(); var transport = new RecordingTransport();
        var signer = new CountingSigner(fixture.PublisherSigner);
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            new ProductionMailboxV2Publisher(NewPostgresStore(database), capacity,
                transport, signer, fixture.PublisherPublicKey, TimeProvider.System, 300, 60)
                .PublishAsync(fixture.ActivationKey, CancellationToken.None).AsTask());
        Assert.Equal(0, capacity.Calls); Assert.Equal(0, signer.Calls);
        Assert.Empty(transport.Commands);
    }

    [Fact]
    public async Task PostgreSqlPhaseIntegrity_CorruptionPrecedesAckCas()
    {
        var connectionString = Environment.GetEnvironmentVariable("DEEP_TEST_POSTGRES");
        if (string.IsNullOrWhiteSpace(connectionString)) return;
        await using var database = await PostgresDatabase.CreateAsync(connectionString);
        var now = checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        var store = NewPostgresStore(database);
        var fixture = await CreateActivationAsync(store, store, now);
        var state = fixture.Created.State!; var target = state.Targets[0];
        var materialized = new ProductionMailboxV2MaterializedCache(
            state.CanonicalEnvelope.ToArray(), state.EnvelopeSha256.ToArray(),
            state.LineageCommitment.ToArray(), state.CacheSalt.ToArray());
        var attempt = await ProductionMailboxV2WireCodec.CreateCommandAsync(materialized,
            target.ReplicaId, state.CohortId, now, fixture.PublisherSigner,
            fixture.PublisherPublicKey, CancellationToken.None);
        Assert.True(await ((IProductionMailboxV2PublicationStateStore)store)
            .RecordV2PublicationAttemptAsync(fixture.ActivationKey, target.ReplicaId,
                attempt, 300, 60, CancellationToken.None));
        await using (var connection = new NpgsqlConnection(database.ConnectionString))
        {
            await connection.OpenAsync();
            await using var corrupt = new NpgsqlCommand(
                "UPDATE production_mailbox_v2_activations SET phase_integrity_tag=@tag WHERE activation_state_key=@key",
                connection);
            corrupt.Parameters.AddWithValue("tag", Bytes(124, 32));
            corrupt.Parameters.AddWithValue("key", fixture.ActivationKey);
            Assert.Equal(1, await corrupt.ExecuteNonQueryAsync());
        }
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            ((IProductionMailboxV2PublicationStateStore)NewPostgresStore(database))
                .AcknowledgeV2PublicationAttemptAsync(fixture.ActivationKey,
                    target.ReplicaId, SHA256.HashData(attempt),
                    CancellationToken.None).AsTask());
    }

    [Fact]
    public async Task Publisher_PersistsBeforeSendAndRecoversLostResponseWithoutNewSalt()
    {
        var now = checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        var clock = new ManualClock(DateTimeOffset.FromUnixTimeSeconds(checked((long)now)));
        var store = new InMemoryProductionMailboxStateStore(clock);
        var fixture = await CreateActivationAsync(store, store, now);
        await SeedCapacityReceiptsAsync(store, fixture, now);
        var transport = new RecordingTransport { Accept = false };
        var capacity = new RecordingCapacityGate();
        var publisher = new ProductionMailboxV2Publisher(store, capacity, transport,
            fixture.PublisherSigner, fixture.PublisherPublicKey, clock, 300, 60);

        Assert.Equal(ProductionMailboxV2ActivationCommitStatus.Incomplete,
            await publisher.PublishAsync(fixture.ActivationKey, CancellationToken.None));
        var afterLost = await ((IProductionMailboxV2PublicationStateStore)store)
            .GetV2ActivationAsync(fixture.ActivationKey, CancellationToken.None);
        Assert.NotNull(afterLost);
        var salt = afterLost.CacheSalt.ToArray();
        var firstCommand = Assert.Single(afterLost.Targets,
            static target => target.CanonicalAttempt is { } attempt
                && !attempt.IsEmpty)
            .CanonicalAttempt!.Value.ToArray();
        Assert.All(afterLost.Targets, static target => Assert.False(target.Acknowledged));

        transport.Accept = true;
        Assert.Equal(ProductionMailboxV2ActivationCommitStatus.Published,
            await publisher.PublishAsync(fixture.ActivationKey, CancellationToken.None));
        var published = await ((IProductionMailboxV2PublicationStateStore)store)
            .GetV2ActivationAsync(fixture.ActivationKey, CancellationToken.None);
        Assert.NotNull(published);
        Assert.Equal(salt, published.CacheSalt.ToArray());
        Assert.True(transport.Commands.Count >= 2);
        Assert.Equal(firstCommand, transport.Commands[0]);
        Assert.Equal(firstCommand, transport.Commands[1]);
        Assert.True(capacity.Calls >= 3);
    }

    [Fact]
    public void PublicSurface_HasNoRawV2MutationOrOwnerRequestApi()
    {
        Assert.False(typeof(IProductionMailboxV2PublicationStateStore).IsPublic);
        Assert.False(typeof(ProductionMailboxV2CacheBuilder).IsPublic);
        Assert.DoesNotContain(typeof(InMemoryProductionMailboxStateStore).GetMethods(),
            method => method.IsPublic && (method.Name.Contains("V2Activation",
                StringComparison.Ordinal) || method.Name.Contains("PMQ",
                StringComparison.OrdinalIgnoreCase)));
        Assert.DoesNotContain(typeof(ProductionMailboxV2CacheBuilder).Assembly
            .GetExportedTypes(), type => type.Name.Contains("ProductionMailboxV2",
                StringComparison.Ordinal));
    }

    [Fact]
    public async Task RegistryPmc2Pmp2_RoundTripsCommittedXNodeCodecsAndSignature()
    {
        var now = checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        var clock = new ManualClock(DateTimeOffset.FromUnixTimeSeconds(checked((long)now)));
        var store = new InMemoryProductionMailboxStateStore(clock);
        var fixture = await CreateActivationAsync(store, store, now);
        var state = fixture.Created.State!;
        var materialized = new ProductionMailboxV2MaterializedCache(
            state.CanonicalEnvelope.ToArray(), state.EnvelopeSha256.ToArray(),
            state.LineageCommitment.ToArray(), state.CacheSalt.ToArray());
        var target = state.Targets[0];
        var command = await ProductionMailboxV2WireCodec.CreateCommandAsync(materialized,
            target.ReplicaId, state.CohortId, now, fixture.PublisherSigner,
            fixture.PublisherPublicKey, CancellationToken.None);

        var decoded = ActualXNode.ProductionMailboxPrepositionCommandCodec.Decode(command);
        Assert.True(ActualXNode.ProductionMailboxPrepositionCommandCodec.VerifyPublisher(
            decoded, fixture.PublisherPublicKey));
        Assert.Equal(state.EnvelopeSha256.ToArray(), decoded.EnvelopeSha256.ToArray());
        Assert.Equal(target.ReplicaId.ToArray(), decoded.TargetReplicaId.ToArray());
        Assert.Equal(state.CohortId.ToArray(), decoded.ReservationCohortId.ToArray());
        var envelope = ActualXNode.ProductionMailboxClosureEnvelopeCodec.Decode(
            decoded.CanonicalEnvelope.Span);
        Assert.Equal(state.CacheSalt.ToArray(), envelope.CacheSalt.ToArray());
        Assert.Equal(state.LineageCommitment.ToArray(),
            envelope.LineageCommitment.ToArray());
    }

    [Fact]
    public void TargetDerivation_MatchesXNodeOldAndCurrentSelectionOnly()
    {
        var now = checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        var ids = Enumerable.Range(1, 4).Select(seed => Bytes((byte)seed, 32)).ToArray();
        var nodes = ids.Select((id, index) => new ProductionMailboxTopologyNode
        {
            NodeId = id,
            HttpsEndpoint = $"https://target-{index}.example.net/",
            CurrentSpkiSha256 = Bytes((byte)(30 + index), 32),
            NextSpkiSha256 = Bytes((byte)(40 + index), 32)
        }).ToArray();
        var topology = new ProductionMailboxTopologySnapshot
        {
            NetworkId = Bytes(50, 16),
            AuthorityGeneration = 7,
            CanonicalAuthorityHash = Bytes(51, 32),
            TopologyGeneration = 9,
            PreviousTopologyHash = Bytes(52, 32),
            IssuedAtUnixSeconds = now - 10,
            ExpiresAtUnixSeconds = now + 300,
            CurrentEpoch = TargetEpoch(10, nodes[..2], now),
            NextEpoch = TargetEpoch(11, nodes[2..], now),
            IssuerSignature = Bytes(53, 64)
        };
        var old = TargetSelection([ids[0], ids[2]], 9, now);
        var current = TargetSelection([ids[1], ids[2]], 10, now);
        var next = TargetSelection([ids[0], ids[3]], 11, now);
        var basePss = ProductionMailboxSelectionSuccessorV2Codec.Decode(
            CreateFakeTransition(Bytes(54,
                ProductionMailboxRouteContinuityConstants.CanonicalRouteOriginLkgLength))
                .CanonicalSuccessor.Span);
        var pss = basePss with
        {
            Selection = basePss.Selection with
            {
                OldCanonicalSelection = ProductionMailboxTopologyCodec.EncodeSelection(old)
            }
        };
        var targets = ProductionMailboxV2CacheBuilder.DeriveTargets(
            new ProductionMailboxNodeCacheArtifacts
            {
                AuthorizationKind = ProductionMailboxRouteAuthorizationKind.OwnerPRA2,
                CanonicalAuthority = basePss.Selection.CanonicalNewAuthority,
                CanonicalRevocations = FramedPmr(),
                CanonicalTopology = ProductionMailboxTopologyCodec.Encode(topology),
                CanonicalCurrentSelection = ProductionMailboxTopologyCodec.EncodeSelection(current),
                CanonicalNextSelection = ProductionMailboxTopologyCodec.EncodeSelection(next),
                CanonicalSelectionSuccessorV2 = ProductionMailboxSelectionSuccessorV2Codec.Encode(pss),
                CanonicalRouteCertificate = new byte[] { 1 },
                CanonicalTransitionContext = new byte[] { 2 },
                CanonicalRouteAuthorization = new byte[] { 3 },
                CanonicalRevocationCheckpoint = ReadOnlyMemory<byte>.Empty
            }, pss);

        Assert.Equal([ids[0], ids[1], ids[2]],
            targets.Select(target => target.ReplicaId.ToArray()).ToArray(),
            ByteArrayComparer.Instance);
        Assert.DoesNotContain(targets,
            target => target.ReplicaId.Span.SequenceEqual(ids[3]));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public async Task Publisher_RestartsAtEveryDurableBoundary(int boundary)
    {
        var now = checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        var clock = new ManualClock(DateTimeOffset.FromUnixTimeSeconds(checked((long)now)));
        var store = new InMemoryProductionMailboxStateStore(clock);
        var fixture = await CreateActivationAsync(store, store, now);
        await SeedCapacityReceiptsAsync(store, fixture, now);
        var transport = new RecordingTransport { Accept = true };
        Action crash = () => throw new IOException("simulated durable-boundary crash");
        var hooks = new ProductionMailboxV2PublisherTestHooks
        {
            AfterAttemptPersisted = boundary == 0 ? crash : null,
            AfterTransportAccepted = boundary == 1 ? crash : null,
            AfterAcknowledged = boundary == 2 ? crash : null,
            BeforeFinalize = boundary == 3 ? crash : null
        };
        var interrupted = new ProductionMailboxV2Publisher(store,
            new RecordingCapacityGate(), transport, fixture.PublisherSigner,
            fixture.PublisherPublicKey, clock, 300, 60, hooks);
        await Assert.ThrowsAsync<IOException>(() => interrupted.PublishAsync(
            fixture.ActivationKey, CancellationToken.None).AsTask());
        var durable = await ((IProductionMailboxV2PublicationStateStore)store)
            .GetV2ActivationAsync(fixture.ActivationKey, CancellationToken.None);
        Assert.NotNull(durable);
        var salt = durable.CacheSalt.ToArray();

        var resumed = new ProductionMailboxV2Publisher(store,
            new RecordingCapacityGate(), transport, fixture.PublisherSigner,
            fixture.PublisherPublicKey, clock, 300, 60);
        Assert.Equal(ProductionMailboxV2ActivationCommitStatus.Published,
            await resumed.PublishAsync(fixture.ActivationKey, CancellationToken.None));
        var published = await ((IProductionMailboxV2PublicationStateStore)store)
            .GetV2ActivationAsync(fixture.ActivationKey, CancellationToken.None);
        Assert.NotNull(published);
        Assert.True(published.Published);
        Assert.Equal(salt, published.CacheSalt.ToArray());
    }

    [Fact]
    public async Task SourceAdvanceInvalidatesCreateAndFinalization()
    {
        var now = checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        var clock = new ManualClock(DateTimeOffset.FromUnixTimeSeconds(checked((long)now)));
        var store = new InMemoryProductionMailboxStateStore(clock);
        var fixture = await CreateActivationAsync(store, store, now);
        await SeedCapacityReceiptsAsync(store, fixture, now);
        var state = fixture.Created.State!;
        var materialized = new ProductionMailboxV2MaterializedCache(
            state.CanonicalEnvelope.ToArray(), state.EnvelopeSha256.ToArray(),
            state.LineageCommitment.ToArray(), state.CacheSalt.ToArray());
        foreach (var target in state.Targets)
        {
            var command = await ProductionMailboxV2WireCodec.CreateCommandAsync(
                materialized, target.ReplicaId, state.CohortId, now,
                fixture.PublisherSigner, fixture.PublisherPublicKey, CancellationToken.None);
            Assert.True(await ((IProductionMailboxV2PublicationStateStore)store)
                .RecordV2PublicationAttemptAsync(fixture.ActivationKey, target.ReplicaId,
                    command, 300, 60, CancellationToken.None));
            Assert.True(await ((IProductionMailboxV2PublicationStateStore)store)
                .AcknowledgeV2PublicationAttemptAsync(fixture.ActivationKey,
                    target.ReplicaId, SHA256.HashData(command), CancellationToken.None));
        }
        var routeStore = (IProductionMailboxRouteContinuityStateStore)store;
        var next = CreateNextTransition(fixture.Source, 93);
        var advanced = await routeStore.CommitVerifiedTransitionAsync(
            fixture.Source.RouteStateKey, fixture.Source.CanonicalRouteOriginLkg, next,
            CancellationToken.None);
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.Accepted, advanced.Status);
        Assert.Equal(ProductionMailboxV2ActivationCommitStatus.SourceChanged,
            await ((IProductionMailboxV2PublicationStateStore)store)
                .TryFinalizeV2ActivationAsync(fixture.ActivationKey, 60,
                    CancellationToken.None));
        var stalePlan = CreatePlan(fixture.Source, fixture.Prepared, Bytes(94, 32),
            fixture.PromotionKey, fixture.PublisherPublicKey);
        Assert.Equal(ProductionMailboxV2ActivationCommitStatus.SourceChanged,
            (await ((IProductionMailboxV2PublicationStateStore)store)
                .TryCreateV2ActivationAsync(stalePlan, CancellationToken.None)).Status);
    }

    [Fact]
    public async Task AttemptRenewalRejectsDelayedAckAndMutatingSigner()
    {
        var now = checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        var clock = new ManualClock(DateTimeOffset.FromUnixTimeSeconds(checked((long)now)));
        var store = new InMemoryProductionMailboxStateStore(clock);
        var fixture = await CreateActivationAsync(store, store, now);
        var state = fixture.Created.State!;
        var target = state.Targets[0];
        var materialized = new ProductionMailboxV2MaterializedCache(
            state.CanonicalEnvelope.ToArray(), state.EnvelopeSha256.ToArray(),
            state.LineageCommitment.ToArray(), state.CacheSalt.ToArray());
        var first = await ProductionMailboxV2WireCodec.CreateCommandAsync(materialized,
            target.ReplicaId, state.CohortId, now, fixture.PublisherSigner,
            fixture.PublisherPublicKey, CancellationToken.None);
        Assert.True(await ((IProductionMailboxV2PublicationStateStore)store)
            .RecordV2PublicationAttemptAsync(fixture.ActivationKey, target.ReplicaId,
                first, 300, 60, CancellationToken.None));
        clock.Advance(TimeSpan.FromSeconds(301));
        var second = await ProductionMailboxV2WireCodec.CreateCommandAsync(materialized,
            target.ReplicaId, state.CohortId, now + 301, fixture.PublisherSigner,
            fixture.PublisherPublicKey, CancellationToken.None);
        Assert.True(await ((IProductionMailboxV2PublicationStateStore)store)
            .RecordV2PublicationAttemptAsync(fixture.ActivationKey, target.ReplicaId,
                second, 300, 60, CancellationToken.None));
        Assert.False(await ((IProductionMailboxV2PublicationStateStore)store)
            .AcknowledgeV2PublicationAttemptAsync(fixture.ActivationKey,
                target.ReplicaId, SHA256.HashData(first), CancellationToken.None));
        Assert.True(await ((IProductionMailboxV2PublicationStateStore)store)
            .AcknowledgeV2PublicationAttemptAsync(fixture.ActivationKey,
                target.ReplicaId, SHA256.HashData(second), CancellationToken.None));

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            ProductionMailboxV2WireCodec.CreateCommandAsync(materialized,
                state.Targets[1].ReplicaId, state.CohortId, now + 301,
                new MutatingSigner(fixture.PublisherSigner), fixture.PublisherPublicKey,
                CancellationToken.None).AsTask());

        var snapshotted = await ProductionMailboxV2WireCodec.CreateCommandAsync(materialized,
            state.Targets[1].ReplicaId, state.CohortId, now + 301,
            fixture.PublisherSigner, fixture.PublisherPublicKey, CancellationToken.None,
            createNonce: null, afterSignatureSnapshotForTests: returned => returned[0] ^= 0x80);
        Assert.True(ProductionMailboxV2WireCodec.VerifyCanonicalCommand(snapshotted,
            fixture.PublisherPublicKey));
    }

    [Theory]
    [InlineData("length")]
    [InlineData("wrong-key")]
    [InlineData("cancel")]
    public async Task Publisher_SignerFailurePersistsNoAttemptOrNetwork(string failure)
    {
        var now = checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        var clock = new ManualClock(DateTimeOffset.FromUnixTimeSeconds(checked((long)now)));
        var store = new InMemoryProductionMailboxStateStore(clock);
        var fixture = await CreateActivationAsync(store, store, now);
        var capacity = new RecordingCapacityGate();
        var transport = new RecordingTransport { Accept = true };
        var signer = new FaultingSigner(failure);
        var publisher = new ProductionMailboxV2Publisher(store, capacity, transport,
            signer, fixture.PublisherPublicKey, clock, 300, 60);

        await Assert.ThrowsAnyAsync<Exception>(() => publisher.PublishAsync(
            fixture.ActivationKey, CancellationToken.None).AsTask());

        var state = await ((IProductionMailboxV2PublicationStateStore)store)
            .GetV2ActivationAsync(fixture.ActivationKey, CancellationToken.None);
        Assert.NotNull(state);
        Assert.All(state.Targets, static target =>
        {
            Assert.True(target.CanonicalAttempt is null
                || target.CanonicalAttempt.Value.IsEmpty);
            Assert.True(target.AttemptSha256 is null
                || target.AttemptSha256.Value.IsEmpty);
            Assert.Null(target.AttemptedAtUnixSeconds);
            Assert.False(target.Acknowledged);
        });
        Assert.Equal(1, capacity.Calls);
        Assert.Equal(1, signer.Calls);
        Assert.Empty(transport.Commands);
    }

    [Fact]
    public async Task InMemoryLineageCap_TwoSourcesThenThirdRejectedAndExpiredGcReopens()
    {
        var now = checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        var clock = new ManualClock(DateTimeOffset.FromUnixTimeSeconds(checked((long)now)));
        var store = new InMemoryProductionMailboxStateStore(clock);
        var fixture = await CreateActivationAsync(store, store, now);
        var second = await CreateAdditionalActivationAsync(store, store, fixture, now, 101);
        Assert.Equal(ProductionMailboxV2ActivationCommitStatus.Accepted, second.Status);
        var third = await CreateAdditionalActivationAsync(store, store, fixture, now, 102);
        Assert.Equal(ProductionMailboxV2ActivationCommitStatus.Conflict, third.Status);
        var duplicate = CreatePlan(fixture.Source, fixture.Prepared, Bytes(103, 32),
            fixture.PromotionKey, fixture.PublisherPublicKey);
        Assert.Equal(ProductionMailboxV2ActivationCommitStatus.Conflict,
            (await ((IProductionMailboxV2PublicationStateStore)store)
                .TryCreateV2ActivationAsync(duplicate, CancellationToken.None)).Status);

        clock.Advance(TimeSpan.FromSeconds(3_601));
        var afterGc = await CreateAdditionalActivationAsync(store, store, fixture,
            now + 3_601, 104);
        Assert.Equal(ProductionMailboxV2ActivationCommitStatus.Accepted, afterGc.Status);
        Assert.NotNull(await ((IProductionMailboxV2PublicationStateStore)store)
            .GetV2ActivationAsync(afterGc.State!.ActivationStateKey,
                CancellationToken.None));
    }

    [Fact]
    public async Task PostgreSqlLineageCap_IsCrossProcessAndRestartStable()
    {
        var connectionString = Environment.GetEnvironmentVariable("DEEP_TEST_POSTGRES");
        if (string.IsNullOrWhiteSpace(connectionString)) return;
        await using var database = await PostgresDatabase.CreateAsync(connectionString);
        var now = checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        var store = NewPostgresStore(database);
        var fixture = await CreateActivationAsync(store, store, now);
        var planA = await PrepareAdditionalPlanAsync(store, fixture, now, 105);
        var planB = await PrepareAdditionalPlanAsync(store, fixture, now, 106);
        var results = await Task.WhenAll(
            ((IProductionMailboxV2PublicationStateStore)
                NewPostgresStore(database))
                .TryCreateV2ActivationAsync(planA, CancellationToken.None).AsTask(),
            ((IProductionMailboxV2PublicationStateStore)
                NewPostgresStore(database))
                .TryCreateV2ActivationAsync(planB, CancellationToken.None).AsTask());
        Assert.Equal(1, results.Count(result =>
            result.Status == ProductionMailboxV2ActivationCommitStatus.Accepted));
        Assert.Equal(1, results.Count(result =>
            result.Status == ProductionMailboxV2ActivationCommitStatus.Conflict));
        var accepted = Assert.Single(results, result => result.State is not null).State!;
        var duplicate = CreatePlan(fixture.Source, fixture.Prepared, Bytes(107, 32),
            fixture.PromotionKey, fixture.PublisherPublicKey);
        Assert.Equal(ProductionMailboxV2ActivationCommitStatus.Conflict,
            (await ((IProductionMailboxV2PublicationStateStore)
                NewPostgresStore(database))
                .TryCreateV2ActivationAsync(duplicate, CancellationToken.None)).Status);
        Assert.NotNull(await ((IProductionMailboxV2PublicationStateStore)
            NewPostgresStore(database))
            .GetV2ActivationAsync(accepted.ActivationStateKey, CancellationToken.None));
    }

    [Theory]
    [InlineData(3_539, false)]
    [InlineData(3_540, false)]
    [InlineData(3_541, true)]
    [InlineData(3_601, true)]
    public async Task Publisher_HardExpiryMarginPrecedesAllCallbacks(
        int clockAdvanceSeconds, bool expired)
    {
        var now = checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        var clock = new ManualClock(DateTimeOffset.FromUnixTimeSeconds(checked((long)now)));
        var store = new InMemoryProductionMailboxStateStore(clock);
        var fixture = await CreateActivationAsync(store, store, now);
        clock.Advance(TimeSpan.FromSeconds(clockAdvanceSeconds));
        var capacity = new RecordingCapacityGate();
        var transport = new RecordingTransport { Accept = true };
        var signer = new CountingSigner(fixture.PublisherSigner);
        var publisher = new ProductionMailboxV2Publisher(store, capacity, transport,
            signer, fixture.PublisherPublicKey, clock, 300, 60);

        var status = await publisher.PublishAsync(fixture.ActivationKey,
            CancellationToken.None);
        if (expired)
        {
            Assert.Equal(ProductionMailboxV2ActivationCommitStatus.Expired, status);
            Assert.Equal(0, capacity.Calls); Assert.Equal(0, signer.Calls);
            Assert.Empty(transport.Commands);
            var pending = await ((IProductionMailboxV2PublicationStateStore)store)
                .ListPendingV2ActivationKeysAsync(16, CancellationToken.None);
            if (clockAdvanceSeconds > 3_600)
                Assert.Empty(pending);
            else
                Assert.Single(pending);
        }
        else
        {
            Assert.NotEqual(ProductionMailboxV2ActivationCommitStatus.Expired, status);
            Assert.True(capacity.Calls > 0); Assert.True(signer.Calls > 0);
            Assert.NotEmpty(transport.Commands);
        }
    }

    [Fact]
    public async Task Publisher_AlreadyStaleSourceHasZeroCallbacks()
    {
        var now = checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        var clock = new ManualClock(DateTimeOffset.FromUnixTimeSeconds(checked((long)now)));
        var store = new InMemoryProductionMailboxStateStore(clock);
        var fixture = await CreateActivationAsync(store, store, now);
        var advanced = await ((IProductionMailboxRouteContinuityStateStore)store)
            .CommitVerifiedTransitionAsync(fixture.Source.RouteStateKey,
                fixture.Source.CanonicalRouteOriginLkg,
                CreateNextTransition(fixture.Source, 108), CancellationToken.None);
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.Accepted, advanced.Status);
        var capacity = new RecordingCapacityGate(); var transport = new RecordingTransport();
        var signer = new CountingSigner(fixture.PublisherSigner);
        var status = await new ProductionMailboxV2Publisher(store, capacity, transport,
            signer, fixture.PublisherPublicKey, clock, 300, 60)
            .PublishAsync(fixture.ActivationKey, CancellationToken.None);
        Assert.Equal(ProductionMailboxV2ActivationCommitStatus.SourceChanged, status);
        Assert.Equal(0, capacity.Calls); Assert.Equal(0, signer.Calls);
        Assert.Empty(transport.Commands);
    }

    [Fact]
    public async Task PostgreSqlPublisher_RestartAfterHardExpiryHasZeroCallbacksAndGc()
    {
        var connectionString = Environment.GetEnvironmentVariable("DEEP_TEST_POSTGRES");
        if (string.IsNullOrWhiteSpace(connectionString)) return;
        await using var database = await PostgresDatabase.CreateAsync(connectionString);
        var now = checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        var store = NewPostgresStore(database);
        var fixture = await CreateActivationAsync(store, store, now,
            verifiedAt: now - 10, cacheExpiresAt: now + 2);
        await Task.Delay(TimeSpan.FromSeconds(3));
        var restarted = (IProductionMailboxV2PublicationStateStore)
            NewPostgresStore(database);
        var capacity = new RecordingCapacityGate(); var transport = new RecordingTransport();
        var signer = new CountingSigner(fixture.PublisherSigner);
        var status = await new ProductionMailboxV2Publisher(restarted, capacity, transport,
            signer, fixture.PublisherPublicKey, TimeProvider.System, 300, 1)
            .PublishAsync(fixture.ActivationKey, CancellationToken.None);
        Assert.Equal(ProductionMailboxV2ActivationCommitStatus.Expired, status);
        Assert.Equal(0, capacity.Calls); Assert.Equal(0, signer.Calls);
        Assert.Empty(transport.Commands);
        Assert.Empty(await restarted.ListPendingV2ActivationKeysAsync(
            16, CancellationToken.None));
        Assert.Null(await restarted.GetV2ActivationAsync(
            fixture.ActivationKey, CancellationToken.None));
    }

    private static async Task<byte[]> RunStateContractAsync(
        IProductionMailboxStateStore capacityStore,
        IProductionMailboxV2PublicationStateStore v2Store,
        ulong now,
        ManualClock? clock)
    {
        var fixture = await CreateActivationAsync(capacityStore, v2Store, now);
        var replayPlan = CreatePlan(fixture.Source, fixture.Prepared,
            fixture.ActivationKey, fixture.PromotionKey, fixture.PublisherPublicKey);
        var replay = await v2Store.TryCreateV2ActivationAsync(
            replayPlan, CancellationToken.None);
        Assert.Equal(ProductionMailboxV2ActivationCommitStatus.ExactReplay, replay.Status);
        Assert.Equal(fixture.Created.State!.CacheSalt.ToArray(), replay.State!.CacheSalt.ToArray());
        Assert.Equal(fixture.Created.State.CanonicalEnvelope.ToArray(),
            replay.State.CanonicalEnvelope.ToArray());

        var materialized = new ProductionMailboxV2MaterializedCache(
            replay.State.CanonicalEnvelope.ToArray(), replay.State.EnvelopeSha256.ToArray(),
            replay.State.LineageCommitment.ToArray(), replay.State.CacheSalt.ToArray());
        foreach (var target in replay.State.Targets)
        {
            var command = await ProductionMailboxV2WireCodec.CreateCommandAsync(
                materialized, target.ReplicaId, replay.State.CohortId, now,
                fixture.PublisherSigner, fixture.PublisherPublicKey, CancellationToken.None,
                () => Bytes((byte)(40 + target.ReplicaId.Span[0]), 32));
            Assert.True(await v2Store.RecordV2PublicationAttemptAsync(
                fixture.ActivationKey, target.ReplicaId, command, 300, 60,
                CancellationToken.None));
            Assert.True(await v2Store.RecordV2PublicationAttemptAsync(
                fixture.ActivationKey, target.ReplicaId, command, 300, 60,
                CancellationToken.None));
            var fork = command.ToArray(); fork[16] ^= 0x80;
            Assert.False(await v2Store.RecordV2PublicationAttemptAsync(
                fixture.ActivationKey, target.ReplicaId, fork, 300, 60,
                CancellationToken.None));
            Assert.True(await v2Store.AcknowledgeV2PublicationAttemptAsync(
                fixture.ActivationKey, target.ReplicaId, SHA256.HashData(command),
                CancellationToken.None));
        }
        Assert.Equal(ProductionMailboxV2ActivationCommitStatus.Incomplete,
            await v2Store.TryFinalizeV2ActivationAsync(
                fixture.ActivationKey, 60, CancellationToken.None));
        await SeedCapacityReceiptsAsync(capacityStore, fixture, now);
        Assert.Equal(ProductionMailboxV2ActivationCommitStatus.Published,
            await v2Store.TryFinalizeV2ActivationAsync(
                fixture.ActivationKey, 60, CancellationToken.None));
        var published = await v2Store.GetV2ActivationAsync(
            fixture.ActivationKey, CancellationToken.None);
        Assert.NotNull(published);
        Assert.True(published.Published);

        if (clock is not null)
        {
            clock.Advance(TimeSpan.FromSeconds(301));
            Assert.False(await v2Store.RecordV2PublicationAttemptAsync(
                fixture.ActivationKey, published.Targets[0].ReplicaId,
                published.Targets[0].CanonicalAttempt!.Value, 300, 60,
                CancellationToken.None));
        }
        return fixture.ActivationKey;
    }

    private static async Task<ActivationFixture> CreateActivationAsync(
        IProductionMailboxStateStore capacityStore,
        IProductionMailboxV2PublicationStateStore v2Store,
        ulong now, ulong? verifiedAt = null, ulong? cacheExpiresAt = null,
        bool attest = true)
    {
        var routeStore = (IProductionMailboxRouteContinuityStateStore)capacityStore;
        var routeKey = Bytes(3, 32);
        var oldRol = Bytes(4,
            ProductionMailboxRouteContinuityConstants.CanonicalRouteOriginLkgLength);
        var transition = CreateFakeTransition(oldRol);
        var committed = await routeStore.CommitVerifiedTransitionAsync(routeKey, oldRol,
            transition, CancellationToken.None);
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.Accepted, committed.Status);
        var source = Assert.IsType<ProductionMailboxRouteContinuityStateSnapshot>(committed.State);

        var publisherKeys = PublicKeyAuth.GenerateKeyPair();
        var publisherSigner = new SodiumSigner(publisherKeys.PrivateKey);
        var nodeKeys = new[] { PublicKeyAuth.GenerateKeyPair(), PublicKeyAuth.GenerateKeyPair() };
        var targets = nodeKeys.Select((pair, index) => new ProductionMailboxV2Target(
            pair.PublicKey, $"https://node-{index}.example.net/", Bytes((byte)(60 + index), 32),
            Bytes((byte)(70 + index), 32))).OrderBy(target =>
                Convert.ToHexString(target.ReplicaId.Span), StringComparer.Ordinal).ToArray();
        var prepared = FakePrepared(source, targets, verifiedAt ?? now,
            cacheExpiresAt ?? now + 3_600);
        var activationKey = Bytes(8, 32);
        var promotionKey = Bytes(9, 32);

        await capacityStore.StoreLatestOwnerBundleAsync(routeKey, Bytes(10, 80), now,
            CancellationToken.None);
        var oldClosure = Bytes(11, 32); var newClosure = Bytes(12, 32);
        _ = await capacityStore.GetOrInitializePublishedArtifactClosureAsync(oldClosure,
            CancellationToken.None);
        _ = await capacityStore.BeginArtifactPromotionAsync(promotionKey, oldClosure,
            newClosure, CancellationToken.None);
        var owners = await capacityStore.ListOwnerBundlesForCapacityPlanningAsync(
            promotionKey, 16, CancellationToken.None);
        var owner = Assert.Single(owners);
        var items = targets.Select((target, index) =>
        {
            var envelope = new byte[] { (byte)(80 + index) };
            return new ProductionMailboxPublicationItem(Bytes((byte)(90 + index), 32),
                target.ReplicaId.ToArray(), target.Endpoint,
                target.CurrentSpkiSha256.ToArray(), target.NextSpkiSha256.ToArray(), [],
                envelope, SHA256.HashData(envelope), promotionKey);
        }).ToArray();
        Assert.True(await capacityStore.CommitCapacityPlannedOwnerAsync(promotionKey,
            owner, items, 16, CancellationToken.None));
        Assert.True(await capacityStore.CompleteCapacityPlanAsync(promotionKey,
            CancellationToken.None));

        var plan = CreatePlan(source, prepared, activationKey, promotionKey,
            publisherKeys.PublicKey);
        var created = await v2Store.TryCreateV2ActivationAsync(plan, CancellationToken.None);
        Assert.Equal(ProductionMailboxV2ActivationCommitStatus.Accepted, created.Status);
        Assert.NotNull(created.State);
        if (attest)
        {
            var attestation = publisherSigner.SignDirect(
                ProductionMailboxV2ActivationAttestation.GetSigningBytes(created.State));
            created = await v2Store.RecordV2ActivationAttestationAsync(
                activationKey, attestation, CancellationToken.None);
            Assert.Equal(ProductionMailboxV2ActivationCommitStatus.Accepted, created.Status);
            Assert.NotNull(created.State);
        }
        return new(activationKey, promotionKey, publisherKeys.PublicKey, publisherSigner,
            nodeKeys.ToDictionary(pair => Convert.ToHexString(pair.PublicKey),
                pair => pair.PrivateKey, StringComparer.Ordinal), source, prepared, created);
    }

    private static async Task CorruptPreparedStateAsync(PostgresDatabase database,
        ActivationFixture fixture, string mutation)
    {
        await using var connection = new NpgsqlConnection(database.ConnectionString);
        await connection.OpenAsync();
        NpgsqlCommand command;
        if (mutation == "materialized")
        {
            var replacement = fixture.Prepared.Materialize(() => Bytes(120, 32));
            command = new NpgsqlCommand(
                "UPDATE production_mailbox_v2_activations SET cache_salt=@salt,lineage_commitment=@lineage,canonical_envelope=@envelope,envelope_sha256=@hash WHERE activation_state_key=@key",
                connection);
            command.Parameters.AddWithValue("salt", replacement.CacheSalt.ToArray());
            command.Parameters.AddWithValue("lineage", replacement.LineageCommitment.ToArray());
            command.Parameters.AddWithValue("envelope", replacement.CanonicalEnvelope.ToArray());
            command.Parameters.AddWithValue("hash", replacement.EnvelopeSha256.ToArray());
        }
        else if (mutation == "artifact")
        {
            var original = ProductionMailboxV2WireCodec.DecodeEnvelope(
                fixture.Created.State!.CanonicalEnvelope.Span);
            var draft = original with
            {
                Authority = Mutate(original.Authority.ToArray()),
                LineageCommitment = new byte[32]
            };
            var lineage = ProductionMailboxV2WireCodec.ComputeLineageCommitment(draft);
            var envelope = ProductionMailboxV2WireCodec.EncodeEnvelope(
                draft with { LineageCommitment = lineage });
            command = new NpgsqlCommand(
                "UPDATE production_mailbox_v2_activations SET lineage_commitment=@lineage,canonical_envelope=@envelope,envelope_sha256=@hash WHERE activation_state_key=@key",
                connection);
            command.Parameters.AddWithValue("lineage", lineage);
            command.Parameters.AddWithValue("envelope", envelope);
            command.Parameters.AddWithValue("hash", SHA256.HashData(envelope));
        }
        else if (mutation == "target")
        {
            command = new NpgsqlCommand(
                "UPDATE production_mailbox_v2_activation_targets SET endpoint='https://changed.example.net/' WHERE activation_state_key=@key",
                connection);
        }
        else
        {
            command = new NpgsqlCommand(
                "UPDATE production_mailbox_v2_activations SET prepared_integrity_tag=@tag WHERE activation_state_key=@key",
                connection);
            command.Parameters.AddWithValue("tag", Bytes(121, 32));
        }
        await using (command)
        {
            command.Parameters.AddWithValue("key", fixture.ActivationKey);
            Assert.True(await command.ExecuteNonQueryAsync() > 0);
        }
    }

    private static async Task<ProductionMailboxV2ActivationCommitResult>
        CreateAdditionalActivationAsync(IProductionMailboxRouteContinuityStateStore routeStore,
            IProductionMailboxV2PublicationStateStore v2Store, ActivationFixture fixture,
            ulong now, byte seed)
    {
        var plan = await PrepareAdditionalPlanAsync(routeStore, fixture, now, seed);
        return await v2Store.TryCreateV2ActivationAsync(plan, CancellationToken.None);
    }

    private static async Task<ProductionMailboxV2ActivationPlan> PrepareAdditionalPlanAsync(
        IProductionMailboxRouteContinuityStateStore routeStore, ActivationFixture fixture,
        ulong now, byte seed)
    {
        var routeKey = Bytes(seed, 32);
        var oldRol = Bytes((byte)(seed + 1),
            ProductionMailboxRouteContinuityConstants.CanonicalRouteOriginLkgLength);
        var committed = await routeStore.CommitVerifiedTransitionAsync(routeKey, oldRol,
            CreateFakeTransition(oldRol), CancellationToken.None);
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.Accepted, committed.Status);
        var source = Assert.IsType<ProductionMailboxRouteContinuityStateSnapshot>(committed.State);
        var prepared = FakePrepared(source, fixture.Prepared.Targets, now, now + 3_600);
        return CreatePlan(source, prepared, Bytes((byte)(seed + 2), 32),
            fixture.PromotionKey, fixture.PublisherPublicKey);
    }

    private static ProductionMailboxV2ActivationPlan CreatePlan(
        ProductionMailboxRouteContinuityStateSnapshot source,
        ProductionMailboxV2PreparedCache prepared, byte[] activationKey,
        byte[] promotionKey, byte[] publisherPublicKey)
    {
        return ProductionMailboxV2ActivationPlan.Create(activationKey, promotionKey,
            promotionKey, publisherPublicKey, source, prepared);
    }

    private static ProductionMailboxV2PreparedCache FakePrepared(
        ProductionMailboxRouteContinuityStateSnapshot source,
        IReadOnlyList<ProductionMailboxV2Target> targets, ulong verifiedAt,
        ulong cacheExpiresAt)
    {
        var proof = ProductionMailboxSelectionSuccessorV2Codec.Decode(
            source.CanonicalSelectionSuccessor.Span);
        var artifacts = new ProductionMailboxNodeCacheArtifacts
        {
            AuthorizationKind = source.CurrentAuthorizationKind,
            CanonicalAuthority = proof.Selection.CanonicalNewAuthority.ToArray(),
            CanonicalRevocations = FramedPmr(),
            CanonicalTopology = FramedPmt(),
            CanonicalCurrentSelection = FramedPms(),
            CanonicalNextSelection = FramedPms(),
            CanonicalSelectionSuccessorV2 = source.CanonicalSelectionSuccessor.ToArray(),
            CanonicalRouteCertificate = source.CanonicalRouteCertificate.ToArray(),
            CanonicalTransitionContext = source.CanonicalTransitionContext.ToArray(),
            CanonicalRouteAuthorization = source.CanonicalRouteAuthorization.ToArray(),
            CanonicalRevocationCheckpoint = source.CanonicalRevocationCheckpoint.ToArray()
        };
        return new(artifacts,
            ProductionMailboxV2ActivationAttestation.ComputeCacheTranscriptHash(artifacts),
            proof.Selection.SelectionInputCommitment.ToArray(),
            proof.Selection.OldCanonicalSelectionHash.ToArray(),
            ProductionMailboxV2SourceFingerprint.Compute(source), verifiedAt, cacheExpiresAt,
            proof.Selection.Mode, source.CurrentAuthorizationKind, targets);
    }

    private static byte[] FramedPmr()
    {
        var value = new byte[
            ProductionMailboxRevocationSnapshotConstants.FixedArtifactBytesWithoutSerials];
        "PMR1"u8.CopyTo(value); value[4] = ProductionMailboxRevocationSnapshotConstants.Version;
        return value;
    }

    private static byte[] Mutate(byte[] value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Length == 0)
            throw new ArgumentException("The value must not be empty.", nameof(value));
        value[^1] ^= 0x5a;
        return value;
    }

    private static ProductionMailboxTopologyEpoch TargetEpoch(ulong epoch,
        IReadOnlyList<ProductionMailboxTopologyNode> nodes, ulong now) => new()
        {
            Epoch = epoch,
            Generation = epoch + 100,
            MembershipCommitment = Bytes((byte)(60 + epoch), 32),
            TopologyPlacementCommitment = Bytes((byte)(70 + epoch), 32),
            NotBeforeUnixSeconds = now - 20,
            NotAfterUnixSeconds = now + 400,
            Nodes = nodes
        };

    private static ProductionMailboxSelectionProof TargetSelection(
        IReadOnlyList<byte[]> replicaIds, ulong epoch, ulong now) => new()
        {
            Algorithm = ProductionMailboxSelectionAlgorithm.RendezvousSha256V2,
            NetworkId = Bytes(50, 16),
            AuthorityGeneration = 7,
            CanonicalAuthorityHash = Bytes(51, 32),
            TopologyGeneration = 9,
            CanonicalTopologyHash = Bytes(80, 32),
            Epoch = epoch,
            Generation = epoch + 100,
            MembershipCommitment = Bytes((byte)(60 + epoch), 32),
            TopologyPlacementCommitment = Bytes((byte)(70 + epoch), 32),
            MailboxPlacementCommitment = Bytes(81, 32),
            SelectionInputCommitment = Bytes(82, 32),
            IssuedAtUnixSeconds = now - 5,
            ExpiresAtUnixSeconds = now + 300,
            Replicas = replicaIds.Select((id, index) => new ProductionMailboxSelectionReplica
            {
                ReplicaId = id,
                CanonicalMIP1Proof = MailboxPeerReplicationCodec.EncodeMembershipProof(
                    new MailboxReplicaMembershipProof
                    {
                        ReplicaId = id,
                        SigningPublicKey = Bytes((byte)(90 + index), 32),
                        Epoch = epoch,
                        MembershipCommitment = Bytes((byte)(60 + epoch), 32),
                        CanonicalInclusionProof = new byte[] { (byte)(index + 1) }
                    })
            }).ToArray(),
            IssuerSignature = Bytes(83, 64)
        };

    private static byte[] FramedPmt()
    {
        var value = new byte[780]; "PMT1"u8.CopyTo(value); value[4] = 1;
        var offset = 120;
        for (var epoch = 0; epoch < 2; epoch++)
        {
            BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(offset + 96), 2);
            offset += 100;
            for (var node = 0; node < 2; node++)
            {
                BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(offset + 32), 1);
                offset += 99;
            }
        }
        Assert.Equal(value.Length - 64, offset);
        return value;
    }

    private static byte[] FramedPms()
    {
        var value = new byte[410]; "PMS1"u8.CopyTo(value); value[4] = 1;
        value[268] = ProductionMailboxTopologyConstants.ReplicaCount;
        var offset = 272;
        for (var replica = 0; replica < ProductionMailboxTopologyConstants.ReplicaCount;
             replica++)
        {
            BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(offset + 32), 1);
            offset += 37;
        }
        Assert.Equal(value.Length - 64, offset);
        return value;
    }

    private static async Task SeedCapacityReceiptsAsync(
        IProductionMailboxStateStore store, ActivationFixture fixture, ulong now)
    {
        var plan = await store.GetCapacityPlanAsync(fixture.PromotionKey,
            CancellationToken.None);
        Assert.NotNull(plan);
        foreach (var targetState in plan.Targets)
        {
            var target = new ProductionMailboxPrepositionTarget(targetState.TargetReplicaId,
                targetState.Endpoint, targetState.CurrentSpkiSha256, targetState.NextSpkiSha256);
            var command = await ProductionMailboxCapacityCommandCodec.CreateAsync(
                ProductionMailboxCapacityOperation.ReserveOrRenew, now, now + 3_600,
                fixture.PromotionKey, target, targetState.ReservedClosureCount,
                targetState.ReservedBytes, targetState.Revision + 1,
                fixture.PublisherPublicKey, fixture.PublisherSigner, CancellationToken.None);
            var durable = await store.GetOrRecordCapacityAttemptAsync(fixture.PromotionKey,
                targetState.TargetReplicaId, targetState.Revision,
                targetState.Revision + 1, command, CancellationToken.None);
            Assert.Equal(command, durable);
            var unsigned = new ProductionMailboxCapacityReceipt(
                ProductionMailboxCapacityOperation.ReserveOrRenew, now, now + 3_600,
                fixture.PromotionKey, targetState.TargetReplicaId,
                targetState.ReservedClosureCount, targetState.ReservedBytes, 0, 0,
                targetState.Revision + 1, SHA256.HashData(command), new byte[64]);
            var privateKey = fixture.NodePrivateKeys[
                Convert.ToHexString(targetState.TargetReplicaId)];
            var receipt = unsigned with
            {
                NodeSignature = PublicKeyAuth.SignDetached(
                    ProductionMailboxCapacityReceiptCodec.GetSigningBytes(unsigned), privateKey)
            };
            Assert.True(await store.RecordCapacityReceiptAsync(fixture.PromotionKey,
                targetState.TargetReplicaId, targetState.Revision, receipt,
                ProductionMailboxCapacityReceiptCodec.Encode(receipt), CancellationToken.None));
        }
    }

    private static async Task AcknowledgeAllTargetsAsync(
        IProductionMailboxV2PublicationStateStore store, ActivationFixture fixture,
        ulong now)
    {
        var state = fixture.Created.State!;
        var materialized = new ProductionMailboxV2MaterializedCache(
            state.CanonicalEnvelope.ToArray(), state.EnvelopeSha256.ToArray(),
            state.LineageCommitment.ToArray(), state.CacheSalt.ToArray());
        foreach (var target in state.Targets)
        {
            var command = await ProductionMailboxV2WireCodec.CreateCommandAsync(
                materialized, target.ReplicaId, state.CohortId, now,
                fixture.PublisherSigner, fixture.PublisherPublicKey,
                CancellationToken.None);
            Assert.True(await store.RecordV2PublicationAttemptAsync(fixture.ActivationKey,
                target.ReplicaId, command, 300, 60, CancellationToken.None));
            Assert.True(await store.AcknowledgeV2PublicationAttemptAsync(fixture.ActivationKey,
                target.ReplicaId, SHA256.HashData(command), CancellationToken.None));
        }
    }

    private static VerifiedProductionMailboxRouteSelectionTransition CreateFakeTransition(
        byte[] oldRol)
    {
        var method = typeof(ProductionMailboxRouteContinuityStateTests).GetMethod("Transition",
            BindingFlags.Static | BindingFlags.NonPublic)
            ?? throw new MissingMethodException("Route continuity test transition helper is missing.");
        return (VerifiedProductionMailboxRouteSelectionTransition)(method.Invoke(null,
            [oldRol, 0x8000_0000_0000_0020UL, Bytes(30, 32),
                0x8000_0000_0000_0010UL, (byte)31, false,
                ProductionMailboxRouteAuthorizationKind.OwnerPRA2])
            ?? throw new InvalidOperationException("Transition helper returned null."));
    }

    private static VerifiedProductionMailboxRouteSelectionTransition CreateNextTransition(
        ProductionMailboxRouteContinuityStateSnapshot source, byte seed)
    {
        var method = typeof(ProductionMailboxRouteContinuityStateTests).GetMethod("Transition",
            BindingFlags.Static | BindingFlags.NonPublic)
            ?? throw new MissingMethodException("Route continuity test transition helper is missing.");
        return (VerifiedProductionMailboxRouteSelectionTransition)(method.Invoke(null,
            [source.CanonicalRouteOriginLkg.ToArray(), source.LocalCommitGeneration,
                source.CurrentAuthorizationHash.ToArray(), source.CurrentAuthorizationSequence,
                seed, false, source.CurrentAuthorizationKind])
            ?? throw new InvalidOperationException("Transition helper returned null."));
    }

    private static byte[] Bytes(byte seed, int length) => Enumerable.Range(0, length)
        .Select(index => unchecked((byte)(seed + index))).ToArray();

    private static byte[] U64Bytes(ulong value)
    {
        var bytes = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(bytes, value);
        return bytes;
    }

    private static PostgreSqlProductionMailboxStateStore NewPostgresStore(
        PostgresDatabase database, ReadOnlyMemory<byte>? integrityKey = null) =>
        new(database.ConnectionString, integrityKey ?? database.IntegrityKey);

    private sealed class ByteArrayComparer : IEqualityComparer<byte[]>
    {
        internal static ByteArrayComparer Instance { get; } = new();
        public bool Equals(byte[]? left, byte[]? right) => ReferenceEquals(left, right)
            || left is not null && right is not null && left.AsSpan().SequenceEqual(right);
        public int GetHashCode(byte[] value) => BitConverter.ToInt32(
            SHA256.HashData(value), 0);
    }

    private sealed class SodiumSigner(byte[] privateKey) : IProductionMailboxClosurePublisherSigner
    {
        internal byte[] SignDirect(ReadOnlySpan<byte> signingBytes) =>
            PublicKeyAuth.SignDetached(signingBytes.ToArray(), privateKey);

        public ValueTask<byte[]> SignAsync(ReadOnlyMemory<byte> signingBytes,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(PublicKeyAuth.SignDetached(
                signingBytes.ToArray(), privateKey));
        }
    }

    private sealed class MutatingSigner(SodiumSigner inner) :
        IProductionMailboxClosurePublisherSigner
    {
        public async ValueTask<byte[]> SignAsync(ReadOnlyMemory<byte> signingBytes,
            CancellationToken cancellationToken)
        {
            var signature = await inner.SignAsync(signingBytes, cancellationToken);
            if (MemoryMarshal.TryGetArray(signingBytes, out ArraySegment<byte> segment))
                segment.Array![segment.Offset] ^= 0x80;
            return signature;
        }
    }

    private sealed class CountingSigner(SodiumSigner inner) :
        IProductionMailboxClosurePublisherSigner
    {
        internal int Calls { get; private set; }
        public ValueTask<byte[]> SignAsync(ReadOnlyMemory<byte> signingBytes,
            CancellationToken cancellationToken)
        {
            Calls++;
            return inner.SignAsync(signingBytes, cancellationToken);
        }
    }

    private sealed class FaultingSigner(string failure) :
        IProductionMailboxClosurePublisherSigner
    {
        private readonly byte[] wrongPrivateKey = PublicKeyAuth.GenerateKeyPair().PrivateKey;
        internal int Calls { get; private set; }

        public ValueTask<byte[]> SignAsync(ReadOnlyMemory<byte> signingBytes,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls++;
            return failure switch
            {
                "length" => ValueTask.FromResult(new byte[63]),
                "wrong-key" => ValueTask.FromResult(PublicKeyAuth.SignDetached(
                    signingBytes.ToArray(), wrongPrivateKey)),
                "cancel" => ValueTask.FromCanceled<byte[]>(new CancellationToken(true)),
                _ => throw new InvalidOperationException("Unknown signer failure fixture.")
            };
        }
    }

    private sealed class RecordingTransport : IProductionMailboxV2ClosureTransport
    {
        internal bool Accept { get; set; }
        internal List<byte[]> Commands { get; } = [];
        public ValueTask<bool> PrepositionV2Async(ProductionMailboxV2Target target,
            ReadOnlyMemory<byte> canonicalCommand, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Commands.Add(canonicalCommand.ToArray());
            return ValueTask.FromResult(Accept);
        }
    }

    private sealed class RecordingCapacityGate : IProductionMailboxV2CapacityGate
    {
        internal int Calls { get; private set; }
        public ValueTask EnsureReservedAsync(ReadOnlyMemory<byte> promotionStateKey,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested(); Calls++;
            return ValueTask.CompletedTask;
        }
    }

    private sealed class ManualClock(DateTimeOffset now) : TimeProvider
    {
        private DateTimeOffset value = now;
        public override DateTimeOffset GetUtcNow() => value;
        internal void Advance(TimeSpan delta) => value += delta;
    }

    private sealed record ActivationFixture(byte[] ActivationKey, byte[] PromotionKey,
        byte[] PublisherPublicKey, SodiumSigner PublisherSigner,
        IReadOnlyDictionary<string, byte[]> NodePrivateKeys,
        ProductionMailboxRouteContinuityStateSnapshot Source,
        ProductionMailboxV2PreparedCache Prepared,
        ProductionMailboxV2ActivationCommitResult Created);

    private sealed class PostgresDatabase : IAsyncDisposable
    {
        private readonly string administrativeConnectionString;
        private readonly string schema;
        private PostgresDatabase(string administrativeConnectionString, string schema,
            string connectionString)
        {
            this.administrativeConnectionString = administrativeConnectionString;
            this.schema = schema; ConnectionString = connectionString;
        }
        internal string ConnectionString { get; }
        internal byte[] IntegrityKey { get; } = RandomNumberGenerator.GetBytes(32);
        internal static async ValueTask<PostgresDatabase> CreateAsync(string connectionString)
        {
            var schema = "deep_registry_pmc2_" +
                Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(8));
            var quoted = new NpgsqlCommandBuilder().QuoteIdentifier(schema);
            await using (var connection = new NpgsqlConnection(connectionString))
            {
                await connection.OpenAsync();
                await new NpgsqlCommand($"CREATE SCHEMA {quoted}", connection)
                    .ExecuteNonQueryAsync();
            }
            var isolated = new NpgsqlConnectionStringBuilder(connectionString)
            { SearchPath = schema };
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
