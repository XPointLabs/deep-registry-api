#if DEEP_PROTOCOL_DIRECTORY_V1
using Deep.Protocol.AccountDirectoryV1;
using Deep.Registry.Api.DirectoryPublication;
using Npgsql;

namespace Deep.Registry.Api.Tests;

public sealed class DeepIdV2PostgreSqlLatestHeadFloorTests
{
    [Fact]
    public async Task ExternalFloorRejectsMissingOldAndConcurrentHeadsWhenConfigured()
    {
        var connectionString = Environment.GetEnvironmentVariable(
            "DEEP_TEST_DID2_FLOOR_POSTGRES");
        if (string.IsNullOrWhiteSpace(connectionString)) return;

        var schema = "did2_floor_test_" + Guid.NewGuid().ToString("N");
        var schemaConnection = new NpgsqlConnectionStringBuilder(connectionString)
        {
            SearchPath = schema
        }.ConnectionString;
        await using var admin = new NpgsqlConnection(connectionString);
        await admin.OpenAsync();
        await using (var setup = new NpgsqlCommand(
                         $"CREATE SCHEMA \"{schema}\"; " +
                         $"CREATE TABLE \"{schema}\".deep_did2_latest_head_floor (" +
                         "network_id bytea PRIMARY KEY CHECK (octet_length(network_id) = 16), " +
                         "exact_adh1 bytea NOT NULL CHECK (octet_length(exact_adh1) BETWEEN 1 AND 4096), " +
                         "core_hash bytea NOT NULL CHECK (octet_length(core_hash) = 32))",
                         admin))
            await setup.ExecuteNonQueryAsync();
        try
        {
            using var fixture = ContactResolveAuthoringFixture.Create(
                currentValue: false);
            var genesis = new AccountDirectoryProtectedLkg(
                fixture.CreateDid2GenesisHead());
            var firstHead = genesis.Head;
            var advanced = new AccountDirectoryProtectedLkg(
                AccountDirectoryAdh1Codec.Encode(new AccountDirectoryAdh1(
                    firstHead.NetworkId.Span, 1, genesis.CoreHash.Span, 1,
                    Enumerable.Repeat((byte)0x71, 32).ToArray(),
                    Enumerable.Repeat((byte)0x72, 32).ToArray(),
                    firstHead.ExactXnaAuthorityCoreReference.Span,
                    firstHead.WitnessPolicyHash.Span,
                    firstHead.ValidFrom,
                    firstHead.ValidUntil, 2,
                    firstHead.Witnesses)));
            using var floor = new DeepIdV2PostgreSqlLatestHeadFloor(
                schemaConnection, fixture.Network);
            await Assert.ThrowsAsync<InvalidDataException>(async () =>
                await floor.RequireCurrentAsync(genesis));
            await floor.ProvisionGenesisAsync(genesis);
            await Assert.ThrowsAsync<PostgresException>(async () =>
                await floor.ProvisionGenesisAsync(genesis));
            await floor.RequireCurrentAsync(genesis);
            await floor.AdvanceAsync(genesis, advanced);
            await floor.RequireCurrentAsync(advanced);
            await Assert.ThrowsAsync<InvalidDataException>(async () =>
                await floor.RequireCurrentAsync(genesis));
            await Assert.ThrowsAsync<InvalidDataException>(async () =>
                await floor.AdvanceAsync(genesis, advanced));
            await Assert.ThrowsAsync<InvalidDataException>(async () =>
                await floor.AdvanceAsync(advanced, advanced));
            using var restarted = new DeepIdV2PostgreSqlLatestHeadFloor(
                schemaConnection, fixture.Network);
            await restarted.RequireCurrentAsync(advanced);
            await Assert.ThrowsAsync<InvalidDataException>(async () =>
                await restarted.RequireCurrentAsync(genesis));
        }
        finally
        {
            await using var cleanup = new NpgsqlCommand(
                $"DROP SCHEMA \"{schema}\" CASCADE", admin);
            await cleanup.ExecuteNonQueryAsync();
        }
    }
}
#endif
