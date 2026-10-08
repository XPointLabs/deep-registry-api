using Deep.Protocol.ApplicationCore;
using Npgsql;

namespace Deep.Registry.Api.Tests;

public sealed class FixturePrerequisiteTests
{
    [Fact]
    [Trait("FixturePreflight", "true")]
    public async Task FixturePreflight_LocalDatabaseAndNativeProvidersAreActuallyAvailable()
    {
        foreach (var name in new[] { "DEEP_TEST_DID2_FLOOR_POSTGRES", "DEEP_TEST_DID2_ROUTE_POSTGRES", "DEEP_TEST_DID2_GRANT_POSTGRES" })
        {
            var value = Environment.GetEnvironmentVariable(name);
            Assert.False(string.IsNullOrWhiteSpace(value), "Use the disposable local PostgreSQL provider.");
            var settings = new NpgsqlConnectionStringBuilder(value);
            Assert.Equal("127.0.0.1", settings.Host);
            Assert.Equal("deep_s00", settings.Database);
            Assert.Equal("deep_s00", settings.Username);
            Assert.False(settings.Pooling);
            await using var connection = new NpgsqlConnection(value);
            await connection.OpenAsync();
            await using var command = new NpgsqlCommand("SELECT current_database(), current_user", connection);
            await using var reader = await command.ExecuteReaderAsync();
            Assert.True(await reader.ReadAsync());
            Assert.Equal("deep_s00", reader.GetString(0));
            Assert.Equal("deep_s00", reader.GetString(1));
        }
        using var verifier = DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess();
    }
}
