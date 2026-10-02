#if DEEP_PROTOCOL_DIRECTORY_V1
using Deep.Protocol.ContactV1;
using Deep.Registry.Api.DirectoryPublication;
using Npgsql;

namespace Deep.Registry.Api.Tests;

public sealed class DeepIdV2RouteThresholdJournalTests
{
    // Actual PostgreSQL durability/concurrency, structural transport records.
    // These are NOT issued route authority or physical delivery evidence.
    [Fact]
    public async Task PermanentJournalSurvivesCallbackFailureConcurrentRetryRestartAndCapacity()
    {
        var connection = Environment.GetEnvironmentVariable("DEEP_TEST_DID2_ROUTE_POSTGRES");
        Assert.False(string.IsNullOrWhiteSpace(connection), "Set the isolated route-test PostgreSQL connection.");
        var schema = "did2_route_test_" + Guid.NewGuid().ToString("N");
        var scoped = new NpgsqlConnectionStringBuilder(connection) { SearchPath = schema }.ConnectionString;
        await using var admin = new NpgsqlConnection(connection);
        await admin.OpenAsync();
        await using (var create = new NpgsqlCommand($"CREATE SCHEMA \"{schema}\"", admin))
            await create.ExecuteNonQueryAsync();
        try
        {
            // Same schema as the operator-provisioned production journal.
            var sqlPath = Path.Combine(AppContext.BaseDirectory, "Fixtures", "did2-route-threshold-journal.sql");
            await using var setup = new NpgsqlConnection(scoped);
            await setup.OpenAsync();
            await using (var ddl = new NpgsqlCommand(await File.ReadAllTextAsync(sqlPath), setup))
                await ddl.ExecuteNonQueryAsync();
            var network = Enumerable.Repeat((byte)0x11, 16).ToArray();
            var records = ContactRouteClosureTransportTests.CanonicalTransportArtifacts.Create(network, 0x50);
            var request = ContactRouteAuthorityHttpTests.Request(network, records.Xra);
            var response = ContactRouteAuthorityWireCodec.EncodeResponse(request,
                new ContactRouteAuthorityWireResponse(network, request.RequestNonce.Span,
                    records.Pms, records.Xrc, records.Xss));
            using var journal = new DeepIdV2PostgreSqlRouteThresholdJournal(scoped, network);
            var calls = 0;
            ValueTask<byte[]> Issue(CancellationToken ct)
            { ct.ThrowIfCancellationRequested(); Interlocked.Increment(ref calls); return ValueTask.FromResult(response); }
            await Assert.ThrowsAsync<InvalidDataException>(async () =>
                await journal.GetOrIssueAsync(request, Issue, default));
            Assert.Equal(0, calls);
            await using (var provision = new NpgsqlCommand("INSERT INTO deep_did2_route_journal_network " +
                             "(network_id, entry_count, maximum_entries) VALUES ($1, 0, 2)", setup))
            {
                provision.Parameters.Add(new() { Value = network });
                await provision.ExecuteNonQueryAsync();
            }
            await Assert.ThrowsAsync<IOException>(async () => await journal.GetOrIssueAsync(request,
                _ => throw new IOException("Injected signing interruption."), default));
            await using (var reserved = new NpgsqlCommand("SELECT entry_count FROM deep_did2_route_journal_network", setup))
                Assert.Equal(1L, await reserved.ExecuteScalarAsync());
            var changed = new ContactRouteAuthorityWireRequest(network, request.RequestNonce.Span,
                request.DirectoryLookupKey.Span, 1, request.MinimumAdh1CoreHash.Span,
                request.ExactDca1.Span, request.ExactXra1.Span);
            await Assert.ThrowsAsync<ContactRouteAuthorityRejectedException>(async () =>
                await journal.GetOrIssueAsync(changed, Issue, default));
            var winners = await Task.WhenAll(Enumerable.Range(0, 8).Select(async _ =>
                (await journal.GetOrIssueAsync(request, Issue, default)).ToArray()));
            Assert.Equal(1, calls);
            Assert.All(winners, winner => Assert.Equal(response, winner));
            using var restarted = new DeepIdV2PostgreSqlRouteThresholdJournal(scoped, network);
            Assert.Equal(response, (await restarted.GetOrIssueAsync(request,
                _ => throw new InvalidOperationException("Replay must not sign."), default)).ToArray());
            var another = WithNonce(request, 0xa1);
            await Assert.ThrowsAsync<OperationCanceledException>(async () =>
                await restarted.GetOrIssueAsync(another, _ => throw new OperationCanceledException(), default));
            await Assert.ThrowsAsync<ContactRouteAuthorityUnavailableException>(async () =>
                await restarted.GetOrIssueAsync(WithNonce(request, 0xa2), Issue, default));
            await using (var corrupt = new NpgsqlCommand("UPDATE deep_did2_route_threshold_journal " +
                             "SET exact_response = set_byte(exact_response, 0, 255) WHERE request_nonce = $1", setup))
            {
                corrupt.Parameters.Add(new() { Value = request.RequestNonce.ToArray() });
                Assert.Equal(1, await corrupt.ExecuteNonQueryAsync());
            }
            await Assert.ThrowsAsync<FormatException>(async () =>
                await restarted.GetOrIssueAsync(request, Issue, default));
            Assert.Equal(1, calls);
        }
        finally
        {
            // Exact random test schema only, never a production database.
            await using var cleanup = new NpgsqlCommand($"DROP SCHEMA \"{schema}\" CASCADE", admin);
            await cleanup.ExecuteNonQueryAsync();
        }
    }

    private static ContactRouteAuthorityWireRequest WithNonce(ContactRouteAuthorityWireRequest request, byte value) =>
        new(request.NetworkId.Span, Enumerable.Repeat(value, 32).ToArray(),
            request.DirectoryLookupKey.Span, request.MinimumAdh1Generation,
            request.MinimumAdh1CoreHash.Span, request.ExactDca1.Span, request.ExactXra1.Span);
}
#endif
