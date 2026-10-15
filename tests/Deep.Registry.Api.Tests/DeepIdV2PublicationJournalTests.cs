#if DEEP_PROTOCOL_DIRECTORY_V1
using Npgsql;
using Deep.Protocol.ContactV1;
using Deep.Registry.Api.DirectoryPublication;
using XNode.IntegrationTests.Runtime;

namespace Deep.Registry.Api.Tests;

public sealed class DeepIdV2PublicationJournalTests
{
    [Fact]
    public async Task CompletedOriginalWinnerReadPreservesPermanentFenceAndRejectsPendingOrSubstitutedScope()
    {
        var database = Environment.GetEnvironmentVariable("DEEP_TEST_DID2_ROUTE_POSTGRES");
        Assert.False(string.IsNullOrWhiteSpace(database), "Set the isolated route-test database.");
        var schema = "did2_publication_recovery_" + Guid.NewGuid().ToString("N");
        await using var admin = new NpgsqlConnection(database); await admin.OpenAsync();
        await using (var create = new NpgsqlCommand($"CREATE SCHEMA \"{schema}\"", admin)) await create.ExecuteNonQueryAsync();
        try
        {
            var scoped = new NpgsqlConnectionStringBuilder(database) { SearchPath = schema }.ConnectionString;
            await using var db = new NpgsqlConnection(scoped); await db.OpenAsync();
            await using (var provision = new NpgsqlCommand(await File.ReadAllTextAsync(
                Path.Combine(AppContext.BaseDirectory, "Fixtures", "did2-publication-journal.sql")), db))
                await provision.ExecuteNonQueryAsync();
            using var fixture = await DeepIdV2PublicationAuthorityFixture.CreateAsync(authorContactPublication: true);
            var request = fixture.ContactOwnedRequest;
            var exactRequest = ContactPublicationAuthorityWireCodec.EncodeRequest(request);
            var exactResponse = ContactPublicationAuthorityWireCodec.EncodeResponse(request,
                new(request.NetworkId.Span, request.RequestNonce.Span, fixture.ContactPublication.CanonicalBytes.Span));
            await using (var root = new NpgsqlCommand(
                "INSERT INTO deep_did2_publication_journal_network(network_id,entry_count,maximum_entries) VALUES ($1,0,8)", db))
            { root.Parameters.Add(new() { Value = request.NetworkId.ToArray() }); await root.ExecuteNonQueryAsync(); }
            var issueCalls = 0;
            using (var journal = new DeepIdV2PostgreSqlPublicationJournal(scoped, request.NetworkId.Span))
                _ = await journal.GetOrIssueAsync(request, _ => { issueCalls++; return ValueTask.FromResult(exactResponse); }, default);
            using var reopened = new DeepIdV2PostgreSqlPublicationJournal(scoped, request.NetworkId.Span);
            var hash = fixture.ContactPublication.RequestHash;
            // Storage read is deliberately not current request or dispatch
            // authority: the original short envelope has elapsed in this fixture.
            fixture.Sample += 120;
            var winner = await reopened.ReadCompletedWinnerAsync(request.RequestNonce, request.DirectoryLookupKey, hash, default);
            Assert.Equal(exactRequest, winner.Request.ToArray()); Assert.Equal(exactResponse, winner.Response.ToArray());
            Assert.Equal(1, issueCalls);
            var wrong = Enumerable.Repeat((byte)0xab, 32).ToArray();
            await Assert.ThrowsAsync<ContactPublicationAuthorityRejectedException>(async () =>
                await reopened.ReadCompletedWinnerAsync(request.RequestNonce, request.DirectoryLookupKey, wrong, default));
            await Assert.ThrowsAsync<ContactPublicationAuthorityRejectedException>(async () =>
                await reopened.ReadCompletedWinnerAsync(request.RequestNonce, wrong, hash, default));
            await Assert.ThrowsAsync<ContactPublicationAuthorityRejectedException>(async () =>
                await reopened.ReadCompletedWinnerAsync(wrong, request.DirectoryLookupKey, hash, default));
            foreach (var hostile in new[] { new byte[31], new byte[32], new byte[33] })
            {
                await Assert.ThrowsAsync<ArgumentException>(async () =>
                    await reopened.ReadCompletedWinnerAsync(hostile, request.DirectoryLookupKey, hash, default));
            }
            using var cancellation = new CancellationTokenSource(); cancellation.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
                await reopened.ReadCompletedWinnerAsync(request.RequestNonce, request.DirectoryLookupKey, hash, cancellation.Token));
            Assert.Equal(1, issueCalls);

            using var pending = await DeepIdV2PublicationAuthorityFixture.CreateAsync(authorContactPublication: true,
                contactPublicationMarker: 0x57);
            var pendingRequest = pending.ContactOwnedRequest;
            await Assert.ThrowsAsync<IOException>(async () => await reopened.GetOrIssueAsync(pendingRequest,
                _ => { issueCalls++; throw new IOException("Injected response loss before winner commit."); }, default));
            await Assert.ThrowsAsync<ContactPublicationAuthorityUnavailableException>(async () =>
                await reopened.ReadCompletedWinnerAsync(pendingRequest.RequestNonce, pendingRequest.DirectoryLookupKey,
                    pending.ContactPublication.RequestHash, default));
            Assert.Equal(2, issueCalls);
            await using (var count = new NpgsqlCommand("SELECT entry_count FROM deep_did2_publication_journal_network", db))
                Assert.Equal(2L, await count.ExecuteScalarAsync());
            // Corruption remains corruption, never a new reservation or repair.
            await using (var corrupt = new NpgsqlCommand(
                "UPDATE deep_did2_publication_journal SET directory_lookup_key=$1 WHERE request_nonce=$2", db))
            {
                corrupt.Parameters.Add(new() { Value = wrong }); corrupt.Parameters.Add(new() { Value = request.RequestNonce.ToArray() });
                Assert.Equal(1, await corrupt.ExecuteNonQueryAsync());
            }
            await Assert.ThrowsAsync<InvalidDataException>(async () =>
                await reopened.ReadCompletedWinnerAsync(request.RequestNonce, request.DirectoryLookupKey, hash, default));
            await using (var audit = new NpgsqlCommand(
                "SELECT exact_request,exact_response,directory_lookup_key FROM deep_did2_publication_journal WHERE request_nonce=$1", db))
            {
                audit.Parameters.Add(new() { Value = request.RequestNonce.ToArray() });
                await using var read = await audit.ExecuteReaderAsync(); Assert.True(await read.ReadAsync());
                Assert.Equal(exactRequest, read.GetFieldValue<byte[]>(0)); Assert.Equal(exactResponse, read.GetFieldValue<byte[]>(1));
                Assert.Equal(wrong, read.GetFieldValue<byte[]>(2)); Assert.False(await read.ReadAsync());
            }
            Assert.Equal(2, issueCalls);
        }
        finally
        {
            await using var cleanup = new NpgsqlCommand($"DROP SCHEMA \"{schema}\" CASCADE", admin);
            await cleanup.ExecuteNonQueryAsync();
        }
    }

    [Fact]
    public async Task PublicationSuccessorProvisionPreservesOpaqueAuditAndUnsignedPermanentFence()
    {
        var database = Environment.GetEnvironmentVariable("DEEP_TEST_DID2_ROUTE_POSTGRES");
        Assert.False(string.IsNullOrWhiteSpace(database), "Set the isolated route-test database.");
        var schema = "did2_publication_provision_" + Guid.NewGuid().ToString("N");
        await using var admin = new NpgsqlConnection(database); await admin.OpenAsync();
        await using (var create = new NpgsqlCommand($"CREATE SCHEMA \"{schema}\"", admin)) await create.ExecuteNonQueryAsync();
        try
        {
            var scoped = new NpgsqlConnectionStringBuilder(database) { SearchPath = schema }.ConnectionString;
            await using var db = new NpgsqlConnection(scoped); await db.OpenAsync();
            // Opaque audit bytes, not a legacy codec/vector or accepted runtime history.
            await using (var oldSchema = new NpgsqlCommand("""
                CREATE TABLE deep_did2_publication_journal_network (
                    network_id bytea PRIMARY KEY, entry_count bigint NOT NULL, maximum_entries bigint NOT NULL);
                CREATE TABLE deep_did2_publication_journal (
                    network_id bytea NOT NULL REFERENCES deep_did2_publication_journal_network(network_id),
                    request_nonce bytea NOT NULL, exact_request bytea NOT NULL CHECK (octet_length(exact_request) BETWEEN 23302 AND 155210),
                    exact_response bytea CHECK (octet_length(exact_response) BETWEEN 14682 AND 93092),
                    PRIMARY KEY(network_id, request_nonce));
                """, db)) await oldSchema.ExecuteNonQueryAsync();
            var network = Enumerable.Repeat((byte)1, 16).ToArray();
            var nonce = Enumerable.Repeat((byte)2, 32).ToArray();
            var request = new byte[23_302]; request[1] = 2;
            var response = new byte[14_682]; response[1] = 2;
            await using (var provisionNetwork = new NpgsqlCommand("INSERT INTO deep_did2_publication_journal_network VALUES ($1,1,128)", db))
            {
                provisionNetwork.Parameters.Add(new() { Value = network }); await provisionNetwork.ExecuteNonQueryAsync();
            }
            await using (var insert = new NpgsqlCommand("INSERT INTO deep_did2_publication_journal VALUES ($1,$2,$3,$4)", db))
            {
                foreach (var value in new[] { network, nonce, request, response }) insert.Parameters.Add(new() { Value = value });
                await insert.ExecuteNonQueryAsync();
            }
            await using (var provision = new NpgsqlCommand(await File.ReadAllTextAsync(
                Path.Combine(AppContext.BaseDirectory, "Fixtures", "did2-publication-successor-fence.sql")), db)) await provision.ExecuteNonQueryAsync();
            await using (var provision = new NpgsqlCommand(await File.ReadAllTextAsync(
                Path.Combine(AppContext.BaseDirectory, "Fixtures", "did2-publication-one-time-scope.sql")), db)) await provision.ExecuteNonQueryAsync();
            await using (var read = new NpgsqlCommand("SELECT j.exact_request,j.exact_response,j.directory_lookup_key," +
                "n.entry_count,n.maximum_entries,n.request_envelope_version,n.generation_fence_version " +
                "FROM deep_did2_publication_journal j JOIN deep_did2_publication_journal_network n USING(network_id)", db))
            await using (var reader = await read.ExecuteReaderAsync())
            {
                Assert.True(await reader.ReadAsync()); Assert.Equal(request, reader.GetFieldValue<byte[]>(0));
                Assert.Equal(response, reader.GetFieldValue<byte[]>(1)); Assert.True(reader.IsDBNull(2));
                Assert.Equal(1L, reader.GetInt64(3)); Assert.Equal(128L, reader.GetInt64(4));
                Assert.Equal(4, reader.GetInt16(5)); Assert.Equal(2, reader.GetInt16(6)); Assert.False(await reader.ReadAsync());
            }
            // No signed-bigint truncation at the schema fence. These are not
            // authenticated requests; runtime must independently verify projections.
            var highGeneration = Enumerable.Repeat((byte)255, 8).ToArray();
            var currentShape = new byte[23_322]; currentShape[1] = 4;
            var leaf = Enumerable.Repeat((byte)3, 32).ToArray();
            await InsertProjectedAsync(4);
            var conflict = await Assert.ThrowsAsync<PostgresException>(() => InsertProjectedAsync(5));
            Assert.Equal(PostgresErrorCodes.UniqueViolation, conflict.SqlState);
            // V4 scopes are independent, but neither half-null scope nor a
            // one-time successor is admissible even as a schema projection.
            var oneTimeShape = new byte[23_322]; oneTimeShape[1] = 4;
            await InsertScopeAsync(6, 2, new byte[8], new byte[32], leaf);
            await InsertScopeAsync(7, 2, new byte[8], new byte[32], Enumerable.Repeat((byte)8, 32).ToArray());
            var sameInvite = await Assert.ThrowsAsync<PostgresException>(() => InsertScopeAsync(8, 2, new byte[8], new byte[32], leaf));
            Assert.Equal(PostgresErrorCodes.UniqueViolation, sameInvite.SqlState);
            var badGeneration = await Assert.ThrowsAsync<PostgresException>(() => InsertScopeAsync(9, 2, highGeneration, leaf, leaf));
            Assert.Equal(PostgresErrorCodes.CheckViolation, badGeneration.SqlState);
            var halfNull = await Assert.ThrowsAsync<PostgresException>(() => InsertScopeAsync(10, null, new byte[8], new byte[32], leaf));
            Assert.Equal(PostgresErrorCodes.CheckViolation, halfNull.SqlState);
            async Task InsertScopeAsync(byte marker, short? kind, byte[] generation, byte[] predecessor, byte[] locator)
            {
                await using var insert = new NpgsqlCommand("INSERT INTO deep_did2_publication_journal " +
                    "(network_id,request_nonce,exact_request,directory_lookup_key,request_generation,predecessor_object_hash,object_ciphertext_hash,publication_kind,locator_hash) " +
                    "VALUES ($1,$2,$3,$4,$5,$6,$4,$7,$8)", db);
                foreach (var value in new[] { network, Enumerable.Repeat(marker, 32).ToArray(), oneTimeShape, leaf, generation, predecessor })
                    insert.Parameters.Add(new() { Value = value });
                insert.Parameters.Add(new() { NpgsqlDbType = NpgsqlTypes.NpgsqlDbType.Smallint, Value = kind is null ? DBNull.Value : kind.Value });
                insert.Parameters.Add(new() { Value = locator });
                await insert.ExecuteNonQueryAsync();
            }
            async Task InsertProjectedAsync(byte marker)
            {
                await using var insert = new NpgsqlCommand("INSERT INTO deep_did2_publication_journal " +
                    "(network_id,request_nonce,exact_request,directory_lookup_key,request_generation,predecessor_object_hash,object_ciphertext_hash,publication_kind,locator_hash) " +
                    "VALUES ($1,$2,$3,$4,$5,$4,$4,1,$4)", db);
                foreach (var value in new[] { network, Enumerable.Repeat(marker, 32).ToArray(), currentShape, leaf, highGeneration })
                    insert.Parameters.Add(new() { Value = value });
                await insert.ExecuteNonQueryAsync();
            }
        }
        finally
        {
            // Exact randomly named schema created by this test only.
            await using var cleanup = new NpgsqlCommand($"DROP SCHEMA \"{schema}\" CASCADE", admin);
            await cleanup.ExecuteNonQueryAsync();
        }
    }
}
#endif
