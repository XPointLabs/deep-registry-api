#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Buffers.Binary;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Registry.Api.DirectoryPublication;
using Npgsql;

namespace Deep.Registry.Api.Tests;

public sealed class DeepIdV2RouteThresholdJournalTests
{
    [Fact]
    public void GenerationIndexProjectionMatchesCanonicalCodecFields()
    {
        var network = Enumerable.Repeat((byte)0x11, 16).ToArray();
        var artifacts = ContactRouteClosureTransportTests.CanonicalTransportArtifacts.Create(network, 0x50);
        var request = ContactRouteAuthorityHttpTests.Request(network, artifacts.Xra);
        var exact = ContactRouteAuthorityWireCodec.EncodeRequest(request);
        var xra = ContactCodec.Decode("XRA1", request.ExactXra1.Span);
        Assert.Equal(request.DirectoryLookupKey.ToArray(), exact.AsSpan(56, 32).ToArray());
        Assert.Equal(xra.Field(2).ToArray(), exact.AsSpan(645, 32).ToArray());
        Assert.Equal(xra.Field(3).ToArray(), exact.AsSpan(685, 8).ToArray());
    }

    [Fact]
    public async Task OperatorFenceAbortsOnExistingCompetingNoncesWithoutChangingEvidence()
    {
        var connection = Environment.GetEnvironmentVariable("DEEP_TEST_DID2_ROUTE_POSTGRES");
        Assert.False(string.IsNullOrWhiteSpace(connection), "Set the isolated route-test PostgreSQL connection.");
        var schema = "did2_route_test_" + Guid.NewGuid().ToString("N");
        await using var admin = new NpgsqlConnection(connection); await admin.OpenAsync();
        await using (var create = new NpgsqlCommand($"CREATE SCHEMA \"{schema}\"", admin)) await create.ExecuteNonQueryAsync();
        var scoped = new NpgsqlConnectionStringBuilder(connection) { SearchPath = schema }.ConnectionString;
        try
        {
            await using var setup = new NpgsqlConnection(scoped); await setup.OpenAsync();
            var sql = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "Fixtures", "did2-route-threshold-journal.sql"));
            await using (var ddl = new NpgsqlCommand(sql, setup)) await ddl.ExecuteNonQueryAsync();
            await using (var old = new NpgsqlCommand("ALTER TABLE deep_did2_route_journal_network DROP COLUMN generation_fence_version; " +
                "DROP INDEX deep_did2_route_generation_winner", setup)) await old.ExecuteNonQueryAsync();
            var network = Enumerable.Repeat((byte)0x11, 16).ToArray();
            var request = ContactRouteAuthorityHttpTests.Request(network,
                ContactRouteClosureTransportTests.CanonicalTransportArtifacts.Create(network, 0x50).Xra);
            var competitors = new[] { request, WithNonce(request, 0xa1) };
            await using (var provision = new NpgsqlCommand("INSERT INTO deep_did2_route_journal_network " +
                "(network_id, entry_count, maximum_entries) VALUES ($1, 2, 4)", setup))
            { provision.Parameters.Add(new() { Value = network }); await provision.ExecuteNonQueryAsync(); }
            foreach (var competitor in competitors)
            {
                await using var insert = new NpgsqlCommand("INSERT INTO deep_did2_route_threshold_journal " +
                    "(network_id, request_nonce, exact_request) VALUES ($1,$2,$3)", setup);
                foreach (var value in new[] { network, competitor.RequestNonce.ToArray(), ContactRouteAuthorityWireCodec.EncodeRequest(competitor) })
                    insert.Parameters.Add(new() { Value = value });
                await insert.ExecuteNonQueryAsync();
            }
            var upgrade = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "Fixtures", "did2-route-threshold-generation-fence.sql"));
            await using (var ddl = new NpgsqlCommand(upgrade, setup))
            {
                var failure = await Assert.ThrowsAsync<PostgresException>(() => ddl.ExecuteNonQueryAsync());
                Assert.Equal(PostgresErrorCodes.UniqueViolation, failure.SqlState);
            }
            await using (var rollback = new NpgsqlCommand("ROLLBACK", setup)) await rollback.ExecuteNonQueryAsync();
            await using (var count = new NpgsqlCommand("SELECT entry_count FROM deep_did2_route_journal_network", setup))
                Assert.Equal(2L, await count.ExecuteScalarAsync());
            await using (var retained = new NpgsqlCommand("SELECT exact_request FROM deep_did2_route_threshold_journal ORDER BY request_nonce", setup))
            {
                await using var reader = await retained.ExecuteReaderAsync();
                foreach (var competitor in competitors)
                { Assert.True(await reader.ReadAsync()); Assert.Equal(ContactRouteAuthorityWireCodec.EncodeRequest(competitor), reader.GetFieldValue<byte[]>(0)); }
                Assert.False(await reader.ReadAsync());
            }
            using var journal = new DeepIdV2PostgreSqlRouteThresholdJournal(scoped, network);
            var calls = 0;
            await Assert.ThrowsAsync<InvalidDataException>(async () => await journal.GetOrIssueAsync(request,
                _ => { calls++; throw new InvalidOperationException("Unprovisioned fence must not sign."); }, default));
            Assert.Equal(0, calls);
        }
        finally
        {
            await using var cleanup = new NpgsqlCommand($"DROP SCHEMA \"{schema}\" CASCADE", admin);
            await cleanup.ExecuteNonQueryAsync();
        }
    }

    // Actual PostgreSQL durability/concurrency, structural transport records.
    // These are NOT issued route authority or physical delivery evidence.
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task PermanentJournalSurvivesCallbackFailureConcurrentRetryRestartAndCapacity(bool upgradeExisting)
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
            var sql = await File.ReadAllTextAsync(sqlPath);
            if (upgradeExisting) sql = sql.Replace("    response_envelope_version smallint NOT NULL DEFAULT 3 CHECK (response_envelope_version = 3),", "")
                .Replace("    request_envelope_version smallint NOT NULL DEFAULT 3 CHECK (request_envelope_version = 3),", "")
                .Replace("BETWEEN 2151 AND 15179", "BETWEEN 2151 AND 11079")
                .Replace("octet_length(exact_request) BETWEEN 1151 AND 25065", "octet_length(exact_request) = 1151");
            await using (var ddl = new NpgsqlCommand(sql, setup))
                await ddl.ExecuteNonQueryAsync();
            if (upgradeExisting)
                await using (var oldFence = new NpgsqlCommand("ALTER TABLE deep_did2_route_journal_network " +
                    "DROP COLUMN generation_fence_version; DROP INDEX deep_did2_route_generation_winner", setup))
                    await oldFence.ExecuteNonQueryAsync();
            var network = Enumerable.Repeat((byte)0x11, 16).ToArray();
            var records = ContactRouteClosureTransportTests.CanonicalTransportArtifacts.Create(network, 0x50);
            var request = ContactRouteAuthorityHttpTests.Request(network, records.Xra);
            var response = ContactRouteAuthorityWireCodec.EncodeResponse(request,
                new ContactRouteAuthorityWireResponse(network, request.RequestNonce.Span,
                    records.Pms, records.Xrc, records.Xss, ContactRouteAuthorityHttpTests.IssuanceHead(network)));
            using var journal = new DeepIdV2PostgreSqlRouteThresholdJournal(scoped, network);
            var calls = 0;
            ValueTask<byte[]> Issue(CancellationToken ct)
            { ct.ThrowIfCancellationRequested(); Interlocked.Increment(ref calls); return ValueTask.FromResult(response); }
            await Assert.ThrowsAsync<InvalidDataException>(async () =>
                await journal.GetOrIssueAsync(request, Issue, default));
            Assert.Equal(0, calls);
            await using (var provision = new NpgsqlCommand("INSERT INTO deep_did2_route_journal_network " +
                             "(network_id, entry_count, maximum_entries) VALUES ($1, 0, $2)", setup))
            {
                provision.Parameters.Add(new() { Value = network });
                provision.Parameters.Add(new() { Value = upgradeExisting ? 4L : 3L });
                await provision.ExecuteNonQueryAsync();
            }
            if (upgradeExisting)
            {
                // Old provision rejects before reservation/signature callbacks.
                await Assert.ThrowsAsync<InvalidDataException>(async () => await journal.GetOrIssueAsync(request, Issue, default));
                Assert.Equal(0, calls);
                var retired = WithLineage(request, 0x60, 0xc1);
                // Opaque retired audit bytes, never a positive V2 reader.
                var retiredRequest = ContactRouteAuthorityWireCodec.EncodeRequest(retired)[..ContactRouteAuthorityWireCodec.RequestPrefixBytes];
                BinaryPrimitives.WriteUInt16BigEndian(retiredRequest, 2);
                BinaryPrimitives.WriteUInt32BigEndian(retiredRequest.AsSpan(4), checked((uint)retiredRequest.Length));
                var current = ContactRouteAuthorityWireCodec.EncodeResponse(retired,
                    new(network, retired.RequestNonce.Span, records.Pms, records.Xrc, records.Xss,
                        ContactRouteAuthorityHttpTests.IssuanceHead(network)));
                var retiredResponse = current[..(current.Length - 4 - ContactRouteAuthorityHttpTests.IssuanceHead(network).Length)];
                BinaryPrimitives.WriteUInt16BigEndian(retiredResponse, 2);
                BinaryPrimitives.WriteUInt32BigEndian(retiredResponse.AsSpan(4), checked((uint)retiredResponse.Length));
                await using (var preserve = new NpgsqlCommand("INSERT INTO deep_did2_route_threshold_journal " +
                    "(network_id, request_nonce, exact_request, exact_response) VALUES ($1,$2,$3,$4)", setup))
                {
                    foreach (var value in new[] { network, retired.RequestNonce.ToArray(), retiredRequest, retiredResponse })
                        preserve.Parameters.Add(new() { Value = value });
                    await preserve.ExecuteNonQueryAsync();
                }
                await using (var updateCount = new NpgsqlCommand("UPDATE deep_did2_route_journal_network SET entry_count=1 WHERE network_id=$1", setup))
                {
                    updateCount.Parameters.Add(new() { Value = network });
                    Assert.Equal(1, await updateCount.ExecuteNonQueryAsync());
                }
                var upgrade = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "Fixtures", "did2-route-threshold-issued-head-upgrade.sql"));
                await using (var ddl = new NpgsqlCommand(upgrade, setup)) await ddl.ExecuteNonQueryAsync();
                // DR75 alone cannot activate a nonce-only journal for renewal.
                await Assert.ThrowsAsync<InvalidDataException>(async () => await journal.GetOrIssueAsync(request, Issue, default));
                Assert.Equal(0, calls);
                var fence = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "Fixtures", "did2-route-threshold-generation-fence.sql"));
                await using (var ddl = new NpgsqlCommand(fence, setup)) await ddl.ExecuteNonQueryAsync();
                await Assert.ThrowsAsync<InvalidDataException>(async () => await journal.GetOrIssueAsync(request, Issue, default));
                Assert.Equal(0, calls);
                var requestUpgrade = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "Fixtures", "did2-route-threshold-successor-request.sql"));
                await using (var ddl = new NpgsqlCommand(requestUpgrade, setup)) await ddl.ExecuteNonQueryAsync();
                await using (var retained = new NpgsqlCommand("SELECT exact_request, exact_response FROM deep_did2_route_threshold_journal WHERE request_nonce=$1", setup))
                {
                    retained.Parameters.Add(new() { Value = retired.RequestNonce.ToArray() });
                    await using var reader = await retained.ExecuteReaderAsync(); Assert.True(await reader.ReadAsync());
                    Assert.Equal(retiredRequest, reader.GetFieldValue<byte[]>(0)); Assert.Equal(retiredResponse, reader.GetFieldValue<byte[]>(1));
                }
                var rejected = await Record.ExceptionAsync(async () => await journal.GetOrIssueAsync(retired, Issue, default));
                Assert.True(rejected is ContactRouteAuthorityRejectedException);
                Assert.Equal(0, calls);
                await using var count = new NpgsqlCommand("SELECT entry_count FROM deep_did2_route_journal_network", setup);
                Assert.Equal(1L, await count.ExecuteScalarAsync());
            }
            await Assert.ThrowsAsync<IOException>(async () => await journal.GetOrIssueAsync(request,
                _ => throw new IOException("Injected signing interruption."), default));
            await using (var reserved = new NpgsqlCommand("SELECT entry_count FROM deep_did2_route_journal_network", setup))
                Assert.Equal(upgradeExisting ? 2L : 1L, await reserved.ExecuteScalarAsync());
            // Failed signing does not release a generation, including another
            // process/nonce; no callback or additional capacity is consumed.
            await Task.WhenAll(Enumerable.Range(0xa0, 8).Select(async value =>
                await Assert.ThrowsAsync<ContactRouteAuthorityRejectedException>(async () =>
                    await journal.GetOrIssueAsync(WithNonce(request, (byte)value), Issue, default))));
            Assert.Equal(0, calls);
            await using (var reserved = new NpgsqlCommand("SELECT entry_count FROM deep_did2_route_journal_network", setup))
                Assert.Equal(upgradeExisting ? 2L : 1L, await reserved.ExecuteScalarAsync());
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
            await Assert.ThrowsAsync<ContactRouteAuthorityRejectedException>(async () =>
                await restarted.GetOrIssueAsync(WithNonce(request, 0xa1), Issue, default));
            var another = WithLineage(request, 0x70, 0xa1);
            await Assert.ThrowsAsync<OperationCanceledException>(async () =>
                await restarted.GetOrIssueAsync(another, _ => throw new OperationCanceledException(), default));
            var next = WithGeneration(request, ulong.MaxValue, 0xa2);
            await Assert.ThrowsAsync<OperationCanceledException>(async () =>
                await restarted.GetOrIssueAsync(next, _ => throw new OperationCanceledException(), default));
            await Assert.ThrowsAsync<ContactRouteAuthorityRejectedException>(async () =>
                await restarted.GetOrIssueAsync(WithNonce(next, 0xa3), Issue, default));
            await Assert.ThrowsAsync<ContactRouteAuthorityUnavailableException>(async () =>
                await restarted.GetOrIssueAsync(WithLineage(request, 0x80, 0xa4), Issue, default));
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
            request.MinimumAdh1CoreHash.Span, request.ExactDca1.Span, request.ExactXra1.Span,
            request.ExactPredecessorXir1V2.Span, request.ExactPredecessorRouteClosure.Span);

    private static ContactRouteAuthorityWireRequest WithLineage(ContactRouteAuthorityWireRequest request, byte seed, byte nonce) =>
        WithNonce(ContactRouteAuthorityHttpTests.Request(request.NetworkId.ToArray(),
            ContactRouteClosureTransportTests.CanonicalTransportArtifacts.Create(request.NetworkId.ToArray(), seed).Xra), nonce);

    private static ContactRouteAuthorityWireRequest WithGeneration(ContactRouteAuthorityWireRequest request, ulong generation, byte nonce)
    {
        var record = ContactCodec.Decode("XRA1", request.ExactXra1.Span);
        var fields = Enumerable.Range(1, 16).Select(tag => record.Field(tag)).ToArray();
        var bytes = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(bytes, generation);
        fields[2] = bytes; fields[3] = Enumerable.Repeat((byte)0x71, 32).ToArray();
        var xra = ContactCodecValidation.AuthorRecord("XRA1", fields);
        var artifacts = ContactRouteClosureTransportTests.CanonicalTransportArtifacts.Create(request.NetworkId.ToArray(), 0x50);
        var prior = ContactCodec.Decode("XRA1", artifacts.Xra);
        var dcaReference = new byte[38]; "DCA1"u8.CopyTo(dcaReference);
        BinaryPrimitives.WriteUInt16BigEndian(dcaReference.AsSpan(4), 2); dcaReference.AsSpan(6).Fill(0x81);
        var invite = DeepIdV2InviteRendezvousCodec.AuthorForValidation([
            request.NetworkId, Enumerable.Repeat((byte)0x82, 32).ToArray(), new byte[8], new byte[32],
            prior.Field(5), prior.Field(6), prior.Field(10), prior.Field(11), new byte[] { 1 }, new byte[4],
            new byte[] { 0, 1 }, prior.Field(9), prior.Field(12), prior.Field(13), prior.Field(15), dcaReference,
            Enumerable.Repeat((byte)0x83, 64).ToArray(), ContactCodec.ArtifactReference("XRA1", prior).CanonicalBytes]);
        return WithNonce(new(request.NetworkId.Span, request.RequestNonce.Span,
            request.DirectoryLookupKey.Span, request.MinimumAdh1Generation,
            request.MinimumAdh1CoreHash.Span, request.ExactDca1.Span, xra.CanonicalBytes.Span,
            invite.CanonicalBytes.Span, artifacts.Closure), nonce);
    }
}
#endif
