#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Registry.Api.DirectoryPublication;
using Npgsql;
using Sodium;

namespace Deep.Registry.Api.Tests;

public sealed class DeepIdV2MailboxGrantJournalTests
{
    // Actual external PostgreSQL durability. Structural target mailbox records
    // are not issuer authority; Protocol/node/client evidence is tested separately.
    [Fact]
    public async Task HashOnlyReservationConcurrentWinnerRestartConflictCapacityAndCorruption()
    {
        var connection = Environment.GetEnvironmentVariable("DEEP_TEST_DID2_GRANT_POSTGRES");
        Assert.False(string.IsNullOrWhiteSpace(connection), "Set the isolated grant-test PostgreSQL connection.");
        var schema = "did2_grant_test_" + Guid.NewGuid().ToString("N");
        var scoped = new NpgsqlConnectionStringBuilder(connection) { SearchPath = schema }.ConnectionString;
        await using var admin = new NpgsqlConnection(connection); await admin.OpenAsync();
        await using (var create = new NpgsqlCommand($"CREATE SCHEMA \"{schema}\"", admin)) await create.ExecuteNonQueryAsync();
        try
        {
            await using var setup = new NpgsqlConnection(scoped); await setup.OpenAsync();
            await using (var ddl = new NpgsqlCommand(await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory,
                "Fixtures", "did2-mailbox-grant-journal.sql")), setup)) await ddl.ExecuteNonQueryAsync();
            var request = Request(0x41); var scope = Bytes(32, 0x42); var response = Success(request);
            using var journal = new DeepIdV2PostgreSqlMailboxGrantJournal(scoped, request.Field(1).Span);
            var calls = 0;
            ValueTask<ReadOnlyMemory<byte>> Issue(CancellationToken ct)
            { ct.ThrowIfCancellationRequested(); Interlocked.Increment(ref calls); return ValueTask.FromResult<ReadOnlyMemory<byte>>(response); }
            await Assert.ThrowsAsync<InvalidDataException>(async () => await journal.GetOrIssueAsync(request.CanonicalBytes, scope, Issue, default));
            Assert.Equal(0, calls);
            await using (var provision = new NpgsqlCommand("INSERT INTO deep_did2_grant_journal_network " +
                "(network_id, entry_count, maximum_entries) VALUES ($1, 0, 2)", setup))
            { provision.Parameters.Add(new() { Value = request.Field(1).ToArray() }); await provision.ExecuteNonQueryAsync(); }
            await Assert.ThrowsAsync<IOException>(async () => await journal.GetOrIssueAsync(request.CanonicalBytes, scope,
                _ => throw new IOException("Injected signing interruption."), default));
            await using (var reserved = new NpgsqlCommand("SELECT entry_count FROM deep_did2_grant_journal_network", setup))
                Assert.Equal(1L, await reserved.ExecuteScalarAsync());
            await using (var hashes = new NpgsqlCommand("SELECT octet_length(request_hash), octet_length(scope_hash), exact_response " +
                "FROM deep_did2_grant_journal", setup))
            await using (var rows = await hashes.ExecuteReaderAsync())
            { Assert.True(await rows.ReadAsync()); Assert.Equal(32, rows.GetInt32(0)); Assert.Equal(32, rows.GetInt32(1)); Assert.True(rows.IsDBNull(2)); }
            await Assert.ThrowsAsync<CryptographicException>(async () => await journal.GetOrIssueAsync(request.CanonicalBytes, Bytes(32, 0x43), Issue, default));
            await Assert.ThrowsAsync<CryptographicException>(async () => await journal.GetOrIssueAsync(Request(0x41, 0x44).CanonicalBytes, scope, Issue, default));
            using var competing = new DeepIdV2PostgreSqlMailboxGrantJournal(scoped, request.Field(1).Span);
            var winners = await Task.WhenAll(Enumerable.Range(0, 8).Select(async index =>
                (await (index % 2 == 0 ? journal : competing).GetOrIssueAsync(request.CanonicalBytes, scope, Issue, default)).ToArray()));
            Assert.Equal(1, calls); Assert.All(winners, exact => Assert.Equal(response, exact));
            using var reopened = new DeepIdV2PostgreSqlMailboxGrantJournal(scoped, request.Field(1).Span);
            Assert.Equal(response, (await reopened.GetOrIssueAsync(request.CanonicalBytes, scope,
                _ => throw new InvalidOperationException("Winner replay cannot sign."), default)).ToArray());
            await Assert.ThrowsAsync<OperationCanceledException>(async () => await reopened.GetOrIssueAsync(Request(0x45).CanonicalBytes,
                scope, _ => throw new OperationCanceledException(), default));
            await Assert.ThrowsAsync<IOException>(async () => await reopened.GetOrIssueAsync(Request(0x46).CanonicalBytes, scope, Issue, default));
            Assert.Equal(1, calls);
            await using (var corrupt = new NpgsqlCommand("UPDATE deep_did2_grant_journal " +
                "SET exact_response = set_byte(exact_response, 0, 255) WHERE operation_id = $1", setup))
            { corrupt.Parameters.Add(new() { Value = request.Field(2).ToArray() }); Assert.Equal(1, await corrupt.ExecuteNonQueryAsync()); }
            await Assert.ThrowsAnyAsync<FormatException>(async () => await reopened.GetOrIssueAsync(request.CanonicalBytes, scope, Issue, default));
            Assert.Equal(1, calls);
        }
        finally
        {
            // Exact random schema created above inside the isolated test DB only.
            await using var cleanup = new NpgsqlCommand($"DROP SCHEMA \"{schema}\" CASCADE", admin); await cleanup.ExecuteNonQueryAsync();
        }
    }

    private static ContactRecord Request(byte operation, byte nonce = 0x51)
    {
        var holder = PublicKeyAuth.GenerateKeyPair(Bytes(32, 0x52));
        try
        {
            var reference = new byte[38]; "PMT2"u8.CopyTo(reference); BinaryPrimitives.WriteUInt16BigEndian(reference.AsSpan(4), 1);
            Bytes(32, 0x53).CopyTo(reference, 6);
            ReadOnlyMemory<byte>[] fields = [Bytes(16, 0x11), Bytes(32, operation), Bytes(32, 0x54), Bytes(32, 0x55),
                holder.PublicKey, new byte[] { 1 }, reference, Bytes(32, 0x56), U64(100), U64(220), Bytes(32, nonce), Bytes(64, 0x57)];
            var unsigned = ContactCodec.AuthorForOperationalAuthority("XMG1", fields);
            fields[11] = PublicKeyAuth.SignDetached(unsigned.SignatureInput.ToArray(), holder.PrivateKey);
            return ContactCodec.AuthorForOperationalAuthority("XMG1", fields);
        }
        finally { CryptographicOperations.ZeroMemory(holder.PrivateKey); }
    }
    private static byte[] Success(ContactRecord request)
    {
        var issuer = PublicKeyAuth.GenerateKeyPair(Bytes(32, 0x61));
        try
        {
            var unsigned = new MailboxAuthenticatedGrant
            {
                Domain = MailboxCapabilityDomain.Deposit, Lifecycle = MailboxCapabilityLifecycle.Active,
                NetworkId = request.Field(1), Epoch = 1, Generation = 1, Serial = Bytes(16, 0x62),
                NotBeforeUnixSeconds = 100, ExpiresAtUnixSeconds = 200, OverlapUntilUnixSeconds = 0,
                PlacementCommitment = Bytes(32, 0x63), MembershipCommitment = Bytes(32, 0x64),
                IssuerPublicKey = issuer.PublicKey, HolderPublicKey = request.Field(5), IssuerSignature = new byte[64],
            };
            var grant = new SodiumMailboxCapabilityCrypto().SignGrant(unsigned, issuer.PrivateKey);
            return ContactCodec.AuthorForOperationalAuthority("XMC1", [request.Field(1), request.Field(2), new byte[] { 0, 1 },
                U64(110), SHA256.HashData(request.CanonicalBytes.Span), U64(220), Bytes(32, 0x65),
                MailboxAuthenticatedCapabilityCodec.EncodeGrant(grant)]).CanonicalBytes.ToArray();
        }
        finally { CryptographicOperations.ZeroMemory(issuer.PrivateKey); }
    }
    private static byte[] Bytes(int count, byte value) => Enumerable.Repeat(value, count).ToArray();
    private static byte[] U64(ulong value) { var bytes = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(bytes, value); return bytes; }
}
#endif
