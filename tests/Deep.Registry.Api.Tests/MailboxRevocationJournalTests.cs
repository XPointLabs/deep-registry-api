#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.XPointNetworkV1;
using Deep.Registry.Api.DirectoryPublication;
using Npgsql;
using Sodium;
using Fixture = XNode.IntegrationTests.Runtime.DeepIdV2PublicationAuthorityFixture;

namespace Deep.Registry.Api.Tests;

/// <summary>Real local PostgreSQL plus actual signed DID2/network/PMA2 fixture.
/// No operator keys, live observer, external signer socket or device evidence.</summary>
public sealed class MailboxRevocationJournalTests
{
    [Theory]
    [InlineData(MailboxCapabilityDomain.Deposit)]
    [InlineData(MailboxCapabilityDomain.Retrieve)]
    public async Task ExactIntentIsDurableBeforeSignerAndRetryRetainsNewRevocationsForNextGeneration(MailboxCapabilityDomain role)
    {
        using var fixture = await Fixture.CreateAsync(); var host = await Host(fixture);
        await using var db = await Database.CreateAsync(host, role); using var signer = new Signer(role);
        byte[]? original = null;
        signer.Callback = async (input, token) =>
        {
            Assert.Equal(input.ToArray(), await db.InputAsync(1));
            Assert.Equal(0L, await db.ScalarAsync("SELECT committed_generation FROM deep_mailbox_revocation_scope"));
            Assert.Equal(1L, await db.ScalarAsync("SELECT entry_count FROM deep_mailbox_revocation_scope"));
            Assert.Equal(0L, await db.ScalarAsync("SELECT count(exact_snapshot) FROM deep_mailbox_revocation_snapshot"));
            original = input.ToArray(); token.ThrowIfCancellationRequested(); throw new IOException("Signer outage after actual durable reservation.");
        };
        using (var journal = db.Open())
            await Assert.ThrowsAsync<IOException>(() => journal.GetOrIssueNextAsync(host, [Serial(0x51)], signer).AsTask());
        Assert.NotNull(original); signer.Callback = null;
        ReadOnlyMemory<byte> first;
        using (var reopened = db.Open()) first = await reopened.GetOrIssueNextAsync(host, [Serial(0x52)], signer);
        Assert.Equal(1UL, MailboxGrantRevocationV1Codec.Decode(first.Span).Generation);
        Assert.Equal(original, signer.Inputs[1]); Assert.Equal(Serial(0x51), MailboxGrantRevocationV1Codec.Decode(first.Span).Field(11).ToArray());
        Assert.Equal(Serial(0x51).Concat(Serial(0x52)).ToArray(), await db.SerialsAsync());
        using var restored = db.Open();
        var next = await restored.GetOrIssueNextAsync(host, [], signer);
        var advance = await MailboxGrantRevocationV1Verifier.PlanAdvanceAsync(host, first, next);
        Assert.Equal(2UL, advance.Generation);
        Assert.Equal(Serial(0x51).Concat(Serial(0x52)).ToArray(), MailboxGrantRevocationV1Codec.Decode(next.Span).Field(11).ToArray());
        Assert.Equal(first.ToArray(), (await restored.ReadSignedStepAsync(host, 1)).ToArray());
        Assert.Equal(next.ToArray(), (await restored.ReadSignedStepAsync(host, 2)).ToArray());
    }

    [Theory]
    [InlineData(MailboxCapabilityDomain.Deposit)]
    [InlineData(MailboxCapabilityDomain.Retrieve)]
    public async Task ExpiredPendingReservationCompletesIdenticallyAsHistoryThenFreshSuccessor(MailboxCapabilityDomain role)
    {
        using var fixture = await Fixture.CreateAsync(); var host = await Host(fixture);
        await using var db = await Database.CreateAsync(host, role); using var signer = new Signer(role);
        var old = Snapshot(db.Scope, signer, expires: 1_080);
        var input = MailboxGrantRevocationV1Codec.Decode(old).SignatureInput;
        await db.SeedPendingAsync(input.ToArray(), Serial(0x51));
        using var journal = db.Open();
        var historical = await journal.GetOrIssueNextAsync(host, [Serial(0x52)], signer);
        Assert.Equal(input.ToArray(), Assert.Single(signer.Inputs)); Assert.Equal(old, historical.ToArray());
        await Assert.ThrowsAsync<CryptographicException>(() => MailboxGrantRevocationV1Verifier.PlanInitialEnrollmentAsync(host, historical).AsTask());
        var fresh = await journal.GetOrIssueNextAsync(host, [], signer);
        var plan = await MailboxGrantRevocationV1Verifier.PlanAdvanceAsync(host, historical, fresh);
        Assert.Equal(2UL, plan.Generation);
        Assert.Equal(Serial(0x51).Concat(Serial(0x52)).ToArray(), MailboxGrantRevocationV1Codec.Decode(fresh.Span).Field(11).ToArray());
        Assert.Equal(historical.ToArray(), (await journal.ReadSignedStepAsync(host, 1)).ToArray());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task WinnerWriteFailureOrCorruptionNeverLosesIntentOrReturnsUncheckedSuccess(bool corrupt)
    {
        using var fixture = await Fixture.CreateAsync(); var host = await Host(fixture);
        await using var db = await Database.CreateAsync(host, MailboxCapabilityDomain.Deposit);
        using var signer = new Signer(MailboxCapabilityDomain.Deposit);
        var effect = corrupt
            ? "NEW.exact_snapshot := set_byte(NEW.exact_snapshot, octet_length(NEW.exact_snapshot)-1, get_byte(NEW.exact_snapshot, octet_length(NEW.exact_snapshot)-1) # 1); RETURN NEW;"
            : "RAISE EXCEPTION 'Injected winner write interruption';";
        await db.ExecuteAsync("CREATE FUNCTION inject_winner() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN " + effect + " END $$; " +
            "CREATE TRIGGER inject_winner BEFORE UPDATE OF exact_snapshot ON deep_mailbox_revocation_snapshot FOR EACH ROW EXECUTE FUNCTION inject_winner();");
        using (var journal = db.Open())
        {
            if (corrupt) await Assert.ThrowsAsync<CryptographicException>(() => journal.GetOrIssueNextAsync(host, [], signer).AsTask());
            else await Assert.ThrowsAsync<PostgresException>(() => journal.GetOrIssueNextAsync(host, [], signer).AsTask());
        }
        var original = Assert.Single(signer.Inputs);
        Assert.Equal(original, await db.InputAsync(1));
        Assert.Equal(corrupt ? 1L : 0L, await db.ScalarAsync("SELECT committed_generation FROM deep_mailbox_revocation_scope"));
        await db.ExecuteAsync("DROP TRIGGER inject_winner ON deep_mailbox_revocation_snapshot; DROP FUNCTION inject_winner();");
        using var reopened = db.Open();
        if (corrupt)
        {
            await Assert.ThrowsAsync<CryptographicException>(() => reopened.ReadSignedStepAsync(host, 1).AsTask());
            await Assert.ThrowsAsync<CryptographicException>(() => reopened.GetOrIssueNextAsync(host, [], signer).AsTask());
            Assert.Single(signer.Inputs);
        }
        else
        {
            var winner = await reopened.GetOrIssueNextAsync(host, [], signer);
            Assert.Equal(1UL, MailboxGrantRevocationV1Codec.Decode(winner.Span).Generation);
            Assert.Equal(original, signer.Inputs[1]);
        }
    }

    [Fact]
    public async Task ConcurrentIndependentWritersKeepOneImmutableWinnerPerGenerationAndCumulativeLedger()
    {
        using var fixture = await Fixture.CreateAsync(); var host = await Host(fixture);
        await using var db = await Database.CreateAsync(host, MailboxCapabilityDomain.Deposit);
        using var signer = new Signer(MailboxCapabilityDomain.Deposit);
        using var first = db.Open(); using var second = db.Open();
        var results = await Task.WhenAll(first.GetOrIssueNextAsync(host, [Serial(0x51)], signer).AsTask(),
            second.GetOrIssueNextAsync(host, [Serial(0x52)], signer).AsTask());
        foreach (var group in results.GroupBy(row => MailboxGrantRevocationV1Codec.Decode(row.Span).Generation))
            Assert.All(group, row => Assert.Equal(group.First().ToArray(), row.ToArray()));
        Assert.Equal(signer.Inputs.Count, signer.Inputs.Select(bytes => Convert.ToHexString(SHA256.HashData(bytes))).Distinct().Count());
        var final = await first.GetOrIssueNextAsync(host, [], signer);
        Assert.Equal(Serial(0x51).Concat(Serial(0x52)).ToArray(), MailboxGrantRevocationV1Codec.Decode(final.Span).Field(11).ToArray());
        Assert.Equal(signer.Inputs.Count, await db.ScalarAsync("SELECT count(*) FROM deep_mailbox_revocation_snapshot"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CorruptPendingPredecessorOrSerialRemovalRejectsBeforeExternalSigner(bool removed)
    {
        using var fixture = await Fixture.CreateAsync(); var host = await Host(fixture);
        await using var db = await Database.CreateAsync(host, MailboxCapabilityDomain.Deposit);
        using var signer = new Signer(MailboxCapabilityDomain.Deposit); using var journal = db.Open();
        var first = await journal.GetOrIssueNextAsync(host, [Serial(0x51)], signer);
        var wrong = Snapshot(db.Scope, signer, expires: 1_120, generation: 2,
            predecessor: removed ? MailboxGrantRevocationV1Codec.Decode(first.Span).CoreHash.ToArray() : Enumerable.Repeat((byte)0xf1, 32).ToArray(),
            issued: 1_095, serials: removed ? [] : [Serial(0x51)]);
        var exactInput = MailboxGrantRevocationV1Codec.Decode(wrong).SignatureInput.ToArray();
        await db.SeedPendingAsync(exactInput, Serial(0x51), generation: 2);
        var error = await Assert.ThrowsAsync<CryptographicException>(() => journal.GetOrIssueNextAsync(host, [], signer).AsTask());
        Assert.Contains(removed ? "removed" : "predecessor", error.Message, StringComparison.Ordinal);
        Assert.Single(signer.Inputs); Assert.Equal(exactInput, await db.InputAsync(2));
        Assert.Equal(1L, await db.ScalarAsync("SELECT committed_generation FROM deep_mailbox_revocation_scope"));
        Assert.Equal(2L, await db.ScalarAsync("SELECT entry_count FROM deep_mailbox_revocation_scope"));
    }

    [Fact]
    public async Task MissingRootOrHistoryRejectsBeforeSigningWithoutRepair()
    {
        using var fixture = await Fixture.CreateAsync(); var host = await Host(fixture);
        await using var db = await Database.CreateAsync(host, MailboxCapabilityDomain.Deposit);
        using var signer = new Signer(MailboxCapabilityDomain.Deposit);
        await db.ExecuteAsync("DELETE FROM deep_mailbox_revocation_scope;");
        using var journal = db.Open();
        await Assert.ThrowsAsync<InvalidDataException>(() => journal.GetOrIssueNextAsync(host, [], signer).AsTask());
        Assert.Empty(signer.Inputs); await db.ProvisionAsync(8);
        await journal.GetOrIssueNextAsync(host, [], signer);
        await db.ExecuteAsync("DELETE FROM deep_mailbox_revocation_snapshot;");
        await Assert.ThrowsAsync<InvalidDataException>(() => journal.GetOrIssueNextAsync(host, [], signer).AsTask());
        Assert.Single(signer.Inputs);
        Assert.Equal(1L, await db.ScalarAsync("SELECT entry_count FROM deep_mailbox_revocation_scope"));
    }

    [Fact]
    public async Task LostPendingRevocationLedgerCannotBeSilentlyRepairedByNewInputBeforeSigning()
    {
        using var fixture = await Fixture.CreateAsync(); var host = await Host(fixture);
        await using var db = await Database.CreateAsync(host, MailboxCapabilityDomain.Deposit);
        using var signer = new Signer(MailboxCapabilityDomain.Deposit);
        signer.Callback = (_, _) => throw new IOException("Interrupted external signer.");
        using var journal = db.Open();
        await Assert.ThrowsAsync<IOException>(() => journal.GetOrIssueNextAsync(host, [Serial(0x51)], signer).AsTask());
        await db.ExecuteAsync("UPDATE deep_mailbox_revocation_scope SET cumulative_serials = ''::bytea;");
        signer.Callback = null;
        await Assert.ThrowsAsync<InvalidDataException>(() => journal.GetOrIssueNextAsync(host, [Serial(0x51)], signer).AsTask());
        Assert.Single(signer.Inputs); Assert.Empty(await db.SerialsAsync());
        Assert.Equal(signer.Inputs[0], await db.InputAsync(1));
        Assert.Equal(0L, await db.ScalarAsync("SELECT committed_generation FROM deep_mailbox_revocation_scope"));
    }

    [Fact]
    public async Task ForeignProvisionedIssuerScopeDoesNotAuthorizeAReservationOrSignerCallback()
    {
        using var fixture = await Fixture.CreateAsync(); var host = await Host(fixture);
        await using var db = await Database.CreateAsync(host, MailboxCapabilityDomain.Deposit);
        using var signer = new Signer(MailboxCapabilityDomain.Deposit);
        var foreign = Enumerable.Repeat((byte)0x99, 32).ToArray();
        await db.ExecuteAsync("UPDATE deep_mailbox_revocation_scope SET issuer_key = $1", foreign);
        using var journal = db.Open(foreign);
        await Assert.ThrowsAsync<CryptographicException>(() => journal.GetOrIssueNextAsync(host, [], signer).AsTask());
        Assert.Empty(signer.Inputs);
        Assert.Equal(0L, await db.ScalarAsync("SELECT entry_count FROM deep_mailbox_revocation_scope"));
        Assert.Equal(0L, await db.ScalarAsync("SELECT count(*) FROM deep_mailbox_revocation_snapshot"));
    }

    [Fact]
    public async Task SnapshotAndSerialCapacityBackpressureNeverEvictsOrSignsOversizeLedger()
    {
        using var fixture = await Fixture.CreateAsync(); var host = await Host(fixture);
        await using var db = await Database.CreateAsync(host, MailboxCapabilityDomain.Deposit, maximum: 1);
        using var signer = new Signer(MailboxCapabilityDomain.Deposit); using var journal = db.Open();
        var rows = Enumerable.Range(1, 4_096).Select(index =>
        {
            var bytes = new byte[16]; BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(12), (uint)index); return (ReadOnlyMemory<byte>)bytes;
        }).ToArray();
        var exact = await journal.GetOrIssueNextAsync(host, rows, signer);
        Assert.Equal(65_824, Assert.Single(signer.Inputs).Length);
        Assert.Equal(65_863, exact.Length);
        await Assert.ThrowsAsync<IOException>(() => journal.GetOrIssueNextAsync(host, [], signer).AsTask());
        await Assert.ThrowsAsync<IOException>(() => journal.GetOrIssueNextAsync(host, [Serial(0xff)], signer).AsTask());
        Assert.Single(signer.Inputs); Assert.Equal(exact.ToArray(), (await journal.ReadSignedStepAsync(host, 1)).ToArray());
        Assert.Equal(65_536, (await db.SerialsAsync()).Length);
    }

    [Fact]
    public async Task RetainedSignedHistoryBeyond64GenerationsRemainsAvailableOneRecordAtATime()
    {
        using var fixture = await Fixture.CreateAsync(); var host = await Host(fixture);
        await using var db = await Database.CreateAsync(host, MailboxCapabilityDomain.Retrieve, maximum: 70);
        using var signer = new Signer(MailboxCapabilityDomain.Retrieve);
        ReadOnlyMemory<byte> prior = ReadOnlyMemory<byte>.Empty;
        for (ulong generation = 1; generation <= 70; generation++)
        {
            using var writer = db.Open(); var exact = await writer.GetOrIssueNextAsync(host, [], signer);
            Assert.Equal(generation, MailboxGrantRevocationV1Codec.Decode(exact.Span).Generation);
            if (!prior.IsEmpty) _ = await MailboxGrantRevocationV1Verifier.PlanCatchUpSuccessorAsync(host, prior, exact);
            prior = exact;
        }
        using var reader = db.Open();
        for (ulong generation = 1; generation <= 70; generation++)
            Assert.Equal(generation, MailboxGrantRevocationV1Codec.Decode((await reader.ReadSignedStepAsync(host, generation)).Span).Generation);
        await Assert.ThrowsAsync<IOException>(() => reader.GetOrIssueNextAsync(host, [], signer).AsTask());
        Assert.Equal(70, signer.Inputs.Count);
    }

    private static ValueTask<VerifiedMailboxHostAuthorityV2> Host(Fixture fixture) =>
        MailboxHostAuthorityV2Verifier.VerifyAsync(fixture.NetworkContext, fixture.Authority, fixture.MailboxAuthority, new(fixture));
    private static byte[] Serial(byte marker) => Enumerable.Repeat(marker, 16).ToArray();
    private static byte[] U64(ulong value) { var bytes = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(bytes, value); return bytes; }
    private static byte[] Snapshot(PreparedMailboxGrantRevocationV1 scope, Signer signer, ulong expires,
        ulong generation = 1, byte[]? predecessor = null, ulong issued = 1_000, byte[][]? serials = null)
    {
        serials ??= [Serial(0x51)];
        var count = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(count, (uint)serials.Length);
        ReadOnlyMemory<byte>[] fields = [scope.NetworkId, scope.PolicyReference, new byte[] { (byte)scope.Domain }, scope.IssuerPublicKey,
            U64(generation), predecessor ?? new byte[32], U64(issued), U64(issued), U64(expires), count, serials.SelectMany(row => row).ToArray()];
        return MailboxGrantRevocationV1Codec.Encode(fields, signer.Sign(MailboxGrantRevocationV1Codec.CreateSignatureInput(fields)));
    }
    private sealed class Signer : IMailboxGrantIssuerSigner, IDisposable
    {
        private readonly KeyPair key;
        internal readonly List<byte[]> Inputs = [];
        internal Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask>? Callback;
        internal Signer(MailboxCapabilityDomain role) => key = PublicKeyAuth.GenerateKeyPair(Enumerable.Repeat(
            role == MailboxCapabilityDomain.Deposit ? (byte)0x31 : (byte)0x32, 32).ToArray());
        public ReadOnlyMemory<byte> Ed25519PublicKey => key.PublicKey.ToArray();
        public async ValueTask<ReadOnlyMemory<byte>> SignAsync(ReadOnlyMemory<byte> input, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested(); Inputs.Add(input.ToArray());
            if (Callback is { } callback) await callback(input, ct);
            ct.ThrowIfCancellationRequested(); return Sign(input.ToArray());
        }
        internal byte[] Sign(byte[] input) => PublicKeyAuth.SignDetached(input, key.PrivateKey);
        public void Dispose() => CryptographicOperations.ZeroMemory(key.PrivateKey);
    }
    private sealed class Database : IAsyncDisposable
    {
        private readonly NpgsqlConnection admin;
        private readonly string schema, connection;
        internal PreparedMailboxGrantRevocationV1 Scope { get; }
        private Database(NpgsqlConnection admin, string schema, string connection, PreparedMailboxGrantRevocationV1 scope)
        { this.admin = admin; this.schema = schema; this.connection = connection; Scope = scope; }
        internal static async Task<Database> CreateAsync(VerifiedMailboxHostAuthorityV2 host, MailboxCapabilityDomain role, int maximum = 8)
        {
            var connection = Environment.GetEnvironmentVariable("DEEP_TEST_DID2_GRANT_POSTGRES");
            Assert.False(string.IsNullOrWhiteSpace(connection), "Use the isolated DevOps PostgreSQL wrapper.");
            var settings = new NpgsqlConnectionStringBuilder(connection);
            Assert.Equal("127.0.0.1", settings.Host); Assert.Equal("deep_s00", settings.Database); Assert.Equal("deep_s00", settings.Username);
            var scope = await MailboxGrantRevocationV1Author.PrepareCurrentAsync(host, role, ReadOnlyMemory<byte>.Empty, []);
            var schema = "s05_mgr1_test_" + Guid.NewGuid().ToString("N");
            var admin = new NpgsqlConnection(connection); await admin.OpenAsync();
            await using (var create = new NpgsqlCommand($"CREATE SCHEMA \"{schema}\"", admin)) await create.ExecuteNonQueryAsync();
            var database = new Database(admin, schema, new NpgsqlConnectionStringBuilder(connection) { SearchPath = schema }.ConnectionString, scope);
            try
            {
                await database.ExecuteAsync(await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "Fixtures", "mailbox-revocation-journal.sql")));
                await database.ProvisionAsync(maximum); return database;
            }
            catch { await database.DisposeAsync(); throw; }
        }
        internal MailboxRevocationJournal Open(byte[]? issuer = null) => new(connection, Scope.NetworkId.Span, Scope.PolicyReference.Span, Scope.Domain, issuer ?? Scope.IssuerPublicKey.ToArray());
        internal async Task ProvisionAsync(int maximum)
        {
            await using var target = new NpgsqlConnection(connection); await target.OpenAsync();
            await using var command = new NpgsqlCommand("INSERT INTO deep_mailbox_revocation_scope VALUES ($1,$2,$3,$4,0,0,$5,$6)", target);
            foreach (var value in new object[] { Scope.NetworkId.ToArray(), Scope.PolicyReference.ToArray(), (short)Scope.Domain, Scope.IssuerPublicKey.ToArray(), (long)maximum, Array.Empty<byte>() }) command.Parameters.Add(new() { Value = value });
            await command.ExecuteNonQueryAsync();
        }
        internal async Task SeedPendingAsync(byte[] input, byte[] serials, long generation = 1)
        {
            await using var target = new NpgsqlConnection(connection); await target.OpenAsync();
            await using var transaction = await target.BeginTransactionAsync();
            await using var insert = new NpgsqlCommand("INSERT INTO deep_mailbox_revocation_snapshot SELECT network_id, policy_reference, role, issuer_key, $2, $1, NULL FROM deep_mailbox_revocation_scope", target, transaction);
            insert.Parameters.Add(new() { Value = input }); insert.Parameters.Add(new() { Value = generation }); await insert.ExecuteNonQueryAsync();
            await using var update = new NpgsqlCommand("UPDATE deep_mailbox_revocation_scope SET entry_count = $2, cumulative_serials = $1", target, transaction);
            update.Parameters.Add(new() { Value = serials }); update.Parameters.Add(new() { Value = generation }); await update.ExecuteNonQueryAsync(); await transaction.CommitAsync();
        }
        internal async Task ExecuteAsync(string sql, params object[] values)
        {
            await using var target = new NpgsqlConnection(connection); await target.OpenAsync(); await using var command = new NpgsqlCommand(sql, target);
            foreach (var value in values) command.Parameters.Add(new() { Value = value });
            await command.ExecuteNonQueryAsync();
        }
        internal async Task<long> ScalarAsync(string sql)
        { await using var target = new NpgsqlConnection(connection); await target.OpenAsync(); await using var command = new NpgsqlCommand(sql, target); return Convert.ToInt64(await command.ExecuteScalarAsync()); }
        internal async Task<byte[]> InputAsync(long generation)
        {
            await using var target = new NpgsqlConnection(connection); await target.OpenAsync();
            await using var command = new NpgsqlCommand("SELECT signing_input FROM deep_mailbox_revocation_snapshot WHERE generation = $1", target);
            command.Parameters.Add(new() { Value = generation }); return (byte[])(await command.ExecuteScalarAsync())!;
        }
        internal async Task<byte[]> SerialsAsync()
        { await using var target = new NpgsqlConnection(connection); await target.OpenAsync(); await using var command = new NpgsqlCommand("SELECT cumulative_serials FROM deep_mailbox_revocation_scope", target); return (byte[])(await command.ExecuteScalarAsync())!; }
        public async ValueTask DisposeAsync()
        { await using var drop = new NpgsqlCommand($"DROP SCHEMA \"{schema}\" CASCADE", admin); await drop.ExecuteNonQueryAsync(); await admin.DisposeAsync(); }
    }
}
#endif
