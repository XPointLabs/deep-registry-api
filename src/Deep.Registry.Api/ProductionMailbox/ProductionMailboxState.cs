using System.Data;
using System.Text.Json;
using Npgsql;

namespace Deep.Registry.Api.ProductionMailbox;

public sealed record ProductionMailboxChallengeState(
    byte[] ChallengeId,
    byte[] Challenge,
    ulong ExpiresAtUnixSeconds);

public sealed record ProductionMailboxIssuanceState(
    byte[] IdempotencyKey,
    byte[] CanonicalResponse,
    bool Replayed);

public interface IProductionMailboxStateStore
{
    ValueTask<ProductionMailboxChallengeState?> CreateChallengeAsync(
        ulong nowUnixSeconds,
        ulong expiresAtUnixSeconds,
        int maximumChallenges,
        ulong windowStartUnixSeconds,
        CancellationToken cancellationToken);

    ValueTask<ProductionMailboxIssuanceState?> ConsumeChallengeAndIssueAsync(
        ReadOnlyMemory<byte> challengeId,
        ReadOnlyMemory<byte> expectedChallenge,
        ulong nowUnixSeconds,
        ulong issuanceExpiresAtUnixSeconds,
        ReadOnlyMemory<byte> idempotencyKey,
        Func<CancellationToken, ValueTask<byte[]>> createCanonicalResponse,
        CancellationToken cancellationToken);

    ValueTask<bool> IsHolderRevokedAsync(ReadOnlyMemory<byte> holderHash, CancellationToken cancellationToken);
    ValueTask RevokeHolderAsync(ReadOnlyMemory<byte> holderHash, ulong nowUnixSeconds, CancellationToken cancellationToken);
}

public sealed class InMemoryProductionMailboxStateStore : IProductionMailboxStateStore
{
    private readonly SemaphoreSlim gate = new(1, 1);
    private readonly Dictionary<string, ChallengeRecord> challenges = new(StringComparer.Ordinal);
    private readonly Dictionary<string, IssuanceRecord> issuances = new(StringComparer.Ordinal);
    private readonly HashSet<string> revokedHolders = new(StringComparer.Ordinal);
    private readonly List<ulong> challengeTimes = [];

    public async ValueTask<ProductionMailboxChallengeState?> CreateChallengeAsync(
        ulong nowUnixSeconds, ulong expiresAtUnixSeconds, int maximumChallenges,
        ulong windowStartUnixSeconds, CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try
        {
            challengeTimes.RemoveAll(value => value < windowStartUnixSeconds);
            if (challengeTimes.Count >= maximumChallenges) return null;
            var id = System.Security.Cryptography.RandomNumberGenerator.GetBytes(16);
            var challenge = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
            challenges[Convert.ToHexString(id)] = new ChallengeRecord(challenge, expiresAtUnixSeconds, false);
            challengeTimes.Add(nowUnixSeconds);
            return new(id, challenge, expiresAtUnixSeconds);
        }
        finally { gate.Release(); }
    }

    public async ValueTask<ProductionMailboxIssuanceState?> ConsumeChallengeAndIssueAsync(
        ReadOnlyMemory<byte> challengeId, ReadOnlyMemory<byte> expectedChallenge,
        ulong nowUnixSeconds, ulong issuanceExpiresAtUnixSeconds, ReadOnlyMemory<byte> idempotencyKey,
        Func<CancellationToken, ValueTask<byte[]>> createCanonicalResponse,
        CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try
        {
            var challengeKey = Convert.ToHexString(challengeId.Span);
            if (!challenges.TryGetValue(challengeKey, out var challenge) || challenge.Used ||
                challenge.ExpiresAtUnixSeconds < nowUnixSeconds ||
                !System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(
                    challenge.Challenge, expectedChallenge.Span)) return null;
            challenges[challengeKey] = challenge with { Used = true };
            var key = Convert.ToHexString(idempotencyKey.Span);
            if (issuances.TryGetValue(key, out var existing) && existing.ExpiresAtUnixSeconds >= nowUnixSeconds)
                return new(idempotencyKey.ToArray(), existing.Response.ToArray(), true);
            var created = await createCanonicalResponse(cancellationToken);
            issuances[key] = new(created.ToArray(), issuanceExpiresAtUnixSeconds);
            return new(idempotencyKey.ToArray(), created, false);
        }
        finally { gate.Release(); }
    }

    public async ValueTask<bool> IsHolderRevokedAsync(ReadOnlyMemory<byte> holderHash, CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try { return revokedHolders.Contains(Convert.ToHexString(holderHash.Span)); }
        finally { gate.Release(); }
    }

    public async ValueTask RevokeHolderAsync(ReadOnlyMemory<byte> holderHash, ulong nowUnixSeconds, CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken);
        try { revokedHolders.Add(Convert.ToHexString(holderHash.Span)); }
        finally { gate.Release(); }
    }

    private sealed record ChallengeRecord(byte[] Challenge, ulong ExpiresAtUnixSeconds, bool Used);
    private sealed record IssuanceRecord(byte[] Response, ulong ExpiresAtUnixSeconds);
}

public sealed class PostgreSqlProductionMailboxStateStore(string connectionString)
    : IProductionMailboxStateStore
{
    private readonly SemaphoreSlim initializeGate = new(1, 1);
    private volatile bool initialized;

    public async ValueTask<ProductionMailboxChallengeState?> CreateChallengeAsync(
        ulong nowUnixSeconds, ulong expiresAtUnixSeconds, int maximumChallenges,
        ulong windowStartUnixSeconds, CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken);
        await using (var cleanup = new NpgsqlCommand(
            "DELETE FROM production_mailbox_challenges WHERE expires_at < @now", connection, transaction))
        {
            cleanup.Parameters.AddWithValue("now", checked((long)nowUnixSeconds));
            await cleanup.ExecuteNonQueryAsync(cancellationToken);
        }
        await using var count = new NpgsqlCommand(
            "SELECT count(*) FROM production_mailbox_challenges WHERE created_at >= @window", connection, transaction);
        count.Parameters.AddWithValue("window", checked((long)windowStartUnixSeconds));
        if ((long)(await count.ExecuteScalarAsync(cancellationToken) ?? 0L) >= maximumChallenges) return null;
        var id = System.Security.Cryptography.RandomNumberGenerator.GetBytes(16);
        var challenge = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
        await using var insert = new NpgsqlCommand(
            "INSERT INTO production_mailbox_challenges(challenge_id, challenge, created_at, expires_at, used) VALUES(@id,@challenge,@now,@expires,false)",
            connection, transaction);
        insert.Parameters.AddWithValue("id", id); insert.Parameters.AddWithValue("challenge", challenge);
        insert.Parameters.AddWithValue("now", checked((long)nowUnixSeconds));
        insert.Parameters.AddWithValue("expires", checked((long)expiresAtUnixSeconds));
        await insert.ExecuteNonQueryAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return new(id, challenge, expiresAtUnixSeconds);
    }

    public async ValueTask<ProductionMailboxIssuanceState?> ConsumeChallengeAndIssueAsync(
        ReadOnlyMemory<byte> challengeId, ReadOnlyMemory<byte> expectedChallenge,
        ulong nowUnixSeconds, ulong issuanceExpiresAtUnixSeconds, ReadOnlyMemory<byte> idempotencyKey,
        Func<CancellationToken, ValueTask<byte[]>> createCanonicalResponse,
        CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken);
        await using (var cleanup = new NpgsqlCommand(
            "DELETE FROM production_mailbox_issuances WHERE expires_at < @now; DELETE FROM production_mailbox_challenges WHERE expires_at < @now",
            connection, transaction))
        {
            cleanup.Parameters.AddWithValue("now", checked((long)nowUnixSeconds));
            await cleanup.ExecuteNonQueryAsync(cancellationToken);
        }
        await using var consume = new NpgsqlCommand(
            "UPDATE production_mailbox_challenges SET used=true WHERE challenge_id=@id AND challenge=@challenge AND used=false AND expires_at>=@now",
            connection, transaction);
        consume.Parameters.AddWithValue("id", challengeId.ToArray());
        consume.Parameters.AddWithValue("challenge", expectedChallenge.ToArray());
        consume.Parameters.AddWithValue("now", checked((long)nowUnixSeconds));
        if (await consume.ExecuteNonQueryAsync(cancellationToken) != 1) return null;
        await using var issuanceLock = new NpgsqlCommand(
            "SELECT pg_advisory_xact_lock(hashtextextended(encode(@key,'hex'),0))", connection, transaction);
        issuanceLock.Parameters.AddWithValue("key", idempotencyKey.ToArray());
        await issuanceLock.ExecuteNonQueryAsync(cancellationToken);
        await using var select = new NpgsqlCommand(
            "SELECT response FROM production_mailbox_issuances WHERE idempotency_key=@key", connection, transaction);
        select.Parameters.AddWithValue("key", idempotencyKey.ToArray());
        var existing = await select.ExecuteScalarAsync(cancellationToken) as byte[];
        if (existing is not null)
        {
            await transaction.CommitAsync(cancellationToken);
            return new(idempotencyKey.ToArray(), existing, true);
        }
        var created = await createCanonicalResponse(cancellationToken);
        await using var insert = new NpgsqlCommand(
            "INSERT INTO production_mailbox_issuances(idempotency_key,response,issued_at,expires_at) VALUES(@key,@response,@now,@expires)",
            connection, transaction);
        insert.Parameters.AddWithValue("key", idempotencyKey.ToArray());
        insert.Parameters.AddWithValue("response", created);
        insert.Parameters.AddWithValue("now", checked((long)nowUnixSeconds));
        insert.Parameters.AddWithValue("expires", checked((long)issuanceExpiresAtUnixSeconds));
        await insert.ExecuteNonQueryAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return new(idempotencyKey.ToArray(), created, false);
    }

    public async ValueTask<bool> IsHolderRevokedAsync(ReadOnlyMemory<byte> holderHash, CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = new NpgsqlCommand(
            "SELECT EXISTS(SELECT 1 FROM production_mailbox_revoked_holders WHERE holder_hash=@hash)", connection);
        command.Parameters.AddWithValue("hash", holderHash.ToArray());
        return (bool)(await command.ExecuteScalarAsync(cancellationToken) ?? false);
    }

    public async ValueTask RevokeHolderAsync(ReadOnlyMemory<byte> holderHash, ulong nowUnixSeconds, CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = new NpgsqlCommand(
            "INSERT INTO production_mailbox_revoked_holders(holder_hash,revoked_at) VALUES(@hash,@now) ON CONFLICT(holder_hash) DO NOTHING", connection);
        command.Parameters.AddWithValue("hash", holderHash.ToArray());
        command.Parameters.AddWithValue("now", checked((long)nowUnixSeconds));
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private async ValueTask<NpgsqlConnection> OpenAsync(CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(connectionString))
            throw new InvalidOperationException("Production mailbox PostgreSQL connection string is missing.");
        var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync(cancellationToken);
        if (!initialized) await InitializeAsync(connection, cancellationToken);
        return connection;
    }

    private async Task InitializeAsync(NpgsqlConnection connection, CancellationToken cancellationToken)
    {
        await initializeGate.WaitAsync(cancellationToken);
        try
        {
            if (initialized) return;
            const string sql = """
                CREATE TABLE IF NOT EXISTS production_mailbox_challenges(
                    challenge_id bytea PRIMARY KEY, challenge bytea NOT NULL, created_at bigint NOT NULL,
                    expires_at bigint NOT NULL, used boolean NOT NULL);
                CREATE INDEX IF NOT EXISTS ix_production_mailbox_challenges_created_at
                    ON production_mailbox_challenges(created_at);
                CREATE TABLE IF NOT EXISTS production_mailbox_issuances(
                    idempotency_key bytea PRIMARY KEY, response bytea NOT NULL, issued_at bigint NOT NULL,
                    expires_at bigint NOT NULL);
                CREATE TABLE IF NOT EXISTS production_mailbox_revoked_holders(
                    holder_hash bytea PRIMARY KEY, revoked_at bigint NOT NULL);
                """;
            await using var command = new NpgsqlCommand(sql, connection);
            await command.ExecuteNonQueryAsync(cancellationToken);
            initialized = true;
        }
        finally { initializeGate.Release(); }
    }
}
