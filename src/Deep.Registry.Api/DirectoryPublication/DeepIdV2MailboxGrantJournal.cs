#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.Registry;
using Npgsql;

namespace Deep.Registry.Api.DirectoryPublication;

internal interface IDeepIdV2MailboxGrantJournal
{
    ValueTask<ReadOnlyMemory<byte>> GetOrIssueAsync(ReadOnlyMemory<byte> exactXmg1,
        ReadOnlyMemory<byte> scopeHash, Func<CancellationToken, ValueTask<ReadOnlyMemory<byte>>> issue,
        CancellationToken cancellationToken);
}

/// <summary>Permanent hash-only reservations and exact winners in the independent
/// restore-authority DB. No schema creation, root initialization or deletion.</summary>
internal sealed class DeepIdV2PostgreSqlMailboxGrantJournal : IDeepIdV2MailboxGrantJournal, IDisposable
{
    private readonly NpgsqlDataSource source;
    private readonly byte[] network;
    internal DeepIdV2PostgreSqlMailboxGrantJournal(string connectionString, ReadOnlySpan<byte> networkId)
    {
        if (string.IsNullOrWhiteSpace(connectionString) || networkId.Length != 16 || networkId.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("DID2 grant journal configuration is invalid.");
        network = networkId.ToArray(); source = NpgsqlDataSource.Create(connectionString);
    }

    public async ValueTask<ReadOnlyMemory<byte>> GetOrIssueAsync(ReadOnlyMemory<byte> exactXmg1,
        ReadOnlyMemory<byte> scopeHash, Func<CancellationToken, ValueTask<ReadOnlyMemory<byte>>> issue, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(issue); ct.ThrowIfCancellationRequested();
        if (exactXmg1.Length != 435 || scopeHash.Length != 32 || scopeHash.Span.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("DID2 grant journal requires exact bounded request/scope.");
        var request = ContactCodec.Decode("XMG1", exactXmg1.Span);
        ContactCodec.VerifyMailboxGrantHolderSignature(request);
        if (!Fixed(network, request.Field(1).Span)) throw new CryptographicException("Grant journal network differs.");
        var operation = request.Field(2).ToArray();
        var hash = SHA256.HashData(request.CanonicalBytes.Span); var scope = scopeHash.ToArray();
        await using (var connection = await source.OpenConnectionAsync(ct).ConfigureAwait(false))
        await using (var transaction = await connection.BeginTransactionAsync(ct).ConfigureAwait(false))
        {
            var capacity = await LockNetworkAsync(connection, transaction, ct).ConfigureAwait(false);
            var retained = await ReadAsync(connection, transaction, operation, ct).ConfigureAwait(false);
            if (retained is not null) RequireScope(retained.Value, hash, scope);
            else
            {
                if (capacity.Count >= capacity.Maximum) throw new IOException("DID2 grant journal capacity is exhausted.");
                await using var insert = new NpgsqlCommand("INSERT INTO deep_did2_grant_journal " +
                    "(network_id, operation_id, request_hash, scope_hash) VALUES ($1, $2, $3, $4)", connection, transaction);
                Add(insert, network, operation, hash, scope);
                if (await insert.ExecuteNonQueryAsync(ct).ConfigureAwait(false) != 1)
                    throw new InvalidDataException("Grant reservation was not committed.");
                await using var count = new NpgsqlCommand("UPDATE deep_did2_grant_journal_network " +
                    "SET entry_count = entry_count + 1 WHERE network_id = $1", connection, transaction);
                Add(count, network);
                if (await count.ExecuteNonQueryAsync(ct).ConfigureAwait(false) != 1)
                    throw new InvalidDataException("Grant capacity reservation was not committed.");
            }
            await transaction.CommitAsync(ct).ConfigureAwait(false);
        }
        byte[] expected;
        await using (var connection = await source.OpenConnectionAsync(ct).ConfigureAwait(false))
        await using (var transaction = await connection.BeginTransactionAsync(ct).ConfigureAwait(false))
        {
            _ = await LockNetworkAsync(connection, transaction, ct).ConfigureAwait(false);
            var retained = await ReadAsync(connection, transaction, operation, ct).ConfigureAwait(false)
                ?? throw new InvalidDataException("Durable grant reservation disappeared.");
            RequireScope(retained, hash, scope);
            if (retained.Winner is { } winner) expected = winner;
            else
            {
                // Cross-process exclusion remains held across the signing callback.
                var candidate = await issue(ct).ConfigureAwait(false);
                if (candidate.Length != 510) throw new InvalidDataException("Grant journal requires a bounded exact winner.");
                expected = candidate.ToArray();
                RequireWinner(request, expected);
                await using var update = new NpgsqlCommand("UPDATE deep_did2_grant_journal SET exact_response = $3 " +
                    "WHERE network_id = $1 AND operation_id = $2 AND request_hash = $4 AND scope_hash = $5 " +
                    "AND exact_response IS NULL", connection, transaction);
                Add(update, network, operation, expected, hash, scope);
                if (await update.ExecuteNonQueryAsync(ct).ConfigureAwait(false) != 1)
                    throw new InvalidDataException("Grant winner compare/exchange failed.");
            }
            RequireWinner(request, expected);
            await transaction.CommitAsync(ct).ConfigureAwait(false);
        }
        await using var readback = await source.OpenConnectionAsync(ct).ConfigureAwait(false);
        var exact = await ReadAsync(readback, null, operation, ct).ConfigureAwait(false)
            ?? throw new InvalidDataException("Committed grant winner disappeared.");
        RequireScope(exact, hash, scope);
        if (exact.Winner is null || !Fixed(exact.Winner, expected))
            throw new InvalidDataException("Committed grant winner did not read back exactly.");
        RequireWinner(request, exact.Winner); ct.ThrowIfCancellationRequested(); return exact.Winner;
    }

    private async ValueTask<(long Count, long Maximum)> LockNetworkAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("SELECT entry_count, maximum_entries FROM " +
            "deep_did2_grant_journal_network WHERE network_id = $1 FOR UPDATE", connection, transaction);
        Add(command, network);
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        if (!await reader.ReadAsync(ct).ConfigureAwait(false)) throw new InvalidDataException("Grant journal network is not provisioned.");
        var count = reader.GetInt64(0); var maximum = reader.GetInt64(1);
        if (maximum is < 1 or > 1_048_576 || count < 0 || count > maximum) throw new InvalidDataException("Grant journal capacity is corrupt.");
        return (count, maximum);
    }
    private async ValueTask<(byte[] Request, byte[] Scope, byte[]? Winner)?> ReadAsync(NpgsqlConnection connection,
        NpgsqlTransaction? transaction, byte[] operation, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("SELECT request_hash, scope_hash, exact_response " +
            "FROM deep_did2_grant_journal WHERE network_id = $1 AND operation_id = $2", connection, transaction);
        Add(command, network, operation);
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        if (!await reader.ReadAsync(ct).ConfigureAwait(false)) return null;
        var request = reader.GetFieldValue<byte[]>(0); var scope = reader.GetFieldValue<byte[]>(1);
        var winner = reader.IsDBNull(2) ? null : reader.GetFieldValue<byte[]>(2);
        if (request.Length != 32 || scope.Length != 32 || request.AsSpan().IndexOfAnyExcept((byte)0) < 0 ||
            scope.AsSpan().IndexOfAnyExcept((byte)0) < 0 || winner is not null && winner.Length != 510)
            throw new InvalidDataException("Grant journal row is malformed.");
        return (request, scope, winner);
    }
    private static void RequireScope((byte[] Request, byte[] Scope, byte[]? Winner) retained, byte[] hash, byte[] scope)
    { if (!Fixed(retained.Request, hash) || !Fixed(retained.Scope, scope)) throw new CryptographicException("Grant operation has conflicting immutable scope."); }
    private static void RequireWinner(ContactRecord request, byte[] exact)
    {
        if (exact.Length != 510) throw new InvalidDataException("Grant journal cannot retain a non-success.");
        ContactCodec.ValidateMailboxGrantResultBinding(request, ContactCodec.Decode(DeepProtocolIdentifiers.Magic.XMC2, exact));
    }
    private static bool Fixed(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) => a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
    private static void Add(NpgsqlCommand command, params byte[][] values)
    { foreach (var value in values) command.Parameters.Add(new() { Value = value }); }
    public void Dispose() { source.Dispose(); CryptographicOperations.ZeroMemory(network); }
}
#endif
