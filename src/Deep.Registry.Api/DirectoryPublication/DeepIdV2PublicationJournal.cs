#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Npgsql;

namespace Deep.Registry.Api.DirectoryPublication;

internal interface IDeepIdV2PublicationJournal
{
    ValueTask<ReadOnlyMemory<byte>> GetOrIssueAsync(ContactPublicationAuthorityWireRequest request,
        Func<CancellationToken, ValueTask<byte[]>> issue, CancellationToken cancellationToken);
}

/// <summary>Permanent exact winners in the independent restore-authority DB.
/// No schema creation, empty-root initialization, deletion or expiring rows.</summary>
internal sealed class DeepIdV2PostgreSqlPublicationJournal : IDeepIdV2PublicationJournal, IDisposable
{
    private readonly NpgsqlDataSource source;
    private readonly byte[] network;

    internal DeepIdV2PostgreSqlPublicationJournal(string connectionString, ReadOnlySpan<byte> networkId)
    {
        if (string.IsNullOrWhiteSpace(connectionString) || networkId.Length != 16 ||
            networkId.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("The DID2 publication journal configuration is invalid.");
        network = networkId.ToArray();
        source = NpgsqlDataSource.Create(connectionString);
    }

    public async ValueTask<ReadOnlyMemory<byte>> GetOrIssueAsync(ContactPublicationAuthorityWireRequest request,
        Func<CancellationToken, ValueTask<byte[]>> issue, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(issue);
        if (!Fixed(network, request.NetworkId.Span)) throw new ContactPublicationAuthorityRejectedException();
        var exactRequest = ContactPublicationAuthorityWireCodec.EncodeRequest(request);
        var nonce = request.RequestNonce.ToArray();
        // Reservation is its own durable transaction before any signing callback.
        await using (var connection = await source.OpenConnectionAsync(cancellationToken).ConfigureAwait(false))
        await using (var transaction = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false))
        {
            var capacity = await LockNetworkAsync(connection, transaction, cancellationToken).ConfigureAwait(false);
            var retained = await ReadAsync(connection, transaction, nonce, cancellationToken).ConfigureAwait(false);
            if (retained is not null) RequireRequest(retained.Value.Request, exactRequest);
            else
            {
                if (capacity.Count >= capacity.Maximum) throw new ContactPublicationAuthorityUnavailableException();
                await using var insert = new NpgsqlCommand("INSERT INTO deep_did2_publication_journal " +
                    "(network_id, request_nonce, exact_request) VALUES ($1, $2, $3)", connection, transaction);
                Add(insert, network, nonce, exactRequest);
                if (await insert.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false) != 1)
                    throw new InvalidDataException("Publication reservation was not committed.");
                await using var update = new NpgsqlCommand("UPDATE deep_did2_publication_journal_network " +
                    "SET entry_count = entry_count + 1 WHERE network_id = $1", connection, transaction);
                Add(update, network);
                if (await update.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false) != 1)
                    throw new InvalidDataException("Publication capacity reservation was not committed.");
            }
            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        }

        byte[] expectedWinner;
        await using (var connection = await source.OpenConnectionAsync(cancellationToken).ConfigureAwait(false))
        await using (var transaction = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false))
        {
            _ = await LockNetworkAsync(connection, transaction, cancellationToken).ConfigureAwait(false);
            var retained = await ReadAsync(connection, transaction, nonce, cancellationToken).ConfigureAwait(false)
                ?? throw new InvalidDataException("Durable publication reservation disappeared.");
            RequireRequest(retained.Request, exactRequest);
            if (retained.Response is { } winner) expectedWinner = winner;
            else
            {
                // Keep the DB lock through the callback: two processes cannot
                // publish different candidates under the same durable nonce.
                expectedWinner = await issue(cancellationToken).ConfigureAwait(false);
                _ = ContactPublicationAuthorityWireCodec.DecodeResponse(request, expectedWinner);
                await using var update = new NpgsqlCommand("UPDATE deep_did2_publication_journal " +
                    "SET exact_response = $3 WHERE network_id = $1 AND request_nonce = $2 " +
                    "AND exact_request = $4 AND exact_response IS NULL", connection, transaction);
                Add(update, network, nonce, expectedWinner, exactRequest);
                if (await update.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false) != 1)
                    throw new InvalidDataException("Publication winner compare/exchange failed.");
            }
            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        }

        // Separate connection/read after commit, including lost-response retry.
        await using var readback = await source.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        var exact = await ReadAsync(readback, null, nonce, cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidDataException("Committed publication winner disappeared.");
        RequireRequest(exact.Request, exactRequest);
        if (exact.Response is null || !Fixed(exact.Response, expectedWinner))
            throw new InvalidDataException("Committed publication winner did not read back exactly.");
        _ = ContactPublicationAuthorityWireCodec.DecodeResponse(request, exact.Response);
        return exact.Response;
    }

    private async ValueTask<(long Count, long Maximum)> LockNetworkAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("SELECT entry_count, maximum_entries " +
            "FROM deep_did2_publication_journal_network WHERE network_id = $1 FOR UPDATE", connection, transaction);
        Add(command, network);
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        if (!await reader.ReadAsync(ct).ConfigureAwait(false))
            throw new InvalidDataException("Publication journal network is not provisioned.");
        var count = reader.GetInt64(0); var maximum = reader.GetInt64(1);
        if (maximum is < 1 or > 1_048_576 || count < 0 || count > maximum)
            throw new InvalidDataException("Publication journal capacity is corrupt.");
        return (count, maximum);
    }

    private async ValueTask<(byte[] Request, byte[]? Response)?> ReadAsync(NpgsqlConnection connection,
        NpgsqlTransaction? transaction, byte[] nonce, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("SELECT exact_request, exact_response " +
            "FROM deep_did2_publication_journal WHERE network_id = $1 AND request_nonce = $2",
            connection, transaction);
        Add(command, network, nonce);
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        if (!await reader.ReadAsync(ct).ConfigureAwait(false)) return null;
        var request = reader.GetFieldValue<byte[]>(0);
        var response = reader.IsDBNull(1) ? null : reader.GetFieldValue<byte[]>(1);
        if ((request.Length < ContactPublicationAuthorityWireCodec.MinimumRequestBytes ||
            request.Length > ContactPublicationAuthorityWireCodec.MaximumRequestBytes) ||
            response is not null && (response.Length < ContactPublicationAuthorityWireCodec.MinimumResponseBytes ||
                response.Length > ContactPublicationAuthorityWireCodec.MaximumResponseBytes))
            throw new InvalidDataException("Publication journal row is malformed.");
        return (request, response);
    }

    private static void Add(NpgsqlCommand command, params byte[][] values)
    { foreach (var value in values) command.Parameters.Add(new() { Value = value }); }
    private static bool Fixed(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) =>
        a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
    private static void RequireRequest(byte[] retained, byte[] expected)
    { if (!Fixed(retained, expected)) throw new ContactPublicationAuthorityRejectedException(); }
    public void Dispose() { source.Dispose(); CryptographicOperations.ZeroMemory(network); }
}
#endif
