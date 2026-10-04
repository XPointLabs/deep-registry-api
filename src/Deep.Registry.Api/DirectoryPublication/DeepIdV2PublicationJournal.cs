#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Npgsql;

namespace Deep.Registry.Api.DirectoryPublication;

internal interface IDeepIdV2PublicationJournal
{
    ValueTask<(ReadOnlyMemory<byte> Request, ReadOnlyMemory<byte> Response)> ReadCompletedPredecessorAsync(
        ContactPublicationAuthorityWireRequest request, CancellationToken cancellationToken);
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

    public async ValueTask<(ReadOnlyMemory<byte> Request, ReadOnlyMemory<byte> Response)> ReadCompletedPredecessorAsync(
        ContactPublicationAuthorityWireRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!Fixed(network, request.NetworkId.Span) || request.Generation == 0)
            throw new ContactPublicationAuthorityRejectedException();
        await using var connection = await source.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        _ = await LockNetworkAsync(connection, transaction, cancellationToken).ConfigureAwait(false);
        var prior = await RequirePredecessorAsync(connection, transaction, request, cancellationToken).ConfigureAwait(false)
            ?? throw new ContactPublicationAuthorityRejectedException();
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return (prior.Request, prior.Response!);
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
            _ = await RequirePredecessorAsync(connection, transaction, request, cancellationToken).ConfigureAwait(false);
            await RequireGenerationAsync(connection, transaction, request, exactRequest, cancellationToken).ConfigureAwait(false);
            var retained = await ReadAsync(connection, transaction, nonce, cancellationToken).ConfigureAwait(false);
            if (retained is not null) RequireRequest(retained.Request, exactRequest);
            else
            {
                if (capacity.Count >= capacity.Maximum) throw new ContactPublicationAuthorityUnavailableException();
                await using var insert = new NpgsqlCommand("INSERT INTO deep_did2_publication_journal " +
                    "(network_id, request_nonce, exact_request, directory_lookup_key, request_generation, " +
                    "predecessor_object_hash, object_ciphertext_hash, publication_kind, locator_hash) " +
                    "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)", connection, transaction);
                Add(insert, network, nonce, exactRequest, request.DirectoryLookupKey.ToArray(), GenerationBytes(request.Generation),
                    request.PredecessorObjectHash.ToArray(), SHA256.HashData(request.ObjectCiphertext.Span));
                insert.Parameters.Add(new() { Value = (short)request.PublicationKind });
                insert.Parameters.Add(new() { Value = request.LocatorHash.ToArray() });
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
            _ = await RequirePredecessorAsync(connection, transaction, request, cancellationToken).ConfigureAwait(false);
            await RequireGenerationAsync(connection, transaction, request, exactRequest, cancellationToken).ConfigureAwait(false);
            var retained = await ReadAsync(connection, transaction, nonce, cancellationToken).ConfigureAwait(false)
                ?? throw new InvalidDataException("Durable publication reservation disappeared.");
            RequireRequest(retained.Request, exactRequest);
            if (retained.Response is { } winner) expectedWinner = winner;
            else
            {
                // Keep the DB lock through the callback: two processes cannot
                // publish different candidates under the permanent generation fence.
                expectedWinner = (await issue(cancellationToken).ConfigureAwait(false)).ToArray();
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
        await using var readbackTransaction = await readback.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        _ = await LockNetworkAsync(readback, readbackTransaction, cancellationToken).ConfigureAwait(false);
        var exact = await ReadAsync(readback, readbackTransaction, nonce, cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidDataException("Committed publication winner disappeared.");
        RequireRequest(exact.Request, exactRequest);
        if (exact.Response is null || !Fixed(exact.Response, expectedWinner))
            throw new InvalidDataException("Committed publication winner did not read back exactly.");
        _ = ContactPublicationAuthorityWireCodec.DecodeResponse(request, exact.Response);
        await readbackTransaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return exact.Response;
    }

    private async ValueTask<(long Count, long Maximum)> LockNetworkAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("SELECT entry_count, maximum_entries, " +
            "request_envelope_version, generation_fence_version " +
            "FROM deep_did2_publication_journal_network WHERE network_id = $1 FOR UPDATE", connection, transaction);
        Add(command, network);
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        if (!await reader.ReadAsync(ct).ConfigureAwait(false))
            throw new InvalidDataException("Publication journal network is not provisioned.");
        var count = reader.GetInt64(0); var maximum = reader.GetInt64(1);
        if (maximum is < 1 or > 1_048_576 || count < 0 || count > maximum)
            throw new InvalidDataException("Publication journal capacity is corrupt.");
        if (reader.GetInt16(2) != 4 || reader.GetInt16(3) != 2)
            throw new InvalidDataException("Publication successor journal is not provisioned.");
        return (count, maximum);
    }

    private sealed record RetainedPublication(byte[] Request, byte[]? Response, ContactPublicationAuthorityWireRequest Parsed);

    private async ValueTask<RetainedPublication?> RequirePredecessorAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, ContactPublicationAuthorityWireRequest request, CancellationToken ct)
    {
        if (request.Generation == 0) return null;
        var prior = await ReadGenerationAsync(connection, transaction, request,
            request.Generation - 1, ct).ConfigureAwait(false);
        if (prior?.Response is null || !Fixed(SHA256.HashData(prior.Parsed.ObjectCiphertext.Span), request.PredecessorObjectHash.Span))
            throw new ContactPublicationAuthorityRejectedException();
        _ = ContactPublicationAuthorityWireCodec.DecodeResponse(prior.Parsed, prior.Response);
        return prior;
    }

    private async ValueTask RequireGenerationAsync(NpgsqlConnection connection, NpgsqlTransaction transaction,
        ContactPublicationAuthorityWireRequest request, byte[] exactRequest, CancellationToken ct)
    {
        if (request.PublicationKind == 1)
        {
            // Old projected permanent reservations remain a fence, never decoded
            // or adopted as V4 history. A cutover cannot remint their generation.
            await using var old = new NpgsqlCommand("SELECT 1 FROM deep_did2_publication_journal " +
                "WHERE network_id=$1 AND directory_lookup_key=$2 AND request_generation=$3 AND publication_kind IS NULL LIMIT 1",
                connection, transaction);
            Add(old, network, request.DirectoryLookupKey.ToArray(), GenerationBytes(request.Generation));
            if (await old.ExecuteScalarAsync(ct).ConfigureAwait(false) is not null)
                throw new ContactPublicationAuthorityRejectedException();
        }
        var retained = await ReadGenerationAsync(connection, transaction, request, request.Generation, ct).ConfigureAwait(false);
        if (retained is not null) RequireRequest(retained.Request, exactRequest);
    }

    private ValueTask<RetainedPublication?> ReadGenerationAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, ContactPublicationAuthorityWireRequest request, ulong generation, CancellationToken ct) =>
        ReadRowAsync(connection, transaction, "directory_lookup_key = $2 AND request_generation = $3 AND publication_kind = $4 AND locator_hash = $5",
            [network, request.DirectoryLookupKey.ToArray(), GenerationBytes(generation), (short)request.PublicationKind, request.LocatorHash.ToArray()], ct);

    private ValueTask<RetainedPublication?> ReadAsync(NpgsqlConnection connection,
        NpgsqlTransaction? transaction, byte[] nonce, CancellationToken ct)
        => ReadRowAsync(connection, transaction, "request_nonce = $2", [network, nonce], ct);

    private async ValueTask<RetainedPublication?> ReadRowAsync(NpgsqlConnection connection,
        NpgsqlTransaction? transaction, string predicate, object[] parameters, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("SELECT octet_length(exact_request), octet_length(exact_response), " +
            "exact_request, exact_response, request_nonce, directory_lookup_key, request_generation, predecessor_object_hash, object_ciphertext_hash, publication_kind, locator_hash " +
            "FROM deep_did2_publication_journal WHERE network_id = $1 AND " + predicate,
            connection, transaction);
        foreach (var value in parameters) command.Parameters.Add(new() { Value = value });
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        if (!await reader.ReadAsync(ct).ConfigureAwait(false)) return null;
        var requestLength = reader.GetInt32(0);
        var responseLength = reader.IsDBNull(1) ? 0 : reader.GetInt32(1);
        if (requestLength < ContactPublicationAuthorityWireCodec.MinimumRequestBytes ||
            requestLength > ContactPublicationAuthorityWireCodec.MaximumRequestBytes ||
            !reader.IsDBNull(1) && (responseLength < ContactPublicationAuthorityWireCodec.MinimumResponseBytes ||
                responseLength > ContactPublicationAuthorityWireCodec.MaximumResponseBytes) ||
            Enumerable.Range(5, 6).Any(reader.IsDBNull))
            throw new InvalidDataException("Publication journal row is malformed.");
        var request = reader.GetFieldValue<byte[]>(2);
        var response = reader.IsDBNull(3) ? null : reader.GetFieldValue<byte[]>(3);
        var parsed = ContactPublicationAuthorityWireCodec.DecodeRequest(request);
        if (!Fixed(parsed.NetworkId.Span, network) || !Fixed(parsed.RequestNonce.Span, reader.GetFieldValue<byte[]>(4)) ||
            !Fixed(parsed.DirectoryLookupKey.Span, reader.GetFieldValue<byte[]>(5)) ||
            !Fixed(GenerationBytes(parsed.Generation), reader.GetFieldValue<byte[]>(6)) ||
            !Fixed(parsed.PredecessorObjectHash.Span, reader.GetFieldValue<byte[]>(7)) ||
            !Fixed(SHA256.HashData(parsed.ObjectCiphertext.Span), reader.GetFieldValue<byte[]>(8)) ||
            parsed.PublicationKind != reader.GetInt16(9) || !Fixed(parsed.LocatorHash.Span, reader.GetFieldValue<byte[]>(10)))
            throw new InvalidDataException("Publication journal projections differ from canonical request custody.");
        if (response is not null) _ = ContactPublicationAuthorityWireCodec.DecodeResponse(parsed, response);
        if (await reader.ReadAsync(ct).ConfigureAwait(false)) throw new InvalidDataException("Publication generation fence is ambiguous.");
        return new(request, response, parsed);
    }

    private static byte[] GenerationBytes(ulong generation)
    { var bytes = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(bytes, generation); return bytes; }

    private static void Add(NpgsqlCommand command, params byte[][] values)
    { foreach (var value in values) command.Parameters.Add(new() { Value = value }); }
    private static bool Fixed(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) =>
        a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
    private static void RequireRequest(byte[] retained, byte[] expected)
    { if (!Fixed(retained, expected)) throw new ContactPublicationAuthorityRejectedException(); }
    public void Dispose() { source.Dispose(); CryptographicOperations.ZeroMemory(network); }
}
#endif
