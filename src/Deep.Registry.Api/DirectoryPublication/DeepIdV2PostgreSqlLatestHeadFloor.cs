#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Npgsql;

namespace Deep.Registry.Api.DirectoryPublication;

/// <summary>
/// An exact-head compare/exchange anchor in a separately restored PostgreSQL
/// database. Schema and initial genesis row are provisioned explicitly by the
/// operator; a missing row or unavailable database never becomes genesis.
/// </summary>
internal sealed class DeepIdV2PostgreSqlLatestHeadFloor :
    IDeepIdV2DirectoryLatestHeadFloor, IDisposable
{
    private readonly NpgsqlDataSource dataSource;
    private readonly byte[] networkId;

    internal DeepIdV2PostgreSqlLatestHeadFloor(string connectionString,
        ReadOnlySpan<byte> networkId)
    {
        if (string.IsNullOrWhiteSpace(connectionString) ||
            networkId.Length != 16 ||
            networkId.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("DID2 external floor configuration is invalid.");
        this.networkId = networkId.ToArray();
        dataSource = NpgsqlDataSource.Create(connectionString);
    }

    public async ValueTask RequireCurrentAsync(
        AccountDirectoryProtectedLkg currentHead,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(currentHead);
        RequireNetwork(currentHead);
        await using var connection = await dataSource.OpenConnectionAsync(
            cancellationToken).ConfigureAwait(false);
        await using var command = new NpgsqlCommand(
            "SELECT exact_adh1, core_hash FROM deep_did2_latest_head_floor " +
            "WHERE network_id = $1", connection);
        command.Parameters.Add(new() { Value = networkId });
        await using var reader = await command.ExecuteReaderAsync(
            cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            throw new InvalidDataException("DID2 external floor is not provisioned.");
        var exact = reader.GetFieldValue<byte[]>(0);
        var hash = reader.GetFieldValue<byte[]>(1);
        if (!Fixed(exact, currentHead.ExactAdh1.Span) ||
            !Fixed(hash, currentHead.CoreHash.Span))
            throw new InvalidDataException(
                "DID2 ADA2 head differs from the external latest-head floor.");
    }

    public async ValueTask AdvanceAsync(
        AccountDirectoryProtectedLkg expectedHead,
        AccountDirectoryProtectedLkg nextHead,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(expectedHead);
        ArgumentNullException.ThrowIfNull(nextHead);
        RequireNetwork(expectedHead);
        RequireNetwork(nextHead);
        if (nextHead.LogGeneration <= expectedHead.LogGeneration ||
            nextHead.TreeSize < expectedHead.TreeSize ||
            Fixed(nextHead.CoreHash.Span, expectedHead.CoreHash.Span))
            throw new InvalidDataException(
                "DID2 external floor can advance only to a newer head.");
        await using var connection = await dataSource.OpenConnectionAsync(
            cancellationToken).ConfigureAwait(false);
        await using var command = new NpgsqlCommand(
            "UPDATE deep_did2_latest_head_floor " +
            "SET exact_adh1 = $4, core_hash = $5 " +
            "WHERE network_id = $1 AND exact_adh1 = $2 AND core_hash = $3",
            connection);
        command.Parameters.Add(new() { Value = networkId });
        command.Parameters.Add(new() { Value = expectedHead.ExactAdh1.ToArray() });
        command.Parameters.Add(new() { Value = expectedHead.CoreHash.ToArray() });
        command.Parameters.Add(new() { Value = nextHead.ExactAdh1.ToArray() });
        command.Parameters.Add(new() { Value = nextHead.CoreHash.ToArray() });
        if (await command.ExecuteNonQueryAsync(cancellationToken)
                .ConfigureAwait(false) != 1)
            throw new InvalidDataException(
                "DID2 external floor compare/exchange rejected stale ADA2 head.");
    }

    internal async ValueTask ProvisionGenesisAsync(
        AccountDirectoryProtectedLkg genesis,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(genesis);
        RequireNetwork(genesis);
        if (genesis.TreeSize != 0 || genesis.LogGeneration != 0)
            throw new InvalidDataException("DID2 floor genesis must be the empty signed head.");
        await using var connection = await dataSource.OpenConnectionAsync(
            cancellationToken).ConfigureAwait(false);
        await using var command = new NpgsqlCommand(
            "INSERT INTO deep_did2_latest_head_floor " +
            "(network_id, exact_adh1, core_hash) VALUES ($1, $2, $3)",
            connection);
        command.Parameters.Add(new() { Value = networkId });
        command.Parameters.Add(new() { Value = genesis.ExactAdh1.ToArray() });
        command.Parameters.Add(new() { Value = genesis.CoreHash.ToArray() });
        if (await command.ExecuteNonQueryAsync(cancellationToken)
                .ConfigureAwait(false) != 1)
            throw new InvalidDataException("DID2 floor genesis was not inserted.");
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length &&
        CryptographicOperations.FixedTimeEquals(left, right);

    private void RequireNetwork(AccountDirectoryProtectedLkg head)
    {
        if (!Fixed(head.Head.NetworkId.Span, networkId))
            throw new InvalidDataException(
                "DID2 external floor head belongs to another network.");
    }

    public void Dispose()
    {
        dataSource.Dispose();
        CryptographicOperations.ZeroMemory(networkId);
    }
}
#endif
