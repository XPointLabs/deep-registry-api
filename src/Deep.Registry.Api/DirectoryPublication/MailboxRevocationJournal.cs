#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Security.Cryptography;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.XPointNetworkV1;
using Npgsql;
using ProtocolMagicBytes = Deep.Protocol.Registry.DeepProtocolIdentifiers.MagicBytes;

namespace Deep.Registry.Api.DirectoryPublication;

/// <summary>Actual independent scoped issuer ledger. A call completes one exact
/// generation, which may be historical. Caller must obtain a fresh successor
/// before readiness; unsigned intents are never exposed as native floors.</summary>
internal sealed class MailboxRevocationJournal : IDisposable
{
    private const string ScopePredicate = "network_id = $1 AND policy_reference = $2 AND role = $3 AND issuer_key = $4";
    private readonly NpgsqlDataSource source;
    private readonly byte[] network, policy, issuer;
    private readonly MailboxCapabilityDomain role;

    internal MailboxRevocationJournal(string connectionString, ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> policyReference, MailboxCapabilityDomain domain, ReadOnlySpan<byte> issuerKey)
    {
        if (string.IsNullOrWhiteSpace(connectionString) || networkId.Length != 16 ||
            networkId.IndexOfAnyExcept((byte)0) < 0 || policyReference.Length != 38 ||
            !policyReference[..4].SequenceEqual(ProtocolMagicBytes.PMA2) || policyReference[4] != 0 || policyReference[5] != 1 ||
            policyReference[6..].IndexOfAnyExcept((byte)0) < 0 || issuerKey.Length != 32 ||
            issuerKey.IndexOfAnyExcept((byte)0) < 0 || domain is not (MailboxCapabilityDomain.Deposit or MailboxCapabilityDomain.Retrieve))
            throw new ArgumentException("MGR1 journal scope is invalid.");
        network = networkId.ToArray(); policy = policyReference.ToArray(); issuer = issuerKey.ToArray(); role = domain;
        source = NpgsqlDataSource.Create(connectionString);
    }

    internal async ValueTask<ReadOnlyMemory<byte>> GetOrIssueNextAsync(VerifiedMailboxHostAuthorityV2 host,
        IReadOnlyList<ReadOnlyMemory<byte>> additionalRevokedSerials, IMailboxGrantIssuerSigner signer,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(host); ArgumentNullException.ThrowIfNull(signer);
        ArgumentNullException.ThrowIfNull(additionalRevokedSerials); cancellationToken.ThrowIfCancellationRequested();
        var additions = CaptureSerials(additionalRevokedSerials);
        PreparedMailboxGrantRevocationV1 reserved;
        long generation;
        // First transaction commits exact unsigned input and cumulative serials
        // BEFORE any external signature callback. Root row is explicit, never created here.
        await using (var connection = await source.OpenConnectionAsync(cancellationToken).ConfigureAwait(false))
        await using (var transaction = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false))
        {
            var state = await LockScopeAsync(connection, transaction, cancellationToken).ConfigureAwait(false);
            var serials = Union(state.Serials, additions);
            if (state.Entries != state.Committed)
            {
                generation = state.Entries;
                var pending = await RequireEntryAsync(connection, transaction, generation, cancellationToken).ConfigureAwait(false);
                if (pending.Winner is not null) throw new InvalidDataException("MGR1 pending row already has an unaccounted winner.");
                reserved = await MailboxGrantRevocationV1Author.RestoreReservedAsync(host, pending.Input, cancellationToken).ConfigureAwait(false);
                RequireScope(reserved, generation);
                RequireLedgerContains(state.Serials, reserved.CumulativeRevokedSerials);
                await RequirePredecessorAsync(host, reserved, generation, connection, transaction, cancellationToken).ConfigureAwait(false);
            }
            else
            {
                if (state.Entries >= state.Maximum) throw new IOException("MGR1 journal snapshot capacity is exhausted.");
                ReadOnlyMemory<byte> prior = ReadOnlyMemory<byte>.Empty;
                if (state.Committed != 0)
                {
                    var entry = await RequireEntryAsync(connection, transaction, state.Committed, cancellationToken).ConfigureAwait(false);
                    prior = await VerifyWinnerAsync(host, entry, state.Committed, cancellationToken).ConfigureAwait(false);
                    RequireLedgerContains(state.Serials, MailboxGrantRevocationV1Codec.Decode(prior.Span));
                }
                reserved = await MailboxGrantRevocationV1Author.PrepareCurrentAsync(host, role, prior,
                    Rows(serials), cancellationToken).ConfigureAwait(false);
                generation = state.Entries + 1; RequireScope(reserved, generation);
                await using var insert = Command("INSERT INTO deep_mailbox_revocation_snapshot " +
                    "(network_id, policy_reference, role, issuer_key, generation, signing_input) VALUES ($1,$2,$3,$4,$5,$6)",
                    connection, transaction, generation, reserved.SigningInput.ToArray());
                RequireSingle(await insert.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false));
            }
            await using var update = Command("UPDATE deep_mailbox_revocation_scope SET entry_count = $5, cumulative_serials = $6 WHERE " + ScopePredicate,
                connection, transaction, generation, serials);
            RequireSingle(await update.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false));
            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        }

        byte[] expected;
        // Cross-process exclusion remains held throughout the signature callback
        // and winner commit. Rollback never removes the already committed intent.
        await using (var connection = await source.OpenConnectionAsync(cancellationToken).ConfigureAwait(false))
        await using (var transaction = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false))
        {
            var state = await LockScopeAsync(connection, transaction, cancellationToken).ConfigureAwait(false);
            var entry = await RequireEntryAsync(connection, transaction, generation, cancellationToken).ConfigureAwait(false);
            if (!Fixed(entry.Input, reserved.SigningInput.Span)) throw new InvalidDataException("MGR1 reserved input changed after commit.");
            if (entry.Winner is null)
            {
                if (state.Committed != generation - 1 || state.Entries != generation)
                    throw new InvalidDataException("MGR1 pending generation is outside its actual protected root.");
                var restored = await MailboxGrantRevocationV1Author.RestoreReservedAsync(host, entry.Input, cancellationToken).ConfigureAwait(false);
                RequireScope(restored, generation);
                RequireLedgerContains(state.Serials, restored.CumulativeRevokedSerials);
                await RequirePredecessorAsync(host, restored, generation, connection, transaction, cancellationToken).ConfigureAwait(false);
                expected = (await MailboxGrantRevocationV1Author.CompleteReservedAsync(restored, signer, cancellationToken).ConfigureAwait(false)).ToArray();
                RequireLedgerContains(state.Serials, MailboxGrantRevocationV1Codec.Decode(expected));
                await using var winner = Command("UPDATE deep_mailbox_revocation_snapshot SET exact_snapshot = $6 WHERE " +
                    ScopePredicate + " AND generation = $5 AND signing_input = $7 AND exact_snapshot IS NULL",
                    connection, transaction, generation, expected, entry.Input);
                RequireSingle(await winner.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false));
                await using var advance = Command("UPDATE deep_mailbox_revocation_scope SET committed_generation = $5 WHERE " +
                    ScopePredicate + " AND committed_generation = $6 AND entry_count = $5", connection, transaction, generation, generation - 1);
                RequireSingle(await advance.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false));
            }
            else
            {
                if (state.Committed < generation) throw new InvalidDataException("MGR1 signed winner is not accounted by its root.");
                expected = (await VerifyWinnerAsync(host, entry, generation, cancellationToken).ConfigureAwait(false)).ToArray();
            }
            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        }
        // Actual DB read-back, not the signer response or a process-local winner cache.
        var readBack = await ReadSignedStepAsync(host, checked((ulong)generation), cancellationToken).ConfigureAwait(false);
        if (!Fixed(expected, readBack.Span)) throw new InvalidDataException("MGR1 committed winner did not read back exactly.");
        cancellationToken.ThrowIfCancellationRequested(); return readBack;
    }

    /// <summary>One retained signed step only. May be expired; no admission or freshness claim.</summary>
    internal async ValueTask<ReadOnlyMemory<byte>> ReadSignedStepAsync(VerifiedMailboxHostAuthorityV2 host,
        ulong generation, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(host); cancellationToken.ThrowIfCancellationRequested();
        if (generation is 0 or > 1_048_576) throw new ArgumentOutOfRangeException(nameof(generation));
        await using var connection = await source.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        var state = await LockScopeAsync(connection, transaction, cancellationToken).ConfigureAwait(false);
        if (generation > (ulong)state.Committed) throw new InvalidDataException("MGR1 requested signed history is unavailable.");
        var entry = await RequireEntryAsync(connection, transaction, (long)generation, cancellationToken).ConfigureAwait(false);
        var winner = await VerifyWinnerAsync(host, entry, (long)generation, cancellationToken).ConfigureAwait(false);
        RequireLedgerContains(state.Serials, MailboxGrantRevocationV1Codec.Decode(winner.Span));
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return winner;
    }

    private async ValueTask<ReadOnlyMemory<byte>> VerifyWinnerAsync(VerifiedMailboxHostAuthorityV2 host,
        Entry entry, long generation, CancellationToken ct)
    {
        if (entry.Winner is null) throw new InvalidDataException("MGR1 signed winner is missing.");
        var prepared = await MailboxGrantRevocationV1Author.RestoreReservedAsync(host, entry.Input, ct).ConfigureAwait(false);
        RequireScope(prepared, generation);
        await MailboxGrantRevocationV1Author.VerifyReservedCompletionAsync(prepared, entry.Winner, ct).ConfigureAwait(false);
        return entry.Winner;
    }

    private async ValueTask RequirePredecessorAsync(VerifiedMailboxHostAuthorityV2 host,
        PreparedMailboxGrantRevocationV1 reserved, long generation,
        NpgsqlConnection connection, NpgsqlTransaction transaction, CancellationToken ct)
    {
        ReadOnlyMemory<byte> prior = ReadOnlyMemory<byte>.Empty;
        if (generation != 1)
            prior = await VerifyWinnerAsync(host, await RequireEntryAsync(connection, transaction,
                generation - 1, ct).ConfigureAwait(false), generation - 1, ct).ConfigureAwait(false);
        await MailboxGrantRevocationV1Author.VerifyReservedPredecessorAsync(reserved, prior, ct).ConfigureAwait(false);
    }

    private async ValueTask<State> LockScopeAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, CancellationToken ct)
    {
        State state;
        await using (var command = Command("SELECT committed_generation, entry_count, maximum_entries, cumulative_serials " +
            "FROM deep_mailbox_revocation_scope WHERE " + ScopePredicate + " FOR UPDATE", connection, transaction))
        await using (var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false))
        {
            if (!await reader.ReadAsync(ct).ConfigureAwait(false)) throw new InvalidDataException("MGR1 issuer scope is not explicitly provisioned.");
            state = new(reader.GetInt64(0), reader.GetInt64(1), reader.GetInt64(2), reader.GetFieldValue<byte[]>(3));
            if (state.Maximum is < 1 or > 1_048_576 || state.Committed < 0 || state.Entries < state.Committed ||
                state.Entries > state.Maximum || state.Entries - state.Committed > 1)
                throw new InvalidDataException("MGR1 protected root counters are invalid.");
            ValidateSerials(state.Serials);
        }
        await using var inventory = Command("SELECT count(*), count(exact_snapshot), min(generation), max(generation) " +
            "FROM deep_mailbox_revocation_snapshot WHERE " + ScopePredicate, connection, transaction);
        await using var rows = await inventory.ExecuteReaderAsync(ct).ConfigureAwait(false);
        if (!await rows.ReadAsync(ct).ConfigureAwait(false) || rows.GetInt64(0) != state.Entries || rows.GetInt64(1) != state.Committed ||
            state.Entries != 0 && (rows.IsDBNull(2) || rows.GetInt64(2) != 1 || rows.GetInt64(3) != state.Entries))
            throw new InvalidDataException("MGR1 retained history differs from its independent protected root.");
        return state;
    }

    private async ValueTask<Entry> RequireEntryAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, long generation, CancellationToken ct)
    {
        await using var command = Command("SELECT signing_input, exact_snapshot FROM deep_mailbox_revocation_snapshot WHERE " +
            ScopePredicate + " AND generation = $5", connection, transaction, generation);
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        if (!await reader.ReadAsync(ct).ConfigureAwait(false)) throw new InvalidDataException("MGR1 retained generation disappeared.");
        var input = reader.GetFieldValue<byte[]>(0); var winner = reader.IsDBNull(1) ? null : reader.GetFieldValue<byte[]>(1);
        if (input.Length is < 288 or > 65_824 || winner is not null && winner.Length is < 327 or > 65_863)
            throw new InvalidDataException("MGR1 retained row exceeds its closed bound.");
        return new(input, winner);
    }
    private void RequireScope(PreparedMailboxGrantRevocationV1 reserved, long generation)
    {
        if (reserved.Generation != (ulong)generation || reserved.Domain != role || !Fixed(network, reserved.NetworkId.Span) ||
            !Fixed(policy, reserved.PolicyReference.Span) || !Fixed(issuer, reserved.IssuerPublicKey.Span))
            throw new CryptographicException("MGR1 journal differs from the actual current reserved issuer scope.");
    }
    private NpgsqlCommand Command(string sql, NpgsqlConnection connection, NpgsqlTransaction transaction, params object[] tail)
    {
        var command = new NpgsqlCommand(sql, connection, transaction);
        foreach (var value in new object[] { network, policy, (short)role, issuer }.Concat(tail)) command.Parameters.Add(new() { Value = value });
        return command;
    }
    private static byte[] CaptureSerials(IReadOnlyList<ReadOnlyMemory<byte>> rows)
    {
        var count = rows.Count;
        if (count is < 0 or > MailboxGrantRevocationV1Codec.MaximumSerials) throw new ArgumentException("MGR1 serial additions exceed capacity.");
        var bytes = new byte[checked(count * 16)];
        for (var index = 0; index < count; index++)
        { if (rows[index].Length != 16) throw new ArgumentException("MGR1 serial must be 16 bytes."); rows[index].Span.CopyTo(bytes.AsSpan(index * 16, 16)); }
        ValidateSerials(bytes); return bytes;
    }
    private static void ValidateSerials(byte[] bytes)
    {
        if (bytes.Length > MailboxGrantRevocationV1Codec.MaximumSerials * 16 || bytes.Length % 16 != 0)
            throw new InvalidDataException("MGR1 ledger exceeds its exact bounds.");
        for (var offset = 0; offset < bytes.Length; offset += 16)
            if (bytes.AsSpan(offset, 16).IndexOfAnyExcept((byte)0) < 0 ||
                offset != 0 && bytes.AsSpan(offset - 16, 16).SequenceCompareTo(bytes.AsSpan(offset, 16)) >= 0)
                throw new InvalidDataException("MGR1 ledger must be nonzero and strictly ordered.");
    }
    private static byte[] Union(byte[] retained, byte[] additions)
    {
        var rows = Rows(retained).Concat(Rows(additions)).Select(row => Convert.ToHexString(row.Span))
            .Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray();
        if (rows.Length > MailboxGrantRevocationV1Codec.MaximumSerials) throw new IOException("MGR1 cumulative serial capacity is exhausted.");
        return rows.SelectMany(Convert.FromHexString).ToArray();
    }
    private static ReadOnlyMemory<byte>[] Rows(byte[] bytes) => Enumerable.Range(0, bytes.Length / 16)
        .Select(index => (ReadOnlyMemory<byte>)bytes.AsSpan(index * 16, 16).ToArray()).ToArray();
    private static void RequireLedgerContains(byte[] ledger, ParsedMailboxGrantRevocationV1 snapshot)
        => RequireLedgerContains(ledger, snapshot.Field(11));
    private static void RequireLedgerContains(byte[] ledger, ReadOnlyMemory<byte> serials)
    {
        var retained = Rows(ledger).Select(row => Convert.ToHexString(row.Span)).ToHashSet(StringComparer.Ordinal);
        for (var offset = 0; offset < serials.Length; offset += 16)
            if (!retained.Contains(Convert.ToHexString(serials.Span.Slice(offset, 16))))
                throw new InvalidDataException("MGR1 signed winner contains a revocation lost by its permanent ledger.");
    }
    private static void RequireSingle(int count) { if (count != 1) throw new InvalidDataException("MGR1 exact journal compare/exchange failed."); }
    private static bool Fixed(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) => a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
    private sealed record State(long Committed, long Entries, long Maximum, byte[] Serials);
    private sealed record Entry(byte[] Input, byte[]? Winner);
    public void Dispose() => source.Dispose();
}
#endif
