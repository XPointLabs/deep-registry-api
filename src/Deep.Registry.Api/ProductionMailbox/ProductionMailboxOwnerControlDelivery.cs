using System.Security.Cryptography;
using System.Data;
using Deep.Protocol.DeepExtension.MailboxTopology;
using Npgsql;

namespace Deep.Registry.Api.ProductionMailbox;

internal sealed record ProductionMailboxOwnerControlDurableDeliveryLease(
    byte[] LeaseId, byte[] MailboxOwnerEd25519PublicKey, byte[] RouteStateKey,
    byte[] ActiveScope, long ReservedBytes, ulong ExpiresAtUnixSeconds,
    byte[] IntegrityTag);

internal interface IProductionMailboxOwnerControlDeliveryLeaseStore
{
    ValueTask<ProductionMailboxOwnerControlDurableDeliveryLease?> TryAcquireDeliveryLeaseAsync(
        ReadOnlyMemory<byte> mailboxOwnerEd25519PublicKey,
        ReadOnlyMemory<byte> routeStateKey,
        ReadOnlyMemory<byte> activeScope,
        long reservedBytes,
        ulong expiresAtUnixSeconds,
        CancellationToken cancellationToken);

    ValueTask ReleaseDeliveryLeaseAsync(ReadOnlyMemory<byte> leaseId,
        CancellationToken cancellationToken);
}

internal static class ProductionMailboxOwnerControlDurableDeliveryLeaseIntegrity
{
    private static ReadOnlySpan<byte> Domain =>
        "Deep/registry/production-mailbox/owner-control/delivery-lease/v1"u8;

    internal static ProductionMailboxOwnerControlDurableDeliveryLease Create(
        ReadOnlySpan<byte> leaseId, ReadOnlySpan<byte> owner, ReadOnlySpan<byte> route,
        ReadOnlySpan<byte> activeScope, long reservedBytes, ulong expiresAt,
        ReadOnlySpan<byte> key)
    {
        Validate(leaseId, owner, route, activeScope, reservedBytes, expiresAt, key);
        var tag = Tag(leaseId, owner, route, activeScope, reservedBytes, expiresAt, key);
        try
        {
            return new(leaseId.ToArray(), owner.ToArray(), route.ToArray(),
            activeScope.ToArray(), reservedBytes, expiresAt, tag.ToArray());
        }
        finally { CryptographicOperations.ZeroMemory(tag); }
    }

    internal static ProductionMailboxOwnerControlDurableDeliveryLease Restore(
        ReadOnlySpan<byte> leaseId, ReadOnlySpan<byte> owner, ReadOnlySpan<byte> route,
        ReadOnlySpan<byte> activeScope, long reservedBytes, ulong expiresAt,
        ReadOnlySpan<byte> tag, ReadOnlySpan<byte> key)
    {
        Validate(leaseId, owner, route, activeScope, reservedBytes, expiresAt, key);
        var expected = Tag(leaseId, owner, route, activeScope, reservedBytes, expiresAt, key);
        try
        {
            if (tag.Length != 32 || !CryptographicOperations.FixedTimeEquals(expected, tag))
                throw new InvalidDataException("Owner-control delivery lease HMAC is invalid.");
            return new(leaseId.ToArray(), owner.ToArray(), route.ToArray(),
                activeScope.ToArray(), reservedBytes, expiresAt, tag.ToArray());
        }
        finally { CryptographicOperations.ZeroMemory(expected); }
    }

    private static void Validate(ReadOnlySpan<byte> leaseId, ReadOnlySpan<byte> owner,
        ReadOnlySpan<byte> route, ReadOnlySpan<byte> activeScope, long reservedBytes,
        ulong expiresAt, ReadOnlySpan<byte> key)
    {
        if (leaseId.Length != 16 || owner.Length != 32 || route.Length != 32 ||
            activeScope.Length != 32 || key.Length != 32 ||
            leaseId.IndexOfAnyExcept((byte)0) < 0 || owner.IndexOfAnyExcept((byte)0) < 0 ||
            route.IndexOfAnyExcept((byte)0) < 0 ||
            activeScope.IndexOfAnyExcept((byte)0) < 0 || key.IndexOfAnyExcept((byte)0) < 0 ||
            reservedBytes < ProductionMailboxOwnerControlConstants.ResponseHeaderLength ||
            reservedBytes > ProductionMailboxOwnerControlConstants.ResponseHeaderLength +
                (long)ProductionMailboxOwnerControlConstants.MaximumHistoryFrameBytes ||
            expiresAt is 0 or ulong.MaxValue)
            throw new InvalidDataException("Owner-control delivery lease fields are invalid.");
    }

    private static byte[] Tag(ReadOnlySpan<byte> leaseId, ReadOnlySpan<byte> owner,
        ReadOnlySpan<byte> route, ReadOnlySpan<byte> activeScope, long reservedBytes,
        ulong expiresAt, ReadOnlySpan<byte> key)
    {
        var ownedKey = key.ToArray();
        try
        {
            using var hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, ownedKey);
            hmac.AppendData(Domain); hmac.AppendData(leaseId); hmac.AppendData(owner);
            hmac.AppendData(route); hmac.AppendData(activeScope);
            Span<byte> scalars = stackalloc byte[16];
            System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian(
                scalars[..8], reservedBytes);
            System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(
                scalars[8..], expiresAt);
            hmac.AppendData(scalars);
            return hmac.GetHashAndReset();
        }
        finally { CryptographicOperations.ZeroMemory(ownedKey); }
    }
}

internal sealed record ProductionMailboxOwnerControlDeliveryLimits(
    int MaximumGlobalCount,
    int MaximumPerOwnerCount,
    int MaximumPerRouteCount,
    long MaximumGlobalBytes,
    TimeSpan AuthorizationReplayTimeout,
    TimeSpan ResponseWriteTimeout,
    TimeSpan CleanupTimeout)
{
    internal void Validate()
    {
        if (MaximumGlobalCount is < 1 or > 4096 ||
            MaximumPerOwnerCount < 1 || MaximumPerOwnerCount > MaximumGlobalCount ||
            MaximumPerRouteCount < 1 || MaximumPerRouteCount > MaximumPerOwnerCount ||
            MaximumGlobalBytes < ProductionMailboxOwnerControlConstants.ResponseHeaderLength +
                ProductionMailboxProtectedHistoryResponseReference.MinimumPayloadLength ||
            MaximumGlobalBytes > 4L * 1024 * 1024 * 1024 ||
            AuthorizationReplayTimeout < TimeSpan.FromSeconds(1) ||
            AuthorizationReplayTimeout > TimeSpan.FromMinutes(5) ||
            ResponseWriteTimeout < TimeSpan.FromSeconds(1) ||
            ResponseWriteTimeout > TimeSpan.FromMinutes(5) ||
            CleanupTimeout < TimeSpan.FromSeconds(1) ||
            CleanupTimeout > TimeSpan.FromMinutes(1))
            throw new InvalidOperationException("Owner-control delivery limits are invalid.");
    }

    internal TimeSpan LeaseLifetime => AuthorizationReplayTimeout +
        ResponseWriteTimeout + CleanupTimeout;
}

internal sealed class ProductionMailboxOwnerControlDeliveryLeaseManager
{
    private readonly TimeProvider timeProvider;
    private readonly ProductionMailboxOwnerControlDeliveryLimits limits;
    private readonly SemaphoreSlim gate = new(1, 1);
    private readonly Dictionary<string, int> ownerCounts = new(StringComparer.Ordinal);
    private readonly Dictionary<string, int> routeCounts = new(StringComparer.Ordinal);
    private TaskCompletionSource changed = NewSignal();
    private int globalCount;
    private long globalBytes;

    internal ProductionMailboxOwnerControlDeliveryLeaseManager(TimeProvider timeProvider,
        ProductionMailboxOwnerControlDeliveryLimits limits)
    {
        this.timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
        this.limits = limits ?? throw new ArgumentNullException(nameof(limits));
        limits.Validate();
    }

    internal async ValueTask<ProductionMailboxOwnerControlDeliveryLease> AcquireAsync(
        ReadOnlyMemory<byte> mailboxOwnerEd25519PublicKey,
        ReadOnlyMemory<byte> routeStateKey,
        uint payloadLength,
        CancellationToken cancellationToken)
    {
        var owner = Exact(mailboxOwnerEd25519PublicKey, "owner key");
        var route = Exact(routeStateKey, "route key");
        var bytes = checked((long)ProductionMailboxOwnerControlConstants.ResponseHeaderLength +
            payloadLength);
        if (payloadLength > ProductionMailboxOwnerControlConstants.MaximumHistoryFrameBytes ||
            bytes > limits.MaximumGlobalBytes)
            throw new InvalidDataException("Owner-control delivery size is invalid.");
        var ownerKey = Convert.ToHexString(owner);
        var routeKey = Convert.ToHexString(route);
        var waitDeadline = timeProvider.GetUtcNow() + limits.AuthorizationReplayTimeout;
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Task wait;
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                if (globalCount < limits.MaximumGlobalCount &&
                    ownerCounts.GetValueOrDefault(ownerKey) < limits.MaximumPerOwnerCount &&
                    routeCounts.GetValueOrDefault(routeKey) < limits.MaximumPerRouteCount &&
                    globalBytes <= limits.MaximumGlobalBytes - bytes)
                {
                    globalCount++;
                    globalBytes = checked(globalBytes + bytes);
                    ownerCounts[ownerKey] = ownerCounts.GetValueOrDefault(ownerKey) + 1;
                    routeCounts[routeKey] = routeCounts.GetValueOrDefault(routeKey) + 1;
                    return new(this, ownerKey, routeKey, bytes,
                        timeProvider.GetUtcNow() + limits.LeaseLifetime);
                }
                wait = changed.Task;
            }
            finally { gate.Release(); }
            var remaining = waitDeadline - timeProvider.GetUtcNow();
            if (remaining <= TimeSpan.Zero)
                throw new TimeoutException("Owner-control delivery admission timed out.");
            await wait.WaitAsync(remaining, cancellationToken).ConfigureAwait(false);
        }
    }

    private async ValueTask ReleaseAsync(string owner, string route, long bytes)
    {
        await gate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (globalCount <= 0 || globalBytes < bytes ||
                !ownerCounts.TryGetValue(owner, out var ownerCount) || ownerCount <= 0 ||
                !routeCounts.TryGetValue(route, out var routeCount) || routeCount <= 0)
                throw new InvalidOperationException("Owner-control delivery lease is unbalanced.");
            globalCount--;
            globalBytes -= bytes;
            if (ownerCount == 1) ownerCounts.Remove(owner);
            else ownerCounts[owner] = ownerCount - 1;
            if (routeCount == 1) routeCounts.Remove(route);
            else routeCounts[route] = routeCount - 1;
            var signal = changed;
            changed = NewSignal();
            signal.TrySetResult();
        }
        finally { gate.Release(); }
    }

    private static TaskCompletionSource NewSignal() =>
        new(TaskCreationOptions.RunContinuationsAsynchronously);

    private static byte[] Exact(ReadOnlyMemory<byte> value, string name)
    {
        if (value.Length != 32 || value.Span.IndexOfAnyExcept((byte)0) < 0)
            throw new InvalidDataException($"Owner-control delivery {name} is invalid.");
        return value.ToArray();
    }

    internal sealed class ProductionMailboxOwnerControlDeliveryLease : IAsyncDisposable
    {
        private readonly ProductionMailboxOwnerControlDeliveryLeaseManager owner;
        private readonly string ownerKey;
        private readonly string routeKey;
        private readonly long bytes;
        private int disposed;

        internal ProductionMailboxOwnerControlDeliveryLease(
            ProductionMailboxOwnerControlDeliveryLeaseManager owner,
            string ownerKey, string routeKey, long bytes, DateTimeOffset expiresAt)
        {
            this.owner = owner;
            this.ownerKey = ownerKey;
            this.routeKey = routeKey;
            this.bytes = bytes;
            ExpiresAt = expiresAt;
        }

        internal DateTimeOffset ExpiresAt { get; }
        internal long ReservedBytes => bytes;

        internal bool HasRemainingWriteWindow() =>
            owner.timeProvider.GetUtcNow() + owner.limits.ResponseWriteTimeout <= ExpiresAt;

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref disposed, 1) == 0)
                await owner.ReleaseAsync(ownerKey, routeKey, bytes).ConfigureAwait(false);
        }
    }
}

internal sealed class ProductionMailboxOwnerControlDeliverySnapshot : IAsyncDisposable
{
    private readonly byte[] header;
    private readonly byte[] batch;
    private readonly byte[] checkpoint;
    private readonly ProductionMailboxOwnerControlDeliveryLeaseManager
        .ProductionMailboxOwnerControlDeliveryLease localLease;
    private readonly IProductionMailboxOwnerControlDeliveryLeaseStore durableStore;
    private readonly byte[] durableLeaseId;
    private readonly TimeSpan cleanupTimeout;
    private int disposed;

    internal ProductionMailboxOwnerControlDeliverySnapshot(ReadOnlySpan<byte> header,
        ReadOnlySpan<byte> batch, ReadOnlySpan<byte> checkpoint,
        ProductionMailboxOwnerControlDeliveryLeaseManager
            .ProductionMailboxOwnerControlDeliveryLease localLease,
        IProductionMailboxOwnerControlDeliveryLeaseStore durableStore,
        ReadOnlySpan<byte> durableLeaseId, TimeSpan cleanupTimeout)
    {
        if (header.Length != ProductionMailboxOwnerControlConstants.ResponseHeaderLength ||
            (batch.IsEmpty != checkpoint.IsEmpty) ||
            (!batch.IsEmpty && (batch.Length is < ProductionMailboxFrozenHistoryBatch
                    .MinimumBatchBytes or > ProductionMailboxFrozenHistoryBatch.MaximumBatchBytes ||
                checkpoint.Length != ProductionMailboxRouteContinuityConstants
                    .CanonicalRouteHistoryCheckpointLength)) ||
            durableLeaseId.Length != 16 || cleanupTimeout <= TimeSpan.Zero)
            throw new InvalidDataException("Owner-control delivery snapshot is invalid.");
        this.header = header.ToArray();
        this.batch = batch.ToArray();
        this.checkpoint = checkpoint.ToArray();
        this.localLease = localLease ?? throw new ArgumentNullException(nameof(localLease));
        this.durableStore = durableStore ?? throw new ArgumentNullException(nameof(durableStore));
        this.durableLeaseId = durableLeaseId.ToArray();
        this.cleanupTimeout = cleanupTimeout;
    }

    internal ReadOnlyMemory<byte> CanonicalHeader => header.ToArray();
    internal ReadOnlyMemory<byte> CanonicalRouteHistoryBatch => batch.ToArray();
    internal ReadOnlyMemory<byte> CanonicalRouteHistoryCheckpoint => checkpoint.ToArray();
    internal int ContentLength => checked(header.Length + batch.Length + checkpoint.Length);
    internal bool IsHistory => batch.Length != 0;

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        using var cleanup = new CancellationTokenSource(cleanupTimeout);
        Exception? failure = null;
        try
        {
            await durableStore.ReleaseDeliveryLeaseAsync(durableLeaseId, cleanup.Token)
                .ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        { failure = exception; }
        finally { await localLease.DisposeAsync().ConfigureAwait(false); }
        if (failure is not null)
            throw new InvalidOperationException("Durable delivery lease cleanup failed.", failure);
    }
}

public sealed partial class InMemoryProductionMailboxStateStore :
    IProductionMailboxOwnerControlDeliveryLeaseStore
{
    private readonly Dictionary<string, ProductionMailboxOwnerControlDurableDeliveryLease>
        ownerDeliveryLeases = new(StringComparer.Ordinal);

    async ValueTask<ProductionMailboxOwnerControlDurableDeliveryLease?>
        IProductionMailboxOwnerControlDeliveryLeaseStore.TryAcquireDeliveryLeaseAsync(
        ReadOnlyMemory<byte> mailboxOwnerEd25519PublicKey,
        ReadOnlyMemory<byte> routeStateKey, ReadOnlyMemory<byte> activeScope,
        long reservedBytes, ulong expiresAtUnixSeconds,
        CancellationToken cancellationToken)
    {
        var owner = DeliveryExact(mailboxOwnerEd25519PublicKey, 32, "owner key");
        var route = DeliveryExact(routeStateKey, 32, "route key");
        var scope = DeliveryExact(activeScope, 32, "active scope");
        await gate.WaitAsync(cancellationToken);
        try
        {
            var nowValue = timeProvider.GetUtcNow().ToUnixTimeSeconds();
            if (nowValue < 0) throw new InvalidDataException("Delivery lease time is invalid.");
            var now = checked((ulong)nowValue);
            GcDeliveryLeases(now);
            if (expiresAtUnixSeconds <= now ||
                reservedBytes < ProductionMailboxOwnerControlConstants.ResponseHeaderLength ||
                reservedBytes > ownerControlLimits.MaximumDeliveryLeaseBytes)
                throw new InvalidDataException("Delivery lease horizon or size is invalid.");
            var leases = ownerDeliveryLeases.Values.Select(RestoreDeliveryLease).ToArray();
            if (leases.Length >= ownerControlLimits.MaximumDeliveryLeasesGlobal ||
                leases.Count(value => DeliveryFixed(
                    value.MailboxOwnerEd25519PublicKey, owner)) >=
                    ownerControlLimits.MaximumDeliveryLeasesPerOwner ||
                leases.Count(value => DeliveryFixed(value.RouteStateKey, route)) >=
                    ownerControlLimits.MaximumDeliveryLeasesPerRoute ||
                leases.Sum(value => value.ReservedBytes) >
                    ownerControlLimits.MaximumDeliveryLeaseBytes - reservedBytes)
                return null;
            byte[] leaseId;
            string key;
            do
            {
                leaseId = RandomNumberGenerator.GetBytes(16);
                key = Convert.ToHexString(leaseId);
            } while (ownerDeliveryLeases.ContainsKey(key));
            var lease = ProductionMailboxOwnerControlDurableDeliveryLeaseIntegrity.Create(
                leaseId, owner, route, scope, reservedBytes, expiresAtUnixSeconds,
                v2PublicationIntegrityKey);
            ownerDeliveryLeases.Add(key, lease);
            return lease with
            {
                LeaseId = lease.LeaseId.ToArray(),
                MailboxOwnerEd25519PublicKey = lease.MailboxOwnerEd25519PublicKey.ToArray(),
                RouteStateKey = lease.RouteStateKey.ToArray(),
                ActiveScope = lease.ActiveScope.ToArray(),
                IntegrityTag = lease.IntegrityTag.ToArray()
            };
        }
        finally { gate.Release(); }
    }

    async ValueTask IProductionMailboxOwnerControlDeliveryLeaseStore.ReleaseDeliveryLeaseAsync(
        ReadOnlyMemory<byte> leaseId, CancellationToken cancellationToken)
    {
        var id = DeliveryExact(leaseId, 16, "lease ID");
        await gate.WaitAsync(cancellationToken);
        try
        {
            var key = Convert.ToHexString(id);
            if (!ownerDeliveryLeases.TryGetValue(key, out var stored)) return;
            _ = RestoreDeliveryLease(stored);
            ownerDeliveryLeases.Remove(key);
        }
        finally { gate.Release(); }
    }

    private void GcDeliveryLeases(ulong now)
    {
        foreach (var key in ownerDeliveryLeases.Where(pair =>
                     pair.Value.ExpiresAtUnixSeconds <= now)
                 .Take(ownerControlLimits.MaximumGcBatch)
                 .Select(pair => pair.Key).ToArray())
        {
            var value = RestoreDeliveryLease(ownerDeliveryLeases[key]);
            if (value.ExpiresAtUnixSeconds <= now) ownerDeliveryLeases.Remove(key);
        }
    }

    private ProductionMailboxOwnerControlDurableDeliveryLease RestoreDeliveryLease(
        ProductionMailboxOwnerControlDurableDeliveryLease value) =>
        ProductionMailboxOwnerControlDurableDeliveryLeaseIntegrity.Restore(value.LeaseId,
            value.MailboxOwnerEd25519PublicKey, value.RouteStateKey, value.ActiveScope,
            value.ReservedBytes, value.ExpiresAtUnixSeconds, value.IntegrityTag,
            v2PublicationIntegrityKey);

    private static byte[] DeliveryExact(ReadOnlyMemory<byte> value, int length, string name)
    {
        if (value.Length != length || value.Span.IndexOfAnyExcept((byte)0) < 0)
            throw new InvalidDataException($"Owner-control delivery {name} is invalid.");
        return value.ToArray();
    }

    private static bool DeliveryFixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}

public sealed partial class PostgreSqlProductionMailboxStateStore :
    IProductionMailboxOwnerControlDeliveryLeaseStore
{
    private readonly SemaphoreSlim ownerDeliveryInitializeGate = new(1, 1);
    private volatile bool ownerDeliveryInitialized;

    async ValueTask<ProductionMailboxOwnerControlDurableDeliveryLease?>
        IProductionMailboxOwnerControlDeliveryLeaseStore.TryAcquireDeliveryLeaseAsync(
        ReadOnlyMemory<byte> mailboxOwnerEd25519PublicKey,
        ReadOnlyMemory<byte> routeStateKey, ReadOnlyMemory<byte> activeScope,
        long reservedBytes, ulong expiresAtUnixSeconds,
        CancellationToken cancellationToken)
    {
        var owner = PgDeliveryExact(mailboxOwnerEd25519PublicKey, 32, "owner key");
        var route = PgDeliveryExact(routeStateKey, 32, "route key");
        var scope = PgDeliveryExact(activeScope, 32, "active scope");
        await using var connection = await OpenAsync(cancellationToken);
        await EnsureOwnerDeliverySchemaAsync(connection, cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(
            IsolationLevel.ReadCommitted, cancellationToken);
        await ConfigureOwnerControlTransactionAsync(connection, transaction, cancellationToken);
        await AdvisoryLockAsync(connection, transaction, route, cancellationToken);
        await AdvisoryLockAsync(connection, transaction,
            SHA256.HashData("Deep/registry/production-mailbox/owner-control/delivery-capacity/v1"u8),
            cancellationToken);
        var dbNow = await OwnerDbNowAsync(connection, transaction, cancellationToken);
        if (expiresAtUnixSeconds <= dbNow ||
            reservedBytes < ProductionMailboxOwnerControlConstants.ResponseHeaderLength ||
            reservedBytes > ownerControlLimits.MaximumDeliveryLeaseBytes)
            throw new InvalidDataException("Delivery lease horizon or size is invalid.");
        await GcPgDeliveryLeasesAsync(connection, transaction, dbNow, cancellationToken);
        var leases = await ReadPgDeliveryLeasesAsync(connection, transaction,
            ownerControlLimits.MaximumDeliveryLeasesGlobal + 1, cancellationToken);
        if (leases.Count >= ownerControlLimits.MaximumDeliveryLeasesGlobal ||
            leases.Count(value => PgDeliveryFixed(
                value.MailboxOwnerEd25519PublicKey, owner)) >=
                ownerControlLimits.MaximumDeliveryLeasesPerOwner ||
            leases.Count(value => PgDeliveryFixed(value.RouteStateKey, route)) >=
                ownerControlLimits.MaximumDeliveryLeasesPerRoute ||
            leases.Sum(value => value.ReservedBytes) >
                ownerControlLimits.MaximumDeliveryLeaseBytes - reservedBytes)
        {
            await transaction.CommitAsync(cancellationToken);
            return null;
        }
        var lease = ProductionMailboxOwnerControlDurableDeliveryLeaseIntegrity.Create(
            RandomNumberGenerator.GetBytes(16), owner, route, scope, reservedBytes,
            expiresAtUnixSeconds, v2PreparedIntegrityKey);
        await InsertPgDeliveryLeaseAsync(connection, transaction, lease, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return lease;
    }

    async ValueTask IProductionMailboxOwnerControlDeliveryLeaseStore.ReleaseDeliveryLeaseAsync(
        ReadOnlyMemory<byte> leaseId, CancellationToken cancellationToken)
    {
        var id = PgDeliveryExact(leaseId, 16, "lease ID");
        await using var connection = await OpenAsync(cancellationToken);
        await EnsureOwnerDeliverySchemaAsync(connection, cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(
            IsolationLevel.ReadCommitted, cancellationToken);
        await ConfigureOwnerControlTransactionAsync(connection, transaction, cancellationToken);
        await AdvisoryLockAsync(connection, transaction,
            SHA256.HashData("Deep/registry/production-mailbox/owner-control/delivery-capacity/v1"u8),
            cancellationToken);
        var stored = await ReadPgDeliveryLeaseAsync(connection, transaction, id,
            cancellationToken);
        if (stored is not null)
        {
            await using var delete = new NpgsqlCommand(
                "DELETE FROM production_mailbox_owner_delivery_leases_v1 WHERE lease_id=@id",
                connection, transaction);
            delete.Parameters.AddWithValue("id", id);
            if (await delete.ExecuteNonQueryAsync(cancellationToken) != 1)
                throw new InvalidDataException("Delivery lease release CAS failed.");
        }
        await transaction.CommitAsync(cancellationToken);
    }

    private async ValueTask EnsureOwnerDeliverySchemaAsync(NpgsqlConnection connection,
        CancellationToken cancellationToken)
    {
        if (ownerDeliveryInitialized) return;
        await ownerDeliveryInitializeGate.WaitAsync(cancellationToken);
        try
        {
            if (ownerDeliveryInitialized) return;
            await using var command = new NpgsqlCommand("""
                CREATE TABLE IF NOT EXISTS production_mailbox_owner_delivery_leases_v1(
                    lease_id bytea PRIMARY KEY CHECK(octet_length(lease_id)=16),
                    mailbox_owner_key bytea NOT NULL CHECK(octet_length(mailbox_owner_key)=32),
                    route_state_key bytea NOT NULL CHECK(octet_length(route_state_key)=32),
                    active_scope bytea NOT NULL CHECK(octet_length(active_scope)=32),
                    reserved_bytes bigint NOT NULL CHECK(reserved_bytes BETWEEN 384 AND 8395152),
                    expires_at bytea NOT NULL CHECK(octet_length(expires_at)=8),
                    integrity_tag bytea NOT NULL CHECK(octet_length(integrity_tag)=32)
                );
                CREATE INDEX IF NOT EXISTS production_mailbox_owner_delivery_route
                    ON production_mailbox_owner_delivery_leases_v1(route_state_key);
                CREATE INDEX IF NOT EXISTS production_mailbox_owner_delivery_owner
                    ON production_mailbox_owner_delivery_leases_v1(mailbox_owner_key);
                """, connection);
            await command.ExecuteNonQueryAsync(cancellationToken);
            ownerDeliveryInitialized = true;
        }
        finally { ownerDeliveryInitializeGate.Release(); }
    }

    private async ValueTask GcPgDeliveryLeasesAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, ulong dbNow, CancellationToken cancellationToken)
    {
        var ids = new List<byte[]>();
        await using (var command = new NpgsqlCommand("""
            SELECT lease_id FROM production_mailbox_owner_delivery_leases_v1
            WHERE expires_at<=@now ORDER BY expires_at,lease_id LIMIT @limit FOR UPDATE
            """, connection, transaction))
        {
            command.Parameters.AddWithValue("now", PgDeliveryU64(dbNow));
            command.Parameters.AddWithValue("limit", ownerControlLimits.MaximumGcBatch);
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
                ids.Add(reader.GetFieldValue<byte[]>(0));
        }
        foreach (var id in ids)
        {
            var value = await ReadPgDeliveryLeaseAsync(connection, transaction, id,
                cancellationToken) ?? throw new InvalidDataException(
                    "Delivery lease disappeared during authenticated GC.");
            if (value.ExpiresAtUnixSeconds > dbNow) continue;
            await using var delete = new NpgsqlCommand(
                "DELETE FROM production_mailbox_owner_delivery_leases_v1 WHERE lease_id=@id",
                connection, transaction);
            delete.Parameters.AddWithValue("id", id);
            await delete.ExecuteNonQueryAsync(cancellationToken);
        }
    }

    private async ValueTask<List<ProductionMailboxOwnerControlDurableDeliveryLease>>
        ReadPgDeliveryLeasesAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, int limit, CancellationToken cancellationToken)
    {
        var result = new List<ProductionMailboxOwnerControlDurableDeliveryLease>();
        await using var command = new NpgsqlCommand("""
            SELECT lease_id FROM production_mailbox_owner_delivery_leases_v1
            ORDER BY lease_id LIMIT @limit FOR UPDATE
            """, connection, transaction);
        command.Parameters.AddWithValue("limit", limit);
        var ids = new List<byte[]>();
        await using (var reader = await command.ExecuteReaderAsync(cancellationToken))
            while (await reader.ReadAsync(cancellationToken))
                ids.Add(reader.GetFieldValue<byte[]>(0));
        foreach (var id in ids)
            result.Add(await ReadPgDeliveryLeaseAsync(connection, transaction, id,
                cancellationToken) ?? throw new InvalidDataException(
                    "Delivery lease disappeared during capacity scan."));
        return result;
    }

    private async ValueTask<ProductionMailboxOwnerControlDurableDeliveryLease?>
        ReadPgDeliveryLeaseAsync(NpgsqlConnection connection, NpgsqlTransaction transaction,
        ReadOnlyMemory<byte> leaseId, CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand("""
            SELECT lease_id,mailbox_owner_key,route_state_key,active_scope,reserved_bytes,
                   expires_at,integrity_tag
            FROM production_mailbox_owner_delivery_leases_v1
            WHERE lease_id=@id FOR UPDATE
            """, connection, transaction);
        command.Parameters.AddWithValue("id", leaseId.ToArray());
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken)) return null;
        return ProductionMailboxOwnerControlDurableDeliveryLeaseIntegrity.Restore(
            reader.GetFieldValue<byte[]>(0), reader.GetFieldValue<byte[]>(1),
            reader.GetFieldValue<byte[]>(2), reader.GetFieldValue<byte[]>(3),
            reader.GetInt64(4), PgDeliveryReadU64(reader.GetFieldValue<byte[]>(5)),
            reader.GetFieldValue<byte[]>(6), v2PreparedIntegrityKey);
    }

    private static async ValueTask InsertPgDeliveryLeaseAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        ProductionMailboxOwnerControlDurableDeliveryLease value,
        CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand("""
            INSERT INTO production_mailbox_owner_delivery_leases_v1(
                lease_id,mailbox_owner_key,route_state_key,active_scope,reserved_bytes,
                expires_at,integrity_tag)
            VALUES(@id,@owner,@route,@scope,@bytes,@expires,@tag)
            """, connection, transaction);
        command.Parameters.AddWithValue("id", value.LeaseId);
        command.Parameters.AddWithValue("owner", value.MailboxOwnerEd25519PublicKey);
        command.Parameters.AddWithValue("route", value.RouteStateKey);
        command.Parameters.AddWithValue("scope", value.ActiveScope);
        command.Parameters.AddWithValue("bytes", value.ReservedBytes);
        command.Parameters.AddWithValue("expires", PgDeliveryU64(value.ExpiresAtUnixSeconds));
        command.Parameters.AddWithValue("tag", value.IntegrityTag);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static byte[] PgDeliveryExact(ReadOnlyMemory<byte> value, int length, string name)
    {
        if (value.Length != length || value.Span.IndexOfAnyExcept((byte)0) < 0)
            throw new InvalidDataException($"Owner-control delivery {name} is invalid.");
        return value.ToArray();
    }

    private static byte[] PgDeliveryU64(ulong value)
    {
        var result = new byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(result, value);
        return result;
    }

    private static ulong PgDeliveryReadU64(ReadOnlySpan<byte> value)
    {
        if (value.Length != 8) throw new InvalidDataException("Delivery lease u64 is invalid.");
        return System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(value);
    }

    private static bool PgDeliveryFixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}
