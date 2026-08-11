using System.Security.Cryptography;
using System.Data;
using Deep.Protocol.DeepExtension.MailboxTopology;
using Npgsql;

namespace Deep.Registry.Api.ProductionMailbox;

internal sealed record ProductionMailboxOwnerRequestV2Result(
    ProductionMailboxOwnerRequestStatus Status,
    ProductionMailboxProtectedOwnerRequestV2? Record);

internal sealed record ProductionMailboxOwnerRequestV2PlanResult(
    ProductionMailboxOwnerRequestStatus Status,
    ulong IssuedAtUnixSeconds,
    ulong ExpiresAtUnixSeconds,
    ProductionMailboxProtectedOwnerRequestV2? Record);

internal interface IProductionMailboxOwnerRequestV2StateStore
{
    ValueTask<ProductionMailboxOwnerRequestV2Result> PrepareOwnerRequestV2Async(
        ReadOnlyMemory<byte> routeStateKey,
        ReadOnlyMemory<byte> activeScope,
        ProductionMailboxRouteHistoryLookupRequest lookupRequest,
        ReadOnlyMemory<byte> expectedSourceFingerprint,
        VerifiedProductionMailboxOwnerControlRequest request,
        ulong retainUntilUnixSeconds,
        ulong nowUnixSeconds,
        CancellationToken cancellationToken);

    ValueTask<ProductionMailboxOwnerRequestV2PlanResult> PlanOwnerRequestV2Async(
        ReadOnlyMemory<byte> routeStateKey,
        ReadOnlyMemory<byte> activeScope,
        ProductionMailboxRouteHistoryLookupRequest lookupRequest,
        VerifiedProductionMailboxOwnerControlRequest request,
        ulong nowUnixSeconds,
        CancellationToken cancellationToken);

    ValueTask<ProductionMailboxOwnerRequestV2Result> RecordOwnerRequestV2Async(
        ReadOnlyMemory<byte> routeStateKey,
        ReadOnlyMemory<byte> activeScope,
        ProductionMailboxRouteHistoryLookupRequest lookupRequest,
        VerifiedProductionMailboxOwnerControlRequest request,
        ReadOnlyMemory<byte> canonicalResponseHeader,
        ReadOnlyMemory<byte> canonicalResponseHash,
        ulong nowUnixSeconds,
        CancellationToken cancellationToken);
}

public sealed partial class InMemoryProductionMailboxStateStore :
    IProductionMailboxOwnerRequestV2StateStore
{
    private readonly Dictionary<string, ProductionMailboxProtectedOwnerRequestV2>
        ownerControlRequestsV2 = new(StringComparer.Ordinal);
    private readonly Dictionary<string, ProductionMailboxProtectedOwnerRequestAliasV2>
        ownerControlRequestIdsV2 = new(StringComparer.Ordinal);

    async ValueTask<ProductionMailboxOwnerRequestV2Result>
        IProductionMailboxOwnerRequestV2StateStore.PrepareOwnerRequestV2Async(
        ReadOnlyMemory<byte> routeStateKey,
        ReadOnlyMemory<byte> activeScope,
        ProductionMailboxRouteHistoryLookupRequest lookupRequest,
        ReadOnlyMemory<byte> expectedSourceFingerprint,
        VerifiedProductionMailboxOwnerControlRequest request,
        ulong retainUntilUnixSeconds,
        ulong nowUnixSeconds,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(lookupRequest);
        ArgumentNullException.ThrowIfNull(request);
        var route = ProductionMailboxRouteContinuityStateGuard.FreezeKey(routeStateKey);
        var scope = V2Exact(activeScope, 32, "active scope");
        var expectedFingerprint = V2Exact(expectedSourceFingerprint, 32,
            "source fingerprint");
        var decoded = ProductionMailboxOwnerControlTransportCodec.DecodeRequest(
            request.CanonicalBytes.Span);
        var requestId = V2Exact(decoded.RequestId, 32, "request ID");
        var requestHash = V2Exact(request.CanonicalHash, 32, "request hash");
        if (nowUnixSeconds is 0 or ulong.MaxValue ||
            retainUntilUnixSeconds < request.ExpiresAtUnixSeconds ||
            retainUntilUnixSeconds == ulong.MaxValue)
            throw new InvalidDataException("Owner request v2 admission time is invalid.");

        await gate.WaitAsync(cancellationToken);
        try
        {
            AuthenticatedOwnerControlGc(nowUnixSeconds);
            if (HasLiveOrCorruptOwnerRequestV1(route, requestId, requestHash,
                    nowUnixSeconds, out var legacyStatus))
                return new(legacyStatus, null);
            var aliasKey = EnrollmentRequestKey(route, requestId);
            var aliasExists = false;
            if (ownerControlRequestIdsV2.TryGetValue(aliasKey, out var existingAlias))
            {
                aliasExists = true;
                var restoredAlias = RestoreV2Alias(existingAlias);
                if (!V2Fixed(restoredAlias.RequestHash.Span, requestHash))
                    return new(ProductionMailboxOwnerRequestStatus.Conflict, null);
                if (nowUnixSeconds >= restoredAlias.ExpiresAtUnixSeconds)
                    return new(ProductionMailboxOwnerRequestStatus.Stale, null);
            }
            var scopeKey = Convert.ToHexString(scope);
            if (ownerControlRequestsV2.TryGetValue(scopeKey, out var existing))
            {
                var restored = RestoreV2(existing);
                if (!V2Fixed(restored.RouteStateKey.Span, route) ||
                    !V2Fixed(restored.RequestHash.Span, requestHash) ||
                    !V2Fixed(restored.SourceFingerprint.Span, expectedFingerprint))
                    return new(ProductionMailboxOwnerRequestStatus.Conflict, null);
                if (restored.TerminalRevoked)
                    return new(ProductionMailboxOwnerRequestStatus.Revoked, null);
                if (nowUnixSeconds >= restored.RequestExpiresAtUnixSeconds)
                    return new(ProductionMailboxOwnerRequestStatus.Stale, null);
                return new(restored.Phase >= ProductionMailboxOwnerRequestV2Phase.Signed
                    ? ProductionMailboxOwnerRequestStatus.ExactReplay
                    : ProductionMailboxOwnerRequestStatus.Prepared, restored);
            }
            if (aliasExists)
                return new(ProductionMailboxOwnerRequestStatus.Conflict, null);

            var lookup = LookupHistoryUnderGate(route, lookupRequest);
            if (lookup.Status is not (ProductionMailboxRouteHistoryLookupStatus.History or
                    ProductionMailboxRouteHistoryLookupStatus.HeadNoChange) ||
                lookup.Lookup is null || !V2Fixed(expectedFingerprint,
                    lookup.Lookup.RouteLocalSourceFingerprint.Span))
                return new(ProductionMailboxOwnerRequestStatus.Conflict, null);

            var reference = lookup.Status == ProductionMailboxRouteHistoryLookupStatus.History
                ? ProductionMailboxProtectedHistoryResponseReference.Create(route,
                    decoded.CurrentRouteHistoryCheckpointHash.Span, lookup.Lookup,
                    v2PublicationIntegrityKey)
                : null;
            if (!EnsureOwnerControlCapacity(route, nowUnixSeconds, 2,
                    ProductionMailboxOwnerControlAccounting.NewOwnerRequestV2Bytes,
                    runGc: false))
                return new(ProductionMailboxOwnerRequestStatus.Conflict, null);
            var alias = ProductionMailboxProtectedOwnerRequestAliasV2.Create(route, requestId,
                requestHash, request.ExpiresAtUnixSeconds, retainUntilUnixSeconds,
                v2PublicationIntegrityKey);
            var created = ProductionMailboxProtectedOwnerRequestV2.CreatePrepared(route, scope,
                request, lookup.Lookup, reference, v2PublicationIntegrityKey);
            ownerControlRequestIdsV2.Add(aliasKey, alias);
            ownerControlRequestsV2.Add(scopeKey, created);
            return new(ProductionMailboxOwnerRequestStatus.Prepared, created);
        }
        finally { gate.Release(); }
    }

    async ValueTask<ProductionMailboxOwnerRequestV2PlanResult>
        IProductionMailboxOwnerRequestV2StateStore.PlanOwnerRequestV2Async(
        ReadOnlyMemory<byte> routeStateKey,
        ReadOnlyMemory<byte> activeScope,
        ProductionMailboxRouteHistoryLookupRequest lookupRequest,
        VerifiedProductionMailboxOwnerControlRequest request,
        ulong nowUnixSeconds,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(lookupRequest);
        ArgumentNullException.ThrowIfNull(request);
        var route = ProductionMailboxRouteContinuityStateGuard.FreezeKey(routeStateKey);
        var scope = V2Exact(activeScope, 32, "active scope");
        await gate.WaitAsync(cancellationToken);
        try
        {
            var scopeKey = Convert.ToHexString(scope);
            if (!ownerControlRequestsV2.TryGetValue(scopeKey, out var stored))
                return new(ProductionMailboxOwnerRequestStatus.MissingState, 0, 0, null);
            var current = RestoreV2(stored);
            if (!V2Fixed(current.RouteStateKey.Span, route) ||
                !V2Fixed(current.RequestHash.Span, request.CanonicalHash.Span))
                return new(ProductionMailboxOwnerRequestStatus.Conflict, 0, 0, null);
            if (current.TerminalRevoked)
                return new(ProductionMailboxOwnerRequestStatus.Revoked, 0, 0, null);
            if (nowUnixSeconds >= current.RequestExpiresAtUnixSeconds)
                return new(ProductionMailboxOwnerRequestStatus.Stale, 0, 0, null);
            if (!SourceStillValidUnderGate(route, lookupRequest, current))
                return new(ProductionMailboxOwnerRequestStatus.Conflict, 0, 0, null);
            if (current.Phase >= ProductionMailboxOwnerRequestV2Phase.Planned)
                return new(ProductionMailboxOwnerRequestStatus.Prepared,
                    current.PlannedIssuedAtUnixSeconds!.Value,
                    current.PlannedExpiresAtUnixSeconds!.Value, current);
            var expires = Math.Min(current.RequestExpiresAtUnixSeconds,
                checked(nowUnixSeconds + ProductionMailboxOwnerControlConstants
                    .MaximumMessageLifetimeSeconds));
            if (expires <= nowUnixSeconds)
                return new(ProductionMailboxOwnerRequestStatus.Stale, 0, 0, null);
            var planned = current.Plan(nowUnixSeconds, expires, v2PublicationIntegrityKey);
            ownerControlRequestsV2[scopeKey] = planned;
            return new(ProductionMailboxOwnerRequestStatus.Prepared, nowUnixSeconds,
                expires, planned);
        }
        finally { gate.Release(); }
    }

    async ValueTask<ProductionMailboxOwnerRequestV2Result>
        IProductionMailboxOwnerRequestV2StateStore.RecordOwnerRequestV2Async(
        ReadOnlyMemory<byte> routeStateKey,
        ReadOnlyMemory<byte> activeScope,
        ProductionMailboxRouteHistoryLookupRequest lookupRequest,
        VerifiedProductionMailboxOwnerControlRequest request,
        ReadOnlyMemory<byte> canonicalResponseHeader,
        ReadOnlyMemory<byte> canonicalResponseHash,
        ulong nowUnixSeconds,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(lookupRequest);
        ArgumentNullException.ThrowIfNull(request);
        var route = ProductionMailboxRouteContinuityStateGuard.FreezeKey(routeStateKey);
        var scope = V2Exact(activeScope, 32, "active scope");
        var header = V2Exact(canonicalResponseHeader,
            ProductionMailboxOwnerControlConstants.ResponseHeaderLength, "response header",
            allowZero: true);
        var responseHash = V2Exact(canonicalResponseHash, 32, "response hash");
        await gate.WaitAsync(cancellationToken);
        try
        {
            var scopeKey = Convert.ToHexString(scope);
            if (!ownerControlRequestsV2.TryGetValue(scopeKey, out var stored))
                return new(ProductionMailboxOwnerRequestStatus.MissingState, null);
            var current = RestoreV2(stored);
            if (!V2Fixed(current.RouteStateKey.Span, route) ||
                !V2Fixed(current.RequestHash.Span, request.CanonicalHash.Span))
                return new(ProductionMailboxOwnerRequestStatus.Conflict, null);
            if (current.TerminalRevoked)
                return new(ProductionMailboxOwnerRequestStatus.Revoked, null);
            if (nowUnixSeconds >= current.RequestExpiresAtUnixSeconds ||
                current.PlannedExpiresAtUnixSeconds is null ||
                nowUnixSeconds >= current.PlannedExpiresAtUnixSeconds)
                return new(ProductionMailboxOwnerRequestStatus.Stale, null);
            if (!SourceStillValidUnderGate(route, lookupRequest, current))
                return new(ProductionMailboxOwnerRequestStatus.Conflict, null);
            if (current.Phase >= ProductionMailboxOwnerRequestV2Phase.Signed)
                return new(V2Fixed(current.ResponseHeader.Span, header) &&
                    V2Fixed(current.ResponseHash.Span, responseHash)
                        ? ProductionMailboxOwnerRequestStatus.ExactReplay
                        : ProductionMailboxOwnerRequestStatus.Conflict, current);
            var signed = current.RecordSigned(header, responseHash,
                v2PublicationIntegrityKey);
            ownerControlRequestsV2[scopeKey] = signed;
            return new(ProductionMailboxOwnerRequestStatus.Prepared, signed);
        }
        finally { gate.Release(); }
    }

    private bool SourceStillValidUnderGate(ReadOnlySpan<byte> route,
        ProductionMailboxRouteHistoryLookupRequest lookupRequest,
        ProductionMailboxProtectedOwnerRequestV2 current)
    {
        var lookup = LookupHistoryUnderGate(route, lookupRequest);
        return lookup.Lookup is not null && lookup.Status is
                ProductionMailboxRouteHistoryLookupStatus.History or
                ProductionMailboxRouteHistoryLookupStatus.HeadNoChange &&
            V2Fixed(lookup.Lookup.RouteLocalSourceFingerprint.Span,
                current.SourceFingerprint.Span);
    }

    private bool HasLiveOrCorruptOwnerRequestV1(ReadOnlySpan<byte> route,
        ReadOnlySpan<byte> requestId, ReadOnlySpan<byte> requestHash,
        ulong nowUnixSeconds, out ProductionMailboxOwnerRequestStatus status)
    {
        var ownedRoute = route.ToArray();
        foreach (var value in ownerControlRequests.Values.Where(value =>
                     V2Fixed(value.RouteStateKey, ownedRoute)))
        {
            VerifyRequestTag(value);
            if (nowUnixSeconds < value.ExpiresAtUnixSeconds)
            {
                status = ProductionMailboxOwnerRequestStatus.Conflict;
                return true;
            }
        }
        var aliasKey = EnrollmentRequestKey(route, requestId);
        if (ownerControlRequestIds.TryGetValue(aliasKey, out var alias))
        {
            VerifyOwnerRequestAliasTag(alias);
            status = V2Fixed(alias.RequestHash, requestHash)
                ? ProductionMailboxOwnerRequestStatus.Stale
                : ProductionMailboxOwnerRequestStatus.Conflict;
            return true;
        }
        status = default;
        return false;
    }

    private ProductionMailboxProtectedOwnerRequestV2 RestoreV2(
        ProductionMailboxProtectedOwnerRequestV2 value) =>
        ProductionMailboxProtectedOwnerRequestV2.Restore(value.RouteStateKey.Span,
            value.ActiveScope.Span, value.CanonicalRequest.Span, value.RequestHash.Span,
            value.SourceKind, value.SourceFingerprint.Span, value.RequestExpiresAtUnixSeconds,
            value.PlannedIssuedAtUnixSeconds, value.PlannedExpiresAtUnixSeconds,
            value.HistoryReference.Span, value.HistoryReferenceTag.Span,
            value.ResponseHeader.Span, value.ResponseHash.Span, value.Phase,
            value.CanonicalTerminalRevocation.Span, value.TerminalRevocationHash.Span,
            value.IntegrityTag.Span, v2PublicationIntegrityKey);

    private ProductionMailboxProtectedOwnerRequestAliasV2 RestoreV2Alias(
        ProductionMailboxProtectedOwnerRequestAliasV2 value) =>
        ProductionMailboxProtectedOwnerRequestAliasV2.Restore(value.RouteStateKey.Span,
            value.RequestId.Span, value.RequestHash.Span, value.ExpiresAtUnixSeconds,
            value.RetainUntilUnixSeconds, value.IntegrityTag.Span,
            v2PublicationIntegrityKey);

    private void AuthenticatedOwnerRequestV2Gc(ulong nowUnixSeconds)
    {
        var removed = 0;
        foreach (var key in ownerControlRequestsV2.Where(pair =>
                     nowUnixSeconds >= pair.Value.RequestExpiresAtUnixSeconds)
                 .Take(ownerControlLimits.MaximumGcBatch)
                 .Select(pair => pair.Key).ToArray())
        {
            var value = RestoreV2(ownerControlRequestsV2[key]);
            if (nowUnixSeconds >= value.RequestExpiresAtUnixSeconds)
            {
                ownerControlRequestsV2.Remove(key);
                removed++;
            }
        }
        foreach (var key in ownerControlRequestIdsV2.Where(pair =>
                     nowUnixSeconds >= pair.Value.RetainUntilUnixSeconds)
                 .Take(Math.Max(0, ownerControlLimits.MaximumGcBatch - removed))
                 .Select(pair => pair.Key).ToArray())
        {
            var value = RestoreV2Alias(ownerControlRequestIdsV2[key]);
            if (nowUnixSeconds >= value.RetainUntilUnixSeconds)
                ownerControlRequestIdsV2.Remove(key);
        }
    }

    private static byte[] V2Exact(ReadOnlyMemory<byte> value, int length, string name,
        bool allowZero = false)
    {
        if (value.Length != length || (!allowZero &&
            value.Span.IndexOfAnyExcept((byte)0) < 0))
            throw new InvalidDataException($"Owner request v2 {name} is invalid.");
        return value.ToArray();
    }

    private static bool V2Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}

public sealed partial class PostgreSqlProductionMailboxStateStore :
    IProductionMailboxOwnerRequestV2StateStore
{
    private readonly SemaphoreSlim ownerRequestV2InitializeGate = new(1, 1);
    private volatile bool ownerRequestV2Initialized;

    async ValueTask<ProductionMailboxOwnerRequestV2Result>
        IProductionMailboxOwnerRequestV2StateStore.PrepareOwnerRequestV2Async(
        ReadOnlyMemory<byte> routeStateKey, ReadOnlyMemory<byte> activeScope,
        ProductionMailboxRouteHistoryLookupRequest lookupRequest,
        ReadOnlyMemory<byte> expectedSourceFingerprint,
        VerifiedProductionMailboxOwnerControlRequest request,
        ulong retainUntilUnixSeconds, ulong nowUnixSeconds,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(lookupRequest);
        ArgumentNullException.ThrowIfNull(request);
        var route = ProductionMailboxRouteContinuityStateGuard.FreezeKey(routeStateKey);
        var scope = PgV2Exact(activeScope, 32, "active scope");
        var fingerprint = PgV2Exact(expectedSourceFingerprint, 32, "source fingerprint");
        var decoded = ProductionMailboxOwnerControlTransportCodec.DecodeRequest(
            request.CanonicalBytes.Span);
        var requestId = PgV2Exact(decoded.RequestId, 32, "request ID");
        var requestHash = PgV2Exact(request.CanonicalHash, 32, "request hash");
        if (retainUntilUnixSeconds < request.ExpiresAtUnixSeconds ||
            retainUntilUnixSeconds == ulong.MaxValue || nowUnixSeconds is 0 or ulong.MaxValue)
            throw new InvalidDataException("Owner request v2 admission time is invalid.");

        await using var connection = await OpenAsync(cancellationToken);
        await EnsureOwnerControlSchemaAsync(connection, cancellationToken);
        await EnsureRouteHistorySchemaAsync(connection, cancellationToken);
        await EnsureOwnerRequestV2SchemaAsync(connection, cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(
            IsolationLevel.ReadCommitted, cancellationToken);
        await ConfigureOwnerControlTransactionAsync(connection, transaction, cancellationToken);
        await AdvisoryLockAsync(connection, transaction, route, cancellationToken);
        var dbNow = await OwnerDbNowAsync(connection, transaction, cancellationToken);
        if (await PgV1QuarantinesAsync(connection, transaction, route, requestId,
                requestHash, dbNow, cancellationToken) is { } legacyStatus)
        {
            await transaction.CommitAsync(cancellationToken);
            return new(legacyStatus, null);
        }
        var alias = await ReadOwnerRequestAliasV2Async(connection, transaction, route,
            requestId, cancellationToken);
        if (alias is not null)
        {
            if (!PgV2Fixed(alias.RequestHash.Span, requestHash))
            {
                await transaction.CommitAsync(cancellationToken);
                return new(ProductionMailboxOwnerRequestStatus.Conflict, null);
            }
            if (dbNow >= alias.ExpiresAtUnixSeconds)
            {
                await transaction.CommitAsync(cancellationToken);
                return new(ProductionMailboxOwnerRequestStatus.Stale, null);
            }
        }
        var existing = await ReadOwnerRequestV2Async(connection, transaction, scope,
            cancellationToken);
        if (existing is not null)
        {
            if (!PgV2Fixed(existing.RouteStateKey.Span, route) ||
                !PgV2Fixed(existing.RequestHash.Span, requestHash) ||
                !PgV2Fixed(existing.SourceFingerprint.Span, fingerprint))
            {
                await transaction.CommitAsync(cancellationToken);
                return new(ProductionMailboxOwnerRequestStatus.Conflict, null);
            }
            var status = existing.TerminalRevoked
                ? ProductionMailboxOwnerRequestStatus.Revoked
                : dbNow >= existing.RequestExpiresAtUnixSeconds
                    ? ProductionMailboxOwnerRequestStatus.Stale
                    : existing.Phase >= ProductionMailboxOwnerRequestV2Phase.Signed
                        ? ProductionMailboxOwnerRequestStatus.ExactReplay
                        : ProductionMailboxOwnerRequestStatus.Prepared;
            await transaction.CommitAsync(cancellationToken);
            return new(status, status is ProductionMailboxOwnerRequestStatus.Prepared or
                ProductionMailboxOwnerRequestStatus.ExactReplay ? existing : null);
        }
        if (alias is not null)
        {
            await transaction.CommitAsync(cancellationToken);
            return new(ProductionMailboxOwnerRequestStatus.Conflict, null);
        }
        var current = await ReadRouteContinuityAsync(connection, transaction, route, true,
            cancellationToken);
        if (current is null)
        {
            await transaction.CommitAsync(cancellationToken);
            return new(ProductionMailboxOwnerRequestStatus.MissingState, null);
        }
        if (current.OwnerRevocationGeneration != 0)
        {
            await transaction.CommitAsync(cancellationToken);
            return new(ProductionMailboxOwnerRequestStatus.Revoked, null);
        }
        var lookup = await ReadHistoryLookupAsync(connection, transaction, route, current,
            lookupRequest, cancellationToken);
        if (lookup.Lookup is null || lookup.Status is not
                (ProductionMailboxRouteHistoryLookupStatus.History or
                ProductionMailboxRouteHistoryLookupStatus.HeadNoChange) ||
            !PgV2Fixed(lookup.Lookup.RouteLocalSourceFingerprint.Span, fingerprint))
        {
            await transaction.CommitAsync(cancellationToken);
            return new(ProductionMailboxOwnerRequestStatus.Conflict, null);
        }
        if (!await OwnerControlCapacityAvailableAsync(connection, transaction, route, dbNow,
                2, ProductionMailboxOwnerControlAccounting.NewOwnerRequestV2Bytes,
                cancellationToken))
        {
            await transaction.CommitAsync(cancellationToken);
            return new(ProductionMailboxOwnerRequestStatus.Conflict, null);
        }
        var reference = lookup.Status == ProductionMailboxRouteHistoryLookupStatus.History
            ? ProductionMailboxProtectedHistoryResponseReference.Create(route,
                decoded.CurrentRouteHistoryCheckpointHash.Span, lookup.Lookup,
                v2PreparedIntegrityKey)
            : null;
        var createdAlias = ProductionMailboxProtectedOwnerRequestAliasV2.Create(route,
            requestId, requestHash, request.ExpiresAtUnixSeconds, retainUntilUnixSeconds,
            v2PreparedIntegrityKey);
        var created = ProductionMailboxProtectedOwnerRequestV2.CreatePrepared(route, scope,
            request, lookup.Lookup, reference, v2PreparedIntegrityKey);
        await InsertOwnerRequestAliasV2Async(connection, transaction, createdAlias,
            cancellationToken);
        await InsertOwnerRequestV2Async(connection, transaction, created, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return new(ProductionMailboxOwnerRequestStatus.Prepared, created);
    }

    async ValueTask<ProductionMailboxOwnerRequestV2PlanResult>
        IProductionMailboxOwnerRequestV2StateStore.PlanOwnerRequestV2Async(
        ReadOnlyMemory<byte> routeStateKey, ReadOnlyMemory<byte> activeScope,
        ProductionMailboxRouteHistoryLookupRequest lookupRequest,
        VerifiedProductionMailboxOwnerControlRequest request, ulong nowUnixSeconds,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(lookupRequest);
        ArgumentNullException.ThrowIfNull(request);
        var route = ProductionMailboxRouteContinuityStateGuard.FreezeKey(routeStateKey);
        var scope = PgV2Exact(activeScope, 32, "active scope");
        await using var connection = await OpenAsync(cancellationToken);
        await EnsureOwnerRequestV2DependenciesAsync(connection, cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(
            IsolationLevel.ReadCommitted, cancellationToken);
        await ConfigureOwnerControlTransactionAsync(connection, transaction, cancellationToken);
        await AdvisoryLockAsync(connection, transaction, route, cancellationToken);
        var dbNow = await OwnerDbNowAsync(connection, transaction, cancellationToken);
        var record = await ReadOwnerRequestV2Async(connection, transaction, scope,
            cancellationToken);
        if (record is null)
        {
            await transaction.CommitAsync(cancellationToken);
            return new(ProductionMailboxOwnerRequestStatus.MissingState, 0, 0, null);
        }
        var status = await ValidatePgV2ContinuationAsync(connection, transaction, route,
            lookupRequest, request, record, dbNow, cancellationToken);
        if (status != ProductionMailboxOwnerRequestStatus.Prepared)
        {
            await transaction.CommitAsync(cancellationToken);
            return new(status, 0, 0, null);
        }
        if (record.Phase >= ProductionMailboxOwnerRequestV2Phase.Planned)
        {
            await transaction.CommitAsync(cancellationToken);
            return new(ProductionMailboxOwnerRequestStatus.Prepared,
                record.PlannedIssuedAtUnixSeconds!.Value,
                record.PlannedExpiresAtUnixSeconds!.Value, record);
        }
        var expires = Math.Min(record.RequestExpiresAtUnixSeconds,
            checked(dbNow + ProductionMailboxOwnerControlConstants
                .MaximumMessageLifetimeSeconds));
        if (expires <= dbNow)
        {
            await transaction.CommitAsync(cancellationToken);
            return new(ProductionMailboxOwnerRequestStatus.Stale, 0, 0, null);
        }
        var planned = record.Plan(dbNow, expires, v2PreparedIntegrityKey);
        await UpdateOwnerRequestV2Async(connection, transaction, planned, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return new(ProductionMailboxOwnerRequestStatus.Prepared, dbNow, expires, planned);
    }

    async ValueTask<ProductionMailboxOwnerRequestV2Result>
        IProductionMailboxOwnerRequestV2StateStore.RecordOwnerRequestV2Async(
        ReadOnlyMemory<byte> routeStateKey, ReadOnlyMemory<byte> activeScope,
        ProductionMailboxRouteHistoryLookupRequest lookupRequest,
        VerifiedProductionMailboxOwnerControlRequest request,
        ReadOnlyMemory<byte> canonicalResponseHeader,
        ReadOnlyMemory<byte> canonicalResponseHash, ulong nowUnixSeconds,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(lookupRequest);
        ArgumentNullException.ThrowIfNull(request);
        var route = ProductionMailboxRouteContinuityStateGuard.FreezeKey(routeStateKey);
        var scope = PgV2Exact(activeScope, 32, "active scope");
        var header = PgV2Exact(canonicalResponseHeader,
            ProductionMailboxOwnerControlConstants.ResponseHeaderLength, "response header",
            allowZero: true);
        var responseHash = PgV2Exact(canonicalResponseHash, 32, "response hash");
        await using var connection = await OpenAsync(cancellationToken);
        await EnsureOwnerRequestV2DependenciesAsync(connection, cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(
            IsolationLevel.ReadCommitted, cancellationToken);
        await ConfigureOwnerControlTransactionAsync(connection, transaction, cancellationToken);
        await AdvisoryLockAsync(connection, transaction, route, cancellationToken);
        var dbNow = await OwnerDbNowAsync(connection, transaction, cancellationToken);
        var record = await ReadOwnerRequestV2Async(connection, transaction, scope,
            cancellationToken);
        if (record is null)
        {
            await transaction.CommitAsync(cancellationToken);
            return new(ProductionMailboxOwnerRequestStatus.MissingState, null);
        }
        var status = await ValidatePgV2ContinuationAsync(connection, transaction, route,
            lookupRequest, request, record, dbNow, cancellationToken);
        if (status != ProductionMailboxOwnerRequestStatus.Prepared)
        {
            await transaction.CommitAsync(cancellationToken);
            return new(status, null);
        }
        if (record.PlannedExpiresAtUnixSeconds is null ||
            dbNow >= record.PlannedExpiresAtUnixSeconds)
        {
            await transaction.CommitAsync(cancellationToken);
            return new(ProductionMailboxOwnerRequestStatus.Stale, null);
        }
        if (record.Phase >= ProductionMailboxOwnerRequestV2Phase.Signed)
        {
            var exact = PgV2Fixed(record.ResponseHeader.Span, header) &&
                PgV2Fixed(record.ResponseHash.Span, responseHash);
            await transaction.CommitAsync(cancellationToken);
            return new(exact ? ProductionMailboxOwnerRequestStatus.ExactReplay :
                ProductionMailboxOwnerRequestStatus.Conflict, record);
        }
        var signed = record.RecordSigned(header, responseHash, v2PreparedIntegrityKey);
        await UpdateOwnerRequestV2Async(connection, transaction, signed, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return new(ProductionMailboxOwnerRequestStatus.Prepared, signed);
    }

    private async ValueTask<ProductionMailboxOwnerRequestStatus>
        ValidatePgV2ContinuationAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, ReadOnlyMemory<byte> route,
        ProductionMailboxRouteHistoryLookupRequest lookupRequest,
        VerifiedProductionMailboxOwnerControlRequest request,
        ProductionMailboxProtectedOwnerRequestV2 record, ulong dbNow,
        CancellationToken cancellationToken)
    {
        if (!PgV2Fixed(record.RouteStateKey.Span, route.Span) ||
            !PgV2Fixed(record.RequestHash.Span, request.CanonicalHash.Span))
            return ProductionMailboxOwnerRequestStatus.Conflict;
        if (record.TerminalRevoked) return ProductionMailboxOwnerRequestStatus.Revoked;
        if (dbNow >= record.RequestExpiresAtUnixSeconds)
            return ProductionMailboxOwnerRequestStatus.Stale;
        var current = await ReadRouteContinuityAsync(connection, transaction, route, true,
            cancellationToken);
        if (current is null) return ProductionMailboxOwnerRequestStatus.MissingState;
        if (current.OwnerRevocationGeneration != 0)
            return ProductionMailboxOwnerRequestStatus.Revoked;
        var lookup = await ReadHistoryLookupAsync(connection, transaction, route, current,
            lookupRequest, cancellationToken);
        return lookup.Lookup is not null && lookup.Status is
                ProductionMailboxRouteHistoryLookupStatus.History or
                ProductionMailboxRouteHistoryLookupStatus.HeadNoChange &&
            PgV2Fixed(lookup.Lookup.RouteLocalSourceFingerprint.Span,
                record.SourceFingerprint.Span)
            ? ProductionMailboxOwnerRequestStatus.Prepared
            : ProductionMailboxOwnerRequestStatus.Conflict;
    }

    private async ValueTask EnsureOwnerRequestV2DependenciesAsync(NpgsqlConnection connection,
        CancellationToken cancellationToken)
    {
        await EnsureOwnerControlSchemaAsync(connection, cancellationToken);
        await EnsureRouteHistorySchemaAsync(connection, cancellationToken);
        await EnsureOwnerRequestV2SchemaAsync(connection, cancellationToken);
    }

    private async ValueTask EnsureOwnerRequestV2SchemaAsync(NpgsqlConnection connection,
        CancellationToken cancellationToken)
    {
        if (ownerRequestV2Initialized) return;
        await ownerRequestV2InitializeGate.WaitAsync(cancellationToken);
        try
        {
            if (ownerRequestV2Initialized) return;
            const string sql = """
                CREATE TABLE IF NOT EXISTS production_mailbox_owner_requests_v2(
                    active_scope bytea PRIMARY KEY CHECK(octet_length(active_scope)=32),
                    route_state_key bytea NOT NULL CHECK(octet_length(route_state_key)=32),
                    canonical_request bytea NOT NULL CHECK(octet_length(canonical_request)=344),
                    request_hash bytea NOT NULL CHECK(octet_length(request_hash)=32),
                    source_kind smallint NOT NULL CHECK(source_kind IN (1,2)),
                    source_fingerprint bytea NOT NULL CHECK(octet_length(source_fingerprint)=32),
                    request_expires bytea NOT NULL CHECK(octet_length(request_expires)=8),
                    planned_issued bytea NULL CHECK(planned_issued IS NULL OR octet_length(planned_issued)=8),
                    planned_expires bytea NULL CHECK(planned_expires IS NULL OR octet_length(planned_expires)=8),
                    history_reference bytea NULL CHECK(history_reference IS NULL OR octet_length(history_reference)=160),
                    history_reference_tag bytea NULL CHECK(history_reference_tag IS NULL OR octet_length(history_reference_tag)=32),
                    response_header bytea NULL CHECK(response_header IS NULL OR octet_length(response_header)=384),
                    response_hash bytea NULL CHECK(response_hash IS NULL OR octet_length(response_hash)=32),
                    phase smallint NOT NULL CHECK(phase BETWEEN 1 AND 4),
                    terminal_revoked boolean NOT NULL,
                    terminal_revocation bytea NULL CHECK(terminal_revocation IS NULL OR octet_length(terminal_revocation)=224),
                    terminal_revocation_hash bytea NULL CHECK(terminal_revocation_hash IS NULL OR octet_length(terminal_revocation_hash)=32),
                    integrity_tag bytea NOT NULL CHECK(octet_length(integrity_tag)=32),
                    CHECK((planned_issued IS NULL)=(planned_expires IS NULL)),
                    CHECK((source_kind=1)=(history_reference IS NOT NULL)),
                    CHECK((history_reference IS NULL)=(history_reference_tag IS NULL)),
                    CHECK((phase>=2)=(planned_issued IS NOT NULL)),
                    CHECK((phase>=3)=(response_header IS NOT NULL)),
                    CHECK((response_header IS NULL)=(response_hash IS NULL)),
                    CHECK(terminal_revoked=(terminal_revocation IS NOT NULL)),
                    CHECK((terminal_revocation IS NULL)=(terminal_revocation_hash IS NULL))
                );
                CREATE INDEX IF NOT EXISTS production_mailbox_owner_requests_v2_route
                    ON production_mailbox_owner_requests_v2(route_state_key);
                CREATE TABLE IF NOT EXISTS production_mailbox_owner_request_ids_v2(
                    route_state_key bytea NOT NULL CHECK(octet_length(route_state_key)=32),
                    request_id bytea NOT NULL CHECK(octet_length(request_id)=32),
                    request_hash bytea NOT NULL CHECK(octet_length(request_hash)=32),
                    expires_at bytea NOT NULL CHECK(octet_length(expires_at)=8),
                    retain_until bytea NOT NULL CHECK(octet_length(retain_until)=8),
                    integrity_tag bytea NOT NULL CHECK(octet_length(integrity_tag)=32),
                    PRIMARY KEY(route_state_key,request_id)
                );
                """;
            await using var command = new NpgsqlCommand(sql, connection);
            await command.ExecuteNonQueryAsync(cancellationToken);
            ownerRequestV2Initialized = true;
        }
        finally { ownerRequestV2InitializeGate.Release(); }
    }

    private async ValueTask<ProductionMailboxOwnerRequestStatus?> PgV1QuarantinesAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction, ReadOnlyMemory<byte> route,
        ReadOnlyMemory<byte> requestId, ReadOnlyMemory<byte> requestHash, ulong dbNow,
        CancellationToken cancellationToken)
    {
        await using (var command = new NpgsqlCommand("""
            SELECT active_scope FROM production_mailbox_owner_requests_v1
            WHERE route_state_key=@route ORDER BY active_scope LIMIT 2 FOR UPDATE
            """, connection, transaction))
        {
            command.Parameters.AddWithValue("route", route.ToArray());
            var scopes = new List<byte[]>(2);
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
                scopes.Add(reader.GetFieldValue<byte[]>(0));
            await reader.DisposeAsync();
            foreach (var scope in scopes)
            {
                var legacy = await ReadOwnerRequestAsync(connection, transaction, scope,
                    cancellationToken) ?? throw new InvalidDataException(
                        "Legacy owner request disappeared during quarantine scan.");
                VerifyOwnerRequest(legacy);
                if (dbNow < legacy.ExpiresAt)
                    return ProductionMailboxOwnerRequestStatus.Conflict;
            }
        }
        var alias = await ReadOwnerRequestAliasAsync(connection, transaction, route, requestId,
            cancellationToken);
        if (alias is null) return null;
        VerifyOwnerRequestAlias(alias);
        return PgV2Fixed(alias.RequestHash, requestHash.Span)
            ? ProductionMailboxOwnerRequestStatus.Stale
            : ProductionMailboxOwnerRequestStatus.Conflict;
    }

    private async ValueTask<ProductionMailboxProtectedOwnerRequestV2?> ReadOwnerRequestV2Async(
        NpgsqlConnection connection, NpgsqlTransaction transaction,
        ReadOnlyMemory<byte> scope, CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand("""
            SELECT route_state_key,active_scope,canonical_request,request_hash,source_kind,
                   source_fingerprint,request_expires,planned_issued,planned_expires,
                   history_reference,history_reference_tag,response_header,response_hash,phase,
                   terminal_revocation,terminal_revocation_hash,integrity_tag
            FROM production_mailbox_owner_requests_v2
            WHERE active_scope=@scope FOR UPDATE
            """, connection, transaction);
        command.Parameters.AddWithValue("scope", scope.ToArray());
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken)) return null;
        return ProductionMailboxProtectedOwnerRequestV2.Restore(
            reader.GetFieldValue<byte[]>(0), reader.GetFieldValue<byte[]>(1),
            reader.GetFieldValue<byte[]>(2), reader.GetFieldValue<byte[]>(3),
            (ProductionMailboxOwnerRequestV2SourceKind)reader.GetInt16(4),
            reader.GetFieldValue<byte[]>(5), PgV2U64(reader.GetFieldValue<byte[]>(6)),
            reader.IsDBNull(7) ? null : PgV2U64(reader.GetFieldValue<byte[]>(7)),
            reader.IsDBNull(8) ? null : PgV2U64(reader.GetFieldValue<byte[]>(8)),
            reader.IsDBNull(9) ? [] : reader.GetFieldValue<byte[]>(9),
            reader.IsDBNull(10) ? [] : reader.GetFieldValue<byte[]>(10),
            reader.IsDBNull(11) ? [] : reader.GetFieldValue<byte[]>(11),
            reader.IsDBNull(12) ? [] : reader.GetFieldValue<byte[]>(12),
            (ProductionMailboxOwnerRequestV2Phase)reader.GetInt16(13),
            reader.IsDBNull(14) ? [] : reader.GetFieldValue<byte[]>(14),
            reader.IsDBNull(15) ? [] : reader.GetFieldValue<byte[]>(15),
            reader.GetFieldValue<byte[]>(16), v2PreparedIntegrityKey);
    }

    private async ValueTask<ProductionMailboxProtectedOwnerRequestAliasV2?>
        ReadOwnerRequestAliasV2Async(NpgsqlConnection connection,
        NpgsqlTransaction transaction, ReadOnlyMemory<byte> route,
        ReadOnlyMemory<byte> requestId, CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand("""
            SELECT route_state_key,request_id,request_hash,expires_at,retain_until,integrity_tag
            FROM production_mailbox_owner_request_ids_v2
            WHERE route_state_key=@route AND request_id=@requestId FOR UPDATE
            """, connection, transaction);
        command.Parameters.AddWithValue("route", route.ToArray());
        command.Parameters.AddWithValue("requestId", requestId.ToArray());
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken)) return null;
        return ProductionMailboxProtectedOwnerRequestAliasV2.Restore(
            reader.GetFieldValue<byte[]>(0), reader.GetFieldValue<byte[]>(1),
            reader.GetFieldValue<byte[]>(2), PgV2U64(reader.GetFieldValue<byte[]>(3)),
            PgV2U64(reader.GetFieldValue<byte[]>(4)), reader.GetFieldValue<byte[]>(5),
            v2PreparedIntegrityKey);
    }

    private static async ValueTask InsertOwnerRequestV2Async(NpgsqlConnection connection,
        NpgsqlTransaction transaction, ProductionMailboxProtectedOwnerRequestV2 value,
        CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand("""
            INSERT INTO production_mailbox_owner_requests_v2(
                active_scope,route_state_key,canonical_request,request_hash,source_kind,
                source_fingerprint,request_expires,planned_issued,planned_expires,
                history_reference,history_reference_tag,response_header,response_hash,phase,
                terminal_revoked,terminal_revocation,terminal_revocation_hash,integrity_tag)
            VALUES(@scope,@route,@request,@requestHash,@sourceKind,@source,@requestExpires,
                @plannedIssued,@plannedExpires,@history,@historyTag,@header,@responseHash,@phase,
                @terminal,@revocation,@revocationHash,@tag)
            """, connection, transaction);
        AddOwnerRequestV2Parameters(command, value);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async ValueTask UpdateOwnerRequestV2Async(NpgsqlConnection connection,
        NpgsqlTransaction transaction, ProductionMailboxProtectedOwnerRequestV2 value,
        CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand("""
            UPDATE production_mailbox_owner_requests_v2 SET
                planned_issued=@plannedIssued,planned_expires=@plannedExpires,
                response_header=@header,response_hash=@responseHash,phase=@phase,
                terminal_revoked=@terminal,terminal_revocation=@revocation,
                terminal_revocation_hash=@revocationHash,integrity_tag=@tag
            WHERE active_scope=@scope AND route_state_key=@route
            """, connection, transaction);
        AddOwnerRequestV2Parameters(command, value);
        if (await command.ExecuteNonQueryAsync(cancellationToken) != 1)
            throw new InvalidDataException("Owner request v2 update lost its row.");
    }

    private static void AddOwnerRequestV2Parameters(NpgsqlCommand command,
        ProductionMailboxProtectedOwnerRequestV2 value)
    {
        command.Parameters.AddWithValue("scope", value.ActiveScope.ToArray());
        command.Parameters.AddWithValue("route", value.RouteStateKey.ToArray());
        command.Parameters.AddWithValue("request", value.CanonicalRequest.ToArray());
        command.Parameters.AddWithValue("requestHash", value.RequestHash.ToArray());
        command.Parameters.AddWithValue("sourceKind", (short)value.SourceKind);
        command.Parameters.AddWithValue("source", value.SourceFingerprint.ToArray());
        command.Parameters.AddWithValue("requestExpires",
            PgV2EncodeU64(value.RequestExpiresAtUnixSeconds));
        command.Parameters.AddWithValue("plannedIssued",
            PgV2NullableU64(value.PlannedIssuedAtUnixSeconds));
        command.Parameters.AddWithValue("plannedExpires",
            PgV2NullableU64(value.PlannedExpiresAtUnixSeconds));
        command.Parameters.AddWithValue("history", value.HistoryReference.IsEmpty
            ? DBNull.Value : value.HistoryReference.ToArray());
        command.Parameters.AddWithValue("historyTag", value.HistoryReferenceTag.IsEmpty
            ? DBNull.Value : value.HistoryReferenceTag.ToArray());
        command.Parameters.AddWithValue("header", value.ResponseHeader.IsEmpty
            ? DBNull.Value : value.ResponseHeader.ToArray());
        command.Parameters.AddWithValue("responseHash", value.ResponseHash.IsEmpty
            ? DBNull.Value : value.ResponseHash.ToArray());
        command.Parameters.AddWithValue("phase", (short)value.Phase);
        command.Parameters.AddWithValue("terminal", value.TerminalRevoked);
        command.Parameters.AddWithValue("revocation", value.CanonicalTerminalRevocation.IsEmpty
            ? DBNull.Value : value.CanonicalTerminalRevocation.ToArray());
        command.Parameters.AddWithValue("revocationHash", value.TerminalRevocationHash.IsEmpty
            ? DBNull.Value : value.TerminalRevocationHash.ToArray());
        command.Parameters.AddWithValue("tag", value.IntegrityTag.ToArray());
    }

    private static async ValueTask InsertOwnerRequestAliasV2Async(NpgsqlConnection connection,
        NpgsqlTransaction transaction, ProductionMailboxProtectedOwnerRequestAliasV2 value,
        CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand("""
            INSERT INTO production_mailbox_owner_request_ids_v2(
                route_state_key,request_id,request_hash,expires_at,retain_until,integrity_tag)
            VALUES(@route,@requestId,@requestHash,@expires,@retain,@tag)
            """, connection, transaction);
        command.Parameters.AddWithValue("route", value.RouteStateKey.ToArray());
        command.Parameters.AddWithValue("requestId", value.RequestId.ToArray());
        command.Parameters.AddWithValue("requestHash", value.RequestHash.ToArray());
        command.Parameters.AddWithValue("expires", PgV2EncodeU64(value.ExpiresAtUnixSeconds));
        command.Parameters.AddWithValue("retain", PgV2EncodeU64(value.RetainUntilUnixSeconds));
        command.Parameters.AddWithValue("tag", value.IntegrityTag.ToArray());
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static byte[] PgV2Exact(ReadOnlyMemory<byte> value, int length, string name,
        bool allowZero = false)
    {
        if (value.Length != length || (!allowZero &&
            value.Span.IndexOfAnyExcept((byte)0) < 0))
            throw new InvalidDataException($"Owner request v2 {name} is invalid.");
        return value.ToArray();
    }

    private static ulong PgV2U64(ReadOnlySpan<byte> value)
    {
        if (value.Length != 8) throw new InvalidDataException("Owner request v2 u64 is invalid.");
        return System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(value);
    }

    private static byte[] PgV2EncodeU64(ulong value)
    {
        var result = new byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(result, value);
        return result;
    }

    private static object PgV2NullableU64(ulong? value) => value.HasValue
        ? PgV2EncodeU64(value.Value) : DBNull.Value;

    private static bool PgV2Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}
