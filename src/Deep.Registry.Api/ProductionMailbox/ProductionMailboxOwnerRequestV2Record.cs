using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxTopology;

namespace Deep.Registry.Api.ProductionMailbox;

internal enum ProductionMailboxOwnerRequestV2SourceKind : byte
{
    History = 1,
    HeadNoChange = 2
}

internal enum ProductionMailboxOwnerRequestV2Phase : byte
{
    Prepared = 1,
    Planned = 2,
    Signed = 3,
    DeliveryAuthorized = 4
}

internal sealed class ProductionMailboxProtectedOwnerRequestV2
{
    internal const int IntegrityTagLength = 32;
    private static ReadOnlySpan<byte> IntegrityDomain =>
        "Deep/registry/production-mailbox/owner-control/request-journal/v2"u8;

    private readonly byte[] routeStateKey;
    private readonly byte[] activeScope;
    private readonly byte[] canonicalRequest;
    private readonly byte[] requestHash;
    private readonly byte[] sourceFingerprint;
    private readonly byte[]? historyReference;
    private readonly byte[]? historyReferenceTag;
    private readonly byte[]? responseHeader;
    private readonly byte[]? responseHash;
    private readonly byte[]? canonicalTerminalRevocation;
    private readonly byte[]? terminalRevocationHash;
    private readonly byte[] integrityTag;

    private ProductionMailboxProtectedOwnerRequestV2(
        ReadOnlySpan<byte> routeStateKey,
        ReadOnlySpan<byte> activeScope,
        ReadOnlySpan<byte> canonicalRequest,
        ReadOnlySpan<byte> requestHash,
        ProductionMailboxOwnerRequestV2SourceKind sourceKind,
        ReadOnlySpan<byte> sourceFingerprint,
        ulong requestExpiresAtUnixSeconds,
        ulong? plannedIssuedAtUnixSeconds,
        ulong? plannedExpiresAtUnixSeconds,
        ReadOnlySpan<byte> historyReference,
        ReadOnlySpan<byte> historyReferenceTag,
        ReadOnlySpan<byte> responseHeader,
        ReadOnlySpan<byte> responseHash,
        ProductionMailboxOwnerRequestV2Phase phase,
        ReadOnlySpan<byte> canonicalTerminalRevocation,
        ReadOnlySpan<byte> terminalRevocationHash,
        ReadOnlySpan<byte> integrityTag)
    {
        this.routeStateKey = routeStateKey.ToArray();
        this.activeScope = activeScope.ToArray();
        this.canonicalRequest = canonicalRequest.ToArray();
        this.requestHash = requestHash.ToArray();
        SourceKind = sourceKind;
        this.sourceFingerprint = sourceFingerprint.ToArray();
        RequestExpiresAtUnixSeconds = requestExpiresAtUnixSeconds;
        PlannedIssuedAtUnixSeconds = plannedIssuedAtUnixSeconds;
        PlannedExpiresAtUnixSeconds = plannedExpiresAtUnixSeconds;
        this.historyReference = historyReference.IsEmpty ? null : historyReference.ToArray();
        this.historyReferenceTag = historyReferenceTag.IsEmpty
            ? null : historyReferenceTag.ToArray();
        this.responseHeader = responseHeader.IsEmpty ? null : responseHeader.ToArray();
        this.responseHash = responseHash.IsEmpty ? null : responseHash.ToArray();
        Phase = phase;
        this.canonicalTerminalRevocation = canonicalTerminalRevocation.IsEmpty
            ? null : canonicalTerminalRevocation.ToArray();
        this.terminalRevocationHash = terminalRevocationHash.IsEmpty
            ? null : terminalRevocationHash.ToArray();
        this.integrityTag = integrityTag.ToArray();
    }

    internal ReadOnlyMemory<byte> RouteStateKey => routeStateKey.ToArray();
    internal ReadOnlyMemory<byte> ActiveScope => activeScope.ToArray();
    internal ReadOnlyMemory<byte> CanonicalRequest => canonicalRequest.ToArray();
    internal ReadOnlyMemory<byte> RequestHash => requestHash.ToArray();
    internal ProductionMailboxOwnerRequestV2SourceKind SourceKind { get; }
    internal ReadOnlyMemory<byte> SourceFingerprint => sourceFingerprint.ToArray();
    internal ulong RequestExpiresAtUnixSeconds { get; }
    internal ulong? PlannedIssuedAtUnixSeconds { get; }
    internal ulong? PlannedExpiresAtUnixSeconds { get; }
    internal ReadOnlyMemory<byte> HistoryReference => historyReference?.ToArray() ?? [];
    internal ReadOnlyMemory<byte> HistoryReferenceTag => historyReferenceTag?.ToArray() ?? [];
    internal ReadOnlyMemory<byte> ResponseHeader => responseHeader?.ToArray() ?? [];
    internal ReadOnlyMemory<byte> ResponseHash => responseHash?.ToArray() ?? [];
    internal ProductionMailboxOwnerRequestV2Phase Phase { get; }
    internal bool TerminalRevoked => canonicalTerminalRevocation is not null;
    internal ReadOnlyMemory<byte> CanonicalTerminalRevocation =>
        canonicalTerminalRevocation?.ToArray() ?? [];
    internal ReadOnlyMemory<byte> TerminalRevocationHash =>
        terminalRevocationHash?.ToArray() ?? [];
    internal ReadOnlyMemory<byte> IntegrityTag => integrityTag.ToArray();

    internal static ProductionMailboxProtectedOwnerRequestV2 CreatePrepared(
        ReadOnlySpan<byte> routeStateKey,
        ReadOnlySpan<byte> activeScope,
        VerifiedProductionMailboxOwnerControlRequest request,
        ProductionMailboxRouteHistoryLookup lookup,
        ProductionMailboxProtectedHistoryResponseReference? historyReference,
        ReadOnlySpan<byte> integrityKey)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(lookup);
        var sourceKind = lookup.Status switch
        {
            ProductionMailboxRouteHistoryLookupStatus.History =>
                ProductionMailboxOwnerRequestV2SourceKind.History,
            ProductionMailboxRouteHistoryLookupStatus.HeadNoChange =>
                ProductionMailboxOwnerRequestV2SourceKind.HeadNoChange,
            _ => throw new InvalidDataException("Owner request source is not deliverable.")
        };
        if ((sourceKind == ProductionMailboxOwnerRequestV2SourceKind.History) !=
            (historyReference is not null))
            throw new InvalidDataException("Owner request history reference shape is invalid.");
        if (historyReference is not null && !historyReference.Matches(lookup))
            throw new InvalidDataException("Owner request history reference differs from lookup.");
        var reference = historyReference?.CanonicalBytes.ToArray() ?? [];
        var referenceTag = historyReference?.IntegrityTag.ToArray() ?? [];
        try
        {
            return Protect(routeStateKey, activeScope, request.CanonicalBytes.Span,
                request.CanonicalHash.Span, sourceKind, lookup.RouteLocalSourceFingerprint.Span,
                request.ExpiresAtUnixSeconds, null, null, reference, referenceTag,
                default, default, ProductionMailboxOwnerRequestV2Phase.Prepared,
                default, default, integrityKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(reference);
            CryptographicOperations.ZeroMemory(referenceTag);
        }
    }

    internal ProductionMailboxProtectedOwnerRequestV2 Plan(
        ulong issuedAtUnixSeconds,
        ulong expiresAtUnixSeconds,
        ReadOnlySpan<byte> integrityKey)
    {
        if (TerminalRevoked || Phase != ProductionMailboxOwnerRequestV2Phase.Prepared ||
            issuedAtUnixSeconds == 0 || expiresAtUnixSeconds <= issuedAtUnixSeconds ||
            expiresAtUnixSeconds > RequestExpiresAtUnixSeconds)
            throw new InvalidDataException("Owner response plan transition is invalid.");
        return Protect(routeStateKey, activeScope, canonicalRequest, requestHash, SourceKind,
            sourceFingerprint, RequestExpiresAtUnixSeconds, issuedAtUnixSeconds,
            expiresAtUnixSeconds, HistoryReference.Span, HistoryReferenceTag.Span,
            default, default, ProductionMailboxOwnerRequestV2Phase.Planned,
            default, default, integrityKey);
    }

    internal ProductionMailboxProtectedOwnerRequestV2 RecordSigned(
        ReadOnlySpan<byte> canonicalResponseHeader,
        ReadOnlySpan<byte> canonicalResponseHash,
        ReadOnlySpan<byte> integrityKey)
    {
        if (TerminalRevoked || Phase != ProductionMailboxOwnerRequestV2Phase.Planned)
            throw new InvalidDataException("Owner signed-response transition is invalid.");
        return Protect(routeStateKey, activeScope, canonicalRequest, requestHash, SourceKind,
            sourceFingerprint, RequestExpiresAtUnixSeconds, PlannedIssuedAtUnixSeconds,
            PlannedExpiresAtUnixSeconds, HistoryReference.Span, HistoryReferenceTag.Span,
            canonicalResponseHeader, canonicalResponseHash,
            ProductionMailboxOwnerRequestV2Phase.Signed, default, default, integrityKey);
    }

    internal ProductionMailboxProtectedOwnerRequestV2 AuthorizeDelivery(
        ReadOnlySpan<byte> integrityKey)
    {
        if (TerminalRevoked || Phase is not (ProductionMailboxOwnerRequestV2Phase.Signed or
                ProductionMailboxOwnerRequestV2Phase.DeliveryAuthorized))
            throw new InvalidDataException("Owner delivery transition is invalid.");
        return Protect(routeStateKey, activeScope, canonicalRequest, requestHash, SourceKind,
            sourceFingerprint, RequestExpiresAtUnixSeconds, PlannedIssuedAtUnixSeconds,
            PlannedExpiresAtUnixSeconds, HistoryReference.Span, HistoryReferenceTag.Span,
            ResponseHeader.Span, ResponseHash.Span,
            ProductionMailboxOwnerRequestV2Phase.DeliveryAuthorized,
            default, default, integrityKey);
    }

    internal ProductionMailboxProtectedOwnerRequestV2 Revoke(
        ReadOnlySpan<byte> canonicalRevocation,
        ReadOnlySpan<byte> canonicalRevocationHash,
        ReadOnlySpan<byte> integrityKey)
    {
        if (TerminalRevoked)
        {
            if (Fixed(canonicalTerminalRevocation!, canonicalRevocation) &&
                Fixed(terminalRevocationHash!, canonicalRevocationHash))
                return this;
            throw new InvalidDataException("Owner terminal revocation forks.");
        }
        return Protect(routeStateKey, activeScope, canonicalRequest, requestHash, SourceKind,
            sourceFingerprint, RequestExpiresAtUnixSeconds, PlannedIssuedAtUnixSeconds,
            PlannedExpiresAtUnixSeconds, HistoryReference.Span, HistoryReferenceTag.Span,
            ResponseHeader.Span, ResponseHash.Span, Phase,
            canonicalRevocation, canonicalRevocationHash, integrityKey);
    }

    internal static ProductionMailboxProtectedOwnerRequestV2 Restore(
        ReadOnlySpan<byte> routeStateKey,
        ReadOnlySpan<byte> activeScope,
        ReadOnlySpan<byte> canonicalRequest,
        ReadOnlySpan<byte> requestHash,
        ProductionMailboxOwnerRequestV2SourceKind sourceKind,
        ReadOnlySpan<byte> sourceFingerprint,
        ulong requestExpiresAtUnixSeconds,
        ulong? plannedIssuedAtUnixSeconds,
        ulong? plannedExpiresAtUnixSeconds,
        ReadOnlySpan<byte> historyReference,
        ReadOnlySpan<byte> historyReferenceTag,
        ReadOnlySpan<byte> responseHeader,
        ReadOnlySpan<byte> responseHash,
        ProductionMailboxOwnerRequestV2Phase phase,
        ReadOnlySpan<byte> canonicalTerminalRevocation,
        ReadOnlySpan<byte> terminalRevocationHash,
        ReadOnlySpan<byte> integrityTag,
        ReadOnlySpan<byte> integrityKey)
    {
        Exact(integrityKey, 32, "integrity key");
        var expected = ComputeTag(routeStateKey, activeScope, canonicalRequest, requestHash,
            sourceKind, sourceFingerprint, requestExpiresAtUnixSeconds,
            plannedIssuedAtUnixSeconds, plannedExpiresAtUnixSeconds,
            historyReference, historyReferenceTag, responseHeader, responseHash, phase,
            canonicalTerminalRevocation, terminalRevocationHash, integrityKey);
        try
        {
            if (integrityTag.Length != IntegrityTagLength || !Fixed(expected, integrityTag))
                throw new InvalidDataException("Owner request v2 HMAC is invalid.");
            ValidateStoredSemantics(routeStateKey, canonicalRequest, requestHash, sourceKind,
                plannedIssuedAtUnixSeconds, plannedExpiresAtUnixSeconds,
                historyReference, historyReferenceTag, responseHeader,
                canonicalTerminalRevocation, integrityKey);
            return CreateValidated(routeStateKey, activeScope, canonicalRequest, requestHash,
                sourceKind, sourceFingerprint, requestExpiresAtUnixSeconds,
                plannedIssuedAtUnixSeconds, plannedExpiresAtUnixSeconds,
                historyReference, historyReferenceTag, responseHeader, responseHash, phase,
                canonicalTerminalRevocation, terminalRevocationHash, integrityTag);
        }
        finally { CryptographicOperations.ZeroMemory(expected); }
    }

    internal bool Exact(ProductionMailboxProtectedOwnerRequestV2 other)
    {
        ArgumentNullException.ThrowIfNull(other);
        return Fixed(routeStateKey, other.routeStateKey) &&
            Fixed(activeScope, other.activeScope) &&
            Fixed(canonicalRequest, other.canonicalRequest) &&
            Fixed(requestHash, other.requestHash) && SourceKind == other.SourceKind &&
            Fixed(sourceFingerprint, other.sourceFingerprint) &&
            RequestExpiresAtUnixSeconds == other.RequestExpiresAtUnixSeconds &&
            PlannedIssuedAtUnixSeconds == other.PlannedIssuedAtUnixSeconds &&
            PlannedExpiresAtUnixSeconds == other.PlannedExpiresAtUnixSeconds &&
            FixedNullable(historyReference, other.historyReference) &&
            FixedNullable(historyReferenceTag, other.historyReferenceTag) &&
            FixedNullable(responseHeader, other.responseHeader) &&
            FixedNullable(responseHash, other.responseHash) && Phase == other.Phase &&
            FixedNullable(canonicalTerminalRevocation, other.canonicalTerminalRevocation) &&
            FixedNullable(terminalRevocationHash, other.terminalRevocationHash) &&
            Fixed(integrityTag, other.integrityTag);
    }

    private static ProductionMailboxProtectedOwnerRequestV2 Protect(
        ReadOnlySpan<byte> routeStateKey,
        ReadOnlySpan<byte> activeScope,
        ReadOnlySpan<byte> canonicalRequest,
        ReadOnlySpan<byte> requestHash,
        ProductionMailboxOwnerRequestV2SourceKind sourceKind,
        ReadOnlySpan<byte> sourceFingerprint,
        ulong requestExpiresAtUnixSeconds,
        ulong? plannedIssuedAtUnixSeconds,
        ulong? plannedExpiresAtUnixSeconds,
        ReadOnlySpan<byte> historyReference,
        ReadOnlySpan<byte> historyReferenceTag,
        ReadOnlySpan<byte> responseHeader,
        ReadOnlySpan<byte> responseHash,
        ProductionMailboxOwnerRequestV2Phase phase,
        ReadOnlySpan<byte> canonicalTerminalRevocation,
        ReadOnlySpan<byte> terminalRevocationHash,
        ReadOnlySpan<byte> integrityKey)
    {
        Exact(integrityKey, 32, "integrity key");
        ValidateShape(routeStateKey, activeScope, canonicalRequest, requestHash, sourceKind,
            sourceFingerprint, requestExpiresAtUnixSeconds, plannedIssuedAtUnixSeconds,
            plannedExpiresAtUnixSeconds, historyReference, historyReferenceTag,
            responseHeader, responseHash, phase, canonicalTerminalRevocation,
            terminalRevocationHash);
        ValidateStoredSemantics(routeStateKey, canonicalRequest, requestHash, sourceKind,
            plannedIssuedAtUnixSeconds, plannedExpiresAtUnixSeconds,
            historyReference, historyReferenceTag, responseHeader,
            canonicalTerminalRevocation, integrityKey);
        var tag = ComputeTag(routeStateKey, activeScope, canonicalRequest, requestHash,
            sourceKind, sourceFingerprint, requestExpiresAtUnixSeconds,
            plannedIssuedAtUnixSeconds, plannedExpiresAtUnixSeconds,
            historyReference, historyReferenceTag, responseHeader, responseHash, phase,
            canonicalTerminalRevocation, terminalRevocationHash, integrityKey);
        try
        {
            return CreateValidated(routeStateKey, activeScope, canonicalRequest, requestHash,
                sourceKind, sourceFingerprint, requestExpiresAtUnixSeconds,
                plannedIssuedAtUnixSeconds, plannedExpiresAtUnixSeconds,
                historyReference, historyReferenceTag, responseHeader, responseHash, phase,
                canonicalTerminalRevocation, terminalRevocationHash, tag);
        }
        finally { CryptographicOperations.ZeroMemory(tag); }
    }

    private static ProductionMailboxProtectedOwnerRequestV2 CreateValidated(
        ReadOnlySpan<byte> routeStateKey, ReadOnlySpan<byte> activeScope,
        ReadOnlySpan<byte> canonicalRequest, ReadOnlySpan<byte> requestHash,
        ProductionMailboxOwnerRequestV2SourceKind sourceKind,
        ReadOnlySpan<byte> sourceFingerprint, ulong requestExpiresAtUnixSeconds,
        ulong? plannedIssuedAtUnixSeconds, ulong? plannedExpiresAtUnixSeconds,
        ReadOnlySpan<byte> historyReference, ReadOnlySpan<byte> historyReferenceTag,
        ReadOnlySpan<byte> responseHeader, ReadOnlySpan<byte> responseHash,
        ProductionMailboxOwnerRequestV2Phase phase,
        ReadOnlySpan<byte> canonicalTerminalRevocation,
        ReadOnlySpan<byte> terminalRevocationHash, ReadOnlySpan<byte> integrityTag)
    {
        ValidateShape(routeStateKey, activeScope, canonicalRequest, requestHash, sourceKind,
            sourceFingerprint, requestExpiresAtUnixSeconds, plannedIssuedAtUnixSeconds,
                plannedExpiresAtUnixSeconds, historyReference, historyReferenceTag,
                responseHeader, responseHash, phase, canonicalTerminalRevocation,
                terminalRevocationHash);
        return new(routeStateKey, activeScope, canonicalRequest, requestHash, sourceKind,
            sourceFingerprint, requestExpiresAtUnixSeconds, plannedIssuedAtUnixSeconds,
            plannedExpiresAtUnixSeconds, historyReference, historyReferenceTag,
            responseHeader, responseHash, phase, canonicalTerminalRevocation,
            terminalRevocationHash, integrityTag);
    }

    private static void ValidateShape(
        ReadOnlySpan<byte> routeStateKey, ReadOnlySpan<byte> activeScope,
        ReadOnlySpan<byte> canonicalRequest, ReadOnlySpan<byte> requestHash,
        ProductionMailboxOwnerRequestV2SourceKind sourceKind,
        ReadOnlySpan<byte> sourceFingerprint, ulong requestExpiresAtUnixSeconds,
        ulong? plannedIssuedAtUnixSeconds, ulong? plannedExpiresAtUnixSeconds,
        ReadOnlySpan<byte> historyReference, ReadOnlySpan<byte> historyReferenceTag,
        ReadOnlySpan<byte> responseHeader, ReadOnlySpan<byte> responseHash,
        ProductionMailboxOwnerRequestV2Phase phase,
        ReadOnlySpan<byte> canonicalTerminalRevocation,
        ReadOnlySpan<byte> terminalRevocationHash)
    {
        Exact(routeStateKey, 32, "route key");
        Exact(activeScope, 32, "active scope");
        Exact(canonicalRequest, ProductionMailboxOwnerControlConstants.RequestLength,
            "canonical request", allowZero: true);
        Exact(requestHash, 32, "request hash");
        Exact(sourceFingerprint, 32, "source fingerprint");
        if (requestExpiresAtUnixSeconds is 0 or ulong.MaxValue ||
            sourceKind is not ProductionMailboxOwnerRequestV2SourceKind.History and
                not ProductionMailboxOwnerRequestV2SourceKind.HeadNoChange ||
            phase is < ProductionMailboxOwnerRequestV2Phase.Prepared or
                > ProductionMailboxOwnerRequestV2Phase.DeliveryAuthorized)
            throw new InvalidDataException("Owner request v2 scalar fields are invalid.");
        var history = sourceKind == ProductionMailboxOwnerRequestV2SourceKind.History;
        if (history != (!historyReference.IsEmpty || !historyReferenceTag.IsEmpty) ||
            (history && (historyReference.Length !=
                ProductionMailboxProtectedHistoryResponseReference.CanonicalLength ||
                historyReferenceTag.Length !=
                ProductionMailboxProtectedHistoryResponseReference.IntegrityTagLength)))
            throw new InvalidDataException("Owner request v2 history shape is invalid.");
        var planned = phase >= ProductionMailboxOwnerRequestV2Phase.Planned;
        if (planned != plannedIssuedAtUnixSeconds.HasValue ||
            planned != plannedExpiresAtUnixSeconds.HasValue ||
            (planned && (plannedIssuedAtUnixSeconds is 0 ||
                plannedExpiresAtUnixSeconds <= plannedIssuedAtUnixSeconds ||
                plannedExpiresAtUnixSeconds > requestExpiresAtUnixSeconds)))
            throw new InvalidDataException("Owner request v2 planned-time shape is invalid.");
        var signed = phase >= ProductionMailboxOwnerRequestV2Phase.Signed;
        if (signed != (!responseHeader.IsEmpty || !responseHash.IsEmpty) ||
            (signed && (responseHeader.Length !=
                ProductionMailboxOwnerControlConstants.ResponseHeaderLength ||
                responseHash.Length != 32 || responseHash.IndexOfAnyExcept((byte)0) < 0)))
            throw new InvalidDataException("Owner request v2 signed-response shape is invalid.");
        var terminal = !canonicalTerminalRevocation.IsEmpty || !terminalRevocationHash.IsEmpty;
        if (terminal && (canonicalTerminalRevocation.Length !=
                ProductionMailboxRouteContinuityConstants.CanonicalRevocationLength ||
                terminalRevocationHash.Length != 32 ||
                terminalRevocationHash.IndexOfAnyExcept((byte)0) < 0))
            throw new InvalidDataException("Owner request v2 terminal shape is invalid.");
    }

    private static void ValidateStoredSemantics(ReadOnlySpan<byte> routeStateKey,
        ReadOnlySpan<byte> canonicalRequest, ReadOnlySpan<byte> requestHash,
        ProductionMailboxOwnerRequestV2SourceKind sourceKind,
        ulong? plannedIssuedAtUnixSeconds, ulong? plannedExpiresAtUnixSeconds,
        ReadOnlySpan<byte> historyReference, ReadOnlySpan<byte> historyReferenceTag,
        ReadOnlySpan<byte> responseHeader, ReadOnlySpan<byte> canonicalTerminalRevocation,
        ReadOnlySpan<byte> integrityKey)
    {
        var request = ProductionMailboxOwnerControlTransportCodec.DecodeRequest(canonicalRequest);
        ProductionMailboxProtectedHistoryResponseReference? history = null;
        if (sourceKind == ProductionMailboxOwnerRequestV2SourceKind.History)
        {
            history = ProductionMailboxProtectedHistoryResponseReference.Restore(routeStateKey,
                request.CurrentRouteHistoryCheckpointHash.Span, historyReference,
                historyReferenceTag, integrityKey);
            if (history.CurrentBatchSequence != request.CurrentRouteHistoryBatchSequence)
                throw new InvalidDataException("Owner request v2 history predecessor is split.");
        }
        if (!responseHeader.IsEmpty)
        {
            var response = ProductionMailboxOwnerControlTransportCodec
                .DecodeResponseHeader(responseHeader);
            var historyResponse = sourceKind == ProductionMailboxOwnerRequestV2SourceKind.History;
            if (!Fixed(response.CanonicalRequestHash.Span, requestHash) ||
                !Fixed(response.RequestId.Span, request.RequestId.Span) ||
                !Fixed(response.NetworkId.Span, request.NetworkId.Span) ||
                !Fixed(response.RouteDomainHash.Span, request.RouteDomainHash.Span) ||
                !Fixed(response.PredecessorRouteOriginLkgHash.Span,
                    request.PredecessorRouteOriginLkgHash.Span) ||
                !Fixed(response.CurrentRouteHistoryCheckpointHash.Span,
                    request.CurrentRouteHistoryCheckpointHash.Span) ||
                response.CurrentRouteHistoryBatchSequence !=
                    request.CurrentRouteHistoryBatchSequence ||
                response.Mode != request.Mode ||
                response.AuthorizationKind != request.ExpectedAuthorizationKind ||
                response.IssuedAtUnixSeconds != plannedIssuedAtUnixSeconds ||
                response.ExpiresAtUnixSeconds != plannedExpiresAtUnixSeconds ||
                response.Kind != (historyResponse
                    ? ProductionMailboxOwnerControlResponseKind.History
                    : ProductionMailboxOwnerControlResponseKind.NoChange))
                throw new InvalidDataException("Owner request v2 response binding is split.");
            if (historyResponse)
            {
                if (response.NextRouteHistoryBatchSequence != history!.NextBatchSequence ||
                    !Fixed(response.NextRouteHistoryCheckpointHash.Span,
                        history.CanonicalNextCheckpointHash.Span) ||
                    response.PayloadLength != history.PayloadLength ||
                    !Fixed(response.PayloadSha256.Span, history.PayloadSha256.Span))
                    throw new InvalidDataException("Owner request v2 History response is split.");
            }
            else if (response.NextRouteHistoryBatchSequence !=
                    response.CurrentRouteHistoryBatchSequence ||
                !Fixed(response.NextRouteHistoryCheckpointHash.Span,
                    response.CurrentRouteHistoryCheckpointHash.Span) ||
                response.PayloadLength != 0 ||
                !Fixed(response.PayloadSha256.Span, SHA256.HashData([])))
            {
                throw new InvalidDataException("Owner request v2 NoChange response is split.");
            }
        }
        if (!canonicalTerminalRevocation.IsEmpty)
        {
            var revocation = ProductionMailboxRouteContinuityCodec.DecodeRevocation(
                canonicalTerminalRevocation);
            if (!Fixed(revocation.NetworkId.Span, request.NetworkId.Span) ||
                !Fixed(revocation.RouteDomainHash.Span, request.RouteDomainHash.Span))
                throw new InvalidDataException("Owner request v2 terminal identity is split.");
        }
    }

    private static byte[] ComputeTag(
        ReadOnlySpan<byte> routeStateKey, ReadOnlySpan<byte> activeScope,
        ReadOnlySpan<byte> canonicalRequest, ReadOnlySpan<byte> requestHash,
        ProductionMailboxOwnerRequestV2SourceKind sourceKind,
        ReadOnlySpan<byte> sourceFingerprint, ulong requestExpiresAtUnixSeconds,
        ulong? plannedIssuedAtUnixSeconds, ulong? plannedExpiresAtUnixSeconds,
        ReadOnlySpan<byte> historyReference, ReadOnlySpan<byte> historyReferenceTag,
        ReadOnlySpan<byte> responseHeader, ReadOnlySpan<byte> responseHash,
        ProductionMailboxOwnerRequestV2Phase phase,
        ReadOnlySpan<byte> canonicalTerminalRevocation,
        ReadOnlySpan<byte> terminalRevocationHash, ReadOnlySpan<byte> integrityKey)
    {
        var key = integrityKey.ToArray();
        try
        {
            using var hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, key);
            Append(IntegrityDomain); Append(routeStateKey); Append(activeScope);
            Append(canonicalRequest); Append(requestHash); Append([(byte)sourceKind]);
            Append(sourceFingerprint); AppendU64(requestExpiresAtUnixSeconds);
            AppendNullableU64(plannedIssuedAtUnixSeconds);
            AppendNullableU64(plannedExpiresAtUnixSeconds);
            AppendOptional(historyReference); AppendOptional(historyReferenceTag);
            AppendOptional(responseHeader); AppendOptional(responseHash);
            Append([(byte)phase]); AppendOptional(canonicalTerminalRevocation);
            AppendOptional(terminalRevocationHash);
            return hmac.GetHashAndReset();

            void Append(ReadOnlySpan<byte> value)
            {
                Span<byte> length = stackalloc byte[4];
                BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)value.Length));
                hmac.AppendData(length); hmac.AppendData(value);
            }
            void AppendOptional(ReadOnlySpan<byte> value) => Append(value);
            void AppendU64(ulong value)
            {
                Span<byte> encoded = stackalloc byte[8];
                BinaryPrimitives.WriteUInt64BigEndian(encoded, value); Append(encoded);
            }
            void AppendNullableU64(ulong? value)
            {
                if (!value.HasValue) { Append([]); return; }
                AppendU64(value.Value);
            }
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    private static void Exact(ReadOnlySpan<byte> value, int length, string name,
        bool allowZero = false)
    {
        if (value.Length != length || (!allowZero && value.IndexOfAnyExcept((byte)0) < 0))
            throw new InvalidDataException($"Owner request v2 {name} is invalid.");
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    private static bool FixedNullable(byte[]? left, byte[]? right) =>
        left is null ? right is null : right is not null && Fixed(left, right);
}

internal sealed class ProductionMailboxProtectedOwnerRequestAliasV2
{
    internal const int IntegrityTagLength = 32;
    private static ReadOnlySpan<byte> IntegrityDomain =>
        "Deep/registry/production-mailbox/owner-control/request-id/v2"u8;

    private readonly byte[] routeStateKey;
    private readonly byte[] requestId;
    private readonly byte[] requestHash;
    private readonly byte[] integrityTag;

    private ProductionMailboxProtectedOwnerRequestAliasV2(ReadOnlySpan<byte> routeStateKey,
        ReadOnlySpan<byte> requestId, ReadOnlySpan<byte> requestHash,
        ulong expiresAtUnixSeconds, ulong retainUntilUnixSeconds,
        ReadOnlySpan<byte> integrityTag)
    {
        this.routeStateKey = routeStateKey.ToArray();
        this.requestId = requestId.ToArray();
        this.requestHash = requestHash.ToArray();
        ExpiresAtUnixSeconds = expiresAtUnixSeconds;
        RetainUntilUnixSeconds = retainUntilUnixSeconds;
        this.integrityTag = integrityTag.ToArray();
    }

    internal ReadOnlyMemory<byte> RouteStateKey => routeStateKey.ToArray();
    internal ReadOnlyMemory<byte> RequestId => requestId.ToArray();
    internal ReadOnlyMemory<byte> RequestHash => requestHash.ToArray();
    internal ulong ExpiresAtUnixSeconds { get; }
    internal ulong RetainUntilUnixSeconds { get; }
    internal ReadOnlyMemory<byte> IntegrityTag => integrityTag.ToArray();

    internal static ProductionMailboxProtectedOwnerRequestAliasV2 Create(
        ReadOnlySpan<byte> routeStateKey, ReadOnlySpan<byte> requestId,
        ReadOnlySpan<byte> requestHash, ulong expiresAtUnixSeconds,
        ulong retainUntilUnixSeconds, ReadOnlySpan<byte> integrityKey)
    {
        Validate(routeStateKey, requestId, requestHash, expiresAtUnixSeconds,
            retainUntilUnixSeconds, integrityKey);
        var tag = ComputeTag(routeStateKey, requestId, requestHash, expiresAtUnixSeconds,
            retainUntilUnixSeconds, integrityKey);
        try
        {
            return new(routeStateKey, requestId, requestHash, expiresAtUnixSeconds,
                retainUntilUnixSeconds, tag);
        }
        finally { CryptographicOperations.ZeroMemory(tag); }
    }

    internal static ProductionMailboxProtectedOwnerRequestAliasV2 Restore(
        ReadOnlySpan<byte> routeStateKey, ReadOnlySpan<byte> requestId,
        ReadOnlySpan<byte> requestHash, ulong expiresAtUnixSeconds,
        ulong retainUntilUnixSeconds, ReadOnlySpan<byte> integrityTag,
        ReadOnlySpan<byte> integrityKey)
    {
        Validate(routeStateKey, requestId, requestHash, expiresAtUnixSeconds,
            retainUntilUnixSeconds, integrityKey);
        var expected = ComputeTag(routeStateKey, requestId, requestHash, expiresAtUnixSeconds,
            retainUntilUnixSeconds, integrityKey);
        try
        {
            if (integrityTag.Length != IntegrityTagLength ||
                !CryptographicOperations.FixedTimeEquals(expected, integrityTag))
                throw new InvalidDataException("Owner request-id v2 HMAC is invalid.");
            return new(routeStateKey, requestId, requestHash, expiresAtUnixSeconds,
                retainUntilUnixSeconds, integrityTag);
        }
        finally { CryptographicOperations.ZeroMemory(expected); }
    }

    private static void Validate(ReadOnlySpan<byte> routeStateKey,
        ReadOnlySpan<byte> requestId, ReadOnlySpan<byte> requestHash,
        ulong expiresAtUnixSeconds, ulong retainUntilUnixSeconds,
        ReadOnlySpan<byte> integrityKey)
    {
        if (routeStateKey.Length != 32 || requestId.Length != 32 ||
            requestHash.Length != 32 || integrityKey.Length != 32 ||
            routeStateKey.IndexOfAnyExcept((byte)0) < 0 ||
            requestId.IndexOfAnyExcept((byte)0) < 0 ||
            requestHash.IndexOfAnyExcept((byte)0) < 0 ||
            integrityKey.IndexOfAnyExcept((byte)0) < 0 ||
            expiresAtUnixSeconds is 0 or ulong.MaxValue ||
            retainUntilUnixSeconds < expiresAtUnixSeconds ||
            retainUntilUnixSeconds == ulong.MaxValue)
            throw new InvalidDataException("Owner request-id v2 fields are invalid.");
    }

    private static byte[] ComputeTag(ReadOnlySpan<byte> routeStateKey,
        ReadOnlySpan<byte> requestId, ReadOnlySpan<byte> requestHash,
        ulong expiresAtUnixSeconds, ulong retainUntilUnixSeconds,
        ReadOnlySpan<byte> integrityKey)
    {
        var key = integrityKey.ToArray();
        try
        {
            using var hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, key);
            hmac.AppendData(IntegrityDomain); hmac.AppendData(routeStateKey);
            hmac.AppendData(requestId); hmac.AppendData(requestHash);
            Span<byte> encoded = stackalloc byte[16];
            BinaryPrimitives.WriteUInt64BigEndian(encoded[..8], expiresAtUnixSeconds);
            BinaryPrimitives.WriteUInt64BigEndian(encoded[8..], retainUntilUnixSeconds);
            hmac.AppendData(encoded);
            return hmac.GetHashAndReset();
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }
}
