using System.Buffers.Binary;
using System.Data;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxAuthority;
using Deep.Protocol.DeepExtension.MailboxTopology;
using Npgsql;
using NpgsqlTypes;

namespace Deep.Registry.Api.ProductionMailbox;

internal sealed class ProductionMailboxProtectedGenesisCatalog
{
    internal const int MaximumPayloadBytes = 8 * 1024 * 1024;
    private static ReadOnlySpan<byte> IntegrityDomain =>
        "Deep/registry/production-mailbox/owner-control-genesis/v1"u8;

    private readonly byte[] payload;
    private readonly byte[] integrityTag;
    private readonly byte[] planHash;

    private ProductionMailboxProtectedGenesisCatalog(
        ReadOnlySpan<byte> payload, ReadOnlySpan<byte> integrityTag,
        ReadOnlySpan<byte> planHash)
    {
        this.payload = payload.ToArray();
        this.integrityTag = integrityTag.ToArray();
        this.planHash = planHash.ToArray();
    }

    internal ReadOnlyMemory<byte> Payload => payload.ToArray();
    internal ReadOnlyMemory<byte> IntegrityTag => integrityTag.ToArray();
    internal ReadOnlyMemory<byte> PlanHash => planHash.ToArray();

    internal static ProductionMailboxProtectedGenesisCatalog Freeze(
        ProductionMailboxRouteContinuityGenesisCommitPlan plan,
        ReadOnlySpan<byte> integrityKey)
    {
        ArgumentNullException.ThrowIfNull(plan);
        Exact(integrityKey, 32, "integrity key");
        var enrollment = plan.ToProtectedEnrollmentRestoreContext();
        var history = plan.ToProtectedRouteHistoryRestoreContext();
        var encoded = Encode(plan, enrollment, history);
        if (encoded.Length > MaximumPayloadBytes)
            throw new InvalidDataException("Genesis protected catalog exceeds its bound.");
        var tag = ComputeTag(encoded, integrityKey);
        return new(encoded, tag, plan.PlanHash.Span);
    }

    internal static ProductionMailboxProtectedGenesisCatalog Restore(
        ReadOnlyMemory<byte> payload, ReadOnlyMemory<byte> integrityTag,
        ReadOnlySpan<byte> integrityKey)
    {
        if (payload.Length is < 4 or > MaximumPayloadBytes || integrityTag.Length != 32)
            throw new InvalidDataException("Stored genesis catalog bounds are invalid.");
        Exact(integrityKey, 32, "integrity key");
        var ownedPayload = payload.ToArray();
        var ownedTag = integrityTag.ToArray();
        if (!CryptographicOperations.FixedTimeEquals(
                ComputeTag(ownedPayload, integrityKey), ownedTag))
            throw new InvalidDataException("Stored genesis catalog integrity is invalid.");
        var decoded = Decode(ownedPayload);
        ValidateDecoded(decoded);
        return new(ownedPayload, ownedTag, decoded.PlanHash);
    }

    internal ProductionMailboxRestoredGenesis RestoreProtocol()
    {
        var value = Decode(payload);
        ValidateDecoded(value);
        return ProductionMailboxRestoredGenesis.Restore(value);
    }

    private static byte[] ComputeTag(ReadOnlySpan<byte> encoded, ReadOnlySpan<byte> key)
    {
        using var hmac = new HMACSHA256(key.ToArray());
        hmac.TransformBlock(IntegrityDomain.ToArray(), 0, IntegrityDomain.Length, null, 0);
        hmac.TransformFinalBlock(encoded.ToArray(), 0, encoded.Length);
        return hmac.Hash ?? throw new CryptographicException("Genesis HMAC failed.");
    }

    private static byte[] Encode(
        ProductionMailboxRouteContinuityGenesisCommitPlan plan,
        ProductionMailboxRouteContinuityProtectedEnrollmentContext enrollment,
        ProductionMailboxRouteHistoryProtectedRestoreContext history)
    {
        using var stream = new MemoryStream();
        stream.Write("PMG1"u8);
        WriteU64(stream, plan.ExpectedPreDelegationLocalCommitGeneration);
        WriteU64(stream, plan.ExpectedPreviousDelegationSequence);
        WriteU64(stream, plan.AcceptedAtUnixSeconds);
        foreach (var item in new[]
                 {
                     plan.ExpectedPreDelegationRouteOriginLkg,
                     plan.ExpectedPreDelegationRouteOriginLkgHash,
                     plan.ExpectedPreviousDelegationHash, plan.GenesisIntentHash,
                     plan.CanonicalAnchorAuthority, plan.CanonicalAnchorAuthorityHash,
                     plan.CanonicalAnchorRevocations, plan.CanonicalAnchorRevocationsHash,
                     plan.CanonicalAnchorRouteCertificate, plan.CanonicalAnchorRouteCertificateHash,
                     plan.CanonicalAnchorRouteAuthorization,
                     plan.CanonicalAnchorRouteAuthorizationHash, plan.CanonicalDelegation,
                     plan.CanonicalDelegationHash, plan.CanonicalAcceptance,
                     plan.CanonicalAcceptanceHash, plan.CanonicalEnrolledRouteOriginLkg,
                     plan.EnrolledRouteOriginLkgHash,
                     plan.CanonicalOwnerControlResponderCertificate,
                     plan.CanonicalOwnerControlResponderCertificateHash,
                     plan.CanonicalInitialRouteHistoryCheckpoint,
                     plan.CanonicalInitialRouteHistoryCheckpointHash, plan.PlanHash
                 })
            WriteBytes(stream, item.Span);

        foreach (var item in EnrollmentItems(enrollment)) WriteBytes(stream, item.Span);
        WriteU64(stream, enrollment.AnchorAuthorityGeneration);
        stream.WriteByte((byte)enrollment.AnchorAuthorizationKind);
        WriteU64(stream, enrollment.AnchorRouteAuthorizationSequence);
        WriteU64(stream, enrollment.RouteVerifiedAtUnixSeconds);
        WriteU64(stream, enrollment.AcceptedAtUnixSeconds);
        WriteU64(stream, enrollment.PreviousDelegationSequence);

        foreach (var item in HistoryItems(history)) WriteBytes(stream, item.Span);
        WriteU64(stream, history.LastCommittedBatchSequence);
        WriteU64(stream, history.CurrentAuthorityGeneration);
        WriteU64(stream, history.CurrentRevocationGeneration);
        return stream.ToArray();
    }

    private static DecodedGenesis Decode(ReadOnlySpan<byte> encoded)
    {
        var reader = new BoundedReader(encoded);
        if (!reader.Read(4).SequenceEqual("PMG1"u8))
            throw new InvalidDataException("Stored genesis catalog magic is invalid.");
        var oldGeneration = reader.U64();
        var previousDelegationSequence = reader.U64();
        var acceptedAt = reader.U64();
        var fields = new byte[23][];
        for (var i = 0; i < fields.Length; i++) fields[i] = reader.Bytes(MaximumPayloadBytes);
        var enrollmentItems = new byte[17][];
        for (var i = 0; i < enrollmentItems.Length; i++)
            enrollmentItems[i] = reader.Bytes(512);
        var enrollmentAuthorityGeneration = reader.U64();
        var enrollmentKind = (ProductionMailboxRouteAuthorizationKind)reader.Byte();
        var enrollmentAuthorizationSequence = reader.U64();
        var routeVerifiedAt = reader.U64();
        var enrollmentAcceptedAt = reader.U64();
        var enrollmentPreviousSequence = reader.U64();
        var historyItems = new byte[13][];
        for (var i = 0; i < historyItems.Length; i++) historyItems[i] = reader.Bytes(512);
        var lastBatchSequence = reader.U64();
        var currentAuthorityGeneration = reader.U64();
        var currentRevocationGeneration = reader.U64();
        reader.End();
        return new(oldGeneration, previousDelegationSequence, acceptedAt, fields,
            enrollmentItems, enrollmentAuthorityGeneration, enrollmentKind,
            enrollmentAuthorizationSequence, routeVerifiedAt, enrollmentAcceptedAt,
            enrollmentPreviousSequence, historyItems, lastBatchSequence,
            currentAuthorityGeneration, currentRevocationGeneration);
    }

    private static void ValidateDecoded(DecodedGenesis value)
    {
        var f = value.Fields;
        Exact(f[0], ProductionMailboxRouteContinuityConstants.CanonicalRouteOriginLkgLength,
            "pre ROL1");
        foreach (var index in new[] { 1, 2, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 22 })
            Exact(f[index], 32, "genesis hash");
        Exact(f[8], ProductionMailboxRouteAdvertisementConstants.CanonicalCertificateLength,
            "PRC1");
        Exact(f[10], ProductionMailboxRouteAuthorizationConstants.CanonicalAdvertisementV2Length,
            "PRA2");
        Exact(f[12], ProductionMailboxRouteContinuityConstants.CanonicalDelegationLength,
            "RCD1");
        Exact(f[14], ProductionMailboxRouteContinuityConstants.CanonicalDelegationAcceptanceLength,
            "RDA1");
        Exact(f[16], ProductionMailboxRouteContinuityConstants.CanonicalRouteOriginLkgLength,
            "enrolled ROL1");
        Exact(f[18], ProductionMailboxOwnerControlConstants.ResponderCertificateLength, "OCR1");
        Exact(f[20], ProductionMailboxRouteContinuityConstants.CanonicalRouteHistoryCheckpointLength,
            "initial RHC1");
        if (f[4].Length == 0 || f[4].Length > MaximumPayloadBytes ||
            f[6].Length == 0 || f[6].Length > MaximumPayloadBytes)
            throw new InvalidDataException("Stored genesis PMA1/PMR1 bounds are invalid.");
        if (value.OldLocalGeneration == ulong.MaxValue ||
            value.PreviousDelegationSequence == ulong.MaxValue || value.AcceptedAt == 0 ||
            value.EnrollmentAcceptedAt != value.AcceptedAt)
            throw new InvalidDataException("Stored genesis scalar state is invalid.");
        _ = EnrollmentContext(value);
        _ = HistoryContext(value);
    }

    private static ProductionMailboxRouteContinuityProtectedEnrollmentContext EnrollmentContext(
        DecodedGenesis value)
    {
        var x = value.EnrollmentItems;
        return new(x[0], x[1], x[2], x[3], x[4], x[5], x[6],
            value.EnrollmentAuthorityGeneration, x[7], x[8], value.EnrollmentKind, x[9],
            value.EnrollmentAuthorizationSequence, value.RouteVerifiedAt,
            value.EnrollmentAcceptedAt, value.EnrollmentPreviousSequence, x[10], x[11], x[12],
            x[13], x[14], x[15], x[16]);
    }

    private static ProductionMailboxRouteHistoryProtectedRestoreContext HistoryContext(
        DecodedGenesis value)
    {
        var x = value.HistoryItems;
        return new(x[0], x[1], value.LastBatchSequence, x[2], x[3], x[4], x[5], x[6],
            x[7], x[8], x[9], value.CurrentAuthorityGeneration, x[10],
            value.CurrentRevocationGeneration, x[11], x[12]);
    }

    private static ReadOnlyMemory<byte>[] EnrollmentItems(
        ProductionMailboxRouteContinuityProtectedEnrollmentContext value) =>
    [
        value.NetworkId, value.MailboxOwnerEd25519PublicKey, value.PinnedMrXPublicKeySha256,
        value.BlindedMailboxId, value.BlindedPlacementId, value.RouteDomainHash,
        value.SelectionInputCommitment, value.AnchorCanonicalAuthorityHash,
        value.AnchorCanonicalRouteCertificateHash, value.AnchorCanonicalRouteAuthorizationHash,
        value.PreviousCanonicalDelegationHash, value.CanonicalDelegationHash,
        value.CanonicalAcceptanceHash, value.PreDelegationRouteOriginLkgHash,
        value.EnrolledRouteOriginLkgHash, value.CanonicalOwnerControlResponderCertificate,
        value.CanonicalOwnerControlResponderCertificateHash
    ];

    private static ReadOnlyMemory<byte>[] HistoryItems(
        ProductionMailboxRouteHistoryProtectedRestoreContext value) =>
    [
        value.CanonicalCheckpoint, value.CanonicalCheckpointHash, value.LastCommittedBatchHash,
        value.CurrentRouteOriginLkgHash, value.EnrollmentCanonicalDelegationHash,
        value.EnrollmentCanonicalAcceptanceHash, value.NetworkId, value.RouteDomainHash,
        value.DelegationHistoryBinding, value.PinnedMrXPublicKeySha256,
        value.CurrentCanonicalAuthorityHash, value.CurrentRevocationHeadHash,
        value.CurrentRevocationSnapshotHash
    ];

    private static void WriteBytes(Stream stream, ReadOnlySpan<byte> value)
    {
        Span<byte> length = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)value.Length));
        stream.Write(length); stream.Write(value);
    }

    private static void WriteU64(Stream stream, ulong value)
    {
        Span<byte> bytes = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(bytes, value); stream.Write(bytes);
    }

    private static void Exact(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length) throw new InvalidDataException($"Stored genesis {name} is invalid.");
    }

    internal sealed record DecodedGenesis(
        ulong OldLocalGeneration, ulong PreviousDelegationSequence, ulong AcceptedAt,
        byte[][] Fields, byte[][] EnrollmentItems, ulong EnrollmentAuthorityGeneration,
        ProductionMailboxRouteAuthorizationKind EnrollmentKind,
        ulong EnrollmentAuthorizationSequence, ulong RouteVerifiedAt,
        ulong EnrollmentAcceptedAt, ulong EnrollmentPreviousSequence, byte[][] HistoryItems,
        ulong LastBatchSequence, ulong CurrentAuthorityGeneration,
        ulong CurrentRevocationGeneration)
    {
        internal byte[] PlanHash => Fields[22];
    }

    private ref struct BoundedReader(ReadOnlySpan<byte> bytes)
    {
        private readonly ReadOnlySpan<byte> value = bytes;
        private int offset;
        internal ReadOnlySpan<byte> Read(int length)
        {
            if (length < 0 || value.Length - offset < length)
                throw new InvalidDataException("Stored genesis catalog is truncated.");
            var result = value.Slice(offset, length); offset += length; return result;
        }
        internal byte Byte() => Read(1)[0];
        internal ulong U64() => BinaryPrimitives.ReadUInt64BigEndian(Read(8));
        internal byte[] Bytes(int maximum)
        {
            var length = BinaryPrimitives.ReadUInt32BigEndian(Read(4));
            if (length > maximum || length > int.MaxValue)
                throw new InvalidDataException("Stored genesis field exceeds its bound.");
            return Read((int)length).ToArray();
        }
        internal void End()
        {
            if (offset != value.Length)
                throw new InvalidDataException("Stored genesis catalog has trailing bytes.");
        }
    }
}

internal sealed class ProductionMailboxRestoredGenesis
{
    private ProductionMailboxRestoredGenesis(
        ProductionMailboxProtectedGenesisCatalog.DecodedGenesis value,
        ProductionMailboxRouteContinuityProtectedEnrollmentContext enrollmentContext,
        ProductionMailboxRouteHistoryProtectedRestoreContext historyContext,
        VerifiedProductionMailboxHistoricalRouteAnchor anchor,
        VerifiedProductionMailboxRouteHistoryCursor cursor,
        VerifiedProductionMailboxRouteContinuityEnrollment verifiedEnrollment)
    {
        Value = value; EnrollmentContext = enrollmentContext; HistoryContext = historyContext;
        Anchor = anchor; Cursor = cursor;
        Enrollment = verifiedEnrollment;
    }

    internal ProductionMailboxProtectedGenesisCatalog.DecodedGenesis Value { get; }
    internal ProductionMailboxRouteContinuityProtectedEnrollmentContext EnrollmentContext { get; }
    internal ProductionMailboxRouteHistoryProtectedRestoreContext HistoryContext { get; }
    internal VerifiedProductionMailboxHistoricalRouteAnchor Anchor { get; }
    internal VerifiedProductionMailboxRouteHistoryCursor Cursor { get; }
    internal VerifiedProductionMailboxRouteContinuityEnrollment Enrollment { get; }

    internal static ProductionMailboxRestoredGenesis Restore(
        ProductionMailboxProtectedGenesisCatalog.DecodedGenesis value)
    {
        var x = value.EnrollmentItems;
        var enrollment = new ProductionMailboxRouteContinuityProtectedEnrollmentContext(
            x[0], x[1], x[2], x[3], x[4], x[5], x[6], value.EnrollmentAuthorityGeneration,
            x[7], x[8], value.EnrollmentKind, x[9], value.EnrollmentAuthorizationSequence,
            value.RouteVerifiedAt, value.EnrollmentAcceptedAt, value.EnrollmentPreviousSequence,
            x[10], x[11], x[12], x[13], x[14], x[15], x[16]);
        var h = value.HistoryItems;
        var history = new ProductionMailboxRouteHistoryProtectedRestoreContext(
            h[0], h[1], value.LastBatchSequence, h[2], h[3], h[4], h[5], h[6], h[7],
            h[8], h[9], value.CurrentAuthorityGeneration, h[10],
            value.CurrentRevocationGeneration, h[11], h[12]);
        var f = value.Fields;
        var authorityValue = ProductionMailboxAuthorityCodec.Decode(f[4]);
        if (authorityValue.AuthorityGeneration is 0 or ulong.MaxValue)
            throw new InvalidDataException("Stored genesis PMA1 generation is invalid.");
        var verifiedAuthority = ProductionMailboxAuthorityVerifier.Verify(authorityValue,
            new ProductionMailboxAuthorityVerificationContext
            {
                PinnedMrXPublicKeySha256 = enrollment.PinnedMrXPublicKeySha256,
                ExpectedNetworkId = enrollment.NetworkId,
                LastCommittedGeneration = authorityValue.AuthorityGeneration - 1,
                LastCommittedAuthorityHash = authorityValue.PreviousAuthorityHash,
                LastCommittedRevocationGeneration = authorityValue.Revocation.Generation,
                LastCommittedRevocationHeadHash = authorityValue.Revocation.HeadHash,
                LastCommittedRevocationSnapshotHash = authorityValue.Revocation.SnapshotHash,
                NowUnixSeconds = value.AcceptedAt,
                ClockSkewSeconds = 0
            }, new SodiumProductionMailboxAuthoritySignatureVerifier());
        var verifiedRevocations = ProductionMailboxRevocationSnapshotVerifier.Verify(f[6],
            verifiedAuthority, value.AcceptedAt, 0,
            new SodiumProductionMailboxRevocationSnapshotSignatureVerifier());
        var verifiedCertificate = ProductionMailboxRouteCertificateVerifier.Verify(f[8],
            verifiedAuthority, value.AcceptedAt, 0,
            new SodiumProductionMailboxRouteSignatureVerifier());
        var advertisement = ProductionMailboxRouteAuthorizationCodec.DecodeAdvertisementV2(f[10]);
        var verifiedAuthorization = ProductionMailboxRouteAuthorizationVerifier
            .VerifyOwnerAuthorization(f[10], verifiedAuthority,
                new ProductionMailboxOwnerRouteAuthorizationVerificationContext
                {
                    ExpectedNetworkId = enrollment.NetworkId,
                    ExpectedRouteDomainHash = enrollment.RouteDomainHash,
                    ExpectedPredecessorKind = advertisement.PredecessorAuthorizationKind,
                    ExpectedPredecessorHash = advertisement.PredecessorCanonicalRouteAuthorizationHash,
                    ExpectedPredecessorSequence = advertisement.PredecessorRouteAuthorizationSequence,
                    NowUnixSeconds = value.AcceptedAt,
                    ClockSkewSeconds = 0
                });
        var verifiedEnrollment = ProductionMailboxRouteContinuityVerifier.VerifyEnrollment(
            f[12], f[14], verifiedAuthority, verifiedRevocations, verifiedCertificate,
            verifiedAuthorization,
            new ProductionMailboxRouteContinuityEnrollmentVerificationContext
            {
                ExpectedNetworkId = enrollment.NetworkId,
                ExpectedPinnedMrXPublicKeySha256 = enrollment.PinnedMrXPublicKeySha256,
                ExpectedRouteDomainHash = enrollment.RouteDomainHash,
                ExpectedMailboxOwnerEd25519PublicKey = enrollment.MailboxOwnerEd25519PublicKey,
                ExpectedBlindedMailboxId = enrollment.BlindedMailboxId,
                ExpectedBlindedPlacementId = enrollment.BlindedPlacementId,
                ExpectedSelectionInputCommitment = enrollment.SelectionInputCommitment,
                ExpectedPreDelegationRouteOriginLkgHash =
                    enrollment.PreDelegationRouteOriginLkgHash,
                ExpectedRouteVerifiedAtUnixSeconds = enrollment.RouteVerifiedAtUnixSeconds,
                LastDelegationSequence = enrollment.PreviousDelegationSequence,
                LastCanonicalDelegationHash = enrollment.PreviousCanonicalDelegationHash,
                NowUnixSeconds = value.AcceptedAt,
                ClockSkewSeconds = 0
            });
        var anchor = ProductionMailboxRouteIssuerAuthoring.RestoreHistoricalAnchor(
            f[12], f[14], f[0], f[16], f[18], verifiedAuthority,
            verifiedRevocations, verifiedCertificate, verifiedAuthorization, enrollment);
        var cursor = ProductionMailboxRouteHistoryAuthoring.RestoreCursor(
            f[20], anchor, history);
        if (!CryptographicOperations.FixedTimeEquals(f[5], verifiedAuthority.CanonicalAuthorityHash.Span)
            || !CryptographicOperations.FixedTimeEquals(f[7],
                verifiedRevocations.CanonicalSnapshotHash.Span)
            || !CryptographicOperations.FixedTimeEquals(f[9],
                verifiedCertificate.CanonicalCertificateHash.Span)
            || !CryptographicOperations.FixedTimeEquals(f[11],
                verifiedAuthorization.CanonicalHash.Span))
            throw new InvalidDataException("Stored genesis artifact hashes are split.");
        return new(value, enrollment, history, anchor, cursor, verifiedEnrollment);
    }
}

internal static class ProductionMailboxOwnerControlAccounting
{
    internal const long RowOverheadBytes = 128;
    internal const long EnrollmentOperationMaximumBytes = 1_774;
    internal const long EnrollmentAliasBytes = 280;
    internal const long OwnerRequestMaximumBytes = 1_042;
    internal const long OwnerRequestAliasBytes = 272;
    internal const long OwnerRevocationAliasBytes = 248;
    internal const long TerminalReservationBytes = 512;

    internal static long GenesisBytes(int payloadLength) => checked(
        RowOverheadBytes + 32L + 32 + payloadLength + 32);

    internal static long PreparedEnrollmentBytes => checked(
        EnrollmentOperationMaximumBytes + EnrollmentAliasBytes
        + GenesisBytes(ProductionMailboxProtectedGenesisCatalog.MaximumPayloadBytes));

    internal const long NewOwnerRequestBytes =
        OwnerRequestMaximumBytes + OwnerRequestAliasBytes;
}

public sealed partial class InMemoryProductionMailboxStateStore :
    IProductionMailboxOwnerControlStateStore
{
    private readonly Dictionary<string, ProductionMailboxProtectedGenesisCatalog> genesisCatalogs =
        new(StringComparer.Ordinal);
    private readonly Dictionary<string, MutableOwnerEnrollmentOperation> ownerEnrollmentOperations =
        new(StringComparer.Ordinal);
    private readonly Dictionary<string, MutableOwnerEnrollmentAlias> ownerEnrollmentRequestIds =
        new(StringComparer.Ordinal);
    private readonly Dictionary<string, MutableOwnerControlRequest> ownerControlRequests =
        new(StringComparer.Ordinal);
    private readonly Dictionary<string, MutableOwnerRequestAlias> ownerControlRequestIds =
        new(StringComparer.Ordinal);
    private readonly Dictionary<string, MutableOwnerRevocationAlias> ownerRevocationRequestIds =
        new(StringComparer.Ordinal);

    async ValueTask<ProductionMailboxOwnerEnrollmentPrepareResult>
        IProductionMailboxOwnerControlStateStore.PrepareOwnerEnrollmentAsync(
        ReadOnlyMemory<byte> routeStateKey, ReadOnlyMemory<byte> requestId,
        ReadOnlyMemory<byte> requestHash, ReadOnlyMemory<byte> operationHash,
        ReadOnlyMemory<byte> intentHash, ReadOnlyMemory<byte> sourceArtifactClosureHash,
        ReadOnlyMemory<byte> ownerControlKeyToken,
        ulong nowUnixSeconds,
        CancellationToken cancellationToken)
    {
        var route = ProductionMailboxRouteContinuityStateGuard.FreezeKey(routeStateKey);
        var requestIdBytes = Exact(requestId, 16, "enrollment request ID");
        var requestHashBytes = Exact(requestHash, 32, "enrollment request hash");
        var operation = Exact(operationHash, 32, "enrollment operation hash");
        var intent = Exact(intentHash, 32, "genesis intent hash");
        var source = Exact(sourceArtifactClosureHash, 32, "source artifact closure hash");
        var keyToken = Exact(ownerControlKeyToken, 32, "OCR key token");
        if (nowUnixSeconds is 0 or ulong.MaxValue)
            throw new InvalidDataException("Enrollment time is invalid.");
        await gate.WaitAsync(cancellationToken);
        try
        {
            var routeHex = Convert.ToHexString(route);
            publishedArtifactClosureHash ??= source.ToArray();
            if (!Fixed(publishedArtifactClosureHash, source))
                return new(ProductionMailboxOwnerEnrollmentStatus.Conflict,
                    nowUnixSeconds, null);
            if (routeContinuityStates.TryGetValue(routeHex, out var current)
                && current.OwnerRevocationGeneration != 0)
                return new(ProductionMailboxOwnerEnrollmentStatus.Revoked, nowUnixSeconds, null);
            var operationKey = EnrollmentOperationKey(route, operation);
            var requestKey = EnrollmentRequestKey(route, requestIdBytes);
            if (ownerEnrollmentRequestIds.TryGetValue(requestKey, out var mapped))
            {
                VerifyEnrollmentAliasTag(mapped);
                if (!string.Equals(mapped.OperationKey, operationKey, StringComparison.Ordinal)
                    || !Fixed(mapped.RequestHash, requestHashBytes))
                    return new(ProductionMailboxOwnerEnrollmentStatus.Conflict,
                        nowUnixSeconds, null);
            }
            if (ownerEnrollmentOperations.TryGetValue(operationKey, out var existing))
            {
                VerifyEnrollmentTag(existing);
                if (!Fixed(existing.IntentHash, intent)
                    || !Fixed(existing.SourceArtifactClosureHash, source)
                    || !Fixed(existing.KeyToken, keyToken))
                    return new(ProductionMailboxOwnerEnrollmentStatus.Conflict,
                        existing.AcceptedAtUnixSeconds, null);
                if (existing.CanonicalResponse is not null)
                {
                    if (!genesisCatalogs.TryGetValue(routeHex, out var storedCatalog)
                        || current is null)
                        throw new InvalidDataException(
                            "Completed owner enrollment durable closure is split.");
                    var verifiedCatalog = ProductionMailboxProtectedGenesisCatalog.Restore(
                        storedCatalog.Payload, storedCatalog.IntegrityTag,
                        v2PublicationIntegrityKey);
                    ValidateEnrollmentReplay(current, existing.PlanHash!, existing.PublicKey!,
                        existing.CanonicalResponse, verifiedCatalog, nowUnixSeconds);
                }
                if (mapped is null)
                {
                    if (!EnsureOwnerControlCapacity(route, nowUnixSeconds, 1,
                            ProductionMailboxOwnerControlAccounting.EnrollmentAliasBytes))
                        return new(ProductionMailboxOwnerEnrollmentStatus.CapacityExceeded,
                            existing.AcceptedAtUnixSeconds, null);
                    mapped = new(route, requestIdBytes, requestHashBytes, operationKey,
                        checked(existing.AcceptedAtUnixSeconds +
                            ProductionMailboxOwnerControlConstants
                                .MaximumResponderCertificateLifetimeSeconds), []);
                    mapped.IntegrityTag = ComputeEnrollmentAliasTag(mapped);
                    ownerEnrollmentRequestIds[requestKey] = mapped;
                }
                return existing.CanonicalResponse is null
                    ? new(ProductionMailboxOwnerEnrollmentStatus.Prepared,
                        existing.AcceptedAtUnixSeconds, null)
                    : new(ProductionMailboxOwnerEnrollmentStatus.ExactReplay,
                        existing.AcceptedAtUnixSeconds, existing.CanonicalResponse.ToArray());
            }
            if (!EnsureOwnerControlCapacity(route, nowUnixSeconds, 3,
                    ProductionMailboxOwnerControlAccounting.PreparedEnrollmentBytes))
                return new(ProductionMailboxOwnerEnrollmentStatus.CapacityExceeded,
                    nowUnixSeconds, null);
            var created = new MutableOwnerEnrollmentOperation(route, requestIdBytes,
                requestHashBytes, operation, intent, source, keyToken, nowUnixSeconds);
            created.IntegrityTag = ComputeEnrollmentTag(created);
            ownerEnrollmentOperations.Add(operationKey, created);
            var enrollmentAlias = new MutableOwnerEnrollmentAlias(route, requestIdBytes,
                requestHashBytes, operationKey,
                checked(nowUnixSeconds + ProductionMailboxOwnerControlConstants
                    .MaximumResponderCertificateLifetimeSeconds), []);
            enrollmentAlias.IntegrityTag = ComputeEnrollmentAliasTag(enrollmentAlias);
            ownerEnrollmentRequestIds.Add(requestKey, enrollmentAlias);
            return new(ProductionMailboxOwnerEnrollmentStatus.Prepared, nowUnixSeconds, null);
        }
        finally { gate.Release(); }
    }

    async ValueTask<ProductionMailboxOwnerEnrollmentStatus>
        IProductionMailboxOwnerControlStateStore.CommitOwnerEnrollmentAsync(
        ReadOnlyMemory<byte> routeStateKey, ReadOnlyMemory<byte> requestId,
        ReadOnlyMemory<byte> requestHash, ReadOnlyMemory<byte> operationHash,
        ReadOnlyMemory<byte> sourceArtifactClosureHash,
        ProductionMailboxRouteContinuityGenesisCommitPlan plan,
        ProductionMailboxOwnerControlKeyHandle key,
        ReadOnlyMemory<byte> canonicalResponse, ulong nowUnixSeconds,
        CancellationToken cancellationToken)
    {
        var route = ProductionMailboxRouteContinuityStateGuard.FreezeKey(routeStateKey);
        var requestIdBytes = Exact(requestId, 16, "enrollment request ID");
        var requestHashBytes = Exact(requestHash, 32, "enrollment request hash");
        var operation = Exact(operationHash, 32, "enrollment operation hash");
        var source = Exact(sourceArtifactClosureHash, 32, "source artifact closure hash");
        var response = Exact(canonicalResponse,
            ProductionMailboxOwnerControlHostCodec.EnrollmentResponseLength,
            "enrollment response");
        var keyId = Exact(key.KeyId, 32, "OCR key ID");
        var publicKey = Exact(key.PublicKey, 32, "OCR public key");
        var frozen = ProductionMailboxFrozenEnrollment.Freeze(plan);
        var catalog = ProductionMailboxProtectedGenesisCatalog.Freeze(plan,
            v2PublicationIntegrityKey);
        if (!Fixed(operation, plan.CanonicalDelegationHash.Span))
            throw new InvalidDataException("Enrollment operation differs from genesis RCD1.");
        await gate.WaitAsync(cancellationToken);
        try
        {
            var operationKey = EnrollmentOperationKey(route, operation);
            if (!ownerEnrollmentOperations.TryGetValue(operationKey, out var record))
                return ProductionMailboxOwnerEnrollmentStatus.Conflict;
            VerifyEnrollmentTag(record);
            if (record.CleanupStarted)
                return ProductionMailboxOwnerEnrollmentStatus.Conflict;
            if (!Fixed(record.RequestId, requestIdBytes)
                || !Fixed(record.RequestHash, requestHashBytes)
                || !Fixed(record.IntentHash, plan.GenesisIntentHash.Span)
                || !Fixed(record.SourceArtifactClosureHash, source)
                || publishedArtifactClosureHash is null
                || !Fixed(publishedArtifactClosureHash, source)
                || record.AcceptedAtUnixSeconds != plan.AcceptedAtUnixSeconds
                || nowUnixSeconds < record.AcceptedAtUnixSeconds)
                return ProductionMailboxOwnerEnrollmentStatus.Conflict;
            if (record.CanonicalResponse is not null)
                return Fixed(record.CanonicalResponse, response)
                    && Fixed(record.PlanHash!, plan.PlanHash.Span)
                    ? ProductionMailboxOwnerEnrollmentStatus.ExactReplay
                    : ProductionMailboxOwnerEnrollmentStatus.Conflict;
            var delegation = ProductionMailboxRouteContinuityCodec.DecodeDelegation(
                plan.CanonicalDelegation.Span);
            var ocr = ProductionMailboxOwnerControlTransportCodec.DecodeResponderCertificate(
                plan.CanonicalOwnerControlResponderCertificate.Span);
            if (nowUnixSeconds >= delegation.ExpiresAtUnixSeconds
                || nowUnixSeconds >= ocr.ExpiresAtUnixSeconds
                || !Fixed(ocr.ResponderEd25519PublicKey.Span, publicKey))
                return ProductionMailboxOwnerEnrollmentStatus.Conflict;
            var routeHex = Convert.ToHexString(route);
            routeContinuityStates.TryGetValue(routeHex, out var current);
            var status = ValidateEnrollmentPredecessor(current, frozen);
            if (status != ProductionMailboxRouteContinuityCommitStatus.Accepted)
                return status == ProductionMailboxRouteContinuityCommitStatus.ExactReplay
                    ? ProductionMailboxOwnerEnrollmentStatus.Conflict
                    : ProductionMailboxOwnerEnrollmentStatus.Revoked;
            routeContinuityStates[routeHex] = FromEnrollment(route, current, frozen);
            genesisCatalogs[routeHex] = catalog;
            record.CanonicalResponse = response;
            record.PlanHash = plan.PlanHash.ToArray();
            record.KeyId = keyId; record.PublicKey = publicKey;
            record.IntegrityTag = ComputeEnrollmentTag(record);
            var aliasKey = EnrollmentRequestKey(route, requestIdBytes);
            if (!ownerEnrollmentRequestIds.TryGetValue(aliasKey, out var alias))
                throw new InvalidDataException("Enrollment request alias disappeared.");
            VerifyEnrollmentAliasTag(alias);
            alias.RetainUntilUnixSeconds = Math.Min(
                ProductionMailboxRouteContinuityCodec.DecodeDelegation(
                    plan.CanonicalDelegation.Span).ExpiresAtUnixSeconds,
                ocr.ExpiresAtUnixSeconds);
            alias.IntegrityTag = ComputeEnrollmentAliasTag(alias);
            return ProductionMailboxOwnerEnrollmentStatus.Prepared;
        }
        finally { gate.Release(); }
    }

    async ValueTask<ProductionMailboxOwnerRequestPrepareResult>
        IProductionMailboxOwnerControlStateStore.PrepareNoChangeAsync(
        ReadOnlyMemory<byte> routeStateKey, ReadOnlyMemory<byte> activeScope,
        VerifiedProductionMailboxOwnerControlRequest request,
        ulong nowUnixSeconds, CancellationToken cancellationToken)
    {
        var route = ProductionMailboxRouteContinuityStateGuard.FreezeKey(routeStateKey);
        var scope = Exact(activeScope, 32, "active request scope");
        ArgumentNullException.ThrowIfNull(request);
        var bytes = request.CanonicalBytes.ToArray();
        var hash = request.CanonicalHash.ToArray();
        var decoded = ProductionMailboxOwnerControlTransportCodec.DecodeRequest(bytes);
        var requestId = Exact(decoded.RequestId, 32, "owner request ID");
        await gate.WaitAsync(cancellationToken);
        try
        {
            var routeHex = Convert.ToHexString(route);
            if (!routeContinuityStates.TryGetValue(routeHex, out var source)
                || !genesisCatalogs.ContainsKey(routeHex))
                return new(ProductionMailboxOwnerRequestStatus.MissingState, null, null);
            if (source.OwnerRevocationGeneration != 0)
                return new(ProductionMailboxOwnerRequestStatus.Revoked, null, null);
            var enrollment = GetCompletedOwnerEnrollment(route);
            var sourceFingerprint = ComputeOwnerRequestSourceFingerprint(source,
                enrollment.SourceArtifactClosureHash, bytes);
            if (sourceFingerprint is null)
                return new(ProductionMailboxOwnerRequestStatus.Conflict, null, null);
            AuthenticatedOwnerControlGc(nowUnixSeconds);
            var aliasKey = EnrollmentRequestKey(route, requestId);
            var scopeKey = Convert.ToHexString(scope);
            if (ownerControlRequestIds.TryGetValue(aliasKey, out var requestAlias))
            {
                VerifyOwnerRequestAliasTag(requestAlias);
                if (!Fixed(requestAlias.RequestHash, hash))
                    return new(ProductionMailboxOwnerRequestStatus.Conflict, null, null);
                if (nowUnixSeconds >= requestAlias.ExpiresAtUnixSeconds)
                    return new(ProductionMailboxOwnerRequestStatus.Stale, null, null);
            }
            if (ownerControlRequests.TryGetValue(scopeKey, out var existing))
            {
                VerifyRequestTag(existing);
                if (requestAlias is null)
                    throw new InvalidDataException(
                        "Stored owner-control request is missing its request-ID alias.");
                if (!Fixed(existing.RequestHash, hash))
                    return new(ProductionMailboxOwnerRequestStatus.Conflict, null, null);
                if (!Fixed(existing.SourceFingerprint, sourceFingerprint))
                    return new(ProductionMailboxOwnerRequestStatus.Conflict, null, null);
                if (existing.DeliveryAuthorized)
                    return new(ProductionMailboxOwnerRequestStatus.ExactReplay,
                        existing.ResponseHeader?.ToArray(), existing.ResponsePayload?.ToArray());
                return new(ProductionMailboxOwnerRequestStatus.Prepared, null, null);
            }
            var additionalEntries = requestAlias is null ? 2 : 1;
            var additionalBytes = requestAlias is null
                ? ProductionMailboxOwnerControlAccounting.NewOwnerRequestBytes
                : ProductionMailboxOwnerControlAccounting.OwnerRequestMaximumBytes;
            if (!EnsureOwnerControlCapacity(route, nowUnixSeconds, additionalEntries,
                    additionalBytes, runGc: false))
                return new(ProductionMailboxOwnerRequestStatus.Conflict, null, null);
            if (requestAlias is null)
            {
                var restored = ProductionMailboxProtectedGenesisCatalog.Restore(
                    genesisCatalogs[routeHex].Payload, genesisCatalogs[routeHex].IntegrityTag,
                    v2PublicationIntegrityKey).RestoreProtocol();
                var delegationExpiry = restored.Enrollment.Delegation.ExpiresAtUnixSeconds;
                var ocrExpiry = ProductionMailboxOwnerControlTransportCodec
                    .DecodeResponderCertificate(restored.EnrollmentContext
                        .CanonicalOwnerControlResponderCertificate.Span).ExpiresAtUnixSeconds;
                requestAlias = new(route, requestId, hash, request.ExpiresAtUnixSeconds,
                    Math.Min(delegationExpiry, ocrExpiry), []);
                requestAlias.IntegrityTag = ComputeOwnerRequestAliasTag(requestAlias);
                ownerControlRequestIds.Add(aliasKey, requestAlias);
            }
            var created = new MutableOwnerControlRequest(route, scope, bytes, hash,
                sourceFingerprint,
                request.ExpiresAtUnixSeconds);
            created.IntegrityTag = ComputeRequestTag(created);
            ownerControlRequests.Add(scopeKey, created);
            return new(ProductionMailboxOwnerRequestStatus.Prepared, null, null);
        }
        finally { gate.Release(); }
    }

    async ValueTask<ProductionMailboxOwnerNoChangePlanResult>
        IProductionMailboxOwnerControlStateStore.PlanNoChangeAsync(
        ReadOnlyMemory<byte> routeStateKey, ReadOnlyMemory<byte> activeScope,
        VerifiedProductionMailboxOwnerControlRequest request,
        ulong nowUnixSeconds, CancellationToken cancellationToken)
    {
        var route = ProductionMailboxRouteContinuityStateGuard.FreezeKey(routeStateKey);
        var scope = Exact(activeScope, 32, "active request scope");
        ArgumentNullException.ThrowIfNull(request);
        await gate.WaitAsync(cancellationToken);
        try
        {
            var routeHex = Convert.ToHexString(route);
            if (!routeContinuityStates.TryGetValue(routeHex, out var source)
                || source.OwnerRevocationGeneration != 0)
                return new(ProductionMailboxOwnerRequestStatus.Revoked, 0, 0);
            if (!ownerControlRequests.TryGetValue(Convert.ToHexString(scope), out var record))
                return new(ProductionMailboxOwnerRequestStatus.MissingState, 0, 0);
            VerifyRequestTag(record);
            var sourceFingerprint = ComputeOwnerRequestSourceFingerprint(source,
                GetCompletedOwnerEnrollment(route).SourceArtifactClosureHash,
                record.CanonicalRequest);
            if (sourceFingerprint is null || !Fixed(record.SourceFingerprint, sourceFingerprint))
                return new(ProductionMailboxOwnerRequestStatus.Conflict, 0, 0);
            if (!Fixed(record.RequestHash, request.CanonicalHash.Span)
                || nowUnixSeconds >= record.ExpiresAtUnixSeconds)
                return new(ProductionMailboxOwnerRequestStatus.Stale, 0, 0);
            if (record.PlannedIssuedAtUnixSeconds is not null)
                return new(ProductionMailboxOwnerRequestStatus.Prepared,
                    record.PlannedIssuedAtUnixSeconds.Value,
                    record.PlannedExpiresAtUnixSeconds!.Value);
            var expires = Math.Min(record.ExpiresAtUnixSeconds,
                checked(nowUnixSeconds + 60));
            if (nowUnixSeconds == 0 || nowUnixSeconds >= expires)
                return new(ProductionMailboxOwnerRequestStatus.Stale, 0, 0);
            record.PlannedIssuedAtUnixSeconds = nowUnixSeconds;
            record.PlannedExpiresAtUnixSeconds = expires;
            record.IntegrityTag = ComputeRequestTag(record);
            return new(ProductionMailboxOwnerRequestStatus.Prepared, nowUnixSeconds, expires);
        }
        finally { gate.Release(); }
    }

    async ValueTask<ProductionMailboxOwnerRequestStatus>
        IProductionMailboxOwnerControlStateStore.RecordNoChangeAsync(
        ReadOnlyMemory<byte> routeStateKey, ReadOnlyMemory<byte> activeScope,
        VerifiedProductionMailboxOwnerControlRequest request,
        VerifiedProductionMailboxOwnerControlResponse response,
        ulong nowUnixSeconds, CancellationToken cancellationToken)
    {
        var route = ProductionMailboxRouteContinuityStateGuard.FreezeKey(routeStateKey);
        var scope = Exact(activeScope, 32, "active request scope");
        ArgumentNullException.ThrowIfNull(request); ArgumentNullException.ThrowIfNull(response);
        if (response.Kind != ProductionMailboxOwnerControlResponseKind.NoChange)
            throw new InvalidDataException("Only NoChange is allowed in owner-control Slice 4A.");
        var header = response.CanonicalHeader.ToArray();
        var payload = response.CanonicalPayload.ToArray();
        await gate.WaitAsync(cancellationToken);
        try
        {
            var routeHex = Convert.ToHexString(route);
            if (!routeContinuityStates.TryGetValue(routeHex, out var source)
                || source.OwnerRevocationGeneration != 0)
                return ProductionMailboxOwnerRequestStatus.Revoked;
            if (!ownerControlRequests.TryGetValue(Convert.ToHexString(scope), out var record))
                return ProductionMailboxOwnerRequestStatus.MissingState;
            VerifyRequestTag(record);
            var sourceFingerprint = ComputeOwnerRequestSourceFingerprint(source,
                GetCompletedOwnerEnrollment(route).SourceArtifactClosureHash,
                record.CanonicalRequest);
            if (sourceFingerprint is null || !Fixed(record.SourceFingerprint, sourceFingerprint))
                return ProductionMailboxOwnerRequestStatus.Conflict;
            if (!Fixed(record.RequestHash, request.CanonicalHash.Span)
                || nowUnixSeconds >= record.ExpiresAtUnixSeconds)
                return ProductionMailboxOwnerRequestStatus.Stale;
            if (record.PlannedIssuedAtUnixSeconds is null)
                return ProductionMailboxOwnerRequestStatus.Stale;
            var decoded = ProductionMailboxOwnerControlTransportCodec.DecodeResponseHeader(header);
            if (decoded.IssuedAtUnixSeconds != record.PlannedIssuedAtUnixSeconds
                || decoded.ExpiresAtUnixSeconds != record.PlannedExpiresAtUnixSeconds)
                return ProductionMailboxOwnerRequestStatus.Conflict;
            if (record.ResponseHeader is not null)
                return Fixed(record.ResponseHeader, header) && Fixed(record.ResponsePayload!, payload)
                    ? ProductionMailboxOwnerRequestStatus.ExactReplay
                    : ProductionMailboxOwnerRequestStatus.Conflict;
            record.ResponseHeader = header; record.ResponsePayload = payload;
            record.IntegrityTag = ComputeRequestTag(record);
            return ProductionMailboxOwnerRequestStatus.Prepared;
        }
        finally { gate.Release(); }
    }

    async ValueTask<ProductionMailboxOwnerRequestPrepareResult>
        IProductionMailboxOwnerControlStateStore.AuthorizeDeliveryAsync(
        ReadOnlyMemory<byte> routeStateKey, ReadOnlyMemory<byte> activeScope,
        ReadOnlyMemory<byte> requestHash, ulong nowUnixSeconds,
        CancellationToken cancellationToken)
    {
        var route = ProductionMailboxRouteContinuityStateGuard.FreezeKey(routeStateKey);
        var scope = Exact(activeScope, 32, "active request scope");
        var hash = Exact(requestHash, 32, "request hash");
        await gate.WaitAsync(cancellationToken);
        try
        {
            var routeHex = Convert.ToHexString(route);
            if (!routeContinuityStates.TryGetValue(routeHex, out var source)
                || source.OwnerRevocationGeneration != 0)
                return new(ProductionMailboxOwnerRequestStatus.Revoked, null, null);
            if (!ownerControlRequests.TryGetValue(Convert.ToHexString(scope), out var record))
                return new(ProductionMailboxOwnerRequestStatus.MissingState, null, null);
            VerifyRequestTag(record);
            var sourceFingerprint = ComputeOwnerRequestSourceFingerprint(source,
                GetCompletedOwnerEnrollment(route).SourceArtifactClosureHash,
                record.CanonicalRequest);
            if (sourceFingerprint is null || !Fixed(record.SourceFingerprint, sourceFingerprint))
                return new(ProductionMailboxOwnerRequestStatus.Conflict, null, null);
            if (!Fixed(record.RequestHash, hash) || nowUnixSeconds >= record.ExpiresAtUnixSeconds
                || record.ResponseHeader is null || record.ResponsePayload is null)
                return new(ProductionMailboxOwnerRequestStatus.Stale, null, null);
            record.DeliveryAuthorized = true;
            record.IntegrityTag = ComputeRequestTag(record);
            return new(ProductionMailboxOwnerRequestStatus.ExactReplay,
                record.ResponseHeader.ToArray(), record.ResponsePayload.ToArray());
        }
        finally { gate.Release(); }
    }

    async ValueTask<ProductionMailboxRouteContinuityCommitResult>
        IProductionMailboxOwnerControlStateStore.CommitOwnerRevocationAndFenceAsync(
        ReadOnlyMemory<byte> routeStateKey, ReadOnlyMemory<byte> requestId,
        VerifiedProductionMailboxRouteContinuityRevocation revocation,
        CancellationToken cancellationToken)
    {
        var id = Exact(requestId, 16, "revocation request ID");
        var route = ProductionMailboxRouteContinuityStateGuard.FreezeKey(routeStateKey);
        var frozen = ProductionMailboxFrozenOwnerRevocation.Freeze(revocation);
        await gate.WaitAsync(cancellationToken);
        try
        {
            var routeHex = Convert.ToHexString(route);
            var aliasKey = EnrollmentRequestKey(route, id);
            if (ownerRevocationRequestIds.TryGetValue(aliasKey, out var alias))
            {
                VerifyRevocationAliasTag(alias);
                if (!Fixed(alias.OperationHash, frozen.CanonicalHash))
                    return new(ProductionMailboxRouteContinuityCommitStatus.Conflict,
                        routeContinuityStates.GetValueOrDefault(routeHex));
            }
            else
            {
                if (!EnsureOwnerControlCapacity(route, 0, 1,
                        ProductionMailboxOwnerControlAccounting.OwnerRevocationAliasBytes,
                        terminal: true))
                    return new(ProductionMailboxRouteContinuityCommitStatus.Conflict,
                        routeContinuityStates.GetValueOrDefault(routeHex));
                if (!genesisCatalogs.TryGetValue(routeHex, out var protectedCatalog))
                    throw new InvalidDataException("Owner revocation genesis catalog is missing.");
                var restored = ProductionMailboxProtectedGenesisCatalog.Restore(
                    protectedCatalog.Payload, protectedCatalog.IntegrityTag,
                    v2PublicationIntegrityKey).RestoreProtocol();
                var ocr = ProductionMailboxOwnerControlTransportCodec.DecodeResponderCertificate(
                    restored.EnrollmentContext.CanonicalOwnerControlResponderCertificate.Span);
                alias = new(route, id, frozen.CanonicalHash,
                    Math.Min(restored.Enrollment.Delegation.ExpiresAtUnixSeconds,
                        ocr.ExpiresAtUnixSeconds), []);
                alias.IntegrityTag = ComputeRevocationAliasTag(alias);
                ownerRevocationRequestIds.Add(aliasKey, alias);
            }
            routeContinuityStates.TryGetValue(routeHex, out var current);
            var status = ValidateOwnerRevocationPredecessor(current, frozen);
            if (status == ProductionMailboxRouteContinuityCommitStatus.Accepted)
            {
                var next = FromOwnerRevocation(current!, frozen);
                routeContinuityStates[routeHex] = next;
                foreach (var value in ownerControlRequests.Values.Where(value =>
                             Fixed(value.RouteStateKey, route)))
                {
                    value.Revoked = true;
                    value.IntegrityTag = ComputeRequestTag(value);
                }
                return new(status, next);
            }
            return new(status, current);
        }
        finally { gate.Release(); }
    }

    async ValueTask<ProductionMailboxOwnerControlKeyHandle?>
        IProductionMailboxOwnerControlStateStore.GetOwnerControlKeyAsync(
        ReadOnlyMemory<byte> routeStateKey, CancellationToken cancellationToken)
    {
        var route = ProductionMailboxRouteContinuityStateGuard.FreezeKey(routeStateKey);
        await gate.WaitAsync(cancellationToken);
        try
        {
            var matches = ownerEnrollmentOperations.Values.Where(value =>
                Fixed(value.RouteStateKey, route) && value.CanonicalResponse is not null).ToArray();
            if (matches.Length == 0) return null;
            if (matches.Length != 1)
                throw new InvalidDataException("Owner key identity is ambiguous.");
            var match = matches[0];
            VerifyEnrollmentTag(match);
            return new(match.KeyId!.ToArray(), match.PublicKey!.ToArray());
        }
        finally { gate.Release(); }
    }

    async ValueTask<ProductionMailboxAbandonedOwnerKeyClaim?>
        IProductionMailboxOwnerControlStateStore.ClaimAbandonedOwnerKeyAsync(
        ulong nowUnixSeconds, ulong leaseUntilUnixSeconds,
        CancellationToken cancellationToken)
    {
        if (nowUnixSeconds == 0 || leaseUntilUnixSeconds <= nowUnixSeconds)
            throw new InvalidDataException("Owner-key cleanup lease is invalid.");
        await gate.WaitAsync(cancellationToken);
        try
        {
            var value = ownerEnrollmentOperations.Values.FirstOrDefault(x =>
                x.CanonicalResponse is null
                && nowUnixSeconds >= x.RetainUntilUnixSeconds
                && (!x.CleanupStarted || nowUnixSeconds >= x.CleanupLeaseUntilUnixSeconds));
            if (value is null) return null;
            VerifyEnrollmentTag(value);
            value.CleanupStarted = true;
            value.CleanupLeaseUntilUnixSeconds = leaseUntilUnixSeconds;
            value.IntegrityTag = ComputeEnrollmentTag(value);
            return new(value.RouteStateKey.ToArray(), value.OperationHash.ToArray(),
                value.KeyToken.ToArray());
        }
        finally { gate.Release(); }
    }

    async ValueTask IProductionMailboxOwnerControlStateStore.CompleteAbandonedOwnerKeyAsync(
        ReadOnlyMemory<byte> routeStateKey, ReadOnlyMemory<byte> operationHash,
        ReadOnlyMemory<byte> keyToken, CancellationToken cancellationToken)
    {
        var route = Exact(routeStateKey, 32, "cleanup route key");
        var operation = Exact(operationHash, 32, "cleanup operation hash");
        var token = Exact(keyToken, 32, "cleanup key token");
        await gate.WaitAsync(cancellationToken);
        try
        {
            var key = EnrollmentOperationKey(route, operation);
            if (!ownerEnrollmentOperations.TryGetValue(key, out var value)) return;
            VerifyEnrollmentTag(value);
            if (value.CanonicalResponse is not null || !value.CleanupStarted
                || !Fixed(value.KeyToken, token))
                throw new InvalidDataException("Owner-key cleanup state is inconsistent.");
            ownerEnrollmentOperations.Remove(key);
            foreach (var alias in ownerEnrollmentRequestIds.Where(x =>
                         string.Equals(x.Value.OperationKey, key, StringComparison.Ordinal))
                     .Select(x => x.Key).ToArray())
                ownerEnrollmentRequestIds.Remove(alias);
        }
        finally { gate.Release(); }
    }

    private MutableOwnerEnrollmentOperation GetCompletedOwnerEnrollment(byte[] route)
    {
        var matches = ownerEnrollmentOperations.Values.Where(value =>
            Fixed(value.RouteStateKey, route) && value.CanonicalResponse is not null).ToArray();
        if (matches.Length != 1)
            throw new InvalidDataException("Owner enrollment source is missing or ambiguous.");
        VerifyEnrollmentTag(matches[0]);
        return matches[0];
    }

    private bool EnsureOwnerControlCapacity(byte[] route, ulong nowUnixSeconds,
        int additionalEntries, long additionalBytes, bool terminal = false,
        bool runGc = true)
    {
        if (runGc) AuthenticatedOwnerControlGc(nowUnixSeconds);
        var routeHex = Convert.ToHexString(route);
        var routeCount = ownerEnrollmentOperations.Values.Count(x => Fixed(x.RouteStateKey, route))
            + ownerControlRequests.Values.Count(x => Fixed(x.RouteStateKey, route))
            + ownerControlRequestIds.Values.Count(x => Fixed(x.RouteStateKey, route))
            + ownerRevocationRequestIds.Values.Count(x => Fixed(x.RouteStateKey, route))
            + ownerEnrollmentRequestIds.Keys.Count(x => x.StartsWith(
                routeHex + ":", StringComparison.Ordinal))
            + (genesisCatalogs.ContainsKey(routeHex) ? 1 : 0)
            + ownerEnrollmentOperations.Values.Count(x => Fixed(x.RouteStateKey, route)
                && x.CanonicalResponse is null);
        var globalCount = ownerEnrollmentOperations.Count + ownerControlRequests.Count
            + ownerControlRequestIds.Count + ownerRevocationRequestIds.Count
            + ownerEnrollmentRequestIds.Count + genesisCatalogs.Count
            + ownerEnrollmentOperations.Values.Count(x => x.CanonicalResponse is null);
        if (globalCount > ownerControlLimits.MaximumEntriesGlobal
            || routeCount > ownerControlLimits.MaximumEntriesPerRoute)
            return false;
        foreach (var value in ownerEnrollmentOperations.Values) VerifyEnrollmentTag(value);
        foreach (var value in ownerControlRequests.Values) VerifyRequestTag(value);
        foreach (var value in ownerControlRequestIds.Values) VerifyOwnerRequestAliasTag(value);
        foreach (var value in ownerRevocationRequestIds.Values) VerifyRevocationAliasTag(value);
        foreach (var value in ownerEnrollmentRequestIds.Values) VerifyEnrollmentAliasTag(value);
        foreach (var value in genesisCatalogs.Values)
            _ = ProductionMailboxProtectedGenesisCatalog.Restore(value.Payload,
                value.IntegrityTag, v2PublicationIntegrityKey);
        long bytes = genesisCatalogs.Values.Sum(x =>
            ProductionMailboxOwnerControlAccounting.GenesisBytes(x.Payload.Length));
        bytes += ownerEnrollmentOperations.Values.Sum(x =>
            ProductionMailboxOwnerControlAccounting.EnrollmentOperationMaximumBytes
            + (x.CanonicalResponse is null
                ? ProductionMailboxOwnerControlAccounting.GenesisBytes(
                    ProductionMailboxProtectedGenesisCatalog.MaximumPayloadBytes)
                : 0));
        bytes += ownerControlRequests.Count
            * ProductionMailboxOwnerControlAccounting.OwnerRequestMaximumBytes;
        bytes += ownerControlRequestIds.Count
            * ProductionMailboxOwnerControlAccounting.OwnerRequestAliasBytes;
        bytes += ownerRevocationRequestIds.Count
            * ProductionMailboxOwnerControlAccounting.OwnerRevocationAliasBytes;
        bytes += ownerEnrollmentRequestIds.Count
            * ProductionMailboxOwnerControlAccounting.EnrollmentAliasBytes;
        var reserveEntries = terminal ? 0 : 1;
        var reserveBytes = terminal ? 0
            : ProductionMailboxOwnerControlAccounting.TerminalReservationBytes;
        return routeCount + additionalEntries + reserveEntries
                <= ownerControlLimits.MaximumEntriesPerRoute
            && globalCount + additionalEntries + reserveEntries
                <= ownerControlLimits.MaximumEntriesGlobal
            && bytes + additionalBytes + reserveBytes
                <= ownerControlLimits.MaximumStateBytes;
    }

    private void AuthenticatedOwnerControlGc(ulong nowUnixSeconds)
    {
        var removed = 0;
        foreach (var key in ownerControlRequests.Where(pair =>
                     nowUnixSeconds >= pair.Value.ExpiresAtUnixSeconds)
                 .Take(ownerControlLimits.MaximumGcBatch - removed)
                 .Select(pair => pair.Key).ToArray())
        {
            var value = ownerControlRequests[key];
            VerifyRequestTag(value);
            if (nowUnixSeconds >= value.ExpiresAtUnixSeconds)
            {
                ownerControlRequests.Remove(key); removed++;
            }
        }
        foreach (var key in ownerControlRequestIds.Where(pair =>
                     nowUnixSeconds >= pair.Value.RetainUntilUnixSeconds)
                 .Take(ownerControlLimits.MaximumGcBatch - removed)
                 .Select(pair => pair.Key).ToArray())
        {
            var value = ownerControlRequestIds[key];
            VerifyOwnerRequestAliasTag(value);
            if (nowUnixSeconds >= value.RetainUntilUnixSeconds)
            {
                ownerControlRequestIds.Remove(key); removed++;
            }
        }
        foreach (var key in ownerEnrollmentRequestIds.Where(pair =>
                     nowUnixSeconds >= pair.Value.RetainUntilUnixSeconds)
                 .Take(ownerControlLimits.MaximumGcBatch - removed)
                 .Select(pair => pair.Key).ToArray())
        {
            var value = ownerEnrollmentRequestIds[key];
            VerifyEnrollmentAliasTag(value);
            if (nowUnixSeconds >= value.RetainUntilUnixSeconds)
            {
                ownerEnrollmentRequestIds.Remove(key); removed++;
            }
        }
        foreach (var key in ownerRevocationRequestIds.Where(pair =>
                     nowUnixSeconds >= pair.Value.RetainUntilUnixSeconds)
                 .Take(ownerControlLimits.MaximumGcBatch - removed)
                 .Select(pair => pair.Key).ToArray())
        {
            var value = ownerRevocationRequestIds[key];
            VerifyRevocationAliasTag(value);
            if (nowUnixSeconds >= value.RetainUntilUnixSeconds)
            {
                ownerRevocationRequestIds.Remove(key); removed++;
            }
        }
    }

    private byte[] ComputeEnrollmentTag(MutableOwnerEnrollmentOperation value)
    {
        using var hash = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256,
            v2PublicationIntegrityKey);
        hash.AppendData("Deep/registry/production-mailbox/owner-enrollment-phase/v1"u8);
        foreach (var item in new[] { value.RouteStateKey, value.RequestId, value.RequestHash,
                     value.OperationHash, value.IntentHash, value.SourceArtifactClosureHash,
                     value.KeyToken,
                     value.CanonicalResponse ?? [],
                     value.PlanHash ?? [], value.KeyId ?? [], value.PublicKey ?? [] })
            Append(hash, item);
        Append(hash, OwnerU64(value.AcceptedAtUnixSeconds));
        Append(hash, OwnerU64(value.RetainUntilUnixSeconds));
        Append(hash, OwnerU64(value.CleanupLeaseUntilUnixSeconds));
        hash.AppendData([value.CleanupStarted ? (byte)1 : (byte)0]);
        return hash.GetHashAndReset();
    }

    private void VerifyEnrollmentTag(MutableOwnerEnrollmentOperation value)
    {
        if (value.IntegrityTag.Length != 32 || !CryptographicOperations.FixedTimeEquals(
                ComputeEnrollmentTag(value), value.IntegrityTag))
            throw new InvalidDataException("Stored owner enrollment phase integrity is invalid.");
    }

    internal static void ValidateEnrollmentReplay(
        ProductionMailboxRouteContinuityStateSnapshot state,
        ReadOnlySpan<byte> planHash, ReadOnlySpan<byte> publicKey,
        ReadOnlySpan<byte> canonicalResponse,
        ProductionMailboxProtectedGenesisCatalog catalog, ulong nowUnixSeconds)
    {
        var restored = catalog.RestoreProtocol();
        var delegation = restored.Enrollment.Delegation;
        var ocr = ProductionMailboxOwnerControlTransportCodec.DecodeResponderCertificate(
            restored.EnrollmentContext.CanonicalOwnerControlResponderCertificate.Span);
        if (nowUnixSeconds >= delegation.ExpiresAtUnixSeconds
            || nowUnixSeconds >= ocr.ExpiresAtUnixSeconds
            || !Fixed(planHash, catalog.PlanHash.Span)
            || !Fixed(publicKey, ocr.ResponderEd25519PublicKey.Span)
            || !Fixed(state.CanonicalRouteOriginLkg.Span,
                restored.Value.Fields[16])
            || !Fixed(state.CanonicalDelegationHash.Span,
                restored.Enrollment.CanonicalDelegationHash.Span)
            || state.History is null
            || !Fixed(state.History.CanonicalCheckpointHash.Span,
                restored.Value.Fields[21]))
            throw new InvalidDataException("Completed owner enrollment replay closure is invalid.");
        ProductionMailboxOwnerControlHostCodec.ValidateEnrollmentResponse(
            canonicalResponse, restored);
    }

    internal static byte[]? ComputeOwnerRequestSourceFingerprint(
        ProductionMailboxRouteContinuityStateSnapshot? state,
        ReadOnlySpan<byte> sourceArtifactClosureHash, ReadOnlySpan<byte> canonicalRequest)
    {
        if (state is null || state.History is null || sourceArtifactClosureHash.Length != 32)
            return null;
        var request = ProductionMailboxOwnerControlTransportCodec.DecodeRequest(canonicalRequest);
        var delegation = ProductionMailboxRouteContinuityCodec.DecodeDelegation(
            state.CanonicalDelegation.Span);
        if (request.Operation != ProductionMailboxOwnerControlOperation.AdvanceOrFinalize
            || !Fixed(request.NetworkId.Span, delegation.NetworkId.Span)
            || !Fixed(request.MailboxOwnerEd25519PublicKey.Span,
                delegation.MailboxOwnerEd25519PublicKey.Span)
            || !Fixed(request.RouteDomainHash.Span, delegation.RouteDomainHash.Span)
            || !Fixed(request.SelectionInputCommitment.Span,
                delegation.SelectionInputCommitment.Span)
            || !Fixed(request.PredecessorRouteOriginLkgHash.Span,
                state.RouteOriginLkgHash.Span)
            || !Fixed(request.CurrentRouteHistoryCheckpointHash.Span,
                state.History.CanonicalCheckpointHash.Span)
            || request.CurrentRouteHistoryBatchSequence !=
                state.History.LastCommittedBatchSequence
            || request.ExpectedAuthorizationKind != state.CurrentAuthorizationKind
            || request.PredecessorAuthorizationSequence != state.CurrentAuthorizationSequence
            || !Fixed(request.PredecessorAuthorizationHash.Span,
                state.CurrentAuthorizationHash.Span))
            return null;
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("Deep/registry/production-mailbox/owner-request-source/v1"u8);
        foreach (var item in new[]
                 {
                     state.RouteOriginLkgHash.ToArray(),
                     state.History.CanonicalCheckpointHash.ToArray(),
                     state.CurrentAuthorizationHash.ToArray(),
                     delegation.SelectionInputCommitment.ToArray(),
                     sourceArtifactClosureHash.ToArray()
                 })
            Append(hash, item);
        Append(hash, OwnerU64(state.History.LastCommittedBatchSequence));
        Append(hash, OwnerU64(state.CurrentAuthorizationSequence));
        hash.AppendData([(byte)state.CurrentAuthorizationKind]);
        return hash.GetHashAndReset();
    }

    private byte[] ComputeRequestTag(MutableOwnerControlRequest value)
    {
        using var hash = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256,
            v2PublicationIntegrityKey);
        hash.AppendData("Deep/registry/production-mailbox/owner-control-phase/v1"u8);
        foreach (var item in new[] { value.RouteStateKey, value.ActiveScope,
                     value.CanonicalRequest, value.RequestHash,
                     value.SourceFingerprint,
                     value.ResponseHeader ?? [], value.ResponsePayload ?? [] })
            Append(hash, item);
        Append(hash, OwnerU64(value.ExpiresAtUnixSeconds));
        Append(hash, value.PlannedIssuedAtUnixSeconds is null
            ? [] : OwnerU64(value.PlannedIssuedAtUnixSeconds.Value));
        Append(hash, value.PlannedExpiresAtUnixSeconds is null
            ? [] : OwnerU64(value.PlannedExpiresAtUnixSeconds.Value));
        hash.AppendData([value.DeliveryAuthorized ? (byte)1 : (byte)0,
            value.Revoked ? (byte)1 : (byte)0]);
        return hash.GetHashAndReset();
    }

    private void VerifyRequestTag(MutableOwnerControlRequest value)
    {
        if (value.IntegrityTag.Length != 32 || !CryptographicOperations.FixedTimeEquals(
                ComputeRequestTag(value), value.IntegrityTag))
            throw new InvalidDataException("Stored owner-control phase integrity is invalid.");
    }

    private byte[] ComputeRevocationAliasTag(MutableOwnerRevocationAlias value)
    {
        using var hash = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256,
            v2PublicationIntegrityKey);
        hash.AppendData("Deep/registry/production-mailbox/owner-revocation-alias/v1"u8);
        foreach (var item in new[] { value.RouteStateKey, value.RequestId,
                     value.OperationHash }) Append(hash, item);
        Append(hash, OwnerU64(value.RetainUntilUnixSeconds));
        return hash.GetHashAndReset();
    }

    private byte[] ComputeEnrollmentAliasTag(MutableOwnerEnrollmentAlias value)
    {
        using var hash = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256,
            v2PublicationIntegrityKey);
        hash.AppendData("Deep/registry/production-mailbox/owner-enrollment-alias/v1"u8);
        foreach (var item in new[] { value.RouteStateKey, value.RequestId, value.RequestHash,
                     System.Text.Encoding.ASCII.GetBytes(value.OperationKey) })
            Append(hash, item);
        Append(hash, OwnerU64(value.RetainUntilUnixSeconds));
        return hash.GetHashAndReset();
    }

    private void VerifyEnrollmentAliasTag(MutableOwnerEnrollmentAlias value)
    {
        if (value.IntegrityTag.Length != 32 || !CryptographicOperations.FixedTimeEquals(
                ComputeEnrollmentAliasTag(value), value.IntegrityTag))
            throw new InvalidDataException("Stored owner-enrollment alias integrity is invalid.");
    }

    private void VerifyRevocationAliasTag(MutableOwnerRevocationAlias value)
    {
        if (value.IntegrityTag.Length != 32 || !CryptographicOperations.FixedTimeEquals(
                ComputeRevocationAliasTag(value), value.IntegrityTag))
            throw new InvalidDataException("Stored owner-revocation alias integrity is invalid.");
    }

    private byte[] ComputeOwnerRequestAliasTag(MutableOwnerRequestAlias value)
    {
        using var hash = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256,
            v2PublicationIntegrityKey);
        hash.AppendData("Deep/registry/production-mailbox/owner-request-alias/v1"u8);
        foreach (var item in new[] { value.RouteStateKey, value.RequestId, value.RequestHash })
            Append(hash, item);
        Append(hash, OwnerU64(value.ExpiresAtUnixSeconds));
        Append(hash, OwnerU64(value.RetainUntilUnixSeconds));
        return hash.GetHashAndReset();
    }

    private void VerifyOwnerRequestAliasTag(MutableOwnerRequestAlias value)
    {
        if (value.IntegrityTag.Length != 32 || !CryptographicOperations.FixedTimeEquals(
                ComputeOwnerRequestAliasTag(value), value.IntegrityTag))
            throw new InvalidDataException("Stored owner-request alias integrity is invalid.");
    }

    private static string EnrollmentOperationKey(ReadOnlySpan<byte> route,
        ReadOnlySpan<byte> operation) => $"{Convert.ToHexString(route)}:{Convert.ToHexString(operation)}";
    private static string EnrollmentRequestKey(ReadOnlySpan<byte> route,
        ReadOnlySpan<byte> request) => $"{Convert.ToHexString(route)}:{Convert.ToHexString(request)}";
    private static byte[] Exact(ReadOnlyMemory<byte> value, int length, string name)
    {
        if (value.Length != length || value.Span.IndexOfAnyExcept((byte)0) < 0)
            throw new InvalidDataException($"{name} is invalid.");
        return value.ToArray();
    }
    private static void Append(IncrementalHash hash, ReadOnlySpan<byte> value)
    {
        Span<byte> length = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)value.Length));
        hash.AppendData(length); hash.AppendData(value);
    }
    private static byte[] OwnerU64(ulong value)
    {
        var bytes = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(bytes, value);
        return bytes;
    }
    private sealed class MutableOwnerEnrollmentOperation(
        byte[] routeStateKey, byte[] requestId, byte[] requestHash, byte[] operationHash,
        byte[] intentHash, byte[] sourceArtifactClosureHash, byte[] keyToken,
        ulong acceptedAtUnixSeconds)
    {
        internal byte[] RouteStateKey { get; } = routeStateKey;
        internal byte[] RequestId { get; } = requestId;
        internal byte[] RequestHash { get; } = requestHash;
        internal byte[] OperationHash { get; } = operationHash;
        internal byte[] IntentHash { get; } = intentHash;
        internal byte[] SourceArtifactClosureHash { get; } = sourceArtifactClosureHash;
        internal byte[] KeyToken { get; } = keyToken;
        internal ulong AcceptedAtUnixSeconds { get; } = acceptedAtUnixSeconds;
        internal ulong RetainUntilUnixSeconds { get; } = checked(acceptedAtUnixSeconds
            + ProductionMailboxOwnerControlConstants.MaximumResponderCertificateLifetimeSeconds);
        internal bool CleanupStarted { get; set; }
        internal ulong CleanupLeaseUntilUnixSeconds { get; set; }
        internal byte[]? CanonicalResponse { get; set; }
        internal byte[]? PlanHash { get; set; }
        internal byte[]? KeyId { get; set; }
        internal byte[]? PublicKey { get; set; }
        internal byte[] IntegrityTag { get; set; } = [];
    }

    private sealed class MutableOwnerControlRequest(
        byte[] routeStateKey, byte[] activeScope, byte[] canonicalRequest,
        byte[] requestHash, byte[] sourceFingerprint, ulong expiresAtUnixSeconds)
    {
        internal byte[] RouteStateKey { get; } = routeStateKey;
        internal byte[] ActiveScope { get; } = activeScope;
        internal byte[] CanonicalRequest { get; } = canonicalRequest;
        internal byte[] RequestHash { get; } = requestHash;
        internal byte[] SourceFingerprint { get; } = sourceFingerprint;
        internal ulong ExpiresAtUnixSeconds { get; } = expiresAtUnixSeconds;
        internal ulong? PlannedIssuedAtUnixSeconds { get; set; }
        internal ulong? PlannedExpiresAtUnixSeconds { get; set; }
        internal byte[]? ResponseHeader { get; set; }
        internal byte[]? ResponsePayload { get; set; }
        internal bool DeliveryAuthorized { get; set; }
        internal bool Revoked { get; set; }
        internal byte[] IntegrityTag { get; set; } = [];
    }

    private sealed class MutableOwnerRevocationAlias(byte[] routeStateKey, byte[] requestId,
        byte[] operationHash, ulong retainUntilUnixSeconds, byte[] integrityTag)
    {
        internal byte[] RouteStateKey { get; } = routeStateKey;
        internal byte[] RequestId { get; } = requestId;
        internal byte[] OperationHash { get; } = operationHash;
        internal ulong RetainUntilUnixSeconds { get; } = retainUntilUnixSeconds;
        internal byte[] IntegrityTag { get; set; } = integrityTag;
    }

    private sealed class MutableOwnerEnrollmentAlias(byte[] routeStateKey, byte[] requestId,
        byte[] requestHash, string operationKey, ulong retainUntilUnixSeconds,
        byte[] integrityTag)
    {
        internal byte[] RouteStateKey { get; } = routeStateKey;
        internal byte[] RequestId { get; } = requestId;
        internal byte[] RequestHash { get; } = requestHash;
        internal string OperationKey { get; } = operationKey;
        internal ulong RetainUntilUnixSeconds { get; set; } = retainUntilUnixSeconds;
        internal byte[] IntegrityTag { get; set; } = integrityTag;
    }

    private sealed class MutableOwnerRequestAlias(byte[] routeStateKey, byte[] requestId,
        byte[] requestHash, ulong expiresAtUnixSeconds, ulong retainUntilUnixSeconds,
        byte[] integrityTag)
    {
        internal byte[] RouteStateKey { get; } = routeStateKey;
        internal byte[] RequestId { get; } = requestId;
        internal byte[] RequestHash { get; } = requestHash;
        internal ulong ExpiresAtUnixSeconds { get; } = expiresAtUnixSeconds;
        internal ulong RetainUntilUnixSeconds { get; } = retainUntilUnixSeconds;
        internal byte[] IntegrityTag { get; set; } = integrityTag;
    }
}

public sealed partial class PostgreSqlProductionMailboxStateStore :
    IProductionMailboxOwnerControlStateStore
{
    private readonly SemaphoreSlim ownerControlInitializeGate = new(1, 1);
    private volatile bool ownerControlInitialized;

    private static ProductionMailboxOwnerControlStoreLimits ValidateOwnerControlLimits(
        ProductionMailboxOwnerControlStoreLimits? value)
    {
        var result = value ?? new(); result.Validate(); return result;
    }

    private async ValueTask ConfigureOwnerControlTransactionAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction,
        CancellationToken cancellationToken)
    {
        var statement = checked(ownerControlLimits.StatementTimeoutSeconds * 1000);
        var locks = checked(ownerControlLimits.LockTimeoutSeconds * 1000);
        var idle = checked(ownerControlLimits.IdleTransactionTimeoutSeconds * 1000);
        await using var command = new NpgsqlCommand($"""
            SET LOCAL statement_timeout = '{statement}ms';
            SET LOCAL lock_timeout = '{locks}ms';
            SET LOCAL idle_in_transaction_session_timeout = '{idle}ms';
            """, connection, transaction);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private async ValueTask EnsureOwnerControlSchemaAsync(
        NpgsqlConnection connection, CancellationToken cancellationToken)
    {
        if (ownerControlInitialized) return;
        await ownerControlInitializeGate.WaitAsync(cancellationToken);
        try
        {
            if (ownerControlInitialized) return;
            const string sql = """
                CREATE TABLE IF NOT EXISTS production_mailbox_route_genesis_v1(
                    route_state_key bytea PRIMARY KEY CHECK(octet_length(route_state_key)=32),
                    plan_hash bytea NOT NULL UNIQUE CHECK(octet_length(plan_hash)=32),
                    protected_payload bytea NOT NULL CHECK(octet_length(protected_payload) BETWEEN 4 AND 8388608),
                    integrity_tag bytea NOT NULL CHECK(octet_length(integrity_tag)=32)
                );
                CREATE TABLE IF NOT EXISTS production_mailbox_owner_enrollment_ops_v1(
                    route_state_key bytea NOT NULL CHECK(octet_length(route_state_key)=32),
                    request_id bytea NOT NULL CHECK(octet_length(request_id)=16),
                    request_hash bytea NOT NULL CHECK(octet_length(request_hash)=32),
                    operation_hash bytea NOT NULL CHECK(octet_length(operation_hash)=32),
                    intent_hash bytea NOT NULL CHECK(octet_length(intent_hash)=32),
                    source_artifact_closure_hash bytea NOT NULL CHECK(octet_length(source_artifact_closure_hash)=32),
                    ocr_key_token bytea NULL CHECK(ocr_key_token IS NULL OR octet_length(ocr_key_token)=32),
                    retain_until bytea NULL CHECK(retain_until IS NULL OR octet_length(retain_until)=8),
                    cleanup_started boolean NOT NULL DEFAULT false,
                    cleanup_lease_until bytea NULL CHECK(cleanup_lease_until IS NULL OR octet_length(cleanup_lease_until)=8),
                    accepted_at bytea NOT NULL CHECK(octet_length(accepted_at)=8),
                    canonical_response bytea NULL CHECK(canonical_response IS NULL OR octet_length(canonical_response)=1285),
                    plan_hash bytea NULL CHECK(plan_hash IS NULL OR octet_length(plan_hash)=32),
                    ocr_key_id bytea NULL CHECK(ocr_key_id IS NULL OR octet_length(ocr_key_id)=32),
                    ocr_public_key bytea NULL CHECK(ocr_public_key IS NULL OR octet_length(ocr_public_key)=32),
                    integrity_tag bytea NOT NULL CHECK(octet_length(integrity_tag)=32),
                    PRIMARY KEY(route_state_key,operation_hash),
                    UNIQUE(route_state_key,request_id)
                );
                CREATE TABLE IF NOT EXISTS production_mailbox_owner_requests_v1(
                    active_scope bytea PRIMARY KEY CHECK(octet_length(active_scope)=32),
                    route_state_key bytea NOT NULL CHECK(octet_length(route_state_key)=32),
                    canonical_request bytea NOT NULL CHECK(octet_length(canonical_request)=344),
                    request_hash bytea NOT NULL CHECK(octet_length(request_hash)=32),
                    source_fingerprint bytea NULL CHECK(source_fingerprint IS NULL OR octet_length(source_fingerprint)=32),
                    expires_at bytea NOT NULL CHECK(octet_length(expires_at)=8),
                    planned_issued_at bytea NULL CHECK(planned_issued_at IS NULL OR octet_length(planned_issued_at)=8),
                    planned_expires_at bytea NULL CHECK(planned_expires_at IS NULL OR octet_length(planned_expires_at)=8),
                    response_header bytea NULL CHECK(response_header IS NULL OR octet_length(response_header)=384),
                    response_payload bytea NULL CHECK(response_payload IS NULL OR octet_length(response_payload)=0),
                    delivery_authorized boolean NOT NULL,
                    revoked boolean NOT NULL,
                    integrity_tag bytea NOT NULL CHECK(octet_length(integrity_tag)=32)
                );
                CREATE INDEX IF NOT EXISTS production_mailbox_owner_requests_route_idx
                    ON production_mailbox_owner_requests_v1(route_state_key);
                ALTER TABLE production_mailbox_owner_requests_v1
                    ADD COLUMN IF NOT EXISTS planned_issued_at bytea NULL;
                ALTER TABLE production_mailbox_owner_requests_v1
                    ADD COLUMN IF NOT EXISTS planned_expires_at bytea NULL;
                ALTER TABLE production_mailbox_owner_requests_v1
                    ADD COLUMN IF NOT EXISTS source_fingerprint bytea NULL;
                ALTER TABLE production_mailbox_owner_enrollment_ops_v1
                    ADD COLUMN IF NOT EXISTS ocr_key_token bytea NULL;
                ALTER TABLE production_mailbox_owner_enrollment_ops_v1
                    ADD COLUMN IF NOT EXISTS retain_until bytea NULL;
                ALTER TABLE production_mailbox_owner_enrollment_ops_v1
                    ADD COLUMN IF NOT EXISTS cleanup_started boolean NOT NULL DEFAULT false;
                ALTER TABLE production_mailbox_owner_enrollment_ops_v1
                    ADD COLUMN IF NOT EXISTS cleanup_lease_until bytea NULL;
                CREATE TABLE IF NOT EXISTS production_mailbox_owner_enrollment_ids_v1(
                    route_state_key bytea NOT NULL CHECK(octet_length(route_state_key)=32),
                    request_id bytea NOT NULL CHECK(octet_length(request_id)=16),
                    operation_hash bytea NOT NULL CHECK(octet_length(operation_hash)=32),
                    request_hash bytea NOT NULL CHECK(octet_length(request_hash)=32),
                    retain_until bytea NULL CHECK(retain_until IS NULL OR octet_length(retain_until)=8),
                    integrity_tag bytea NOT NULL CHECK(octet_length(integrity_tag)=32),
                    PRIMARY KEY(route_state_key,request_id)
                );
                CREATE TABLE IF NOT EXISTS production_mailbox_owner_revocation_ids_v1(
                    route_state_key bytea NOT NULL CHECK(octet_length(route_state_key)=32),
                    request_id bytea NOT NULL CHECK(octet_length(request_id)=16),
                    operation_hash bytea NOT NULL CHECK(octet_length(operation_hash)=32),
                    retain_until bytea NULL CHECK(retain_until IS NULL OR octet_length(retain_until)=8),
                    integrity_tag bytea NOT NULL CHECK(octet_length(integrity_tag)=32),
                    PRIMARY KEY(route_state_key,request_id)
                );
                CREATE TABLE IF NOT EXISTS production_mailbox_owner_request_ids_v1(
                    route_state_key bytea NOT NULL CHECK(octet_length(route_state_key)=32),
                    request_id bytea NOT NULL CHECK(octet_length(request_id)=32),
                    request_hash bytea NOT NULL CHECK(octet_length(request_hash)=32),
                    expires_at bytea NOT NULL CHECK(octet_length(expires_at)=8),
                    retain_until bytea NOT NULL CHECK(octet_length(retain_until)=8),
                    integrity_tag bytea NOT NULL CHECK(octet_length(integrity_tag)=32),
                    PRIMARY KEY(route_state_key,request_id)
                );
                ALTER TABLE production_mailbox_owner_enrollment_ids_v1
                    ADD COLUMN IF NOT EXISTS retain_until bytea NULL;
                ALTER TABLE production_mailbox_owner_revocation_ids_v1
                    ADD COLUMN IF NOT EXISTS retain_until bytea NULL;
                """;
            await using var command = new NpgsqlCommand(sql, connection);
            await command.ExecuteNonQueryAsync(cancellationToken);
            ownerControlInitialized = true;
        }
        finally { ownerControlInitializeGate.Release(); }
    }

    private static async ValueTask<ProductionMailboxProtectedGenesisCatalog?>
        ReadGenesisCatalogAsync(NpgsqlConnection connection, NpgsqlTransaction transaction,
            ReadOnlyMemory<byte> routeStateKey, ReadOnlyMemory<byte> key,
            CancellationToken cancellationToken)
    {
        const string sql = """
            SELECT octet_length(protected_payload),protected_payload,integrity_tag,plan_hash
            FROM production_mailbox_route_genesis_v1 WHERE route_state_key=@key FOR UPDATE
            """;
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue("key", routeStateKey.ToArray());
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken)) return null;
        var length = reader.GetInt32(0);
        if (length is < 4 or > ProductionMailboxProtectedGenesisCatalog.MaximumPayloadBytes)
            throw new InvalidDataException("Stored genesis catalog length is invalid.");
        var payload = reader.GetFieldValue<byte[]>(1);
        var tag = reader.GetFieldValue<byte[]>(2);
        var planHash = reader.GetFieldValue<byte[]>(3);
        if (payload.Length != length)
            throw new InvalidDataException("Stored genesis catalog length changed while reading.");
        var catalog = ProductionMailboxProtectedGenesisCatalog.Restore(payload, tag, key.Span);
        if (!CryptographicOperations.FixedTimeEquals(catalog.PlanHash.Span, planHash))
            throw new InvalidDataException("Stored genesis plan hash is split.");
        return catalog;
    }

    private static async ValueTask InsertGenesisCatalogAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction,
        ReadOnlyMemory<byte> routeStateKey, ProductionMailboxProtectedGenesisCatalog value,
        CancellationToken cancellationToken)
    {
        const string sql = """
            INSERT INTO production_mailbox_route_genesis_v1(
                route_state_key,plan_hash,protected_payload,integrity_tag)
            VALUES(@key,@plan,@payload,@tag)
            """;
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue("key", routeStateKey.ToArray());
        command.Parameters.AddWithValue("plan", value.PlanHash.ToArray());
        command.Parameters.AddWithValue("payload", value.Payload.ToArray());
        command.Parameters.AddWithValue("tag", value.IntegrityTag.ToArray());
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    async ValueTask<ProductionMailboxOwnerEnrollmentPrepareResult>
        IProductionMailboxOwnerControlStateStore.PrepareOwnerEnrollmentAsync(
        ReadOnlyMemory<byte> routeStateKey, ReadOnlyMemory<byte> requestId,
        ReadOnlyMemory<byte> requestHash, ReadOnlyMemory<byte> operationHash,
        ReadOnlyMemory<byte> intentHash, ReadOnlyMemory<byte> sourceArtifactClosureHash,
        ReadOnlyMemory<byte> ownerControlKeyToken,
        ulong nowUnixSeconds,
        CancellationToken cancellationToken)
    {
        var route = ProductionMailboxRouteContinuityStateGuard.FreezeKey(routeStateKey);
        var id = OwnerExact(requestId, 16, "enrollment request ID");
        var request = OwnerExact(requestHash, 32, "enrollment request hash");
        var operation = OwnerExact(operationHash, 32, "enrollment operation hash");
        var intent = OwnerExact(intentHash, 32, "genesis intent hash");
        var source = OwnerExact(sourceArtifactClosureHash, 32,
            "source artifact closure hash");
        var keyToken = OwnerExact(ownerControlKeyToken, 32, "OCR key token");
        if (nowUnixSeconds is 0 or ulong.MaxValue)
            throw new InvalidDataException("Enrollment time is invalid.");
        await using var connection = await OpenAsync(cancellationToken);
        await EnsureRouteContinuitySchemaAsync(connection, cancellationToken);
        await EnsureOwnerControlSchemaAsync(connection, cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(
            IsolationLevel.ReadCommitted, cancellationToken);
        await ConfigureOwnerControlTransactionAsync(connection, transaction, cancellationToken);
        await AdvisoryLockAsync(connection, transaction, route, cancellationToken);
        var dbNow = await OwnerDbNowAsync(connection, transaction, cancellationToken);
        var published = await EnsurePublishedArtifactClosureAsync(connection, transaction,
            source, cancellationToken);
        if (!OwnerFixed(published, source))
        {
            await transaction.CommitAsync(cancellationToken);
            return new(ProductionMailboxOwnerEnrollmentStatus.Conflict, dbNow, null);
        }
        var current = await ReadRouteContinuityAsync(connection, transaction, route, true,
            cancellationToken);
        if (current is not null && current.OwnerRevocationGeneration != 0)
        {
            await transaction.CommitAsync(cancellationToken);
            return new(ProductionMailboxOwnerEnrollmentStatus.Revoked, dbNow, null);
        }
        var alias = await ReadOwnerEnrollmentAliasAsync(connection, transaction, route, id,
            cancellationToken);
        if (alias is not null && (!OwnerFixed(alias.OperationHash, operation)
            || !OwnerFixed(alias.RequestHash, request)))
        {
            await transaction.CommitAsync(cancellationToken);
            return new(ProductionMailboxOwnerEnrollmentStatus.Conflict, dbNow, null);
        }
        var existing = await ReadOwnerEnrollmentAsync(connection, transaction, route,
            operation, cancellationToken);
        if (existing is not null)
        {
            VerifyOwnerEnrollment(existing);
            if (!OwnerFixed(existing.IntentHash, intent)
                || !OwnerFixed(existing.SourceArtifactClosureHash, source)
                || !OwnerFixed(existing.KeyToken, keyToken))
            {
                await transaction.CommitAsync(cancellationToken);
                return new(ProductionMailboxOwnerEnrollmentStatus.Conflict,
                    existing.AcceptedAt, null);
            }
            if (existing.Response is not null)
            {
                var catalog = await ReadGenesisCatalogAsync(connection, transaction, route,
                    v2PreparedIntegrityKey, cancellationToken)
                    ?? throw new InvalidDataException(
                        "Completed owner enrollment is missing its protected catalog.");
                if (current is null || existing.PlanHash is null || existing.PublicKey is null)
                    throw new InvalidDataException(
                        "Completed owner enrollment durable closure is split.");
                InMemoryProductionMailboxStateStore.ValidateEnrollmentReplay(current,
                    existing.PlanHash, existing.PublicKey, existing.Response, catalog, dbNow);
            }
            if (alias is null)
            {
                if (!await OwnerControlCapacityAvailableAsync(connection, transaction, route,
                        dbNow, 1, ProductionMailboxOwnerControlAccounting.EnrollmentAliasBytes,
                        cancellationToken))
                {
                    await transaction.CommitAsync(cancellationToken);
                    return new(ProductionMailboxOwnerEnrollmentStatus.CapacityExceeded,
                        existing.AcceptedAt, null);
                }
                await InsertOwnerEnrollmentAliasAsync(connection, transaction, route, id,
                    operation, request, checked(existing.AcceptedAt +
                        ProductionMailboxOwnerControlConstants
                            .MaximumResponderCertificateLifetimeSeconds), cancellationToken);
            }
            await transaction.CommitAsync(cancellationToken);
            return existing.Response is null
                ? new(ProductionMailboxOwnerEnrollmentStatus.Prepared,
                    existing.AcceptedAt, null)
                : new(ProductionMailboxOwnerEnrollmentStatus.ExactReplay,
                    existing.AcceptedAt, existing.Response.ToArray());
        }
        if (alias is not null)
            throw new InvalidDataException("Stored enrollment alias has no operation row.");
        if (!await OwnerControlCapacityAvailableAsync(connection, transaction, route, dbNow,
                3, ProductionMailboxOwnerControlAccounting.PreparedEnrollmentBytes,
                cancellationToken))
        {
            await transaction.CommitAsync(cancellationToken);
            return new(ProductionMailboxOwnerEnrollmentStatus.CapacityExceeded, dbNow, null);
        }
        var created = new PgOwnerEnrollment(route, id, request, operation, intent, source,
            keyToken, dbNow, checked(dbNow + ProductionMailboxOwnerControlConstants
                .MaximumResponderCertificateLifetimeSeconds), false, 0,
            null, null, null, null, []);
        created = created with { Tag = ComputeOwnerEnrollmentTag(created) };
        await InsertOwnerEnrollmentAsync(connection, transaction, created, cancellationToken);
        await InsertOwnerEnrollmentAliasAsync(connection, transaction, route, id, operation,
            request, checked(dbNow + ProductionMailboxOwnerControlConstants
                .MaximumResponderCertificateLifetimeSeconds), cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return new(ProductionMailboxOwnerEnrollmentStatus.Prepared, dbNow, null);
    }

    async ValueTask<ProductionMailboxOwnerEnrollmentStatus>
        IProductionMailboxOwnerControlStateStore.CommitOwnerEnrollmentAsync(
        ReadOnlyMemory<byte> routeStateKey, ReadOnlyMemory<byte> requestId,
        ReadOnlyMemory<byte> requestHash, ReadOnlyMemory<byte> operationHash,
        ReadOnlyMemory<byte> sourceArtifactClosureHash,
        ProductionMailboxRouteContinuityGenesisCommitPlan plan,
        ProductionMailboxOwnerControlKeyHandle key,
        ReadOnlyMemory<byte> canonicalResponse, ulong nowUnixSeconds,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan); ArgumentNullException.ThrowIfNull(key);
        var route = ProductionMailboxRouteContinuityStateGuard.FreezeKey(routeStateKey);
        var id = OwnerExact(requestId, 16, "enrollment request ID");
        var request = OwnerExact(requestHash, 32, "enrollment request hash");
        var operation = OwnerExact(operationHash, 32, "enrollment operation hash");
        var source = OwnerExact(sourceArtifactClosureHash, 32,
            "source artifact closure hash");
        var response = OwnerExact(canonicalResponse,
            ProductionMailboxOwnerControlHostCodec.EnrollmentResponseLength,
            "enrollment response");
        var keyId = OwnerExact(key.KeyId, 32, "OCR key ID");
        var publicKey = OwnerExact(key.PublicKey, 32, "OCR public key");
        if (!OwnerFixed(operation, plan.CanonicalDelegationHash.Span))
            throw new InvalidDataException("Enrollment operation differs from genesis RCD1.");
        var frozen = ProductionMailboxFrozenEnrollment.Freeze(plan);
        var catalog = ProductionMailboxProtectedGenesisCatalog.Freeze(plan,
            V2PreparedIntegrityKey);
        await using var connection = await OpenAsync(cancellationToken);
        await EnsureRouteContinuitySchemaAsync(connection, cancellationToken);
        await EnsureOwnerControlSchemaAsync(connection, cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(
            IsolationLevel.ReadCommitted, cancellationToken);
        await ConfigureOwnerControlTransactionAsync(connection, transaction, cancellationToken);
        await AdvisoryLockAsync(connection, transaction, route, cancellationToken);
        var dbNow = await OwnerDbNowAsync(connection, transaction, cancellationToken);
        var record = await ReadOwnerEnrollmentAsync(connection, transaction, route, operation,
            cancellationToken) ?? throw new InvalidDataException(
                "Prepared enrollment operation is missing.");
        VerifyOwnerEnrollment(record);
        if (record.CleanupStarted
            || !OwnerFixed(record.RequestId, id) || !OwnerFixed(record.RequestHash, request)
            || !OwnerFixed(record.IntentHash, plan.GenesisIntentHash.Span)
            || !OwnerFixed(record.SourceArtifactClosureHash, source)
            || record.AcceptedAt != plan.AcceptedAtUnixSeconds || dbNow < record.AcceptedAt)
        {
            await transaction.CommitAsync(cancellationToken);
            return ProductionMailboxOwnerEnrollmentStatus.Conflict;
        }
        if (record.Response is not null)
        {
            await transaction.CommitAsync(cancellationToken);
            return OwnerFixed(record.Response, response) && OwnerFixed(record.PlanHash!,
                plan.PlanHash.Span)
                ? ProductionMailboxOwnerEnrollmentStatus.ExactReplay
                : ProductionMailboxOwnerEnrollmentStatus.Conflict;
        }
        var delegation = ProductionMailboxRouteContinuityCodec.DecodeDelegation(
            plan.CanonicalDelegation.Span);
        var ocr = ProductionMailboxOwnerControlTransportCodec.DecodeResponderCertificate(
            plan.CanonicalOwnerControlResponderCertificate.Span);
        if (dbNow >= delegation.ExpiresAtUnixSeconds || dbNow >= ocr.ExpiresAtUnixSeconds
            || !OwnerFixed(ocr.ResponderEd25519PublicKey.Span, publicKey))
        {
            await transaction.CommitAsync(cancellationToken);
            return ProductionMailboxOwnerEnrollmentStatus.Conflict;
        }
        var published = await EnsurePublishedArtifactClosureAsync(connection, transaction,
            source, cancellationToken);
        if (!OwnerFixed(published, source))
        {
            await transaction.CommitAsync(cancellationToken);
            return ProductionMailboxOwnerEnrollmentStatus.Conflict;
        }
        var current = await ReadRouteContinuityAsync(connection, transaction, route, true,
            cancellationToken);
        if (ValidateEnrollmentPredecessor(current, frozen) !=
            ProductionMailboxRouteContinuityCommitStatus.Accepted)
        {
            await transaction.CommitAsync(cancellationToken);
            return ProductionMailboxOwnerEnrollmentStatus.Conflict;
        }
        if (await ReadGenesisCatalogAsync(connection, transaction, route,
                v2PreparedIntegrityKey, cancellationToken) is not null)
            throw new InvalidDataException("Genesis catalog exists before enrollment commit.");
        await UpsertRouteContinuityAsync(connection, transaction,
            FromEnrollment(route, current, frozen), cancellationToken);
        await InsertGenesisCatalogAsync(connection, transaction, route, catalog,
            cancellationToken);
        var completed = record with
        {
            Response = response,
            PlanHash = plan.PlanHash.ToArray(),
            KeyId = keyId,
            PublicKey = publicKey
        };
        completed = completed with { Tag = ComputeOwnerEnrollmentTag(completed) };
        await UpdateOwnerEnrollmentAsync(connection, transaction, completed, cancellationToken);
        var requestAlias = await ReadOwnerEnrollmentAliasAsync(connection, transaction, route, id,
            cancellationToken) ?? throw new InvalidDataException(
                "Enrollment request alias disappeared before commit.");
        requestAlias = requestAlias with
        {
            RetainUntil = Math.Min(
                ProductionMailboxRouteContinuityCodec.DecodeDelegation(
                    plan.CanonicalDelegation.Span).ExpiresAtUnixSeconds,
                ocr.ExpiresAtUnixSeconds)
        };
        requestAlias = requestAlias with { Tag = ComputeOwnerEnrollmentAliasTag(requestAlias) };
        await UpdateOwnerEnrollmentAliasAsync(connection, transaction, requestAlias,
            cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return ProductionMailboxOwnerEnrollmentStatus.Prepared;
    }

    async ValueTask<ProductionMailboxOwnerRequestPrepareResult>
        IProductionMailboxOwnerControlStateStore.PrepareNoChangeAsync(
        ReadOnlyMemory<byte> routeStateKey, ReadOnlyMemory<byte> activeScope,
        VerifiedProductionMailboxOwnerControlRequest request,
        ulong nowUnixSeconds, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var route = ProductionMailboxRouteContinuityStateGuard.FreezeKey(routeStateKey);
        var scope = OwnerExact(activeScope, 32, "active request scope");
        var canonical = request.CanonicalBytes.ToArray(); var hash = request.CanonicalHash.ToArray();
        var decoded = ProductionMailboxOwnerControlTransportCodec.DecodeRequest(canonical);
        var requestId = OwnerExact(decoded.RequestId, 32, "owner request ID");
        await using var connection = await OpenAsync(cancellationToken);
        await EnsureRouteContinuitySchemaAsync(connection, cancellationToken);
        await EnsureOwnerControlSchemaAsync(connection, cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(
            IsolationLevel.ReadCommitted, cancellationToken);
        await ConfigureOwnerControlTransactionAsync(connection, transaction, cancellationToken);
        await AdvisoryLockAsync(connection, transaction, route, cancellationToken);
        var dbNow = await OwnerDbNowAsync(connection, transaction, cancellationToken);
        var current = await ReadRouteContinuityAsync(connection, transaction, route, true,
            cancellationToken);
        if (current is null)
        {
            await transaction.CommitAsync(cancellationToken);
            return new(ProductionMailboxOwnerRequestStatus.MissingState, null, null);
        }
        if (current.OwnerRevocationGeneration != 0)
        {
            await transaction.CommitAsync(cancellationToken);
            return new(ProductionMailboxOwnerRequestStatus.Revoked, null, null);
        }
        var enrollment = await ReadCompletedOwnerEnrollmentAsync(connection, transaction, route,
            cancellationToken);
        if (enrollment is null)
            throw new InvalidDataException("Owner request enrollment source is missing.");
        var sourceFingerprint = InMemoryProductionMailboxStateStore
            .ComputeOwnerRequestSourceFingerprint(current,
                enrollment.SourceArtifactClosureHash, canonical);
        if (sourceFingerprint is null)
        {
            await transaction.CommitAsync(cancellationToken);
            return new(ProductionMailboxOwnerRequestStatus.Conflict, null, null);
        }
        var alias = await ReadOwnerRequestAliasAsync(connection, transaction, route, requestId,
            cancellationToken);
        var hadAlias = alias is not null;
        if (alias is not null)
        {
            VerifyOwnerRequestAlias(alias);
            if (!OwnerFixed(alias.RequestHash, hash))
            {
                await transaction.CommitAsync(cancellationToken);
                return new(ProductionMailboxOwnerRequestStatus.Conflict, null, null);
            }
            if (dbNow >= alias.ExpiresAt)
            {
                await transaction.CommitAsync(cancellationToken);
                return new(ProductionMailboxOwnerRequestStatus.Stale, null, null);
            }
        }
        else
        {
            if (!await OwnerControlCapacityAvailableAsync(connection, transaction, route, dbNow,
                    2, ProductionMailboxOwnerControlAccounting.NewOwnerRequestBytes,
                    cancellationToken))
            {
                await transaction.CommitAsync(cancellationToken);
                return new(ProductionMailboxOwnerRequestStatus.Conflict, null, null);
            }
            var catalog = await ReadGenesisCatalogAsync(connection, transaction, route,
                v2PreparedIntegrityKey, cancellationToken)
                ?? throw new InvalidDataException("Owner request genesis catalog is missing.");
            var restored = catalog.RestoreProtocol();
            var delegationExpiry = restored.Enrollment.Delegation.ExpiresAtUnixSeconds;
            var ocrExpiry = ProductionMailboxOwnerControlTransportCodec
                .DecodeResponderCertificate(restored.EnrollmentContext
                    .CanonicalOwnerControlResponderCertificate.Span).ExpiresAtUnixSeconds;
            alias = new(route, requestId, hash, request.ExpiresAtUnixSeconds,
                Math.Min(delegationExpiry, ocrExpiry), []);
            alias = alias with { Tag = ComputeOwnerRequestAliasTag(alias) };
            await InsertOwnerRequestAliasAsync(connection, transaction, alias,
                cancellationToken);
        }
        var existing = await ReadOwnerRequestAsync(connection, transaction, scope,
            cancellationToken);
        if (existing is not null)
        {
            VerifyOwnerRequest(existing);
            if (dbNow >= existing.ExpiresAt)
            {
                await DeleteOwnerRequestAsync(connection, transaction, scope, cancellationToken);
            }
            else
            {
                await transaction.CommitAsync(cancellationToken);
                if (!OwnerFixed(existing.RequestHash, hash))
                    return new(ProductionMailboxOwnerRequestStatus.Conflict, null, null);
                if (!OwnerFixed(existing.SourceFingerprint, sourceFingerprint))
                    return new(ProductionMailboxOwnerRequestStatus.Conflict, null, null);
                return existing.DeliveryAuthorized
                    ? new(ProductionMailboxOwnerRequestStatus.ExactReplay,
                        existing.Header?.ToArray(), existing.Payload?.ToArray())
                    : new(ProductionMailboxOwnerRequestStatus.Prepared, null, null);
            }
        }
        if (dbNow >= request.ExpiresAtUnixSeconds)
        {
            await transaction.CommitAsync(cancellationToken);
            return new(ProductionMailboxOwnerRequestStatus.Stale, null, null);
        }
        if (hadAlias && !await OwnerControlCapacityAvailableAsync(connection, transaction, route,
                dbNow, 1, ProductionMailboxOwnerControlAccounting.OwnerRequestMaximumBytes,
                cancellationToken))
        {
            await transaction.CommitAsync(cancellationToken);
            return new(ProductionMailboxOwnerRequestStatus.Conflict, null, null);
        }
        var created = new PgOwnerRequest(scope, route, canonical, hash, sourceFingerprint,
            request.ExpiresAtUnixSeconds, null, null, null, null, false, false, []);
        created = created with { Tag = ComputeOwnerRequestTag(created) };
        await InsertOwnerRequestAsync(connection, transaction, created, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return new(ProductionMailboxOwnerRequestStatus.Prepared, null, null);
    }

    async ValueTask<ProductionMailboxOwnerNoChangePlanResult>
        IProductionMailboxOwnerControlStateStore.PlanNoChangeAsync(
        ReadOnlyMemory<byte> routeStateKey, ReadOnlyMemory<byte> activeScope,
        VerifiedProductionMailboxOwnerControlRequest request,
        ulong nowUnixSeconds, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var route = ProductionMailboxRouteContinuityStateGuard.FreezeKey(routeStateKey);
        var scope = OwnerExact(activeScope, 32, "active request scope");
        await using var connection = await OpenAsync(cancellationToken);
        await EnsureRouteContinuitySchemaAsync(connection, cancellationToken);
        await EnsureOwnerControlSchemaAsync(connection, cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(
            IsolationLevel.ReadCommitted, cancellationToken);
        await ConfigureOwnerControlTransactionAsync(connection, transaction, cancellationToken);
        await AdvisoryLockAsync(connection, transaction, route, cancellationToken);
        var dbNow = await OwnerDbNowAsync(connection, transaction, cancellationToken);
        var current = await ReadRouteContinuityAsync(connection, transaction, route, true,
            cancellationToken);
        if (current is null)
        {
            await transaction.CommitAsync(cancellationToken);
            return new(ProductionMailboxOwnerRequestStatus.MissingState, 0, 0);
        }
        if (current.OwnerRevocationGeneration != 0)
        {
            await transaction.CommitAsync(cancellationToken);
            return new(ProductionMailboxOwnerRequestStatus.Revoked, 0, 0);
        }
        var record = await ReadOwnerRequestAsync(connection, transaction, scope,
            cancellationToken);
        if (record is null)
        {
            await transaction.CommitAsync(cancellationToken);
            return new(ProductionMailboxOwnerRequestStatus.MissingState, 0, 0);
        }
        VerifyOwnerRequest(record);
        if (!await OwnerRequestSourceIsCurrentAsync(connection, transaction, current, record,
                cancellationToken))
        {
            await transaction.CommitAsync(cancellationToken);
            return new(ProductionMailboxOwnerRequestStatus.Conflict, 0, 0);
        }
        if (!OwnerFixed(record.RequestHash, request.CanonicalHash.Span)
            || dbNow >= record.ExpiresAt)
        {
            await transaction.CommitAsync(cancellationToken);
            return new(ProductionMailboxOwnerRequestStatus.Stale, 0, 0);
        }
        if (record.PlannedIssuedAt is not null)
        {
            await transaction.CommitAsync(cancellationToken);
            return new(ProductionMailboxOwnerRequestStatus.Prepared,
                record.PlannedIssuedAt.Value, record.PlannedExpiresAt!.Value);
        }
        var expires = Math.Min(record.ExpiresAt, checked(dbNow + 60));
        if (dbNow == 0 || dbNow >= expires)
        {
            await transaction.CommitAsync(cancellationToken);
            return new(ProductionMailboxOwnerRequestStatus.Stale, 0, 0);
        }
        var planned = record with { PlannedIssuedAt = dbNow, PlannedExpiresAt = expires };
        planned = planned with { Tag = ComputeOwnerRequestTag(planned) };
        await UpdateOwnerRequestAsync(connection, transaction, planned, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return new(ProductionMailboxOwnerRequestStatus.Prepared, dbNow, expires);
    }

    async ValueTask<ProductionMailboxOwnerRequestStatus>
        IProductionMailboxOwnerControlStateStore.RecordNoChangeAsync(
        ReadOnlyMemory<byte> routeStateKey, ReadOnlyMemory<byte> activeScope,
        VerifiedProductionMailboxOwnerControlRequest request,
        VerifiedProductionMailboxOwnerControlResponse response,
        ulong nowUnixSeconds, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request); ArgumentNullException.ThrowIfNull(response);
        if (response.Kind != ProductionMailboxOwnerControlResponseKind.NoChange)
            throw new InvalidDataException("Only NoChange is allowed in owner-control Slice 4A.");
        var route = ProductionMailboxRouteContinuityStateGuard.FreezeKey(routeStateKey);
        var scope = OwnerExact(activeScope, 32, "active request scope");
        await using var connection = await OpenAsync(cancellationToken);
        await EnsureRouteContinuitySchemaAsync(connection, cancellationToken);
        await EnsureOwnerControlSchemaAsync(connection, cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(
            IsolationLevel.ReadCommitted, cancellationToken);
        await ConfigureOwnerControlTransactionAsync(connection, transaction, cancellationToken);
        await AdvisoryLockAsync(connection, transaction, route, cancellationToken);
        var dbNow = await OwnerDbNowAsync(connection, transaction, cancellationToken);
        var current = await ReadRouteContinuityAsync(connection, transaction, route, true,
            cancellationToken);
        if (current is null)
        {
            await transaction.CommitAsync(cancellationToken);
            return ProductionMailboxOwnerRequestStatus.MissingState;
        }
        if (current.OwnerRevocationGeneration != 0)
        {
            await transaction.CommitAsync(cancellationToken);
            return ProductionMailboxOwnerRequestStatus.Revoked;
        }
        var record = await ReadOwnerRequestAsync(connection, transaction, scope,
            cancellationToken);
        if (record is null) return ProductionMailboxOwnerRequestStatus.MissingState;
        VerifyOwnerRequest(record);
        if (!await OwnerRequestSourceIsCurrentAsync(connection, transaction, current, record,
                cancellationToken))
        {
            await transaction.CommitAsync(cancellationToken);
            return ProductionMailboxOwnerRequestStatus.Conflict;
        }
        if (!OwnerFixed(record.RequestHash, request.CanonicalHash.Span)
            || dbNow >= record.ExpiresAt)
        {
            await transaction.CommitAsync(cancellationToken);
            return ProductionMailboxOwnerRequestStatus.Stale;
        }
        var header = response.CanonicalHeader.ToArray(); var payload = response.CanonicalPayload.ToArray();
        if (record.PlannedIssuedAt is null)
        {
            await transaction.CommitAsync(cancellationToken);
            return ProductionMailboxOwnerRequestStatus.Stale;
        }
        var decoded = ProductionMailboxOwnerControlTransportCodec.DecodeResponseHeader(header);
        if (decoded.IssuedAtUnixSeconds != record.PlannedIssuedAt
            || decoded.ExpiresAtUnixSeconds != record.PlannedExpiresAt)
        {
            await transaction.CommitAsync(cancellationToken);
            return ProductionMailboxOwnerRequestStatus.Conflict;
        }
        if (record.Header is not null)
        {
            await transaction.CommitAsync(cancellationToken);
            return OwnerFixed(record.Header, header) && OwnerFixed(record.Payload!, payload)
                ? ProductionMailboxOwnerRequestStatus.ExactReplay
                : ProductionMailboxOwnerRequestStatus.Conflict;
        }
        var changed = record with { Header = header, Payload = payload };
        changed = changed with { Tag = ComputeOwnerRequestTag(changed) };
        await UpdateOwnerRequestAsync(connection, transaction, changed, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return ProductionMailboxOwnerRequestStatus.Prepared;
    }

    async ValueTask<ProductionMailboxOwnerRequestPrepareResult>
        IProductionMailboxOwnerControlStateStore.AuthorizeDeliveryAsync(
        ReadOnlyMemory<byte> routeStateKey, ReadOnlyMemory<byte> activeScope,
        ReadOnlyMemory<byte> requestHash, ulong nowUnixSeconds,
        CancellationToken cancellationToken)
    {
        var route = ProductionMailboxRouteContinuityStateGuard.FreezeKey(routeStateKey);
        var scope = OwnerExact(activeScope, 32, "active request scope");
        var hash = OwnerExact(requestHash, 32, "request hash");
        await using var connection = await OpenAsync(cancellationToken);
        await EnsureRouteContinuitySchemaAsync(connection, cancellationToken);
        await EnsureOwnerControlSchemaAsync(connection, cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(
            IsolationLevel.ReadCommitted, cancellationToken);
        await ConfigureOwnerControlTransactionAsync(connection, transaction, cancellationToken);
        await AdvisoryLockAsync(connection, transaction, route, cancellationToken);
        var dbNow = await OwnerDbNowAsync(connection, transaction, cancellationToken);
        var current = await ReadRouteContinuityAsync(connection, transaction, route, true,
            cancellationToken);
        var record = await ReadOwnerRequestAsync(connection, transaction, scope,
            cancellationToken);
        if ((current is not null && current.OwnerRevocationGeneration != 0)
            || record?.Revoked == true)
        {
            await transaction.CommitAsync(cancellationToken);
            return new(ProductionMailboxOwnerRequestStatus.Revoked, null, null);
        }
        if (record is null)
        {
            await transaction.CommitAsync(cancellationToken);
            return new(ProductionMailboxOwnerRequestStatus.MissingState, null, null);
        }
        if (current is null)
        {
            await transaction.CommitAsync(cancellationToken);
            return new(ProductionMailboxOwnerRequestStatus.MissingState, null, null);
        }
        VerifyOwnerRequest(record);
        if (!await OwnerRequestSourceIsCurrentAsync(connection, transaction, current, record,
                cancellationToken))
        {
            await transaction.CommitAsync(cancellationToken);
            return new(ProductionMailboxOwnerRequestStatus.Conflict, null, null);
        }
        if (!OwnerFixed(record.RequestHash, hash) || dbNow >= record.ExpiresAt
            || record.Header is null || record.Payload is null)
        {
            await transaction.CommitAsync(cancellationToken);
            return new(ProductionMailboxOwnerRequestStatus.Stale, null, null);
        }
        if (!record.DeliveryAuthorized)
        {
            record = record with { DeliveryAuthorized = true };
            record = record with { Tag = ComputeOwnerRequestTag(record) };
            await UpdateOwnerRequestAsync(connection, transaction, record, cancellationToken);
        }
        await transaction.CommitAsync(cancellationToken);
        return new(ProductionMailboxOwnerRequestStatus.ExactReplay,
            record.Header.ToArray(), record.Payload.ToArray());
    }

    async ValueTask<ProductionMailboxRouteContinuityCommitResult>
        IProductionMailboxOwnerControlStateStore.CommitOwnerRevocationAndFenceAsync(
        ReadOnlyMemory<byte> routeStateKey, ReadOnlyMemory<byte> requestId,
        VerifiedProductionMailboxRouteContinuityRevocation revocation,
        CancellationToken cancellationToken)
    {
        var id = OwnerExact(requestId, 16, "revocation request ID");
        var route = ProductionMailboxRouteContinuityStateGuard.FreezeKey(routeStateKey);
        var frozen = ProductionMailboxFrozenOwnerRevocation.Freeze(revocation);
        await using var connection = await OpenAsync(cancellationToken);
        await EnsureRouteContinuitySchemaAsync(connection, cancellationToken);
        await EnsureOwnerControlSchemaAsync(connection, cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(
            IsolationLevel.ReadCommitted, cancellationToken);
        await ConfigureOwnerControlTransactionAsync(connection, transaction, cancellationToken);
        await AdvisoryLockAsync(connection, transaction, route, cancellationToken);
        var current = await ReadRouteContinuityAsync(connection, transaction, route, true,
            cancellationToken);
        var alias = await ReadOwnerRevocationAliasAsync(connection, transaction, route, id,
            cancellationToken);
        if (alias is not null)
        {
            VerifyOwnerRevocationAlias(alias);
            if (!OwnerFixed(alias.OperationHash, frozen.CanonicalHash))
            {
                var conflictState = await ReadRouteContinuityAsync(connection, transaction,
                    route, true, cancellationToken);
                await transaction.CommitAsync(cancellationToken);
                return new(ProductionMailboxRouteContinuityCommitStatus.Conflict, conflictState);
            }
        }
        else
        {
            var dbNow = await OwnerDbNowAsync(connection, transaction, cancellationToken);
            if (!await OwnerControlCapacityAvailableAsync(connection, transaction, route, dbNow,
                    1, ProductionMailboxOwnerControlAccounting.OwnerRevocationAliasBytes,
                    cancellationToken, terminal: true))
            {
                await transaction.CommitAsync(cancellationToken);
                return new(ProductionMailboxRouteContinuityCommitStatus.Conflict, current);
            }
            var catalog = await ReadGenesisCatalogAsync(connection, transaction, route,
                v2PreparedIntegrityKey, cancellationToken)
                ?? throw new InvalidDataException("Owner revocation genesis catalog is missing.");
            var restored = catalog.RestoreProtocol();
            var ocr = ProductionMailboxOwnerControlTransportCodec.DecodeResponderCertificate(
                restored.EnrollmentContext.CanonicalOwnerControlResponderCertificate.Span);
            alias = new(route, id, frozen.CanonicalHash,
                Math.Min(restored.Enrollment.Delegation.ExpiresAtUnixSeconds,
                    ocr.ExpiresAtUnixSeconds), []);
            alias = alias with { Tag = ComputeOwnerRevocationAliasTag(alias) };
            await InsertOwnerRevocationAliasAsync(connection, transaction, alias,
                cancellationToken);
        }
        var status = InMemoryProductionMailboxStateStore.ValidateOwnerRevocationPredecessor(
            current, frozen);
        if (status == ProductionMailboxRouteContinuityCommitStatus.Accepted)
        {
            var next = InMemoryProductionMailboxStateStore.FromOwnerRevocation(current!, frozen);
            await UpsertRouteContinuityAsync(connection, transaction, next, cancellationToken);
            const string selectSql = """
                SELECT active_scope FROM production_mailbox_owner_requests_v1
                WHERE route_state_key=@route FOR UPDATE
                """;
            var scopes = new List<byte[]>();
            await using (var select = new NpgsqlCommand(selectSql, connection, transaction))
            {
                select.Parameters.AddWithValue("route", route);
                await using var reader = await select.ExecuteReaderAsync(cancellationToken);
                while (await reader.ReadAsync(cancellationToken))
                {
                    if (scopes.Count == 1024)
                        throw new InvalidDataException("Owner request fence exceeds its bound.");
                    scopes.Add(reader.GetFieldValue<byte[]>(0));
                }
            }
            foreach (var scope in scopes)
            {
                var request = await ReadOwnerRequestAsync(connection, transaction, scope,
                    cancellationToken) ?? throw new InvalidDataException(
                        "Owner request disappeared under route lock.");
                VerifyOwnerRequest(request);
                request = request with { Revoked = true };
                request = request with { Tag = ComputeOwnerRequestTag(request) };
                await UpdateOwnerRequestAsync(connection, transaction, request, cancellationToken);
            }
            await transaction.CommitAsync(cancellationToken);
            return new(status, next);
        }
        await transaction.CommitAsync(cancellationToken);
        return new(status, current);
    }

    async ValueTask<ProductionMailboxOwnerControlKeyHandle?>
        IProductionMailboxOwnerControlStateStore.GetOwnerControlKeyAsync(
        ReadOnlyMemory<byte> routeStateKey, CancellationToken cancellationToken)
    {
        var route = ProductionMailboxRouteContinuityStateGuard.FreezeKey(routeStateKey);
        await using var connection = await OpenAsync(cancellationToken);
        await EnsureOwnerControlSchemaAsync(connection, cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(
            IsolationLevel.ReadCommitted, cancellationToken);
        await ConfigureOwnerControlTransactionAsync(connection, transaction, cancellationToken);
        await AdvisoryLockAsync(connection, transaction, route, cancellationToken);
        var value = await ReadCompletedOwnerEnrollmentAsync(connection, transaction, route,
            cancellationToken);
        if (value is null) { await transaction.CommitAsync(cancellationToken); return null; }
        await transaction.CommitAsync(cancellationToken);
        return new(value.KeyId!.ToArray(), value.PublicKey!.ToArray());
    }

    async ValueTask<ProductionMailboxAbandonedOwnerKeyClaim?>
        IProductionMailboxOwnerControlStateStore.ClaimAbandonedOwnerKeyAsync(
        ulong nowUnixSeconds, ulong leaseUntilUnixSeconds,
        CancellationToken cancellationToken)
    {
        if (nowUnixSeconds == 0 || leaseUntilUnixSeconds <= nowUnixSeconds)
            throw new InvalidDataException("Owner-key cleanup lease is invalid.");
        await using var connection = await OpenAsync(cancellationToken);
        await EnsureOwnerControlSchemaAsync(connection, cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(
            IsolationLevel.ReadCommitted, cancellationToken);
        await ConfigureOwnerControlTransactionAsync(connection, transaction, cancellationToken);
        await AdvisoryLockAsync(connection, transaction,
            SHA256.HashData("Deep/registry/production-mailbox/owner-key-cleanup/v1"u8),
            cancellationToken);
        const string selectSql = """
            SELECT route_state_key,operation_hash
            FROM production_mailbox_owner_enrollment_ops_v1
            WHERE canonical_response IS NULL AND retain_until IS NOT NULL
                AND retain_until <= @now
                AND (cleanup_started=false OR cleanup_lease_until IS NULL
                    OR cleanup_lease_until <= @now)
            ORDER BY retain_until,route_state_key,operation_hash
            LIMIT 1 FOR UPDATE SKIP LOCKED
            """;
        byte[]? route = null; byte[]? operation = null;
        await using (var select = new NpgsqlCommand(selectSql, connection, transaction))
        {
            select.Parameters.AddWithValue("now", U64(nowUnixSeconds));
            await using var reader = await select.ExecuteReaderAsync(cancellationToken);
            if (await reader.ReadAsync(cancellationToken))
            {
                route = reader.GetFieldValue<byte[]>(0);
                operation = reader.GetFieldValue<byte[]>(1);
            }
        }
        if (route is null)
        {
            await transaction.CommitAsync(cancellationToken); return null;
        }
        var value = await ReadOwnerEnrollmentAsync(connection, transaction, route, operation!,
            cancellationToken) ?? throw new InvalidDataException("Cleanup row disappeared.");
        VerifyOwnerEnrollment(value);
        if (value.Response is not null)
            throw new InvalidDataException("Committed owner key entered cleanup.");
        value = value with { CleanupStarted = true, CleanupLeaseUntil = leaseUntilUnixSeconds };
        value = value with { Tag = ComputeOwnerEnrollmentTag(value) };
        const string updateSql = """
            UPDATE production_mailbox_owner_enrollment_ops_v1
            SET cleanup_started=true,cleanup_lease_until=@lease,integrity_tag=@tag
            WHERE route_state_key=@route AND operation_hash=@operation
                AND canonical_response IS NULL
            """;
        await using (var update = new NpgsqlCommand(updateSql, connection, transaction))
        {
            update.Parameters.AddWithValue("lease", U64(leaseUntilUnixSeconds));
            update.Parameters.AddWithValue("tag", value.Tag);
            update.Parameters.AddWithValue("route", route);
            update.Parameters.AddWithValue("operation", operation!);
            if (await update.ExecuteNonQueryAsync(cancellationToken) != 1)
                throw new InvalidDataException("Owner-key cleanup claim CAS failed.");
        }
        await transaction.CommitAsync(cancellationToken);
        return new(route, operation!, value.KeyToken.ToArray());
    }

    async ValueTask IProductionMailboxOwnerControlStateStore.CompleteAbandonedOwnerKeyAsync(
        ReadOnlyMemory<byte> routeStateKey, ReadOnlyMemory<byte> operationHash,
        ReadOnlyMemory<byte> keyToken, CancellationToken cancellationToken)
    {
        var route = OwnerExact(routeStateKey, 32, "cleanup route key");
        var operation = OwnerExact(operationHash, 32, "cleanup operation hash");
        var token = OwnerExact(keyToken, 32, "cleanup key token");
        await using var connection = await OpenAsync(cancellationToken);
        await EnsureOwnerControlSchemaAsync(connection, cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(
            IsolationLevel.ReadCommitted, cancellationToken);
        await ConfigureOwnerControlTransactionAsync(connection, transaction, cancellationToken);
        await AdvisoryLockAsync(connection, transaction, route, cancellationToken);
        var value = await ReadOwnerEnrollmentAsync(connection, transaction, route, operation,
            cancellationToken);
        if (value is null) { await transaction.CommitAsync(cancellationToken); return; }
        VerifyOwnerEnrollment(value);
        if (value.Response is not null || !value.CleanupStarted
            || !OwnerFixed(value.KeyToken, token))
            throw new InvalidDataException("Owner-key cleanup state is inconsistent.");
        await using (var deleteAlias = new NpgsqlCommand("""
            DELETE FROM production_mailbox_owner_enrollment_ids_v1
            WHERE route_state_key=@route AND operation_hash=@operation
            """, connection, transaction))
        {
            deleteAlias.Parameters.AddWithValue("route", route);
            deleteAlias.Parameters.AddWithValue("operation", operation);
            await deleteAlias.ExecuteNonQueryAsync(cancellationToken);
        }
        await using (var delete = new NpgsqlCommand("""
            DELETE FROM production_mailbox_owner_enrollment_ops_v1
            WHERE route_state_key=@route AND operation_hash=@operation
                AND canonical_response IS NULL AND cleanup_started=true
            """, connection, transaction))
        {
            delete.Parameters.AddWithValue("route", route);
            delete.Parameters.AddWithValue("operation", operation);
            if (await delete.ExecuteNonQueryAsync(cancellationToken) != 1)
                throw new InvalidDataException("Owner-key cleanup completion CAS failed.");
        }
        await transaction.CommitAsync(cancellationToken);
    }

    private async ValueTask<PgOwnerEnrollment?> ReadCompletedOwnerEnrollmentAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction, ReadOnlyMemory<byte> route,
        CancellationToken cancellationToken)
    {
        const string sql = """
            SELECT operation_hash FROM production_mailbox_owner_enrollment_ops_v1
            WHERE route_state_key=@route AND canonical_response IS NOT NULL
            LIMIT 2 FOR UPDATE
            """;
        var operations = new List<byte[]>();
        await using (var command = new NpgsqlCommand(sql, connection, transaction))
        {
            command.Parameters.AddWithValue("route", route.ToArray());
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
                operations.Add(reader.GetFieldValue<byte[]>(0));
        }
        if (operations.Count == 0) return null;
        if (operations.Count != 1)
            throw new InvalidDataException("Owner enrollment source is ambiguous.");
        var value = await ReadOwnerEnrollmentAsync(connection, transaction, route, operations[0],
            cancellationToken) ?? throw new InvalidDataException("Owner enrollment row disappeared.");
        VerifyOwnerEnrollment(value);
        return value;
    }

    private async ValueTask<bool> OwnerRequestSourceIsCurrentAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction,
        ProductionMailboxRouteContinuityStateSnapshot? current, PgOwnerRequest request,
        CancellationToken cancellationToken)
    {
        if (current is null) return false;
        var enrollment = await ReadCompletedOwnerEnrollmentAsync(connection, transaction,
            request.Route, cancellationToken);
        if (enrollment is null) return false;
        var fingerprint = InMemoryProductionMailboxStateStore
            .ComputeOwnerRequestSourceFingerprint(current,
                enrollment.SourceArtifactClosureHash, request.CanonicalRequest);
        return fingerprint is not null && OwnerFixed(fingerprint, request.SourceFingerprint);
    }

    private async ValueTask<PgOwnerEnrollment?> ReadOwnerEnrollmentAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction, ReadOnlyMemory<byte> route,
        ReadOnlyMemory<byte> operation, CancellationToken cancellationToken)
    {
        const string sql = """
            SELECT request_id,request_hash,operation_hash,intent_hash,
                source_artifact_closure_hash,ocr_key_token,accepted_at,retain_until,
                cleanup_started,cleanup_lease_until,
                canonical_response,plan_hash,ocr_key_id,ocr_public_key,integrity_tag
            FROM production_mailbox_owner_enrollment_ops_v1
            WHERE route_state_key=@route AND operation_hash=@operation FOR UPDATE
            """;
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue("route", route.ToArray());
        command.Parameters.AddWithValue("operation", operation.ToArray());
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken)) return null;
        return new(route.ToArray(), reader.GetFieldValue<byte[]>(0),
            reader.GetFieldValue<byte[]>(1), reader.GetFieldValue<byte[]>(2),
            reader.GetFieldValue<byte[]>(3), reader.GetFieldValue<byte[]>(4),
            reader.IsDBNull(5) ? [] : reader.GetFieldValue<byte[]>(5),
            ReadU64(reader.GetFieldValue<byte[]>(6)),
            reader.IsDBNull(7) ? 0 : ReadU64(reader.GetFieldValue<byte[]>(7)),
            reader.GetBoolean(8),
            reader.IsDBNull(9) ? 0 : ReadU64(reader.GetFieldValue<byte[]>(9)),
            reader.IsDBNull(10) ? null : reader.GetFieldValue<byte[]>(10),
            reader.IsDBNull(11) ? null : reader.GetFieldValue<byte[]>(11),
            reader.IsDBNull(12) ? null : reader.GetFieldValue<byte[]>(12),
            reader.IsDBNull(13) ? null : reader.GetFieldValue<byte[]>(13),
            reader.GetFieldValue<byte[]>(14));
    }

    private async ValueTask<PgOwnerEnrollmentAlias?> ReadOwnerEnrollmentAliasAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction, ReadOnlyMemory<byte> route,
        ReadOnlyMemory<byte> id, CancellationToken cancellationToken)
    {
        const string sql = """
            SELECT operation_hash,request_hash,retain_until,integrity_tag
            FROM production_mailbox_owner_enrollment_ids_v1
            WHERE route_state_key=@route AND request_id=@id FOR UPDATE
            """;
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue("route", route.ToArray()); command.Parameters.AddWithValue("id", id.ToArray());
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken)) return null;
        var result = new PgOwnerEnrollmentAlias(route.ToArray(), id.ToArray(),
            reader.GetFieldValue<byte[]>(0), reader.GetFieldValue<byte[]>(1),
            reader.IsDBNull(2) ? 0 : ReadU64(reader.GetFieldValue<byte[]>(2)),
            reader.GetFieldValue<byte[]>(3));
        if (!OwnerFixed(result.Tag, ComputeOwnerEnrollmentAliasTag(result)))
            throw new InvalidDataException("Stored enrollment request alias integrity is invalid.");
        return result;
    }

    private async ValueTask InsertOwnerEnrollmentAliasAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, ReadOnlyMemory<byte> route, ReadOnlyMemory<byte> id,
        ReadOnlyMemory<byte> operation, ReadOnlyMemory<byte> request,
        ulong retainUntil,
        CancellationToken cancellationToken)
    {
        var value = new PgOwnerEnrollmentAlias(route.ToArray(), id.ToArray(),
            operation.ToArray(), request.ToArray(), retainUntil, []);
        value = value with { Tag = ComputeOwnerEnrollmentAliasTag(value) };
        const string sql = """
            INSERT INTO production_mailbox_owner_enrollment_ids_v1(
                route_state_key,request_id,operation_hash,request_hash,retain_until,integrity_tag)
            VALUES(@route,@id,@operation,@request,@retain,@tag)
            """;
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue("route", value.Route);
        command.Parameters.AddWithValue("id", value.RequestId);
        command.Parameters.AddWithValue("operation", value.OperationHash);
        command.Parameters.AddWithValue("request", value.RequestHash);
        command.Parameters.AddWithValue("retain", U64(value.RetainUntil));
        command.Parameters.AddWithValue("tag", value.Tag);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async ValueTask UpdateOwnerEnrollmentAliasAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction,
        PgOwnerEnrollmentAlias value, CancellationToken cancellationToken)
    {
        const string sql = """
            UPDATE production_mailbox_owner_enrollment_ids_v1
            SET retain_until=@retain,integrity_tag=@tag
            WHERE route_state_key=@route AND request_id=@id
            """;
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue("route", value.Route);
        command.Parameters.AddWithValue("id", value.RequestId);
        command.Parameters.AddWithValue("retain", U64(value.RetainUntil));
        command.Parameters.AddWithValue("tag", value.Tag);
        if (await command.ExecuteNonQueryAsync(cancellationToken) != 1)
            throw new InvalidDataException("Enrollment request alias CAS row disappeared.");
    }

    private async ValueTask<PgOwnerRevocationAlias?> ReadOwnerRevocationAliasAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction, ReadOnlyMemory<byte> route,
        ReadOnlyMemory<byte> id, CancellationToken cancellationToken)
    {
        const string sql = """
            SELECT operation_hash,retain_until,integrity_tag
            FROM production_mailbox_owner_revocation_ids_v1
            WHERE route_state_key=@route AND request_id=@id FOR UPDATE
            """;
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue("route", route.ToArray());
        command.Parameters.AddWithValue("id", id.ToArray());
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken)) return null;
        return new(route.ToArray(), id.ToArray(), reader.GetFieldValue<byte[]>(0),
            reader.IsDBNull(1) ? 0 : ReadU64(reader.GetFieldValue<byte[]>(1)),
            reader.GetFieldValue<byte[]>(2));
    }

    private async ValueTask<PgOwnerRequestAlias?> ReadOwnerRequestAliasAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction, ReadOnlyMemory<byte> route,
        ReadOnlyMemory<byte> id, CancellationToken cancellationToken)
    {
        const string sql = """
            SELECT request_hash,expires_at,retain_until,integrity_tag
            FROM production_mailbox_owner_request_ids_v1
            WHERE route_state_key=@route AND request_id=@id FOR UPDATE
            """;
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue("route", route.ToArray());
        command.Parameters.AddWithValue("id", id.ToArray());
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken)) return null;
        return new(route.ToArray(), id.ToArray(), reader.GetFieldValue<byte[]>(0),
            ReadU64(reader.GetFieldValue<byte[]>(1)),
            ReadU64(reader.GetFieldValue<byte[]>(2)), reader.GetFieldValue<byte[]>(3));
    }

    private static async ValueTask InsertOwnerRequestAliasAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, PgOwnerRequestAlias value,
        CancellationToken cancellationToken)
    {
        const string sql = """
            INSERT INTO production_mailbox_owner_request_ids_v1(
                route_state_key,request_id,request_hash,expires_at,retain_until,integrity_tag)
            VALUES(@route,@id,@hash,@expires,@retain,@tag)
            """;
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue("route", value.Route);
        command.Parameters.AddWithValue("id", value.RequestId);
        command.Parameters.AddWithValue("hash", value.RequestHash);
        command.Parameters.AddWithValue("expires", U64(value.ExpiresAt));
        command.Parameters.AddWithValue("retain", U64(value.RetainUntil));
        command.Parameters.AddWithValue("tag", value.Tag);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async ValueTask InsertOwnerRevocationAliasAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, PgOwnerRevocationAlias value,
        CancellationToken cancellationToken)
    {
        const string sql = """
            INSERT INTO production_mailbox_owner_revocation_ids_v1(
                route_state_key,request_id,operation_hash,retain_until,integrity_tag)
            VALUES(@route,@id,@operation,@retain,@tag)
            """;
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue("route", value.Route);
        command.Parameters.AddWithValue("id", value.RequestId);
        command.Parameters.AddWithValue("operation", value.OperationHash);
        command.Parameters.AddWithValue("retain", U64(value.RetainUntil));
        command.Parameters.AddWithValue("tag", value.Tag);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async ValueTask InsertOwnerEnrollmentAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, PgOwnerEnrollment value,
        CancellationToken cancellationToken)
    {
        const string sql = """
            INSERT INTO production_mailbox_owner_enrollment_ops_v1(
                route_state_key,request_id,request_hash,operation_hash,intent_hash,
                source_artifact_closure_hash,ocr_key_token,accepted_at,
                retain_until,cleanup_started,cleanup_lease_until,
                canonical_response,plan_hash,ocr_key_id,ocr_public_key,integrity_tag)
            VALUES(@route,@id,@request,@operation,@intent,@source,@keyToken,@accepted,
                @retain,false,NULL,NULL,NULL,NULL,NULL,@tag)
            """;
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        AddOwnerEnrollmentParameters(command, value); await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async ValueTask UpdateOwnerEnrollmentAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, PgOwnerEnrollment value,
        CancellationToken cancellationToken)
    {
        const string sql = """
            UPDATE production_mailbox_owner_enrollment_ops_v1 SET
                canonical_response=@response,plan_hash=@plan,ocr_key_id=@keyId,
                ocr_public_key=@publicKey,integrity_tag=@tag
            WHERE route_state_key=@route AND operation_hash=@operation
            """;
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        AddOwnerEnrollmentParameters(command, value);
        command.Parameters.AddWithValue("response", value.Response!);
        command.Parameters.AddWithValue("plan", value.PlanHash!);
        command.Parameters.AddWithValue("keyId", value.KeyId!);
        command.Parameters.AddWithValue("publicKey", value.PublicKey!);
        if (await command.ExecuteNonQueryAsync(cancellationToken) != 1)
            throw new InvalidDataException("Owner enrollment CAS row disappeared.");
    }

    private static void AddOwnerEnrollmentParameters(NpgsqlCommand command, PgOwnerEnrollment value)
    {
        command.Parameters.AddWithValue("route", value.Route);
        command.Parameters.AddWithValue("id", value.RequestId);
        command.Parameters.AddWithValue("request", value.RequestHash);
        command.Parameters.AddWithValue("operation", value.OperationHash);
        command.Parameters.AddWithValue("intent", value.IntentHash);
        command.Parameters.AddWithValue("source", value.SourceArtifactClosureHash);
        command.Parameters.AddWithValue("keyToken", value.KeyToken);
        command.Parameters.AddWithValue("accepted", U64(value.AcceptedAt));
        command.Parameters.AddWithValue("retain", U64(value.RetainUntil));
        command.Parameters.AddWithValue("tag", value.Tag);
    }

    private async ValueTask<PgOwnerRequest?> ReadOwnerRequestAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, ReadOnlyMemory<byte> scope,
        CancellationToken cancellationToken)
    {
        const string sql = """
            SELECT route_state_key,canonical_request,request_hash,source_fingerprint,expires_at,
                planned_issued_at,planned_expires_at,response_header,response_payload,
                delivery_authorized,revoked,integrity_tag
            FROM production_mailbox_owner_requests_v1 WHERE active_scope=@scope FOR UPDATE
            """;
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue("scope", scope.ToArray());
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken)) return null;
        return new(scope.ToArray(), reader.GetFieldValue<byte[]>(0),
            reader.GetFieldValue<byte[]>(1), reader.GetFieldValue<byte[]>(2),
            reader.IsDBNull(3) ? [] : reader.GetFieldValue<byte[]>(3),
            ReadU64(reader.GetFieldValue<byte[]>(4)),
            reader.IsDBNull(5) ? null : ReadU64(reader.GetFieldValue<byte[]>(5)),
            reader.IsDBNull(6) ? null : ReadU64(reader.GetFieldValue<byte[]>(6)),
            reader.IsDBNull(7) ? null : reader.GetFieldValue<byte[]>(7),
            reader.IsDBNull(8) ? null : reader.GetFieldValue<byte[]>(8),
            reader.GetBoolean(9), reader.GetBoolean(10), reader.GetFieldValue<byte[]>(11));
    }

    private static async ValueTask InsertOwnerRequestAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, PgOwnerRequest value, CancellationToken cancellationToken)
    {
        const string sql = """
            INSERT INTO production_mailbox_owner_requests_v1(
                active_scope,route_state_key,canonical_request,request_hash,expires_at,
                source_fingerprint,
                planned_issued_at,planned_expires_at,response_header,response_payload,
                delivery_authorized,revoked,integrity_tag)
            VALUES(@scope,@route,@request,@hash,@expires,@source,NULL,NULL,NULL,NULL,false,false,@tag)
            """;
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        AddOwnerRequestParameters(command, value); await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async ValueTask UpdateOwnerRequestAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, PgOwnerRequest value, CancellationToken cancellationToken)
    {
        const string sql = """
            UPDATE production_mailbox_owner_requests_v1 SET planned_issued_at=@plannedIssued,
                planned_expires_at=@plannedExpires,response_header=@header,
                response_payload=@payload,delivery_authorized=@delivery,revoked=@revoked,
                integrity_tag=@tag WHERE active_scope=@scope
            """;
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        AddOwnerRequestParameters(command, value);
        var plannedIssued = command.Parameters.Add("plannedIssued", NpgsqlDbType.Bytea);
        plannedIssued.Value = value.PlannedIssuedAt is null
            ? DBNull.Value : U64(value.PlannedIssuedAt.Value);
        var plannedExpires = command.Parameters.Add("plannedExpires", NpgsqlDbType.Bytea);
        plannedExpires.Value = value.PlannedExpiresAt is null
            ? DBNull.Value : U64(value.PlannedExpiresAt.Value);
        var header = command.Parameters.Add("header", NpgsqlDbType.Bytea);
        header.Value = value.Header is null ? DBNull.Value : value.Header;
        var payload = command.Parameters.Add("payload", NpgsqlDbType.Bytea);
        payload.Value = value.Payload is null ? DBNull.Value : value.Payload;
        command.Parameters.AddWithValue("delivery", value.DeliveryAuthorized);
        command.Parameters.AddWithValue("revoked", value.Revoked);
        if (await command.ExecuteNonQueryAsync(cancellationToken) != 1)
            throw new InvalidDataException("Owner request CAS row disappeared.");
    }

    private static void AddOwnerRequestParameters(NpgsqlCommand command, PgOwnerRequest value)
    {
        command.Parameters.AddWithValue("scope", value.Scope);
        command.Parameters.AddWithValue("route", value.Route);
        command.Parameters.AddWithValue("request", value.CanonicalRequest);
        command.Parameters.AddWithValue("hash", value.RequestHash);
        command.Parameters.AddWithValue("source", value.SourceFingerprint);
        command.Parameters.AddWithValue("expires", U64(value.ExpiresAt));
        command.Parameters.AddWithValue("tag", value.Tag);
    }

    private static async ValueTask DeleteOwnerRequestAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, ReadOnlyMemory<byte> scope,
        CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand(
            "DELETE FROM production_mailbox_owner_requests_v1 WHERE active_scope=@scope",
            connection, transaction);
        command.Parameters.AddWithValue("scope", scope.ToArray());
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private async ValueTask<bool> OwnerControlCapacityAvailableAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction, ReadOnlyMemory<byte> route,
        ulong nowUnixSeconds, int additionalEntries, long additionalBytes,
        CancellationToken cancellationToken, bool terminal = false)
    {
        await AdvisoryLockAsync(connection, transaction,
            SHA256.HashData("Deep/registry/production-mailbox/owner-control-capacity/v1"u8),
            cancellationToken);
        await AuthenticatedOwnerControlGcAsync(connection, transaction, nowUnixSeconds,
            cancellationToken);
        var keys = await ReadOwnerCapacityKeysAsync(connection, transaction,
            checked(ownerControlLimits.MaximumEntriesGlobal + 1), cancellationToken);
        if (keys.Count > ownerControlLimits.MaximumEntriesGlobal)
            return false;
        long globalCount = keys.Count;
        long routeCount = keys.LongCount(value => OwnerFixed(value.Route, route.Span));
        long bytes = 0;
        foreach (var key in keys)
        {
            switch (key.Kind)
            {
                case 1:
                {
                    var value = await ReadOwnerEnrollmentAsync(connection, transaction,
                        key.Route, key.Key, cancellationToken)
                        ?? throw new InvalidDataException(
                            "Owner enrollment disappeared during capacity scan.");
                    VerifyOwnerEnrollment(value);
                    bytes = checked(bytes + OwnerEnrollmentAccountingBytes(value));
                    if (value.Response is null)
                    {
                        globalCount++;
                        if (OwnerFixed(value.Route, route.Span)) routeCount++;
                    }
                    break;
                }
                case 2:
                {
                    var value = await ReadOwnerRequestAsync(connection, transaction, key.Key,
                        cancellationToken) ?? throw new InvalidDataException(
                            "Owner request disappeared during capacity scan.");
                    VerifyOwnerRequest(value);
                    bytes = checked(bytes + OwnerRequestAccountingBytes(value));
                    break;
                }
                case 3:
                {
                    var value = await ReadOwnerRequestAliasAsync(connection, transaction,
                        key.Route, key.Key, cancellationToken) ?? throw new InvalidDataException(
                            "Owner request alias disappeared during capacity scan.");
                    VerifyOwnerRequestAlias(value);
                    bytes = checked(bytes + OwnerRequestAliasAccountingBytes(value));
                    break;
                }
                case 4:
                {
                    var value = await ReadOwnerRevocationAliasAsync(connection, transaction,
                        key.Route, key.Key, cancellationToken) ?? throw new InvalidDataException(
                            "Owner revocation alias disappeared during capacity scan.");
                    VerifyOwnerRevocationAlias(value);
                    bytes = checked(bytes + OwnerRevocationAliasAccountingBytes(value));
                    break;
                }
                case 5:
                {
                    var value = await ReadOwnerEnrollmentAliasAsync(connection, transaction,
                        key.Route, key.Key, cancellationToken) ?? throw new InvalidDataException(
                            "Owner enrollment alias disappeared during capacity scan.");
                    bytes = checked(bytes + OwnerEnrollmentAliasAccountingBytes(value));
                    break;
                }
                case 6:
                {
                    var value = await ReadGenesisCatalogAsync(connection, transaction, key.Route,
                        v2PreparedIntegrityKey, cancellationToken) ?? throw new InvalidDataException(
                            "Genesis catalog disappeared during capacity scan.");
                    bytes = checked(bytes + OwnerGenesisAccountingBytes(value));
                    break;
                }
                default:
                    throw new InvalidDataException("Owner-control capacity kind is invalid.");
            }
            if (bytes > ownerControlLimits.MaximumStateBytes) return false;
        }
        var reserveEntries = terminal ? 0 : 1;
        var reserveBytes = terminal ? 0
            : ProductionMailboxOwnerControlAccounting.TerminalReservationBytes;
        return routeCount + additionalEntries + reserveEntries
                <= ownerControlLimits.MaximumEntriesPerRoute
            && globalCount + additionalEntries + reserveEntries
                <= ownerControlLimits.MaximumEntriesGlobal
            && bytes + additionalBytes + reserveBytes
                <= ownerControlLimits.MaximumStateBytes;
    }

    private async ValueTask<List<PgOwnerCapacityKey>> ReadOwnerCapacityKeysAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction, int limit,
        CancellationToken cancellationToken)
    {
        const string sql = """
            SELECT kind,route_state_key,item_key FROM (
                SELECT 1 AS kind,route_state_key,operation_hash AS item_key
                    FROM production_mailbox_owner_enrollment_ops_v1
                UNION ALL SELECT 2,route_state_key,active_scope
                    FROM production_mailbox_owner_requests_v1
                UNION ALL SELECT 3,route_state_key,request_id
                    FROM production_mailbox_owner_request_ids_v1
                UNION ALL SELECT 4,route_state_key,request_id
                    FROM production_mailbox_owner_revocation_ids_v1
                UNION ALL SELECT 5,route_state_key,request_id
                    FROM production_mailbox_owner_enrollment_ids_v1
                UNION ALL SELECT 6,route_state_key,route_state_key
                    FROM production_mailbox_route_genesis_v1
            ) AS entries
            ORDER BY kind,route_state_key,item_key LIMIT @limit
            """;
        var result = new List<PgOwnerCapacityKey>(Math.Min(limit, 4096));
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue("limit", limit);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
            result.Add(new(reader.GetInt32(0), reader.GetFieldValue<byte[]>(1),
                reader.GetFieldValue<byte[]>(2)));
        return result;
    }

    private async ValueTask AuthenticatedOwnerControlGcAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, ulong nowUnixSeconds,
        CancellationToken cancellationToken)
    {
        var remaining = ownerControlLimits.MaximumGcBatch;
        foreach (var scope in await ReadOwnerGcKeysAsync(connection, transaction,
                     "SELECT active_scope FROM production_mailbox_owner_requests_v1 " +
                     "WHERE expires_at<=@now ORDER BY expires_at,active_scope " +
                     "LIMIT @limit FOR UPDATE", nowUnixSeconds, remaining, cancellationToken))
        {
            var value = await ReadOwnerRequestAsync(connection, transaction, scope,
                cancellationToken) ?? throw new InvalidDataException(
                    "Owner request disappeared during authenticated GC.");
            VerifyOwnerRequest(value);
            if (value.ExpiresAt <= nowUnixSeconds)
            {
                await DeleteOwnerRequestAsync(connection, transaction, scope, cancellationToken);
                remaining--;
            }
        }
        if (remaining == 0) return;
        remaining = await GcOwnerAliasesAsync(connection, transaction,
            PgOwnerAliasKind.Request, nowUnixSeconds, remaining, cancellationToken);
        if (remaining == 0) return;
        remaining = await GcOwnerAliasesAsync(connection, transaction,
            PgOwnerAliasKind.Enrollment, nowUnixSeconds, remaining, cancellationToken);
        if (remaining == 0) return;
        _ = await GcOwnerAliasesAsync(connection, transaction,
            PgOwnerAliasKind.Revocation, nowUnixSeconds, remaining, cancellationToken);
    }

    private static async ValueTask<List<byte[]>> ReadOwnerGcKeysAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction, string sql,
        ulong nowUnixSeconds, int limit, CancellationToken cancellationToken)
    {
        if (limit <= 0) return [];
        var result = new List<byte[]>(Math.Min(limit, 4096));
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue("now", U64(nowUnixSeconds));
        command.Parameters.AddWithValue("limit", limit);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
            result.Add(reader.GetFieldValue<byte[]>(0));
        return result;
    }

    private async ValueTask<int> GcOwnerAliasesAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, PgOwnerAliasKind kind, ulong nowUnixSeconds,
        int remaining, CancellationToken cancellationToken)
    {
        var table = kind switch
        {
            PgOwnerAliasKind.Request => "production_mailbox_owner_request_ids_v1",
            PgOwnerAliasKind.Enrollment => "production_mailbox_owner_enrollment_ids_v1",
            PgOwnerAliasKind.Revocation => "production_mailbox_owner_revocation_ids_v1",
            _ => throw new InvalidOperationException("Owner alias kind is invalid.")
        };
        var sql = $"SELECT route_state_key,request_id FROM {table} " +
            "WHERE retain_until<=@now ORDER BY retain_until,route_state_key,request_id " +
            "LIMIT @limit FOR UPDATE";
        var keys = new List<(byte[] Route, byte[] Id)>(Math.Min(remaining, 4096));
        await using (var command = new NpgsqlCommand(sql, connection, transaction))
        {
            command.Parameters.AddWithValue("now", U64(nowUnixSeconds));
            command.Parameters.AddWithValue("limit", remaining);
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
                keys.Add((reader.GetFieldValue<byte[]>(0), reader.GetFieldValue<byte[]>(1)));
        }
        foreach (var key in keys)
        {
            ulong retainUntil;
            switch (kind)
            {
                case PgOwnerAliasKind.Request:
                {
                    var value = await ReadOwnerRequestAliasAsync(connection, transaction,
                        key.Route, key.Id, cancellationToken) ?? throw new InvalidDataException(
                            "Owner request alias disappeared during authenticated GC.");
                    VerifyOwnerRequestAlias(value); retainUntil = value.RetainUntil; break;
                }
                case PgOwnerAliasKind.Enrollment:
                {
                    var value = await ReadOwnerEnrollmentAliasAsync(connection, transaction,
                        key.Route, key.Id, cancellationToken) ?? throw new InvalidDataException(
                            "Owner enrollment alias disappeared during authenticated GC.");
                    retainUntil = value.RetainUntil; break;
                }
                case PgOwnerAliasKind.Revocation:
                {
                    var value = await ReadOwnerRevocationAliasAsync(connection, transaction,
                        key.Route, key.Id, cancellationToken) ?? throw new InvalidDataException(
                            "Owner revocation alias disappeared during authenticated GC.");
                    VerifyOwnerRevocationAlias(value); retainUntil = value.RetainUntil; break;
                }
                default: throw new InvalidOperationException("Owner alias kind is invalid.");
            }
            if (retainUntil > nowUnixSeconds) continue;
            await using var delete = new NpgsqlCommand(
                $"DELETE FROM {table} WHERE route_state_key=@route AND request_id=@id",
                connection, transaction);
            delete.Parameters.AddWithValue("route", key.Route);
            delete.Parameters.AddWithValue("id", key.Id);
            if (await delete.ExecuteNonQueryAsync(cancellationToken) != 1)
                throw new InvalidDataException("Owner alias GC CAS failed.");
            remaining--;
            if (remaining == 0) break;
        }
        return remaining;
    }

    private static long OwnerEnrollmentAccountingBytes(PgOwnerEnrollment value) => checked(
        ProductionMailboxOwnerControlAccounting.EnrollmentOperationMaximumBytes
        + (value.Response is null
            ? ProductionMailboxOwnerControlAccounting.GenesisBytes(
                ProductionMailboxProtectedGenesisCatalog.MaximumPayloadBytes)
            : 0));

    private static long OwnerRequestAccountingBytes(PgOwnerRequest value) =>
        ProductionMailboxOwnerControlAccounting.OwnerRequestMaximumBytes;

    private static long OwnerRequestAliasAccountingBytes(PgOwnerRequestAlias value) =>
        ProductionMailboxOwnerControlAccounting.OwnerRequestAliasBytes;

    private static long OwnerRevocationAliasAccountingBytes(PgOwnerRevocationAlias value) =>
        ProductionMailboxOwnerControlAccounting.OwnerRevocationAliasBytes;

    private static long OwnerEnrollmentAliasAccountingBytes(PgOwnerEnrollmentAlias value) =>
        ProductionMailboxOwnerControlAccounting.EnrollmentAliasBytes;

    private static long OwnerGenesisAccountingBytes(ProductionMailboxProtectedGenesisCatalog value)
        => ProductionMailboxOwnerControlAccounting.GenesisBytes(value.Payload.Length);

    private async ValueTask<ulong> OwnerDbNowAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand(
            "SELECT floor(extract(epoch FROM clock_timestamp()))::bigint", connection, transaction);
        return checked((ulong)(long)(await command.ExecuteScalarAsync(cancellationToken)
            ?? throw new InvalidDataException("PostgreSQL time is unavailable.")));
    }

    private byte[] ComputeOwnerEnrollmentTag(PgOwnerEnrollment value)
    {
        using var hash = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256,
            v2PreparedIntegrityKey);
        hash.AppendData("Deep/registry/production-mailbox/owner-enrollment-phase/v1"u8);
        foreach (var item in new[] { value.Route, value.RequestId, value.RequestHash,
                     value.OperationHash, value.IntentHash, value.SourceArtifactClosureHash,
                     value.KeyToken,
                     value.Response ?? [],
                     value.PlanHash ?? [], value.KeyId ?? [], value.PublicKey ?? [] })
            OwnerAppend(hash, item);
        OwnerAppend(hash, U64(value.AcceptedAt));
        OwnerAppend(hash, U64(value.RetainUntil));
        OwnerAppend(hash, U64(value.CleanupLeaseUntil));
        hash.AppendData([value.CleanupStarted ? (byte)1 : (byte)0]);
        return hash.GetHashAndReset();
    }

    private byte[] ComputeOwnerEnrollmentAliasTag(PgOwnerEnrollmentAlias value)
    {
        using var hash = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256,
            v2PreparedIntegrityKey);
        hash.AppendData("Deep/registry/production-mailbox/owner-enrollment-alias/v1"u8);
        foreach (var item in new[] { value.Route, value.RequestId, value.OperationHash,
                     value.RequestHash }) OwnerAppend(hash, item);
        OwnerAppend(hash, U64(value.RetainUntil));
        return hash.GetHashAndReset();
    }

    private byte[] ComputeOwnerRevocationAliasTag(PgOwnerRevocationAlias value)
    {
        using var hash = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256,
            v2PreparedIntegrityKey);
        hash.AppendData("Deep/registry/production-mailbox/owner-revocation-alias/v1"u8);
        foreach (var item in new[] { value.Route, value.RequestId, value.OperationHash })
            OwnerAppend(hash, item);
        OwnerAppend(hash, U64(value.RetainUntil));
        return hash.GetHashAndReset();
    }

    private void VerifyOwnerRevocationAlias(PgOwnerRevocationAlias value)
    {
        if (!OwnerFixed(value.Tag, ComputeOwnerRevocationAliasTag(value)))
            throw new InvalidDataException("Stored owner-revocation alias integrity is invalid.");
    }

    private byte[] ComputeOwnerRequestAliasTag(PgOwnerRequestAlias value)
    {
        using var hash = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256,
            v2PreparedIntegrityKey);
        hash.AppendData("Deep/registry/production-mailbox/owner-request-alias/v1"u8);
        foreach (var item in new[] { value.Route, value.RequestId, value.RequestHash })
            OwnerAppend(hash, item);
        OwnerAppend(hash, U64(value.ExpiresAt));
        OwnerAppend(hash, U64(value.RetainUntil));
        return hash.GetHashAndReset();
    }

    private void VerifyOwnerRequestAlias(PgOwnerRequestAlias value)
    {
        if (!OwnerFixed(value.Tag, ComputeOwnerRequestAliasTag(value)))
            throw new InvalidDataException("Stored owner-request alias integrity is invalid.");
    }

    private byte[] ComputeOwnerRequestTag(PgOwnerRequest value)
    {
        using var hash = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256,
            v2PreparedIntegrityKey);
        hash.AppendData("Deep/registry/production-mailbox/owner-control-phase/v1"u8);
        foreach (var item in new[] { value.Route, value.Scope, value.CanonicalRequest,
                     value.RequestHash, value.SourceFingerprint,
                     value.Header ?? [], value.Payload ?? [] })
            OwnerAppend(hash, item);
        OwnerAppend(hash, U64(value.ExpiresAt));
        OwnerAppend(hash, value.PlannedIssuedAt is null
            ? [] : U64(value.PlannedIssuedAt.Value));
        OwnerAppend(hash, value.PlannedExpiresAt is null
            ? [] : U64(value.PlannedExpiresAt.Value));
        hash.AppendData([value.DeliveryAuthorized ? (byte)1 : (byte)0,
            value.Revoked ? (byte)1 : (byte)0]);
        return hash.GetHashAndReset();
    }

    private void VerifyOwnerEnrollment(PgOwnerEnrollment value)
    {
        if (value.KeyToken.Length != 32
            || !OwnerFixed(value.Tag, ComputeOwnerEnrollmentTag(value)))
            throw new InvalidDataException("Stored owner enrollment phase integrity is invalid.");
        var complete = value.Response is not null;
        if (complete != (value.PlanHash is not null && value.KeyId is not null
            && value.PublicKey is not null))
            throw new InvalidDataException("Stored owner enrollment phase is split.");
    }
    private void VerifyOwnerRequest(PgOwnerRequest value)
    {
        if (!OwnerFixed(value.Tag, ComputeOwnerRequestTag(value))
            || value.SourceFingerprint.Length != 32
            || ((value.Header is null) != (value.Payload is null))
            || ((value.PlannedIssuedAt is null) != (value.PlannedExpiresAt is null))
            || (value.Header is not null && value.PlannedIssuedAt is null)
            || (value.DeliveryAuthorized && value.Header is null))
            throw new InvalidDataException("Stored owner request phase integrity is invalid.");
    }
    private static void OwnerAppend(IncrementalHash hash, ReadOnlySpan<byte> value)
    {
        Span<byte> length = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)value.Length));
        hash.AppendData(length); hash.AppendData(value);
    }
    private static byte[] OwnerExact(ReadOnlyMemory<byte> value, int length, string name)
    {
        if (value.Length != length || value.Span.IndexOfAnyExcept((byte)0) < 0)
            throw new InvalidDataException($"{name} is invalid.");
        return value.ToArray();
    }
    private static bool OwnerFixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    private sealed record PgOwnerEnrollment(byte[] Route, byte[] RequestId,
        byte[] RequestHash, byte[] OperationHash, byte[] IntentHash,
        byte[] SourceArtifactClosureHash, byte[] KeyToken, ulong AcceptedAt,
        ulong RetainUntil, bool CleanupStarted, ulong CleanupLeaseUntil,
        byte[]? Response, byte[]? PlanHash, byte[]? KeyId, byte[]? PublicKey, byte[] Tag);
    private sealed record PgOwnerEnrollmentAlias(byte[] Route, byte[] RequestId,
        byte[] OperationHash, byte[] RequestHash, ulong RetainUntil, byte[] Tag);
    private sealed record PgOwnerRevocationAlias(byte[] Route, byte[] RequestId,
        byte[] OperationHash, ulong RetainUntil, byte[] Tag);
    private sealed record PgOwnerRequestAlias(byte[] Route, byte[] RequestId,
        byte[] RequestHash, ulong ExpiresAt, ulong RetainUntil, byte[] Tag);
    private sealed record PgOwnerRequest(byte[] Scope, byte[] Route, byte[] CanonicalRequest,
        byte[] RequestHash, byte[] SourceFingerprint, ulong ExpiresAt,
        ulong? PlannedIssuedAt, ulong? PlannedExpiresAt,
        byte[]? Header, byte[]? Payload,
        bool DeliveryAuthorized, bool Revoked, byte[] Tag);
    private sealed record PgOwnerCapacityKey(int Kind, byte[] Route, byte[] Key);
    private enum PgOwnerAliasKind { Request, Enrollment, Revocation }
}
