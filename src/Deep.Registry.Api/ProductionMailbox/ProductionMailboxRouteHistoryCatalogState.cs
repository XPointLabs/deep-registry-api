using System.Buffers.Binary;
using System.Data;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxTopology;
using Npgsql;
using NpgsqlTypes;

namespace Deep.Registry.Api.ProductionMailbox;

internal enum ProductionMailboxRouteHistoryCommitFaultPoint
{
    None,
    AfterBatch,
    AfterCheckpoint,
    AfterManifest,
    AfterRouteState
}

internal static class ProductionMailboxRouteHistoryCatalogLimits
{
    internal const ulong MaximumBatches =
        ProductionMailboxRouteContinuityConstants.MaximumHistoryBatchCount;
    internal const long MaximumRetainedBatchBytesPerRoute =
        (long)MaximumBatches * ProductionMailboxFrozenHistoryBatch.MaximumBatchBytes;
    internal const int MaximumCatalogRowsPerRoute = 67;
    internal const int ManifestPayloadLength = 216;
    internal const int CheckpointPayloadLength =
        48 + ProductionMailboxRouteHistoryStateSnapshot.ProtectedEncodingLength;
    internal const int TombstonePayloadLength = 232;
    internal const int BatchFixedPayloadLength = 116;
    internal const int MaximumBatchPayloadLength =
        BatchFixedPayloadLength + ProductionMailboxFrozenHistoryBatch.MaximumBatchBytes;
    private const int PhysicalRowOverhead = 16;

    internal static long ManifestRowBytes(int payloadLength, int tagLength) => checked(
        32L + payloadLength + tagLength + PhysicalRowOverhead);
    internal static long SequencedRowBytes(int payloadLength, int tagLength) => checked(
        32L + 8 + payloadLength + tagLength + PhysicalRowOverhead);
}

internal static class ProductionMailboxRouteHistoryCatalogIntegrity
{
    internal static byte[] Compute(ReadOnlySpan<byte> domain, ReadOnlySpan<byte> payload,
        ReadOnlySpan<byte> key)
    {
        if (key.Length != 32 || key.IndexOfAnyExcept((byte)0) < 0)
            throw new InvalidDataException("Route-history integrity key is invalid.");
        using var hmac = new HMACSHA256(key.ToArray());
        hmac.TransformBlock(domain.ToArray(), 0, domain.Length, null, 0);
        hmac.TransformFinalBlock(payload.ToArray(), 0, payload.Length);
        return hmac.Hash ?? throw new CryptographicException("Route-history HMAC failed.");
    }

    internal static void Verify(ReadOnlySpan<byte> domain, ReadOnlySpan<byte> payload,
        ReadOnlySpan<byte> tag, ReadOnlySpan<byte> key)
    {
        if (tag.Length != 32 || !CryptographicOperations.FixedTimeEquals(
                Compute(domain, payload, key), tag))
            throw new InvalidDataException("Stored route-history catalog integrity is invalid.");
    }
}

internal sealed class ProductionMailboxProtectedHistoryManifest
{
    private static ReadOnlySpan<byte> Domain =>
        "Deep/registry/production-mailbox/route-history-manifest/v1"u8;
    private readonly byte[] payload;
    private readonly byte[] tag;

    private ProductionMailboxProtectedHistoryManifest(byte[] payload, byte[] tag)
    {
        this.payload = payload; this.tag = tag;
    }

    internal ReadOnlyMemory<byte> Payload => payload.ToArray();
    internal ReadOnlyMemory<byte> IntegrityTag => tag.ToArray();
    internal ReadOnlyMemory<byte> RouteStateKey => payload.AsMemory(8, 32).ToArray();
    internal ReadOnlyMemory<byte> GenesisPlanHash => payload.AsMemory(40, 32).ToArray();
    internal ReadOnlyMemory<byte> GenesisCheckpointHash => payload.AsMemory(72, 32).ToArray();
    internal ulong HeadSequence => ReadU64(104);
    internal ReadOnlyMemory<byte> HeadCheckpointHash => payload.AsMemory(112, 32).ToArray();
    internal ReadOnlyMemory<byte> HeadBatchHash => payload.AsMemory(144, 32).ToArray();
    internal ulong RetainedBatchCount => ReadU64(176);
    internal ulong RetainedBatchBytes => ReadU64(184);
    internal ulong CumulativeVerifiedLinkCount => ReadU64(192);
    internal ulong CumulativeCanonicalPayloadBytes => ReadU64(200);
    internal bool Terminal => payload[208] == 1;

    internal static ProductionMailboxProtectedHistoryManifest CreateGenesis(
        ReadOnlySpan<byte> routeStateKey, ReadOnlySpan<byte> genesisPlanHash,
        ProductionMailboxRouteHistoryStateSnapshot genesis, ReadOnlySpan<byte> key)
    {
        var payload = Header("PMHM"u8, routeStateKey);
        Put(payload, 40, genesisPlanHash, 32, "genesis plan hash");
        Put(payload, 72, genesis.CanonicalCheckpointHash.Span, 32,
            "genesis checkpoint hash");
        Put(payload, 112, genesis.CanonicalCheckpointHash.Span, 32,
            "head checkpoint hash");
        // Sequence, batch hash, counts, bytes and terminal are canonical zero at genesis.
        return Restore(payload, ProductionMailboxRouteHistoryCatalogIntegrity.Compute(
            Domain, payload, key), key);
    }

    internal ProductionMailboxProtectedHistoryManifest Advance(
        ProductionMailboxFrozenHistoryBatch batch, ReadOnlySpan<byte> key)
    {
        if (Terminal || batch.Next.LastCommittedBatchSequence != HeadSequence + 1 ||
            !Fixed(batch.ExpectedCurrent.CanonicalCheckpointHash.Span,
                HeadCheckpointHash.Span) ||
            RetainedBatchCount != HeadSequence)
            throw new InvalidDataException("Route-history manifest predecessor is invalid.");
        var nextBytes = checked(RetainedBatchBytes + (ulong)batch.CanonicalBatch.Length);
        if (nextBytes > (ulong)ProductionMailboxRouteHistoryCatalogLimits
                .MaximumRetainedBatchBytesPerRoute)
            throw new InvalidDataException("Route-history retained-byte cap is exceeded.");
        var next = payload.ToArray();
        WriteU64(next, 104, batch.Next.LastCommittedBatchSequence);
        Put(next, 112, batch.Next.CanonicalCheckpointHash.Span, 32, "head checkpoint hash");
        Put(next, 144, batch.CanonicalBatchHash, 32, "head batch hash");
        WriteU64(next, 176, checked(RetainedBatchCount + 1));
        WriteU64(next, 184, nextBytes);
        WriteU64(next, 192, batch.CumulativeVerifiedRouteLinkCount);
        WriteU64(next, 200, batch.CumulativeCanonicalPayloadBytes);
        next[208] = batch.IsTerminal ? (byte)1 : (byte)0;
        return Restore(next, ProductionMailboxRouteHistoryCatalogIntegrity.Compute(
            Domain, next, key), key);
    }

    internal static ProductionMailboxProtectedHistoryManifest Restore(
        ReadOnlyMemory<byte> payload, ReadOnlyMemory<byte> tag, ReadOnlySpan<byte> key)
    {
        if (payload.Length != ProductionMailboxRouteHistoryCatalogLimits.ManifestPayloadLength)
            throw new InvalidDataException("Stored route-history manifest length is invalid.");
        var owned = payload.ToArray(); var ownedTag = tag.ToArray();
        ProductionMailboxRouteHistoryCatalogIntegrity.Verify(Domain, owned, ownedTag, key);
        ValidateHeader(owned, "PMHM"u8);
        if (owned.AsSpan(209, 7).IndexOfAnyExcept((byte)0) >= 0 || owned[208] > 1)
            throw new InvalidDataException("Stored route-history manifest flags are invalid.");
        var result = new ProductionMailboxProtectedHistoryManifest(owned, ownedTag);
        if (result.RouteStateKey.Span.IndexOfAnyExcept((byte)0) < 0 ||
            result.GenesisPlanHash.Span.IndexOfAnyExcept((byte)0) < 0 ||
            result.GenesisCheckpointHash.Span.IndexOfAnyExcept((byte)0) < 0 ||
            result.HeadCheckpointHash.Span.IndexOfAnyExcept((byte)0) < 0 ||
            result.HeadSequence > ProductionMailboxRouteHistoryCatalogLimits.MaximumBatches ||
            result.RetainedBatchCount != result.HeadSequence ||
            result.RetainedBatchBytes > (ulong)ProductionMailboxRouteHistoryCatalogLimits
                .MaximumRetainedBatchBytesPerRoute ||
            (result.HeadSequence == 0
                ? result.HeadBatchHash.Span.IndexOfAnyExcept((byte)0) >= 0
                : result.HeadBatchHash.Span.IndexOfAnyExcept((byte)0) < 0))
            throw new InvalidDataException("Stored route-history manifest scalars are invalid.");
        return result;
    }

    private ulong ReadU64(int offset) => BinaryPrimitives.ReadUInt64BigEndian(
        payload.AsSpan(offset, 8));

    private static byte[] Header(ReadOnlySpan<byte> magic, ReadOnlySpan<byte> route)
    {
        if (route.Length != 32 || route.IndexOfAnyExcept((byte)0) < 0)
            throw new InvalidDataException("Route-history route key is invalid.");
        var value = new byte[ProductionMailboxRouteHistoryCatalogLimits.ManifestPayloadLength];
        magic.CopyTo(value); value[4] = 1; route.CopyTo(value.AsSpan(8, 32)); return value;
    }

    internal static void ValidateHeader(ReadOnlySpan<byte> value, ReadOnlySpan<byte> magic)
    {
        if (!value[..4].SequenceEqual(magic) || value[4] != 1 ||
            value.Slice(5, 3).IndexOfAnyExcept((byte)0) >= 0)
            throw new InvalidDataException("Stored route-history catalog header is invalid.");
    }

    internal static void Put(Span<byte> target, int offset, ReadOnlySpan<byte> value,
        int length, string name)
    {
        if (value.Length != length)
            throw new InvalidDataException($"Route-history {name} length is invalid.");
        value.CopyTo(target.Slice(offset, length));
    }

    internal static void WriteU64(Span<byte> target, int offset, ulong value) =>
        BinaryPrimitives.WriteUInt64BigEndian(target.Slice(offset, 8), value);

    internal static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}

internal sealed class ProductionMailboxProtectedHistoryBatch
{
    private static ReadOnlySpan<byte> Domain =>
        "Deep/registry/production-mailbox/route-history-batch/v1"u8;
    private readonly byte[] payload;
    private readonly byte[] tag;

    private ProductionMailboxProtectedHistoryBatch(byte[] payload, byte[] tag)
    { this.payload = payload; this.tag = tag; }

    internal ReadOnlyMemory<byte> Payload => payload.ToArray();
    internal ReadOnlyMemory<byte> IntegrityTag => tag.ToArray();
    internal ReadOnlyMemory<byte> RouteStateKey => payload.AsMemory(8, 32).ToArray();
    internal ulong Sequence => BinaryPrimitives.ReadUInt64BigEndian(payload.AsSpan(40, 8));
    internal ReadOnlyMemory<byte> CanonicalBatchHash => payload.AsMemory(48, 32).ToArray();
    internal ReadOnlyMemory<byte> PlanHash => payload.AsMemory(80, 32).ToArray();
    internal ReadOnlyMemory<byte> CanonicalBatch => payload.AsMemory(116,
        checked((int)BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(112, 4)))).ToArray();

    internal static ProductionMailboxProtectedHistoryBatch Freeze(ReadOnlySpan<byte> route,
        ProductionMailboxFrozenHistoryBatch batch, ReadOnlySpan<byte> key)
    {
        var bytes = batch.CanonicalBatch;
        var payload = new byte[checked(
            ProductionMailboxRouteHistoryCatalogLimits.BatchFixedPayloadLength + bytes.Length)];
        "PMHB"u8.CopyTo(payload); payload[4] = 1;
        ProductionMailboxProtectedHistoryManifest.Put(payload, 8, route, 32, "route key");
        ProductionMailboxProtectedHistoryManifest.WriteU64(payload, 40,
            batch.Next.LastCommittedBatchSequence);
        ProductionMailboxProtectedHistoryManifest.Put(payload, 48, batch.CanonicalBatchHash,
            32, "batch hash");
        ProductionMailboxProtectedHistoryManifest.Put(payload, 80, batch.PlanHash, 32,
            "plan hash");
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(112, 4), checked((uint)bytes.Length));
        bytes.CopyTo(payload.AsSpan(116));
        return Restore(payload, ProductionMailboxRouteHistoryCatalogIntegrity.Compute(
            Domain, payload, key), key);
    }

    internal static ProductionMailboxProtectedHistoryBatch Restore(ReadOnlyMemory<byte> payload,
        ReadOnlyMemory<byte> tag, ReadOnlySpan<byte> key)
    {
        if (payload.Length < ProductionMailboxRouteHistoryCatalogLimits.BatchFixedPayloadLength ||
            payload.Length > ProductionMailboxRouteHistoryCatalogLimits.MaximumBatchPayloadLength)
            throw new InvalidDataException("Stored route-history batch bounds are invalid.");
        var owned = payload.ToArray(); var ownedTag = tag.ToArray();
        ProductionMailboxRouteHistoryCatalogIntegrity.Verify(Domain, owned, ownedTag, key);
        ProductionMailboxProtectedHistoryManifest.ValidateHeader(owned, "PMHB"u8);
        var length = BinaryPrimitives.ReadUInt32BigEndian(owned.AsSpan(112, 4));
        if (length < ProductionMailboxFrozenHistoryBatch.MinimumBatchBytes ||
            length > ProductionMailboxFrozenHistoryBatch.MaximumBatchBytes ||
            owned.Length != ProductionMailboxRouteHistoryCatalogLimits.BatchFixedPayloadLength +
                checked((int)length))
            throw new InvalidDataException("Stored route-history batch framing is invalid.");
        var result = new ProductionMailboxProtectedHistoryBatch(owned, ownedTag);
        if (result.RouteStateKey.Span.IndexOfAnyExcept((byte)0) < 0 ||
            result.Sequence is 0 or > ProductionMailboxRouteHistoryCatalogLimits.MaximumBatches ||
            !ProductionMailboxProtectedHistoryManifest.Fixed(
                SHA256.HashData(result.CanonicalBatch.Span), result.CanonicalBatchHash.Span) ||
            result.PlanHash.Span.IndexOfAnyExcept((byte)0) < 0)
            throw new InvalidDataException("Stored route-history batch identity is invalid.");
        return result;
    }
}

internal sealed class ProductionMailboxProtectedHistoryCheckpoint
{
    private static ReadOnlySpan<byte> Domain =>
        "Deep/registry/production-mailbox/route-history-checkpoint/v1"u8;
    private readonly byte[] payload;
    private readonly byte[] tag;
    private readonly ProductionMailboxRouteHistoryStateSnapshot checkpoint;

    private ProductionMailboxProtectedHistoryCheckpoint(byte[] payload, byte[] tag,
        ProductionMailboxRouteHistoryStateSnapshot checkpoint)
    { this.payload = payload; this.tag = tag; this.checkpoint = checkpoint; }

    internal ReadOnlyMemory<byte> Payload => payload.ToArray();
    internal ReadOnlyMemory<byte> IntegrityTag => tag.ToArray();
    internal ReadOnlyMemory<byte> RouteStateKey => payload.AsMemory(8, 32).ToArray();
    internal ulong Sequence => BinaryPrimitives.ReadUInt64BigEndian(payload.AsSpan(40, 8));
    internal ProductionMailboxRouteHistoryStateSnapshot Checkpoint => checkpoint.Clone();

    internal static ProductionMailboxProtectedHistoryCheckpoint Freeze(ReadOnlySpan<byte> route,
        ProductionMailboxRouteHistoryStateSnapshot checkpoint, ReadOnlySpan<byte> key)
    {
        var payload = new byte[ProductionMailboxRouteHistoryCatalogLimits.CheckpointPayloadLength];
        "PMHC"u8.CopyTo(payload); payload[4] = 1;
        ProductionMailboxProtectedHistoryManifest.Put(payload, 8, route, 32, "route key");
        ProductionMailboxProtectedHistoryManifest.WriteU64(payload, 40,
            checkpoint.LastCommittedBatchSequence);
        checkpoint.EncodeProtected().CopyTo(payload.AsSpan(48));
        return Restore(payload, ProductionMailboxRouteHistoryCatalogIntegrity.Compute(
            Domain, payload, key), key);
    }

    internal static ProductionMailboxProtectedHistoryCheckpoint Restore(
        ReadOnlyMemory<byte> payload, ReadOnlyMemory<byte> tag, ReadOnlySpan<byte> key)
    {
        if (payload.Length != ProductionMailboxRouteHistoryCatalogLimits.CheckpointPayloadLength)
            throw new InvalidDataException("Stored route-history checkpoint length is invalid.");
        var owned = payload.ToArray(); var ownedTag = tag.ToArray();
        ProductionMailboxRouteHistoryCatalogIntegrity.Verify(Domain, owned, ownedTag, key);
        ProductionMailboxProtectedHistoryManifest.ValidateHeader(owned, "PMHC"u8);
        var sequence = BinaryPrimitives.ReadUInt64BigEndian(owned.AsSpan(40, 8));
        var checkpoint = ProductionMailboxRouteHistoryStateSnapshot.DecodeProtected(
            owned.AsSpan(48));
        if (sequence != checkpoint.LastCommittedBatchSequence ||
            sequence > ProductionMailboxRouteHistoryCatalogLimits.MaximumBatches)
            throw new InvalidDataException("Stored route-history checkpoint sequence is invalid.");
        return new(owned, ownedTag, checkpoint);
    }
}

internal sealed class ProductionMailboxProtectedRouteTombstone
{
    private static ReadOnlySpan<byte> Domain =>
        "Deep/registry/production-mailbox/route-history-tombstone/v1"u8;
    private readonly byte[] payload;
    private readonly byte[] tag;

    private ProductionMailboxProtectedRouteTombstone(byte[] payload, byte[] tag)
    { this.payload = payload; this.tag = tag; }

    internal ReadOnlyMemory<byte> Payload => payload.ToArray();
    internal ReadOnlyMemory<byte> IntegrityTag => tag.ToArray();
    internal ReadOnlyMemory<byte> RouteStateKey => payload.AsMemory(8, 32).ToArray();
    internal ReadOnlyMemory<byte> GenesisPlanHash => payload.AsMemory(40, 32).ToArray();
    internal ReadOnlyMemory<byte> HeadCheckpointHash => payload.AsMemory(72, 32).ToArray();
    internal ReadOnlyMemory<byte> HeadBatchHash => payload.AsMemory(104, 32).ToArray();
    internal ReadOnlyMemory<byte> OwnerRevocationHash => payload.AsMemory(136, 32).ToArray();
    internal ReadOnlyMemory<byte> DelegationHash => payload.AsMemory(168, 32).ToArray();
    internal ulong RetainUntilUnixSeconds => BinaryPrimitives.ReadUInt64BigEndian(
        payload.AsSpan(200, 8));
    internal ulong CollectedAtUnixSeconds => BinaryPrimitives.ReadUInt64BigEndian(
        payload.AsSpan(208, 8));

    internal static ProductionMailboxProtectedRouteTombstone Freeze(
        ReadOnlySpan<byte> routeStateKey, ReadOnlySpan<byte> genesisPlanHash,
        ProductionMailboxProtectedHistoryManifest manifest,
        ReadOnlySpan<byte> ownerRevocationHash, ReadOnlySpan<byte> delegationHash,
        ulong retainUntilUnixSeconds, ulong collectedAtUnixSeconds, ReadOnlySpan<byte> key)
    {
        if (retainUntilUnixSeconds == 0 || collectedAtUnixSeconds < retainUntilUnixSeconds)
            throw new InvalidDataException("Route-history tombstone time is invalid.");
        var payload = new byte[ProductionMailboxRouteHistoryCatalogLimits.TombstonePayloadLength];
        "PMHT"u8.CopyTo(payload); payload[4] = 1;
        ProductionMailboxProtectedHistoryManifest.Put(payload, 8, routeStateKey, 32,
            "tombstone route key");
        ProductionMailboxProtectedHistoryManifest.Put(payload, 40, genesisPlanHash, 32,
            "tombstone genesis plan hash");
        ProductionMailboxProtectedHistoryManifest.Put(payload, 72,
            manifest.HeadCheckpointHash.Span, 32, "tombstone checkpoint hash");
        ProductionMailboxProtectedHistoryManifest.Put(payload, 104,
            manifest.HeadBatchHash.Span, 32, "tombstone batch hash");
        ProductionMailboxProtectedHistoryManifest.Put(payload, 136, ownerRevocationHash, 32,
            "tombstone revocation hash");
        ProductionMailboxProtectedHistoryManifest.Put(payload, 168, delegationHash, 32,
            "tombstone delegation hash");
        ProductionMailboxProtectedHistoryManifest.WriteU64(payload, 200,
            retainUntilUnixSeconds);
        ProductionMailboxProtectedHistoryManifest.WriteU64(payload, 208,
            collectedAtUnixSeconds);
        return Restore(payload, ProductionMailboxRouteHistoryCatalogIntegrity.Compute(
            Domain, payload, key), key);
    }

    internal static ProductionMailboxProtectedRouteTombstone Restore(
        ReadOnlyMemory<byte> payload, ReadOnlyMemory<byte> tag, ReadOnlySpan<byte> key)
    {
        if (payload.Length != ProductionMailboxRouteHistoryCatalogLimits.TombstonePayloadLength)
            throw new InvalidDataException("Stored route-history tombstone length is invalid.");
        var owned = payload.ToArray(); var ownedTag = tag.ToArray();
        ProductionMailboxRouteHistoryCatalogIntegrity.Verify(Domain, owned, ownedTag, key);
        ProductionMailboxProtectedHistoryManifest.ValidateHeader(owned, "PMHT"u8);
        if (owned.AsSpan(216, 16).IndexOfAnyExcept((byte)0) >= 0)
            throw new InvalidDataException("Stored route-history tombstone reserve is invalid.");
        var result = new ProductionMailboxProtectedRouteTombstone(owned, ownedTag);
        if (result.RouteStateKey.Span.IndexOfAnyExcept((byte)0) < 0 ||
            result.GenesisPlanHash.Span.IndexOfAnyExcept((byte)0) < 0 ||
            result.HeadCheckpointHash.Span.IndexOfAnyExcept((byte)0) < 0 ||
            result.OwnerRevocationHash.Span.IndexOfAnyExcept((byte)0) < 0 ||
            result.DelegationHash.Span.IndexOfAnyExcept((byte)0) < 0 ||
            result.RetainUntilUnixSeconds == 0 ||
            result.CollectedAtUnixSeconds < result.RetainUntilUnixSeconds)
            throw new InvalidDataException("Stored route-history tombstone is invalid.");
        return result;
    }
}

internal sealed record ProductionMailboxRestoredHistoryCatalog(
    ProductionMailboxProtectedHistoryManifest Manifest,
    VerifiedProductionMailboxRouteHistoryCursor Cursor,
    ProductionMailboxRouteHistoryBatchCommitPlan? HeadPlan,
    ProductionMailboxRouteHistoryStateSnapshot HeadCheckpoint);

internal sealed class ProductionMailboxRouteHistoryLookupRequest
{
    private readonly byte[] networkId;
    private readonly byte[] mailboxOwnerEd25519PublicKey;
    private readonly byte[] routeDomainHash;
    private readonly byte[] selectionInputCommitment;
    private readonly byte[] predecessorRouteOriginLkgHash;
    private readonly byte[] currentCheckpointHash;
    private readonly byte[] predecessorAuthorizationHash;

    internal ProductionMailboxRouteHistoryLookupRequest(
        ReadOnlyMemory<byte> networkId,
        ReadOnlyMemory<byte> mailboxOwnerEd25519PublicKey,
        ReadOnlyMemory<byte> routeDomainHash,
        ReadOnlyMemory<byte> selectionInputCommitment,
        ReadOnlyMemory<byte> predecessorRouteOriginLkgHash,
        ReadOnlyMemory<byte> currentCheckpointHash,
        ulong currentBatchSequence,
        ProductionMailboxRouteAuthorizationKind expectedAuthorizationKind,
        ulong predecessorAuthorizationSequence,
        ReadOnlyMemory<byte> predecessorAuthorizationHash)
    {
        this.networkId = Exact(networkId, 16, "network ID");
        this.mailboxOwnerEd25519PublicKey = Exact(mailboxOwnerEd25519PublicKey, 32,
            "mailbox-owner key");
        this.routeDomainHash = Exact(routeDomainHash, 32, "route-domain hash");
        this.selectionInputCommitment = Exact(selectionInputCommitment, 32,
            "selection commitment");
        this.predecessorRouteOriginLkgHash = Exact(predecessorRouteOriginLkgHash, 32,
            "route-origin hash");
        this.currentCheckpointHash = Exact(currentCheckpointHash, 32,
            "checkpoint hash");
        this.predecessorAuthorizationHash = Exact(predecessorAuthorizationHash, 32,
            "authorization hash");
        if (currentBatchSequence > ProductionMailboxRouteHistoryCatalogLimits.MaximumBatches)
            throw new InvalidDataException("Route-history lookup sequence exceeds its bound.");
        if (expectedAuthorizationKind is not ProductionMailboxRouteAuthorizationKind.OwnerPRA2
                and not ProductionMailboxRouteAuthorizationKind.DelegatedRCA1 ||
            predecessorAuthorizationSequence == ulong.MaxValue)
            throw new InvalidDataException("Route-history lookup authorization is invalid.");
        CurrentBatchSequence = currentBatchSequence;
        ExpectedAuthorizationKind = expectedAuthorizationKind;
        PredecessorAuthorizationSequence = predecessorAuthorizationSequence;
    }

    internal ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    internal ReadOnlyMemory<byte> MailboxOwnerEd25519PublicKey =>
        mailboxOwnerEd25519PublicKey.ToArray();
    internal ReadOnlyMemory<byte> RouteDomainHash => routeDomainHash.ToArray();
    internal ReadOnlyMemory<byte> SelectionInputCommitment => selectionInputCommitment.ToArray();
    internal ReadOnlyMemory<byte> PredecessorRouteOriginLkgHash =>
        predecessorRouteOriginLkgHash.ToArray();
    internal ReadOnlyMemory<byte> CurrentCheckpointHash => currentCheckpointHash.ToArray();
    internal ulong CurrentBatchSequence { get; }
    internal ProductionMailboxRouteAuthorizationKind ExpectedAuthorizationKind { get; }
    internal ulong PredecessorAuthorizationSequence { get; }
    internal ReadOnlyMemory<byte> PredecessorAuthorizationHash =>
        predecessorAuthorizationHash.ToArray();

    private static byte[] Exact(ReadOnlyMemory<byte> value, int length, string name)
    {
        if (value.Length != length || value.Span.IndexOfAnyExcept((byte)0) < 0)
            throw new InvalidDataException($"Route-history lookup {name} is invalid.");
        return value.ToArray();
    }
}

internal sealed class ProductionMailboxRouteHistoryLookup
{
    private readonly byte[] routeLocalSourceFingerprint;
    private readonly byte[] currentRouteOriginLkgHash;
    private readonly byte[] currentAuthorizationHash;
    private readonly byte[] canonicalNextBatch;
    private readonly byte[] canonicalNextCheckpoint;

    internal ProductionMailboxRouteHistoryLookup(
        ProductionMailboxRouteHistoryLookupStatus status,
        VerifiedProductionMailboxHistoricalRouteAnchor anchor,
        VerifiedProductionMailboxRouteHistoryCursor cursor,
        ProductionMailboxRouteHistoryBatchCommitPlan? nextPlan,
        ReadOnlySpan<byte> routeLocalSourceFingerprint,
        ReadOnlySpan<byte> currentRouteOriginLkgHash,
        ProductionMailboxRouteAuthorizationKind currentAuthorizationKind,
        ulong currentAuthorizationSequence,
        ReadOnlySpan<byte> currentAuthorizationHash)
    {
        if (status is not ProductionMailboxRouteHistoryLookupStatus.History and
                not ProductionMailboxRouteHistoryLookupStatus.HeadNoChange ||
            routeLocalSourceFingerprint.Length != 32 ||
            currentRouteOriginLkgHash.Length != 32 || currentAuthorizationHash.Length != 32 ||
            routeLocalSourceFingerprint.IndexOfAnyExcept((byte)0) < 0 ||
            currentRouteOriginLkgHash.IndexOfAnyExcept((byte)0) < 0 ||
            currentAuthorizationHash.IndexOfAnyExcept((byte)0) < 0 ||
            (status == ProductionMailboxRouteHistoryLookupStatus.History) != (nextPlan is not null))
            throw new InvalidDataException("Route-history lookup result is inconsistent.");
        Status = status;
        Anchor = anchor ?? throw new ArgumentNullException(nameof(anchor));
        Cursor = cursor ?? throw new ArgumentNullException(nameof(cursor));
        NextPlan = nextPlan;
        this.routeLocalSourceFingerprint = routeLocalSourceFingerprint.ToArray();
        this.currentRouteOriginLkgHash = currentRouteOriginLkgHash.ToArray();
        CurrentAuthorizationKind = currentAuthorizationKind;
        CurrentAuthorizationSequence = currentAuthorizationSequence;
        this.currentAuthorizationHash = currentAuthorizationHash.ToArray();
        canonicalNextBatch = nextPlan?.CanonicalBatch.ToArray() ?? [];
        canonicalNextCheckpoint = nextPlan?.NextCursor.CanonicalCheckpoint.ToArray() ?? [];
    }

    internal ProductionMailboxRouteHistoryLookupStatus Status { get; }
    internal VerifiedProductionMailboxHistoricalRouteAnchor Anchor { get; }
    internal VerifiedProductionMailboxRouteHistoryCursor Cursor { get; }
    internal ProductionMailboxRouteHistoryBatchCommitPlan? NextPlan { get; }
    internal ReadOnlyMemory<byte> RouteLocalSourceFingerprint =>
        routeLocalSourceFingerprint.ToArray();
    internal ReadOnlyMemory<byte> CurrentRouteOriginLkgHash =>
        currentRouteOriginLkgHash.ToArray();
    internal ProductionMailboxRouteAuthorizationKind CurrentAuthorizationKind { get; }
    internal ulong CurrentAuthorizationSequence { get; }
    internal ReadOnlyMemory<byte> CurrentAuthorizationHash => currentAuthorizationHash.ToArray();
    internal ReadOnlyMemory<byte> CanonicalNextBatch => canonicalNextBatch.ToArray();
    internal ReadOnlyMemory<byte> CanonicalNextCheckpoint => canonicalNextCheckpoint.ToArray();
}

internal static class ProductionMailboxRouteHistoryCatalogVerifier
{
    internal static ProductionMailboxRestoredHistoryCatalog Restore(
        ReadOnlySpan<byte> route,
        ProductionMailboxRouteContinuityStateSnapshot current,
        ProductionMailboxProtectedGenesisCatalog genesisProtected,
        ProductionMailboxProtectedHistoryManifest manifestProtected,
        IReadOnlyDictionary<ulong, ProductionMailboxProtectedHistoryBatch> batchRows,
        IReadOnlyDictionary<ulong, ProductionMailboxProtectedHistoryCheckpoint> checkpointRows,
        ReadOnlySpan<byte> integrityKey)
        => RestoreCore(route, current, genesisProtected, manifestProtected, batchRows,
            checkpointRows, integrityKey, null).Catalog;

    internal static ProductionMailboxRouteHistoryLookupResult Lookup(
        ReadOnlySpan<byte> route,
        ProductionMailboxRouteContinuityStateSnapshot current,
        ProductionMailboxProtectedGenesisCatalog genesisProtected,
        ProductionMailboxProtectedHistoryManifest manifestProtected,
        IReadOnlyDictionary<ulong, ProductionMailboxProtectedHistoryBatch> batchRows,
        IReadOnlyDictionary<ulong, ProductionMailboxProtectedHistoryCheckpoint> checkpointRows,
        ReadOnlySpan<byte> integrityKey,
        ProductionMailboxRouteHistoryLookupRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        return RestoreCore(route, current, genesisProtected, manifestProtected, batchRows,
            checkpointRows, integrityKey, request).Lookup ?? throw new InvalidDataException(
                "Route-history lookup result was not materialized.");
    }

    private static RestoredWithLookup RestoreCore(
        ReadOnlySpan<byte> route,
        ProductionMailboxRouteContinuityStateSnapshot current,
        ProductionMailboxProtectedGenesisCatalog genesisProtected,
        ProductionMailboxProtectedHistoryManifest manifestProtected,
        IReadOnlyDictionary<ulong, ProductionMailboxProtectedHistoryBatch> batchRows,
        IReadOnlyDictionary<ulong, ProductionMailboxProtectedHistoryCheckpoint> checkpointRows,
        ReadOnlySpan<byte> integrityKey,
        ProductionMailboxRouteHistoryLookupRequest? request)
    {
        var genesis = ProductionMailboxProtectedGenesisCatalog.Restore(
            genesisProtected.Payload, genesisProtected.IntegrityTag, integrityKey)
            .RestoreProtocol();
        var manifest = ProductionMailboxProtectedHistoryManifest.Restore(
            manifestProtected.Payload, manifestProtected.IntegrityTag, integrityKey);
        if (!ProductionMailboxProtectedHistoryManifest.Fixed(route,
                manifest.RouteStateKey.Span) ||
            !ProductionMailboxProtectedHistoryManifest.Fixed(genesis.Value.PlanHash,
                manifest.GenesisPlanHash.Span) ||
            !ProductionMailboxProtectedHistoryManifest.Fixed(
                genesis.Cursor.CanonicalCheckpointHash.Span,
                manifest.GenesisCheckpointHash.Span) ||
            batchRows.Count != checked((int)manifest.HeadSequence) ||
            checkpointRows.Count != checked((int)manifest.HeadSequence + 1))
            throw new InvalidDataException(
                "Route-history manifest does not match retained rows.");

        var genesisCheckpoint = RestoreCheckpoint(checkpointRows, 0, route, integrityKey);
        var expectedGenesis = new ProductionMailboxRouteHistoryStateSnapshot(
            genesis.Cursor.ToProtectedRestoreContext());
        if (!genesisCheckpoint.Exact(expectedGenesis))
            throw new InvalidDataException("Route-history genesis checkpoint is split.");
        var cursor = genesis.Cursor;
        var requestedCursor = request?.CurrentBatchSequence == 0 ? cursor : null;
        var requestedLineage = request?.CurrentBatchSequence == 0
            ? LookupLineage.FromGenesis(genesis) : null;
        ProductionMailboxRouteHistoryBatchCommitPlan? requestedNextPlan = null;
        ProductionMailboxRouteHistoryBatchCommitPlan? headPlan = null;
        ulong retainedBytes = 0;
        for (ulong sequence = 1; sequence <= manifest.HeadSequence; sequence++)
        {
            if (!batchRows.TryGetValue(sequence, out var protectedBatch))
                throw new InvalidDataException("Route-history batch sequence has a gap.");
            var batch = ProductionMailboxProtectedHistoryBatch.Restore(
                protectedBatch.Payload, protectedBatch.IntegrityTag, integrityKey);
            if (!ProductionMailboxProtectedHistoryManifest.Fixed(route,
                    batch.RouteStateKey.Span) || batch.Sequence != sequence)
                throw new InvalidDataException("Route-history batch route/sequence is split.");
            var checkpoint = RestoreCheckpoint(checkpointRows, sequence, route, integrityKey);
            var verified = ProductionMailboxRouteHistoryAuthoring.VerifyNextBatchForCommit(
                cursor, batch.CanonicalBatch.Span);
            var verifiedCheckpoint = new ProductionMailboxRouteHistoryStateSnapshot(
                verified.ToProtectedRestoreContext());
            if (!checkpoint.Exact(verifiedCheckpoint) ||
                !ProductionMailboxProtectedHistoryManifest.Fixed(
                    verified.CanonicalBatchHash.Span, batch.CanonicalBatchHash.Span) ||
                !ProductionMailboxProtectedHistoryManifest.Fixed(
                    verified.PlanHash.Span, batch.PlanHash.Span))
                throw new InvalidDataException(
                    "Route-history batch/checkpoint plan is split.");
            retainedBytes = checked(retainedBytes + (ulong)batch.CanonicalBatch.Length);
            cursor = verified.NextCursor;
            headPlan = verified;
            if (request is not null && sequence == request.CurrentBatchSequence)
            {
                requestedCursor = cursor;
                requestedLineage = LookupLineage.FromPlan(verified);
            }
            if (request is not null && request.CurrentBatchSequence <
                    ProductionMailboxRouteHistoryCatalogLimits.MaximumBatches &&
                sequence == request.CurrentBatchSequence + 1)
                requestedNextPlan = verified;
        }
        var head = new ProductionMailboxRouteHistoryStateSnapshot(
            cursor.ToProtectedRestoreContext());
        if (!head.Exact(RestoreCheckpoint(checkpointRows, manifest.HeadSequence, route,
                integrityKey)) ||
            !ProductionMailboxProtectedHistoryManifest.Fixed(
                head.CanonicalCheckpointHash.Span, manifest.HeadCheckpointHash.Span) ||
            !ProductionMailboxProtectedHistoryManifest.Fixed(
                head.LastCommittedBatchHash.Span, manifest.HeadBatchHash.Span) ||
            retainedBytes != manifest.RetainedBatchBytes)
            throw new InvalidDataException("Route-history manifest head is inconsistent.");
        InMemoryProductionMailboxStateStore.ValidateHistoryHeadAgainstRouteState(
            current, genesis, headPlan, head);
        var catalog = new ProductionMailboxRestoredHistoryCatalog(
            manifest, cursor, headPlan, head);
        if (request is null) return new(catalog, null);
        if (current.OwnerRevocationGeneration != 0)
            return new(catalog, new(ProductionMailboxRouteHistoryLookupStatus.Revoked, null));
        if (request.CurrentBatchSequence > manifest.HeadSequence)
            return new(catalog, new(ProductionMailboxRouteHistoryLookupStatus.Ahead, null));
        if (requestedCursor is null || requestedLineage is null)
            throw new InvalidDataException("Route-history requested cursor was not retained.");
        if (!LookupMatches(request, genesis, requestedCursor, requestedLineage))
            return new(catalog, new(
                ProductionMailboxRouteHistoryLookupStatus.PredecessorMismatch, null));
        var status = request.CurrentBatchSequence == manifest.HeadSequence
            ? ProductionMailboxRouteHistoryLookupStatus.HeadNoChange
            : ProductionMailboxRouteHistoryLookupStatus.History;
        if ((status == ProductionMailboxRouteHistoryLookupStatus.History) !=
                (requestedNextPlan is not null))
            throw new InvalidDataException("Route-history successor lookup is incomplete.");
        var fingerprint = ComputeLookupFingerprint(route, genesis, manifest, request,
            requestedLineage, requestedNextPlan, status);
        return new(catalog, new(status, new ProductionMailboxRouteHistoryLookup(status,
            genesis.Anchor, requestedCursor, requestedNextPlan, fingerprint,
            requestedLineage.RouteOriginLkgHash,
            requestedLineage.AuthorizationKind,
            requestedLineage.AuthorizationSequence,
            requestedLineage.AuthorizationHash)));
    }

    private static bool LookupMatches(ProductionMailboxRouteHistoryLookupRequest request,
        ProductionMailboxRestoredGenesis genesis,
        VerifiedProductionMailboxRouteHistoryCursor cursor,
        LookupLineage lineage)
    {
        var delegation = genesis.Enrollment.Delegation;
        return cursor.LastCommittedBatchSequence == request.CurrentBatchSequence &&
            ProductionMailboxProtectedHistoryManifest.Fixed(
                cursor.CanonicalCheckpointHash.Span, request.CurrentCheckpointHash.Span) &&
            ProductionMailboxProtectedHistoryManifest.Fixed(
                lineage.RouteOriginLkgHash, request.PredecessorRouteOriginLkgHash.Span) &&
            lineage.AuthorizationKind == request.ExpectedAuthorizationKind &&
            lineage.AuthorizationSequence == request.PredecessorAuthorizationSequence &&
            ProductionMailboxProtectedHistoryManifest.Fixed(
                lineage.AuthorizationHash, request.PredecessorAuthorizationHash.Span) &&
            ProductionMailboxProtectedHistoryManifest.Fixed(
                delegation.NetworkId.Span, request.NetworkId.Span) &&
            ProductionMailboxProtectedHistoryManifest.Fixed(
                delegation.MailboxOwnerEd25519PublicKey.Span,
                request.MailboxOwnerEd25519PublicKey.Span) &&
            ProductionMailboxProtectedHistoryManifest.Fixed(
                delegation.RouteDomainHash.Span, request.RouteDomainHash.Span) &&
            ProductionMailboxProtectedHistoryManifest.Fixed(
                delegation.SelectionInputCommitment.Span,
                request.SelectionInputCommitment.Span);
    }

    private static byte[] ComputeLookupFingerprint(ReadOnlySpan<byte> route,
        ProductionMailboxRestoredGenesis genesis,
        ProductionMailboxProtectedHistoryManifest manifest,
        ProductionMailboxRouteHistoryLookupRequest request,
        LookupLineage lineage,
        ProductionMailboxRouteHistoryBatchCommitPlan? nextPlan,
        ProductionMailboxRouteHistoryLookupStatus status)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(status == ProductionMailboxRouteHistoryLookupStatus.History
            ? "Deep/registry/production-mailbox/route-history-lookup/history/v1"u8
            : "Deep/registry/production-mailbox/route-history-lookup/head/v1"u8);
        Append(route); Append(manifest.GenesisPlanHash.Span);
        Append(genesis.Enrollment.CanonicalDelegationHash.Span);
        Append(genesis.Enrollment.CanonicalAcceptanceHash.Span);
        Append(request.NetworkId.Span); Append(request.MailboxOwnerEd25519PublicKey.Span);
        Append(request.RouteDomainHash.Span); Append(request.SelectionInputCommitment.Span);
        AppendU64(request.CurrentBatchSequence); Append(request.CurrentCheckpointHash.Span);
        Append(lineage.RouteOriginLkgHash); hash.AppendData([(byte)lineage.AuthorizationKind]);
        AppendU64(lineage.AuthorizationSequence); Append(lineage.AuthorizationHash);
        if (nextPlan is not null)
        {
            AppendU64(nextPlan.NextCursor.LastCommittedBatchSequence);
            Append(nextPlan.CanonicalBatchHash.Span);
            Append(nextPlan.NextCursor.CanonicalCheckpointHash.Span);
            Append(nextPlan.PlanHash.Span);
        }
        else
        {
            AppendU64(manifest.HeadSequence); Append(manifest.HeadCheckpointHash.Span);
            Append(manifest.HeadBatchHash.Span);
        }
        return hash.GetHashAndReset();

        void Append(ReadOnlySpan<byte> value) => hash.AppendData(value);
        void AppendU64(ulong value)
        {
            Span<byte> encoded = stackalloc byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(encoded, value); hash.AppendData(encoded);
        }
    }

    private static ProductionMailboxRouteHistoryStateSnapshot RestoreCheckpoint(
        IReadOnlyDictionary<ulong, ProductionMailboxProtectedHistoryCheckpoint> rows,
        ulong sequence, ReadOnlySpan<byte> exactRoute, ReadOnlySpan<byte> integrityKey)
    {
        if (!rows.TryGetValue(sequence, out var protectedCheckpoint))
            throw new InvalidDataException("Route-history checkpoint sequence has a gap.");
        var checkpoint = ProductionMailboxProtectedHistoryCheckpoint.Restore(
            protectedCheckpoint.Payload, protectedCheckpoint.IntegrityTag, integrityKey);
        if (checkpoint.Sequence != sequence ||
            !ProductionMailboxProtectedHistoryManifest.Fixed(exactRoute,
                checkpoint.RouteStateKey.Span))
            throw new InvalidDataException("Route-history checkpoint route/sequence is split.");
        return checkpoint.Checkpoint;
    }

    private sealed record RestoredWithLookup(
        ProductionMailboxRestoredHistoryCatalog Catalog,
        ProductionMailboxRouteHistoryLookupResult? Lookup);

    private sealed class LookupLineage
    {
        private LookupLineage(ReadOnlySpan<byte> routeOriginLkgHash,
            ProductionMailboxRouteAuthorizationKind authorizationKind,
            ulong authorizationSequence, ReadOnlySpan<byte> authorizationHash)
        {
            RouteOriginLkgHash = routeOriginLkgHash.ToArray();
            AuthorizationKind = authorizationKind;
            AuthorizationSequence = authorizationSequence;
            AuthorizationHash = authorizationHash.ToArray();
        }

        internal byte[] RouteOriginLkgHash { get; }
        internal ProductionMailboxRouteAuthorizationKind AuthorizationKind { get; }
        internal ulong AuthorizationSequence { get; }
        internal byte[] AuthorizationHash { get; }

        internal static LookupLineage FromGenesis(ProductionMailboxRestoredGenesis genesis)
        {
            var delegation = genesis.Enrollment.Delegation;
            var hash = genesis.Cursor.ToProtectedRestoreContext()
                .CurrentRouteOriginLkgHash.ToArray();
            if (!ProductionMailboxProtectedHistoryManifest.Fixed(
                    hash, genesis.Value.Fields[17]))
                throw new InvalidDataException("Genesis route-history lineage is split.");
            return new(hash, delegation.AnchorAuthorizationKind,
                delegation.AnchorRouteAuthorizationSequence,
                delegation.AnchorCanonicalRouteAuthorizationHash.Span);
        }

        internal static LookupLineage FromPlan(
            ProductionMailboxRouteHistoryBatchCommitPlan plan)
        {
            var value = plan.NextDurableRouteState;
            return new(value.CanonicalRouteOriginLkgHash.Span, value.AuthorizationKind,
                value.AuthorizationSequence, value.CanonicalAuthorizationHash.Span);
        }
    }
}

public sealed partial class InMemoryProductionMailboxStateStore
{
    private readonly Dictionary<string, ProductionMailboxProtectedHistoryManifest>
        routeHistoryManifests = new(StringComparer.Ordinal);
    private readonly Dictionary<string, SortedDictionary<ulong,
        ProductionMailboxProtectedHistoryBatch>> routeHistoryBatches = new(StringComparer.Ordinal);
    private readonly Dictionary<string, SortedDictionary<ulong,
        ProductionMailboxProtectedHistoryCheckpoint>> routeHistoryCheckpoints = new(StringComparer.Ordinal);
    private readonly Dictionary<string, ProductionMailboxProtectedRouteTombstone>
        routeHistoryTombstones = new(StringComparer.Ordinal);

    async ValueTask<ProductionMailboxRouteHistoryLookupResult>
        IProductionMailboxRouteContinuityStateStore.LookupRouteHistoryAsync(
        ReadOnlyMemory<byte> routeStateKey,
        ProductionMailboxRouteHistoryLookupRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var route = ProductionMailboxRouteContinuityStateGuard.FreezeKey(routeStateKey);
        await gate.WaitAsync(cancellationToken);
        try
        {
            var key = Convert.ToHexString(route);
            if (HasRouteHistoryTombstone(route))
                return new(ProductionMailboxRouteHistoryLookupStatus.Terminal, null);
            if (!routeContinuityStates.TryGetValue(key, out var current))
                return new(ProductionMailboxRouteHistoryLookupStatus.MissingState, null);
            PostgreSqlProductionMailboxStateStore.ValidateStoredState(current);
            if (!genesisCatalogs.TryGetValue(key, out var genesis) ||
                !routeHistoryManifests.TryGetValue(key, out var manifest) ||
                !routeHistoryBatches.TryGetValue(key, out var batches) ||
                !routeHistoryCheckpoints.TryGetValue(key, out var checkpoints))
                throw new InvalidDataException("Route-history lookup catalog is incomplete.");
            return ProductionMailboxRouteHistoryCatalogVerifier.Lookup(route, current,
                genesis, manifest, batches, checkpoints, v2PublicationIntegrityKey, request);
        }
        finally { gate.Release(); }
    }

    internal async ValueTask<bool> TryCollectTerminalRouteAsync(
        ReadOnlyMemory<byte> routeStateKey, CancellationToken cancellationToken)
    {
        var route = ProductionMailboxRouteContinuityStateGuard.FreezeKey(routeStateKey);
        await gate.WaitAsync(cancellationToken);
        try
        {
            var key = Convert.ToHexString(route);
            if (routeHistoryTombstones.TryGetValue(key, out var existingTombstone))
            {
                _ = ProductionMailboxProtectedRouteTombstone.Restore(
                    existingTombstone.Payload, existingTombstone.IntegrityTag,
                    v2PublicationIntegrityKey);
                return true;
            }
            if (!routeContinuityStates.TryGetValue(key, out var current)) return false;
            PostgreSqlProductionMailboxStateStore.ValidateStoredState(current);
            var restored = RestoreHistoryCatalog(route, current);
            if (current.OwnerRevocationGeneration == 0 ||
                current.CanonicalOwnerRevocation.Length !=
                    ProductionMailboxRouteContinuityConstants.CanonicalRevocationLength ||
                !Fixed(SHA256.HashData(current.CanonicalOwnerRevocation.Span),
                    current.CanonicalOwnerRevocationHash.Span))
                return false;
            var enrollment = ownerEnrollmentOperations.Values.Where(value =>
                Fixed(value.RouteStateKey, route) && value.CanonicalResponse is not null).ToArray();
            if (enrollment.Length != 1) return false;
            VerifyEnrollmentTag(enrollment[0]);
            if (!genesisCatalogs.TryGetValue(key, out var genesisProtected))
                throw new InvalidDataException("Terminal route genesis catalog is missing.");
            var genesis = ProductionMailboxProtectedGenesisCatalog.Restore(
                genesisProtected.Payload, genesisProtected.IntegrityTag,
                v2PublicationIntegrityKey).RestoreProtocol();
            var delegation = genesis.Enrollment.Delegation;
            var ocr = ProductionMailboxOwnerControlTransportCodec.DecodeResponderCertificate(
                genesis.EnrollmentContext.CanonicalOwnerControlResponderCertificate.Span);
            var horizon = Math.Min(delegation.ExpiresAtUnixSeconds, ocr.ExpiresAtUnixSeconds);
            var unix = timeProvider.GetUtcNow().ToUnixTimeSeconds();
            if (unix < 0) throw new InvalidDataException("Terminal route collection time is invalid.");
            var now = checked((ulong)unix);
            if (now < horizon) return false;
            AuthenticatedOwnerControlGc(now);
            if (ownerControlRequests.Values.Any(value => Fixed(value.RouteStateKey, route)) ||
                ownerControlRequestIds.Values.Any(value => Fixed(value.RouteStateKey, route)) ||
                ownerRevocationRequestIds.Values.Any(value => Fixed(value.RouteStateKey, route)) ||
                ownerEnrollmentRequestIds.Values.Any(value => Fixed(value.RouteStateKey, route)) ||
                v2Activations.Values.Any(value => Fixed(value.RouteStateKey, route)) ||
                ownerBundles.ContainsKey(key))
                return false;
            var tombstone = ProductionMailboxProtectedRouteTombstone.Freeze(route,
                genesis.Value.PlanHash, restored.Manifest,
                current.CanonicalOwnerRevocationHash.Span,
                current.CanonicalDelegationHash.Span, horizon, now,
                v2PublicationIntegrityKey);
            routeHistoryTombstones.Add(key, tombstone);
            routeHistoryManifests.Remove(key);
            routeHistoryBatches.Remove(key);
            routeHistoryCheckpoints.Remove(key);
            routeContinuityStates.Remove(key);
            genesisCatalogs.Remove(key);
            ownerEnrollmentOperations.Remove(EnrollmentOperationKey(route,
                enrollment[0].OperationHash));
            foreach (var alias in ownerEnrollmentRequestIds.Where(value =>
                         Fixed(value.Value.RouteStateKey, route)).Select(value => value.Key).ToArray())
                ownerEnrollmentRequestIds.Remove(alias);
            foreach (var alias in ownerRevocationRequestIds.Where(value =>
                         Fixed(value.Value.RouteStateKey, route)).Select(value => value.Key).ToArray())
                ownerRevocationRequestIds.Remove(alias);
            return true;
        }
        finally { gate.Release(); }
    }

    private bool HasRouteHistoryTombstone(ReadOnlySpan<byte> routeStateKey)
    {
        if (!routeHistoryTombstones.TryGetValue(Convert.ToHexString(routeStateKey),
                out var tombstone)) return false;
        _ = ProductionMailboxProtectedRouteTombstone.Restore(tombstone.Payload,
            tombstone.IntegrityTag, v2PublicationIntegrityKey);
        return true;
    }

    private void SeedHistoryCatalog(ReadOnlySpan<byte> routeStateKey,
        ProductionMailboxProtectedGenesisCatalog genesis,
        ProductionMailboxRouteHistoryStateSnapshot initial)
    {
        var route = routeStateKey.ToArray();
        var key = Convert.ToHexString(route);
        if (routeHistoryManifests.ContainsKey(key) || routeHistoryBatches.ContainsKey(key) ||
            routeHistoryCheckpoints.ContainsKey(key))
            throw new InvalidDataException("Route-history catalog already exists at genesis.");
        var manifest = ProductionMailboxProtectedHistoryManifest.CreateGenesis(route,
            genesis.PlanHash.Span, initial, v2PublicationIntegrityKey);
        var checkpoint = ProductionMailboxProtectedHistoryCheckpoint.Freeze(route, initial,
            v2PublicationIntegrityKey);
        EnsureHistoryCapacityForAppend(key,
            ProductionMailboxRouteHistoryCatalogLimits.ManifestRowBytes(
                manifest.Payload.Length, manifest.IntegrityTag.Length) +
            ProductionMailboxRouteHistoryCatalogLimits.SequencedRowBytes(
                checkpoint.Payload.Length, checkpoint.IntegrityTag.Length), 2);
        routeHistoryManifests[key] = manifest;
        routeHistoryBatches[key] = new();
        routeHistoryCheckpoints[key] = new() { [0] = checkpoint };
    }

    private ProductionMailboxRestoredHistoryCatalog RestoreHistoryCatalog(
        ReadOnlySpan<byte> routeStateKey, ProductionMailboxRouteContinuityStateSnapshot current)
    {
        var route = routeStateKey.ToArray(); var key = Convert.ToHexString(route);
        if (!genesisCatalogs.TryGetValue(key, out var genesisProtected) ||
            !routeHistoryManifests.TryGetValue(key, out var manifestProtected) ||
            !routeHistoryBatches.TryGetValue(key, out var batchRows) ||
            !routeHistoryCheckpoints.TryGetValue(key, out var checkpointRows))
            throw new InvalidDataException("Route-history catalog is incomplete.");
        return ProductionMailboxRouteHistoryCatalogVerifier.Restore(route, current,
            genesisProtected, manifestProtected, batchRows, checkpointRows,
            v2PublicationIntegrityKey);
    }

    private void AppendHistoryCatalog(ReadOnlySpan<byte> routeStateKey,
        ProductionMailboxRestoredHistoryCatalog restored,
        ProductionMailboxFrozenHistoryBatch batch)
    {
        var route = routeStateKey.ToArray(); var key = Convert.ToHexString(route);
        var protectedBatch = ProductionMailboxProtectedHistoryBatch.Freeze(route, batch,
            v2PublicationIntegrityKey);
        var protectedCheckpoint = ProductionMailboxProtectedHistoryCheckpoint.Freeze(route,
            batch.Next, v2PublicationIntegrityKey);
        var nextManifest = restored.Manifest.Advance(batch, v2PublicationIntegrityKey);
        EnsureHistoryCapacityForAppend(key,
            ProductionMailboxRouteHistoryCatalogLimits.SequencedRowBytes(
                protectedBatch.Payload.Length, protectedBatch.IntegrityTag.Length) +
            ProductionMailboxRouteHistoryCatalogLimits.SequencedRowBytes(
                protectedCheckpoint.Payload.Length,
                protectedCheckpoint.IntegrityTag.Length), 2);
        var sequence = batch.Next.LastCommittedBatchSequence;
        if (routeHistoryBatches[key].ContainsKey(sequence) ||
            routeHistoryCheckpoints[key].ContainsKey(sequence))
            throw new InvalidDataException("Route-history append collided with retained state.");
        routeHistoryBatches[key].Add(sequence, protectedBatch);
        routeHistoryCheckpoints[key].Add(sequence, protectedCheckpoint);
        routeHistoryManifests[key] = nextManifest;
    }

    private void EnsureHistoryCapacityForAppend(string routeKey, long additionalBytes,
        int additionalRows)
    {
        if (additionalBytes < 0 || additionalRows < 0)
            throw new InvalidDataException("Route-history prospective accounting is invalid.");
        var routeRows = (routeHistoryManifests.ContainsKey(routeKey) ? 1 : 0) +
            (routeHistoryBatches.TryGetValue(routeKey, out var batches) ? batches.Count : 0) +
            (routeHistoryCheckpoints.TryGetValue(routeKey, out var checkpoints)
                ? checkpoints.Count : 0) + (routeHistoryTombstones.ContainsKey(routeKey) ? 1 : 0);
        var globalRows = routeHistoryManifests.Count + routeHistoryBatches.Values.Sum(x => x.Count) +
            routeHistoryCheckpoints.Values.Sum(x => x.Count) + routeHistoryTombstones.Count;
        long bytes = 0;
        foreach (var value in routeHistoryManifests.Values)
        {
            _ = ProductionMailboxProtectedHistoryManifest.Restore(value.Payload,
                value.IntegrityTag, v2PublicationIntegrityKey);
            bytes = checked(bytes + ProductionMailboxRouteHistoryCatalogLimits
                .ManifestRowBytes(value.Payload.Length, value.IntegrityTag.Length));
        }
        foreach (var value in routeHistoryBatches.Values.SelectMany(x => x.Values))
        {
            _ = ProductionMailboxProtectedHistoryBatch.Restore(value.Payload,
                value.IntegrityTag, v2PublicationIntegrityKey);
            bytes = checked(bytes + ProductionMailboxRouteHistoryCatalogLimits
                .SequencedRowBytes(value.Payload.Length, value.IntegrityTag.Length));
        }
        foreach (var value in routeHistoryCheckpoints.Values.SelectMany(x => x.Values))
        {
            _ = ProductionMailboxProtectedHistoryCheckpoint.Restore(value.Payload,
                value.IntegrityTag, v2PublicationIntegrityKey);
            bytes = checked(bytes + ProductionMailboxRouteHistoryCatalogLimits
                .SequencedRowBytes(value.Payload.Length, value.IntegrityTag.Length));
        }
        foreach (var value in routeHistoryTombstones.Values)
        {
            _ = ProductionMailboxProtectedRouteTombstone.Restore(value.Payload,
                value.IntegrityTag, v2PublicationIntegrityKey);
            bytes = checked(bytes + ProductionMailboxRouteHistoryCatalogLimits
                .ManifestRowBytes(value.Payload.Length, value.IntegrityTag.Length));
        }
        if (routeRows + additionalRows > ownerControlLimits.MaximumEntriesPerRoute ||
            globalRows + additionalRows > ownerControlLimits.MaximumEntriesGlobal ||
            checked(bytes + additionalBytes) > ownerControlLimits.MaximumStateBytes)
            throw new InvalidDataException("Route-history catalog capacity is exhausted.");
    }

    internal static void ValidateHistoryHeadAgainstRouteState(
        ProductionMailboxRouteContinuityStateSnapshot current,
        ProductionMailboxRestoredGenesis genesis,
        ProductionMailboxRouteHistoryBatchCommitPlan? headPlan,
        ProductionMailboxRouteHistoryStateSnapshot head)
    {
        if (current.History is null || !current.History.Exact(head))
            throw new InvalidDataException("Route-history head differs from durable route state.");
        if (headPlan is null)
        {
            var f = genesis.Value.Fields;
            if (!Fixed(current.CanonicalRouteOriginLkg.Span, f[16]) ||
                !Fixed(current.RouteOriginLkgHash.Span, f[17]) ||
                !Fixed(current.CanonicalRouteCertificate.Span, f[8]) ||
                !Fixed(current.CanonicalRouteAuthorization.Span, f[10]))
                throw new InvalidDataException("Genesis route state differs from its catalog.");
            return;
        }
        var durable = headPlan.NextDurableRouteState;
        var artifacts = headPlan.FinalArtifacts;
        var authorization = durable.AuthorizationKind ==
            ProductionMailboxRouteAuthorizationKind.OwnerPRA2
            ? artifacts.CanonicalOwnerAdvertisement : artifacts.CanonicalContinuityActivation;
        if (!Fixed(current.CanonicalRouteOriginLkg.Span, durable.CanonicalRouteOriginLkg.Span) ||
            !Fixed(current.RouteOriginLkgHash.Span, durable.CanonicalRouteOriginLkgHash.Span) ||
            current.LocalCommitGeneration != durable.LocalCommitGeneration ||
            current.CurrentAuthorizationKind != durable.AuthorizationKind ||
            !Fixed(current.CurrentAuthorizationHash.Span,
                durable.CanonicalAuthorizationHash.Span) ||
            current.CurrentAuthorizationSequence != durable.AuthorizationSequence ||
            !Fixed(current.CanonicalRouteCertificate.Span,
                artifacts.CanonicalRouteCertificate.Span) ||
            !Fixed(current.CanonicalRouteAuthorization.Span, authorization.Span) ||
            !Fixed(current.CanonicalRevocationCheckpoint.Span,
                artifacts.CanonicalRevocationCheckpoint.Span) ||
            !Fixed(current.CanonicalTransitionContext.Span,
                artifacts.CanonicalTransitionContext.Span))
            throw new InvalidDataException("Current route authorization is split from history.");
    }
}

public sealed partial class PostgreSqlProductionMailboxStateStore
{
    private readonly SemaphoreSlim routeHistoryInitializeGate = new(1, 1);
    private volatile bool routeHistoryInitialized;

    async ValueTask<ProductionMailboxRouteHistoryLookupResult>
        IProductionMailboxRouteContinuityStateStore.LookupRouteHistoryAsync(
        ReadOnlyMemory<byte> routeStateKey,
        ProductionMailboxRouteHistoryLookupRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var route = ProductionMailboxRouteContinuityStateGuard.FreezeKey(routeStateKey);
        await using var connection = await OpenAsync(cancellationToken);
        await EnsureRouteContinuitySchemaAsync(connection, cancellationToken);
        await EnsureOwnerControlSchemaAsync(connection, cancellationToken);
        await EnsureRouteHistorySchemaAsync(connection, cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(
            IsolationLevel.ReadCommitted, cancellationToken);
        await ConfigureOwnerControlTransactionAsync(connection, transaction, cancellationToken);
        await AdvisoryLockAsync(connection, transaction, route, cancellationToken);
        if (await HasRouteHistoryTombstoneAsync(connection, transaction, route,
                cancellationToken))
        {
            await transaction.CommitAsync(cancellationToken);
            return new(ProductionMailboxRouteHistoryLookupStatus.Terminal, null);
        }
        var current = await ReadRouteContinuityAsync(connection, transaction, route, true,
            cancellationToken);
        if (current is null)
        {
            await transaction.CommitAsync(cancellationToken);
            return new(ProductionMailboxRouteHistoryLookupStatus.MissingState, null);
        }
        var result = await ReadHistoryLookupAsync(connection, transaction, route, current,
            request, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return result;
    }
    internal ProductionMailboxRouteHistoryCommitFaultPoint RouteHistoryCommitFaultPoint
    { get; set; }
    internal bool ThrowAfterRouteTombstoneInsertOnce { get; set; }

    private void ThrowRouteHistoryCommitFault(
        ProductionMailboxRouteHistoryCommitFaultPoint point)
    {
        if (RouteHistoryCommitFaultPoint != point) return;
        RouteHistoryCommitFaultPoint = ProductionMailboxRouteHistoryCommitFaultPoint.None;
        throw new IOException($"Injected route-history commit fault after {point}.");
    }

    internal async ValueTask<bool> TryCollectTerminalRouteAsync(
        ReadOnlyMemory<byte> routeStateKey, CancellationToken cancellationToken)
    {
        var route = ProductionMailboxRouteContinuityStateGuard.FreezeKey(routeStateKey);
        await using var connection = await OpenAsync(cancellationToken);
        await EnsureRouteContinuitySchemaAsync(connection, cancellationToken);
        await EnsureOwnerControlSchemaAsync(connection, cancellationToken);
        await EnsureRouteHistorySchemaAsync(connection, cancellationToken);
        await EnsureV2PublicationSchemaAsync(connection, cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(
            IsolationLevel.ReadCommitted, cancellationToken);
        await ConfigureOwnerControlTransactionAsync(connection, transaction, cancellationToken);
        await AdvisoryLockAsync(connection, transaction, route, cancellationToken);
        var dbNow = await OwnerDbNowAsync(connection, transaction, cancellationToken);
        if (await HasRouteHistoryTombstoneAsync(connection, transaction, route,
                cancellationToken))
        {
            await transaction.CommitAsync(cancellationToken);
            return true;
        }
        var current = await ReadRouteContinuityRowAsync(connection, transaction, route, true,
            cancellationToken);
        if (current is null)
        {
            await transaction.CommitAsync(cancellationToken);
            return false;
        }
        ValidateStoredState(current);
        var restored = await ReadHistoryCatalogAsync(connection, transaction, route, current,
            cancellationToken);
        if (current.OwnerRevocationGeneration == 0 ||
            current.CanonicalOwnerRevocation.Length !=
                ProductionMailboxRouteContinuityConstants.CanonicalRevocationLength ||
            !CryptographicOperations.FixedTimeEquals(
                SHA256.HashData(current.CanonicalOwnerRevocation.Span),
                current.CanonicalOwnerRevocationHash.Span))
        {
            await transaction.CommitAsync(cancellationToken);
            return false;
        }
        var enrollment = await ReadCompletedOwnerEnrollmentAsync(connection, transaction,
            route, cancellationToken);
        if (enrollment is null)
        {
            await transaction.CommitAsync(cancellationToken);
            return false;
        }
        VerifyOwnerEnrollment(enrollment);
        var genesisProtected = await ReadGenesisCatalogAsync(connection, transaction, route,
            v2PreparedIntegrityKey, cancellationToken) ?? throw new InvalidDataException(
                "Terminal route genesis catalog is missing.");
        var genesis = genesisProtected.RestoreProtocol();
        var delegation = genesis.Enrollment.Delegation;
        var ocr = ProductionMailboxOwnerControlTransportCodec.DecodeResponderCertificate(
            genesis.EnrollmentContext.CanonicalOwnerControlResponderCertificate.Span);
        var horizon = Math.Min(delegation.ExpiresAtUnixSeconds, ocr.ExpiresAtUnixSeconds);
        if (dbNow < horizon)
        {
            await transaction.CommitAsync(cancellationToken);
            return false;
        }
        await AuthenticatedOwnerControlGcAsync(connection, transaction, dbNow,
            cancellationToken);
        if (await HasTerminalRouteLiveReferencesAsync(connection, transaction, route,
                cancellationToken))
        {
            await transaction.CommitAsync(cancellationToken);
            return false;
        }
        var tombstone = ProductionMailboxProtectedRouteTombstone.Freeze(route,
            genesis.Value.PlanHash, restored.Manifest,
            current.CanonicalOwnerRevocationHash.Span,
            current.CanonicalDelegationHash.Span, horizon, dbNow,
            v2PreparedIntegrityKey);
        await InsertRouteHistoryTombstoneAsync(connection, transaction, route, tombstone,
            cancellationToken);
        if (ThrowAfterRouteTombstoneInsertOnce)
        {
            ThrowAfterRouteTombstoneInsertOnce = false;
            throw new IOException("Injected terminal route collection fault.");
        }
        await DeleteCollectedTerminalRouteAsync(connection, transaction, route,
            enrollment.OperationHash, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return true;
    }

    private async ValueTask<bool> HasRouteHistoryTombstoneAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction,
        ReadOnlyMemory<byte> routeStateKey, CancellationToken cancellationToken)
    {
        const string sql = """
            SELECT CASE WHEN octet_length(protected_payload)=232 THEN protected_payload END,
                   CASE WHEN octet_length(integrity_tag)=32 THEN integrity_tag END
            FROM production_mailbox_route_history_tombstone_v1
            WHERE route_state_key=@route FOR UPDATE
            """;
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue("route", routeStateKey.ToArray());
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken)) return false;
        if (reader.IsDBNull(0) || reader.IsDBNull(1))
            throw new InvalidDataException("Stored route-history tombstone bounds are invalid.");
        var tombstone = ProductionMailboxProtectedRouteTombstone.Restore(
            reader.GetFieldValue<byte[]>(0), reader.GetFieldValue<byte[]>(1),
            v2PreparedIntegrityKey);
        if (!ProductionMailboxProtectedHistoryManifest.Fixed(routeStateKey.Span,
                tombstone.RouteStateKey.Span))
            throw new InvalidDataException("Stored route-history tombstone key is split.");
        return true;
    }

    private static async ValueTask InsertRouteHistoryTombstoneAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction,
        ReadOnlyMemory<byte> routeStateKey,
        ProductionMailboxProtectedRouteTombstone tombstone,
        CancellationToken cancellationToken)
    {
        const string sql = """
            INSERT INTO production_mailbox_route_history_tombstone_v1(
                route_state_key,protected_payload,integrity_tag)
            VALUES(@route,@payload,@tag)
            """;
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue("route", routeStateKey.ToArray());
        command.Parameters.AddWithValue("payload", tombstone.Payload.ToArray());
        command.Parameters.AddWithValue("tag", tombstone.IntegrityTag.ToArray());
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async ValueTask<bool> HasTerminalRouteLiveReferencesAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction,
        ReadOnlyMemory<byte> routeStateKey, CancellationToken cancellationToken)
    {
        const string sql = """
            SELECT EXISTS(
                SELECT 1 FROM production_mailbox_owner_requests_v1 WHERE route_state_key=@route
                UNION ALL SELECT 1 FROM production_mailbox_owner_request_ids_v1
                    WHERE route_state_key=@route
                UNION ALL SELECT 1 FROM production_mailbox_owner_revocation_ids_v1
                    WHERE route_state_key=@route
                UNION ALL SELECT 1 FROM production_mailbox_owner_enrollment_ids_v1
                    WHERE route_state_key=@route
                UNION ALL SELECT 1 FROM production_mailbox_v2_activations
                    WHERE route_state_key=@route
                UNION ALL SELECT 1 FROM production_mailbox_owner_route_state
                    WHERE route_state_key=@route)
            """;
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue("route", routeStateKey.ToArray());
        return (bool)(await command.ExecuteScalarAsync(cancellationToken)
            ?? throw new InvalidDataException("Terminal route live-reference query failed."));
    }

    private static async ValueTask DeleteCollectedTerminalRouteAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction,
        ReadOnlyMemory<byte> routeStateKey, ReadOnlyMemory<byte> enrollmentOperationHash,
        CancellationToken cancellationToken)
    {
        const string sql = """
            DELETE FROM production_mailbox_owner_enrollment_ids_v1
                WHERE route_state_key=@route;
            DELETE FROM production_mailbox_owner_revocation_ids_v1
                WHERE route_state_key=@route;
            DELETE FROM production_mailbox_owner_enrollment_ops_v1
                WHERE route_state_key=@route AND operation_hash=@operation
                    AND canonical_response IS NOT NULL;
            DELETE FROM production_mailbox_route_continuity_v2 WHERE route_state_key=@route;
            DELETE FROM production_mailbox_route_genesis_v1 WHERE route_state_key=@route;
            DELETE FROM production_mailbox_route_history_manifest_v1 WHERE route_state_key=@route;
            """;
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue("route", routeStateKey.ToArray());
        command.Parameters.AddWithValue("operation", enrollmentOperationHash.ToArray());
        var affected = await command.ExecuteNonQueryAsync(cancellationToken);
        if (affected < 4)
            throw new InvalidDataException("Terminal route collection closure is incomplete.");
    }

    private async ValueTask EnsureRouteHistorySchemaAsync(
        NpgsqlConnection connection, CancellationToken cancellationToken)
    {
        if (routeHistoryInitialized) return;
        await routeHistoryInitializeGate.WaitAsync(cancellationToken);
        try
        {
            if (routeHistoryInitialized) return;
            const string sql = """
                CREATE TABLE IF NOT EXISTS production_mailbox_route_history_manifest_v1(
                    route_state_key bytea PRIMARY KEY CHECK(octet_length(route_state_key)=32),
                    protected_payload bytea NOT NULL CHECK(octet_length(protected_payload)=216),
                    integrity_tag bytea NOT NULL CHECK(octet_length(integrity_tag)=32)
                );
                CREATE TABLE IF NOT EXISTS production_mailbox_route_history_batch_v1(
                    route_state_key bytea NOT NULL CHECK(octet_length(route_state_key)=32),
                    batch_sequence bytea NOT NULL CHECK(octet_length(batch_sequence)=8),
                    protected_payload bytea NOT NULL CHECK(octet_length(protected_payload)
                        BETWEEN 180 AND 8394420),
                    integrity_tag bytea NOT NULL CHECK(octet_length(integrity_tag)=32),
                    PRIMARY KEY(route_state_key,batch_sequence),
                    FOREIGN KEY(route_state_key) REFERENCES
                        production_mailbox_route_history_manifest_v1(route_state_key)
                        ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS production_mailbox_route_history_checkpoint_v1(
                    route_state_key bytea NOT NULL CHECK(octet_length(route_state_key)=32),
                    batch_sequence bytea NOT NULL CHECK(octet_length(batch_sequence)=8),
                    protected_payload bytea NOT NULL CHECK(octet_length(protected_payload)=908),
                    integrity_tag bytea NOT NULL CHECK(octet_length(integrity_tag)=32),
                    PRIMARY KEY(route_state_key,batch_sequence),
                    FOREIGN KEY(route_state_key) REFERENCES
                        production_mailbox_route_history_manifest_v1(route_state_key)
                        ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS production_mailbox_route_history_tombstone_v1(
                    route_state_key bytea PRIMARY KEY CHECK(octet_length(route_state_key)=32),
                    protected_payload bytea NOT NULL CHECK(octet_length(protected_payload)=232),
                    integrity_tag bytea NOT NULL CHECK(octet_length(integrity_tag)=32)
                );
                """;
            await using var command = new NpgsqlCommand(sql, connection);
            await command.ExecuteNonQueryAsync(cancellationToken);
            routeHistoryInitialized = true;
        }
        finally { routeHistoryInitializeGate.Release(); }
    }

    private async ValueTask<ProductionMailboxRestoredHistoryCatalog> ReadHistoryCatalogAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction,
        ReadOnlyMemory<byte> routeStateKey,
        ProductionMailboxRouteContinuityStateSnapshot current,
        CancellationToken cancellationToken)
    {
        var genesis = await ReadGenesisCatalogAsync(connection, transaction, routeStateKey,
            v2PreparedIntegrityKey, cancellationToken) ?? throw new InvalidDataException(
                "Route-history genesis catalog is missing.");
        var manifest = await ReadHistoryManifestAsync(connection, transaction, routeStateKey,
            cancellationToken) ?? throw new InvalidDataException(
                "Route-history manifest is missing.");
        var batches = await ReadHistoryBatchesAsync(connection, transaction, routeStateKey,
            cancellationToken);
        var checkpoints = await ReadHistoryCheckpointsAsync(connection, transaction,
            routeStateKey, cancellationToken);
        return ProductionMailboxRouteHistoryCatalogVerifier.Restore(routeStateKey.Span,
            current, genesis, manifest, batches, checkpoints, v2PreparedIntegrityKey);
    }

    private async ValueTask<ProductionMailboxRouteHistoryLookupResult> ReadHistoryLookupAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction,
        ReadOnlyMemory<byte> routeStateKey,
        ProductionMailboxRouteContinuityStateSnapshot current,
        ProductionMailboxRouteHistoryLookupRequest request,
        CancellationToken cancellationToken)
    {
        var genesis = await ReadGenesisCatalogAsync(connection, transaction, routeStateKey,
            v2PreparedIntegrityKey, cancellationToken) ?? throw new InvalidDataException(
                "Route-history genesis catalog is missing.");
        var manifest = await ReadHistoryManifestAsync(connection, transaction, routeStateKey,
            cancellationToken) ?? throw new InvalidDataException(
                "Route-history manifest is missing.");
        var batches = await ReadHistoryBatchesAsync(connection, transaction, routeStateKey,
            cancellationToken);
        var checkpoints = await ReadHistoryCheckpointsAsync(connection, transaction,
            routeStateKey, cancellationToken);
        return ProductionMailboxRouteHistoryCatalogVerifier.Lookup(routeStateKey.Span,
            current, genesis, manifest, batches, checkpoints, v2PreparedIntegrityKey, request);
    }

    private async ValueTask<ProductionMailboxProtectedHistoryManifest?> ReadHistoryManifestAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction,
        ReadOnlyMemory<byte> routeStateKey, CancellationToken cancellationToken)
    {
        const string sql = """
            SELECT CASE WHEN octet_length(protected_payload)=216 THEN protected_payload END,
                   CASE WHEN octet_length(integrity_tag)=32 THEN integrity_tag END
            FROM production_mailbox_route_history_manifest_v1
            WHERE route_state_key=@route FOR UPDATE
            """;
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue("route", routeStateKey.ToArray());
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken)) return null;
        if (reader.IsDBNull(0) || reader.IsDBNull(1))
            throw new InvalidDataException("Stored route-history manifest bounds are invalid.");
        return ProductionMailboxProtectedHistoryManifest.Restore(
            reader.GetFieldValue<byte[]>(0), reader.GetFieldValue<byte[]>(1),
            v2PreparedIntegrityKey);
    }

    private async ValueTask<SortedDictionary<ulong, ProductionMailboxProtectedHistoryBatch>>
        ReadHistoryBatchesAsync(NpgsqlConnection connection, NpgsqlTransaction transaction,
            ReadOnlyMemory<byte> routeStateKey, CancellationToken cancellationToken)
    {
        const string sql = """
            SELECT CASE WHEN octet_length(batch_sequence)=8 THEN batch_sequence END,
                   CASE WHEN octet_length(protected_payload) BETWEEN 180 AND 8394420
                        THEN protected_payload END,
                   CASE WHEN octet_length(integrity_tag)=32 THEN integrity_tag END
            FROM production_mailbox_route_history_batch_v1
            WHERE route_state_key=@route ORDER BY batch_sequence LIMIT 33 FOR UPDATE
            """;
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue("route", routeStateKey.ToArray());
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var result = new SortedDictionary<ulong, ProductionMailboxProtectedHistoryBatch>();
        while (await reader.ReadAsync(cancellationToken))
        {
            if (reader.IsDBNull(0) || reader.IsDBNull(1) || reader.IsDBNull(2))
                throw new InvalidDataException("Stored route-history batch bounds are invalid.");
            var sequence = ReadU64(reader.GetFieldValue<byte[]>(0));
            if (!result.TryAdd(sequence, ProductionMailboxProtectedHistoryBatch.Restore(
                    reader.GetFieldValue<byte[]>(1), reader.GetFieldValue<byte[]>(2),
                    v2PreparedIntegrityKey)))
                throw new InvalidDataException("Stored route-history batch sequence forks.");
        }
        if ((ulong)result.Count > ProductionMailboxRouteHistoryCatalogLimits.MaximumBatches)
            throw new InvalidDataException("Stored route-history batch count exceeds its cap.");
        return result;
    }

    private async ValueTask<SortedDictionary<ulong, ProductionMailboxProtectedHistoryCheckpoint>>
        ReadHistoryCheckpointsAsync(NpgsqlConnection connection, NpgsqlTransaction transaction,
            ReadOnlyMemory<byte> routeStateKey, CancellationToken cancellationToken)
    {
        const string sql = """
            SELECT CASE WHEN octet_length(batch_sequence)=8 THEN batch_sequence END,
                   CASE WHEN octet_length(protected_payload)=908 THEN protected_payload END,
                   CASE WHEN octet_length(integrity_tag)=32 THEN integrity_tag END
            FROM production_mailbox_route_history_checkpoint_v1
            WHERE route_state_key=@route ORDER BY batch_sequence LIMIT 34 FOR UPDATE
            """;
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue("route", routeStateKey.ToArray());
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var result = new SortedDictionary<ulong, ProductionMailboxProtectedHistoryCheckpoint>();
        while (await reader.ReadAsync(cancellationToken))
        {
            if (reader.IsDBNull(0) || reader.IsDBNull(1) || reader.IsDBNull(2))
                throw new InvalidDataException(
                    "Stored route-history checkpoint bounds are invalid.");
            var sequence = ReadU64(reader.GetFieldValue<byte[]>(0));
            if (!result.TryAdd(sequence, ProductionMailboxProtectedHistoryCheckpoint.Restore(
                    reader.GetFieldValue<byte[]>(1), reader.GetFieldValue<byte[]>(2),
                    v2PreparedIntegrityKey)))
                throw new InvalidDataException("Stored route-history checkpoint sequence forks.");
        }
        if (result.Count > checked((int)
                ProductionMailboxRouteHistoryCatalogLimits.MaximumBatches + 1))
            throw new InvalidDataException("Stored route-history checkpoint count exceeds its cap.");
        return result;
    }

    private async ValueTask InsertHistoryGenesisAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, ReadOnlyMemory<byte> routeStateKey,
        ProductionMailboxProtectedGenesisCatalog genesis,
        ProductionMailboxRouteHistoryStateSnapshot initial,
        CancellationToken cancellationToken)
    {
        var manifest = ProductionMailboxProtectedHistoryManifest.CreateGenesis(
            routeStateKey.Span, genesis.PlanHash.Span, initial, v2PreparedIntegrityKey);
        var checkpoint = ProductionMailboxProtectedHistoryCheckpoint.Freeze(
            routeStateKey.Span, initial, v2PreparedIntegrityKey);
        await EnsureHistoryCapacityAsync(connection, transaction, routeStateKey,
            ProductionMailboxRouteHistoryCatalogLimits.ManifestRowBytes(
                manifest.Payload.Length, manifest.IntegrityTag.Length) +
            ProductionMailboxRouteHistoryCatalogLimits.SequencedRowBytes(
                checkpoint.Payload.Length, checkpoint.IntegrityTag.Length), 2,
            cancellationToken);
        const string manifestSql = """
            INSERT INTO production_mailbox_route_history_manifest_v1(
                route_state_key,protected_payload,integrity_tag)
            VALUES(@route,@payload,@tag)
            """;
        await using (var command = new NpgsqlCommand(manifestSql, connection, transaction))
        {
            command.Parameters.AddWithValue("route", routeStateKey.ToArray());
            command.Parameters.AddWithValue("payload", manifest.Payload.ToArray());
            command.Parameters.AddWithValue("tag", manifest.IntegrityTag.ToArray());
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
        await InsertHistoryCheckpointAsync(connection, transaction, routeStateKey,
            checkpoint, cancellationToken);
    }

    private async ValueTask AppendHistoryCatalogAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, ReadOnlyMemory<byte> routeStateKey,
        ProductionMailboxRestoredHistoryCatalog restored,
        ProductionMailboxFrozenHistoryBatch batch, CancellationToken cancellationToken)
    {
        var protectedBatch = ProductionMailboxProtectedHistoryBatch.Freeze(
            routeStateKey.Span, batch, v2PreparedIntegrityKey);
        var checkpoint = ProductionMailboxProtectedHistoryCheckpoint.Freeze(
            routeStateKey.Span, batch.Next, v2PreparedIntegrityKey);
        var manifest = restored.Manifest.Advance(batch, v2PreparedIntegrityKey);
        await EnsureHistoryCapacityAsync(connection, transaction, routeStateKey,
            ProductionMailboxRouteHistoryCatalogLimits.SequencedRowBytes(
                protectedBatch.Payload.Length, protectedBatch.IntegrityTag.Length) +
            ProductionMailboxRouteHistoryCatalogLimits.SequencedRowBytes(
                checkpoint.Payload.Length, checkpoint.IntegrityTag.Length), 2,
            cancellationToken);
        const string batchSql = """
            INSERT INTO production_mailbox_route_history_batch_v1(
                route_state_key,batch_sequence,protected_payload,integrity_tag)
            VALUES(@route,@sequence,@payload,@tag)
            """;
        await using (var command = new NpgsqlCommand(batchSql, connection, transaction))
        {
            command.Parameters.AddWithValue("route", routeStateKey.ToArray());
            command.Parameters.AddWithValue("sequence", U64(batch.Next.LastCommittedBatchSequence));
            command.Parameters.AddWithValue("payload", protectedBatch.Payload.ToArray());
            command.Parameters.AddWithValue("tag", protectedBatch.IntegrityTag.ToArray());
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
        ThrowRouteHistoryCommitFault(ProductionMailboxRouteHistoryCommitFaultPoint.AfterBatch);
        await InsertHistoryCheckpointAsync(connection, transaction, routeStateKey, checkpoint,
            cancellationToken);
        ThrowRouteHistoryCommitFault(
            ProductionMailboxRouteHistoryCommitFaultPoint.AfterCheckpoint);
        const string manifestSql = """
            UPDATE production_mailbox_route_history_manifest_v1
            SET protected_payload=@payload,integrity_tag=@tag
            WHERE route_state_key=@route
            """;
        await using var update = new NpgsqlCommand(manifestSql, connection, transaction);
        update.Parameters.AddWithValue("route", routeStateKey.ToArray());
        update.Parameters.AddWithValue("payload", manifest.Payload.ToArray());
        update.Parameters.AddWithValue("tag", manifest.IntegrityTag.ToArray());
        if (await update.ExecuteNonQueryAsync(cancellationToken) != 1)
            throw new InvalidDataException("Route-history manifest CAS row disappeared.");
        ThrowRouteHistoryCommitFault(ProductionMailboxRouteHistoryCommitFaultPoint.AfterManifest);
    }

    private static async ValueTask InsertHistoryCheckpointAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction,
        ReadOnlyMemory<byte> routeStateKey,
        ProductionMailboxProtectedHistoryCheckpoint checkpoint,
        CancellationToken cancellationToken)
    {
        const string sql = """
            INSERT INTO production_mailbox_route_history_checkpoint_v1(
                route_state_key,batch_sequence,protected_payload,integrity_tag)
            VALUES(@route,@sequence,@payload,@tag)
            """;
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue("route", routeStateKey.ToArray());
        command.Parameters.AddWithValue("sequence", U64(checkpoint.Sequence));
        command.Parameters.AddWithValue("payload", checkpoint.Payload.ToArray());
        command.Parameters.AddWithValue("tag", checkpoint.IntegrityTag.ToArray());
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private async ValueTask EnsureHistoryCapacityAsync(NpgsqlConnection connection,
        NpgsqlTransaction transaction, ReadOnlyMemory<byte> routeStateKey,
        long additionalBytes, int additionalRows, CancellationToken cancellationToken)
    {
        if (additionalBytes < 0 || additionalRows < 0)
            throw new InvalidDataException("Route-history prospective accounting is invalid.");
        await AdvisoryLockAsync(connection, transaction,
            SHA256.HashData("Deep/registry/production-mailbox/route-history-capacity/v1"u8),
            cancellationToken);
        const string sql = """
            SELECT kind,route_state_key,payload,tag FROM (
                SELECT 1::smallint AS kind,
                    CASE WHEN octet_length(route_state_key)=32 THEN route_state_key END
                        AS route_state_key,
                    CASE WHEN octet_length(protected_payload)=216 THEN protected_payload END AS payload,
                    CASE WHEN octet_length(integrity_tag)=32 THEN integrity_tag END AS tag
                FROM production_mailbox_route_history_manifest_v1
                UNION ALL
                SELECT 2::smallint,
                    CASE WHEN octet_length(route_state_key)=32 THEN route_state_key END,
                    CASE WHEN octet_length(protected_payload) BETWEEN 180 AND 8394420
                         THEN protected_payload END,
                    CASE WHEN octet_length(integrity_tag)=32 THEN integrity_tag END
                FROM production_mailbox_route_history_batch_v1
                UNION ALL
                SELECT 3::smallint,
                    CASE WHEN octet_length(route_state_key)=32 THEN route_state_key END,
                    CASE WHEN octet_length(protected_payload)=908 THEN protected_payload END,
                    CASE WHEN octet_length(integrity_tag)=32 THEN integrity_tag END
                FROM production_mailbox_route_history_checkpoint_v1
                UNION ALL
                SELECT 4::smallint,
                    CASE WHEN octet_length(route_state_key)=32 THEN route_state_key END,
                    CASE WHEN octet_length(protected_payload)=232 THEN protected_payload END,
                    CASE WHEN octet_length(integrity_tag)=32 THEN integrity_tag END
                FROM production_mailbox_route_history_tombstone_v1
            ) rows LIMIT @limit
            """;
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue("limit", checked(ownerControlLimits.MaximumEntriesGlobal + 1));
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        long rows = 0, routeRows = 0, bytes = 0;
        while (await reader.ReadAsync(cancellationToken))
        {
            rows++;
            if (reader.IsDBNull(1) || reader.IsDBNull(2) || reader.IsDBNull(3))
                throw new InvalidDataException("Stored route-history capacity row is invalid.");
            var rowRoute = reader.GetFieldValue<byte[]>(1);
            var payload = reader.GetFieldValue<byte[]>(2);
            var tag = reader.GetFieldValue<byte[]>(3);
            switch (reader.GetInt16(0))
            {
                case 1:
                    _ = ProductionMailboxProtectedHistoryManifest.Restore(payload, tag,
                        v2PreparedIntegrityKey);
                    break;
                case 2:
                    _ = ProductionMailboxProtectedHistoryBatch.Restore(payload, tag,
                        v2PreparedIntegrityKey);
                    break;
                case 3:
                    _ = ProductionMailboxProtectedHistoryCheckpoint.Restore(payload, tag,
                        v2PreparedIntegrityKey);
                    break;
                case 4:
                    _ = ProductionMailboxProtectedRouteTombstone.Restore(payload, tag,
                        v2PreparedIntegrityKey);
                    break;
                default:
                    throw new InvalidDataException("Stored route-history capacity kind is invalid.");
            }
            if (ProductionMailboxProtectedHistoryManifest.Fixed(rowRoute, routeStateKey.Span))
                routeRows++;
            bytes = checked(bytes + (reader.GetInt16(0) == 1
                ? ProductionMailboxRouteHistoryCatalogLimits.ManifestRowBytes(
                    payload.Length, tag.Length)
                : ProductionMailboxRouteHistoryCatalogLimits.SequencedRowBytes(
                    payload.Length, tag.Length)));
            if (rows > ownerControlLimits.MaximumEntriesGlobal ||
                bytes > ownerControlLimits.MaximumStateBytes)
                throw new InvalidDataException("Route-history catalog capacity is exhausted.");
        }
        if (routeRows + additionalRows > ownerControlLimits.MaximumEntriesPerRoute ||
            rows + additionalRows > ownerControlLimits.MaximumEntriesGlobal ||
            checked(bytes + additionalBytes) > ownerControlLimits.MaximumStateBytes)
            throw new InvalidDataException("Route-history catalog capacity is exhausted.");
    }
}
