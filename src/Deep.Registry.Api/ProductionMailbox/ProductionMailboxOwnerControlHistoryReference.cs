using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxTopology;

namespace Deep.Registry.Api.ProductionMailbox;

internal sealed class ProductionMailboxProtectedHistoryResponseReference
{
    internal const int CanonicalLength = 160;
    internal const int IntegrityTagLength = 32;
    internal const int MinimumPayloadLength =
        ProductionMailboxFrozenHistoryBatch.MinimumBatchBytes +
        ProductionMailboxRouteContinuityConstants.CanonicalRouteHistoryCheckpointLength;
    internal const int MaximumPayloadLength =
        ProductionMailboxFrozenHistoryBatch.MaximumBatchBytes +
        ProductionMailboxRouteContinuityConstants.CanonicalRouteHistoryCheckpointLength;

    private static ReadOnlySpan<byte> Magic => "PMHP"u8;
    private static ReadOnlySpan<byte> IntegrityDomain =>
        "Deep/registry/production-mailbox/owner-control/history-response-reference/v1"u8;

    private readonly byte[] canonical;
    private readonly byte[] integrityTag;

    private ProductionMailboxProtectedHistoryResponseReference(
        ReadOnlySpan<byte> canonical,
        ReadOnlySpan<byte> integrityTag)
    {
        this.canonical = canonical.ToArray();
        this.integrityTag = integrityTag.ToArray();
    }

    internal ReadOnlyMemory<byte> CanonicalBytes => canonical.ToArray();
    internal ReadOnlyMemory<byte> IntegrityTag => integrityTag.ToArray();
    internal ulong CurrentBatchSequence =>
        BinaryPrimitives.ReadUInt64BigEndian(canonical.AsSpan(8, 8));
    internal ulong NextBatchSequence =>
        BinaryPrimitives.ReadUInt64BigEndian(canonical.AsSpan(16, 8));
    internal uint PayloadLength =>
        BinaryPrimitives.ReadUInt32BigEndian(canonical.AsSpan(24, 4));
    internal ReadOnlyMemory<byte> PayloadSha256 => canonical.AsSpan(32, 32).ToArray();
    internal ReadOnlyMemory<byte> CanonicalBatchHash => canonical.AsSpan(64, 32).ToArray();
    internal ReadOnlyMemory<byte> CanonicalNextCheckpointHash =>
        canonical.AsSpan(96, 32).ToArray();
    internal ReadOnlyMemory<byte> BatchCommitPlanHash => canonical.AsSpan(128, 32).ToArray();

    internal static ProductionMailboxProtectedHistoryResponseReference Create(
        ReadOnlySpan<byte> routeStateKey,
        ReadOnlySpan<byte> currentCheckpointHash,
        ProductionMailboxRouteHistoryLookup lookup,
        ReadOnlySpan<byte> integrityKey)
    {
        ArgumentNullException.ThrowIfNull(lookup);
        ValidateContext(routeStateKey, currentCheckpointHash, integrityKey);
        if (lookup.Status != ProductionMailboxRouteHistoryLookupStatus.History ||
            lookup.NextPlan is null)
            throw new InvalidDataException("History response reference requires an immutable successor.");
        if (!Fixed(currentCheckpointHash, lookup.Cursor.CanonicalCheckpointHash.Span))
            throw new InvalidDataException("History response reference current checkpoint is split.");

        var plan = lookup.NextPlan;
        var currentSequence = lookup.Cursor.LastCommittedBatchSequence;
        var nextSequence = plan.NextCursor.LastCommittedBatchSequence;
        var batch = lookup.CanonicalNextBatch.ToArray();
        var checkpoint = lookup.CanonicalNextCheckpoint.ToArray();
        try
        {
            if (currentSequence >= ProductionMailboxRouteHistoryCatalogLimits.MaximumBatches ||
                nextSequence != checked(currentSequence + 1) ||
                batch.Length is < ProductionMailboxFrozenHistoryBatch.MinimumBatchBytes or
                    > ProductionMailboxFrozenHistoryBatch.MaximumBatchBytes ||
                checkpoint.Length != ProductionMailboxRouteContinuityConstants
                    .CanonicalRouteHistoryCheckpointLength)
                throw new InvalidDataException("History response reference sequence or payload is invalid.");
            var payloadLength = checked(batch.Length + checkpoint.Length);
            if (payloadLength is < MinimumPayloadLength or > MaximumPayloadLength ||
                payloadLength > ProductionMailboxOwnerControlConstants.MaximumHistoryFrameBytes)
                throw new InvalidDataException("History response reference payload length is invalid.");

            Span<byte> encoded = stackalloc byte[CanonicalLength];
            Magic.CopyTo(encoded);
            encoded[4] = 1;
            encoded[5] = (byte)ProductionMailboxOwnerControlResponseKind.History;
            BinaryPrimitives.WriteUInt64BigEndian(encoded[8..16], currentSequence);
            BinaryPrimitives.WriteUInt64BigEndian(encoded[16..24], nextSequence);
            BinaryPrimitives.WriteUInt32BigEndian(encoded[24..28], checked((uint)payloadLength));
            using (var payloadHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
            {
                payloadHash.AppendData(batch);
                payloadHash.AppendData(checkpoint);
                payloadHash.GetHashAndReset(encoded[32..64]);
            }
            CopyHash(plan.CanonicalBatchHash.Span, encoded[64..96], "batch hash");
            CopyHash(plan.NextCursor.CanonicalCheckpointHash.Span, encoded[96..128],
                "checkpoint hash");
            CopyHash(plan.PlanHash.Span, encoded[128..160], "plan hash");
            ValidateCanonical(encoded);
            var tag = ComputeTag(routeStateKey, currentCheckpointHash, encoded, integrityKey);
            return new ProductionMailboxProtectedHistoryResponseReference(encoded, tag);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(batch);
            CryptographicOperations.ZeroMemory(checkpoint);
        }
    }

    internal static ProductionMailboxProtectedHistoryResponseReference Restore(
        ReadOnlySpan<byte> routeStateKey,
        ReadOnlySpan<byte> currentCheckpointHash,
        ReadOnlySpan<byte> canonical,
        ReadOnlySpan<byte> integrityTag,
        ReadOnlySpan<byte> integrityKey)
    {
        ValidateContext(routeStateKey, currentCheckpointHash, integrityKey);
        if (canonical.Length != CanonicalLength || integrityTag.Length != IntegrityTagLength)
            throw new InvalidDataException("Stored history response reference length is invalid.");
        var owned = canonical.ToArray();
        var ownedTag = integrityTag.ToArray();
        var expected = ComputeTag(routeStateKey, currentCheckpointHash, owned, integrityKey);
        try
        {
            if (!Fixed(expected, ownedTag))
                throw new InvalidDataException("Stored history response reference HMAC is invalid.");
            ValidateCanonical(owned);
            return new ProductionMailboxProtectedHistoryResponseReference(owned, ownedTag);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expected);
            CryptographicOperations.ZeroMemory(owned);
            CryptographicOperations.ZeroMemory(ownedTag);
        }
    }

    internal bool Exact(ProductionMailboxProtectedHistoryResponseReference other)
    {
        ArgumentNullException.ThrowIfNull(other);
        return Fixed(canonical, other.canonical) && Fixed(integrityTag, other.integrityTag);
    }

    private static void ValidateCanonical(ReadOnlySpan<byte> value)
    {
        if (value.Length != CanonicalLength || !value[..4].SequenceEqual(Magic) ||
            value[4] != 1 ||
            value[5] != (byte)ProductionMailboxOwnerControlResponseKind.History ||
            value[6..8].IndexOfAnyExcept((byte)0) >= 0 ||
            value[28..32].IndexOfAnyExcept((byte)0) >= 0)
            throw new InvalidDataException("History response reference header is invalid.");
        var current = BinaryPrimitives.ReadUInt64BigEndian(value[8..16]);
        var next = BinaryPrimitives.ReadUInt64BigEndian(value[16..24]);
        var payloadLength = BinaryPrimitives.ReadUInt32BigEndian(value[24..28]);
        if (current >= ProductionMailboxRouteHistoryCatalogLimits.MaximumBatches ||
            next != checked(current + 1) ||
            payloadLength is < MinimumPayloadLength or > MaximumPayloadLength ||
            payloadLength > ProductionMailboxOwnerControlConstants.MaximumHistoryFrameBytes ||
            value[32..64].IndexOfAnyExcept((byte)0) < 0 ||
            value[64..96].IndexOfAnyExcept((byte)0) < 0 ||
            value[96..128].IndexOfAnyExcept((byte)0) < 0 ||
            value[128..160].IndexOfAnyExcept((byte)0) < 0)
            throw new InvalidDataException("History response reference fields are invalid.");
        var batchLength = checked((int)payloadLength -
            ProductionMailboxRouteContinuityConstants.CanonicalRouteHistoryCheckpointLength);
        if (batchLength is < ProductionMailboxFrozenHistoryBatch.MinimumBatchBytes or
                > ProductionMailboxFrozenHistoryBatch.MaximumBatchBytes)
            throw new InvalidDataException("History response reference batch length is invalid.");
    }

    private static void ValidateContext(ReadOnlySpan<byte> routeStateKey,
        ReadOnlySpan<byte> currentCheckpointHash, ReadOnlySpan<byte> integrityKey)
    {
        if (routeStateKey.Length != 32 || currentCheckpointHash.Length != 32 ||
            integrityKey.Length != 32 || routeStateKey.IndexOfAnyExcept((byte)0) < 0 ||
            currentCheckpointHash.IndexOfAnyExcept((byte)0) < 0 ||
            integrityKey.IndexOfAnyExcept((byte)0) < 0)
            throw new InvalidDataException("History response reference context is invalid.");
    }

    private static byte[] ComputeTag(ReadOnlySpan<byte> routeStateKey,
        ReadOnlySpan<byte> currentCheckpointHash, ReadOnlySpan<byte> value,
        ReadOnlySpan<byte> integrityKey)
    {
        var ownedKey = integrityKey.ToArray();
        var final = value.ToArray();
        try
        {
            using var hmac = new HMACSHA256(ownedKey);
            Append(IntegrityDomain);
            Append(routeStateKey);
            Append(currentCheckpointHash);
            hmac.TransformFinalBlock(final, 0, final.Length);
            return hmac.Hash ?? throw new CryptographicException(
                "History response reference HMAC failed.");

            void Append(ReadOnlySpan<byte> bytes)
            {
                var owned = bytes.ToArray();
                try { hmac.TransformBlock(owned, 0, owned.Length, null, 0); }
                finally { CryptographicOperations.ZeroMemory(owned); }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ownedKey);
            CryptographicOperations.ZeroMemory(final);
        }
    }

    private static void CopyHash(ReadOnlySpan<byte> source, Span<byte> destination,
        string name)
    {
        if (source.Length != 32 || source.IndexOfAnyExcept((byte)0) < 0)
            throw new InvalidDataException($"History response reference {name} is invalid.");
        source.CopyTo(destination);
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}
