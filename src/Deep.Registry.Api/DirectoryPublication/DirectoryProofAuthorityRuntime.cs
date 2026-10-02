#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Registry.Api.DirectoryPublication;


internal readonly record struct ContactResolveTrustedTimeContext(
    ReadOnlyMemory<byte> ServerBootId,
    ulong ServerMonotonicSample,
    ulong ObservedUnixTime,
    uint UncertaintySeconds)
{
    internal void Validate()
    {
        if (ServerBootId.Length != 16 || ServerBootId.Span.IndexOfAnyExcept((byte)0) < 0)
            throw new CryptographicException("The trusted-time server boot ID is invalid.");
        if (ObservedUnixTime == 0 || UncertaintySeconds is < 1 or > 30 ||
            ObservedUnixTime <= UncertaintySeconds ||
            ObservedUnixTime > ulong.MaxValue - UncertaintySeconds)
            throw new CryptographicException("The trusted-time interval is invalid.");
    }
}


/// <summary>
/// Supplies an authenticated UTC interval advanced by a protected monotonic clock. OS wall time
/// alone is not a valid implementation of this boundary.
/// </summary>
internal interface IContactResolveTrustedTimeContextSource
{
    ValueTask<ContactResolveTrustedTimeContext> ReadAsync(CancellationToken cancellationToken);
}


/// <summary>
/// Atomically and durably consumes one client request. Implementations must reject a nonce that
/// was already consumed, regardless of a changed client boot ID or monotonic sample.
/// </summary>
internal interface IContactResolveOneUseRequestLedger
{
    ValueTask ConsumeAsync(
        DirectoryProofReplayRequest request,
        ContactResolveTrustedTimeContext trustedTime,
        AccountDirectoryDtt1IssuanceEpoch issuanceEpoch,
        CancellationToken cancellationToken);
}


/// <summary>
/// Returns custody-backed witnesses for the exact current authority. The protocol author checks
/// membership, unique witness IDs, signatures and distinct failure-domain threshold.
/// </summary>
internal interface IContactResolveDtt1WitnessCustody
{
    ValueTask<IReadOnlyList<IAccountDirectoryDtt1WitnessSigner>> GetSignersAsync(
        VerifiedXPointNetworkAuthority authority,
        CancellationToken cancellationToken);
}


/// <summary>
/// Protected, exact and process-safe one-use ledger. Every nonce becomes a sharded authenticated
/// marker. Marker existence is authoritative even after a partial crash write, so corruption can
/// reduce availability but can never reopen a consumed nonce.
/// </summary>
internal sealed class ProtectedFileContactResolveOneUseRequestLedger :
    IContactResolveOneUseRequestLedger,
    IDisposable
{
    private static ReadOnlySpan<byte> Magic => "CRL1"u8;
    private static ReadOnlySpan<byte> StateMagic => "CRS1"u8;
    private const int PayloadBytes = 4 + 2 + 16 + 8 + 32 + 32 + 16 + 8 + 16 + 8 + 8;
    private const int StatePayloadBytes = 4 + 2 + 16 + 8 + 32 + 4 + 8;
    private readonly string rootPath;
    private readonly string statePath;
    private readonly byte[] networkId;
    private readonly byte[] integrityKey;
    private readonly int capacity;
    private readonly int compactionInterval;

    internal ProtectedFileContactResolveOneUseRequestLedger(
        string rootPath,
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> integrityKey,
        int capacity = 65_536,
        int compactionInterval = 1_024)
    {
        if (string.IsNullOrWhiteSpace(rootPath))
            throw new ArgumentException("A ContactResolve request-ledger path is required.", nameof(rootPath));
        if (networkId.Length != 16 || networkId.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("A non-zero 16-byte network ID is required.", nameof(networkId));
        if (integrityKey.Length != 32 || integrityKey.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("A non-zero 32-byte integrity key is required.", nameof(integrityKey));
        // The production options enforce the operational floor. Smaller values keep the bounded
        // state machine directly testable without thousands of durable filesystem mutations.
        if (capacity is < 16 or > 1_000_000)
            throw new ArgumentOutOfRangeException(nameof(capacity));
        if (compactionInterval is < 1 or > 16_384)
            throw new ArgumentOutOfRangeException(nameof(compactionInterval));
        this.rootPath = Path.GetFullPath(rootPath);
        RejectReparseDirectoryIfPresent(this.rootPath);
        statePath = Path.Combine(this.rootPath, ".quota.state");
        this.networkId = networkId.ToArray();
        this.integrityKey = integrityKey.ToArray();
        this.capacity = capacity;
        this.compactionInterval = compactionInterval;
    }

    public ValueTask ConsumeAsync(
        DirectoryProofReplayRequest request,
        ContactResolveTrustedTimeContext trustedTime,
        AccountDirectoryDtt1IssuanceEpoch issuanceEpoch,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        trustedTime.Validate();
        ArgumentNullException.ThrowIfNull(issuanceEpoch);
        if (!CryptographicOperations.FixedTimeEquals(request.NetworkId.Span, networkId))
            throw new CryptographicException("The request ledger rejected a different network.");

        Span<byte> digestInput = stackalloc byte[88];
        networkId.CopyTo(digestInput);
        BinaryPrimitives.WriteUInt64BigEndian(digestInput[16..], issuanceEpoch.Number);
        issuanceEpoch.Id.Span.CopyTo(digestInput[24..]);
        request.Nonce.Span.CopyTo(digestInput[56..]);
        var digest = HMACSHA256.HashData(integrityKey, digestInput);
        var hex = Convert.ToHexString(digest);
        var firstShard = Path.Combine(rootPath, hex[..2]);
        var shard = Path.Combine(firstShard, hex.Substring(2, 2));
        var marker = Path.Combine(shard, hex[4..] + ".request");
        var payload = new byte[PayloadBytes];
        Magic.CopyTo(payload);
        BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(4), 2);
        networkId.CopyTo(payload, 6);
        BinaryPrimitives.WriteUInt64BigEndian(payload.AsSpan(22), issuanceEpoch.Number);
        issuanceEpoch.Id.Span.CopyTo(payload.AsSpan(30));
        digest.CopyTo(payload, 62);
        request.BootId.Span.CopyTo(payload.AsSpan(94));
        BinaryPrimitives.WriteUInt64BigEndian(payload.AsSpan(110), request.NonceCreatedAt);
        trustedTime.ServerBootId.Span.CopyTo(payload.AsSpan(118));
        BinaryPrimitives.WriteUInt64BigEndian(payload.AsSpan(134), trustedTime.ServerMonotonicSample);
        BinaryPrimitives.WriteUInt64BigEndian(payload.AsSpan(142), trustedTime.ObservedUnixTime);
        var protectedMarker = DirectoryPublicationProtectedFile.Protect(payload, integrityKey);

        try
        {
            Directory.CreateDirectory(rootPath);
            RejectReparseDirectory(rootPath);
            using var lease = DirectoryPublicationProtectedFile.AcquireLease(statePath, cancellationToken);
            if (File.Exists(marker))
            {
                if ((File.GetAttributes(marker) & FileAttributes.ReparsePoint) != 0)
                    throw new InvalidDataException(
                        "Reparse points are forbidden in the ContactResolve request ledger.");
                throw new CryptographicException("The ContactResolve request nonce was already consumed.");
            }

            var state = ReadStateOrCompact(issuanceEpoch);
            if (state.Count >= capacity || state.Revision % (ulong)compactionInterval == 0)
                state = Compact(issuanceEpoch, state.Revision);
            if (state.Count >= capacity)
                throw new ContactResolveDirectoryAdmissionException(
                    "The ContactResolve request ledger reached its bounded capacity.");

            // Reserve quota first. A crash after this write can only over-count and reduce
            // availability; it cannot create an unaccounted marker or reopen a nonce.
            var reserved = new LedgerState(state.Count + 1, checked(state.Revision + 1));
            WriteState(reserved, issuanceEpoch);

            Directory.CreateDirectory(firstShard);
            RejectReparseDirectory(firstShard);
            Directory.CreateDirectory(shard);
            RejectReparseDirectory(shard);
            using var stream = new FileStream(
                marker,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                4096,
                FileOptions.WriteThrough);
            stream.Write(protectedMarker);
            stream.Flush(true);
        }
        catch (IOException) when (File.Exists(marker))
        {
            throw new CryptographicException("The ContactResolve request nonce was already consumed.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(digestInput);
            CryptographicOperations.ZeroMemory(digest);
            CryptographicOperations.ZeroMemory(payload);
            CryptographicOperations.ZeroMemory(protectedMarker);
        }
        return ValueTask.CompletedTask;
    }

    public void Dispose() => CryptographicOperations.ZeroMemory(integrityKey);

    private LedgerState ReadStateOrCompact(AccountDirectoryDtt1IssuanceEpoch issuanceEpoch)
    {
        if (!File.Exists(statePath)) return Compact(issuanceEpoch, 0);
        var encoded = DirectoryPublicationProtectedFile.ReadBounded(
            statePath, StatePayloadBytes + 32);
        try
        {
            var payload = DirectoryPublicationProtectedFile.Verify(encoded, integrityKey);
            if (payload.Length != StatePayloadBytes || !payload[..4].SequenceEqual(StateMagic) ||
                BinaryPrimitives.ReadUInt16BigEndian(payload[4..]) != 2 ||
                !CryptographicOperations.FixedTimeEquals(payload.Slice(6, 16), networkId))
                throw new InvalidDataException("The ContactResolve request-ledger quota state is invalid.");
            var storedEpochNumber = BinaryPrimitives.ReadUInt64BigEndian(payload[22..]);
            var revision = BinaryPrimitives.ReadUInt64BigEndian(payload[66..]);
            var sameEpochId = CryptographicOperations.FixedTimeEquals(
                payload.Slice(30, 32), issuanceEpoch.Id.Span);
            if (storedEpochNumber > issuanceEpoch.Number ||
                storedEpochNumber == issuanceEpoch.Number && !sameEpochId)
                throw new CryptographicException(
                    "The ContactResolve request ledger rejected an issuance-epoch rollback or fork.");
            if (storedEpochNumber < issuanceEpoch.Number)
                return Compact(issuanceEpoch, revision);
            var count = BinaryPrimitives.ReadUInt32BigEndian(payload[62..]);
            if (count > capacity || revision < count)
                throw new InvalidDataException("The ContactResolve request-ledger quota state is invalid.");
            return new LedgerState(checked((int)count), revision);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encoded);
        }
    }

    private LedgerState Compact(
        AccountDirectoryDtt1IssuanceEpoch issuanceEpoch,
        ulong priorRevision)
    {
        var count = 0;
        var inspected = 0;
        var enumeration = new EnumerationOptions
        {
            RecurseSubdirectories = true,
            IgnoreInaccessible = false,
            AttributesToSkip = FileAttributes.ReparsePoint,
            MatchType = MatchType.Simple,
        };
        foreach (var marker in Directory.EnumerateFiles(rootPath, "*.request", enumeration))
        {
            if (++inspected > checked(capacity * 2))
                throw new InvalidDataException(
                    "The ContactResolve request ledger exceeds its bounded recovery scan.");
            var encoded = DirectoryPublicationProtectedFile.ReadBounded(marker, PayloadBytes + 32);
            try
            {
                var payload = DirectoryPublicationProtectedFile.Verify(encoded, integrityKey);
                var isCurrent = ValidateMarker(payload, marker, issuanceEpoch);
                if (isCurrent)
                {
                    count++;
                }
                else
                {
                    File.Delete(marker);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(encoded);
            }
        }
        var nextRevision = Math.Max(checked(priorRevision + 1), checked((ulong)count));
        var compacted = new LedgerState(count, nextRevision);
        WriteState(compacted, issuanceEpoch);
        return compacted;
    }

    private bool ValidateMarker(
        ReadOnlySpan<byte> payload,
        string marker,
        AccountDirectoryDtt1IssuanceEpoch issuanceEpoch)
    {
        if (payload.Length != PayloadBytes || !payload[..4].SequenceEqual(Magic) ||
            BinaryPrimitives.ReadUInt16BigEndian(payload[4..]) != 2 ||
            !CryptographicOperations.FixedTimeEquals(payload.Slice(6, 16), networkId))
            throw new InvalidDataException("A ContactResolve request-ledger marker is invalid.");
        var relative = Path.GetRelativePath(rootPath, marker);
        var parts = relative.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (parts.Length != 3 || parts[0].Length != 2 || parts[1].Length != 2 ||
            !parts[2].EndsWith(".request", StringComparison.Ordinal) || parts[2].Length != 68)
            throw new InvalidDataException("A ContactResolve request-ledger marker path is invalid.");
        byte[] pathDigest;
        try
        {
            pathDigest = Convert.FromHexString(parts[0] + parts[1] + parts[2][..^8]);
        }
        catch (FormatException exception)
        {
            throw new InvalidDataException(
                "A ContactResolve request-ledger marker path is invalid.", exception);
        }
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(pathDigest, payload.Slice(62, 32)))
                throw new InvalidDataException(
                    "A ContactResolve request-ledger marker path is not bound to its payload.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pathDigest);
        }
        var markerEpochNumber = BinaryPrimitives.ReadUInt64BigEndian(payload[22..]);
        if (markerEpochNumber > issuanceEpoch.Number ||
            markerEpochNumber == issuanceEpoch.Number &&
            !CryptographicOperations.FixedTimeEquals(payload.Slice(30, 32), issuanceEpoch.Id.Span))
            throw new CryptographicException(
                "The ContactResolve request ledger rejected an issuance-epoch rollback or fork.");
        return markerEpochNumber == issuanceEpoch.Number;
    }

    private void WriteState(
        LedgerState state,
        AccountDirectoryDtt1IssuanceEpoch issuanceEpoch)
    {
        Span<byte> payload = stackalloc byte[StatePayloadBytes];
        StateMagic.CopyTo(payload);
        BinaryPrimitives.WriteUInt16BigEndian(payload[4..], 2);
        networkId.CopyTo(payload[6..]);
        BinaryPrimitives.WriteUInt64BigEndian(payload[22..], issuanceEpoch.Number);
        issuanceEpoch.Id.Span.CopyTo(payload[30..]);
        BinaryPrimitives.WriteUInt32BigEndian(payload[62..], checked((uint)state.Count));
        BinaryPrimitives.WriteUInt64BigEndian(payload[66..], state.Revision);
        var encoded = DirectoryPublicationProtectedFile.Protect(payload, integrityKey);
        try
        {
            DirectoryPublicationProtectedFile.WriteAtomic(statePath, encoded);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(payload);
            CryptographicOperations.ZeroMemory(encoded);
        }
    }

    private static void RejectReparseDirectoryIfPresent(string path)
    {
        if (Directory.Exists(path)) RejectReparseDirectory(path);
    }

    private static void RejectReparseDirectory(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException(
                "Reparse points are forbidden in the ContactResolve request ledger.");
    }

    private readonly record struct LedgerState(int Count, ulong Revision);
}

/// <summary>Bounded nonce-ledger input; it carries no directory or network verification authority.</summary>
internal sealed class DirectoryProofReplayRequest
{
    private readonly byte[] networkId;
    private readonly byte[] nonce;
    private readonly byte[] bootId;

    internal DirectoryProofReplayRequest(
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> bootId,
        ulong nonceCreatedAt)
    {
        RequireNonZero(networkId, 16, nameof(networkId));
        RequireNonZero(nonce, 32, nameof(nonce));
        RequireNonZero(bootId, 16, nameof(bootId));
        this.networkId = networkId.ToArray();
        this.nonce = nonce.ToArray();
        this.bootId = bootId.ToArray();
        NonceCreatedAt = nonceCreatedAt;
    }

    internal ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    internal ReadOnlyMemory<byte> Nonce => nonce.ToArray();
    internal ReadOnlyMemory<byte> BootId => bootId.ToArray();
    internal ulong NonceCreatedAt { get; }

    private static void RequireNonZero(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("A fixed-size non-zero replay field is required.", name);
    }
}

#endif
