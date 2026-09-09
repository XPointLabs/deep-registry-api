using System.Buffers.Binary;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace Deep.Registry.Api.DirectoryPublication;

internal sealed record DirectoryPublicationChallengeTicket(
    ReadOnlyMemory<byte> Nonce,
    ReadOnlyMemory<byte> BootId,
    ulong CreatedAtMonotonicSeconds);

internal interface IDirectoryPublicationChallengeIssuer
{
    ValueTask<DirectoryPublicationChallengeTicket> IssueAsync(CancellationToken cancellationToken);
}

internal static class DirectoryPublicationProtectedFile
{
    internal static byte[] ReadKey(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new InvalidOperationException("A protected integrity-key path is required.");
        }

        var bytes = ReadBounded(Path.GetFullPath(path), 256);
        if (bytes.Length == 32)
        {
            if (bytes.AsSpan().IndexOfAnyExcept((byte)0) < 0)
            {
                CryptographicOperations.ZeroMemory(bytes);
                throw new InvalidDataException("A protected integrity key cannot be all-zero.");
            }
            return bytes;
        }

        var text = Encoding.ASCII.GetString(bytes).Trim();
        if (text.Length == 64)
        {
            try
            {
                var decoded = Convert.FromHexString(text);
                if (decoded.AsSpan().IndexOfAnyExcept((byte)0) < 0)
                {
                    CryptographicOperations.ZeroMemory(decoded);
                    throw new InvalidDataException("A protected integrity key cannot be all-zero.");
                }
                CryptographicOperations.ZeroMemory(bytes);
                return decoded;
            }
            catch (FormatException)
            {
                // Normalize malformed protected input below.
            }
        }

        CryptographicOperations.ZeroMemory(bytes);
        throw new InvalidDataException("A protected integrity key must be exactly 32 raw bytes or 64 hexadecimal characters.");
    }

    internal static byte[] ReadBounded(string path, int maximumBytes)
    {
        using var stream = new FileStream(
            Path.GetFullPath(path),
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            4096,
            FileOptions.SequentialScan);
        if (stream.Length < 1 || stream.Length > maximumBytes || stream.Length > int.MaxValue)
        {
            throw new InvalidDataException("The protected state file has an invalid length.");
        }
        var bytes = GC.AllocateUninitializedArray<byte>(checked((int)stream.Length));
        stream.ReadExactly(bytes);
        if (stream.ReadByte() != -1)
        {
            CryptographicOperations.ZeroMemory(bytes);
            throw new InvalidDataException("The protected state file changed while it was read.");
        }
        return bytes;
    }

    internal static IDisposable AcquireLease(string protectedPath, CancellationToken cancellationToken)
    {
        var fullPath = Path.GetFullPath(protectedPath);
        var directory = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var stopwatch = Stopwatch.StartNew();
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                return new FileStream(
                    fullPath + ".lock",
                    FileMode.OpenOrCreate,
                    FileAccess.ReadWrite,
                    FileShare.None,
                    1,
                    FileOptions.WriteThrough);
            }
            catch (IOException) when (stopwatch.Elapsed < TimeSpan.FromSeconds(5))
            {
                Thread.Sleep(10);
            }
        }
    }

    internal static byte[] Protect(ReadOnlySpan<byte> payload, ReadOnlySpan<byte> key)
    {
        var result = new byte[checked(payload.Length + 32)];
        payload.CopyTo(result);
        HMACSHA256.HashData(key, payload, result.AsSpan(payload.Length));
        return result;
    }

    internal static ReadOnlySpan<byte> Verify(ReadOnlySpan<byte> encoded, ReadOnlySpan<byte> key)
    {
        if (encoded.Length < 32)
        {
            throw new InvalidDataException("The protected state is truncated.");
        }

        var payload = encoded[..^32];
        var expected = HMACSHA256.HashData(key, payload);
        if (!CryptographicOperations.FixedTimeEquals(expected, encoded[^32..]))
        {
            throw new CryptographicException("The protected state authentication failed.");
        }
        return payload;
    }

    internal static void WriteAtomic(string path, ReadOnlySpan<byte> bytes)
    {
        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var writing = fullPath + ".writing";
        using (var stream = new FileStream(
            writing,
            FileMode.Create,
            FileAccess.Write,
            FileShare.None,
            4096,
            FileOptions.WriteThrough))
        {
            stream.Write(bytes);
            stream.Flush(true);
        }
        File.Move(writing, fullPath, overwrite: true);
    }
}

internal sealed class DurableDirectoryPublicationMonotonicClock : IDirectoryPublicationMonotonicClock
{
    private static readonly byte[] Magic = "DMC1"u8.ToArray();
    private const int PayloadBytes = 4 + 2 + 16 + 8;
    private readonly string path;
    private readonly byte[] integrityKey;
    private readonly SemaphoreSlim gate = new(1, 1);

    internal DurableDirectoryPublicationMonotonicClock(string path, ReadOnlySpan<byte> integrityKey)
    {
        if (string.IsNullOrWhiteSpace(path)) throw new ArgumentException("A monotonic state path is required.", nameof(path));
        if (integrityKey.Length != 32) throw new ArgumentException("A 32-byte integrity key is required.", nameof(integrityKey));
        this.path = Path.GetFullPath(path);
        this.integrityKey = integrityKey.ToArray();
    }

    public async ValueTask<DirectoryPublicationMonotonicReading> ReadAsync(CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var lease = DirectoryPublicationProtectedFile.AcquireLease(path, cancellationToken);
            var sample = checked((ulong)(Environment.TickCount64 / 1000));
            byte[] bootId;
            if (!File.Exists(path))
            {
                bootId = RandomNumberGenerator.GetBytes(16);
            }
            else
            {
                var payload = DirectoryPublicationProtectedFile.Verify(
                    DirectoryPublicationProtectedFile.ReadBounded(path, PayloadBytes + 32),
                    integrityKey);
                if (payload.Length != PayloadBytes || !payload[..4].SequenceEqual(Magic) ||
                    BinaryPrimitives.ReadUInt16BigEndian(payload[4..]) != 1)
                {
                    throw new InvalidDataException("The monotonic state has an unsupported encoding.");
                }
                bootId = payload.Slice(6, 16).ToArray();
                var previous = BinaryPrimitives.ReadUInt64BigEndian(payload[22..]);
                if (sample < previous)
                {
                    bootId = RandomNumberGenerator.GetBytes(16);
                }
            }

            Span<byte> next = stackalloc byte[PayloadBytes];
            Magic.CopyTo(next);
            BinaryPrimitives.WriteUInt16BigEndian(next[4..], 1);
            bootId.CopyTo(next[6..]);
            BinaryPrimitives.WriteUInt64BigEndian(next[22..], sample);
            DirectoryPublicationProtectedFile.WriteAtomic(
                path,
                DirectoryPublicationProtectedFile.Protect(next, integrityKey));
            return new DirectoryPublicationMonotonicReading(bootId, sample);
        }
        finally
        {
            gate.Release();
        }
    }
}

internal sealed class DurableDirectoryPublicationChallengeLedger :
    IDirectoryPublicationChallengeIssuer,
    IDirectoryPublicationLiveChallengeAuthority
{
    private static readonly byte[] Magic = "DCL1"u8.ToArray();
    private const int EntryBytes = 32 + 16 + 8 + 1;
    private const int MaximumEntries = 4_096;
    internal const ulong ChallengeLifetimeSeconds = 30;

    private readonly string path;
    private readonly byte[] networkId;
    private readonly byte[] integrityKey;
    private readonly IDirectoryPublicationMonotonicClock clock;
    private readonly SemaphoreSlim gate = new(1, 1);

    internal DurableDirectoryPublicationChallengeLedger(
        string path,
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> integrityKey,
        IDirectoryPublicationMonotonicClock clock)
    {
        if (string.IsNullOrWhiteSpace(path)) throw new ArgumentException("A challenge-ledger path is required.", nameof(path));
        if (networkId.Length != 16 || networkId.IndexOfAnyExcept((byte)0) < 0) throw new ArgumentException("A non-zero 16-byte network ID is required.", nameof(networkId));
        if (integrityKey.Length != 32) throw new ArgumentException("A 32-byte integrity key is required.", nameof(integrityKey));
        this.clock = clock ?? throw new ArgumentNullException(nameof(clock));
        this.path = Path.GetFullPath(path);
        this.networkId = networkId.ToArray();
        this.integrityKey = integrityKey.ToArray();
    }

    public async ValueTask<DirectoryPublicationChallengeTicket> IssueAsync(CancellationToken cancellationToken)
    {
        var now = await clock.ReadAsync(cancellationToken).ConfigureAwait(false);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var lease = DirectoryPublicationProtectedFile.AcquireLease(path, cancellationToken);
            var entries = Load();
            Prune(entries, now);
            if (entries.Count >= MaximumEntries)
            {
                throw new InvalidOperationException("The durable challenge ledger is at capacity.");
            }

            byte[] nonce;
            do
            {
                nonce = RandomNumberGenerator.GetBytes(32);
            }
            while (entries.Any(entry => CryptographicOperations.FixedTimeEquals(entry.Nonce, nonce)));

            entries.Add(new Entry(nonce, now.BootId.ToArray(), now.SampleSeconds, false));
            Save(entries);
            return new DirectoryPublicationChallengeTicket(nonce, now.BootId.ToArray(), now.SampleSeconds);
        }
        finally
        {
            gate.Release();
        }
    }

    public async ValueTask<VerifiedDirectoryPublicationChallenge> VerifyAndConsumeAsync(
        ReadOnlyMemory<byte> nonce,
        ReadOnlyMemory<byte> bootId,
        ulong nonceCreatedAtMonotonicSeconds,
        ulong responseReceivedAtMonotonicSeconds,
        ulong currentMonotonicSeconds,
        CancellationToken cancellationToken)
    {
        if (nonce.Length != 32 || bootId.Length != 16 ||
            nonceCreatedAtMonotonicSeconds > responseReceivedAtMonotonicSeconds ||
            responseReceivedAtMonotonicSeconds > currentMonotonicSeconds)
        {
            throw new CryptographicException("The publication challenge window is invalid.");
        }

        var observed = await clock.ReadAsync(cancellationToken).ConfigureAwait(false);
        if (!CryptographicOperations.FixedTimeEquals(observed.BootId.Span, bootId.Span) ||
            currentMonotonicSeconds > observed.SampleSeconds ||
            currentMonotonicSeconds - nonceCreatedAtMonotonicSeconds > ChallengeLifetimeSeconds)
        {
            throw new CryptographicException("The publication challenge is not live.");
        }

        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var lease = DirectoryPublicationProtectedFile.AcquireLease(path, cancellationToken);
            var entries = Load();
            var entry = entries.SingleOrDefault(value =>
                CryptographicOperations.FixedTimeEquals(value.Nonce, nonce.Span));
            if (entry is null || entry.Consumed ||
                !CryptographicOperations.FixedTimeEquals(entry.BootId, bootId.Span) ||
                entry.CreatedAt != nonceCreatedAtMonotonicSeconds)
            {
                throw new CryptographicException("The publication challenge is absent, changed, or already consumed.");
            }

            entry.Consumed = true;
            Prune(entries, observed, preserve: entry);
            Save(entries);
            return new VerifiedDirectoryPublicationChallenge(
                nonce.Span,
                bootId.Span,
                nonceCreatedAtMonotonicSeconds,
                responseReceivedAtMonotonicSeconds,
                currentMonotonicSeconds);
        }
        finally
        {
            gate.Release();
        }
    }

    private List<Entry> Load()
    {
        if (!File.Exists(path)) return [];
        var payload = DirectoryPublicationProtectedFile.Verify(
            DirectoryPublicationProtectedFile.ReadBounded(
                path,
                26 + MaximumEntries * EntryBytes + 32),
            integrityKey);
        if (payload.Length < 26 || !payload[..4].SequenceEqual(Magic) ||
            BinaryPrimitives.ReadUInt16BigEndian(payload[4..]) != 1 ||
            !CryptographicOperations.FixedTimeEquals(payload.Slice(6, 16), networkId))
        {
            throw new InvalidDataException("The durable challenge ledger header is invalid.");
        }
        var count = BinaryPrimitives.ReadUInt32BigEndian(payload[22..]);
        if (count > MaximumEntries || payload.Length != 26 + checked((int)count * EntryBytes))
        {
            throw new InvalidDataException("The durable challenge ledger bounds are invalid.");
        }
        var entries = new List<Entry>((int)count);
        var offset = 26;
        for (var index = 0; index < count; index++, offset += EntryBytes)
        {
            var consumed = payload[offset + 56];
            if (consumed > 1) throw new InvalidDataException("The durable challenge state is invalid.");
            entries.Add(new Entry(
                payload.Slice(offset, 32).ToArray(),
                payload.Slice(offset + 32, 16).ToArray(),
                BinaryPrimitives.ReadUInt64BigEndian(payload[(offset + 48)..]),
                consumed == 1));
        }
        return entries;
    }

    private void Save(IReadOnlyList<Entry> entries)
    {
        var payload = new byte[26 + checked(entries.Count * EntryBytes)];
        Magic.CopyTo(payload, 0);
        BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(4), 1);
        networkId.CopyTo(payload, 6);
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(22), checked((uint)entries.Count));
        var offset = 26;
        foreach (var entry in entries)
        {
            entry.Nonce.CopyTo(payload, offset);
            entry.BootId.CopyTo(payload, offset + 32);
            BinaryPrimitives.WriteUInt64BigEndian(payload.AsSpan(offset + 48), entry.CreatedAt);
            payload[offset + 56] = entry.Consumed ? (byte)1 : (byte)0;
            offset += EntryBytes;
        }
        DirectoryPublicationProtectedFile.WriteAtomic(
            path,
            DirectoryPublicationProtectedFile.Protect(payload, integrityKey));
    }

    private static void Prune(
        List<Entry> entries,
        DirectoryPublicationMonotonicReading now,
        Entry? preserve = null)
    {
        entries.RemoveAll(entry => !ReferenceEquals(entry, preserve) &&
            (!CryptographicOperations.FixedTimeEquals(entry.BootId, now.BootId.Span) ||
             now.SampleSeconds >= entry.CreatedAt &&
             now.SampleSeconds - entry.CreatedAt > ChallengeLifetimeSeconds));
    }

    private sealed class Entry(byte[] nonce, byte[] bootId, ulong createdAt, bool consumed)
    {
        internal byte[] Nonce { get; } = nonce;
        internal byte[] BootId { get; } = bootId;
        internal ulong CreatedAt { get; } = createdAt;
        internal bool Consumed { get; set; } = consumed;
    }
}

internal sealed class ProtectedFileDirectoryPublicationNetworkLkgSource :
    IDirectoryPublicationProtectedNetworkLkgSource
{
    private static readonly byte[] Magic = "DPL1"u8.ToArray();
    private const int BasePayloadBytes = 4 + 2 + 16 + 38 + 8 + 32 + 38 + 8 + 38 + 1;
    private readonly string path;
    private readonly byte[] integrityKey;

    internal ProtectedFileDirectoryPublicationNetworkLkgSource(string path, ReadOnlySpan<byte> integrityKey)
    {
        if (string.IsNullOrWhiteSpace(path)) throw new ArgumentException("A protected LKG path is required.", nameof(path));
        if (integrityKey.Length != 32) throw new ArgumentException("A 32-byte integrity key is required.", nameof(integrityKey));
        this.path = Path.GetFullPath(path);
        this.integrityKey = integrityKey.ToArray();
    }

    public ValueTask<DirectoryPublicationProtectedNetworkLkg?> ReadAsync(
        ReadOnlyMemory<byte> expectedNetworkId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!File.Exists(path)) return ValueTask.FromResult<DirectoryPublicationProtectedNetworkLkg?>(null);
        var payload = DirectoryPublicationProtectedFile.Verify(
            DirectoryPublicationProtectedFile.ReadBounded(path, BasePayloadBytes + 46 + 32),
            integrityKey);
        if (payload.Length is not (BasePayloadBytes or BasePayloadBytes + 46) ||
            !payload[..4].SequenceEqual(Magic) || BinaryPrimitives.ReadUInt16BigEndian(payload[4..]) != 1 ||
            !CryptographicOperations.FixedTimeEquals(payload.Slice(6, 16), expectedNetworkId.Span))
        {
            throw new CryptographicException("The independent protected network LKG is invalid.");
        }
        var hasForward = payload[184];
        if (hasForward > 1 || payload.Length != BasePayloadBytes + (hasForward == 1 ? 46 : 0))
        {
            throw new InvalidDataException("The protected network LKG shape is invalid.");
        }
        return ValueTask.FromResult<DirectoryPublicationProtectedNetworkLkg?>(new(
            payload.Slice(6, 16),
            payload.Slice(22, 38),
            BinaryPrimitives.ReadUInt64BigEndian(payload[60..]),
            payload.Slice(68, 32),
            payload.Slice(100, 38),
            BinaryPrimitives.ReadUInt64BigEndian(payload[138..]),
            payload.Slice(146, 38),
            hasForward == 1 ? payload.Slice(185, 38) : default,
            hasForward == 1 ? BinaryPrimitives.ReadUInt64BigEndian(payload[223..]) : null));
    }
}
