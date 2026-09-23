#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;

namespace Deep.Registry.Api.DirectoryPublication;

internal sealed record DeepIdV2DirectoryHeadRow(
    ReadOnlyMemory<byte> ExactAdh1, ReadOnlyMemory<byte> CoreHash);

internal sealed record DeepIdV2DirectoryAdmissionRow(
    ulong VerifiedAtUnixSeconds, ReadOnlyMemory<byte> ExactDga1V2);

/// <summary>
/// Shape-only ADA2 payload. The caller must HMAC-protect the exact bytes and
/// reverify every head, transition and PQ admission against current authority
/// before promoting decoded rows into durable directory capabilities.
/// </summary>
internal sealed class DeepIdV2DirectoryStateRows
{
    internal DeepIdV2DirectoryStateRows(
        IReadOnlyList<DeepIdV2DirectoryHeadRow> heads,
        IReadOnlyList<ReadOnlyMemory<byte>> transitions,
        IReadOnlyList<DeepIdV2DirectoryAdmissionRow> admissions)
    {
        Heads = heads.Select(static row => new DeepIdV2DirectoryHeadRow(
            row.ExactAdh1.ToArray(), row.CoreHash.ToArray())).ToArray();
        Transitions = transitions.Select(static value =>
            (ReadOnlyMemory<byte>)value.ToArray()).ToArray();
        Admissions = admissions.Select(static row => new DeepIdV2DirectoryAdmissionRow(
            row.VerifiedAtUnixSeconds, row.ExactDga1V2.ToArray())).ToArray();
    }

    internal IReadOnlyList<DeepIdV2DirectoryHeadRow> Heads { get; }
    internal IReadOnlyList<ReadOnlyMemory<byte>> Transitions { get; }
    internal IReadOnlyList<DeepIdV2DirectoryAdmissionRow> Admissions { get; }
}

internal static class DeepIdV2DirectoryStateCodec
{
    internal const int MaximumPayloadBytes = 64 * 1024 * 1024;
    internal const int MaximumEntries = 100_000;
    private static ReadOnlySpan<byte> Magic => "ADA2"u8;

    internal static byte[] Encode(ReadOnlySpan<byte> networkId,
        DeepIdV2DirectoryStateRows state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (networkId.Length != 16 || networkId.IndexOfAnyExcept((byte)0) < 0 ||
            state.Heads.Count is < 1 or > MaximumEntries + 1 ||
            state.Transitions.Count > MaximumEntries ||
            state.Admissions.Count > MaximumEntries)
            throw new ArgumentException("ADA2 network or row count is invalid.");
        using var stream = new MemoryStream();
        stream.Write(Magic);
        WriteU16(stream, 2);
        stream.Write(networkId);
        WriteU32(stream, checked((uint)state.Heads.Count));
        foreach (var row in state.Heads)
        {
            var head = AccountDirectoryAdh1Codec.Decode(row.ExactAdh1.Span);
            if (head.MinimumReader < 2 || row.CoreHash.Length != 32 ||
                row.CoreHash.Span.IndexOfAnyExcept((byte)0) < 0)
                throw new ArgumentException("ADA2 head row is not a V2 reader head.");
            WriteArtifact(stream, row.ExactAdh1.Span, 4096);
            stream.Write(row.CoreHash.Span);
            RequireBound(stream);
        }
        WriteU32(stream, checked((uint)state.Transitions.Count));
        foreach (var transition in state.Transitions)
        {
            _ = DeepIdV2DirectoryTransitionCodec.Decode(transition.Span);
            stream.Write(transition.Span);
            RequireBound(stream);
        }
        WriteU32(stream, checked((uint)state.Admissions.Count));
        foreach (var row in state.Admissions)
        {
            if (row.VerifiedAtUnixSeconds == 0)
                throw new ArgumentException("ADA2 admission verification time is zero.");
            _ = DeepIdV2GenesisAdmissionWireCodec.DecodeRequest(row.ExactDga1V2.Span);
            WriteU64(stream, row.VerifiedAtUnixSeconds);
            WriteArtifact(stream, row.ExactDga1V2.Span,
                DeepIdV2GenesisAdmissionWireCodec.MaximumRequestLength);
            RequireBound(stream);
        }
        return stream.ToArray();
    }

    internal static DeepIdV2DirectoryStateRows Decode(ReadOnlySpan<byte> payload,
        ReadOnlySpan<byte> expectedNetworkId)
    {
        if (payload.Length > MaximumPayloadBytes ||
            expectedNetworkId.Length != 16 ||
            expectedNetworkId.IndexOfAnyExcept((byte)0) < 0)
            throw new InvalidDataException("ADA2 payload or expected network is invalid.");
        try
        {
            var reader = new Reader(payload);
            if (!reader.Read(4).SequenceEqual(Magic) || reader.ReadU16() != 2 ||
                !Fixed(reader.Read(16), expectedNetworkId))
                throw new InvalidDataException("ADA2 header or network mismatch.");
            var headCount = reader.ReadCount(MaximumEntries + 1, minimum: 1);
            var heads = new DeepIdV2DirectoryHeadRow[headCount];
            for (var index = 0; index < heads.Length; index++)
            {
                var exact = reader.ReadArtifact(4096);
                var hash = reader.Read(32).ToArray();
                var parsed = AccountDirectoryAdh1Codec.Decode(exact);
                if (parsed.MinimumReader < 2 ||
                    hash.AsSpan().IndexOfAnyExcept((byte)0) < 0)
                    throw new InvalidDataException("ADA2 head row is invalid.");
                heads[index] = new DeepIdV2DirectoryHeadRow(exact, hash);
            }
            var transitionCount = reader.ReadCount(MaximumEntries);
            var transitions = new ReadOnlyMemory<byte>[transitionCount];
            for (var index = 0; index < transitions.Length; index++)
            {
                var exact = reader.Read(DeepIdV2DirectoryTransitionCodec.CanonicalLength);
                _ = DeepIdV2DirectoryTransitionCodec.Decode(exact);
                transitions[index] = exact.ToArray();
            }
            var admissionCount = reader.ReadCount(MaximumEntries);
            var admissions = new DeepIdV2DirectoryAdmissionRow[admissionCount];
            for (var index = 0; index < admissions.Length; index++)
            {
                var time = reader.ReadU64();
                if (time == 0)
                    throw new InvalidDataException("ADA2 admission time is zero.");
                var exact = reader.ReadArtifact(
                    DeepIdV2GenesisAdmissionWireCodec.MaximumRequestLength);
                _ = DeepIdV2GenesisAdmissionWireCodec.DecodeRequest(exact);
                admissions[index] = new DeepIdV2DirectoryAdmissionRow(time, exact);
            }
            reader.RequireEnd();
            return new DeepIdV2DirectoryStateRows(heads, transitions, admissions);
        }
        catch (Exception exception) when (exception is ArgumentException or
            FormatException or CryptographicException or OverflowException)
        {
            throw new InvalidDataException("ADA2 payload has invalid V2 records.",
                exception);
        }
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length &&
        CryptographicOperations.FixedTimeEquals(left, right);

    private static void RequireBound(Stream stream)
    {
        if (stream.Length > MaximumPayloadBytes)
            throw new ArgumentOutOfRangeException(nameof(stream),
                "ADA2 payload exceeds its protected-state bound.");
    }

    private static void WriteArtifact(Stream stream, ReadOnlySpan<byte> value,
        int maximum)
    {
        if (value.Length is < 1 || value.Length > maximum)
            throw new ArgumentOutOfRangeException(nameof(value));
        WriteU32(stream, checked((uint)value.Length));
        stream.Write(value);
    }

    private static void WriteU16(Stream stream, ushort value)
    {
        Span<byte> bytes = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(bytes, value);
        stream.Write(bytes);
    }

    private static void WriteU32(Stream stream, uint value)
    {
        Span<byte> bytes = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, value);
        stream.Write(bytes);
    }

    private static void WriteU64(Stream stream, ulong value)
    {
        Span<byte> bytes = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(bytes, value);
        stream.Write(bytes);
    }

    private ref struct Reader
    {
        private readonly ReadOnlySpan<byte> payload;
        private int offset;

        internal Reader(ReadOnlySpan<byte> payload)
        {
            this.payload = payload;
            offset = 0;
        }

        internal ReadOnlySpan<byte> Read(int length)
        {
            if (length < 0 || length > payload.Length - offset)
                throw new InvalidDataException("ADA2 payload is truncated.");
            var result = payload.Slice(offset, length);
            offset += length;
            return result;
        }

        internal ushort ReadU16() => BinaryPrimitives.ReadUInt16BigEndian(Read(2));
        internal uint ReadU32() => BinaryPrimitives.ReadUInt32BigEndian(Read(4));
        internal ulong ReadU64() => BinaryPrimitives.ReadUInt64BigEndian(Read(8));

        internal int ReadCount(int maximum, int minimum = 0)
        {
            var count = ReadU32();
            if (count < minimum || count > maximum)
                throw new InvalidDataException("ADA2 row count is invalid.");
            return checked((int)count);
        }

        internal byte[] ReadArtifact(int maximum)
        {
            var length = ReadU32();
            if (length is < 1 || length > maximum)
                throw new InvalidDataException("ADA2 artifact length is invalid.");
            return Read(checked((int)length)).ToArray();
        }

        internal void RequireEnd()
        {
            if (offset != payload.Length)
                throw new InvalidDataException("ADA2 payload has trailing bytes.");
        }
    }
}
#endif
