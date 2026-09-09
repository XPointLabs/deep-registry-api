using System.Buffers.Binary;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Deep.Registry.Api.DirectoryPublication;

internal sealed class ContactResolveDirectoryPackageRequest
{
    private readonly byte[] networkId;
    private readonly byte[] nonce;
    private readonly byte[] bootId;
    private readonly byte[]? directoryCoreHash;
    private readonly byte[]? expectedDirectoryLookupKey;
    private readonly byte[]? minimumAdhHash;

    internal ContactResolveDirectoryPackageRequest(
        byte[] networkId,
        byte[] nonce,
        byte[] bootId,
        ulong nonceCreatedAt,
        ulong? directoryTreeSize,
        byte[]? directoryCoreHash,
        ContactResolveNetworkFloor? networkFloor,
        byte[]? expectedDirectoryLookupKey = null,
        ulong? minimumAdhGeneration = null,
        byte[]? minimumAdhHash = null,
        bool requireCurrentValue = false)
    {
        this.networkId = networkId.ToArray();
        this.nonce = nonce.ToArray();
        this.bootId = bootId.ToArray();
        NonceCreatedAt = nonceCreatedAt;
        DirectoryTreeSize = directoryTreeSize;
        this.directoryCoreHash = directoryCoreHash?.ToArray();
        NetworkFloor = networkFloor;
        this.expectedDirectoryLookupKey = expectedDirectoryLookupKey?.ToArray();
        MinimumAdhGeneration = minimumAdhGeneration;
        this.minimumAdhHash = minimumAdhHash?.ToArray();
        RequireCurrentValue = requireCurrentValue;
    }

    internal ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    internal ReadOnlyMemory<byte> Nonce => nonce.ToArray();
    internal ReadOnlyMemory<byte> BootId => bootId.ToArray();
    internal ulong NonceCreatedAt { get; }
    internal ulong? DirectoryTreeSize { get; }
    internal ReadOnlyMemory<byte> DirectoryCoreHash => directoryCoreHash?.ToArray() ?? [];
    internal ContactResolveNetworkFloor? NetworkFloor { get; }
    internal ReadOnlyMemory<byte> ExpectedDirectoryLookupKey =>
        expectedDirectoryLookupKey?.ToArray() ?? [];
    internal ulong? MinimumAdhGeneration { get; }
    internal ReadOnlyMemory<byte> MinimumAdhHash => minimumAdhHash?.ToArray() ?? [];
    internal bool RequireCurrentValue { get; }
}

internal sealed class ContactResolveNetworkFloor
{
    private readonly byte[] headCoreReference;
    private readonly byte[] headRoot;
    private readonly byte[] viewCoreReference;
    private readonly byte[] authorityCoreReference;
    private readonly byte[] lastForwardCheckpointCoreReference;

    internal ContactResolveNetworkFloor(
        byte[] headCoreReference,
        ulong headTreeSize,
        byte[] headRoot,
        byte[] viewCoreReference,
        ulong viewGeneration,
        byte[] authorityCoreReference,
        byte[]? lastForwardCheckpointCoreReference,
        ulong? lastForwardCheckpointGeneration)
    {
        this.headCoreReference = headCoreReference.ToArray();
        HeadTreeSize = headTreeSize;
        this.headRoot = headRoot.ToArray();
        this.viewCoreReference = viewCoreReference.ToArray();
        ViewGeneration = viewGeneration;
        this.authorityCoreReference = authorityCoreReference.ToArray();
        this.lastForwardCheckpointCoreReference =
            lastForwardCheckpointCoreReference?.ToArray() ?? [];
        LastForwardCheckpointGeneration = lastForwardCheckpointGeneration;
    }

    internal ReadOnlyMemory<byte> HeadCoreReference => headCoreReference.ToArray();
    internal ulong HeadTreeSize { get; }
    internal ReadOnlyMemory<byte> HeadRoot => headRoot.ToArray();
    internal ReadOnlyMemory<byte> ViewCoreReference => viewCoreReference.ToArray();
    internal ulong ViewGeneration { get; }
    internal ReadOnlyMemory<byte> AuthorityCoreReference => authorityCoreReference.ToArray();
    internal ReadOnlyMemory<byte> LastForwardCheckpointCoreReference =>
        lastForwardCheckpointCoreReference.ToArray();
    internal ulong? LastForwardCheckpointGeneration { get; }
}

/// <summary>
/// Authority boundary for request-bound ContactResolve packages. Implementations must obtain a
/// fresh threshold-authorized DTT1/ADP1 proof for the exact request nonce and monotonic echo.
/// Returning catalog snapshots or rewriting an old ADP1 as a fresh response is forbidden.
/// </summary>
internal interface IContactResolveDirectoryPackageIssuer
{
    ValueTask<ContactResolveDirectoryIssuedPackage> IssueAsync(
        ContactResolveDirectoryPackageRequest request,
        CancellationToken cancellationToken);
}

internal sealed class ContactResolveDirectoryPackageUnavailableException : IOException
{
    internal ContactResolveDirectoryPackageUnavailableException()
        : base("The threshold ContactResolve directory package issuer is unavailable.")
    {
    }
}

internal sealed class ContactResolveDirectoryTargetNotFoundException : Exception
{
    internal ContactResolveDirectoryTargetNotFoundException()
        : base("The requested current directory value is not available.")
    {
    }
}

internal sealed class ContactResolveForwardCheckpointPackage
{
    internal const long MaximumForwardPackageBytes = 560L * 1024;

    internal ContactResolveForwardCheckpointPackage(
        IReadOnlyList<ReadOnlyMemory<byte>> exactOrderedXnf1Chain,
        ReadOnlyMemory<byte> exactNfp1,
        ReadOnlyMemory<byte> exactTargetXnv1,
        ReadOnlyMemory<byte> exactTargetXnh1)
    {
        var total = ContactResolveDirectoryIssuedPackage.ValidateChain(
            exactOrderedXnf1Chain, 64, nameof(exactOrderedXnf1Chain))
            + ContactResolveDirectoryIssuedPackage.ValidateArtifact(exactNfp1, nameof(exactNfp1))
            + ContactResolveDirectoryIssuedPackage.ValidateArtifact(
                exactTargetXnv1, nameof(exactTargetXnv1))
            + ContactResolveDirectoryIssuedPackage.ValidateArtifact(
                exactTargetXnh1, nameof(exactTargetXnh1));
        if (total > MaximumForwardPackageBytes)
            throw new ArgumentException(
                $"The forward-checkpoint package exceeds {MaximumForwardPackageBytes} bytes.");
        ExactOrderedXnf1Chain = ContactResolveDirectoryIssuedPackage.CopyChain(
            exactOrderedXnf1Chain, 64, nameof(exactOrderedXnf1Chain));
        ExactNfp1 = ContactResolveDirectoryIssuedPackage.CopyArtifact(exactNfp1, nameof(exactNfp1));
        ExactTargetXnv1 = ContactResolveDirectoryIssuedPackage.CopyArtifact(
            exactTargetXnv1, nameof(exactTargetXnv1));
        ExactTargetXnh1 = ContactResolveDirectoryIssuedPackage.CopyArtifact(
            exactTargetXnh1, nameof(exactTargetXnh1));
    }

    internal IReadOnlyList<ReadOnlyMemory<byte>> ExactOrderedXnf1Chain { get; }
    internal ReadOnlyMemory<byte> ExactNfp1 { get; }
    internal ReadOnlyMemory<byte> ExactTargetXnv1 { get; }
    internal ReadOnlyMemory<byte> ExactTargetXnh1 { get; }
}

/// <summary>
/// Opaque output of an issuer. The request binding is retained separately from the artifacts so
/// the HTTP boundary can reject accidental replay of an issuance made for another request.
/// This is shape validation only; authority remains the issuer's responsibility.
/// </summary>
internal sealed class ContactResolveDirectoryIssuedPackage
{
    internal const int MaximumChainArtifacts = 4_096;
    internal const int MaximumSingleArtifactBytes = 16 * 1024 * 1024;
    internal const long MaximumPackageBytes = 68L * 1024 * 1024;

    private readonly byte[] networkId;
    private readonly byte[] nonce;
    private readonly byte[] bootId;
    private readonly byte[] queriedDirectoryLeafKey;

    internal ContactResolveDirectoryIssuedPackage(
        ReadOnlyMemory<byte> networkId,
        ReadOnlyMemory<byte> nonce,
        ReadOnlyMemory<byte> bootId,
        ulong nonceCreatedAt,
        ReadOnlyMemory<byte> queriedDirectoryLeafKey,
        IReadOnlyList<ReadOnlyMemory<byte>> exactXna1AuthorityChain,
        IReadOnlyList<ReadOnlyMemory<byte>> exactDts1PolicyChain,
        ReadOnlyMemory<byte> exactAdh1,
        ReadOnlyMemory<byte> exactDtt1,
        ReadOnlyMemory<byte> exactAdp1,
        IReadOnlyList<ReadOnlyMemory<byte>> exactOrderedXvp1Chain,
        IReadOnlyList<ReadOnlyMemory<byte>> exactOrderedXnv1Chain,
        IReadOnlyList<ReadOnlyMemory<byte>> exactOrderedXnh1Chain,
        IReadOnlyList<ReadOnlyMemory<byte>> exactActiveXnd1,
        IReadOnlyList<ReadOnlyMemory<byte>> exactOrderedPmt2Chain,
        ContactResolveForwardCheckpointPackage? forwardCheckpoint = null)
    {
        _ = ValidateFixed(networkId, 16, nameof(networkId));
        _ = ValidateFixed(bootId, 16, nameof(bootId));
        var total = ValidateChain(
                exactXna1AuthorityChain, MaximumChainArtifacts, nameof(exactXna1AuthorityChain))
            + ValidateChain(
                exactDts1PolicyChain, MaximumChainArtifacts, nameof(exactDts1PolicyChain))
            + ValidateArtifact(exactAdh1, nameof(exactAdh1))
            + ValidateArtifact(exactDtt1, nameof(exactDtt1))
            + ValidateArtifact(exactAdp1, nameof(exactAdp1))
            + ValidateFixed(nonce, 32, nameof(nonce))
            + ValidateFixed(queriedDirectoryLeafKey, 32, nameof(queriedDirectoryLeafKey))
            + ValidateChain(
                exactOrderedXvp1Chain, MaximumChainArtifacts, nameof(exactOrderedXvp1Chain))
            + ValidateChain(
                exactOrderedXnv1Chain, MaximumChainArtifacts, nameof(exactOrderedXnv1Chain))
            + ValidateChain(
                exactOrderedXnh1Chain, MaximumChainArtifacts, nameof(exactOrderedXnh1Chain))
            + ValidateChain(exactActiveXnd1, MaximumChainArtifacts, nameof(exactActiveXnd1))
            + ValidateChain(
                exactOrderedPmt2Chain, MaximumChainArtifacts, nameof(exactOrderedPmt2Chain));
        if (forwardCheckpoint is not null)
        {
            total = checked(total + Sum(forwardCheckpoint.ExactOrderedXnf1Chain)
                + forwardCheckpoint.ExactNfp1.Length
                + forwardCheckpoint.ExactTargetXnv1.Length
                + forwardCheckpoint.ExactTargetXnh1.Length);
        }
        if (total > MaximumPackageBytes)
            throw new ArgumentException($"The ContactResolve directory package exceeds {MaximumPackageBytes} bytes.");

        this.networkId = CopyFixed(networkId, 16, nameof(networkId));
        this.nonce = CopyFixed(nonce, 32, nameof(nonce));
        this.bootId = CopyFixed(bootId, 16, nameof(bootId));
        NonceCreatedAt = nonceCreatedAt;
        this.queriedDirectoryLeafKey = CopyFixed(
            queriedDirectoryLeafKey, 32, nameof(queriedDirectoryLeafKey));
        ExactXna1AuthorityChain = CopyChain(
            exactXna1AuthorityChain, MaximumChainArtifacts, nameof(exactXna1AuthorityChain));
        ExactDts1PolicyChain = CopyChain(
            exactDts1PolicyChain, MaximumChainArtifacts, nameof(exactDts1PolicyChain));
        if (ExactXna1AuthorityChain.Count != ExactDts1PolicyChain.Count)
            throw new ArgumentException("XNA1 and DTS1 authority chains must be positionally complete.");
        ExactAdh1 = CopyArtifact(exactAdh1, nameof(exactAdh1));
        ExactDtt1 = CopyArtifact(exactDtt1, nameof(exactDtt1));
        ExactAdp1 = CopyArtifact(exactAdp1, nameof(exactAdp1));
        ExactOrderedXvp1Chain = CopyChain(
            exactOrderedXvp1Chain, MaximumChainArtifacts, nameof(exactOrderedXvp1Chain));
        ExactOrderedXnv1Chain = CopyChain(
            exactOrderedXnv1Chain, MaximumChainArtifacts, nameof(exactOrderedXnv1Chain));
        ExactOrderedXnh1Chain = CopyChain(
            exactOrderedXnh1Chain, MaximumChainArtifacts, nameof(exactOrderedXnh1Chain));
        if (ExactOrderedXnv1Chain.Count != ExactOrderedXnh1Chain.Count)
            throw new ArgumentException("XNV1 and XNH1 chains must contain exact corresponding pairs.");
        ExactActiveXnd1 = CopyChain(
            exactActiveXnd1, MaximumChainArtifacts, nameof(exactActiveXnd1));
        ExactOrderedPmt2Chain = CopyChain(
            exactOrderedPmt2Chain, MaximumChainArtifacts, nameof(exactOrderedPmt2Chain));
        ForwardCheckpoint = forwardCheckpoint;
    }

    internal ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    internal ReadOnlyMemory<byte> Nonce => nonce.ToArray();
    internal ReadOnlyMemory<byte> BootId => bootId.ToArray();
    internal ulong NonceCreatedAt { get; }
    internal ReadOnlyMemory<byte> QueriedDirectoryLeafKey => queriedDirectoryLeafKey.ToArray();
    internal IReadOnlyList<ReadOnlyMemory<byte>> ExactXna1AuthorityChain { get; }
    internal IReadOnlyList<ReadOnlyMemory<byte>> ExactDts1PolicyChain { get; }
    internal ReadOnlyMemory<byte> ExactAdh1 { get; }
    internal ReadOnlyMemory<byte> ExactDtt1 { get; }
    internal ReadOnlyMemory<byte> ExactAdp1 { get; }
    internal IReadOnlyList<ReadOnlyMemory<byte>> ExactOrderedXvp1Chain { get; }
    internal IReadOnlyList<ReadOnlyMemory<byte>> ExactOrderedXnv1Chain { get; }
    internal IReadOnlyList<ReadOnlyMemory<byte>> ExactOrderedXnh1Chain { get; }
    internal IReadOnlyList<ReadOnlyMemory<byte>> ExactActiveXnd1 { get; }
    internal IReadOnlyList<ReadOnlyMemory<byte>> ExactOrderedPmt2Chain { get; }
    internal ContactResolveForwardCheckpointPackage? ForwardCheckpoint { get; }

    internal static IReadOnlyList<ReadOnlyMemory<byte>> CopyChain(
        IReadOnlyList<ReadOnlyMemory<byte>> values,
        int maximumCount,
        string name)
    {
        ArgumentNullException.ThrowIfNull(values);
        if (values.Count is 0 || values.Count > maximumCount)
            throw new ArgumentException($"{name} must contain 1..{maximumCount} artifacts.", name);
        return Array.AsReadOnly(values.Select(value =>
            (ReadOnlyMemory<byte>)CopyArtifact(value, name)).ToArray());
    }

    internal static ReadOnlyMemory<byte> CopyArtifact(ReadOnlyMemory<byte> value, string name)
    {
        ValidateArtifact(value, name);
        return value.ToArray();
    }

    internal static long ValidateChain(
        IReadOnlyList<ReadOnlyMemory<byte>> values,
        int maximumCount,
        string name)
    {
        ArgumentNullException.ThrowIfNull(values);
        if (values.Count is 0 || values.Count > maximumCount)
            throw new ArgumentException($"{name} must contain 1..{maximumCount} artifacts.", name);
        return values.Aggregate(0L,
            (sum, value) => checked(sum + ValidateArtifact(value, name)));
    }

    internal static int ValidateArtifact(ReadOnlyMemory<byte> value, string name)
    {
        if (value.IsEmpty || value.Length > MaximumSingleArtifactBytes)
            throw new ArgumentException(
                $"{name} entries must contain 1..{MaximumSingleArtifactBytes} bytes.", name);
        return value.Length;
    }

    private static byte[] CopyFixed(ReadOnlyMemory<byte> value, int length, string name)
    {
        ValidateFixed(value, length, name);
        return value.ToArray();
    }

    private static int ValidateFixed(ReadOnlyMemory<byte> value, int length, string name)
    {
        if (value.Length != length || value.Span.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException($"{name} must be exactly {length} non-zero bytes.", name);
        return value.Length;
    }

    private static long Sum(IReadOnlyList<ReadOnlyMemory<byte>> values) =>
        values.Aggregate(0L, static (total, value) => checked(total + value.Length));
}

internal static class ContactResolveDirectoryPackageCodec
{
    internal const string RequestMediaType =
        "application/vnd.deep.contact-resolve-directory-request.v1";
    internal const string ResponseMediaType =
        "application/vnd.deep.contact-resolve-directory.v1";
    internal const int MinimumRequestBytes = 84;
    internal const int AbsoluteMaximumRequestBytes = 333;
    internal const int AbsoluteMaximumEnvelopeBytes =
        (int)ContactResolveDirectoryIssuedPackage.MaximumPackageBytes + (256 * 1024);

    private const ushort Version = 1;
    private const ushort RequestDirectoryFloorFlag = 0x0001;
    private const ushort RequestNetworkFloorFlag = 0x0002;
    private const ushort ResponseForwardFlag = 0x0001;
    private static ReadOnlySpan<byte> RequestMagic => "CDQ1"u8;
    private static ReadOnlySpan<byte> ResponseMagic => "CDR1"u8;

    internal static ContactResolveDirectoryPackageRequest DecodeRequest(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length is < MinimumRequestBytes or > AbsoluteMaximumRequestBytes)
            throw new FormatException("The ContactResolve request length is outside its bound.");
        var reader = new Reader(encoded, AbsoluteMaximumRequestBytes);
        var flags = reader.ReadHeader(
            RequestMagic, RequestDirectoryFloorFlag | RequestNetworkFloorFlag);
        var networkId = reader.ReadFixed(16, true, "network ID");
        var nonce = reader.ReadFixed(32, true, "nonce");
        var bootId = reader.ReadFixed(16, true, "boot ID");
        var nonceCreatedAt = reader.ReadU64();

        ulong? directoryTreeSize = null;
        byte[]? directoryCoreHash = null;
        if ((flags & RequestDirectoryFloorFlag) != 0)
        {
            directoryTreeSize = reader.ReadU64();
            if (directoryTreeSize == 0)
                throw new FormatException("The directory LKG tree size must be non-zero.");
            directoryCoreHash = reader.ReadFixed(32, true, "directory LKG core hash");
        }

        ContactResolveNetworkFloor? networkFloor = null;
        if ((flags & RequestNetworkFloorFlag) != 0)
            networkFloor = ReadNetworkFloor(ref reader);
        reader.EnsureComplete();
        return new ContactResolveDirectoryPackageRequest(
            networkId, nonce, bootId, nonceCreatedAt,
            directoryTreeSize, directoryCoreHash, networkFloor);
    }

    internal static byte[] EncodeResponse(
        ContactResolveDirectoryPackageRequest request,
        ContactResolveDirectoryIssuedPackage package)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(package);
        RequireExact(package.NetworkId.Span, request.NetworkId.Span, "issued network ID");
        RequireExact(package.Nonce.Span, request.Nonce.Span, "issued nonce");
        RequireExact(package.BootId.Span, request.BootId.Span, "issued boot ID");
        if (package.NonceCreatedAt != request.NonceCreatedAt)
            throw new InvalidOperationException("The issuance does not echo the request monotonic sample.");

        var flags = package.ForwardCheckpoint is null ? (ushort)0 : ResponseForwardFlag;
        using var stream = new MemoryStream();
        WriteHeader(stream, ResponseMagic, flags, 0);
        Write(stream, request.NetworkId.Span);
        Write(stream, request.Nonce.Span);
        Write(stream, request.BootId.Span);
        WriteU64(stream, request.NonceCreatedAt);
        Write(stream, package.QueriedDirectoryLeafKey.Span);
        WriteChain(stream, package.ExactXna1AuthorityChain);
        WriteChain(stream, package.ExactDts1PolicyChain);
        WriteArtifact(stream, package.ExactAdh1.Span);
        WriteArtifact(stream, package.ExactDtt1.Span);
        WriteArtifact(stream, package.ExactAdp1.Span);
        WriteChain(stream, package.ExactOrderedXvp1Chain);
        WriteChain(stream, package.ExactOrderedXnv1Chain);
        WriteChain(stream, package.ExactOrderedXnh1Chain);
        WriteChain(stream, package.ExactActiveXnd1);
        WriteChain(stream, package.ExactOrderedPmt2Chain);
        if (package.ForwardCheckpoint is { } forward)
        {
            WriteChain(stream, forward.ExactOrderedXnf1Chain);
            WriteArtifact(stream, forward.ExactNfp1.Span);
            WriteArtifact(stream, forward.ExactTargetXnv1.Span);
            WriteArtifact(stream, forward.ExactTargetXnh1.Span);
        }

        if (stream.Length > AbsoluteMaximumEnvelopeBytes)
            throw new InvalidOperationException("The ContactResolve response exceeds its absolute bound.");
        var encoded = stream.ToArray();
        BinaryPrimitives.WriteUInt32BigEndian(encoded.AsSpan(8, 4), checked((uint)encoded.Length));
        return encoded;
    }

    private static ContactResolveNetworkFloor ReadNetworkFloor(ref Reader reader)
    {
        var head = reader.ReadFixed(38, true, "XNH1 floor reference");
        var treeSize = reader.ReadU64();
        var root = reader.ReadFixed(32, true, "XNH1 floor root");
        var view = reader.ReadFixed(38, true, "XNV1 floor reference");
        var generation = reader.ReadU64();
        var authority = reader.ReadFixed(38, true, "XNA1 floor reference");
        RequireCoreReference(head, "XNH1"u8, "XNH1 floor reference");
        RequireCoreReference(view, "XNV1"u8, "XNV1 floor reference");
        RequireCoreReference(authority, "XNA1"u8, "XNA1 floor reference");
        if (treeSize == 0 || generation == ulong.MaxValue || treeSize != generation + 1)
            throw new FormatException(
                "The protected XNH1 tree size must equal the protected XNV1 generation plus one.");
        var checkpointPresence = reader.ReadByte();
        if (checkpointPresence > 1)
            throw new FormatException("The network checkpoint floor presence flag is invalid.");
        var checkpoint = checkpointPresence == 1
            ? reader.ReadFixed(38, true, "XNF1 floor reference")
            : null;
        ulong? checkpointGeneration = checkpointPresence == 1 ? reader.ReadU64() : null;
        if (checkpoint is not null)
            RequireCoreReference(checkpoint, "XNF1"u8, "XNF1 floor reference");
        return new ContactResolveNetworkFloor(
            head, treeSize, root, view, generation, authority, checkpoint, checkpointGeneration);
    }

    private static void WriteHeader(Stream stream, ReadOnlySpan<byte> magic, ushort flags, uint length)
    {
        Write(stream, magic);
        Span<byte> header = stackalloc byte[8];
        BinaryPrimitives.WriteUInt16BigEndian(header, Version);
        BinaryPrimitives.WriteUInt16BigEndian(header[2..], flags);
        BinaryPrimitives.WriteUInt32BigEndian(header[4..], length);
        Write(stream, header);
    }

    private static void WriteChain(Stream stream, IReadOnlyList<ReadOnlyMemory<byte>> values)
    {
        WriteU32(stream, checked((uint)values.Count));
        foreach (var value in values) WriteArtifact(stream, value.Span);
    }

    private static void WriteArtifact(Stream stream, ReadOnlySpan<byte> value)
    {
        WriteU32(stream, checked((uint)value.Length));
        Write(stream, value);
    }

    private static void WriteU32(Stream stream, uint value)
    {
        Span<byte> bytes = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, value);
        Write(stream, bytes);
    }

    private static void WriteU64(Stream stream, ulong value)
    {
        Span<byte> bytes = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(bytes, value);
        Write(stream, bytes);
    }

    private static void Write(Stream stream, ReadOnlySpan<byte> value) => stream.Write(value);

    private static void RequireExact(ReadOnlySpan<byte> actual, ReadOnlySpan<byte> expected, string name)
    {
        if (actual.Length != expected.Length
            || !CryptographicOperations.FixedTimeEquals(actual, expected))
            throw new InvalidOperationException($"The {name} does not match the request.");
    }

    private static void RequireCoreReference(
        ReadOnlySpan<byte> value,
        ReadOnlySpan<byte> magic,
        string name)
    {
        if (value.Length != 38
            || !value[..4].SequenceEqual(magic)
            || BinaryPrimitives.ReadUInt16BigEndian(value[4..6]) != Version
            || value[6..].IndexOfAnyExcept((byte)0) < 0)
            throw new FormatException($"The {name} is not a canonical version-1 core reference.");
    }

    private ref struct Reader
    {
        private readonly ReadOnlySpan<byte> value;
        private int offset;

        internal Reader(ReadOnlySpan<byte> value, int maximumBytes)
        {
            if (value.Length > maximumBytes)
                throw new FormatException("The ContactResolve envelope exceeds its absolute limit.");
            this.value = value;
            offset = 0;
        }

        internal ushort ReadHeader(ReadOnlySpan<byte> expectedMagic, ushort allowedFlags)
        {
            if (value.Length < 12)
                throw new FormatException("The ContactResolve envelope is truncated.");
            if (!ReadSpan(4).SequenceEqual(expectedMagic)
                || BinaryPrimitives.ReadUInt16BigEndian(ReadSpan(2)) != Version)
                throw new FormatException("The ContactResolve envelope header is invalid.");
            var flags = BinaryPrimitives.ReadUInt16BigEndian(ReadSpan(2));
            if ((flags & ~allowedFlags) != 0)
                throw new FormatException("The ContactResolve envelope has unknown flags.");
            var declared = BinaryPrimitives.ReadUInt32BigEndian(ReadSpan(4));
            if (declared != value.Length)
                throw new FormatException("The ContactResolve envelope length is not canonical.");
            return flags;
        }

        internal byte ReadByte() => ReadSpan(1)[0];
        internal ulong ReadU64() => BinaryPrimitives.ReadUInt64BigEndian(ReadSpan(8));

        internal byte[] ReadFixed(int length, bool nonZero, string name)
        {
            var result = ReadSpan(length);
            if (nonZero && result.IndexOfAnyExcept((byte)0) < 0)
                throw new FormatException($"The {name} must be non-zero.");
            return result.ToArray();
        }

        internal void EnsureComplete()
        {
            if (offset != value.Length)
                throw new FormatException("The ContactResolve envelope has trailing bytes.");
        }

        private ReadOnlySpan<byte> ReadSpan(int length)
        {
            if (length < 0 || offset > value.Length - length)
                throw new FormatException("The ContactResolve envelope is truncated.");
            var result = value.Slice(offset, length);
            offset += length;
            return result;
        }
    }
}

internal readonly struct ContactResolveDirectoryPackageHostingState
{
    private readonly byte[]? expectedNetworkId;

    internal ContactResolveDirectoryPackageHostingState(ReadOnlySpan<byte> expectedNetworkId)
    {
        if (expectedNetworkId.Length != 16 || expectedNetworkId.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException(
                "The ContactResolve network ID must be exactly 16 non-zero bytes.",
                nameof(expectedNetworkId));
        this.expectedNetworkId = expectedNetworkId.ToArray();
    }

    internal ReadOnlyMemory<byte> NetworkId => expectedNetworkId?.ToArray() ?? [];
}

internal static class ContactResolveDirectoryPackageHostingExtensions
{
    internal const string EndpointPath = "/api/v1/directory/contact-resolve-packages";

    internal static ContactResolveDirectoryPackageHostingState AddContactResolveDirectoryPackages(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<ContactResolveIssuanceAdmissionGate>();
#if DEEP_PROTOCOL_DIRECTORY_V1
        services.AddContactResolveProductionAuthority(configuration);
        services.AddFileContactResolveDirectoryArtifactSources(configuration);
        services.TryAddSingleton<IContactResolveDirectoryPackageIssuer>(
            ProductionContactResolveDirectoryPackageIssuer.CreateFailClosed);
#else
        services.TryAddSingleton<IContactResolveDirectoryPackageIssuer,
            UnavailableContactResolveDirectoryPackageIssuer>();
#endif
        var configuredNetwork = configuration["DirectoryPublication:NetworkIdHex"];
        return string.IsNullOrWhiteSpace(configuredNetwork)
            ? default
            : new ContactResolveDirectoryPackageHostingState(
                DirectoryPublicationHostingExtensions.Hex(
                    configuredNetwork, 16, "ContactResolve network ID"));
    }

    internal static void MapContactResolveDirectoryPackageEndpoint(
        this WebApplication app,
        ContactResolveDirectoryPackageHostingState state)
    {
        app.MapPost(EndpointPath, (HttpContext context,
                IContactResolveDirectoryPackageIssuer issuer,
                ContactResolveIssuanceAdmissionGate admission,
                CancellationToken cancellationToken) =>
                HandleAsync(context, issuer, admission, state, cancellationToken))
            .WithMetadata(new RequestSizeLimitAttribute(
                ContactResolveDirectoryPackageCodec.AbsoluteMaximumRequestBytes));
    }

    private static async Task<IResult> HandleAsync(
        HttpContext context,
        IContactResolveDirectoryPackageIssuer issuer,
        ContactResolveIssuanceAdmissionGate admission,
        ContactResolveDirectoryPackageHostingState state,
        CancellationToken cancellationToken)
    {
        SetNoStoreHeaders(context.Response);
        var decision = admission.TryAcquire(context.Connection.RemoteIpAddress);
        if (!decision.IsAccepted)
        {
            context.Response.Headers.RetryAfter = decision.RetryAfterSeconds.ToString(
                System.Globalization.CultureInfo.InvariantCulture);
            return Failure(StatusCodes.Status429TooManyRequests,
                "contact-resolve-rate-limited");
        }
        if (!string.Equals(context.Request.ContentType,
                ContactResolveDirectoryPackageCodec.RequestMediaType,
                StringComparison.OrdinalIgnoreCase))
            return Failure(StatusCodes.Status415UnsupportedMediaType,
                "unsupported-contact-resolve-media-type");
        if (context.Request.ContentLength is not { } declared)
            return Failure(StatusCodes.Status411LengthRequired, "contact-resolve-content-length-required");
        if (declared > ContactResolveDirectoryPackageCodec.AbsoluteMaximumRequestBytes)
            return Failure(StatusCodes.Status413PayloadTooLarge, "contact-resolve-request-too-large");
        if (declared < ContactResolveDirectoryPackageCodec.MinimumRequestBytes)
            return Failure(StatusCodes.Status400BadRequest, "malformed-contact-resolve-request");

        byte[]? encodedRequest = null;
        try
        {
            encodedRequest = await ReadExactAsync(
                context.Request.Body, checked((int)declared), cancellationToken).ConfigureAwait(false);
            var request = ContactResolveDirectoryPackageCodec.DecodeRequest(encodedRequest);
            if (state.NetworkId.IsEmpty)
                return Failure(StatusCodes.Status503ServiceUnavailable,
                    "contact-resolve-issuer-unavailable");
            if (!CryptographicOperations.FixedTimeEquals(
                    request.NetworkId.Span, state.NetworkId.Span))
                return Failure(StatusCodes.Status400BadRequest, "contact-resolve-wrong-network");

            ContactResolveDirectoryIssuedPackage package;
            try
            {
                package = await issuer.IssueAsync(request, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (ContactResolveDirectoryAdmissionException)
            {
                context.Response.Headers.RetryAfter = "10";
                return Failure(StatusCodes.Status429TooManyRequests,
                    "contact-resolve-rate-limited");
            }
            catch (Exception exception) when (exception is
                ContactResolveDirectoryPackageUnavailableException or IOException or
                CryptographicException or InvalidDataException or InvalidOperationException or
                ArgumentException or FormatException or OverflowException)
            {
                return Failure(StatusCodes.Status503ServiceUnavailable,
                    "contact-resolve-issuer-unavailable");
            }

            byte[] encodedResponse;
            try
            {
                encodedResponse = ContactResolveDirectoryPackageCodec.EncodeResponse(request, package);
            }
            catch (Exception exception) when (exception is ArgumentException or
                FormatException or InvalidOperationException or OverflowException)
            {
                return Failure(StatusCodes.Status503ServiceUnavailable,
                    "contact-resolve-issuer-rejected");
            }
            context.Response.ContentLength = encodedResponse.Length;
            return Results.Bytes(
                encodedResponse,
                ContactResolveDirectoryPackageCodec.ResponseMediaType,
                enableRangeProcessing: false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (ContactResolveDirectoryRequestTooLargeException)
        {
            return Failure(StatusCodes.Status413PayloadTooLarge, "contact-resolve-request-too-large");
        }
        catch (Exception exception) when (exception is FormatException or EndOfStreamException)
        {
            return Failure(StatusCodes.Status400BadRequest, "malformed-contact-resolve-request");
        }
        finally
        {
            if (encodedRequest is not null) CryptographicOperations.ZeroMemory(encodedRequest);
        }
    }

    private static async ValueTask<byte[]> ReadExactAsync(
        Stream body,
        int declaredLength,
        CancellationToken cancellationToken)
    {
        var bytes = new byte[declaredLength];
        var offset = 0;
        try
        {
            while (offset < bytes.Length)
            {
                var read = await body.ReadAsync(bytes.AsMemory(offset), cancellationToken)
                    .ConfigureAwait(false);
                if (read == 0) throw new EndOfStreamException();
                offset += read;
            }
            var extra = new byte[1];
            if (await body.ReadAsync(extra, cancellationToken).ConfigureAwait(false) != 0)
                throw new ContactResolveDirectoryRequestTooLargeException();
            return bytes;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(bytes);
            throw;
        }
    }

    private static void SetNoStoreHeaders(HttpResponse response)
    {
        response.Headers.CacheControl = "private,no-store,max-age=0,must-revalidate";
        response.Headers.Pragma = "no-cache";
        response.Headers.Expires = "0";
        response.Headers["X-Content-Type-Options"] = "nosniff";
    }

    private static IResult Failure(int statusCode, string code) =>
        Results.Json(new ContactResolveDirectoryPackageFailure(code), statusCode: statusCode);

    private sealed class ContactResolveDirectoryRequestTooLargeException : IOException;
}

internal sealed class UnavailableContactResolveDirectoryPackageIssuer :
    IContactResolveDirectoryPackageIssuer
{
    public ValueTask<ContactResolveDirectoryIssuedPackage> IssueAsync(
        ContactResolveDirectoryPackageRequest request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromException<ContactResolveDirectoryIssuedPackage>(
            new ContactResolveDirectoryPackageUnavailableException());
    }
}

internal sealed record ContactResolveDirectoryPackageFailure(string Code);
