#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Registry.Api.Tests;

// DID2-only directory heads and signed identity-neutral network view.
// Deterministic keys are test fixtures, not operational custody.
internal sealed class Did2DirectoryAuthorityFixture : IDisposable
{
    private readonly KeyPair root = PublicKeyAuth.GenerateKeyPair(Bytes(0x20, 32));
    private readonly Witness[] witnesses = Enumerable.Range(0, 3).Select(index => new Witness(
        Bytes(checked((byte)(0x40 + index)), 32),
        PublicKeyAuth.GenerateKeyPair(Bytes(checked((byte)(0x50 + index)), 32)),
        Bytes(checked((byte)(0x60 + index)), 32))).ToArray();

    private Did2DirectoryAuthorityFixture()
    {
        Authority = DirectoryNetworkAuthorityFixture.Create(out var xna, out var dts);
        ExactXna1 = xna;
        ExactDts1 = dts;
        ExactCurrentXnv1 = CreateCurrentXnv1(Network, Authority, witnesses);
    }

    internal static Did2DirectoryAuthorityFixture Create() => new();
    internal byte[] Network { get; } = Bytes(0x11, 16);
    internal byte[] ExactXna1 { get; }
    internal byte[] ExactDts1 { get; }
    internal byte[] ExactCurrentXnv1 { get; }
    internal VerifiedXPointNetworkAuthority Authority { get; }
    internal IReadOnlyList<IAccountDirectoryDtt1WitnessSigner> Signers =>
        witnesses.Take(2).Select(value =>
            (IAccountDirectoryDtt1WitnessSigner)new WitnessSigner(value)).ToArray();

    internal byte[] CreateDid2GenesisHead() => AccountDirectoryAdh1Codec.Encode(
        CreateHead(Network, Authority, witnesses, 0, new byte[32], 0,
            AccountDirectoryRfc6962.ComputeEmptyTreeHash(),
            DeepIdV2DirectorySparseMap.EmptyMapRoot.ToArray(),
            minimumReader: 2));

    internal byte[] SignDid2ForwardCheckpoint(
        AccountDirectoryProtectedLkg source,
        AccountDirectoryProtectedLkg target)
    {
        Span<byte> preimage = stackalloc byte[49];
        preimage[0] = 0;
        BinaryPrimitives.WriteUInt64BigEndian(preimage[1..9],
            source.LogGeneration);
        BinaryPrimitives.WriteUInt64BigEndian(preimage[9..17],
            source.TreeSize);
        source.CoreHash.Span.CopyTo(preimage[17..]);
        var coveredRoot = SHA256.HashData(preimage);
        var targetReference = Reference("ADH1", target.CoreHash.Span);
        var placeholder = new[]
        {
            new AccountDirectoryAdf1RootReceipt(Bytes(0x20, 32),
                Bytes(0xaa, 64)),
        };
        var unsigned = new AccountDirectoryAdf1(Network, 0,
            new byte[32], source.LogGeneration, source.LogGeneration,
            1, coveredRoot, targetReference, target.TreeSize,
            target.AppendLogMerkleRoot.Span,
            target.CurrentValueMapRoot.Span,
            Authority.AuthorityCoreReference.Span, 1_700_000_400,
            2, placeholder);
        var signature = PublicKeyAuth.SignDetached(
            AccountDirectoryCrypto.ComputeAdf1SigningInput(unsigned),
            root.PrivateKey);
        return AccountDirectoryAdf1Codec.Encode(new AccountDirectoryAdf1(
            Network, 0, new byte[32], source.LogGeneration,
            source.LogGeneration, 1, coveredRoot, targetReference,
            target.TreeSize, target.AppendLogMerkleRoot.Span,
            target.CurrentValueMapRoot.Span,
            Authority.AuthorityCoreReference.Span, 1_700_000_400,
            2, [new AccountDirectoryAdf1RootReceipt(Bytes(0x20, 32),
                signature)]));
    }


    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(root.PrivateKey);
        foreach (var witness in witnesses)
            CryptographicOperations.ZeroMemory(witness.Key.PrivateKey);
    }

    private static AccountDirectoryAdh1 CreateHead(
        byte[] network,
        VerifiedXPointNetworkAuthority authority,
        Witness[] witnesses,
        ulong generation,
        byte[] predecessor,
        ulong treeSize,
        byte[] appendRoot,
        byte[] mapRoot,
        ushort minimumReader = 1)
    {
        var selected = witnesses.Take(2).OrderBy(static value => value.Id, ByteArrayComparer.Instance).ToArray();
        var placeholders = selected.Select((value, index) => new AccountDirectoryAdh1WitnessEntry(
            value.Id, Bytes(checked((byte)(0x70 + index)), 64))).ToArray();
        var unsigned = new AccountDirectoryAdh1(
            network, generation, predecessor, treeSize, appendRoot, mapRoot,
            authority.AuthorityCoreReference.Span, authority.DirectoryWitnessPolicyHash.Span,
            1_700_000_000, 1_700_010_000, minimumReader, placeholders);
        var input = AccountDirectoryCrypto.ComputeAdh1SigningInput(unsigned);
        var receipts = selected.Select(value => new AccountDirectoryAdh1WitnessEntry(
            value.Id, PublicKeyAuth.SignDetached(input, value.Key.PrivateKey))).ToArray();
        CryptographicOperations.ZeroMemory(input);
        return new AccountDirectoryAdh1(
            network, generation, predecessor, treeSize, appendRoot, mapRoot,
            authority.AuthorityCoreReference.Span, authority.DirectoryWitnessPolicyHash.Span,
            1_700_000_000, 1_700_010_000, minimumReader, receipts);
    }

    private static byte[] CreateCurrentXnv1(
        byte[] network,
        VerifiedXPointNetworkAuthority authority,
        Witness[] witnesses)
    {
        ReadOnlyMemory<byte>[] fields =
        [
            network, U64(0), new byte[32], Bytes(0x91, 32), U64(1), Bytes(0x92, 32),
            authority.AuthorityCoreReference, authority.DirectoryWitnessPolicyHash,
            Reference("XVP1", Bytes(0x93, 32)), U16(1), U16(3),
            Join(Reference("XND1", Bytes(0x94, 32)), Reference("XND1", Bytes(0x95, 32)),
                Reference("XND1", Bytes(0x96, 32))),
            U16(0), ReadOnlyMemory<byte>.Empty, U16(0), ReadOnlyMemory<byte>.Empty,
            U16(1), Reference("XCB1", Bytes(0x97, 32)),
            U64(1), U64(1_699_999_000), U64(1_700_010_000), U16(1), new byte[] { 2 },
            Join(witnesses[0].Id, Bytes(0xa1, 64), witnesses[1].Id, Bytes(0xa2, 64)),
        ];
        var provisional = XPointNetworkCodec.Parse<Xnv1Record>(
            XPointNetworkCodec.Write(XPointNetworkRegistry.Xnv1, fields));
        var input = XPointNetworkCrypto.ComputeSigningInput(provisional);
        fields[23] = Join(
            witnesses[0].Id, PublicKeyAuth.SignDetached(input, witnesses[0].Key.PrivateKey),
            witnesses[1].Id, PublicKeyAuth.SignDetached(input, witnesses[1].Key.PrivateKey));
        CryptographicOperations.ZeroMemory(input);
        return XPointNetworkCodec.Write(XPointNetworkRegistry.Xnv1, fields);
    }


    private static byte[] Bytes(byte value, int length) => Enumerable.Repeat(value, length).ToArray();
    private static byte[] Reference(string magic, ReadOnlySpan<byte> hash)
    {
        var result = new byte[38];
        Encoding.ASCII.GetBytes(magic).CopyTo(result, 0);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(4), 1);
        hash.CopyTo(result.AsSpan(6));
        return result;
    }
    private static byte[] Join(params byte[][] values)
    {
        var result = new byte[values.Sum(static value => value.Length)];
        var offset = 0;
        foreach (var value in values) { value.CopyTo(result, offset); offset += value.Length; }
        return result;
    }
    private static byte[] U16(ushort value) { var result = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(result, value); return result; }
    private static byte[] U32(uint value) { var result = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(result, value); return result; }
    private static byte[] U64(ulong value) { var result = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(result, value); return result; }

    private sealed record Witness(byte[] Id, KeyPair Key, byte[] FailureDomain);

    private sealed class WitnessSigner(Witness witness) : IAccountDirectoryDtt1WitnessSigner
    {
        public ReadOnlyMemory<byte> WitnessId => witness.Id.ToArray();
        public ValueTask<ReadOnlyMemory<byte>> SignDtt1Async(
            ReadOnlyMemory<byte> signingInput,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult<ReadOnlyMemory<byte>>(
                PublicKeyAuth.SignDetached(signingInput.ToArray(), witness.Key.PrivateKey));
        }
    }
    private sealed class ByteArrayComparer : IComparer<byte[]>
    {
        internal static readonly ByteArrayComparer Instance = new();
        public int Compare(byte[]? left, byte[]? right) => left.AsSpan().SequenceCompareTo(right);
    }
}
#endif
