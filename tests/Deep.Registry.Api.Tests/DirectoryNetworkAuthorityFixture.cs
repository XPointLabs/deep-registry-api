#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Registry.Api.Tests;

// Only signed identity-neutral network/time authority. No account, directory proof,
// topology, dispatch or device capability is supplied by this fixture.
internal static class DirectoryNetworkAuthorityFixture
{
    internal static VerifiedXPointNetworkAuthority Create() => Create(out _, out _);

    internal static VerifiedXPointNetworkAuthority Create(out byte[] exactXna1, out byte[] exactDts1)
    {
        var network = Bytes(0x11, 16);
        var root = PublicKeyAuth.GenerateKeyPair(Bytes(0x20, 32));
        var witnesses = Enumerable.Range(0, 3).Select(index => new Witness(
            Bytes(checked((byte)(0x40 + index)), 32),
            PublicKeyAuth.GenerateKeyPair(Bytes(checked((byte)(0x50 + index)), 32)),
            Bytes(checked((byte)(0x60 + index)), 32))).ToArray();
        try
        {
            var dts = CreateDts1(network, root);
            var policyHash = AccountDirectoryCrypto.ComputeDts1PolicyHash(
                AccountDirectoryDts1Codec.Decode(dts));
            var xna = CreateXna1(network, root, witnesses, policyHash);
            exactXna1 = xna;
            exactDts1 = dts;
            var parsed = XPointNetworkCodec.Parse<Xna1Record>(xna);
            return XPointNetworkAuthorityVerifier.Verify(
                new XPointNetworkGenesisPin(network, parsed.CoreHash.Span), [xna], [dts]);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(root.PrivateKey);
            foreach (var witness in witnesses)
                CryptographicOperations.ZeroMemory(witness.Key.PrivateKey);
        }
    }

    private static byte[] CreateDts1(byte[] network, KeyPair root)
    {
        var sources = new[]
        {
            new AccountDirectoryDts1Source(Bytes(0x10, 32), Bytes(0x12, 32), 1,
                "time-a.example", 443, Bytes(0x14, 32), 5),
            new AccountDirectoryDts1Source(Bytes(0x11, 32), Bytes(0x13, 32), 1,
                "time-b.example", 443, Bytes(0x15, 32), 5),
        };
        var rootId = Bytes(0x20, 32);
        var unsigned = new AccountDirectoryDts1(
            network, 0, new byte[32], sources, 2, 2, 30, 5,
            1_699_000_000, 1_701_000_000, 1, 0,
            [new AccountDirectoryDts1RootReceipt(rootId, Bytes(0x21, 64))]);
        var signature = PublicKeyAuth.SignDetached(
            AccountDirectoryCrypto.ComputeDts1SigningInput(unsigned), root.PrivateKey);
        return AccountDirectoryDts1Codec.Encode(new AccountDirectoryDts1(
            network, 0, new byte[32], sources, 2, 2, 30, 5,
            1_699_000_000, 1_701_000_000, 1, 0,
            [new AccountDirectoryDts1RootReceipt(rootId, signature)]));
    }


    private static byte[] CreateXna1(
        byte[] network,
        KeyPair root,
        Witness[] witnesses,
        byte[] policyHash)
    {
        ReadOnlyMemory<byte>[] fields = new ReadOnlyMemory<byte>[20];
        fields[0] = network; fields[1] = U64(0); fields[2] = new byte[32]; fields[3] = new byte[] { 1 };
        fields[4] = Join(Bytes(0x20, 32), U64(0), root.PublicKey); fields[5] = new byte[] { 1 };
        fields[6] = U64(0); fields[7] = U16(1); fields[8] = new byte[] { 3 };
        fields[9] = Join(witnesses.Select(value => Join(
            value.Id, U64(0), value.Key.PublicKey, value.FailureDomain)).ToArray());
        fields[10] = new byte[] { 2 }; fields[11] = Reference("DTS1", policyHash); fields[12] = policyHash;
        fields[13] = U32(30); fields[14] = U64(1); fields[15] = U64(1_699_000_000);
        fields[16] = U64(1_699_000_000); fields[17] = U64(1_710_000_000); fields[18] = new byte[] { 1 };
        fields[19] = Join(Bytes(0x20, 32), Bytes(0x22, 64));
        var unsigned = XPointNetworkCodec.Parse<Xna1Record>(
            XPointNetworkCodec.Write(XPointNetworkRegistry.Xna1, fields));
        fields[19] = Join(Bytes(0x20, 32), PublicKeyAuth.SignDetached(
            XPointNetworkCrypto.ComputeSigningInput(unsigned), root.PrivateKey));
        return XPointNetworkCodec.Write(XPointNetworkRegistry.Xna1, fields);
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

}
#endif
