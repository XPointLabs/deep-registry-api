#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Registry.Api.Tests;

internal sealed partial class Did2DirectoryAuthorityFixture
{
    // Synthetic rotation bytes exercise the existing pinned verifier/runtime.
    // This is not a production authoring command or retained private custody.
    internal (byte[] Xna, byte[] Dts, byte[] View) RotateAuthority(
        ReadOnlyMemory<byte> priorXna, ReadOnlyMemory<byte> priorDts,
        ReadOnlyMemory<byte> priorView, ulong observed)
    {
        var nextRoot = PublicKeyAuth.GenerateKeyPair(Bytes(0x25, 32));
        var nextWitnesses = Enumerable.Range(0, 3).Select(index => new Witness(
            Bytes(checked((byte)(0x44 + index)), 32),
            PublicKeyAuth.GenerateKeyPair(Bytes(checked((byte)(0x54 + index)), 32)),
            Bytes(checked((byte)(0x64 + index)), 32))).ToArray();
        try
        {
            var predecessor = XPointNetworkCodec.Parse<Xna1Record>(priorXna.Span);
            var policy = AccountDirectoryDts1Codec.Decode(priorDts.Span);
            var generation = checked(predecessor.AuthorityGeneration + 1);
            AccountDirectoryDts1 Policy(IReadOnlyList<AccountDirectoryDts1RootReceipt> receipts) => new(
                Network, checked(policy.PolicyGeneration + 1), AccountDirectoryCrypto.ComputeDts1PolicyHash(policy),
                policy.Sources, policy.RequiredSourceCount, policy.RequiredDistinctFailureFamilies,
                policy.MaximumIntervalWidthSeconds, policy.MaximumSourceSampleAgeSeconds,
                observed - 5, observed + 2_000_000, policy.MinimumReader, generation, receipts);
            var unsignedPolicy = Policy([new(Bytes(0x24, 32), Bytes(1, 64))]);
            var policyInput = AccountDirectoryCrypto.ComputeDts1SigningInput(unsignedPolicy);
            byte[] dts;
            try
            {
                dts = AccountDirectoryDts1Codec.Encode(Policy([new(Bytes(0x24, 32),
                    PublicKeyAuth.SignDetached(policyInput, nextRoot.PrivateKey))]));
            }
            finally { CryptographicOperations.ZeroMemory(policyInput); }
            var policyHash = AccountDirectoryCrypto.ComputeDts1PolicyHash(AccountDirectoryDts1Codec.Decode(dts));
            var fields = Enumerable.Range(1, 20).Select(tag => (ReadOnlyMemory<byte>)predecessor.FieldSpan(tag).ToArray()).ToArray();
            fields[1] = U64(generation); fields[2] = predecessor.CoreHash.ToArray();
            fields[4] = Join(Bytes(0x24, 32), U64(0), nextRoot.PublicKey);
            fields[6] = U64(checked(predecessor.UInt64(7) + 1));
            fields[9] = Join(nextWitnesses.Select(value => Join(value.Id, U64(0), value.Key.PublicKey, value.FailureDomain)).ToArray());
            fields[11] = Reference("DTS1", policyHash); fields[12] = policyHash;
            fields[15] = U64(observed - 5); fields[16] = U64(observed - 5);
            fields[19] = Join(Bytes(0x20, 32), Bytes(1, 64));
            var unsigned = XPointNetworkCodec.Parse<Xna1Record>(XPointNetworkCodec.Write(XPointNetworkRegistry.Xna1, fields));
            var input = XPointNetworkCrypto.ComputeSigningInput(unsigned);
            try { fields[19] = Join(Bytes(0x20, 32), PublicKeyAuth.SignDetached(input, root.PrivateKey)); }
            finally { CryptographicOperations.ZeroMemory(input); }
            var xna = XPointNetworkCodec.Write(XPointNetworkRegistry.Xna1, fields);
            var authority = XPointNetworkAuthorityVerifier.Verify(new(Network, Authority.AuthorityCoreHash.Span),
                [ExactXna1, priorXna, xna], [ExactDts1, priorDts, dts]);
            var previousView = XPointNetworkCodec.Parse<Xnv1Record>(priorView.Span);
            var view = CreateCurrentXnv1(Network, authority, nextWitnesses, observed - 5,
                observed + 7_200, previousView.CoreHash.ToArray(), checked(previousView.ViewGeneration + 1));
            return (xna, dts, view);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(nextRoot.PrivateKey);
            foreach (var witness in nextWitnesses) CryptographicOperations.ZeroMemory(witness.Key.PrivateKey);
        }
    }
}
#endif
