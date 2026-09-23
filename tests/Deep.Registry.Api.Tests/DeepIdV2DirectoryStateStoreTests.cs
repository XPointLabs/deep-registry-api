#if DEEP_PROTOCOL_DIRECTORY_V1
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Registry.Api.DirectoryPublication;

namespace Deep.Registry.Api.Tests;

public sealed class DeepIdV2DirectoryStateStoreTests
{
    [Fact]
    public async Task Ada2RequiresExplicitProvisioningAndHmacAuthenticatedState()
    {
        using var fixture = ContactResolveAuthoringFixture.Create(currentValue: false);
        var root = Path.Combine(Path.GetTempPath(),
            "deep-ada2-store", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var headPath = Path.Combine(root, "did2-genesis.adh1");
            var statePath = Path.Combine(root, "authority.ada2");
            var exactHead = fixture.CreateDid2GenesisHead();
            var hash = AccountDirectoryCrypto.ComputeAdh1CoreHash(
                AccountDirectoryAdh1Codec.Decode(exactHead));
            var key = Enumerable.Repeat((byte)0x5a, 32).ToArray();
            await File.WriteAllBytesAsync(headPath, exactHead);
            using var store = new DeepIdV2DirectoryStateStore(statePath, key,
                fixture.Network,
                new DeepIdV2DirectoryBootstrapSource(headPath, hash),
                fixture.Authority, new DenyingVerifier(), 1);

            using (var lease = store.Open())
                Assert.Throws<InvalidDataException>(() =>
                    lease.Read(1_700_000_100));

            var rows = new DeepIdV2DirectoryStateRows(
                [new DeepIdV2DirectoryHeadRow(exactHead, hash)], [], []);
            var payload = DeepIdV2DirectoryStateCodec.Encode(fixture.Network, rows);
            await File.WriteAllBytesAsync(statePath,
                DirectoryPublicationProtectedFile.Protect(payload, key));
            using (var lease = store.Open())
            {
                var restored = lease.Read(1_700_000_100);
                Assert.Equal(exactHead, restored.CurrentHead.ExactAdh1.ToArray());
                Assert.Throws<InvalidDataException>(() => lease.Write(
                    new DeepIdV2DirectoryStateRows(
                        [new DeepIdV2DirectoryHeadRow(exactHead,
                            Enumerable.Repeat((byte)0x77, 32).ToArray())], [], []),
                    1_700_000_100));
                _ = lease.Write(rows, 1_700_000_100);
            }

            var damaged = await File.ReadAllBytesAsync(statePath);
            damaged[^1] ^= 1;
            await File.WriteAllBytesAsync(statePath, damaged);
            using (var lease = store.Open())
                Assert.Throws<System.Security.Cryptography.CryptographicException>(
                    () => lease.Read(1_700_000_100));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private sealed class DenyingVerifier : IDeepMlDsa65Verifier
    {
        public bool Verify(ReadOnlySpan<byte> publicKey1952,
            ReadOnlySpan<byte> message, ReadOnlySpan<byte> context,
            ReadOnlySpan<byte> signature3309) => false;
    }
}
#endif
