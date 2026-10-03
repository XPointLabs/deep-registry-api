#if DEEP_PROTOCOL_DIRECTORY_V1
using Deep.Protocol.AccountDirectoryV1;
using Deep.Registry.Api.DirectoryPublication;

namespace Deep.Registry.Api.Tests;

public sealed class DeepIdV2DirectoryBootstrapSourceTests
{
    [Fact]
    public async Task SeparatelyPinnedDid2HeadRestoresAndWrongPinRejects()
    {
        using var fixture = Did2DirectoryAuthorityFixture.Create();
        var root = Path.Combine(Path.GetTempPath(),
            "deep-did2-bootstrap", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var path = Path.Combine(root, "did2-genesis.adh1");
            var did2 = fixture.CreateDid2GenesisHead();
            var head = AccountDirectoryAdh1Codec.Decode(did2);
            var pin = AccountDirectoryCrypto.ComputeAdh1CoreHash(head);
            await File.WriteAllBytesAsync(path, did2);

            var restored = new DeepIdV2DirectoryBootstrapSource(path, pin)
                .Read(fixture.Authority);
            Assert.Equal(did2, restored.ExactAdh1.ToArray());
            Assert.Equal((ushort)2, restored.Head.MinimumReader);

            Assert.Equal("PersistedLkgHashMismatch",
                Assert.Throws<AccountDirectoryFreshnessVerificationException>(() =>
                    new DeepIdV2DirectoryBootstrapSource(path,
                        Enumerable.Repeat((byte)0x77, 32).ToArray())
                        .Read(fixture.Authority)).Code);

        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }
}
#endif
