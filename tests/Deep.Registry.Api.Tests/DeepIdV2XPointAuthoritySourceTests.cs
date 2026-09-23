#if DEEP_PROTOCOL_DIRECTORY_V1
using Deep.Protocol.XPointNetworkV1;
using Deep.Registry.Api.DirectoryPublication;

namespace Deep.Registry.Api.Tests;

public sealed class DeepIdV2XPointAuthoritySourceTests
{
    [Fact]
    public async Task ReadsPinnedNetworkAuthorityWithoutAnAda1DirectoryPackage()
    {
        using var fixture = ContactResolveAuthoringFixture.Create(currentValue: false);
        var root = Path.Combine(Path.GetTempPath(),
            "deep-did2-authority-source", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var authorityPath = Path.Combine(root, "genesis.xna1");
            var policyPath = Path.Combine(root, "genesis.dts1");
            await File.WriteAllBytesAsync(authorityPath, fixture.ExactXna1);
            await File.WriteAllBytesAsync(policyPath, fixture.ExactDts1);
            var pin = XPointNetworkCodec.Parse<Xna1Record>(fixture.ExactXna1)
                .CoreHash.ToArray();
            var source = new DeepIdV2XPointAuthoritySource(fixture.Network,
                pin, [authorityPath], [policyPath]);
            var verified = source.Read();
            Assert.Equal(fixture.Authority.AuthorityCoreReference.ToArray(),
                verified.AuthorityCoreReference.ToArray());

            var wrongPin = pin.ToArray();
            wrongPin[0] ^= 0x80;
            Assert.Throws<XPointNetworkAuthorityVerificationException>(() =>
                new DeepIdV2XPointAuthoritySource(fixture.Network,
                    wrongPin, [authorityPath], [policyPath]).Read());

            var tamperedPolicy = fixture.ExactDts1.ToArray();
            tamperedPolicy[^1] ^= 1;
            await File.WriteAllBytesAsync(policyPath, tamperedPolicy);
            Assert.Throws<XPointNetworkAuthorityVerificationException>(() =>
                source.Read());
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }
}
#endif
