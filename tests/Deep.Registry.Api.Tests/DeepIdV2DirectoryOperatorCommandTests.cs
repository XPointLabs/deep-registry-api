#if DEEP_PROTOCOL_DIRECTORY_V1
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.XPointNetworkV1;
using Deep.Registry.Api.DirectoryPublication;
using Microsoft.Extensions.Configuration;

namespace Deep.Registry.Api.Tests;

public sealed class DeepIdV2DirectoryOperatorCommandTests
{
    [Fact]
    public async Task ProvisionsOnlyPinnedEmptyAda2AndNeverOverwritesIt()
    {
        using var fixture = ContactResolveAuthoringFixture.Create(currentValue: false);
        var root = Path.Combine(Path.GetTempPath(),
            "deep-did2-provision", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var authorityPath = Path.Combine(root, "genesis.xna1");
            var policyPath = Path.Combine(root, "genesis.dts1");
            var headPath = Path.Combine(root, "genesis.adh1");
            var statePath = Path.Combine(root, "authority.ada2");
            var keyPath = Path.Combine(root, "authority.key");
            var head = fixture.CreateDid2GenesisHead();
            var headPin = AccountDirectoryCrypto.ComputeAdh1CoreHash(
                AccountDirectoryAdh1Codec.Decode(head));
            var networkPin = XPointNetworkCodec.Parse<Xna1Record>(
                fixture.ExactXna1).CoreHash.ToArray();
            var key = Enumerable.Repeat((byte)0x5a, 32).ToArray();
            await File.WriteAllBytesAsync(authorityPath, fixture.ExactXna1);
            await File.WriteAllBytesAsync(policyPath, fixture.ExactDts1);
            await File.WriteAllBytesAsync(headPath, head);
            await File.WriteAllBytesAsync(keyPath, key);
            var config = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["DeepIdV2DirectoryAuthority:NetworkIdHex"] =
                        Convert.ToHexString(fixture.Network),
                    ["DeepIdV2DirectoryAuthority:GenesisAuthorityCoreHashHex"] =
                        Convert.ToHexString(networkPin),
                    ["DeepIdV2DirectoryAuthority:ExactAuthorityPaths:0"] =
                        authorityPath,
                    ["DeepIdV2DirectoryAuthority:ExactTimePolicyPaths:0"] =
                        policyPath,
                    ["DeepIdV2DirectoryAuthority:GenesisHeadPath"] = headPath,
                    ["DeepIdV2DirectoryAuthority:GenesisHeadCoreHashHex"] =
                        Convert.ToHexString(headPin),
                    ["DeepIdV2DirectoryAuthority:StatePath"] = statePath,
                    ["DeepIdV2DirectoryAuthority:IntegrityKeyPath"] = keyPath
                }).Build();
            Assert.Equal(0, DeepIdV2DirectoryOperatorCommand.TryRun(
                ["did2-directory", "provision-state"], config));
            var encoded = await File.ReadAllBytesAsync(statePath);
            var rows = DeepIdV2DirectoryStateCodec.Decode(
                DirectoryPublicationProtectedFile.Verify(encoded, key),
                fixture.Network);
            Assert.Single(rows.Heads);
            Assert.Empty(rows.Transitions);
            Assert.Empty(rows.Admissions);
            Assert.Equal(head, rows.Heads[0].ExactAdh1.ToArray());
            Assert.Equal(2, DeepIdV2DirectoryOperatorCommand.TryRun(
                ["did2-directory", "provision-state"], config));
            Assert.Equal(encoded, await File.ReadAllBytesAsync(statePath));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }
}
#endif
