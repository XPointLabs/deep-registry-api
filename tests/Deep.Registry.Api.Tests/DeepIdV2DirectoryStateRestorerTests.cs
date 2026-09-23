#if DEEP_PROTOCOL_DIRECTORY_V1
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Registry.Api.DirectoryPublication;

namespace Deep.Registry.Api.Tests;

public sealed class DeepIdV2DirectoryStateRestorerTests
{
    [Fact]
    public void AuthenticatedEmptyAda2RestoresOnlyAgainstItsPinnedV2Genesis()
    {
        using var fixture = ContactResolveAuthoringFixture.Create(currentValue: false);
        var exact = fixture.CreateDid2GenesisHead();
        var hash = AccountDirectoryCrypto.ComputeAdh1CoreHash(
            AccountDirectoryAdh1Codec.Decode(exact));
        var genesis = DeepIdV2DirectoryBootstrapVerifier.RestoreGenesis(
            fixture.Authority, exact, hash);
        var rows = new DeepIdV2DirectoryStateRows(
            [new DeepIdV2DirectoryHeadRow(exact, hash)], [], []);

        var restored = DeepIdV2DirectoryStateRestorer.Restore(
            fixture.Authority, genesis, rows, 1_700_000_100, 1,
            new DenyingVerifier());
        Assert.Equal(exact, restored.CurrentHead.ExactAdh1.ToArray());
        Assert.Empty(restored.CurrentCheckpoints);

        var substituted = new DeepIdV2DirectoryStateRows(
            [new DeepIdV2DirectoryHeadRow(exact,
                Enumerable.Repeat((byte)0x77, 32).ToArray())], [], []);
        Assert.Throws<InvalidDataException>(() =>
            DeepIdV2DirectoryStateRestorer.Restore(
                fixture.Authority, genesis, substituted, 1_700_000_100, 1,
                new DenyingVerifier()));
        Assert.Throws<InvalidDataException>(() =>
            DeepIdV2DirectoryStateRestorer.Restore(
                fixture.Authority, genesis,
                new DeepIdV2DirectoryStateRows([], [], []),
                1_700_000_100, 1, new DenyingVerifier()));
    }

    private sealed class DenyingVerifier : IDeepMlDsa65Verifier
    {
        public bool Verify(ReadOnlySpan<byte> publicKey1952,
            ReadOnlySpan<byte> message, ReadOnlySpan<byte> context,
            ReadOnlySpan<byte> signature3309) => false;
    }
}
#endif
