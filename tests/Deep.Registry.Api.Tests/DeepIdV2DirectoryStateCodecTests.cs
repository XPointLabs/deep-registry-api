#if DEEP_PROTOCOL_DIRECTORY_V1
using Deep.Protocol.AccountDirectoryV1;
using Deep.Registry.Api.DirectoryPublication;

namespace Deep.Registry.Api.Tests;

public sealed class DeepIdV2DirectoryStateCodecTests
{
    [Fact]
    public void Ada2RoundTripsOnlyV2RowsAndRejectsAda1OrSubstitutedNetwork()
    {
        using var fixture = ContactResolveAuthoringFixture.Create(currentValue: false);
        var exact = fixture.CreateDid2GenesisHead();
        var hash = AccountDirectoryCrypto.ComputeAdh1CoreHash(
            AccountDirectoryAdh1Codec.Decode(exact));
        var state = new DeepIdV2DirectoryStateRows(
            [new DeepIdV2DirectoryHeadRow(exact, hash)], [], []);
        var payload = DeepIdV2DirectoryStateCodec.Encode(fixture.Network, state);

        Assert.Equal("ADA2"u8.ToArray(), payload[..4]);
        var decoded = DeepIdV2DirectoryStateCodec.Decode(payload, fixture.Network);
        Assert.Equal(exact, Assert.Single(decoded.Heads).ExactAdh1.ToArray());
        Assert.Empty(decoded.Transitions);
        Assert.Empty(decoded.Admissions);

        var oldMagic = payload.ToArray();
        "ADA1"u8.CopyTo(oldMagic);
        Assert.Throws<InvalidDataException>(() =>
            DeepIdV2DirectoryStateCodec.Decode(oldMagic, fixture.Network));
        Assert.Throws<InvalidDataException>(() =>
            DeepIdV2DirectoryStateCodec.Decode(payload,
                Enumerable.Repeat((byte)0x75, 16).ToArray()));
        Assert.Throws<InvalidDataException>(() =>
            DeepIdV2DirectoryStateCodec.Decode(payload[..^1], fixture.Network));
        Assert.Throws<InvalidDataException>(() =>
            DeepIdV2DirectoryStateCodec.Decode([.. payload, (byte)0x01],
                fixture.Network));

        var legacyHead = fixture.Snapshot.CurrentDirectoryHead;
        Assert.Throws<ArgumentException>(() =>
            DeepIdV2DirectoryStateCodec.Encode(fixture.Network,
                new DeepIdV2DirectoryStateRows(
                    [new DeepIdV2DirectoryHeadRow(
                        legacyHead.ExactAdh1, legacyHead.CoreHash)], [], [])));
    }
}
#endif
