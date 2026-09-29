#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.XPointNetworkV1;
using Deep.Registry.Api.DirectoryPublication;
using Microsoft.Extensions.Logging.Abstractions;

namespace Deep.Registry.Api.Tests;

public sealed class AutomaticNtsTrustedTimeSourceTests
{
    [Fact]
    public async Task RestartRequiresReattestationEvenWhenUptimeIncreasedAndRetainsLowerFloor()
    {
        using var world = new World();
        using (var first = world.Create())
        {
            await Assert.ThrowsAsync<ContactResolveDirectoryPackageUnavailableException>(async () => await first.ReadAsync(default));
            first.AcceptObservations(world.Authority, world.Policy, world.Observations(1_700_000_100), 1_000, 1_000);
            world.Sample = 1_001;
            Assert.Equal(1_700_000_101UL, (await first.ReadAsync(default)).ObservedUnixTime);
        }
        using var restarted = world.Create();
        await Assert.ThrowsAsync<ContactResolveDirectoryPackageUnavailableException>(async () => await restarted.ReadAsync(default));
        // Authenticated intervals overlapping the retained floor are valid;
        // integer enclosure must not lose a second from that lower bound.
        restarted.AcceptObservations(world.Authority, world.Policy,
            world.Observations(1_700_000_100), 1_001, 1_001);
        var overlapping = await restarted.ReadAsync(default);
        Assert.True(overlapping.ObservedUnixTime - overlapping.UncertaintySeconds >= 1_700_000_100UL);
        Assert.Throws<CryptographicException>(() => restarted.AcceptObservations(
            world.Authority, world.Policy, world.Observations(1_700_000_098), 1_001, 1_001));
        world.Sample = 1_011;
        restarted.AcceptObservations(world.Authority, world.Policy, world.Observations(1_700_000_110), 1_011, 1_011);
        var current = await restarted.ReadAsync(default);
        Assert.True(current.ObservedUnixTime - current.UncertaintySeconds <= 1_700_000_110UL);
        Assert.True(current.ObservedUnixTime + current.UncertaintySeconds >= 1_700_000_110UL);
        Assert.True(current.ObservedUnixTime - current.UncertaintySeconds >= 1_700_000_100UL);
    }

    [Fact]
    public async Task SourceLossExpiresWithoutFloorResetAndReturningQuorumRecovers()
    {
        using var world = new World();
        using var source = world.Create();
        source.AcceptObservations(world.Authority, world.Policy, world.Observations(1_700_000_100), 1_000, 1_000);
        world.Sample = 1_000UL + world.Policy.MaximumSourceSampleAgeSeconds + 1;
        await Assert.ThrowsAsync<ContactResolveDirectoryPackageUnavailableException>(async () => await source.ReadAsync(default));
        source.AcceptObservations(world.Authority, world.Policy, world.Observations(1_700_000_200), world.Sample, world.Sample);
        Assert.Equal(1_700_000_200UL, (await source.ReadAsync(default)).ObservedUnixTime);
        world.Sample--;
        await Assert.ThrowsAsync<ContactResolveDirectoryPackageUnavailableException>(async () => await source.ReadAsync(default));
    }

    [Fact]
    public void MissingDuplicateUnpinnedConflictingOrOversizedSamplesNeverPublish()
    {
        using var world = new World();
        using var source = world.Create();
        var samples = world.Observations(1_700_000_100);
        var hostile = new[]
        {
            samples[..1], new[] { samples[0], samples[0] },
            new[] { samples[0], samples[1] with { Id = new string('f',64) } },
            new[] { samples[0], samples[1] with { UnixSeconds = 1_700_000_200 } },
            new[] { samples[0], samples[1] with { RadiusSeconds = 11 } },
        };
        foreach (var sample in hostile)
            Assert.Throws<CryptographicException>(() => source.AcceptObservations(world.Authority,world.Policy,sample,1_000,1_000));
        Assert.Throws<CryptographicException>(() => source.AcceptObservations(world.Authority,world.Policy,samples,1_001,1_000));
        Assert.Throws<CryptographicException>(() => source.AcceptObservations(world.Authority,world.Policy,samples,1_000,1_031));
        Assert.Equal(world.InitialFloor, File.ReadAllBytes(world.FloorPath));
    }

    [Fact]
    public void TamperedProtectedFloorCannotBeReinitialized()
    {
        using var world = new World();
        using (var source = world.Create())
            source.AcceptObservations(world.Authority,world.Policy,world.Observations(1_700_000_100),1_000,1_000);
        var bytes = File.ReadAllBytes(world.FloorPath); bytes[^1] ^= 1;
        File.WriteAllBytes(world.FloorPath,bytes);
        Assert.Throws<CryptographicException>(() => world.Create());
    }

    [Fact]
    public void MissingFloorAfterRestartOrDuringAcquisitionIsNeverReset()
    {
        using var world = new World();
        using var source = world.Create();
        File.Delete(world.FloorPath);
        Assert.Throws<InvalidDataException>(() => world.Create());
        Assert.Throws<InvalidDataException>(() => source.AcceptObservations(world.Authority,
            world.Policy,world.Observations(1_700_000_100),1_000,1_000));
        Assert.False(File.Exists(world.FloorPath));
    }

    [Fact]
    public void ExplicitProvisioningRefusesExistingFloorWithoutChangingIt()
    {
        using var world = new World();
        Assert.Throws<IOException>(() => world.Provision());
        Assert.Equal(world.InitialFloor,File.ReadAllBytes(world.FloorPath));
    }

    private sealed class World : IDisposable
    {
        private readonly ContactResolveAuthoringFixture fixture = ContactResolveAuthoringFixture.Create(currentValue:false);
        private readonly string root = Path.Combine(Path.GetTempPath(), "deep-nts-unit-" + Guid.NewGuid().ToString("N"));
        private readonly byte[] key = RandomNumberGenerator.GetBytes(32);
        private readonly DeepIdV2XPointAuthoritySource authoritySource;
        internal ulong Sample = 1_000;
        internal string FloorPath => Path.Combine(root,"nts-floor.bin");
        internal VerifiedXPointNetworkAuthority Authority => fixture.Authority;
        internal AccountDirectoryDts1 Policy => AccountDirectoryDts1Codec.Decode(fixture.ExactDts1);
        internal byte[] InitialFloor { get; }
        internal World()
        {
            Directory.CreateDirectory(root);
            var xna = Path.Combine(root,"authority.xna1"); var dts = Path.Combine(root,"policy.dts1");
            File.WriteAllBytes(xna,fixture.ExactXna1); File.WriteAllBytes(dts,fixture.ExactDts1);
            authoritySource = new(fixture.Network, XPointNetworkCodec.Parse<Xna1Record>(fixture.ExactXna1).CoreHash.Span,[xna],[dts]);
            Provision();
            InitialFloor = File.ReadAllBytes(FloorPath);
        }
        internal void Provision() => AutomaticNtsTrustedTimeSource.ProvisionFloor(FloorPath,
            fixture.Network,key,Authority.NotBefore);
        internal AutomaticNtsTrustedTimeSource Create() => new(authoritySource,
            Environment.ProcessPath!,FloorPath,fixture.Network,key,NullLogger<AutomaticNtsTrustedTimeSource>.Instance,()=>Sample);
        internal AutomaticNtsTrustedTimeSource.NtsObservation[] Observations(long time) => Policy.Sources.Take(2)
            .Select(source => new AutomaticNtsTrustedTimeSource.NtsObservation(
                Convert.ToHexString(source.SourceId.Span).ToLowerInvariant(),time,1)).ToArray();
        public void Dispose() { fixture.Dispose(); CryptographicOperations.ZeroMemory(key); Directory.Delete(root,recursive:true); }
    }
}
#endif
