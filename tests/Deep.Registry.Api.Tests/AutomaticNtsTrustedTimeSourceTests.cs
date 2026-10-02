#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.XPointNetworkV1;
using Deep.Registry.Api.DirectoryPublication;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Configuration;

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

    [Fact]
    public async Task ManualUpgradeRetainsOnlyAuthenticatedLowerAndRequiresFreshAcquisition()
    {
        using var world = new World(provision: false);
        var hash = world.ProvisionManual(); var manual = File.ReadAllBytes(world.ManualPath);
        world.Upgrade(hash);
        Assert.Equal(manual, File.ReadAllBytes(world.ManualPath));
        using var source = world.Create();
        await Assert.ThrowsAsync<ContactResolveDirectoryPackageUnavailableException>(async () => await source.ReadAsync(default));
        Assert.Throws<CryptographicException>(() => source.AcceptObservations(world.Authority,
            world.Policy, world.Observations(1_700_000_090), 1_000, 1_000));
        source.AcceptObservations(world.Authority, world.Policy, world.Observations(1_700_000_100), 1_000, 1_000);
        var current = await source.ReadAsync(default);
        Assert.True(current.ObservedUnixTime - current.UncertaintySeconds >= 1_700_000_095);
    }

    [Fact]
    public void InterruptedManualUpgradeResumesExactPendingBytesWithoutChangingManualState()
    {
        using var world = new World(provision: false); var hash = world.ProvisionManual();
        var manual = File.ReadAllBytes(world.ManualPath);
        Assert.Throws<IOException>(() => world.Upgrade(hash, () => throw new IOException("Injected pre-activation interruption.")));
        Assert.False(File.Exists(world.FloorPath));
        var pending = File.ReadAllBytes(world.FloorPath + ".manual-upgrade-pending");
        Assert.Throws<InvalidDataException>(() => world.Create());
        world.Upgrade(hash);
        Assert.Equal(pending, File.ReadAllBytes(world.FloorPath));
        Assert.False(File.Exists(world.FloorPath + ".manual-upgrade-pending"));
        Assert.Equal(manual, File.ReadAllBytes(world.ManualPath));
    }

    [Fact]
    public void CompletedUpgradeCannotResetExistingOrLostAdvancedFloor()
    {
        using var world = new World(provision: false); var hash = world.ProvisionManual();
        world.Upgrade(hash);
        using (var source = world.Create())
            source.AcceptObservations(world.Authority, world.Policy, world.Observations(1_700_000_200), 1_000, 1_000);
        var advanced = File.ReadAllBytes(world.FloorPath);
        Assert.Throws<InvalidDataException>(() => world.Upgrade(hash));
        Assert.Equal(advanced, File.ReadAllBytes(world.FloorPath));
        File.Delete(world.FloorPath); // Exact test-created file: simulate custody loss.
        Assert.Throws<InvalidDataException>(() => world.Upgrade(hash));
        Assert.False(File.Exists(world.FloorPath));
    }

    [Theory]
    [InlineData("manual-cas")]
    [InlineData("manual-hmac")]
    [InlineData("pending")]
    [InlineData("fence")]
    public void ConflictingOrCorruptUpgradeInputsNeverActivate(string mutation)
    {
        using var world = new World(provision: false); var hash = world.ProvisionManual();
        if (mutation is "pending" or "fence")
        {
            Assert.Throws<IOException>(() => world.Upgrade(hash, () => throw new IOException("Injected interruption.")));
            var path = world.FloorPath + (mutation == "pending" ? ".manual-upgrade-pending" : ".manual-upgrade-fence");
            var bytes = File.ReadAllBytes(path); bytes[^1] ^= 1; File.WriteAllBytes(path, bytes);
        }
        else if (mutation == "manual-cas") hash[0] ^= 1;
        else
        {
            var bytes = File.ReadAllBytes(world.ManualPath); bytes[^1] ^= 1; File.WriteAllBytes(world.ManualPath, bytes);
            hash = SHA256.HashData(bytes); // Correct CAS is not an HMAC bypass.
        }
        Assert.Throws<CryptographicException>(() => world.Upgrade(hash));
        Assert.False(File.Exists(world.FloorPath));
    }

    [Fact]
    public void OperatorTransitionPreservesInitializedDirectoryAndRejectsReprovisioning()
    {
        using var world = new World(provision: false); var hash = world.ProvisionManual();
        var config = world.UpgradeConfiguration();
        var directory = File.ReadAllBytes(config["DeepIdV2DirectoryAuthority:StatePath"]!);
        var args = new[] { "did2-directory", "provision-nts-floor", Convert.ToHexString(hash) };
        Assert.Equal(0, DeepIdV2DirectoryOperatorCommand.TryRun(args, config));
        var initial = File.ReadAllBytes(world.FloorPath);
        Assert.Equal(2, DeepIdV2DirectoryOperatorCommand.TryRun(args, config));
        Assert.Equal(initial, File.ReadAllBytes(world.FloorPath));
        Assert.Equal(directory, File.ReadAllBytes(config["DeepIdV2DirectoryAuthority:StatePath"]!));
    }

    [Theory]
    [InlineData("disabled")]
    [InlineData("automatic-disabled")]
    [InlineData("foreign-network")]
    [InlineData("alias")]
    [InlineData("bad-hash")]
    [InlineData("bad-key")]
    [InlineData("relative")]
    [InlineData("arity")]
    [InlineData("pending-key-alias")]
    [InlineData("nonce-root")]
    public void OperatorInvalidScopeOrArgumentsNeverCreatesFloor(string mutation)
    {
        using var world = new World(provision: false); var hash = world.ProvisionManual();
        var config = world.UpgradeConfiguration(); var manual = File.ReadAllBytes(world.ManualPath);
        if (mutation == "disabled") config["DeepIdV2DirectoryAuthority:Enabled"] = "false";
        if (mutation == "automatic-disabled") config["ContactResolveProductionAuthority:AutomaticTrustedTimeEnabled"] = "false";
        if (mutation == "foreign-network") config["ContactResolveProductionAuthority:NetworkIdHex"] = new string('a', 32);
        if (mutation == "alias") config["ContactResolveProductionAuthority:NtsLowerFloorPath"] = config["DeepIdV2DirectoryAuthority:StatePath"];
        if (mutation == "relative") config["ContactResolveProductionAuthority:NtsLowerFloorPath"] = "relative.bin";
        if (mutation == "pending-key-alias") config["DeepIdV2DirectoryAuthority:ProofRequestLedgerIntegrityKeyPath"] = world.FloorPath + ".manual-upgrade-pending";
        if (mutation == "nonce-root") config["ContactResolveProductionAuthority:RequestLedgerRootPath"] = Path.GetDirectoryName(world.FloorPath);
        if (mutation == "bad-key") File.WriteAllBytes(config["ContactResolveProductionAuthority:TrustedTimeIntegrityKeyPath"]!, new byte[32]);
        if (mutation == "bad-hash") hash[0] ^= 1;
        var args = new[] { "did2-directory", "provision-nts-floor", Convert.ToHexString(hash) };
        if (mutation == "arity") args = [.. args, "extra"];
        Assert.Equal(2, DeepIdV2DirectoryOperatorCommand.TryRun(args, config));
        Assert.False(File.Exists(world.FloorPath));
        Assert.Equal(manual, File.ReadAllBytes(world.ManualPath));
    }

    private sealed class World : IDisposable
    {
        private readonly ContactResolveAuthoringFixture fixture = ContactResolveAuthoringFixture.Create(currentValue:false);
        private readonly string root = Path.Combine(Path.GetTempPath(), "deep-nts-unit-" + Guid.NewGuid().ToString("N"));
        private readonly byte[] key = RandomNumberGenerator.GetBytes(32);
        private readonly DeepIdV2XPointAuthoritySource authoritySource;
        internal ulong Sample = 1_000;
        internal string FloorPath => Path.Combine(root,"nts-floor.bin");
        internal string ManualPath => Path.Combine(root,"manual-time.bin");
        internal VerifiedXPointNetworkAuthority Authority => fixture.Authority;
        internal AccountDirectoryDts1 Policy => AccountDirectoryDts1Codec.Decode(fixture.ExactDts1);
        internal byte[] InitialFloor { get; }
        internal World(bool provision = true)
        {
            Directory.CreateDirectory(root);
            var xna = Path.Combine(root,"authority.xna1"); var dts = Path.Combine(root,"policy.dts1");
            File.WriteAllBytes(xna,fixture.ExactXna1); File.WriteAllBytes(dts,fixture.ExactDts1);
            authoritySource = new(fixture.Network, XPointNetworkCodec.Parse<Xna1Record>(fixture.ExactXna1).CoreHash.Span,[xna],[dts]);
            if (provision) Provision();
            InitialFloor = provision ? File.ReadAllBytes(FloorPath) : [];
        }
        internal void Provision() => AutomaticNtsTrustedTimeSource.ProvisionFloor(FloorPath,
            fixture.Network,key,Authority.NotBefore);
        internal byte[] ProvisionManual() => ProtectedMonotonicContactResolveTrustedTimeSource.Provision(
            ManualPath, fixture.Network, key, 1_700_000_100, 1_700_000_120, 5, [], 1_000,
            Enumerable.Repeat((byte)1, 16).ToArray());
        internal void Upgrade(byte[] hash, Action? hook = null) => ManualToNtsFloorUpgrade.Run(
            ManualPath, FloorPath, fixture.Network, key, hash, Authority.NotBefore, default, hook);
        internal IConfiguration UpgradeConfiguration()
        {
            // Sentinel proves absence of directory mutation, not ADA2 authority.
            var state = Path.Combine(root, "directory-sentinel.bin");
            var stateKey = Path.Combine(root, "directory-key.bin");
            var timeKey = Path.Combine(root, "time-key.bin");
            File.WriteAllBytes(state, [1, 2, 3]); File.WriteAllBytes(stateKey, key); File.WriteAllBytes(timeKey, key);
            return new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> {
                ["DeepIdV2DirectoryAuthority:Enabled"] = "true",
                ["DeepIdV2DirectoryAuthority:NetworkIdHex"] = Convert.ToHexString(fixture.Network),
                ["DeepIdV2DirectoryAuthority:GenesisAuthorityCoreHashHex"] = Convert.ToHexString(Authority.AuthorityCoreHash.Span),
                ["DeepIdV2DirectoryAuthority:ExactAuthorityPaths:0"] = Path.Combine(root, "authority.xna1"),
                ["DeepIdV2DirectoryAuthority:ExactTimePolicyPaths:0"] = Path.Combine(root, "policy.dts1"),
                ["DeepIdV2DirectoryAuthority:StatePath"] = state,
                ["DeepIdV2DirectoryAuthority:IntegrityKeyPath"] = stateKey,
                ["DeepIdV2DirectoryAuthority:GenesisHeadPath"] = Path.Combine(root, "genesis.adh1"),
                ["ContactResolveProductionAuthority:Enabled"] = "true",
                ["ContactResolveProductionAuthority:NetworkIdHex"] = Convert.ToHexString(fixture.Network),
                ["ContactResolveProductionAuthority:AutomaticTrustedTimeEnabled"] = "true",
                ["ContactResolveProductionAuthority:TrustedTimeStatePath"] = ManualPath,
                ["ContactResolveProductionAuthority:TrustedTimeIntegrityKeyPath"] = timeKey,
                ["ContactResolveProductionAuthority:NtsLowerFloorPath"] = FloorPath,
            }).Build();
        }
        internal AutomaticNtsTrustedTimeSource Create() => new(authoritySource,
            Environment.ProcessPath!,FloorPath,fixture.Network,key,NullLogger<AutomaticNtsTrustedTimeSource>.Instance,()=>Sample);
        internal AutomaticNtsTrustedTimeSource.NtsObservation[] Observations(long time) => Policy.Sources.Take(2)
            .Select(source => new AutomaticNtsTrustedTimeSource.NtsObservation(
                Convert.ToHexString(source.SourceId.Span).ToLowerInvariant(),time,1)).ToArray();
        public void Dispose() { fixture.Dispose(); CryptographicOperations.ZeroMemory(key); Directory.Delete(root,recursive:true); }
    }
}
#endif
