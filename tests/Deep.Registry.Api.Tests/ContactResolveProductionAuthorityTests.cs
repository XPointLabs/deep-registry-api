#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Registry.Api.DirectoryPublication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Deep.Registry.Api.Tests;

public sealed class ContactResolveProductionAuthorityTests
{
    [Fact]
    public void DefaultCompositionRemainsDormantWithoutMutation()
    {
        var services = new ServiceCollection();
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(
            new Dictionary<string, string?>()).Build();

        services.AddContactResolveProductionAuthority(configuration);
        using var provider = services.BuildServiceProvider();

        Assert.Null(provider.GetService<IContactResolveTrustedTimeContextSource>());
        Assert.Null(provider.GetService<IContactResolveOneUseRequestLedger>());
        Assert.Null(provider.GetService<IContactResolveDtt1WitnessCustody>());
    }

    [Fact]
    public void PartialEnabledConfigurationFailsBeforeFilesystemMutation()
    {
        using var world = AuthorityWorld.Create(writeKeys: false);
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(
            new Dictionary<string, string?>
            {
                ["ContactResolveProductionAuthority:Enabled"] = "true",
                ["ContactResolveProductionAuthority:NetworkIdHex"] = Convert.ToHexString(world.Network),
                ["ContactResolveProductionAuthority:TrustedTimeStatePath"] = world.TimeStatePath,
            }).Build();

        Assert.Throws<InvalidOperationException>(() =>
            new ServiceCollection().AddContactResolveProductionAuthority(configuration));
        Assert.False(File.Exists(world.TimeStatePath));
        Assert.False(Directory.Exists(world.LedgerRootPath));
    }

    [Fact]
    public async Task ProtectedTrustedTimeSurvivesProcessRestartAndAdvancesMonotonically()
    {
        using var world = AuthorityWorld.Create();
        var hash = world.ProvisionTime(1_700_000_100, 1_700_000_300, sample: 1_000);
        try
        {
            using (var first = world.TimeSource(() => 1_005))
            {
                var observed = await first.ReadAsync(default);
                Assert.Equal(1_700_000_105UL, observed.ObservedUnixTime);
                Assert.Equal(1_005UL, observed.ServerMonotonicSample);
            }

            using var restarted = world.TimeSource(() => 1_009);
            var afterRestart = await restarted.ReadAsync(default);
            Assert.Equal(1_700_000_109UL, afterRestart.ObservedUnixTime);
            Assert.Equal(world.BootId, afterRestart.ServerBootId.ToArray());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(hash);
        }
    }

    [Fact]
    public async Task ProtectedTrustedTimeRejectsStaleTamperedAndMonotonicRollbackState()
    {
        using var world = AuthorityWorld.Create();
        _ = world.ProvisionTime(1_700_000_100, 1_700_000_120, sample: 1_000);

        using (var stale = world.TimeSource(() => 1_019))
            await Assert.ThrowsAsync<CryptographicException>(async () =>
                await stale.ReadAsync(default));
        using (var rollback = world.TimeSource(() => 999))
            await Assert.ThrowsAsync<CryptographicException>(async () =>
                await rollback.ReadAsync(default));

        var encoded = File.ReadAllBytes(world.TimeStatePath);
        encoded[40] ^= 0x01;
        File.WriteAllBytes(world.TimeStatePath, encoded);
        CryptographicOperations.ZeroMemory(encoded);
        using var tampered = world.TimeSource(() => 1_001);
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await tampered.ReadAsync(default));
    }

    [Fact]
    public void TrustedTimeRotationRequiresExactPredecessorAndRejectsFork()
    {
        using var world = AuthorityWorld.Create();
        var current = world.ProvisionTime(1_700_000_100, 1_700_000_300, sample: 1_000);
        var original = File.ReadAllBytes(world.TimeStatePath);
        try
        {
            Assert.Throws<InvalidOperationException>(() =>
                world.ProvisionTime(1_700_000_110, 1_700_000_400, sample: 1_010));
            Assert.Throws<CryptographicException>(() =>
                world.ProvisionTime(
                    1_700_000_110, 1_700_000_400, sample: 1_010,
                    expectedHash: Bytes(0x7f, 32)));
            Assert.Equal(original, File.ReadAllBytes(world.TimeStatePath));

            var next = world.ProvisionTime(
                1_700_000_110, 1_700_000_400, sample: 1_010,
                expectedHash: current);
            Assert.NotEqual(Convert.ToHexString(current), Convert.ToHexString(next));
            CryptographicOperations.ZeroMemory(next);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(current);
            CryptographicOperations.ZeroMemory(original);
        }
    }

    [Fact]
    public async Task ProtectedOneUseLedgerRejectsReplayAcrossRestart()
    {
        using var world = AuthorityWorld.Create();
        using var fixture = ContactResolveAuthoringFixture.Create(currentValue: false);
        var request = Request(world.Network, Bytes(0x31, 32), Bytes(0x32, 16), 71);
        var trusted = new ContactResolveTrustedTimeContext(
            world.BootId, 101, 1_700_000_101, 2);
        var epoch = Epoch(fixture, trusted);

        using (var first = world.Ledger())
            await first.ConsumeAsync(request, trusted, epoch, default);
        using var restarted = world.Ledger();
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await restarted.ConsumeAsync(request, trusted, epoch, default));
        Assert.Single(Directory.EnumerateFiles(
            world.LedgerRootPath, "*.request", SearchOption.AllDirectories));
    }

    [Fact]
    public async Task ProtectedOneUseLedgerRotatesAuthenticatedEpochAndReopensNonceOnlyAfterRotation()
    {
        using var world = AuthorityWorld.Create();
        using var fixture = ContactResolveAuthoringFixture.Create(currentValue: false);
        var request = Request(world.Network, Bytes(0x35, 32), world.BootId, 72);
        var firstTrusted = new ContactResolveTrustedTimeContext(
            world.BootId, 101, 1_700_000_101, 2);
        var firstEpoch = Epoch(fixture, firstTrusted);

        using (var first = world.Ledger())
            await first.ConsumeAsync(request, firstTrusted, firstEpoch, default);

        var nextTrusted = firstTrusted with
        {
            ServerMonotonicSample = 102,
            ObservedUnixTime = checked(firstEpoch.ValidUntil + 3),
        };
        var nextEpoch = Epoch(fixture, nextTrusted);
        Assert.NotEqual(firstEpoch.Id.ToArray(), nextEpoch.Id.ToArray());

        using (var rotated = world.Ledger())
            await rotated.ConsumeAsync(request, nextTrusted, nextEpoch, default);
        Assert.Single(Directory.EnumerateFiles(
            world.LedgerRootPath, "*.request", SearchOption.AllDirectories));

        using var restarted = world.Ledger();
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await restarted.ConsumeAsync(request, nextTrusted, nextEpoch, default));
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await restarted.ConsumeAsync(
                Request(world.Network, Bytes(0x37, 32), world.BootId, 74),
                firstTrusted,
                firstEpoch,
                default));
        Assert.Single(Directory.EnumerateFiles(
            world.LedgerRootPath, "*.request", SearchOption.AllDirectories));
    }

    [Fact]
    public async Task ProtectedOneUseLedgerFailsClosedOnTamperedMarkerDuringEpochRotation()
    {
        using var world = AuthorityWorld.Create();
        using var fixture = ContactResolveAuthoringFixture.Create(currentValue: false);
        var request = Request(world.Network, Bytes(0x36, 32), world.BootId, 73);
        var firstTrusted = new ContactResolveTrustedTimeContext(
            world.BootId, 101, 1_700_000_101, 2);
        var firstEpoch = Epoch(fixture, firstTrusted);
        using (var first = world.Ledger())
            await first.ConsumeAsync(request, firstTrusted, firstEpoch, default);

        var marker = Assert.Single(Directory.EnumerateFiles(
            world.LedgerRootPath, "*.request", SearchOption.AllDirectories));
        var encoded = File.ReadAllBytes(marker);
        encoded[30] ^= 0x01;
        File.WriteAllBytes(marker, encoded);
        CryptographicOperations.ZeroMemory(encoded);

        var nextTrusted = firstTrusted with
        {
            ServerMonotonicSample = 102,
            ObservedUnixTime = checked(firstEpoch.ValidUntil + 3),
        };
        var nextEpoch = Epoch(fixture, nextTrusted);
        using var rotated = world.Ledger();
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await rotated.ConsumeAsync(request, nextTrusted, nextEpoch, default));
        Assert.True(File.Exists(marker));
    }

    [Fact]
    public async Task ProtectedOneUseLedgerBoundsAdmissionWithoutEverReopeningANonce()
    {
        using var world = AuthorityWorld.Create();
        using var fixture = ContactResolveAuthoringFixture.Create(currentValue: false);
        var trusted = new ContactResolveTrustedTimeContext(
            world.BootId, 101, 1_700_000_101, 2);
        var epoch = Epoch(fixture, trusted);
        using (var ledger = world.Ledger(
            capacity: 16, compactionInterval: 4))
        {
            for (var index = 1; index <= 16; index++)
                await ledger.ConsumeAsync(
                    Request(world.Network, Bytes(checked((byte)index), 32), world.BootId,
                        checked((ulong)index)), trusted, epoch, default);

            await Assert.ThrowsAsync<ContactResolveDirectoryAdmissionException>(async () =>
                await ledger.ConsumeAsync(
                    Request(world.Network, Bytes(0x71, 32), world.BootId, 17),
                    trusted, epoch, default));
        }

        using (var restarted = world.Ledger(
            capacity: 16, compactionInterval: 4))
        {
            var afterExpiry = trusted with
            {
                ServerMonotonicSample = 165,
                ObservedUnixTime = trusted.ObservedUnixTime + 64,
            };
            var afterExpiryEpoch = Epoch(fixture, afterExpiry);
            await Assert.ThrowsAsync<ContactResolveDirectoryAdmissionException>(async () =>
                await restarted.ConsumeAsync(
                    Request(world.Network, Bytes(0x72, 32), world.BootId, 18),
                    afterExpiry, afterExpiryEpoch, default));
            await Assert.ThrowsAsync<CryptographicException>(async () =>
                await restarted.ConsumeAsync(
                    Request(world.Network, Bytes(0x01, 32), Bytes(0x7a, 16), 999),
                    afterExpiry, afterExpiryEpoch, default));
        }

        Assert.Equal(16, Directory.EnumerateFiles(
            world.LedgerRootPath, "*.request", SearchOption.AllDirectories).Count());
    }

    [Fact]
    public async Task ProtectedOneUseLedgerFailsClosedOnTamperedQuotaState()
    {
        using var world = AuthorityWorld.Create();
        using var fixture = ContactResolveAuthoringFixture.Create(currentValue: false);
        var trusted = new ContactResolveTrustedTimeContext(
            world.BootId, 101, 1_700_000_101, 2);
        var epoch = Epoch(fixture, trusted);
        using (var first = world.Ledger())
            await first.ConsumeAsync(
                Request(world.Network, Bytes(0x73, 32), world.BootId, 1), trusted, epoch, default);

        var statePath = Path.Combine(world.LedgerRootPath, ".quota.state");
        var encoded = File.ReadAllBytes(statePath);
        encoded[10] ^= 0x01;
        File.WriteAllBytes(statePath, encoded);
        CryptographicOperations.ZeroMemory(encoded);

        using var restarted = world.Ledger();
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await restarted.ConsumeAsync(
                Request(world.Network, Bytes(0x74, 32), world.BootId, 2), trusted, epoch, default));
        Assert.Single(Directory.EnumerateFiles(
            world.LedgerRootPath, "*.request", SearchOption.AllDirectories));
    }

    [Fact]
    public async Task WitnessCustodyRejectsASeedOutsideVerifiedAuthority()
    {
        using var world = AuthorityWorld.Create();
        using var fixture = ContactResolveAuthoringFixture.Create(currentValue: false);
        File.WriteAllBytes(world.WitnessSeedPaths[0], Bytes(0x7e, 32));

        using var custody = new FileContactResolveDtt1WitnessCustody(
            world.Network, world.Witnesses);
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await custody.GetSignersAsync(fixture.Authority, default));
    }

    [Fact]
    public async Task CompleteProductionCompositionActivatesHttpIssuerAndPreservesReplayState()
    {
        using var world = AuthorityWorld.Create();
        using var fixture = ContactResolveAuthoringFixture.Create(currentValue: false);
        Assert.Equal(fixture.Network, world.Network);
        var now = ProtectedMonotonicContactResolveTrustedTimeSource
            .ReadPlatformMonotonicSeconds();
        var stateHash = world.ProvisionTime(
            1_700_000_100, 1_700_000_500, sample: now);
        CryptographicOperations.ZeroMemory(stateHash);

        var services = new ServiceCollection();
        services.AddContactResolveProductionAuthority(world.Configuration);
        services.AddSingleton<IContactResolveCanonicalDirectorySnapshotSource>(
            new FixedSnapshotSource(fixture.Snapshot));
        services.AddSingleton<IContactResolveDirectoryProofMaterialSource>(
            new FixedProofSource(fixture.ProofMaterial));
        services.AddProductionContactResolveDirectoryPackageIssuer();

        var request = Request(fixture.Network, Bytes(0x41, 32), Bytes(0x42, 16), 901);
        await using (var provider = services.BuildServiceProvider(new ServiceProviderOptions
        {
            ValidateOnBuild = true,
            ValidateScopes = true,
        }))
        {
            var httpIssuer = provider.GetRequiredService<IContactResolveDirectoryPackageIssuer>();
            Assert.IsType<ProductionContactResolveDirectoryPackageIssuer>(httpIssuer);
            var package = await httpIssuer.IssueAsync(request, default);
            var encoded = ContactResolveDirectoryPackageCodec.EncodeResponse(request, package);
            try
            {
                Assert.True(encoded.AsSpan(0, 4).SequenceEqual("CDR1"u8));
                Assert.Equal(request.Nonce.ToArray(), encoded.AsSpan(28, 32).ToArray());
                Assert.False(package.ExactDtt1.IsEmpty);
                Assert.False(package.ExactAdp1.IsEmpty);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(encoded);
            }
        }

        await using var restarted = services.BuildServiceProvider();
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await restarted.GetRequiredService<IContactResolveDirectoryPackageIssuer>()
                .IssueAsync(request, default));
        Assert.Single(Directory.EnumerateFiles(
            world.LedgerRootPath, "*.request", SearchOption.AllDirectories));
    }

    [Fact]
    public async Task OperatorTimeProvisioningRejectsUnknownOptionsWithoutMutation()
    {
        using var world = AuthorityWorld.Create();
        var result = await ContactResolveOperatorCommand.TryRunAsync(
            ["contact-resolve-authority", "provision-time", "--unknown", "1"],
            world.Configuration);

        Assert.Equal(2, result);
        Assert.False(File.Exists(world.TimeStatePath));
    }

    [Fact]
    public async Task OperatorTimeProvisioningCreatesOnlyProtectedConfiguredState()
    {
        using var world = AuthorityWorld.Create();
        var result = await ContactResolveOperatorCommand.TryRunAsync(
            [
                "contact-resolve-authority", "provision-time",
                "--observed-unix-time", "1700000100",
                "--valid-until-unix", "1700000400",
                "--uncertainty-seconds", "2",
            ],
            world.Configuration);

        Assert.Equal(0, result);
        Assert.True(File.Exists(world.TimeStatePath));
        var encoded = File.ReadAllBytes(world.TimeStatePath);
        Assert.Equal(138, encoded.Length);
        Assert.Equal(-1, encoded.AsSpan().IndexOf("1700000100"u8));
        CryptographicOperations.ZeroMemory(encoded);
        Assert.False(Directory.Exists(world.LedgerRootPath));
    }

    private static ContactResolveDirectoryPackageRequest Request(
        byte[] network,
        byte[] nonce,
        byte[] boot,
        ulong sample) => new(network, nonce, boot, sample, null, null, null);

    private static AccountDirectoryDtt1IssuanceEpoch Epoch(
        ContactResolveAuthoringFixture fixture,
        ContactResolveTrustedTimeContext trusted) =>
        AccountDirectoryDtt1IssuanceEpoch.Derive(
            fixture.Authority,
            trusted.ObservedUnixTime,
            trusted.UncertaintySeconds);

    private static byte[] Bytes(byte value, int length) =>
        Enumerable.Repeat(value, length).ToArray();

    private sealed class FixedSnapshotSource(ContactResolveCanonicalDirectorySnapshot snapshot) :
        IContactResolveCanonicalDirectorySnapshotSource
    {
        public ValueTask<ContactResolveCanonicalDirectorySnapshot> ReadAsync(
            ContactResolveDirectoryPackageRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(snapshot);
        }
    }

    private sealed class FixedProofSource(AccountDirectoryAdp1ProofMaterial proof) :
        IContactResolveDirectoryProofMaterialSource
    {
        public ValueTask<AccountDirectoryAdp1ProofMaterial> ReadAsync(
            ContactResolveCanonicalDirectorySnapshot snapshot,
            ContactResolveDirectoryPackageRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(proof);
        }
    }

    private sealed class AuthorityWorld : IDisposable
    {
        private readonly string root;
        private readonly byte[] timeKey;
        private readonly byte[] ledgerKey;

        private AuthorityWorld(string root, bool writeKeys)
        {
            this.root = root;
            Directory.CreateDirectory(root);
            Network = Bytes(0x11, 16);
            BootId = Bytes(0x21, 16);
            timeKey = Bytes(0xa1, 32);
            ledgerKey = Bytes(0xa2, 32);
            TimeStatePath = Path.Combine(root, "trusted-time.state");
            TimeKeyPath = Path.Combine(root, "trusted-time.key");
            LedgerRootPath = Path.Combine(root, "requests");
            LedgerKeyPath = Path.Combine(root, "request-ledger.key");
            WitnessSeedPaths = Enumerable.Range(0, 3)
                .Select(index => Path.Combine(root, $"witness-{index}.seed"))
                .ToArray();
            Witnesses = Enumerable.Range(0, 3).Select(index =>
                new ContactResolveWitnessCustodyOptions
                {
                    WitnessIdHex = Convert.ToHexString(Bytes(checked((byte)(0x40 + index)), 32)),
                    KeyGeneration = 0,
                    Ed25519SeedPath = WitnessSeedPaths[index],
                }).ToList();
            if (writeKeys)
            {
                File.WriteAllBytes(TimeKeyPath, timeKey);
                File.WriteAllBytes(LedgerKeyPath, ledgerKey);
                for (var index = 0; index < WitnessSeedPaths.Length; index++)
                    File.WriteAllBytes(
                        WitnessSeedPaths[index], Bytes(checked((byte)(0x50 + index)), 32));
            }
            var values = new Dictionary<string, string?>
            {
                ["DirectoryPublication:NetworkIdHex"] = Convert.ToHexString(Network),
                ["ContactResolveProductionAuthority:Enabled"] = "true",
                ["ContactResolveProductionAuthority:NetworkIdHex"] = Convert.ToHexString(Network),
                ["ContactResolveProductionAuthority:TrustedTimeStatePath"] = TimeStatePath,
                ["ContactResolveProductionAuthority:TrustedTimeIntegrityKeyPath"] = TimeKeyPath,
                ["ContactResolveProductionAuthority:RequestLedgerRootPath"] = LedgerRootPath,
                ["ContactResolveProductionAuthority:RequestLedgerIntegrityKeyPath"] = LedgerKeyPath,
            };
            for (var index = 0; index < Witnesses.Count; index++)
            {
                values[$"ContactResolveProductionAuthority:Witnesses:{index}:WitnessIdHex"] =
                    Witnesses[index].WitnessIdHex;
                values[$"ContactResolveProductionAuthority:Witnesses:{index}:KeyGeneration"] =
                    Witnesses[index].KeyGeneration.ToString();
                values[$"ContactResolveProductionAuthority:Witnesses:{index}:Ed25519SeedPath"] =
                    Witnesses[index].Ed25519SeedPath;
            }
            Configuration = new ConfigurationBuilder().AddInMemoryCollection(values).Build();
        }

        internal byte[] Network { get; }
        internal byte[] BootId { get; }
        internal string TimeStatePath { get; }
        internal string TimeKeyPath { get; }
        internal string LedgerRootPath { get; }
        internal string LedgerKeyPath { get; }
        internal string[] WitnessSeedPaths { get; }
        internal List<ContactResolveWitnessCustodyOptions> Witnesses { get; }
        internal IConfiguration Configuration { get; }

        internal static AuthorityWorld Create(bool writeKeys = true) => new(
            Path.Combine(Path.GetTempPath(), "deep-registry-contact-authority-tests",
                Guid.NewGuid().ToString("N")),
            writeKeys);

        internal byte[] ProvisionTime(
            ulong observed,
            ulong validUntil,
            uint uncertainty = 2,
            ulong sample = 1_000,
            byte[]? expectedHash = null) =>
            ProtectedMonotonicContactResolveTrustedTimeSource.Provision(
                TimeStatePath, Network, timeKey, observed, validUntil, uncertainty,
                expectedHash ?? [], sample, BootId);

        internal ProtectedMonotonicContactResolveTrustedTimeSource TimeSource(
            Func<ulong> sample) => new(TimeStatePath, Network, timeKey, sample);

        internal ProtectedFileContactResolveOneUseRequestLedger Ledger(
            int capacity = 65_536,
            int compactionInterval = 1_024) =>
            new(LedgerRootPath, Network, ledgerKey, capacity, compactionInterval);

        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(timeKey);
            CryptographicOperations.ZeroMemory(ledgerKey);
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }
}
#endif
