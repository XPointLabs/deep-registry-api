#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Registry.Api.DirectoryPublication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Deep.Registry.Api.Tests;

public sealed class DirectorySourceCutoverTests
{
    [Theory]
    [InlineData("AccountDirectoryAuthority")]
    [InlineData("ContactResolveDirectoryArtifacts")]
    [InlineData("TargetedCurrentValueDirectoryPackages")]
    public void RetiredSectionsRejectEvenDisabledScalarOrUnknown(string section)
    {
        foreach (var pair in new[] { (section + ":Enabled", "false"),
            (section + ":Unknown", "ignored"), (section, "false") })
        {
            var config = new ConfigurationBuilder().AddInMemoryCollection(
                new Dictionary<string, string?> { [pair.Item1] = pair.Item2 }).Build();
            Assert.Throws<InvalidOperationException>(() => RetiredDirectoryConfiguration.RequireAbsent(config));
            Assert.Throws<InvalidOperationException>(() => new ServiceCollection()
                .AddDeepIdV2DirectoryAuthority(config));
            Assert.Throws<InvalidOperationException>(() => new ServiceCollection()
                .AddDirectoryPublication(config));
        }
    }

    [Fact]
    public void AbsentRetiredSectionsDoNotActivateAnyAuthority()
    {
        var config = new ConfigurationBuilder().Build();
        RetiredDirectoryConfiguration.RequireAbsent(config);
        var services = new ServiceCollection();
        Assert.False(services.AddDeepIdV2DirectoryAuthority(config).Enabled);
        Assert.False(services.AddDirectoryPublication(config).MirrorEnabled);
        Assert.DoesNotContain(services, item => item.ServiceType == typeof(DeepIdV2DirectoryProofIssuer));
    }

    [Fact]
    public async Task RemovedOperatorActionCannotOpenInputOrOutput()
    {
        var config = new ConfigurationBuilder().Build();
        Assert.Equal(2, await ContactResolveOperatorCommand.TryRunAsync(
            ["contact-resolve-authority", "author-package", "--request", "absent", "--output", "absent"], config));
    }

    [Theory]
    [InlineData(0, 15)]
    [InlineData(0, 17)]
    [InlineData(1, 31)]
    [InlineData(1, 33)]
    [InlineData(2, 15)]
    [InlineData(2, 17)]
    [InlineData(0, 0)]
    [InlineData(1, 0)]
    [InlineData(2, 0)]
    public void ReplayInputRejectsWrongSizeAndZeroBeforeLedger(int field, int length)
    {
        var fields = new[] { Bytes(16, 1), Bytes(32, 2), Bytes(16, 3) };
        fields[field] = length == 0 ? new byte[fields[field].Length] : Bytes(length, 9);
        Assert.Throws<ArgumentException>(() => new DirectoryProofReplayRequest(fields[0], fields[1], fields[2], 0));
    }

    [Fact]
    public void ReplayInputDefensivelyOwnsEveryBufferAndCarriesNoProofAuthority()
    {
        var network = Bytes(16, 1); var nonce = Bytes(32, 2); var boot = Bytes(16, 3);
        var request = new DirectoryProofReplayRequest(network, nonce, boot, 77);
        Array.Clear(network); Array.Clear(nonce); Array.Clear(boot);
        Assert.Equal(Bytes(16, 1), request.NetworkId.ToArray());
        Assert.Equal(Bytes(32, 2), request.Nonce.ToArray());
        Assert.Equal(Bytes(16, 3), request.BootId.ToArray());
        Assert.Equal(77UL, request.NonceCreatedAt);
        foreach (var copy in new[] { request.NetworkId, request.Nonce, request.BootId })
        {
            Assert.True(MemoryMarshal.TryGetArray(copy, out var buffer));
            Array.Clear(buffer.Array!);
        }
        Assert.Equal(Bytes(16, 1), request.NetworkId.ToArray());
        Assert.Equal(Bytes(32, 2), request.Nonce.ToArray());
        Assert.Equal(Bytes(16, 3), request.BootId.ToArray());
        Assert.Empty(typeof(DirectoryProofReplayRequest).GetInterfaces());
    }

    [Fact]
    public async Task DurableNonceRejectionSurvivesRestartAndChangedBootOrSample()
    {
        var authority = DirectoryNetworkAuthorityFixture.Create();
        var epoch = AccountDirectoryDtt1IssuanceEpoch.Derive(authority, 1_700_000_100, 1);
        var root = TemporaryRoot();
        var time = new ContactResolveTrustedTimeContext(Bytes(16, 4), 900, 1_700_000_100, 1);
        try
        {
            using (var ledger = new ProtectedFileContactResolveOneUseRequestLedger(root, authority.NetworkId.Span, Bytes(32, 5)))
                await ledger.ConsumeAsync(new DirectoryProofReplayRequest(authority.NetworkId.Span, Bytes(32, 6),
                    Bytes(16, 7), 10), time, epoch, default);
            using var restored = new ProtectedFileContactResolveOneUseRequestLedger(root, authority.NetworkId.Span, Bytes(32, 5));
            foreach (var input in new[] {
                new DirectoryProofReplayRequest(authority.NetworkId.Span, Bytes(32, 6), Bytes(16, 7), 10),
                new DirectoryProofReplayRequest(authority.NetworkId.Span, Bytes(32, 6), Bytes(16, 8), 11) })
                await Assert.ThrowsAsync<CryptographicException>(() => restored.ConsumeAsync(input, time, epoch, default).AsTask());
            await restored.ConsumeAsync(new DirectoryProofReplayRequest(authority.NetworkId.Span, Bytes(32, 9),
                Bytes(16, 8), 11), time, epoch, default);
            Assert.Equal(2, Directory.EnumerateFiles(root, "*.request", SearchOption.AllDirectories).Count());
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
    }

    [Fact]
    public async Task ProofBudgetExpansionRetainsConsumedNoncesWithoutReprovisioning()
    {
        var authority = DirectoryNetworkAuthorityFixture.Create();
        var epoch = AccountDirectoryDtt1IssuanceEpoch.Derive(authority, 1_700_000_100, 1);
        var root = TemporaryRoot();
        var time = new ContactResolveTrustedTimeContext(Bytes(16, 4), 900, 1_700_000_100, 1);
        var used = new DirectoryProofReplayRequest(authority.NetworkId.Span, Bytes(32, 6), Bytes(16, 7), 10);
        try
        {
            using (var oldBudget = new ProtectedFileContactResolveOneUseRequestLedger(root,
                authority.NetworkId.Span, Bytes(32, 5), capacity: 65_536, compactionInterval: 1))
                await oldBudget.ConsumeAsync(used, time, epoch, default);
            var marker = Assert.Single(Directory.EnumerateFiles(root, "*.request", SearchOption.AllDirectories));
            var retained = File.ReadAllBytes(marker);
            using var expanded = new ProtectedFileContactResolveOneUseRequestLedger(root,
                authority.NetworkId.Span, Bytes(32, 5),
                capacity: DeepIdV2IssuanceAdmissionGate.MinimumLedgerCapacity, compactionInterval: 1);
            await Assert.ThrowsAsync<CryptographicException>(() =>
                expanded.ConsumeAsync(used, time, epoch, default).AsTask());
            Assert.Equal(retained, File.ReadAllBytes(marker));
            await expanded.ConsumeAsync(new DirectoryProofReplayRequest(authority.NetworkId.Span,
                Bytes(32, 9), Bytes(16, 8), 11), time, epoch, default);
            Assert.Equal(retained, File.ReadAllBytes(marker));
            Assert.Equal(2, Directory.EnumerateFiles(root, "*.request", SearchOption.AllDirectories).Count());
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
    }

    [Fact]
    public async Task LargerProofBudgetCannotHideCorruptRetainedLedgerState()
    {
        var authority = DirectoryNetworkAuthorityFixture.Create();
        var epoch = AccountDirectoryDtt1IssuanceEpoch.Derive(authority, 1_700_000_100, 1);
        var root = TemporaryRoot();
        var time = new ContactResolveTrustedTimeContext(Bytes(16, 4), 900, 1_700_000_100, 1);
        try
        {
            using (var oldBudget = new ProtectedFileContactResolveOneUseRequestLedger(root,
                authority.NetworkId.Span, Bytes(32, 5)))
                await oldBudget.ConsumeAsync(new DirectoryProofReplayRequest(authority.NetworkId.Span,
                    Bytes(32, 6), Bytes(16, 7), 10), time, epoch, default);
            var path = Path.Combine(root, ".quota.state");
            var corrupt = File.ReadAllBytes(path); corrupt[^1] ^= 1;
            File.WriteAllBytes(path, corrupt);
            using var expanded = new ProtectedFileContactResolveOneUseRequestLedger(root,
                authority.NetworkId.Span, Bytes(32, 5),
                capacity: DeepIdV2IssuanceAdmissionGate.MinimumLedgerCapacity);
            await Assert.ThrowsAsync<CryptographicException>(() => expanded.ConsumeAsync(
                new DirectoryProofReplayRequest(authority.NetworkId.Span, Bytes(32, 9), Bytes(16, 8), 11),
                time, epoch, default).AsTask());
            Assert.Equal(corrupt, File.ReadAllBytes(path));
            Assert.Single(Directory.EnumerateFiles(root, "*.request", SearchOption.AllDirectories));
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
    }

    [Fact]
    public async Task CancelledOrWrongNetworkNonceDoesNotCreateLedgerState()
    {
        var authority = DirectoryNetworkAuthorityFixture.Create();
        var epoch = AccountDirectoryDtt1IssuanceEpoch.Derive(authority, 1_700_000_100, 1);
        var root = TemporaryRoot();
        var time = new ContactResolveTrustedTimeContext(Bytes(16, 4), 900, 1_700_000_100, 1);
        using var ledger = new ProtectedFileContactResolveOneUseRequestLedger(root, authority.NetworkId.Span, Bytes(32, 5));
        try
        {
            var correct = new DirectoryProofReplayRequest(authority.NetworkId.Span, Bytes(32, 6), Bytes(16, 7), 10);
            await Assert.ThrowsAsync<OperationCanceledException>(() => ledger.ConsumeAsync(correct, time, epoch,
                new CancellationToken(true)).AsTask());
            var foreign = new DirectoryProofReplayRequest(Bytes(16, 8), Bytes(32, 6), Bytes(16, 7), 10);
            await Assert.ThrowsAsync<CryptographicException>(() => ledger.ConsumeAsync(foreign, time, epoch, default).AsTask());
            Assert.False(Directory.Exists(root));
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
    }

    private static byte[] Bytes(int length, byte value) => Enumerable.Repeat(value, length).ToArray();
    [Fact]
    public async Task CatalogCannotConsumeChallengeWithoutIndependentDid2Context()
    {
        var authority = DirectoryNetworkAuthorityFixture.Create(out var xna, out var dts);
        var dummy = Bytes(8, 9);
        var closure = new DirectoryPublicationVerificationClosure(
            [xna], [dts], [dummy], [dummy], [dummy], [dummy, dummy, dummy], [dummy],
            dummy, dummy, dummy, Bytes(32, 1), Bytes(32, 2), Bytes(16, 3),
            10, 11, 11, supportedReader: 2);
        var candidate = new DirectoryPublicationCandidate(dummy, dummy, dummy, closure);
        var clock = new UntouchedClock();
        var challenge = new UntouchedChallenge();
        var verifier = new ProductionDirectoryCanonicalPublicationVerifier(
            new DirectoryPublicationTrustAnchor(authority.NetworkId.Span, 0, authority.AuthorityCoreHash.Span),
            clock, challenge);
        var error = await Assert.ThrowsAsync<DirectoryCanonicalVerificationException>(() =>
            verifier.VerifyAsync(candidate.Freeze(), default).AsTask());
        Assert.Equal(DirectoryCanonicalVerificationError.FreshnessClosureInvalid, error.Error);
        Assert.Equal(0, clock.Calls);
        Assert.Equal(0, challenge.Calls);
    }

    [Theory]
    [InlineData((ushort)0)]
    [InlineData((ushort)1)]
    [InlineData((ushort)3)]
    [InlineData(ushort.MaxValue)]
    public void CatalogClosureRejectsAnyReaderExceptTwoBeforeCopy(ushort reader)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new DirectoryPublicationVerificationClosure(
            [], [], [], [], [], [], [], [], [], [], [], [], [], 0, 0, 0, reader));
    }

    private sealed class UntouchedClock : IDirectoryPublicationMonotonicClock
    {
        internal int Calls { get; private set; }
        public ValueTask<DirectoryPublicationMonotonicReading> ReadAsync(CancellationToken cancellationToken)
        {
            Calls++;
            throw new InvalidOperationException("Unexpected clock callback.");
        }
    }

    private sealed class UntouchedChallenge : IDirectoryPublicationLiveChallengeAuthority
    {
        internal int Calls { get; private set; }
        public ValueTask<VerifiedDirectoryPublicationChallenge> VerifyAndConsumeAsync(
            ReadOnlyMemory<byte> nonce, ReadOnlyMemory<byte> bootId,
            ulong nonceCreatedAtMonotonicSeconds, ulong responseReceivedAtMonotonicSeconds,
            ulong currentMonotonicSeconds, CancellationToken cancellationToken)
        {
            Calls++;
            throw new InvalidOperationException("Unexpected nonce mutation.");
        }
    }

    private static string TemporaryRoot() => Path.Combine(Path.GetTempPath(), "deep-directory-cutover", Guid.NewGuid().ToString("N"));
}
#endif
