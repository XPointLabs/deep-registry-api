#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.XPointNetworkV1;
using Deep.Registry.Api.DirectoryPublication;

namespace Deep.Registry.Api.Tests;

public sealed class DirectorySameDayReplayLedgerTests
{
    private const ulong Observed = 1_700_000_100;
    private static byte[] B(int length, byte value) => Enumerable.Repeat(value, length).ToArray();
    private static ContactResolveTrustedTimeContext Time => new(B(16, 4), 901, Observed, 1);
    private static DirectoryProofReplayRequest Request(byte[] network, byte nonce) => new(network, B(32, nonce), B(16, 8), 99);
    private static string Root() => Path.Combine(Path.GetTempPath(), "deep-same-day-ledger", Guid.NewGuid().ToString("N"));

    private static async Task<(AccountDirectoryDtt1IssuanceEpoch Old, AccountDirectoryDtt1IssuanceEpoch New)> Epochs(Did2DirectoryAuthorityFixture fixture)
    {
        var renewal = await fixture.RenewAuthorityAsync(Observed);
        var authority = XPointNetworkAuthorityVerifier.Verify(new(fixture.Network, fixture.Authority.AuthorityCoreHash.Span),
            [fixture.ExactXna1, renewal.ExactXna1], [fixture.ExactDts1, renewal.ExactDts1]);
        return (AccountDirectoryDtt1IssuanceEpoch.Derive(fixture.Authority, Observed, 1),
            AccountDirectoryDtt1IssuanceEpoch.Derive(authority, Observed, 1));
    }

    [Fact]
    public async Task SameDayQuotaSpansAuthorityNamespacesAndReadinessDoesNotResetIt()
    {
        using var fixture = Did2DirectoryAuthorityFixture.Create(); var (old, current) = await Epochs(fixture); var root = Root();
        try {
            using (var first = new ProtectedFileContactResolveOneUseRequestLedger(root, fixture.Network, B(32, 5), capacity:16))
                for (byte nonce = 1; nonce <= 16; nonce++) await first.ConsumeAsync(Request(fixture.Network, nonce), Time, old, default);
            var before = Directory.GetFiles(root, "*", SearchOption.AllDirectories).ToDictionary(p => p, File.ReadAllBytes);
            using var cold = new ProtectedFileContactResolveOneUseRequestLedger(root, fixture.Network, B(32, 5), capacity:16);
            await Assert.ThrowsAsync<ContactResolveDirectoryAdmissionException>(() => cold.RequireReadyAsync(current, default).AsTask());
            foreach (var (path, bytes) in before) Assert.Equal(bytes, await File.ReadAllBytesAsync(path));
            await Assert.ThrowsAsync<ContactResolveDirectoryAdmissionException>(() => cold.ConsumeAsync(Request(fixture.Network, 17), Time, current, default).AsTask());
            Assert.Equal(16, Directory.GetFiles(root, "*.request", SearchOption.AllDirectories).Length);
            var payload = DirectoryPublicationProtectedFile.Verify(await File.ReadAllBytesAsync(Path.Combine(root, ".quota.state")), B(32, 5));
            Assert.Equal(16U, BinaryPrimitives.ReadUInt32BigEndian(payload.Slice(62, 4)));
            foreach (var (path, bytes) in before.Where(p => p.Key.EndsWith(".request", StringComparison.Ordinal))) Assert.Equal(bytes, await File.ReadAllBytesAsync(path));
        } finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
    }

    [Fact]
    public async Task CompetingColdSameDayWritersConsumeOneNonceAcrossTheHandover()
    {
        using var fixture = Did2DirectoryAuthorityFixture.Create(); var (old, current) = await Epochs(fixture); var root = Root();
        try {
            using (var first = new ProtectedFileContactResolveOneUseRequestLedger(root, fixture.Network, B(32, 5)))
                await first.ConsumeAsync(Request(fixture.Network, 1), Time, old, default);
            using var a = new ProtectedFileContactResolveOneUseRequestLedger(root, fixture.Network, B(32, 5));
            using var b = new ProtectedFileContactResolveOneUseRequestLedger(root, fixture.Network, B(32, 5));
            var results = await Task.WhenAll(Try(a), Try(b));
            Assert.Equal(1, results.Count(accepted => accepted));
            Assert.Equal(2, Directory.GetFiles(root, "*.request", SearchOption.AllDirectories).Length);
            await Assert.ThrowsAsync<CryptographicException>(() => b.ConsumeAsync(Request(fixture.Network, 1), Time, current, default).AsTask());
            async Task<bool> Try(ProtectedFileContactResolveOneUseRequestLedger ledger) => await Task.Run(async () => {
                try { await ledger.ConsumeAsync(Request(fixture.Network, 2), Time, current, default); return true; }
                catch (CryptographicException) { return false; }
            });
        } finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
    }

    [Fact]
    public async Task PartialAncestorMarkerNeverReopensItsNonceAndBlocksBoundedRecovery()
    {
        using var fixture = Did2DirectoryAuthorityFixture.Create(); var (old, current) = await Epochs(fixture); var root = Root();
        try {
            using (var first = new ProtectedFileContactResolveOneUseRequestLedger(root, fixture.Network, B(32, 5)))
                await first.ConsumeAsync(Request(fixture.Network, 1), Time, old, default);
            var marker = Directory.GetFiles(root, "*.request", SearchOption.AllDirectories).Single();
            await File.WriteAllBytesAsync(marker, []); // Simulated crash, not a runtime custody repair.
            using var cold = new ProtectedFileContactResolveOneUseRequestLedger(root, fixture.Network, B(32, 5));
            await Assert.ThrowsAsync<CryptographicException>(() => cold.ConsumeAsync(Request(fixture.Network, 1), Time, current, default).AsTask());
            var tomorrow = AccountDirectoryDtt1IssuanceEpoch.Derive(fixture.Authority, Observed + 86_400, 1);
            await Assert.ThrowsAsync<InvalidDataException>(() => cold.RequireReadyAsync(tomorrow, default).AsTask());
            Assert.Empty(await File.ReadAllBytesAsync(marker)); Assert.Single(Directory.GetFiles(root, "*.request", SearchOption.AllDirectories));
        } finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
    }
}
#endif
