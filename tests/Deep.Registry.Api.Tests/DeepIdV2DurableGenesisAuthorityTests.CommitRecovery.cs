#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.XPointNetworkV1;
using Deep.Registry.Api.DirectoryPublication;
using Npgsql;
using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Deep.Registry.Api.Tests;

public sealed partial class DeepIdV2DurableGenesisAuthorityTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public async Task PreparedPqAdmissionCompletesExactIntentAfterColdAuthorRestart(int phase)
    {
        await using var fixture = await PreparedCommitFixture.CreateAsync();
        await fixture.PrepareInterruptedAsync(phase);
        var pending = await File.ReadAllBytesAsync(fixture.StatePath + ".pending");
        var old = await File.ReadAllBytesAsync(fixture.StatePath);
        var advances = fixture.Floor.Advances;
        using (var readOnly = fixture.Open())
            await Assert.ThrowsAsync<IOException>(() => readOnly.RequireReadyAsync().AsTask());
        Assert.Equal(old, await File.ReadAllBytesAsync(fixture.StatePath));
        Assert.Equal(pending, await File.ReadAllBytesAsync(fixture.StatePath + ".pending"));
        Assert.Equal(advances, fixture.Floor.Advances);
        fixture.Floor.ClearFault();
        using (var cold = fixture.Open())
        {
            Assert.False(await cold.RenewHeadIfDueAsync(300)); // Completes head1, never authors another head.
            await cold.RequireReadyAsync();
            var replay = await cold.AdmitAsync(fixture.Request);
            Assert.Equal(pending, await File.ReadAllBytesAsync(fixture.StatePath));
            var rows = DeepIdV2DirectoryStateCodec.Decode(DirectoryPublicationProtectedFile.Verify(pending, fixture.Key), fixture.Network.Network);
            Assert.Equal(rows.Heads[^1].ExactAdh1.ToArray(), replay.ExactAdh1.ToArray());
            Assert.Single(rows.Admissions); Assert.Single(rows.Transitions);
            Assert.Equal(1UL, AccountDirectoryAdh1Codec.Decode(replay.ExactAdh1.Span).LogGeneration);
            Assert.False(await cold.RenewHeadIfDueAsync(300));
        }
        Assert.False(File.Exists(fixture.StatePath + ".pending"));
        Assert.Equal(1, fixture.Floor.Advances);
        using var reopened = fixture.Open(); await reopened.RequireReadyAsync();
        Assert.Equal(pending, await File.ReadAllBytesAsync(fixture.StatePath));
    }

    [Fact]
    public async Task ExpiredPreparedHeadCompletesHistoryThenRenewsWithoutRecreatingAdmission()
    {
        await using var fixture = await PreparedCommitFixture.CreateAsync();
        await fixture.PrepareInterruptedAsync(1); fixture.Floor.ClearFault();
        var pending = await File.ReadAllBytesAsync(fixture.StatePath + ".pending");
        var original = DeepIdV2DirectoryStateCodec.Decode(DirectoryPublicationProtectedFile.Verify(pending, fixture.Key), fixture.Network.Network);
        fixture.Time.UnixTime = 1_700_005_000;
        using var cold = fixture.Open(); Assert.True(await cold.RenewHeadIfDueAsync(300));
        await cold.RequireReadyAsync(); Assert.Equal(2, fixture.Floor.Advances);
        var final = DeepIdV2DirectoryStateCodec.Decode(DirectoryPublicationProtectedFile.Verify(
            await File.ReadAllBytesAsync(fixture.StatePath), fixture.Key), fixture.Network.Network);
        Assert.Equal(3, final.Heads.Count); Assert.Single(final.Admissions); Assert.Single(final.Transitions);
        Assert.Equal(original.Heads[1].ExactAdh1.ToArray(), final.Heads[1].ExactAdh1.ToArray());
        Assert.Equal(original.Transitions[0].ToArray(), final.Transitions[0].ToArray());
        Assert.Equal(original.Admissions[0].ExactDga1V2.ToArray(), final.Admissions[0].ExactDga1V2.ToArray());
        Assert.False(File.Exists(fixture.StatePath + ".pending"));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    public async Task InvalidPreparedCustodyOrMissingFloorRejectsWithoutRepair(int damage)
    {
        await using var fixture = await PreparedCommitFixture.CreateAsync();
        await fixture.PrepareInterruptedAsync(1); fixture.Floor.ClearFault();
        if (damage == 0)
        {
            var corrupted = await File.ReadAllBytesAsync(fixture.StatePath + ".pending"); corrupted[^1] ^= 1;
            await File.WriteAllBytesAsync(fixture.StatePath + ".pending", corrupted);
        }
        else if (damage == 1)
            await File.WriteAllBytesAsync(fixture.StatePath + ".pending", await File.ReadAllBytesAsync(fixture.StatePath));
        else if (damage == 2) File.Delete(fixture.StatePath);
        else if (damage == 3) await fixture.DeleteOwnedFloorAsync();
        else if (damage == 4)
        {
            var exact = await File.ReadAllBytesAsync(fixture.StatePath + ".pending");
            var rows = DeepIdV2DirectoryStateCodec.Decode(DirectoryPublicationProtectedFile.Verify(exact, fixture.Key), fixture.Network.Network);
            var heads = rows.Heads.ToArray(); heads[0] = new(heads[0].ExactAdh1, Bytes(32, 0x7f));
            await File.WriteAllBytesAsync(fixture.StatePath + ".pending", DirectoryPublicationProtectedFile.Protect(
                DeepIdV2DirectoryStateCodec.Encode(fixture.Network.Network, new(heads, rows.Transitions, rows.Admissions)), fixture.Key));
        }
        else
        {
            var corrupted = await File.ReadAllBytesAsync(fixture.StatePath); corrupted[^1] ^= 1;
            await File.WriteAllBytesAsync(fixture.StatePath, corrupted);
        }
        var primary = File.Exists(fixture.StatePath) ? await File.ReadAllBytesAsync(fixture.StatePath) : null;
        var pending = await File.ReadAllBytesAsync(fixture.StatePath + ".pending");
        using var cold = fixture.Open();
        if (damage is 0 or 5) await Assert.ThrowsAsync<CryptographicException>(() => cold.RenewHeadIfDueAsync(300).AsTask());
        else if (damage == 2) await Assert.ThrowsAsync<FileNotFoundException>(() => cold.RenewHeadIfDueAsync(300).AsTask());
        else await Assert.ThrowsAsync<InvalidDataException>(() => cold.RenewHeadIfDueAsync(300).AsTask());
        Assert.Equal(1, fixture.Floor.Advances);
        Assert.Equal(pending, await File.ReadAllBytesAsync(fixture.StatePath + ".pending"));
        if (primary is null) Assert.False(File.Exists(fixture.StatePath));
        else Assert.Equal(primary, await File.ReadAllBytesAsync(fixture.StatePath));
        if (damage == 3) Assert.Equal(0L, await fixture.FloorRowsAsync());
    }

    [Fact]
    public async Task PreparedRecoveryWaitsForExternalFloorWithoutChangingExactIntent()
    {
        await using var fixture = await PreparedCommitFixture.CreateAsync();
        await fixture.PrepareInterruptedAsync(1); fixture.Floor.ClearFault();
        var primary = await File.ReadAllBytesAsync(fixture.StatePath);
        var pending = await File.ReadAllBytesAsync(fixture.StatePath + ".pending");
        fixture.Floor.ReadsUnavailable = true;
        using (var cold = fixture.Open())
            await Assert.ThrowsAsync<IOException>(() => cold.RenewHeadIfDueAsync(300).AsTask());
        Assert.Equal(primary, await File.ReadAllBytesAsync(fixture.StatePath));
        Assert.Equal(pending, await File.ReadAllBytesAsync(fixture.StatePath + ".pending")); Assert.Equal(1, fixture.Floor.Advances);
        fixture.Floor.ReadsUnavailable = false;
        using var resumed = fixture.Open(); Assert.False(await resumed.RenewHeadIfDueAsync(300));
        await resumed.RequireReadyAsync(); Assert.Equal(1, fixture.Floor.Advances);
        Assert.Equal(pending, await File.ReadAllBytesAsync(fixture.StatePath));
    }

    [Fact]
    public async Task ConcurrentColdAuthorsCompleteOnePreparedFloorGeneration()
    {
        await using var fixture = await PreparedCommitFixture.CreateAsync();
        await fixture.PrepareInterruptedAsync(0); fixture.Floor.ClearFault();
        var pending = await File.ReadAllBytesAsync(fixture.StatePath + ".pending");
        var results = await Task.WhenAll(Enumerable.Range(0, 6).Select(async _ =>
        {
            using var author = fixture.Open(); return await author.RenewHeadIfDueAsync(300);
        }));
        Assert.All(results, result => Assert.False(result)); Assert.Equal(1, fixture.Floor.Advances);
        Assert.Equal(pending, await File.ReadAllBytesAsync(fixture.StatePath)); Assert.False(File.Exists(fixture.StatePath + ".pending"));
    }

    [Fact]
    public async Task ActualHostedWorkerRecoversPreparedCommitAfterFloorReturns()
    {
        await using var fixture = await PreparedCommitFixture.CreateAsync();
        await fixture.PrepareInterruptedAsync(1); fixture.Floor.ClearFault(); fixture.Floor.ReadsTimedOut = true;
        var pending = await File.ReadAllBytesAsync(fixture.StatePath + ".pending");
        var builder = WebApplication.CreateBuilder(); builder.WebHost.UseTestServer(); builder.Logging.ClearProviders();
        builder.Services.AddSingleton(fixture.Open());
        builder.Services.AddSingleton<IDeepIdV2GenesisAuthority>(provider => provider.GetRequiredService<DeepIdV2DurableGenesisAuthority>());
        builder.Services.AddSingleton(TimeProvider.System); builder.Services.AddSingleton<DeepIdV2IssuanceAdmissionGate>();
        builder.Services.AddHostedService(provider => new DeepIdV2DirectoryHeadRenewalWorker(
            provider.GetRequiredService<DeepIdV2DurableGenesisAuthority>(), 300, TimeSpan.FromSeconds(60),
            provider.GetRequiredService<ILogger<DeepIdV2DirectoryHeadRenewalWorker>>()));
        await using var app = builder.Build(); app.MapDeepIdV2DirectoryAuthorityEndpoint(new(true, false));
        await app.StartAsync(); using var http = app.GetTestClient();
        using (var unavailable = await http.GetAsync(DeepIdV2DirectoryAuthorityHostingExtensions.ReadinessEndpointPath))
            Assert.Equal(HttpStatusCode.ServiceUnavailable, unavailable.StatusCode);
        Assert.Equal(pending, await File.ReadAllBytesAsync(fixture.StatePath + ".pending"));
        fixture.Floor.ReadsTimedOut = false;
        using var budget = new CancellationTokenSource(TimeSpan.FromSeconds(12));
        while (true)
        {
            using var readiness = await http.GetAsync(DeepIdV2DirectoryAuthorityHostingExtensions.ReadinessEndpointPath, budget.Token);
            if (readiness.StatusCode == HttpStatusCode.OK) break;
            Assert.Equal(HttpStatusCode.ServiceUnavailable, readiness.StatusCode); await Task.Delay(50, budget.Token);
        }
        Assert.Equal(pending, await File.ReadAllBytesAsync(fixture.StatePath)); Assert.Equal(1, fixture.Floor.Advances);
        Assert.False(File.Exists(fixture.StatePath + ".pending")); await app.StopAsync(budget.Token);
    }

    [Fact]
    public async Task PreparedHistoryCompletesAcrossVerifiedRootAndWitnessRotation()
    {
        await using var fixture = await PreparedCommitFixture.CreateAsync();
        await fixture.PrepareInterruptedAsync(1); fixture.Floor.ClearFault();
        var pending = await File.ReadAllBytesAsync(fixture.StatePath + ".pending");
        var original = DeepIdV2DirectoryStateCodec.Decode(DirectoryPublicationProtectedFile.Verify(pending, fixture.Key), fixture.Network.Network);
        var current = await fixture.RotateAuthorityAsync();
        using var cold = fixture.Open(); Assert.True(await cold.RenewHeadIfDueAsync(300)); await cold.RequireReadyAsync();
        Assert.Equal(2, fixture.Floor.Advances);
        var final = DeepIdV2DirectoryStateCodec.Decode(DirectoryPublicationProtectedFile.Verify(
            await File.ReadAllBytesAsync(fixture.StatePath), fixture.Key), fixture.Network.Network);
        Assert.Equal(3, final.Heads.Count); Assert.Single(final.Transitions); Assert.Single(final.Admissions);
        Assert.Equal(original.Heads[1].ExactAdh1.ToArray(), final.Heads[1].ExactAdh1.ToArray());
        Assert.Equal(original.Admissions[0].ExactDga1V2.ToArray(), final.Admissions[0].ExactDga1V2.ToArray());
        Assert.Equal(current.AuthorityCoreReference.ToArray(), AccountDirectoryAdh1Codec.Decode(final.Heads[2].ExactAdh1.Span).ExactXnaAuthorityCoreReference.ToArray());
        Assert.False(File.Exists(fixture.StatePath + ".pending")); Assert.False(await cold.RenewHeadIfDueAsync(300));
    }

    private sealed class PreparedCommitFixture : IAsyncDisposable
    {
        private readonly string root = Path.Combine(Path.GetTempPath(), "deep-prepared-commit-" + Guid.NewGuid().ToString("N"));
        private readonly string schema = "did2_commit_" + Guid.NewGuid().ToString("N");
        private NpgsqlConnection admin = null!;
        private FileContactResolveDtt1WitnessCustody custody = null!;
        private DeepIdV2XPointAuthoritySource roots = null!;
        private DeepIdV2DirectoryBootstrapSource bootstrap = null!;
        internal Did2DirectoryAuthorityFixture Network { get; } = Did2DirectoryAuthorityFixture.Create();
        internal byte[] Key { get; } = Bytes(32, 0x5a);
        internal FixedTimeSource Time { get; } = new(1_700_000_400);
        internal FaultingCommitFloor Floor { get; private set; } = null!;
        internal DeepIdV2GenesisAdmissionWireRequest Request { get; private set; } = null!;
        internal string StatePath => Path.Combine(root, "state.ada2");
        internal static async Task<PreparedCommitFixture> CreateAsync()
        {
            var value = new PreparedCommitFixture();
            try { await value.InitializeAsync(); return value; }
            catch { await value.DisposeAsync(); throw; }
        }
        private async Task InitializeAsync()
        {
            var connection = Environment.GetEnvironmentVariable("DEEP_TEST_DID2_FLOOR_POSTGRES");
            Assert.False(string.IsNullOrWhiteSpace(connection), "Disposable PostgreSQL provider is required.");
            Directory.CreateDirectory(root); admin = new(connection); await admin.OpenAsync();
            await using (var setup = new NpgsqlCommand($"CREATE SCHEMA \"{schema}\"; CREATE TABLE \"{schema}\".deep_did2_latest_head_floor (" +
                "network_id bytea PRIMARY KEY CHECK(octet_length(network_id)=16), exact_adh1 bytea NOT NULL, core_hash bytea NOT NULL)", admin))
                await setup.ExecuteNonQueryAsync();
            var head = Network.CreateDid2GenesisHead(); var pin = AccountDirectoryCrypto.ComputeAdh1CoreHash(AccountDirectoryAdh1Codec.Decode(head));
            var headPath = Path.Combine(root, "genesis.adh1"); await File.WriteAllBytesAsync(headPath, head);
            var xna = Path.Combine(root, "root.xna1"); var dts = Path.Combine(root, "time.dts1");
            await File.WriteAllBytesAsync(xna, Network.ExactXna1); await File.WriteAllBytesAsync(dts, Network.ExactDts1);
            roots = new(Network.Network, Network.Authority.AuthorityCoreHash.Span, [xna], [dts]); bootstrap = new(headPath, pin);
            await File.WriteAllBytesAsync(StatePath, DirectoryPublicationProtectedFile.Protect(DeepIdV2DirectoryStateCodec.Encode(Network.Network,
                new([new(head, pin)], [], [])), Key));
            var options = new List<ContactResolveWitnessCustodyOptions>();
            for (var i = 0; i < 2; i++)
            {
                var path = Path.Combine(root, $"witness-{i}.seed"); await File.WriteAllBytesAsync(path, Bytes(32, checked((byte)(0x50 + i))));
                options.Add(new() { WitnessIdHex = Convert.ToHexString(Bytes(32, checked((byte)(0x40 + i)))), KeyGeneration = 0, Ed25519SeedPath = path });
            }
            custody = new(Network.Network, options);
            var database = new DeepIdV2PostgreSqlLatestHeadFloor(new NpgsqlConnectionStringBuilder(connection!) { SearchPath = schema }.ConnectionString, Network.Network);
            Floor = new(database, StatePath); await database.ProvisionGenesisAsync(new(head));
            Request = DeepIdV2GenesisAdmissionWireCodec.DecodeRequest(await File.ReadAllBytesAsync(Path.Combine(AppContext.BaseDirectory, "Fixtures", "did2-genesis.dga1v2")));
        }
        internal DeepIdV2DurableGenesisAuthority Open() => new(roots, bootstrap, custody, Time, StatePath, Network.Network, Key, 1, 3_600, Floor);
        internal async Task<VerifiedXPointNetworkAuthority> RotateAuthorityAsync()
        {
            var renewal = await Network.RenewAuthorityAsync(Time.UnixTime);
            var renewedAuthority = XPointNetworkAuthorityVerifier.Verify(new(Network.Network, Network.Authority.AuthorityCoreHash.Span),
                [Network.ExactXna1, renewal.ExactXna1], [Network.ExactDts1, renewal.ExactDts1]);
            var rotation = Network.RotateAuthority(renewal.ExactXna1, renewal.ExactDts1,
                Network.CreateRenewedView(renewedAuthority, Time.UnixTime), Time.UnixTime);
            var xna1 = Path.Combine(root, "renewed.xna1"); var dts1 = Path.Combine(root, "renewed.dts1");
            var xna2 = Path.Combine(root, "rotated.xna1"); var dts2 = Path.Combine(root, "rotated.dts1");
            await File.WriteAllBytesAsync(xna1, renewal.ExactXna1.ToArray()); await File.WriteAllBytesAsync(dts1, renewal.ExactDts1.ToArray());
            await File.WriteAllBytesAsync(xna2, rotation.Xna); await File.WriteAllBytesAsync(dts2, rotation.Dts);
            roots = new(Network.Network, Network.Authority.AuthorityCoreHash.Span,
                [Path.Combine(root, "root.xna1"), xna1, xna2], [Path.Combine(root, "time.dts1"), dts1, dts2]);
            var options = new List<ContactResolveWitnessCustodyOptions>();
            for (var i = 0; i < 2; i++)
            {
                var path = Path.Combine(root, $"rotated-witness-{i}.seed"); await File.WriteAllBytesAsync(path, Bytes(32, checked((byte)(0x54 + i))));
                options.Add(new() { WitnessIdHex = Convert.ToHexString(Bytes(32, checked((byte)(0x44 + i)))), KeyGeneration = 0, Ed25519SeedPath = path });
            }
            custody.Dispose(); custody = new(Network.Network, options); return roots.Read();
        }
        internal async Task PrepareInterruptedAsync(int phase)
        {
            Floor.Phase = phase;
            using var writer = Open();
            if (phase == 3)
            {
                Floor.Phase = -1; _ = await writer.AdmitAsync(Request);
                await File.WriteAllBytesAsync(StatePath + ".pending", await File.ReadAllBytesAsync(StatePath));
            }
            else
            {
                var error = await Record.ExceptionAsync(() => writer.AdmitAsync(Request).AsTask());
                Assert.NotNull(error); Assert.True(error is IOException or UnauthorizedAccessException);
            }
            Assert.True(File.Exists(StatePath + ".pending"));
        }
        internal async Task DeleteOwnedFloorAsync()
        {
            await using var command = new NpgsqlCommand($"DELETE FROM \"{schema}\".deep_did2_latest_head_floor", admin);
            Assert.Equal(1, await command.ExecuteNonQueryAsync());
        }
        internal async Task<long> FloorRowsAsync()
        {
            await using var command = new NpgsqlCommand($"SELECT count(*) FROM \"{schema}\".deep_did2_latest_head_floor", admin);
            return (long)(await command.ExecuteScalarAsync())!;
        }
        public async ValueTask DisposeAsync()
        {
            Floor?.ClearFault(); Floor?.Dispose(); custody?.Dispose(); Network.Dispose(); CryptographicOperations.ZeroMemory(Key);
            if (admin is not null)
            {
                if (admin.State == System.Data.ConnectionState.Open)
                { await using var cleanup = new NpgsqlCommand($"DROP SCHEMA IF EXISTS \"{schema}\" CASCADE", admin); await cleanup.ExecuteNonQueryAsync(); }
                await admin.DisposeAsync();
            }
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    private sealed class FaultingCommitFloor(DeepIdV2PostgreSqlLatestHeadFloor inner, string path) : IDeepIdV2DirectoryLatestHeadFloor, IDisposable
    {
        private FileStream? blocker;
        internal int Phase { get; set; } = -1;
        internal int Advances { get; private set; }
        internal bool ReadsUnavailable { get; set; }
        internal bool ReadsTimedOut { get; set; }
        public ValueTask RequireCurrentAsync(AccountDirectoryProtectedLkg head, CancellationToken ct = default) =>
            ReadsTimedOut ? ValueTask.FromException(new TimeoutException("Injected floor read timeout.")) :
            ReadsUnavailable ? ValueTask.FromException(new IOException("Injected floor read outage.")) : inner.RequireCurrentAsync(head, ct);
        public async ValueTask AdvanceAsync(AccountDirectoryProtectedLkg prior, AccountDirectoryProtectedLkg next, CancellationToken ct = default)
        {
            Assert.True(File.Exists(path + ".pending"));
            if (Phase == 0) throw new IOException("Injected pre-CAS interruption.");
            await inner.AdvanceAsync(prior, next, ct); Advances++;
            if (Phase == 1) throw new IOException("Injected lost CAS acknowledgement.");
            if (Phase == 2)
            {
                if (!OperatingSystem.IsWindows()) throw new IOException("Injected post-CAS interruption on non-Windows.");
                blocker = new(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            }
        }
        internal void ClearFault() { Phase = -1; blocker?.Dispose(); blocker = null; }
        public void Dispose() { ClearFault(); inner.Dispose(); }
    }
}
#endif
