#if DEEP_PROTOCOL_DIRECTORY_V1
extern alias xnode;
using System.Buffers.Binary;
using System.Net;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.AccountDirectoryV2;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Registry.Api.DirectoryPublication;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;

namespace Deep.Registry.Api.Tests;

public sealed partial class DeepIdV2DirectoryAuthorityHttpTests
{
    [Fact]
    public async Task ActualClientAndNodeCatchUpAcrossTwoHistoryPagesAfterInterruptedRecovery()
    {
        var connectionString = Environment.GetEnvironmentVariable("DEEP_TEST_DID2_FLOOR_POSTGRES");
        Assert.False(string.IsNullOrWhiteSpace(connectionString), "This source lane requires the disposable PostgreSQL provider.");
        var schema = "did2_catchup_" + Guid.NewGuid().ToString("N");
        var scoped = new NpgsqlConnectionStringBuilder(connectionString!) { SearchPath = schema }.ConnectionString;
        await using var admin = new NpgsqlConnection(connectionString);
        await admin.OpenAsync();
        await using (var setup = new NpgsqlCommand($"CREATE SCHEMA \"{schema}\"; " +
            $"CREATE TABLE \"{schema}\".deep_did2_latest_head_floor (" +
            "network_id bytea PRIMARY KEY CHECK (octet_length(network_id)=16), " +
            "exact_adh1 bytea NOT NULL CHECK (octet_length(exact_adh1) BETWEEN 1 AND 4096), " +
            "core_hash bytea NOT NULL CHECK (octet_length(core_hash)=32))", admin))
            await setup.ExecuteNonQueryAsync();
        var root = Path.Combine(Path.GetTempPath(), "deep-did2-two-page-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            using var fixture = Did2DirectoryAuthorityFixture.Create();
            var paths = await ProvisionAsync(root, fixture);
            var time = new FixedTimeSource();
            var view = Path.Combine(root, "current.xnv1"); var proofKey = Path.Combine(root, "proof.key");
            await File.WriteAllBytesAsync(view, fixture.ExactCurrentXnv1);
            await File.WriteAllBytesAsync(proofKey, Bytes(32, 0x6b));
            using var independentFloor = new DeepIdV2PostgreSqlLatestHeadFloor(scoped, fixture.Network);
            await independentFloor.ProvisionGenesisAsync(new AccountDirectoryProtectedLkg(paths.Head));
            await using var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
            {
                Configure(builder, paths, fixture.Network, null, scoped, time);
                builder.UseSetting("DeepIdV2DirectoryAuthority:ProofEnabled", "true");
                builder.UseSetting("DeepIdV2DirectoryAuthority:CurrentXnv1Path", view);
                builder.UseSetting("DeepIdV2DirectoryAuthority:ProofRequestLedgerRootPath", Path.Combine(root, "proof-nonces"));
                builder.UseSetting("DeepIdV2DirectoryAuthority:ProofRequestLedgerIntegrityKeyPath", proofKey);
            });
            using var storage = new InMemoryDeepSecureStorage();
            var clientRoot = Path.Combine(root, "client"); Directory.CreateDirectory(clientRoot);
            DeepIdV2AccountService Account() => new(storage, clientRoot, fixture.Network, 1,
                new FrozenClock(DateTimeOffset.FromUnixTimeSeconds(1_700_000_400)),
                DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess);
            var account = Account(); var created = await account.CreateAsync("Catch-up Alice");
            var floor = await account.OpenDirectoryLkgStoreAsync(fixture.Authority, paths.Head, paths.HeadPin);
            var exactAdmission = await account.PrepareGenesisAdmissionAsync();
            var did = DeepIdV2Codec.DecodeDid2(DeepIdV2GenesisAdmissionWireCodec.DecodeRequest(exactAdmission).Admission.ExactDid2.Span);
            using var http = factory.CreateClient(); http.BaseAddress = new Uri("https://registry.example/");
            using var admissionHttp = factory.CreateClient(); admissionHttp.BaseAddress = http.BaseAddress;
            using var admissionTransport = new HttpServiceRequestTransport(admissionHttp,
                DeepIdV2GenesisAdmissionClient.CreateTransportOptions(http.BaseAddress.AbsoluteUri), HttpServiceEndpointPolicy.Production);
            using var admission = new DeepIdV2GenesisAdmissionClient(admissionTransport);
            using var crypto = DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess();
            using var firstProofHttp = factory.CreateClient(); firstProofHttp.BaseAddress = http.BaseAddress;
            using var firstHistoryHttp = factory.CreateClient(); firstHistoryHttp.BaseAddress = http.BaseAddress;
            using var proofTransport = new HttpServiceRequestTransport(firstProofHttp,
                DeepIdV2DirectoryProofClient.CreateTransportOptions(http.BaseAddress.AbsoluteUri), HttpServiceEndpointPolicy.Production);
            using (var proof = new DeepIdV2DirectoryProofClient(proofTransport, History(firstHistoryHttp), new IncreasingMonotonicClock(), crypto, floor))
            {
                var first = await account.AdmitAndVerifyGenesisAsync(admission, proof, fixture.Authority);
                Assert.Equal(1UL, first.NextProtectedLkg.LogGeneration);
            }

            var nodeOptions = new XNode.Core.RouterNodeOptions { DataDirectory = Path.Combine(root, "node") };
            var settings = new xnode::XNode.DeepIdV2DirectoryProofOptions
            {
                Enabled = true, RegistryOrigin = http.BaseAddress.AbsoluteUri,
                NetworkIdHex = Convert.ToHexString(fixture.Network), GenesisAuthorityCoreHashHex = Convert.ToHexString(paths.NetworkPin),
                ExactAuthorityPaths = [paths.AuthorityPath], ExactTimePolicyPaths = [paths.PolicyPath],
                GenesisHeadPath = paths.HeadPath, GenesisHeadCoreHashHex = Convert.ToHexString(paths.HeadPin),
                StateRelativeDirectory = "proof-head", DataProtectionKeysRelativeDirectory = "proof-keys",
                DeploymentProfileId = 1, RequestTimeoutSeconds = 5
            };
            xnode::XNode.DeepIdV2DirectoryProofRuntime Node(HttpClient client) => new(
                settings.ValidateAndLoad(nodeOptions, developmentOrUat: true)!, client, new IncreasingMonotonicClock(),
                new XNode.Core.Mailbox.MailboxStorageSecurity(), new XNode.Core.Mailbox.MailboxDurabilityBarrier());
            using (var node = Node(http))
                Assert.Equal(1UL, (await node.ReadCurrentAsync(did, default)).NextProtectedLkg.LogGeneration);

            var renewal = factory.Services.GetRequiredService<DeepIdV2DurableGenesisAuthority>();
            var observed = 1_700_000_400L;
            for (var index = 0; index < 69; index++)
            {
                observed += 3_300; time.SetUnixTime(observed);
                Assert.True(await renewal.RenewHeadIfDueAsync(300));
            }
            await File.WriteAllBytesAsync(view, fixture.CreateRenewedView(fixture.Authority, checked((ulong)observed)));
            await renewal.RequireReadyAsync();
            Assert.Equal(1UL, (await floor.RestoreAsync(fixture.Authority, default)).LogGeneration);
            var issuerHead = await factory.Services.GetRequiredService<DeepIdV2DirectoryProofIssuer>().ReadCurrentHeadAsync(default);
            Assert.Equal(70UL, issuerHead.LogGeneration); Assert.Equal(1UL, issuerHead.TreeSize);

            // Interrupt the second actual history page. The first verified page
            // must survive cold reopen, but cannot be promoted to fresh proof.
            using var interrupted = new HistoryPageProbe(factory.Server.CreateHandler()) { RejectHistoryRequest = 2 };
            using var recoveryHttp = new HttpClient(interrupted, disposeHandler: false) { BaseAddress = http.BaseAddress };
            using var recoveryHistoryHttp = new HttpClient(interrupted, disposeHandler: false) { BaseAddress = http.BaseAddress };
            using var recoveryTransport = new HttpServiceRequestTransport(recoveryHttp,
                DeepIdV2DirectoryProofClient.CreateTransportOptions(http.BaseAddress.AbsoluteUri), HttpServiceEndpointPolicy.Production);
            using (var proof = new DeepIdV2DirectoryProofClient(recoveryTransport, History(recoveryHistoryHttp), new IncreasingMonotonicClock(), crypto, floor))
                await Assert.ThrowsAsync<DeepIdV2DirectoryProofUnavailableException>(() => proof.FetchByDid2Async(did, fixture.Authority, 1, 2).AsTask());
            Assert.Equal(new[] { 64 }, interrupted.PageSizes); Assert.Equal(new ulong[] { 1, 65 }, interrupted.SourceGenerations);
            Assert.Equal(65UL, (await floor.RestoreAsync(fixture.Authority, default)).LogGeneration);
            var reopened = Account(); Assert.Equal(created.PermanentId, (await reopened.GetCurrentAsync())!.PermanentId);
            var reopenedFloor = await reopened.OpenDirectoryLkgStoreAsync(fixture.Authority, paths.Head, paths.HeadPin);
            Assert.Equal(65UL, (await reopenedFloor.RestoreAsync(fixture.Authority, default)).LogGeneration);
            interrupted.RejectHistoryRequest = 0;
            using var resumedHttp = new HttpClient(interrupted, disposeHandler: false) { BaseAddress = http.BaseAddress };
            using var resumedHistoryHttp = new HttpClient(interrupted, disposeHandler: false) { BaseAddress = http.BaseAddress };
            using var resumedTransport = new HttpServiceRequestTransport(resumedHttp,
                DeepIdV2DirectoryProofClient.CreateTransportOptions(http.BaseAddress.AbsoluteUri), HttpServiceEndpointPolicy.Production);
            using (var proof = new DeepIdV2DirectoryProofClient(resumedTransport, History(resumedHistoryHttp), new IncreasingMonotonicClock(), crypto, reopenedFloor))
            {
                var current = await proof.FetchByDid2Async(did, fixture.Authority, 1, 2);
                Assert.NotNull(current.CurrentCheckpoint); Assert.Equal(70UL, current.NextProtectedLkg.LogGeneration);
            }
            Assert.Equal(new[] { 64, 5 }, interrupted.PageSizes);
            Assert.Equal(issuerHead.ExactAdh1.ToArray(), (await reopenedFloor.RestoreAsync(fixture.Authority, default)).ExactAdh1.ToArray());

            using var nodeHistory = new HistoryPageProbe(factory.Server.CreateHandler());
            using var nodeHttp = new HttpClient(nodeHistory) { BaseAddress = http.BaseAddress };
            using (var node = Node(nodeHttp))
            {
                Assert.Equal(1UL, (await node.RestoreHeadAsync(default)).LogGeneration);
                var current = await node.ReadCurrentAsync(did, default);
                Assert.NotNull(current.CurrentCheckpoint); Assert.Equal(70UL, current.NextProtectedLkg.LogGeneration);
                await node.ValidateObservedAsync(current, default);
            }
            Assert.Equal(new[] { 64, 5 }, nodeHistory.PageSizes);
            Assert.Equal(new ulong[] { 1, 65 }, nodeHistory.SourceGenerations);
            using (var coldNode = Node(nodeHttp))
            {
                Assert.Equal(issuerHead.ExactAdh1.ToArray(), (await coldNode.RestoreHeadAsync(default)).ExactAdh1.ToArray());
                _ = await coldNode.ReadCurrentAsync(did, default);
            }
            Assert.Equal(2, nodeHistory.PageSizes.Count); // No replay/reset after native cold reopen.
        }
        finally
        {
            Directory.Delete(root, recursive: true);
            await using var cleanup = new NpgsqlCommand($"DROP SCHEMA \"{schema}\" CASCADE", admin);
            await cleanup.ExecuteNonQueryAsync();
        }
    }

    private sealed class HistoryPageProbe(HttpMessageHandler inner) : DelegatingHandler(inner)
    {
        internal List<int> PageSizes { get; } = [];
        internal List<ulong> SourceGenerations { get; } = [];
        internal int RejectHistoryRequest { get; set; }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            if (request.RequestUri!.AbsolutePath != DeepIdV2DirectoryAuthorityHostingExtensions.HistoryEndpointPath)
                return await base.SendAsync(request, ct);
            var exact = await request.Content!.ReadAsByteArrayAsync(ct);
            DeepIdV2DirectoryHistoryWireCodec.ValidateRequest(exact);
            SourceGenerations.Add(BinaryPrimitives.ReadUInt64BigEndian(exact.AsSpan(28)));
            if (SourceGenerations.Count == RejectHistoryRequest)
                return new HttpResponseMessage(HttpStatusCode.ServiceUnavailable) { RequestMessage = request };
            var response = await base.SendAsync(request, ct);
            if (response.StatusCode == HttpStatusCode.OK)
            {
                var body = await response.Content.ReadAsByteArrayAsync(ct);
                PageSizes.Add(DeepIdV2DirectoryHistoryWireCodec.DecodeResponse(body, exact).ExactSuccessors.Count);
            }
            return response;
        }
    }
}
#endif
