#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.XPointNetworkV1;
using Deep.Registry.Api.DirectoryPublication;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.AccountDirectoryV2;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Npgsql;

namespace Deep.Registry.Api.Tests;

public sealed class DeepIdV2DirectoryAuthorityHttpTests
{
    [Fact]
    public async Task ExternalRegistryAcceptsAndProvesFreshDid2GenesisWhenConfigured()
    {
        var origin = Environment.GetEnvironmentVariable(
            "DEEP_TEST_DID2_EXTERNAL_ORIGIN");
        if (string.IsNullOrWhiteSpace(origin)) return;
        if (!(OperatingSystem.IsWindows() ||
              (OperatingSystem.IsLinux() &&
               System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture ==
               System.Runtime.InteropServices.Architecture.X64)))
            return;

        static string Required(string name) =>
            Environment.GetEnvironmentVariable(name) is { Length: > 0 } value
                ? value
                : throw new InvalidOperationException(
                    $"The external DID2 test requires {name}.");

        var network = Convert.FromHexString(Required(
            "DEEP_TEST_DID2_EXTERNAL_NETWORK_ID"));
        var xnaPin = Convert.FromHexString(Required(
            "DEEP_TEST_DID2_EXTERNAL_XNA1_PIN"));
        var headPin = Convert.FromHexString(Required(
            "DEEP_TEST_DID2_EXTERNAL_ADH1_PIN"));
        var authority = new DeepIdV2XPointAuthoritySource(network, xnaPin,
            [Required("DEEP_TEST_DID2_EXTERNAL_XNA1_PATH")],
            [Required("DEEP_TEST_DID2_EXTERNAL_DTS1_PATH")]).Read();
        var genesisHead = await File.ReadAllBytesAsync(Required(
            "DEEP_TEST_DID2_EXTERNAL_ADH1_PATH"));
        var root = Path.Combine(Path.GetTempPath(),
            "deep-did2-external-registry", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            using var secureStorage = new InMemoryDeepSecureStorage();
            var accounts = new DeepIdV2AccountService(secureStorage, root,
                network, 1, new SystemClock(),
                DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess);
            var created = await accounts.CreateAsync("DID2 External Probe");
            var protectedFloor = await accounts.OpenDirectoryLkgStoreAsync(
                authority, genesisHead, headPin);
            Assert.Equal(0UL, (await protectedFloor.RestoreAsync(authority,
                default)).TreeSize);

            using var admissionHttp = new HttpClient { BaseAddress = new Uri(origin) };
            using var admissionTransport = new HttpServiceRequestTransport(
                admissionHttp,
                DeepIdV2GenesisAdmissionClient.CreateTransportOptions(origin),
                HttpServiceEndpointPolicy.Production);
            using var admission = new DeepIdV2GenesisAdmissionClient(
                admissionTransport);
            using var proofHttp = new HttpClient { BaseAddress = new Uri(origin) };
            using var proofTransport = new HttpServiceRequestTransport(
                proofHttp,
                DeepIdV2DirectoryProofClient.CreateTransportOptions(origin),
                HttpServiceEndpointPolicy.Production);
            using var verifier = DeepMlDsa65CandidateVerifierFactory
                .OpenForCurrentProcess();
            using var proof = new DeepIdV2DirectoryProofClient(proofTransport,
                new ExternalMonotonicClock(), verifier, protectedFloor);
            var verified = await accounts.AdmitAndVerifyGenesisAsync(admission,
                proof, authority);
            Assert.NotNull(verified.CurrentCheckpoint);
            // A long-running external canary may already contain other
            // admitted accounts. The signed proof must confirm this exact
            // account, not assume a freshly reset directory.
            Assert.True(verified.NextProtectedLkg.TreeSize >= 1);
            Assert.Equal(created.PermanentId,
                (await accounts.GetCurrentAsync())!.PermanentId);
            Assert.Equal(verified.NextProtectedLkg.CoreHash.ToArray(),
                (await protectedFloor.RestoreAsync(authority, default))
                .CoreHash.ToArray());
            var contactExport = Environment.GetEnvironmentVariable(
                "DEEP_TEST_DID2_EXTERNAL_CONTACT_EXPORT");
            if (!string.IsNullOrWhiteSpace(contactExport))
            {
                var exactAdmission = await accounts.PrepareGenesisAdmissionAsync();
                try
                {
                    var exactDid2 = DeepIdV2GenesisAdmissionWireCodec
                        .DecodeRequest(exactAdmission).Admission.ExactDid2;
                    await using var output = new FileStream(
                        Path.GetFullPath(contactExport), FileMode.CreateNew,
                        FileAccess.Write, FileShare.None);
                    await using var writer = new StreamWriter(output,
                        new System.Text.UTF8Encoding(false));
                    await writer.WriteLineAsync(created.PermanentId.CanonicalText);
                    await writer.WriteLineAsync(
                        Convert.ToHexString(exactDid2.Span));
                }
                finally { CryptographicOperations.ZeroMemory(exactAdmission); }
            }
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task CreatedClientAccountRequiresAndCommitsRealRegistryProof()
    {
        if (!(OperatingSystem.IsWindows() ||
              (OperatingSystem.IsLinux() &&
               System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture ==
               System.Runtime.InteropServices.Architecture.X64)))
            return;
        using var fixture = ContactResolveAuthoringFixture.Create(
            currentValue: false);
        var root = Path.Combine(Path.GetTempPath(),
            "deep-did2-client-registry", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var paths = await ProvisionAsync(root, fixture);
            var clientRoot = Path.Combine(root, "client");
            Directory.CreateDirectory(clientRoot);
            var currentView = Path.Combine(root, "current.xnv1");
            var proofKey = Path.Combine(root, "proof-ledger.key");
            await File.WriteAllBytesAsync(currentView,
                fixture.Snapshot.ExactCurrentXnv1.ToArray());
            await File.WriteAllBytesAsync(proofKey, Bytes(32, 0x6b));
            await using var factory = new WebApplicationFactory<Program>()
                .WithWebHostBuilder(builder =>
                {
                    Configure(builder, paths, fixture.Network, null);
                    builder.UseSetting("DeepIdV2DirectoryAuthority:ProofEnabled",
                        "true");
                    builder.UseSetting("DeepIdV2DirectoryAuthority:CurrentXnv1Path",
                        currentView);
                    builder.UseSetting(
                        "DeepIdV2DirectoryAuthority:ProofRequestLedgerRootPath",
                        Path.Combine(root, "proof-ledger"));
                    builder.UseSetting(
                        "DeepIdV2DirectoryAuthority:ProofRequestLedgerIntegrityKeyPath",
                        proofKey);
                });
            using (var readinessClient = factory.CreateClient())
            using (var readiness = await readinessClient.GetAsync(
                       DeepIdV2DirectoryAuthorityHostingExtensions
                           .ReadinessEndpointPath))
                Assert.Equal(HttpStatusCode.ServiceUnavailable,
                    readiness.StatusCode); // No independent latest-head floor.
            using var secureStorage = new InMemoryDeepSecureStorage();
            var accounts = new DeepIdV2AccountService(secureStorage,
                clientRoot, fixture.Network, 1,
                new FrozenClock(DateTimeOffset.FromUnixTimeSeconds(
                    1_700_000_400)),
                DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess);
            var created = await accounts.CreateAsync("Alice");
            var protectedFloor = await accounts.OpenDirectoryLkgStoreAsync(
                fixture.Authority, paths.Head, paths.HeadPin);
            var initial = await protectedFloor.RestoreAsync(fixture.Authority,
                default);
            Assert.Equal(0UL, initial.TreeSize);

            using var admissionHttp = factory.CreateClient();
            admissionHttp.BaseAddress = new Uri("https://registry.example/");
            using var admissionTransport = new HttpServiceRequestTransport(
                admissionHttp,
                DeepIdV2GenesisAdmissionClient.CreateTransportOptions(
                    "https://registry.example/"),
                HttpServiceEndpointPolicy.Production);
            using var admission = new DeepIdV2GenesisAdmissionClient(
                admissionTransport);
            using var proofHttp = factory.CreateClient();
            proofHttp.BaseAddress = new Uri("https://registry.example/");
            using var proofTransport = new HttpServiceRequestTransport(
                proofHttp,
                DeepIdV2DirectoryProofClient.CreateTransportOptions(
                    "https://registry.example/"),
                HttpServiceEndpointPolicy.Production);
            using var verifier = DeepMlDsa65CandidateVerifierFactory
                .OpenForCurrentProcess();
            using var proof = new DeepIdV2DirectoryProofClient(
                proofTransport, new IncreasingMonotonicClock(), verifier,
                protectedFloor);
            var verified = await accounts.AdmitAndVerifyGenesisAsync(
                admission, proof, fixture.Authority);
            Assert.NotNull(verified.CurrentCheckpoint);
            Assert.Equal(1UL, verified.NextProtectedLkg.TreeSize);
            var dtt = AccountDirectoryDtt1Codec.Decode(
                verified.ExactDtt1.Span);
            Assert.Equal(1_700_000_400UL, dtt.IssuedAt);
            Assert.InRange(dtt.ExpiresAt,
                dtt.ObservedUnixTime + dtt.UncertaintySeconds + 1,
                dtt.ObservedUnixTime + 30);
            Assert.True(verified.IsCurrentAtMonotonic(
                Bytes(16, 0xc1), verified.MonotonicSample + 1));
            Assert.False(verified.IsCurrentAtMonotonic(
                Bytes(16, 0xc1),
                verified.FreshnessDeadlineMonotonicSeconds));
            using (var prekeys = await accounts
                       .OpenLocalPreKeyAuthoringAuthorityAsync())
            {
                var currentDirectory = ApplicationCoreVerifier.StartDmd1Lineage(
                    verified.CurrentCheckpoint!.Directory).Next;
                var context = new Dpk2AuthoringContext(currentDirectory,
                    1, 1, 1, 1_700_000_400, 1_700_000_400,
                    1_700_086_800);
                if (OperatingSystem.IsWindows())
                {
                    using var offering = prekeys.AuthorOneTime(context);
                    Assert.Equal(prekeys.DeviceId.ToArray(),
                        offering.Record.ResponderDeviceId.ToArray());
                    Assert.Equal(32, offering.ExactDpk2Hash.Length);
                }
                else
                    Assert.Throws<PlatformNotSupportedException>(() =>
                        prekeys.AuthorOneTime(context));
            }
            Assert.Equal(verified.NextProtectedLkg.CoreHash.ToArray(),
                (await protectedFloor.RestoreAsync(fixture.Authority, default))
                .CoreHash.ToArray());
            var reopened = new DeepIdV2AccountService(secureStorage,
                clientRoot, fixture.Network, 1,
                new FrozenClock(DateTimeOffset.FromUnixTimeSeconds(
                    1_700_000_400)),
                DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess);
            Assert.Equal(created.PermanentId,
                (await reopened.GetCurrentAsync())!.PermanentId);
            var reopenedFloor = await reopened.OpenDirectoryLkgStoreAsync(
                fixture.Authority, paths.Head, paths.HeadPin);
            Assert.Equal(verified.NextProtectedLkg.CoreHash.ToArray(),
                (await reopenedFloor.RestoreAsync(fixture.Authority, default))
                .CoreHash.ToArray());

            var secondRoot = Path.Combine(root, "second-client");
            Directory.CreateDirectory(secondRoot);
            using var secondStorage = new InMemoryDeepSecureStorage();
            var secondAccounts = new DeepIdV2AccountService(secondStorage,
                secondRoot, fixture.Network, 1,
                new FrozenClock(DateTimeOffset.FromUnixTimeSeconds(
                    1_700_000_400)),
                DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess);
            _ = await secondAccounts.CreateAsync("Bob");
            var secondFloor = await secondAccounts.OpenDirectoryLkgStoreAsync(
                fixture.Authority, paths.Head, paths.HeadPin);
            using var secondAdmissionHttp = factory.CreateClient();
            secondAdmissionHttp.BaseAddress = new Uri("https://registry.example/");
            using var secondAdmissionTransport = new HttpServiceRequestTransport(
                secondAdmissionHttp,
                DeepIdV2GenesisAdmissionClient.CreateTransportOptions(
                    "https://registry.example/"),
                HttpServiceEndpointPolicy.Production);
            using var secondAdmission = new DeepIdV2GenesisAdmissionClient(
                secondAdmissionTransport);
            using var secondProofHttp = factory.CreateClient();
            secondProofHttp.BaseAddress = new Uri("https://registry.example/");
            using var secondProofTransport = new HttpServiceRequestTransport(
                secondProofHttp,
                DeepIdV2DirectoryProofClient.CreateTransportOptions(
                    "https://registry.example/"),
                HttpServiceEndpointPolicy.Production);
            using var secondVerifier = DeepMlDsa65CandidateVerifierFactory
                .OpenForCurrentProcess();
            using var secondProof = new DeepIdV2DirectoryProofClient(
                secondProofTransport, new IncreasingMonotonicClock(),
                secondVerifier, secondFloor);
            await Assert.ThrowsAsync<IOException>(async () =>
                await secondAccounts.AdmitAndVerifyGenesisAsync(
                    secondAdmission, secondProof, fixture.Authority));
            var secondProtected = await secondFloor.RestoreAsync(
                fixture.Authority, default);
            Assert.Equal(0UL, secondProtected.TreeSize);
            var secondWire = DeepIdV2GenesisAdmissionWireCodec.DecodeRequest(
                await secondAccounts.PrepareGenesisAdmissionAsync());
            var secondDid = DeepIdV2Codec.DecodeDid2(
                secondWire.Admission.ExactDid2.Span);
            var secondLeaf = DeepIdV2AccountDirectoryCodec
                .ComputeDirectoryLeafKey(fixture.Network, secondDid);
            var directRequest = new DeepIdV2DirectoryProofRequest(
                fixture.Network, Bytes(32, 0x77), Bytes(16, 0x78),
                4_000, secondLeaf, secondProtected);
            var noCheckpoint = await Assert.ThrowsAsync<CryptographicException>(
                async () => await factory.Services.GetRequiredService<
                    DeepIdV2DirectoryProofIssuer>().IssueAsync(directRequest));
            Assert.Contains("forward checkpoint", noCheckpoint.Message,
                StringComparison.OrdinalIgnoreCase);
            var firstAtLatest = await proof.FetchOwnGenesisAsync(
                verified.CurrentCheckpoint!.Binding, fixture.Authority, 1, 2);
            Assert.Equal(2UL, firstAtLatest.NextProtectedLkg.TreeSize);
            Assert.NotNull(firstAtLatest.CurrentCheckpoint);
            await factory.DisposeAsync();

            // Offline export reads the authenticated ADA2 journal and only
            // writes the head matching an independently observed floor pin.
            var exportPath = Path.Combine(root, "current-export.adh1");
            var exportConfig = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["DeepIdV2DirectoryAuthority:NetworkIdHex"] =
                        Convert.ToHexString(fixture.Network),
                    ["DeepIdV2DirectoryAuthority:GenesisAuthorityCoreHashHex"] =
                        Convert.ToHexString(paths.NetworkPin),
                    ["DeepIdV2DirectoryAuthority:ExactAuthorityPaths:0"] =
                        paths.AuthorityPath,
                    ["DeepIdV2DirectoryAuthority:ExactTimePolicyPaths:0"] =
                        paths.PolicyPath,
                    ["DeepIdV2DirectoryAuthority:GenesisHeadPath"] =
                        paths.HeadPath,
                    ["DeepIdV2DirectoryAuthority:GenesisHeadCoreHashHex"] =
                        Convert.ToHexString(paths.HeadPin),
                    ["DeepIdV2DirectoryAuthority:StatePath"] = paths.StatePath,
                    ["DeepIdV2DirectoryAuthority:IntegrityKeyPath"] =
                        paths.KeyPath
                }).Build();
            Assert.Equal(2, DeepIdV2DirectoryOperatorCommand.TryRun(
                ["did2-directory", "export-current-head",
                    Convert.ToHexString(Bytes(32, 0x55)), exportPath],
                exportConfig));
            Assert.False(File.Exists(exportPath));
            Assert.Equal(0, DeepIdV2DirectoryOperatorCommand.TryRun(
                ["did2-directory", "export-current-head",
                    Convert.ToHexString(firstAtLatest.NextProtectedLkg.CoreHash.Span),
                    exportPath], exportConfig));
            Assert.Equal(firstAtLatest.NextProtectedLkg.ExactAdh1.ToArray(),
                await File.ReadAllBytesAsync(exportPath));
            var lineageDirectory = Path.Combine(root, "covered-lineage");
            Directory.CreateDirectory(lineageDirectory);
            Assert.Equal(0, DeepIdV2DirectoryOperatorCommand.TryRun(
                ["did2-directory", "export-covered-lineage",
                    Convert.ToHexString(firstAtLatest.NextProtectedLkg.CoreHash.Span),
                    lineageDirectory], exportConfig));
            using (var manifest = JsonDocument.Parse(await File.ReadAllBytesAsync(
                       Path.Combine(lineageDirectory, "manifest.json"))))
            {
                Assert.Equal("deep-did2-authenticated-covered-lineage.v1",
                    manifest.RootElement.GetProperty("schema").GetString());
                Assert.Equal(Convert.ToHexString(
                        firstAtLatest.NextProtectedLkg.CoreHash.Span),
                    manifest.RootElement.GetProperty(
                        "currentFloorCoreHashHex").GetString());
                Assert.Equal(2, manifest.RootElement.GetProperty(
                    "coveredHeads").GetArrayLength());
            }
            Assert.Equal(initial.ExactAdh1.ToArray(),
                await File.ReadAllBytesAsync(Path.Combine(lineageDirectory,
                    "head-0000.adh1")));
            Assert.Equal(verified.NextProtectedLkg.ExactAdh1.ToArray(),
                await File.ReadAllBytesAsync(Path.Combine(lineageDirectory,
                    "head-0001.adh1")));
            Assert.Equal(2, DeepIdV2DirectoryOperatorCommand.TryRun(
                ["did2-directory", "export-covered-lineage",
                    Convert.ToHexString(firstAtLatest.NextProtectedLkg.CoreHash.Span),
                    lineageDirectory], exportConfig));

            // The offline root signs a forward checkpoint over the original
            // protected floor. Registry imports only the signed artifact.
            var checkpointPath = Path.Combine(root, "forward.adf1");
            await File.WriteAllBytesAsync(checkpointPath,
                fixture.SignDid2ForwardCheckpoint(initial,
                    verified.NextProtectedLkg));
            await using var forwardFactory = new WebApplicationFactory<Program>()
                .WithWebHostBuilder(builder =>
                {
                    Configure(builder, paths, fixture.Network, null);
                    builder.UseSetting("DeepIdV2DirectoryAuthority:ProofEnabled",
                        "true");
                    builder.UseSetting("DeepIdV2DirectoryAuthority:CurrentXnv1Path",
                        currentView);
                    builder.UseSetting(
                        "DeepIdV2DirectoryAuthority:ProofRequestLedgerRootPath",
                        Path.Combine(root, "proof-ledger"));
                    builder.UseSetting(
                        "DeepIdV2DirectoryAuthority:ProofRequestLedgerIntegrityKeyPath",
                        proofKey);
                    builder.UseSetting(
                        "DeepIdV2DirectoryAuthority:ForwardCheckpointPaths:0",
                        checkpointPath);
                });
            using var forwardAdmissionHttp = forwardFactory.CreateClient();
            forwardAdmissionHttp.BaseAddress = new Uri("https://registry.example/");
            using var forwardAdmissionTransport = new HttpServiceRequestTransport(
                forwardAdmissionHttp,
                DeepIdV2GenesisAdmissionClient.CreateTransportOptions(
                    "https://registry.example/"),
                HttpServiceEndpointPolicy.Production);
            using var forwardAdmission = new DeepIdV2GenesisAdmissionClient(
                forwardAdmissionTransport);
            using var forwardProofHttp = forwardFactory.CreateClient();
            forwardProofHttp.BaseAddress = new Uri("https://registry.example/");
            using var forwardProofTransport = new HttpServiceRequestTransport(
                forwardProofHttp,
                DeepIdV2DirectoryProofClient.CreateTransportOptions(
                    "https://registry.example/"),
                HttpServiceEndpointPolicy.Production);
            using var forwardVerifier = DeepMlDsa65CandidateVerifierFactory
                .OpenForCurrentProcess();
            using var forwardProof = new DeepIdV2DirectoryProofClient(
                forwardProofTransport, new IncreasingMonotonicClock(),
                forwardVerifier, secondFloor);
            var secondVerified = await secondAccounts.AdmitAndVerifyGenesisAsync(
                forwardAdmission, forwardProof, fixture.Authority);
            Assert.NotNull(secondVerified.CurrentCheckpoint);
            Assert.Equal(2UL, secondVerified.NextProtectedLkg.TreeSize);
            Assert.Equal(secondVerified.NextProtectedLkg.CoreHash.ToArray(),
                (await secondFloor.RestoreAsync(fixture.Authority, default))
                .CoreHash.ToArray());

            // Alice can discover Bob from the exact DID2 alone. The returned
            // binding and checkpoint must be authenticated by the proof,
            // not supplied by the caller or inherited from a V1 address.
            using var peerProofHttp = forwardFactory.CreateClient();
            peerProofHttp.BaseAddress = new Uri("https://registry.example/");
            using var peerProofTransport = new HttpServiceRequestTransport(
                peerProofHttp,
                DeepIdV2DirectoryProofClient.CreateTransportOptions(
                    "https://registry.example/"),
                HttpServiceEndpointPolicy.Production);
            using var peerVerifier = DeepMlDsa65CandidateVerifierFactory
                .OpenForCurrentProcess();
            using var peerProof = new DeepIdV2DirectoryProofClient(
                peerProofTransport, new IncreasingMonotonicClock(),
                peerVerifier, protectedFloor);
            var discovered = await peerProof.FetchByDid2Async(secondDid,
                fixture.Authority, 1, 2);
            Assert.NotNull(discovered.CurrentCheckpoint);
            Assert.Equal(secondDid.CanonicalBytes.ToArray(),
                discovered.CurrentCheckpoint!.Binding.DeepId.CanonicalBytes
                    .ToArray());
            Assert.Equal(2UL, discovered.NextProtectedLkg.TreeSize);
            var secondDescriptor = (await secondAccounts.GetCurrentAsync())!
                .PermanentId;
            await Assert.ThrowsAsync<CryptographicException>(async () =>
                await peerProof.FetchByContactDescriptorAsync(
                    created.PermanentId, secondDid, fixture.Authority, 1, 2));
            var descriptorBound = await peerProof
                .FetchByContactDescriptorAsync(secondDescriptor, secondDid,
                    fixture.Authority, 1, 2);
            Assert.Equal(secondDid.CanonicalBytes.ToArray(),
                descriptorBound.CurrentCheckpoint!.Binding.DeepId.CanonicalBytes
                    .ToArray());

            // The imported root checkpoint targets head 1. After another
            // admission, a genesis-floor reader must receive a live DTT1 for
            // head 3, not a freshly signed copy of the older anchor/head 2.
            var thirdRoot = Path.Combine(root, "third-client");
            Directory.CreateDirectory(thirdRoot);
            using var thirdStorage = new InMemoryDeepSecureStorage();
            var thirdAccounts = new DeepIdV2AccountService(thirdStorage,
                thirdRoot, fixture.Network, 1,
                new FrozenClock(DateTimeOffset.FromUnixTimeSeconds(
                    1_700_000_400)),
                DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess);
            _ = await thirdAccounts.CreateAsync("Charlie");
            var thirdFloor = await thirdAccounts.OpenDirectoryLkgStoreAsync(
                fixture.Authority, paths.Head, paths.HeadPin);
            using var thirdProofHttp = forwardFactory.CreateClient();
            thirdProofHttp.BaseAddress = new Uri("https://registry.example/");
            using var thirdProofTransport = new HttpServiceRequestTransport(
                thirdProofHttp,
                DeepIdV2DirectoryProofClient.CreateTransportOptions(
                    "https://registry.example/"),
                HttpServiceEndpointPolicy.Production);
            using var thirdVerifier = DeepMlDsa65CandidateVerifierFactory
                .OpenForCurrentProcess();
            using var thirdProof = new DeepIdV2DirectoryProofClient(
                thirdProofTransport, new IncreasingMonotonicClock(),
                thirdVerifier, thirdFloor);
            var thirdVerified = await thirdAccounts.AdmitAndVerifyGenesisAsync(
                forwardAdmission, thirdProof, fixture.Authority);
            Assert.Equal(3UL, thirdVerified.NextProtectedLkg.LogGeneration);
            Assert.Equal(3UL, thirdVerified.NextProtectedLkg.TreeSize);
            Assert.Equal(3UL, AccountDirectoryDtt1Codec.Decode(
                thirdVerified.ExactDtt1.Span).CurrentAdh1Generation);
            Assert.Equal(thirdVerified.NextProtectedLkg.CoreHash.ToArray(),
                AccountDirectoryDtt1Codec.Decode(thirdVerified.ExactDtt1.Span)
                    .CurrentAdh1CoreHash.ToArray());
            Assert.NotEqual(firstAtLatest.NextProtectedLkg.CoreHash.ToArray(),
                thirdVerified.NextProtectedLkg.CoreHash.ToArray());
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task PostgreSqlFloorRejectsRestoredOldAda2OverRealHttpWhenConfigured()
    {
        var connectionString = Environment.GetEnvironmentVariable(
            "DEEP_TEST_DID2_FLOOR_POSTGRES");
        if (string.IsNullOrWhiteSpace(connectionString)) return;
        if (!(OperatingSystem.IsWindows() ||
              (OperatingSystem.IsLinux() &&
               System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture ==
               System.Runtime.InteropServices.Architecture.X64)))
            return;
        var schema = "did2_http_floor_" + Guid.NewGuid().ToString("N");
        var schemaConnection = new NpgsqlConnectionStringBuilder(connectionString)
        {
            SearchPath = schema
        }.ConnectionString;
        await using var admin = new NpgsqlConnection(connectionString);
        await admin.OpenAsync();
        await using (var setup = new NpgsqlCommand(
                         $"CREATE SCHEMA \"{schema}\"; " +
                         $"CREATE TABLE \"{schema}\".deep_did2_latest_head_floor (" +
                         "network_id bytea PRIMARY KEY CHECK (octet_length(network_id) = 16), " +
                         "exact_adh1 bytea NOT NULL CHECK (octet_length(exact_adh1) BETWEEN 1 AND 4096), " +
                         "core_hash bytea NOT NULL CHECK (octet_length(core_hash) = 32))",
                         admin))
            await setup.ExecuteNonQueryAsync();
        var root = Path.Combine(Path.GetTempPath(),
            "deep-did2-http-pg-floor", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            using var fixture = ContactResolveAuthoringFixture.Create(
                currentValue: false);
            var paths = await ProvisionAsync(root, fixture);
            var oldAda2 = await File.ReadAllBytesAsync(paths.StatePath);
            using var floor = new DeepIdV2PostgreSqlLatestHeadFloor(
                schemaConnection, fixture.Network);
            await floor.ProvisionGenesisAsync(
                new AccountDirectoryProtectedLkg(paths.Head));
            await using var factory = new WebApplicationFactory<Program>()
                .WithWebHostBuilder(builder => Configure(builder, paths,
                    fixture.Network, null, schemaConnection));
            using var client = factory.CreateClient();
            using (var readiness = await client.GetAsync(
                       DeepIdV2DirectoryAuthorityHostingExtensions
                           .ReadinessEndpointPath))
                Assert.Equal(HttpStatusCode.OK, readiness.StatusCode);
            var request = await File.ReadAllBytesAsync(Path.Combine(
                AppContext.BaseDirectory, "Fixtures", "did2-genesis.dga1v2"));
            using (var first = new ByteArrayContent(request))
            {
                first.Headers.ContentType = new(
                    DeepIdV2GenesisAdmissionWireCodec.RequestMediaType);
                using var response = await client.PostAsync(
                    DeepIdV2DirectoryAuthorityHostingExtensions.EndpointPath,
                    first);
                Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            }
            byte[] beforeRefreshHash;
            await using (var readFloor = new NpgsqlConnection(schemaConnection))
            {
                await readFloor.OpenAsync();
                await using var read = new NpgsqlCommand(
                    "SELECT core_hash FROM deep_did2_latest_head_floor",
                    readFloor);
                beforeRefreshHash = (byte[])(await read.ExecuteScalarAsync())!;
            }
            var refreshConfig = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["ContactResolveProductionAuthority:Enabled"] = "true",
                    ["ContactResolveProductionAuthority:NetworkIdHex"] =
                        Convert.ToHexString(fixture.Network),
                    ["ContactResolveProductionAuthority:TrustedTimeStatePath"] =
                        paths.TimeStatePath,
                    ["ContactResolveProductionAuthority:TrustedTimeIntegrityKeyPath"] =
                        paths.TimeKeyPath,
                    ["ContactResolveProductionAuthority:RequestLedgerRootPath"] =
                        paths.LedgerRootPath,
                    ["ContactResolveProductionAuthority:RequestLedgerIntegrityKeyPath"] =
                        paths.LedgerKeyPath,
                    ["ContactResolveProductionAuthority:Witnesses:0:WitnessIdHex"] =
                        Convert.ToHexString(Bytes(32, 0x40)),
                    ["ContactResolveProductionAuthority:Witnesses:0:KeyGeneration"] = "0",
                    ["ContactResolveProductionAuthority:Witnesses:0:Ed25519SeedPath"] =
                        paths.WitnessPath,
                    ["ContactResolveProductionAuthority:Witnesses:1:WitnessIdHex"] =
                        Convert.ToHexString(Bytes(32, 0x41)),
                    ["ContactResolveProductionAuthority:Witnesses:1:KeyGeneration"] = "0",
                    ["ContactResolveProductionAuthority:Witnesses:1:Ed25519SeedPath"] =
                        paths.Witness2Path,
                    ["DeepIdV2DirectoryAuthority:NetworkIdHex"] =
                        Convert.ToHexString(fixture.Network),
                    ["DeepIdV2DirectoryAuthority:GenesisAuthorityCoreHashHex"] =
                        Convert.ToHexString(paths.NetworkPin),
                    ["DeepIdV2DirectoryAuthority:ExactAuthorityPaths:0"] =
                        paths.AuthorityPath,
                    ["DeepIdV2DirectoryAuthority:ExactTimePolicyPaths:0"] =
                        paths.PolicyPath,
                    ["DeepIdV2DirectoryAuthority:GenesisHeadPath"] = paths.HeadPath,
                    ["DeepIdV2DirectoryAuthority:GenesisHeadCoreHashHex"] =
                        Convert.ToHexString(paths.HeadPin),
                    ["DeepIdV2DirectoryAuthority:StatePath"] = paths.StatePath,
                    ["DeepIdV2DirectoryAuthority:IntegrityKeyPath"] = paths.KeyPath,
                    ["DeepIdV2DirectoryAuthority:LatestHeadFloorPostgreSqlConnectionString"] =
                        schemaConnection
                }).Build();
            Assert.Throws<InvalidOperationException>(() =>
                DeepIdV2DirectoryOperatorCommand.RefreshCurrentHead(
                    refreshConfig, 1_700_000_500, 1_700_004_100,
                    1_700_000_500, default));
            Assert.Equal(2, DeepIdV2DirectoryOperatorCommand.TryRun(
                ["did2-directory", "refresh-current-head",
                    "1700004970", "1700008570"], refreshConfig));
            _ = ProtectedMonotonicContactResolveTrustedTimeSource.Provision(
                paths.TimeStatePath, fixture.Network, Bytes(32, 0x61),
                1_700_005_000, 1_700_008_600, 5,
                ReadOnlySpan<byte>.Empty,
                ProtectedMonotonicContactResolveTrustedTimeSource
                    .ReadPlatformMonotonicSeconds(), Bytes(16, 0xc1));
            Assert.Equal(0, DeepIdV2DirectoryOperatorCommand.TryRun(
                ["did2-directory", "refresh-current-head",
                    "1700004970", "1700008570"], refreshConfig));
            await using (var readFloor = new NpgsqlConnection(schemaConnection))
            {
                await readFloor.OpenAsync();
                await using var read = new NpgsqlCommand(
                    "SELECT exact_adh1, core_hash FROM deep_did2_latest_head_floor",
                    readFloor);
                await using var row = await read.ExecuteReaderAsync();
                Assert.True(await row.ReadAsync());
                var refreshed = AccountDirectoryProtectedLkgFactory.Restore(
                    fixture.Authority, (byte[])row[0], (byte[])row[1]);
                Assert.Equal(2UL, refreshed.LogGeneration);
                Assert.Equal(1UL, refreshed.TreeSize);
                Assert.Equal(beforeRefreshHash,
                    refreshed.Head.PredecessorAdh1CoreHash.ToArray());
                Assert.False(await row.ReadAsync());
            }
            await File.WriteAllBytesAsync(paths.StatePath, oldAda2);
            using var replay = new ByteArrayContent(request);
            replay.Headers.ContentType = new(
                DeepIdV2GenesisAdmissionWireCodec.RequestMediaType);
            using var rejected = await client.PostAsync(
                DeepIdV2DirectoryAuthorityHostingExtensions.EndpointPath,
                replay);
            Assert.Equal(HttpStatusCode.ServiceUnavailable,
                rejected.StatusCode);
            Assert.Equal(oldAda2, await File.ReadAllBytesAsync(paths.StatePath));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
            await using var cleanup = new NpgsqlCommand(
                $"DROP SCHEMA \"{schema}\" CASCADE", admin);
            await cleanup.ExecuteNonQueryAsync();
        }
    }

    [Fact]
    public async Task RealV2RoutePersistsPqGenesisAndReplaysExactReceipt()
    {
        if (!(OperatingSystem.IsWindows() ||
              (OperatingSystem.IsLinux() &&
               System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture ==
               System.Runtime.InteropServices.Architecture.X64)))
            return;
        using var fixture = ContactResolveAuthoringFixture.Create(currentValue: false);
        var root = Path.Combine(Path.GetTempPath(),
            "deep-did2-real-http", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var paths = await ProvisionAsync(root, fixture);
            await using var factory = new WebApplicationFactory<Program>()
                .WithWebHostBuilder(builder => Configure(builder, paths,
                    fixture.Network, null));
            using var client = factory.CreateClient();
            var exactRequest = await File.ReadAllBytesAsync(Path.Combine(
                AppContext.BaseDirectory, "Fixtures", "did2-genesis.dga1v2"));
            using var content = new ByteArrayContent(exactRequest);
            content.Headers.ContentType = new(
                DeepIdV2GenesisAdmissionWireCodec.RequestMediaType);
            using var response = await client.PostAsync(
                DeepIdV2DirectoryAuthorityHostingExtensions.EndpointPath,
                content);
            var body = await response.Content.ReadAsByteArrayAsync();
            Assert.True(response.StatusCode == HttpStatusCode.OK,
                $"Unexpected {response.StatusCode}: {System.Text.Encoding.UTF8.GetString(body)}");
            var receipt = DeepIdV2GenesisAdmissionWireCodec.DecodeReceipt(body);
            Assert.Equal(1UL, AccountDirectoryAdh1Codec.Decode(
                receipt.ExactAdh1.Span).TreeSize);
            using var replayContent = new ByteArrayContent(exactRequest);
            replayContent.Headers.ContentType = new(
                DeepIdV2GenesisAdmissionWireCodec.RequestMediaType);
            using var replay = await client.PostAsync(
                DeepIdV2DirectoryAuthorityHostingExtensions.EndpointPath,
                replayContent);
            Assert.Equal(HttpStatusCode.OK, replay.StatusCode);
            Assert.Equal(body, await replay.Content.ReadAsByteArrayAsync());
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task V2RouteReturnsExactReceiptAndRejectsLegacyMediaType()
    {
        using var fixture = ContactResolveAuthoringFixture.Create(currentValue: false);
        var root = Path.Combine(Path.GetTempPath(),
            "deep-did2-http", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var paths = await ProvisionAsync(root, fixture);
            var fake = new FixedAuthority(paths.Head);
            await using var factory = new WebApplicationFactory<Program>()
                .WithWebHostBuilder(builder => Configure(builder, paths,
                    fixture.Network, fake));
            using var client = factory.CreateClient();
            var exactRequest = await File.ReadAllBytesAsync(Path.Combine(
                AppContext.BaseDirectory, "Fixtures", "did2-genesis.dga1v2"));
            using var content = new ByteArrayContent(exactRequest);
            content.Headers.ContentType = new(
                DeepIdV2GenesisAdmissionWireCodec.RequestMediaType);
            using var response = await client.PostAsync(
                DeepIdV2DirectoryAuthorityHostingExtensions.EndpointPath,
                content);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(DeepIdV2GenesisAdmissionWireCodec.ResponseMediaType,
                response.Content.Headers.ContentType?.MediaType);
            var receipt = DeepIdV2GenesisAdmissionWireCodec.DecodeReceipt(
                await response.Content.ReadAsByteArrayAsync());
            Assert.Equal(Bytes(32, 0x91), receipt.OperationId.ToArray());
            Assert.Equal(1, fake.Calls);

            using var legacyContent = new ByteArrayContent(exactRequest);
            legacyContent.Headers.ContentType = new(
                AccountDirectoryGenesisAdmissionWireCodec.RequestMediaType);
            using var wrongMedia = await client.PostAsync(
                DeepIdV2DirectoryAuthorityHostingExtensions.EndpointPath,
                legacyContent);
            Assert.Equal(HttpStatusCode.UnsupportedMediaType,
                wrongMedia.StatusCode);
            using var malformedContent = new ByteArrayContent(Bytes(32, 0x22));
            malformedContent.Headers.ContentType = new(
                DeepIdV2GenesisAdmissionWireCodec.RequestMediaType);
            await using var secondFactory = new WebApplicationFactory<Program>()
                .WithWebHostBuilder(builder => Configure(builder, paths,
                    fixture.Network, fake));
            using var secondClient = secondFactory.CreateClient();
            using var malformed = await secondClient.PostAsync(
                DeepIdV2DirectoryAuthorityHostingExtensions.EndpointPath,
                malformedContent);
            Assert.Equal(HttpStatusCode.BadRequest, malformed.StatusCode);
            Assert.Equal(1, fake.Calls);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static async Task<Paths> ProvisionAsync(string root,
        ContactResolveAuthoringFixture fixture)
    {
        var paths = new Paths(
            Path.Combine(root, "genesis.xna1"),
            Path.Combine(root, "genesis.dts1"),
            Path.Combine(root, "genesis.adh1"),
            Path.Combine(root, "authority.ada2"),
            Path.Combine(root, "authority.key"),
            Path.Combine(root, "time.key"),
            Path.Combine(root, "ledger.key"),
            Path.Combine(root, "witness.seed"),
            Path.Combine(root, "witness-2.seed"),
            Path.Combine(root, "time.state"),
            Path.Combine(root, "ledger"),
            [], [], []);
        var head = fixture.CreateDid2GenesisHead();
        var headPin = AccountDirectoryCrypto.ComputeAdh1CoreHash(
            AccountDirectoryAdh1Codec.Decode(head));
        var networkPin = XPointNetworkCodec.Parse<Xna1Record>(
            fixture.ExactXna1).CoreHash.ToArray();
        await File.WriteAllBytesAsync(paths.AuthorityPath,
            fixture.ExactXna1);
        await File.WriteAllBytesAsync(paths.PolicyPath,
            fixture.ExactDts1);
        await File.WriteAllBytesAsync(paths.HeadPath, head);
        await File.WriteAllBytesAsync(paths.KeyPath, Bytes(32, 0x5a));
        await File.WriteAllBytesAsync(paths.TimeKeyPath, Bytes(32, 0x61));
        await File.WriteAllBytesAsync(paths.LedgerKeyPath, Bytes(32, 0x62));
        await File.WriteAllBytesAsync(paths.WitnessPath, Bytes(32, 0x50));
        await File.WriteAllBytesAsync(paths.Witness2Path, Bytes(32, 0x51));
        await File.WriteAllBytesAsync(paths.StatePath,
            DirectoryPublicationProtectedFile.Protect(
                DeepIdV2DirectoryStateCodec.Encode(fixture.Network,
                    new DeepIdV2DirectoryStateRows(
                        [new DeepIdV2DirectoryHeadRow(head, headPin)],
                        [], [])), Bytes(32, 0x5a)));
        return paths with
        {
            Head = head,
            HeadPin = headPin,
            NetworkPin = networkPin
        };
    }

    private static void Configure(IWebHostBuilder builder, Paths paths,
        byte[] network, IDeepIdV2GenesisAuthority? fake,
        string? floorConnectionString = null)
    {
        var networkHex = Convert.ToHexString(network);
        builder.UseSetting("ContactResolveProductionAuthority:Enabled", "true");
        builder.UseSetting("ContactResolveProductionAuthority:NetworkIdHex",
            networkHex);
        builder.UseSetting("ContactResolveProductionAuthority:TrustedTimeStatePath",
            paths.TimeStatePath);
        builder.UseSetting("ContactResolveProductionAuthority:TrustedTimeIntegrityKeyPath",
            paths.TimeKeyPath);
        builder.UseSetting("ContactResolveProductionAuthority:RequestLedgerRootPath",
            paths.LedgerRootPath);
        builder.UseSetting("ContactResolveProductionAuthority:RequestLedgerIntegrityKeyPath",
            paths.LedgerKeyPath);
        builder.UseSetting("ContactResolveProductionAuthority:Witnesses:0:WitnessIdHex",
            Convert.ToHexString(Bytes(32, 0x40)));
        builder.UseSetting("ContactResolveProductionAuthority:Witnesses:0:KeyGeneration",
            "0");
        builder.UseSetting("ContactResolveProductionAuthority:Witnesses:0:Ed25519SeedPath",
            paths.WitnessPath);
        builder.UseSetting("ContactResolveProductionAuthority:Witnesses:1:WitnessIdHex",
            Convert.ToHexString(Bytes(32, 0x41)));
        builder.UseSetting("ContactResolveProductionAuthority:Witnesses:1:KeyGeneration",
            "0");
        builder.UseSetting("ContactResolveProductionAuthority:Witnesses:1:Ed25519SeedPath",
            paths.Witness2Path);
        builder.UseSetting("DeepIdV2DirectoryAuthority:Enabled", "true");
        builder.UseSetting("DeepIdV2DirectoryAuthority:NetworkIdHex", networkHex);
        builder.UseSetting("DeepIdV2DirectoryAuthority:GenesisAuthorityCoreHashHex",
            Convert.ToHexString(paths.NetworkPin));
        builder.UseSetting("DeepIdV2DirectoryAuthority:ExactAuthorityPaths:0",
            paths.AuthorityPath);
        builder.UseSetting("DeepIdV2DirectoryAuthority:ExactTimePolicyPaths:0",
            paths.PolicyPath);
        builder.UseSetting("DeepIdV2DirectoryAuthority:GenesisHeadPath",
            paths.HeadPath);
        builder.UseSetting("DeepIdV2DirectoryAuthority:GenesisHeadCoreHashHex",
            Convert.ToHexString(paths.HeadPin));
        builder.UseSetting("DeepIdV2DirectoryAuthority:StatePath", paths.StatePath);
        builder.UseSetting("DeepIdV2DirectoryAuthority:IntegrityKeyPath", paths.KeyPath);
        if (floorConnectionString is not null)
            builder.UseSetting(
                "DeepIdV2DirectoryAuthority:LatestHeadFloorPostgreSqlConnectionString",
                floorConnectionString);
        builder.ConfigureServices(services =>
        {
            if (fake is not null)
            {
                services.RemoveAll<IDeepIdV2GenesisAuthority>();
                services.AddSingleton(fake);
            }
            services.RemoveAll<IContactResolveTrustedTimeContextSource>();
            services.AddSingleton<IContactResolveTrustedTimeContextSource>(
                new FixedTimeSource());
        });
    }

    private static byte[] Bytes(int count, byte value) =>
        Enumerable.Repeat(value, count).ToArray();

    private sealed record Paths(string AuthorityPath, string PolicyPath,
        string HeadPath, string StatePath, string KeyPath,
        string TimeKeyPath, string LedgerKeyPath, string WitnessPath,
        string Witness2Path,
        string TimeStatePath, string LedgerRootPath,
        byte[] Head, byte[] HeadPin, byte[] NetworkPin);

    private sealed class FixedTimeSource :
        IContactResolveTrustedTimeContextSource
    {
        public ValueTask<ContactResolveTrustedTimeContext> ReadAsync(
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(new ContactResolveTrustedTimeContext(
                Bytes(16, 0xc1), 4_000, 1_700_000_400, 5));
        }
    }

    private sealed class IncreasingMonotonicClock : IOnionMonotonicClock
    {
        private long sample = 4_000;

        public ValueTask<OnionMonotonicReading> ReadAsync(
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(new OnionMonotonicReading(
                Bytes(16, 0xc1), checked((ulong)Interlocked.Increment(
                    ref sample))));
        }
    }

    private sealed class ExternalMonotonicClock : IOnionMonotonicClock
    {
        private readonly byte[] bootId =
            System.Security.Cryptography.RandomNumberGenerator.GetBytes(16);
        private readonly long started = Stopwatch.GetTimestamp();

        public ValueTask<OnionMonotonicReading> ReadAsync(
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var elapsed = Stopwatch.GetElapsedTime(started);
            return ValueTask.FromResult(new OnionMonotonicReading(bootId,
                checked(1_000UL + (ulong)Math.Floor(elapsed.TotalSeconds))));
        }
    }

    private sealed class FixedAuthority(byte[] head) :
        IDeepIdV2GenesisAuthority
    {
        internal int Calls { get; private set; }

        public ValueTask<DeepIdV2GenesisAdmissionReceipt> AdmitAsync(
            DeepIdV2GenesisAdmissionWireRequest request,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls++;
            return ValueTask.FromResult(new DeepIdV2GenesisAdmissionReceipt(
                request.OperationId.Span, Bytes(32, 0x41), head));
        }
    }
}
#endif
