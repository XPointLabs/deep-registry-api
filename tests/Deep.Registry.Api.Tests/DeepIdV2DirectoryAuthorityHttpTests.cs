#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Net;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.XPointNetworkV1;
using Deep.Registry.Api.DirectoryPublication;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Npgsql;

namespace Deep.Registry.Api.Tests;

public sealed class DeepIdV2DirectoryAuthorityHttpTests
{
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
