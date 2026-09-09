#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Buffers.Binary;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.XPointNetworkV1;
using Deep.Registry.Api.DirectoryPublication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Deep.Registry.Api.Tests;

public sealed class TargetedCurrentValueDirectoryPackageTests
{
    [Fact]
    public async Task Current_value_returns_exact_bounded_artifacts_and_transport_headers()
    {
        using var fixture = ContactResolveAuthoringFixture.Create(currentValue: true);
        using var ledger = new LedgerDirectory();
        await using var app = await StartAsync(fixture, enabled: true, ledger.Path);
        var nonce = Bytes(0x21, 32);
        var boot = Bytes(0x22, 16);
        var request = EncodeRequest(fixture, nonce, boot, 901);

        var response = await Client(app).PostAsync(
            TargetedCurrentValueDirectoryPackageHostingExtensions.EndpointPath,
            Content(request));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(TargetedCurrentValueDirectoryPackageCodec.ResponseMediaType,
            response.Content.Headers.ContentType!.MediaType);
        Assert.Empty(response.Content.Headers.ContentType.Parameters);
        Assert.True(response.Headers.CacheControl!.NoStore);
        Assert.True(response.Headers.CacheControl.Private);
        Assert.Null(response.Headers.Location);
        Assert.Equal("nosniff", Assert.Single(response.Headers.GetValues("X-Content-Type-Options")));
        var encoded = await response.Content.ReadAsByteArrayAsync();
        Assert.Equal(encoded.Length, response.Content.Headers.ContentLength);
        var decoded = DecodeResponse(encoded);
        Assert.Equal(fixture.Network, decoded.Network);
        Assert.Equal(fixture.ProofMaterial.QueriedDirectoryLeafKey.ToArray(), decoded.LookupKey);
        Assert.Equal(nonce, decoded.Nonce);
        Assert.Equal(boot, decoded.Boot);
        Assert.Equal(901UL, decoded.Sample);
        Assert.Equal(fixture.ExactXna1, decoded.Artifacts[0]);
        Assert.Equal(fixture.ExactDts1, decoded.Artifacts[1]);
        var adp = AccountDirectoryAdp1Codec.Decode(decoded.Artifacts[4]);
        Assert.Equal(AccountDirectoryAdp1ResultKind.CurrentValue, adp.ResultKind);
        Assert.Equal(decoded.LookupKey, adp.QueriedDirectoryLeafKey.ToArray());
        Assert.Equal(fixture.Network, adp.NetworkId.ToArray());
    }

    [Fact]
    public async Task Replay_is_rejected_after_restart_by_the_shared_one_use_ledger()
    {
        using var fixture = ContactResolveAuthoringFixture.Create(currentValue: true);
        using var ledger = new LedgerDirectory();
        var request = EncodeRequest(fixture, Bytes(0x31, 32), Bytes(0x32, 16), 902);
        await using (var first = await StartAsync(fixture, enabled: true, ledger.Path))
        {
            var accepted = await Client(first).PostAsync(
                TargetedCurrentValueDirectoryPackageHostingExtensions.EndpointPath,
                Content(request));
            Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        }
        await using var restarted = await StartAsync(fixture, enabled: true, ledger.Path);

        var replay = await Client(restarted).PostAsync(
            TargetedCurrentValueDirectoryPackageHostingExtensions.EndpointPath,
            Content(request));

        Assert.Equal(HttpStatusCode.ServiceUnavailable, replay.StatusCode);
        Assert.Equal(0, replay.Content.Headers.ContentLength);
        Assert.True(replay.Headers.CacheControl!.NoStore);
    }

    [Fact]
    public async Task Cross_network_nonmembership_and_stale_floor_are_indistinguishable()
    {
        using var current = ContactResolveAuthoringFixture.Create(currentValue: true);
        using var absent = ContactResolveAuthoringFixture.Create(currentValue: false);
        using var firstLedger = new LedgerDirectory();
        using var secondLedger = new LedgerDirectory();
        await using var currentApp = await StartAsync(current, enabled: true, firstLedger.Path);
        await using var absentApp = await StartAsync(absent, enabled: true, secondLedger.Path);

        var wrongNetwork = EncodeRequest(current, Bytes(0x41, 32), Bytes(0x42, 16), 903,
            networkOverride: Bytes(0x7f, 16));
        var stale = EncodeRequest(current, Bytes(0x43, 32), Bytes(0x44, 16), 904,
            minimumGeneration: current.Snapshot.CurrentDirectoryHead.LogGeneration + 1);
        var nonmembership = EncodeRequest(absent, Bytes(0x45, 32), Bytes(0x46, 16), 905);

        var responses = new[]
        {
            await Client(currentApp).PostAsync(
                TargetedCurrentValueDirectoryPackageHostingExtensions.EndpointPath,
                Content(wrongNetwork)),
            await Client(currentApp).PostAsync(
                TargetedCurrentValueDirectoryPackageHostingExtensions.EndpointPath,
                Content(stale)),
            await Client(absentApp).PostAsync(
                TargetedCurrentValueDirectoryPackageHostingExtensions.EndpointPath,
                Content(nonmembership)),
        };

        Assert.All(responses, response =>
        {
            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
            Assert.Equal(0, response.Content.Headers.ContentLength);
            Assert.Null(response.Content.Headers.ContentType);
            Assert.True(response.Headers.CacheControl!.NoStore);
        });
    }

    [Fact]
    public async Task Older_floor_requires_the_exact_protocol_proof_lkg()
    {
        using var fixture = ContactResolveAuthoringFixture.Create(currentValue: true);
        using var ledger = new LedgerDirectory();
        await using var app = await StartAsync(fixture, enabled: true, ledger.Path);
        var callerFloor = Assert.IsType<AccountDirectoryProtectedLkg>(
            fixture.ProofMaterial.CallerProtectedLkg);
        var nonce = Bytes(0x47, 32);

        var wrongHash = await Client(app).PostAsync(
            TargetedCurrentValueDirectoryPackageHostingExtensions.EndpointPath,
            Content(EncodeRequest(
                fixture, nonce, Bytes(0x48, 16), 908,
                minimumGeneration: callerFloor.LogGeneration,
                minimumHash: Bytes(0xee, 32))));
        var accepted = await Client(app).PostAsync(
            TargetedCurrentValueDirectoryPackageHostingExtensions.EndpointPath,
            Content(EncodeRequest(
                fixture, Bytes(0x49, 32), Bytes(0x48, 16), 909,
                minimumGeneration: callerFloor.LogGeneration,
                minimumHash: callerFloor.CoreHash.ToArray())));

        Assert.Equal(HttpStatusCode.NotFound, wrongHash.StatusCode);
        Assert.Equal(0, wrongHash.Content.Headers.ContentLength);
        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
    }

    [Fact]
    public async Task Endpoint_is_dormant_by_default_even_when_the_shared_issuer_is_composed()
    {
        using var fixture = ContactResolveAuthoringFixture.Create(currentValue: true);
        using var ledger = new LedgerDirectory();
        await using var app = await StartAsync(fixture, enabled: false, ledger.Path);

        var response = await Client(app).PostAsync(
            TargetedCurrentValueDirectoryPackageHostingExtensions.EndpointPath,
            Content(EncodeRequest(fixture, Bytes(0x51, 32), Bytes(0x52, 16), 906)));

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal(0, response.Content.Headers.ContentLength);
    }

    [Fact]
    public void Explicit_activation_without_the_shared_network_configuration_fails_startup()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(
            new Dictionary<string, string?>
            {
                ["TargetedCurrentValueDirectoryPackages:Enabled"] = "true",
            }).Build();
        var services = new ServiceCollection();
        var baseState = services.AddContactResolveDirectoryPackages(configuration);

        Assert.Throws<InvalidOperationException>(() =>
            services.AddTargetedCurrentValueDirectoryPackages(configuration, baseState));
    }

    [Fact]
    public async Task Hostile_http_framing_is_rejected_before_issuance()
    {
        using var fixture = ContactResolveAuthoringFixture.Create(currentValue: true);
        using var ledger = new LedgerDirectory();
        var canonical = EncodeRequest(fixture, Bytes(0x61, 32), Bytes(0x62, 16), 907);

        var malformed = canonical.ToArray();
        malformed[2] ^= 0x80;
        var wrongType = new ByteArrayContent(canonical);
        wrongType.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        var unknownLength = new UnknownLengthContent(canonical);
        unknownLength.Headers.ContentType = new MediaTypeHeaderValue(
            TargetedCurrentValueDirectoryPackageCodec.RequestMediaType);

        var responses = new[]
        {
            await SendOnFreshHost(Content(malformed)),
            await SendOnFreshHost(wrongType),
            await SendOnFreshHost(unknownLength),
            await SendOnFreshHost(Content(canonical.Concat(new byte[] { 1 }).ToArray())),
        };

        Assert.Equal(HttpStatusCode.BadRequest, responses[0].StatusCode);
        Assert.Equal(HttpStatusCode.UnsupportedMediaType, responses[1].StatusCode);
        Assert.Equal(HttpStatusCode.LengthRequired, responses[2].StatusCode);
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, responses[3].StatusCode);
        Assert.All(responses, response => Assert.True(response.Headers.CacheControl!.NoStore));

        var accepted = await SendOnFreshHost(Content(canonical));
        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);

        async Task<HttpResponseMessage> SendOnFreshHost(HttpContent content)
        {
            await using var host = await StartAsync(fixture, enabled: true, ledger.Path);
            return await Client(host).PostAsync(
                TargetedCurrentValueDirectoryPackageHostingExtensions.EndpointPath,
                content);
        }
    }

    private static async Task<WebApplication> StartAsync(
        ContactResolveAuthoringFixture fixture,
        bool enabled,
        string ledgerPath)
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(
            new Dictionary<string, string?>
            {
                ["DirectoryPublication:NetworkIdHex"] = Convert.ToHexString(fixture.Network),
                ["TargetedCurrentValueDirectoryPackages:Enabled"] = enabled.ToString(),
            }).Build();
        var builder = WebApplication.CreateBuilder();
        builder.Environment.EnvironmentName = "Development";
        builder.WebHost.UseTestServer();
        var baseState = builder.Services.AddContactResolveDirectoryPackages(configuration);
        var targetState = builder.Services.AddTargetedCurrentValueDirectoryPackages(
            configuration, baseState);
        builder.Services.AddContactResolveDirectoryPackageIssuerForUat(
            new FixedSnapshotSource(fixture.Snapshot),
            new FixedProofSource(fixture.ProofMaterial),
            new FixedWitnessCustody(fixture.Signers),
            new ProtectedFileContactResolveOneUseRequestLedger(
                ledgerPath, fixture.Network, Bytes(0xd8, 32)),
            new FixedTrustedTimeSource());
        var app = builder.Build();
        app.MapTargetedCurrentValueDirectoryPackageEndpoint(targetState);
        await app.StartAsync();
        return app;
    }

    private static byte[] EncodeRequest(
        ContactResolveAuthoringFixture fixture,
        byte[] nonce,
        byte[] boot,
        ulong sample,
        byte[]? networkOverride = null,
        ulong? minimumGeneration = null,
        byte[]? minimumHash = null)
    {
        var head = fixture.Snapshot.CurrentDirectoryHead;
        var adl = new AccountDirectoryAdl1(
            networkOverride ?? fixture.Network,
            fixture.ProofMaterial.QueriedDirectoryLeafKey.Span,
            minimumGeneration ?? head.LogGeneration,
            minimumHash ?? head.CoreHash.ToArray(),
            1,
            new byte[38],
            new byte[32]);
        var exactAdl = AccountDirectoryAdl1Codec.Encode(adl);
        Assert.Equal(TargetedCurrentValueDirectoryPackageCodec.ExactAdl1Bytes, exactAdl.Length);
        var result = new byte[TargetedCurrentValueDirectoryPackageCodec.RequestBytes];
        BinaryPrimitives.WriteUInt16BigEndian(result, 1);
        exactAdl.CopyTo(result, 2);
        nonce.CopyTo(result, 2 + exactAdl.Length);
        boot.CopyTo(result, 2 + exactAdl.Length + 32);
        BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(result.Length - 8), sample);
        return result;
    }

    private static DecodedResponse DecodeResponse(byte[] encoded)
    {
        Assert.True(encoded.Length <= TargetedCurrentValueDirectoryPackageCodec.MaximumResponseBytes);
        Assert.Equal((ushort)1, BinaryPrimitives.ReadUInt16BigEndian(encoded));
        Assert.Equal((ushort)0, BinaryPrimitives.ReadUInt16BigEndian(encoded.AsSpan(2)));
        Assert.Equal((uint)encoded.Length, BinaryPrimitives.ReadUInt32BigEndian(encoded.AsSpan(4)));
        var offset = 8;
        var network = encoded.AsSpan(offset, 16).ToArray(); offset += 16;
        var lookup = encoded.AsSpan(offset, 32).ToArray(); offset += 32;
        var nonce = encoded.AsSpan(offset, 32).ToArray(); offset += 32;
        var boot = encoded.AsSpan(offset, 16).ToArray(); offset += 16;
        var sample = BinaryPrimitives.ReadUInt64BigEndian(encoded.AsSpan(offset)); offset += 8;
        var artifacts = new List<byte[]>();
        for (var index = 0; index < 8; index++)
        {
            var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(encoded.AsSpan(offset)));
            offset += 4;
            artifacts.Add(encoded.AsSpan(offset, length).ToArray());
            offset += length;
        }
        Assert.Equal(encoded.Length, offset);
        return new DecodedResponse(network, lookup, nonce, boot, sample, artifacts);
    }

    private static HttpClient Client(WebApplication app)
    {
        var client = app.GetTestClient();
        client.BaseAddress = new Uri("https://localhost");
        return client;
    }

    private static ByteArrayContent Content(byte[] value)
    {
        var content = new ByteArrayContent(value);
        content.Headers.ContentType = new MediaTypeHeaderValue(
            TargetedCurrentValueDirectoryPackageCodec.RequestMediaType);
        return content;
    }

    private static byte[] Bytes(byte value, int length) =>
        Enumerable.Repeat(value, length).ToArray();

    private sealed record DecodedResponse(
        byte[] Network,
        byte[] LookupKey,
        byte[] Nonce,
        byte[] Boot,
        ulong Sample,
        IReadOnlyList<byte[]> Artifacts);

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

    private sealed class FixedWitnessCustody(
        IReadOnlyList<IAccountDirectoryDtt1WitnessSigner> signers) :
        IContactResolveDtt1WitnessCustody
    {
        public ValueTask<IReadOnlyList<IAccountDirectoryDtt1WitnessSigner>> GetSignersAsync(
            VerifiedXPointNetworkAuthority authority,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(signers);
        }
    }

    private sealed class FixedTrustedTimeSource : IContactResolveTrustedTimeContextSource
    {
        public ValueTask<ContactResolveTrustedTimeContext> ReadAsync(
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(new ContactResolveTrustedTimeContext(
                Bytes(0xc1, 16), 4_000, 1_700_000_200, 5));
        }
    }

    private sealed class LedgerDirectory : IDisposable
    {
        internal LedgerDirectory() => Path = System.IO.Path.Combine(
            System.IO.Path.GetTempPath(), "deep-target-ledger-" + Guid.NewGuid().ToString("N"));
        internal string Path { get; }
        public void Dispose()
        {
            if (Directory.Exists(Path)) Directory.Delete(Path, recursive: true);
        }
    }

    private sealed class UnknownLengthContent(byte[] bytes) : HttpContent
    {
        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) =>
            stream.WriteAsync(bytes).AsTask();

        protected override bool TryComputeLength(out long length)
        {
            length = 0;
            return false;
        }
    }
}
#endif
