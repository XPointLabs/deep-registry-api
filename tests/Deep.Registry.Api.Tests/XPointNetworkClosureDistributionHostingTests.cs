#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Net;
using System.Buffers.Binary;
using System.Text;
using Deep.Protocol.XPointNetworkV1;
using Deep.Registry.Api.DirectoryPublication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Deep.Registry.Api.Tests;

// Pipeline/file distribution tests; raw shape fixtures do not prove signed freshness.
public sealed class XPointNetworkClosureDistributionHostingTests
{
    private static readonly byte[] Network = Enumerable.Repeat((byte)0x61, 16).ToArray();

    [Fact]
    public async Task DisabledRouteIsAbsent()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        var enabled = builder.Services.AddXPointNetworkClosureDistribution(new ConfigurationBuilder().Build());
        Assert.False(enabled);
        await using var app = builder.Build();
        app.MapXPointNetworkClosureDistribution(enabled);
        await app.StartAsync();
        using var client = app.GetTestClient();
        using var response = await client.PostAsync(XPointNetworkClosureDistributionHosting.EndpointPath, Request());
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task ExactPublicBundleIsByteIdenticalAndNoStore()
    {
        await using var fixture = await Fixture.CreateAsync();
        using var response = await fixture.Client.PostAsync(XPointNetworkClosureDistributionHosting.EndpointPath, Request());
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(fixture.Frame, await response.Content.ReadAsByteArrayAsync());
        Assert.Equal(XPointNetworkClosureWireCodec.ResponseMediaType, response.Content.Headers.ContentType!.MediaType);
        Assert.True(response.Headers.CacheControl!.NoStore);
        Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").Single());
    }

    [Fact]
    public async Task CleartextAndQueryInputsRejectBeforeDistribution()
    {
        await using var fixture = await Fixture.CreateAsync();
        using var cleartext = fixture.App.GetTestClient();
        cleartext.BaseAddress = new("http://localhost/");
        using var insecure = await cleartext.PostAsync(XPointNetworkClosureDistributionHosting.EndpointPath, Request());
        Assert.Equal(HttpStatusCode.Forbidden, insecure.StatusCode);
        using var query = await fixture.Client.PostAsync(XPointNetworkClosureDistributionHosting.EndpointPath + "?bundle=private", Request());
        Assert.Equal(HttpStatusCode.BadRequest, query.StatusCode);
    }

    [Fact]
    public async Task WrongScopeMalformedAndLegacyBodyReject()
    {
        await using var fixture = await Fixture.CreateAsync();
        var otherNetwork = Network.ToArray();
        otherNetwork[0] ^= 1;
        using var other = Request(XPointNetworkClosureWireCodec.EncodeRequest(otherNetwork));
        using var wrongScope = await fixture.Client.PostAsync(XPointNetworkClosureDistributionHosting.EndpointPath, other);
        Assert.Equal(HttpStatusCode.NotFound, wrongScope.StatusCode);
        var invalid = XPointNetworkClosureWireCodec.EncodeRequest(Network);
        invalid[5] = 1;
        using var malformed = await fixture.Client.PostAsync(XPointNetworkClosureDistributionHosting.EndpointPath, Request(invalid));
        Assert.Equal(HttpStatusCode.BadRequest, malformed.StatusCode);
        using var legacy = await fixture.Client.PostAsync(XPointNetworkClosureDistributionHosting.EndpointPath, Request(new byte[100]));
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, legacy.StatusCode);
        using var media = Request();
        media.Headers.ContentType = new("application/octet-stream");
        using var wrongMedia = await fixture.Client.PostAsync(XPointNetworkClosureDistributionHosting.EndpointPath, media);
        Assert.Equal(HttpStatusCode.UnsupportedMediaType, wrongMedia.StatusCode);
    }

    [Fact]
    public async Task MissingContentLengthIsRejectedWithoutReadingUnboundedStream()
    {
        await using var fixture = await Fixture.CreateAsync();
        using var content = new UnknownLengthContent();
        content.Headers.ContentType = new(XPointNetworkClosureWireCodec.RequestMediaType);
        using var response = await fixture.Client.PostAsync(XPointNetworkClosureDistributionHosting.EndpointPath, content);
        Assert.Equal(HttpStatusCode.LengthRequired, response.StatusCode);
    }

    [Fact]
    public async Task MalformedOrSubstitutedBundleIsUnavailableNotAuthority()
    {
        await using var fixture = await Fixture.CreateAsync();
        var frame = fixture.Frame.ToArray();
        frame[12] ^= 1;
        File.WriteAllBytes(fixture.Path, frame);
        using var swapped = await fixture.Client.PostAsync(XPointNetworkClosureDistributionHosting.EndpointPath, Request());
        Assert.Equal(HttpStatusCode.ServiceUnavailable, swapped.StatusCode);
        frame[0] ^= 1;
        File.WriteAllBytes(fixture.Path, frame);
        using var malformed = await fixture.Client.PostAsync(XPointNetworkClosureDistributionHosting.EndpointPath, Request());
        Assert.Equal(HttpStatusCode.ServiceUnavailable, malformed.StatusCode);
        File.WriteAllBytes(fixture.Path, fixture.Frame);
        using var restored = await fixture.Client.PostAsync(XPointNetworkClosureDistributionHosting.EndpointPath, Request());
        Assert.Equal(HttpStatusCode.OK, restored.StatusCode);
    }

    [Fact]
    public async Task RetiredSevenChainBundleIsUnavailableWithoutPartialResponse()
    {
        await using var fixture = await Fixture.CreateAsync();
        var retired = fixture.Frame[..^20];
        BinaryPrimitives.WriteUInt16BigEndian(retired.AsSpan(8), 7);
        File.WriteAllBytes(fixture.Path, retired);
        using var response = await fixture.Client.PostAsync(XPointNetworkClosureDistributionHosting.EndpointPath, Request());
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Empty(await response.Content.ReadAsByteArrayAsync());
    }

    [Fact]
    public async Task ConcurrentFetchDoesNotQueueOrAllocateAnotherBundle()
    {
        await using var fixture = await Fixture.CreateAsync();
        var distribution = fixture.App.Services.GetRequiredService<XPointNetworkClosureDistribution>();
        Assert.True(distribution.TryEnter());
        try
        {
            using var busy = await fixture.Client.PostAsync(XPointNetworkClosureDistributionHosting.EndpointPath, Request());
            Assert.Equal(HttpStatusCode.TooManyRequests, busy.StatusCode);
        }
        finally { distribution.Exit(); }
        using var available = await fixture.Client.PostAsync(XPointNetworkClosureDistributionHosting.EndpointPath, Request());
        Assert.Equal(HttpStatusCode.OK, available.StatusCode);
    }

    [Fact]
    public void EnabledConfigurationRequiresExplicitNonzeroScopeAndRegularAbsolutePublicFile()
    {
        Assert.Throws<InvalidOperationException>(() => new XPointNetworkClosureDistribution(new()
        { NetworkIdHex = new('0', 32), BundlePath = "bundle.ncp2" }));
        Assert.Throws<InvalidOperationException>(() => new XPointNetworkClosureDistribution(new()
        { NetworkIdHex = Convert.ToHexString(Network), BundlePath = "bundle.ncp2" }));
    }

    private static ByteArrayContent Request(byte[]? bytes = null)
    {
        var content = new ByteArrayContent(bytes ?? XPointNetworkClosureWireCodec.EncodeRequest(Network));
        content.Headers.ContentType = new(XPointNetworkClosureWireCodec.RequestMediaType);
        return content;
    }

    private sealed class UnknownLengthContent : HttpContent
    {
        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) =>
            stream.WriteAsync(XPointNetworkClosureWireCodec.EncodeRequest(Network)).AsTask();
        protected override bool TryComputeLength(out long length) { length = 0; return false; }
    }

    private sealed class Fixture : IAsyncDisposable
    {
        internal string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(),
            "deep-public-closure-" + Guid.NewGuid().ToString("N") + ".ncp2");
        internal byte[] Frame { get; }
        internal WebApplication App { get; private set; } = null!;
        internal HttpClient Client { get; private set; } = null!;

        private Fixture()
        {
            var chains = new[] { "XNA1", "DTS1", "XVP1", "XNV1", "XNH1", "XND1", "PMT2", "PMA2" }
                .Select(magic => { var record = new byte[12]; Encoding.ASCII.GetBytes(magic).CopyTo(record, 0);
                    return (IReadOnlyList<ReadOnlyMemory<byte>>)new ReadOnlyMemory<byte>[] { record }; }).ToArray();
            Frame = XPointNetworkClosureWireCodec.EncodeResponse(Network,
                chains[0], chains[1], chains[2], chains[3], chains[4], chains[5], chains[6], chains[7]);
        }

        internal static async Task<Fixture> CreateAsync()
        {
            var fixture = new Fixture();
            try
            {
                File.WriteAllBytes(fixture.Path, fixture.Frame);
                var builder = WebApplication.CreateBuilder();
                builder.WebHost.UseTestServer();
                var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["XPointNetworkClosureDistribution:Enabled"] = "true",
                    ["XPointNetworkClosureDistribution:NetworkIdHex"] = Convert.ToHexString(Network),
                    ["XPointNetworkClosureDistribution:BundlePath"] = fixture.Path
                }).Build();
                var enabled = builder.Services.AddXPointNetworkClosureDistribution(configuration);
                fixture.App = builder.Build();
                fixture.App.MapXPointNetworkClosureDistribution(enabled);
                await fixture.App.StartAsync();
                fixture.Client = fixture.App.GetTestClient();
                fixture.Client.BaseAddress = new("https://localhost/");
                return fixture;
            }
            catch { await fixture.DisposeAsync(); throw; }
        }

        public async ValueTask DisposeAsync()
        {
            Client?.Dispose();
            if (App is not null) await App.DisposeAsync();
            File.Delete(Path);
        }
    }
}
#endif
