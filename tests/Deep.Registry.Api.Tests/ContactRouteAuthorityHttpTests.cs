#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Net;
using System.Net.Http.Headers;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Registry.Api.ContactRouteClosure;
using Deep.Registry.Api.DirectoryPublication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Deep.Registry.Api.Tests;

public sealed class ContactRouteAuthorityHttpTests
{
    [Fact]
    public async Task ExactRequestReturnsBoundedNoStoreThresholdRecords()
    {
        var network = Bytes(16, 0x11);
        var artifacts = ContactRouteClosureTransportTests.CanonicalTransportArtifacts
            .Create(network, 0x20);
        var request = Request(network, artifacts.Xra);
        var issuer = new FixedIssuer(artifacts);
        await using var host = await StartAsync(
            new ContactRouteAuthorityHostingState(network), issuer);
        using var message = Message(request);

        using var response = await host.Client.SendAsync(message);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(ContactRouteAuthorityWireCodec.ResponseMediaType,
            response.Content.Headers.ContentType?.MediaType);
        Assert.True(response.Headers.CacheControl?.NoStore);
        Assert.True(response.Headers.CacheControl?.Private);
        Assert.Equal(TimeSpan.Zero, response.Headers.CacheControl?.MaxAge);
        var decoded = ContactRouteAuthorityWireCodec.DecodeResponse(
            request, await response.Content.ReadAsByteArrayAsync());
        Assert.Equal(artifacts.Pms, decoded.ExactPms2.ToArray());
        Assert.Equal(artifacts.Xrc, decoded.ExactXrc1.ToArray());
        Assert.Equal(artifacts.Xss, decoded.ExactXss1.ToArray());
        Assert.Equal(1, issuer.CallCount);
    }

    [Fact]
    public async Task WrongNetworkMalformedAndUnavailableRequestsFailClosed()
    {
        var network = Bytes(16, 0x11);
        var artifacts = ContactRouteClosureTransportTests.CanonicalTransportArtifacts
            .Create(network, 0x30);
        var issuer = new FixedIssuer(artifacts);
        await using var host = await StartAsync(
            new ContactRouteAuthorityHostingState(network), issuer);

        using (var wrongNetwork = Message(Request(Bytes(16, 0x12),
                   ContactRouteClosureTransportTests.CanonicalTransportArtifacts
                       .Create(Bytes(16, 0x12), 0x31).Xra)))
        using (var response = await host.Client.SendAsync(wrongNetwork))
            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal(0, issuer.CallCount);

        using (var malformed = new HttpRequestMessage(
                   HttpMethod.Post, ContactRouteAuthorityHostingExtensions.EndpointPath)
               {
                   Content = new ByteArrayContent(new byte[10]),
               })
        {
            malformed.Content.Headers.ContentType = MediaTypeHeaderValue.Parse(
                ContactRouteAuthorityWireCodec.RequestMediaType);
            using var response = await host.Client.SendAsync(malformed);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        }

        await using var disabled = await StartAsync(default, issuer);
        using var canonical = Message(Request(network, artifacts.Xra));
        using var unavailable = await disabled.Client.SendAsync(canonical);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, unavailable.StatusCode);
        Assert.Equal(0, unavailable.Content.Headers.ContentLength);
    }

    private static ContactRouteAuthorityWireRequest Request(byte[] network, byte[] exactXra1)
    {
        var dpa = ApplicationCoreCodec.CreateArtifactReference(
            1, 644, Bytes(32, 0x41));
        var dab = ApplicationCoreCodec.CreateArtifactReference(
            ApplicationCoreCodec.Dab1ArtifactTypeCode, 394, Bytes(32, 0x42));
        var deviceId = ContactCodec.Decode("XRA1", exactXra1).Field(14);
        var dca = ApplicationCoreCodec.AuthorDca1(
            network, Bytes(32, 0x43), dpa, 1, Bytes(32, 0x44),
            Bytes(32, 0x45), deviceId.Span, 3, 5, 20, 90,
            Bytes(64, 0x46), Bytes(32, 0x47), dab);
        return new ContactRouteAuthorityWireRequest(
            network, Bytes(32, 0x48), Bytes(32, 0x49), 0,
            Bytes(32, 0x4a), dca.CanonicalBytes.Span, exactXra1);
    }

    private static HttpRequestMessage Message(ContactRouteAuthorityWireRequest request)
    {
        var message = new HttpRequestMessage(
            HttpMethod.Post, ContactRouteAuthorityHostingExtensions.EndpointPath)
        {
            Content = new ByteArrayContent(
                ContactRouteAuthorityWireCodec.EncodeRequest(request)),
        };
        message.Content.Headers.ContentType = MediaTypeHeaderValue.Parse(
            ContactRouteAuthorityWireCodec.RequestMediaType);
        return message;
    }

    private static async Task<TestHost> StartAsync(
        ContactRouteAuthorityHostingState state,
        IContactRouteThresholdIssuer issuer)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = "Testing",
        });
        builder.WebHost.UseTestServer();
        builder.Services.TryAddSingleton(TimeProvider.System);
        builder.Services.TryAddSingleton<ContactResolveIssuanceAdmissionGate>();
        builder.Services.AddSingleton(issuer);
        var app = builder.Build();
        app.MapContactRouteAuthorityEndpoint(state);
        await app.StartAsync();
        return new TestHost(app, app.GetTestClient());
    }

    private static byte[] Bytes(int length, byte start) =>
        Enumerable.Range(0, length)
            .Select(index => unchecked((byte)(start + index))).ToArray();

    private sealed class FixedIssuer(
        ContactRouteClosureTransportTests.CanonicalTransportArtifacts artifacts) :
        IContactRouteThresholdIssuer
    {
        internal int CallCount { get; private set; }

        public ValueTask<ContactRouteAuthorityWireResponse> IssueAsync(
            ContactRouteAuthorityWireRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            CallCount++;
            return ValueTask.FromResult(new ContactRouteAuthorityWireResponse(
                request.NetworkId.Span, request.RequestNonce.Span,
                artifacts.Pms, artifacts.Xrc, artifacts.Xss));
        }
    }

    private sealed class TestHost(WebApplication app, HttpClient client) : IAsyncDisposable
    {
        internal HttpClient Client { get; } = client;

        public async ValueTask DisposeAsync()
        {
            Client.Dispose();
            await app.DisposeAsync();
        }
    }
}
#endif
