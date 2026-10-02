#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Net;
using System.Net.Http.Headers;
using System.Globalization;
using System.Security.Cryptography;
using System.Buffers.Binary;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ContactV2;
using Sodium;
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
    public void IssuedHeadResponseIsV3OnlyBoundedAndDefensivelyOwned()
    {
        var network = Bytes(16, 0x11);
        var artifacts = ContactRouteClosureTransportTests.CanonicalTransportArtifacts.Create(network, 0x21);
        var request = Request(network, artifacts.Xra);
        var head = IssuanceHead(network);
        Assert.Equal(ContactRouteAuthorityWireCodec.MinimumIssuanceAdh1Bytes, head.Length);
        var response = new ContactRouteAuthorityWireResponse(network, request.RequestNonce.Span,
            artifacts.Pms, artifacts.Xrc, artifacts.Xss, head);
        var exact = ContactRouteAuthorityWireCodec.EncodeResponse(request, response);
        Assert.Equal(3, BinaryPrimitives.ReadUInt16BigEndian(ContactRouteAuthorityWireCodec.EncodeRequest(request)));
        Assert.Equal(3, BinaryPrimitives.ReadUInt16BigEndian(exact));
        Assert.Equal(head, ContactRouteAuthorityWireCodec.DecodeResponse(request, exact).ExactIssuanceAdh1.ToArray());
        Array.Clear(head);
        Assert.Equal(IssuanceHead(network), response.ExactIssuanceAdh1.ToArray());
        var escaped = response.ExactIssuanceAdh1.ToArray(); Array.Clear(escaped);
        Assert.Equal(IssuanceHead(network), response.ExactIssuanceAdh1.ToArray());
        foreach (var mutation in new[] { "v2", "missing", "trailing", "hostile", "oversize", "network", "nonce" })
        {
            var damaged = exact.ToArray();
            if (mutation == "v2") BinaryPrimitives.WriteUInt16BigEndian(damaged, 2);
            if (mutation == "missing") damaged = damaged[..(damaged.Length - 4 - IssuanceHead(network).Length)];
            if (mutation == "trailing") damaged = damaged.Append((byte)0).ToArray();
            if (mutation == "oversize") damaged = new byte[ContactRouteAuthorityWireCodec.MaximumResponseBytes + 1];
            var offset = 56;
            if (mutation is "hostile" or "network")
            {
                for (var i = 0; i < 3; i++) offset += 4 + checked((int)BinaryPrimitives.ReadUInt32BigEndian(damaged.AsSpan(offset)));
                if (mutation == "hostile") BinaryPrimitives.WriteUInt32BigEndian(damaged.AsSpan(offset), uint.MaxValue);
                else damaged[offset + 4 + 20] ^= 1; // ADH1 field1 network
            }
            if (mutation == "nonce") damaged[24] ^= 1;
            if (mutation is "missing" or "trailing") BinaryPrimitives.WriteUInt32BigEndian(damaged.AsSpan(4), checked((uint)damaged.Length));
            var error = Record.Exception(() => ContactRouteAuthorityWireCodec.DecodeResponse(request, damaged));
            Assert.True(error is FormatException or CryptographicException or ArgumentException, mutation);
        }
        Assert.Throws<ArgumentException>(() => new ContactRouteAuthorityWireResponse(network, request.RequestNonce.Span,
            artifacts.Pms, artifacts.Xrc, artifacts.Xss, new byte[4097]));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task BothTerminalsRejectUnauthenticatedOrSubstitutedNodeBeforeIssuer(bool publication)
    {
        var network = Bytes(16, 0x11);
        var artifacts = ContactRouteClosureTransportTests.CanonicalTransportArtifacts.Create(network, 0x21);
        var issuer = new FixedIssuer(artifacts);
        var access = PeerAuthenticationFixture.Access();
        var target = publication ? ContactCoordinationTarget.Publication : ContactCoordinationTarget.Route;
        var bytes = publication ? Bytes(ContactPublicationAuthorityWireCodec.MinimumRequestBytes, 0x21) :
            ContactRouteAuthorityWireCodec.EncodeRequest(Request(network, artifacts.Xra));
        foreach (var mutation in new[] { "missing", "unknown", "duplicate", "upper", "expired", "future", "network", "target", "body", "nonce", "zero-signature" })
        {
            // Each hostile input gets an independent real admission budget; otherwise
            // the shared flood limiter legitimately returns 429 before body verification.
            await using var host = await StartAsync(new(network, access), issuer, new(network, access));
            using var message = new HttpRequestMessage(HttpMethod.Post, publication ? ContactPublicationAuthorityHostingExtensions.EndpointPath :
                ContactRouteAuthorityHostingExtensions.EndpointPath) { Content = new ByteArrayContent(bytes) };
            message.Content.Headers.ContentType = MediaTypeHeaderValue.Parse(publication ? ContactPublicationAuthorityWireCodec.RequestMediaType :
                ContactRouteAuthorityWireCodec.RequestMediaType);
            PeerAuthenticationFixture.Authenticate(message, mutation == "network" ? Bytes(16, 0x12) : network, target, bytes,
                mutation == "expired" ? DateTimeOffset.UtcNow.AddMinutes(-1).ToUnixTimeMilliseconds() :
                mutation == "future" ? DateTimeOffset.UtcNow.AddMinutes(1).ToUnixTimeMilliseconds() : null,
                mutation == "unknown" ? (byte)0x74 : (byte)0x73, mutation == "target");
            if (mutation == "missing") message.Headers.Remove(ContactCoordinationPeerAuthentication.SignatureHeader);
            if (mutation == "duplicate") message.Headers.Add(ContactCoordinationPeerAuthentication.NodeHeader,
                message.Headers.GetValues(ContactCoordinationPeerAuthentication.NodeHeader).Single());
            if (mutation is "upper" or "nonce" or "zero-signature")
            {
                var name = mutation == "upper" ? ContactCoordinationPeerAuthentication.NodeHeader : mutation == "nonce" ?
                    ContactCoordinationPeerAuthentication.NonceHeader : ContactCoordinationPeerAuthentication.SignatureHeader;
                var value = message.Headers.GetValues(name).Single();
                message.Headers.Remove(name);
                message.Headers.Add(name, mutation == "upper" ? value.ToUpperInvariant() : mutation == "nonce" ?
                    (value[0] == 'a' ? "b" : "a") + value[1..] : new string('0', 128));
            }
            if (mutation == "body")
            {
                var changed = bytes.ToArray(); changed[^1] ^= 1;
                message.Content = new ByteArrayContent(changed);
                message.Content.Headers.ContentType = MediaTypeHeaderValue.Parse(publication ? ContactPublicationAuthorityWireCodec.RequestMediaType :
                    ContactRouteAuthorityWireCodec.RequestMediaType);
            }
            using var response = await host.Client.SendAsync(message);
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Empty(await response.Content.ReadAsByteArrayAsync());
            Assert.True(response.Headers.CacheControl?.NoStore);
            Assert.Equal(0, issuer.CallCount);
        }
    }

    [Fact]
    public void TransportAllowListRejectsMissingDuplicateNoncanonicalOrUnboundedConfiguration()
    {
        Assert.Throws<InvalidOperationException>(() => new ContactCoordinationIngressAuthenticator([]));
        Assert.Throws<InvalidOperationException>(() => new ContactCoordinationIngressAuthenticator([new string('0', 64)]));
        var key = new string('a', 64);
        Assert.Throws<InvalidOperationException>(() => new ContactCoordinationIngressAuthenticator([key, key]));
        Assert.Throws<InvalidOperationException>(() => new ContactCoordinationIngressAuthenticator([key.ToUpperInvariant()]));
        Assert.Throws<InvalidOperationException>(() => new ContactCoordinationIngressAuthenticator(Enumerable.Repeat(key, 257).ToArray()));
        Assert.NotNull(new ContactCoordinationIngressAuthenticator([key]));
    }

    [Theory]
    [InlineData(ContactCoordinationTarget.Route)]
    [InlineData(ContactCoordinationTarget.Publication)]
    public void ActualNodeSignatureBindsBothTargetsAndExactWindow(ContactCoordinationTarget target)
    {
        var network = Bytes(16, 0x11);
        var body = Bytes(target == ContactCoordinationTarget.Route ? ContactRouteAuthorityWireCodec.MinimumRequestBytes :
            ContactPublicationAuthorityWireCodec.MinimumRequestBytes, 0x22);
        var now = DateTimeOffset.FromUnixTimeMilliseconds(1_000_000);
        using var message = new HttpRequestMessage();
        PeerAuthenticationFixture.Authenticate(message, network, target, body, now.ToUnixTimeMilliseconds());
        var headers = new ContactCoordinationPeerHeaders(message.Headers.GetValues(ContactCoordinationPeerAuthentication.NodeHeader).Single(),
            message.Headers.GetValues(ContactCoordinationPeerAuthentication.TimestampHeader).Single(),
            message.Headers.GetValues(ContactCoordinationPeerAuthentication.NonceHeader).Single(),
            message.Headers.GetValues(ContactCoordinationPeerAuthentication.SignatureHeader).Single());
        Assert.True(ContactCoordinationPeerAuthentication.Verify(headers, network, target, body, now));
        Assert.True(ContactCoordinationPeerAuthentication.Verify(headers, network, target, body, now.AddMilliseconds(30_000)));
        Assert.True(ContactCoordinationPeerAuthentication.Verify(headers, network, target, body, now.AddMilliseconds(-30_000)));
        Assert.False(ContactCoordinationPeerAuthentication.Verify(headers, network, target, body, now.AddMilliseconds(30_001)));
        Assert.False(ContactCoordinationPeerAuthentication.Verify(headers, network, target, body, now.AddMilliseconds(-30_001)));
        Assert.False(ContactCoordinationPeerAuthentication.Verify(headers with { TimestampUnixMilliseconds = "01000000" }, network, target, body, now));
    }

    // Pipeline-only canonical records. FixedIssuer is not authority evidence.
    [Theory]
    [InlineData("http", 400)]
    [InlineData("query", 400)]
    [InlineData("old-path", 404)]
    [InlineData("media", 415)]
    [InlineData("v1", 400)]
    [InlineData("v2", 400)]
    [InlineData("old-media", 415)]
    [InlineData("prior-size", 400)]
    [InlineData("missing-prior", 400)]
    [InlineData("flags", 400)]
    [InlineData("oversize", 413)]
    [InlineData("trailing", 400)]
    [InlineData("old-dca", 400)]
    public async Task HostileFramingRejectsBeforeIssuer(string mutation, int expectedStatus)
    {
        var network = Bytes(16, 0x11);
        var artifacts = ContactRouteClosureTransportTests.CanonicalTransportArtifacts.Create(network, 0x21);
        var request = Request(network, artifacts.Xra);
        var issuer = new FixedIssuer(artifacts);
        await using var host = await StartAsync(new(network, PeerAuthenticationFixture.Access()), issuer);
        var bytes = ContactRouteAuthorityWireCodec.EncodeRequest(request);
        var uri = "https://authority.example" + ContactRouteAuthorityHostingExtensions.EndpointPath;
        if (mutation == "http") uri = uri.Replace("https:", "http:", StringComparison.Ordinal);
        if (mutation == "query") uri += "?extra=1";
        if (mutation == "old-path") uri = uri.Replace("/v2/", "/v1/", StringComparison.Ordinal);
        if (mutation == "v1") bytes[1] = 1;
        if (mutation == "v2") bytes[1] = 2;
        if (mutation == "prior-size") bytes.AsSpan(ContactRouteAuthorityWireCodec.RequestPrefixBytes, 4).Fill(255);
        if (mutation == "missing-prior") { bytes[692] = 1; bytes.AsSpan(701, 32).Fill(1); }
        if (mutation == "flags") bytes[3] = 1;
        if (mutation == "oversize") bytes = new byte[ContactRouteAuthorityWireCodec.MaximumRequestBytes + 1];
        if (mutation == "trailing") bytes = [.. bytes, 1];
        if (mutation == "old-dca") bytes[128 + 5] = 1;
        using var message = new HttpRequestMessage(HttpMethod.Post, uri) { Content = new ByteArrayContent(bytes) };
        message.Content.Headers.ContentType = MediaTypeHeaderValue.Parse(mutation == "media" ?
            "application/octet-stream" : mutation == "old-media" ?
            "application/vnd.deep.contact-route-authority-request.v2+octet-stream" : ContactRouteAuthorityWireCodec.RequestMediaType);
        if (mutation == "trailing") message.Content.Headers.ContentLength = ContactRouteAuthorityWireCodec.MinimumRequestBytes;
        PeerAuthenticationFixture.Authenticate(message, network, ContactCoordinationTarget.Route,
            bytes.Length <= ContactRouteAuthorityWireCodec.MaximumRequestBytes && mutation != "trailing" ? bytes : bytes[..ContactRouteAuthorityWireCodec.MinimumRequestBytes]);
        using var response = await host.Client.SendAsync(message);
        Assert.Equal(expectedStatus, (int)response.StatusCode);
        Assert.Equal(0, issuer.CallCount);
        if (mutation != "old-path")
        {
            Assert.Empty(await response.Content.ReadAsByteArrayAsync());
            Assert.True(response.Headers.CacheControl?.NoStore);
        }
    }

    [Fact]
    public async Task ExactRequestReturnsBoundedNoStoreThresholdRecords()
    {
        var network = Bytes(16, 0x11);
        var artifacts = ContactRouteClosureTransportTests.CanonicalTransportArtifacts
            .Create(network, 0x20);
        var request = Request(network, artifacts.Xra);
        var issuer = new FixedIssuer(artifacts);
        await using var host = await StartAsync(
            new ContactRouteAuthorityHostingState(network, PeerAuthenticationFixture.Access()), issuer);
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
            new ContactRouteAuthorityHostingState(network, PeerAuthenticationFixture.Access()), issuer);

        using (var wrongNetwork = Message(Request(Bytes(16, 0x12),
                   ContactRouteClosureTransportTests.CanonicalTransportArtifacts
                       .Create(Bytes(16, 0x12), 0x31).Xra), network))
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
            PeerAuthenticationFixture.Authenticate(malformed, network, ContactCoordinationTarget.Route,
                ContactRouteAuthorityWireCodec.EncodeRequest(Request(network, artifacts.Xra)));
            using var response = await host.Client.SendAsync(malformed);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        }

        await using var disabled = await StartAsync(default, issuer);
        using var canonical = Message(Request(network, artifacts.Xra));
        using var unavailable = await disabled.Client.SendAsync(canonical);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, unavailable.StatusCode);
        Assert.Equal(0, unavailable.Content.Headers.ContentLength);
    }

    internal static ContactRouteAuthorityWireRequest Request(byte[] network, byte[] exactXra1)
    {
        var dpa = ApplicationCoreCodec.CreateArtifactReference(
            1, 644, Bytes(32, 0x41));
        var dab = ApplicationCoreCodec.CreateArtifactReference(
            DeepIdV2Codec.Dab2ArtifactType, DeepIdV2Codec.Dab2Length, Bytes(32, 0x42));
        var deviceId = ContactCodec.Decode("XRA1", exactXra1).Field(14);
        var dca = DeepIdV2ContactAuthorizationCodec.Author(
            network, Bytes(32, 0x43), dpa, 1, Bytes(32, 0x44),
            Bytes(32, 0x45), deviceId.Span, 3, 5, 20, 90,
            Bytes(64, 0x46), Bytes(32, 0x47), dab);
        return new ContactRouteAuthorityWireRequest(
            network, Bytes(32, 0x48), Bytes(32, 0x49), 0,
            Bytes(32, 0x4a), dca.CanonicalBytes.Span, exactXra1);
    }

    private static HttpRequestMessage Message(ContactRouteAuthorityWireRequest request, byte[]? hostingNetwork = null)
    {
        var message = new HttpRequestMessage(
            HttpMethod.Post, ContactRouteAuthorityHostingExtensions.EndpointPath)
        {
            Content = new ByteArrayContent(
                ContactRouteAuthorityWireCodec.EncodeRequest(request)),
        };
        message.Content.Headers.ContentType = MediaTypeHeaderValue.Parse(
            ContactRouteAuthorityWireCodec.RequestMediaType);
        PeerAuthenticationFixture.Authenticate(message, hostingNetwork ?? request.NetworkId.ToArray(),
            ContactCoordinationTarget.Route, ContactRouteAuthorityWireCodec.EncodeRequest(request));
        return message;
    }

    private static async Task<TestHost> StartAsync(
        ContactRouteAuthorityHostingState state,
        IContactRouteThresholdIssuer issuer,
        ContactPublicationAuthorityHostingState publicationState = default)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = "Testing",
        });
        builder.WebHost.UseTestServer();
        builder.Services.TryAddSingleton(TimeProvider.System);
        builder.Services.TryAddSingleton<ContactResolveIssuanceAdmissionGate>();
        builder.Services.AddSingleton(issuer);
        builder.Services.AddSingleton<IContactPublicationThresholdIssuer, MustNotCallPublicationIssuer>();
        var app = builder.Build();
        app.MapContactRouteAuthorityEndpoint(state);
        app.MapContactPublicationAuthorityEndpoint(publicationState);
        await app.StartAsync();
        var client = app.GetTestClient();
        client.BaseAddress = new Uri("https://authority.example/");
        return new TestHost(app, client);
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
                artifacts.Pms, artifacts.Xrc, artifacts.Xss, IssuanceHead(request.NetworkId.Span)));
        }
    }

    // Canonical transport shape only; fake signatures do not grant authority.
    internal static byte[] IssuanceHead(ReadOnlySpan<byte> network)
    {
        var reference = new byte[38]; "XNA1"u8.CopyTo(reference);
        BinaryPrimitives.WriteUInt16BigEndian(reference.AsSpan(4), 1);
        Bytes(32, 0x81).CopyTo(reference, 6);
        return AccountDirectoryAdh1Codec.Encode(new(network, 0, new byte[32], 0,
            Bytes(32, 0x82), Bytes(32, 0x83), reference, Bytes(32, 0x84), 20, 90, 2,
            [new AccountDirectoryAdh1WitnessEntry(Bytes(32, 0x85), Bytes(64, 0x86))]));
    }

    private sealed class MustNotCallPublicationIssuer : IContactPublicationThresholdIssuer
    {
        public ValueTask<ContactPublicationAuthorityWireResponse> IssueAsync(ContactPublicationAuthorityWireRequest request, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Unauthenticated publication must never reach the issuer.");
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

// Deterministic test-only node key. This signs the real DR48 transcript, not issuer evidence.
internal static class PeerAuthenticationFixture
{
    internal static ContactCoordinationIngressAuthenticator Access()
    {
        var key = PublicKeyAuth.GenerateKeyPair(Enumerable.Repeat((byte)0x73, 32).ToArray());
        try { return new([Convert.ToHexStringLower(key.PublicKey)]); }
        finally { CryptographicOperations.ZeroMemory(key.PrivateKey); }
    }

    internal static void Authenticate(HttpRequestMessage message, byte[] network,
        ContactCoordinationTarget target, byte[] exactBody, long? timestamp = null, byte marker = 0x73, bool substituteTarget = false)
    {
        var key = PublicKeyAuth.GenerateKeyPair(Enumerable.Repeat(marker, 32).ToArray());
        var nonce = RandomNumberGenerator.GetBytes(16);
        var time = timestamp ?? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var input = ContactCoordinationPeerAuthentication.GetSigningInput(network, target, key.PublicKey, time, nonce, exactBody);
        if (substituteTarget) input["Deep/ContactResolver/V2/private-coordination-peer".Length + 1 + 2 + 16] =
            (byte)(target == ContactCoordinationTarget.Route ? ContactCoordinationTarget.Publication : ContactCoordinationTarget.Route);
        try
        {
            foreach (var name in new[] { ContactCoordinationPeerAuthentication.NodeHeader, ContactCoordinationPeerAuthentication.TimestampHeader,
                         ContactCoordinationPeerAuthentication.NonceHeader, ContactCoordinationPeerAuthentication.SignatureHeader })
                message.Headers.Remove(name);
            message.Headers.Add(ContactCoordinationPeerAuthentication.NodeHeader, Convert.ToHexStringLower(key.PublicKey));
            message.Headers.Add(ContactCoordinationPeerAuthentication.TimestampHeader, time.ToString(CultureInfo.InvariantCulture));
            message.Headers.Add(ContactCoordinationPeerAuthentication.NonceHeader, Convert.ToHexStringLower(nonce));
            message.Headers.Add(ContactCoordinationPeerAuthentication.SignatureHeader, Convert.ToHexStringLower(PublicKeyAuth.SignDetached(input, key.PrivateKey)));
        }
        finally { CryptographicOperations.ZeroMemory(key.PrivateKey); CryptographicOperations.ZeroMemory(input); }
    }
}
#endif
