using System.Buffers.Binary;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Deep.Registry.Api.DirectoryPublication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Deep.Registry.Api.Tests;

public sealed class ContactResolveDirectoryPackageHttpTests
{
    [Fact]
    public void Cdq1_decoder_accepts_client_framing_and_preserves_complete_floors()
    {
        var network = Bytes(1, 16);
        var nonce = Bytes(2, 32);
        var boot = Bytes(3, 16);
        var encoded = EncodeRequest(network, nonce, boot, 41, includeFloors: true);

        var decoded = ContactResolveDirectoryPackageCodec.DecodeRequest(encoded);

        Assert.Equal(network, decoded.NetworkId.ToArray());
        Assert.Equal(nonce, decoded.Nonce.ToArray());
        Assert.Equal(boot, decoded.BootId.ToArray());
        Assert.Equal((ulong)41, decoded.NonceCreatedAt);
        Assert.Equal((ulong)9, decoded.DirectoryTreeSize);
        Assert.Equal(Bytes(4, 32), decoded.DirectoryCoreHash.ToArray());
        Assert.NotNull(decoded.NetworkFloor);
        Assert.Equal(CoreReference("XNH1", 5), decoded.NetworkFloor!.HeadCoreReference.ToArray());
        Assert.Equal((ulong)8, decoded.NetworkFloor.HeadTreeSize);
        Assert.Equal(CoreReference("XNF1", 10),
            decoded.NetworkFloor.LastForwardCheckpointCoreReference.ToArray());
        Assert.Equal((ulong)6, decoded.NetworkFloor.LastForwardCheckpointGeneration);
    }

    [Fact]
    public async Task Success_is_byte_identical_cdr1_and_has_strict_transport_headers()
    {
        var network = Bytes(11, 16);
        var issuer = new DelegateIssuer(request => Issued(request, includeForward: true));
        await using var app = await StartAsync(network, issuer);
        var requestBytes = EncodeRequest(network, Bytes(12, 32), Bytes(13, 16), 72, true);

        var response = await Client(app).PostAsync(
            ContactResolveDirectoryPackageHostingExtensions.EndpointPath,
            Content(requestBytes));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(ContactResolveDirectoryPackageCodec.ResponseMediaType,
            response.Content.Headers.ContentType!.MediaType);
        Assert.Empty(response.Content.Headers.ContentType.Parameters);
        Assert.True(response.Headers.CacheControl!.NoStore);
        Assert.True(response.Headers.CacheControl.Private);
        Assert.Null(response.Headers.Location);
        Assert.Equal("nosniff", Assert.Single(response.Headers.GetValues("X-Content-Type-Options")));
        var actual = await response.Content.ReadAsByteArrayAsync();
        Assert.Equal(actual.Length, response.Content.Headers.ContentLength);
        Assert.Equal(ExpectedResponse(issuer.LastRequest!, issuer.LastIssued!), actual);
        Assert.Equal(1, issuer.Calls);
    }

    [Fact]
    public async Task Default_production_composition_is_stably_unavailable_and_never_uses_catalog_state()
    {
        var network = Bytes(21, 16);
        await using var app = await StartAsync(network, issuer: null);
        var client = Client(app);
        var request = EncodeRequest(network, Bytes(22, 32), Bytes(23, 16), 91, false);

        var first = await client.PostAsync(
            ContactResolveDirectoryPackageHostingExtensions.EndpointPath, Content(request));
        var second = await client.PostAsync(
            ContactResolveDirectoryPackageHostingExtensions.EndpointPath, Content(request));

        Assert.Equal(HttpStatusCode.ServiceUnavailable, first.StatusCode);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, second.StatusCode);
        Assert.Equal("contact-resolve-issuer-unavailable", await FailureCode(first));
        Assert.Equal("contact-resolve-issuer-unavailable", await FailureCode(second));
        Assert.True(first.Headers.CacheControl!.NoStore);
    }

    [Fact]
    public async Task Malformed_oversize_trailing_and_wrong_network_fail_before_issuer()
    {
        var network = Bytes(31, 16);
        var issuer = new DelegateIssuer(request => Issued(request, includeForward: false));
        var canonical = EncodeRequest(network, Bytes(32, 32), Bytes(33, 16), 5, false);

        var malformed = canonical.ToArray();
        malformed[0] ^= 0x80;
        var malformedResponse = await SendOnFreshHost(Content(malformed));

        var trailing = canonical.Concat(new byte[] { 0x01 }).ToArray();
        var trailingResponse = await SendOnFreshHost(Content(trailing));

        var oversizeResponse = await SendOnFreshHost(
            Content(new byte[ContactResolveDirectoryPackageCodec.AbsoluteMaximumRequestBytes + 1]));

        var wrongNetworkResponse = await SendOnFreshHost(
            Content(EncodeRequest(Bytes(34, 16), Bytes(35, 32), Bytes(36, 16), 5, false)));

        Assert.Equal(HttpStatusCode.BadRequest, malformedResponse.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, trailingResponse.StatusCode);
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, oversizeResponse.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, wrongNetworkResponse.StatusCode);
        Assert.Equal("contact-resolve-wrong-network", await FailureCode(wrongNetworkResponse));
        Assert.All(new[] { malformedResponse, trailingResponse, oversizeResponse, wrongNetworkResponse },
            response => Assert.True(response.Headers.CacheControl!.NoStore));
        Assert.Equal(0, issuer.Calls);

        async Task<HttpResponseMessage> SendOnFreshHost(HttpContent content)
        {
            await using var host = await StartAsync(network, issuer);
            return await Client(host).PostAsync(
                ContactResolveDirectoryPackageHostingExtensions.EndpointPath,
                content);
        }
    }

    [Fact]
    public async Task Content_type_and_length_are_mandatory_before_issuer()
    {
        var network = Bytes(41, 16);
        var issuer = new DelegateIssuer(request => Issued(request, includeForward: false));
        await using var app = await StartAsync(network, issuer);
        var client = Client(app);
        var request = EncodeRequest(network, Bytes(42, 32), Bytes(43, 16), 7, false);

        var wrongType = new ByteArrayContent(request);
        wrongType.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        var wrongTypeResponse = await client.PostAsync(
            ContactResolveDirectoryPackageHostingExtensions.EndpointPath, wrongType);

        var unknownLength = new UnknownLengthContent(request);
        unknownLength.Headers.ContentType = new MediaTypeHeaderValue(
            ContactResolveDirectoryPackageCodec.RequestMediaType);
        var lengthResponse = await client.PostAsync(
            ContactResolveDirectoryPackageHostingExtensions.EndpointPath, unknownLength);

        Assert.Equal(HttpStatusCode.UnsupportedMediaType, wrongTypeResponse.StatusCode);
        Assert.Equal(HttpStatusCode.LengthRequired, lengthResponse.StatusCode);
        Assert.Equal(0, issuer.Calls);
    }

    [Fact]
    public async Task Issuance_for_another_nonce_is_rejected_as_server_unavailable()
    {
        var network = Bytes(51, 16);
        var issuer = new DelegateIssuer(request => Issued(
            request, includeForward: false, nonceOverride: Bytes(52, 32)));
        await using var app = await StartAsync(network, issuer);

        var response = await Client(app).PostAsync(
            ContactResolveDirectoryPackageHostingExtensions.EndpointPath,
            Content(EncodeRequest(network, Bytes(53, 32), Bytes(54, 16), 8, false)));

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal("contact-resolve-issuer-rejected", await FailureCode(response));
        Assert.Equal(1, issuer.Calls);
    }

    [Fact]
    public void Cdq1_decoder_rejects_unknown_flags_noncanonical_reference_and_length_mismatch()
    {
        var canonical = EncodeRequest(Bytes(61, 16), Bytes(62, 32), Bytes(63, 16), 9, true);

        var unknownFlags = canonical.ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(unknownFlags.AsSpan(6, 2), 0x8003);
        Assert.Throws<FormatException>(() =>
            ContactResolveDirectoryPackageCodec.DecodeRequest(unknownFlags));

        var invalidReference = canonical.ToArray();
        invalidReference[124] = (byte)'B';
        Assert.Throws<FormatException>(() =>
            ContactResolveDirectoryPackageCodec.DecodeRequest(invalidReference));

        var badLength = canonical.ToArray();
        BinaryPrimitives.WriteUInt32BigEndian(
            badLength.AsSpan(8, 4), checked((uint)badLength.Length - 1));
        Assert.Throws<FormatException>(() =>
            ContactResolveDirectoryPackageCodec.DecodeRequest(badLength));
    }

    private static async Task<WebApplication> StartAsync(
        byte[] network,
        IContactResolveDirectoryPackageIssuer? issuer)
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(
            new Dictionary<string, string?>
            {
                ["DirectoryPublication:NetworkIdHex"] = Convert.ToHexString(network)
            }).Build();
        var builder = WebApplication.CreateBuilder();
        builder.Environment.EnvironmentName = "Development";
        builder.WebHost.UseTestServer();
        if (issuer is not null) builder.Services.AddSingleton(issuer);
        var state = builder.Services.AddContactResolveDirectoryPackages(configuration);
        var app = builder.Build();
        app.MapContactResolveDirectoryPackageEndpoint(state);
        await app.StartAsync();
        return app;
    }

    private static HttpClient Client(WebApplication app)
    {
        var client = app.GetTestClient();
        client.BaseAddress = new Uri("https://localhost");
        return client;
    }

    private static ByteArrayContent Content(byte[] bytes)
    {
        var content = new ByteArrayContent(bytes);
        content.Headers.ContentType = new MediaTypeHeaderValue(
            ContactResolveDirectoryPackageCodec.RequestMediaType);
        return content;
    }

    private static async Task<string> FailureCode(HttpResponseMessage response)
    {
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return json.RootElement.GetProperty("code").GetString()!;
    }

    private static byte[] EncodeRequest(
        byte[] network,
        byte[] nonce,
        byte[] boot,
        ulong createdAt,
        bool includeFloors)
    {
        using var stream = new MemoryStream();
        stream.Write("CDQ1"u8);
        WriteU16(stream, 1);
        WriteU16(stream, includeFloors ? (ushort)3 : (ushort)0);
        WriteU32(stream, 0);
        stream.Write(network);
        stream.Write(nonce);
        stream.Write(boot);
        WriteU64(stream, createdAt);
        if (includeFloors)
        {
            WriteU64(stream, 9);
            stream.Write(Bytes(4, 32));
            stream.Write(CoreReference("XNH1", 5));
            WriteU64(stream, 8);
            stream.Write(Bytes(6, 32));
            stream.Write(CoreReference("XNV1", 7));
            WriteU64(stream, 7);
            stream.Write(CoreReference("XNA1", 8));
            stream.WriteByte(1);
            stream.Write(CoreReference("XNF1", 10));
            WriteU64(stream, 6);
        }
        var encoded = stream.ToArray();
        BinaryPrimitives.WriteUInt32BigEndian(encoded.AsSpan(8, 4), checked((uint)encoded.Length));
        return encoded;
    }

    private static ContactResolveDirectoryIssuedPackage Issued(
        ContactResolveDirectoryPackageRequest request,
        bool includeForward,
        byte[]? nonceOverride = null) => new(
            request.NetworkId,
            nonceOverride ?? request.Nonce,
            request.BootId,
            request.NonceCreatedAt,
            Bytes(70, 32),
            [Bytes(71, 3)],
            [Bytes(72, 4)],
            Bytes(73, 5),
            Bytes(74, 6),
            Bytes(75, 7),
            [Bytes(76, 8)],
            [Bytes(77, 9)],
            [Bytes(78, 10)],
            [Bytes(79, 11)],
            [Bytes(80, 12)],
            includeForward
                ? new ContactResolveForwardCheckpointPackage(
                    [Bytes(81, 13)], Bytes(82, 14), Bytes(83, 15), Bytes(84, 16))
                : null);

    private static byte[] ExpectedResponse(
        ContactResolveDirectoryPackageRequest request,
        ContactResolveDirectoryIssuedPackage package)
    {
        using var stream = new MemoryStream();
        stream.Write("CDR1"u8);
        WriteU16(stream, 1);
        WriteU16(stream, package.ForwardCheckpoint is null ? (ushort)0 : (ushort)1);
        WriteU32(stream, 0);
        stream.Write(request.NetworkId.Span);
        stream.Write(request.Nonce.Span);
        stream.Write(request.BootId.Span);
        WriteU64(stream, request.NonceCreatedAt);
        stream.Write(package.QueriedDirectoryLeafKey.Span);
        WriteChain(stream, package.ExactXna1AuthorityChain);
        WriteChain(stream, package.ExactDts1PolicyChain);
        WriteArtifact(stream, package.ExactAdh1.Span);
        WriteArtifact(stream, package.ExactDtt1.Span);
        WriteArtifact(stream, package.ExactAdp1.Span);
        WriteChain(stream, package.ExactOrderedXvp1Chain);
        WriteChain(stream, package.ExactOrderedXnv1Chain);
        WriteChain(stream, package.ExactOrderedXnh1Chain);
        WriteChain(stream, package.ExactActiveXnd1);
        WriteChain(stream, package.ExactOrderedPmt2Chain);
        if (package.ForwardCheckpoint is { } forward)
        {
            WriteChain(stream, forward.ExactOrderedXnf1Chain);
            WriteArtifact(stream, forward.ExactNfp1.Span);
            WriteArtifact(stream, forward.ExactTargetXnv1.Span);
            WriteArtifact(stream, forward.ExactTargetXnh1.Span);
        }
        var encoded = stream.ToArray();
        BinaryPrimitives.WriteUInt32BigEndian(encoded.AsSpan(8, 4), checked((uint)encoded.Length));
        return encoded;
    }

    private static void WriteChain(Stream stream, IReadOnlyList<ReadOnlyMemory<byte>> values)
    {
        WriteU32(stream, checked((uint)values.Count));
        foreach (var value in values) WriteArtifact(stream, value.Span);
    }

    private static void WriteArtifact(Stream stream, ReadOnlySpan<byte> value)
    {
        WriteU32(stream, checked((uint)value.Length));
        stream.Write(value);
    }

    private static void WriteU16(Stream stream, ushort value)
    {
        Span<byte> bytes = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(bytes, value);
        stream.Write(bytes);
    }

    private static void WriteU32(Stream stream, uint value)
    {
        Span<byte> bytes = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, value);
        stream.Write(bytes);
    }

    private static void WriteU64(Stream stream, ulong value)
    {
        Span<byte> bytes = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(bytes, value);
        stream.Write(bytes);
    }

    private static byte[] CoreReference(string magic, byte marker)
    {
        var result = new byte[38];
        System.Text.Encoding.ASCII.GetBytes(magic).CopyTo(result, 0);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(4, 2), 1);
        result.AsSpan(6).Fill(marker);
        return result;
    }

    private static byte[] Bytes(byte value, int count) =>
        Enumerable.Repeat(value, count).ToArray();

    private sealed class DelegateIssuer(
        Func<ContactResolveDirectoryPackageRequest, ContactResolveDirectoryIssuedPackage> issue)
        : IContactResolveDirectoryPackageIssuer
    {
        private int calls;
        internal int Calls => Volatile.Read(ref calls);
        internal ContactResolveDirectoryPackageRequest? LastRequest { get; private set; }
        internal ContactResolveDirectoryIssuedPackage? LastIssued { get; private set; }

        public ValueTask<ContactResolveDirectoryIssuedPackage> IssueAsync(
            ContactResolveDirectoryPackageRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Interlocked.Increment(ref calls);
            LastRequest = request;
            LastIssued = issue(request);
            return ValueTask.FromResult(LastIssued);
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
