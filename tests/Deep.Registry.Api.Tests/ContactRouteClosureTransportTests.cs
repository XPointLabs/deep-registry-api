#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Buffers.Binary;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.ContactV1;
using Deep.Registry.Api.ContactRouteClosure;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Deep.Registry.Api.Tests;

public sealed class ContactRouteClosureTransportTests
{
    [Fact]
    public async Task CanonicalPublicationIsReturnedAsExactBoundedNoStoreTransportBytes()
    {
        using var store = RouteStore.Create();
        var fixture = CanonicalTransportArtifacts.Create(store.Network, 0x20);
        store.Publish(store.Locator, 1, fixture);
        await using var host = await StartAsync(store.Configuration());

        using var response = await host.Client.SendAsync(Request(store.Network, store.Locator));
        var actual = await response.Content.ReadAsByteArrayAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(ContactRouteClosureTransportCodec.ResponseMediaType,
            response.Content.Headers.ContentType?.MediaType);
        Assert.Equal(fixture.Closure.Length, response.Content.Headers.ContentLength);
        Assert.Equal(fixture.Closure, actual);
        Assert.Contains("no-store", response.Headers.CacheControl?.ToString());
        Assert.Equal("no-cache", Assert.Single(response.Headers.Pragma).Name);
        Assert.DoesNotContain(response.Headers, header =>
            StringComparer.OrdinalIgnoreCase.Equals(header.Key, "Location"));
    }

    [Fact]
    public async Task DormantHostAndUnknownLocatorUseEmptyCoarseFailures()
    {
        await using var dormant = await StartAsync(new Dictionary<string, string?>());
        var network = Bytes(16, 0x11);
        var locator = Bytes(32, 0x22);
        using var unavailable = await dormant.Client.SendAsync(Request(network, locator));
        Assert.Equal(HttpStatusCode.ServiceUnavailable, unavailable.StatusCode);
        Assert.Equal(0, unavailable.Content.Headers.ContentLength);

        using var store = RouteStore.Create();
        await using var active = await StartAsync(store.Configuration());
        using var missing = await active.Client.SendAsync(Request(store.Network, store.Locator));
        Assert.Equal(HttpStatusCode.NotFound, missing.StatusCode);
        Assert.Equal(0, missing.Content.Headers.ContentLength);
        Assert.Equal(unavailable.Headers.CacheControl?.ToString(),
            missing.Headers.CacheControl?.ToString());
    }

    [Fact]
    public async Task CompleteConfigurationWithUnavailableKeyFailsClosedAsNoStore503()
    {
        using var store = RouteStore.Create();
        var configuration = store.Configuration();
        configuration["ContactRouteClosureTransport:IntegrityKeyPath"] =
            Path.Combine(store.BasePath, "missing.key");
        await using var host = await StartAsync(configuration);

        using var response = await host.Client.SendAsync(Request(store.Network, store.Locator));

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal(0, response.Content.Headers.ContentLength);
        Assert.Contains("no-store", response.Headers.CacheControl?.ToString());
    }

    [Fact]
    public async Task HostileHttpShapesAreRejectedBeforeLookup()
    {
        await using var host = await StartAsync(new Dictionary<string, string?>());
        var canonical = EncodeRequest(Bytes(16, 0x31), Bytes(32, 0x32));

        using var wrongMedia = new HttpRequestMessage(HttpMethod.Post,
            ContactRouteClosureHostingExtensions.EndpointPath)
        {
            Content = new ByteArrayContent(canonical),
        };
        wrongMedia.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        using var wrongMediaResponse = await host.Client.SendAsync(wrongMedia);
        Assert.Equal(HttpStatusCode.UnsupportedMediaType, wrongMediaResponse.StatusCode);

        using var oversized = Request(Bytes(16, 0x31), Bytes(32, 0x32));
        oversized.Content = new ByteArrayContent(new byte[ContactRouteClosureTransportCodec.RequestBytes + 1]);
        oversized.Content.Headers.ContentType = MediaTypeHeaderValue.Parse(
            ContactRouteClosureTransportCodec.RequestMediaType);
        using var oversizedResponse = await host.Client.SendAsync(oversized);
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, oversizedResponse.StatusCode);

        canonical[0] = 0;
        canonical[1] = 2;
        using var nonCanonical = RawRequest(canonical);
        using var nonCanonicalResponse = await host.Client.SendAsync(nonCanonical);
        Assert.Equal(HttpStatusCode.BadRequest, nonCanonicalResponse.StatusCode);
    }

    [Fact]
    public void PartialConfigurationFailsComposition()
    {
        var services = new ServiceCollection();
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(
            new Dictionary<string, string?>
            {
                ["ContactRouteClosureTransport:ReadOnlyRoot"] = "present-only",
            }).Build();

        Assert.Throws<InvalidOperationException>(() =>
            services.AddContactRouteClosureTransport(configuration));
    }

    [Fact]
    public async Task TamperedArtifactIsRejectedAndLooksAbsentOverHttp()
    {
        using var store = RouteStore.Create();
        var fixture = CanonicalTransportArtifacts.Create(store.Network, 0x40);
        var generation = store.Publish(store.Locator, 1, fixture);
        var xrr = Path.Combine(generation, "xrr1.bin");
        var tampered = File.ReadAllBytes(xrr);
        tampered[^1] ^= 0x01;
        File.WriteAllBytes(xrr, tampered);
        await using var host = await StartAsync(store.Configuration());

        using var response = await host.Client.SendAsync(Request(store.Network, store.Locator));

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal(0, response.Content.Headers.ContentLength);
    }

    [Fact]
    public async Task CanonicalButUnboundXirIsRejectedBeforeTransport()
    {
        using var store = RouteStore.Create();
        var fixture = CanonicalTransportArtifacts.Create(store.Network, 0x44);
        var other = CanonicalTransportArtifacts.Create(store.Network, 0x45);
        var generation = store.Publish(store.Locator, 1, fixture);
        File.WriteAllBytes(Path.Combine(generation, "xir1.bin"), other.Xir);
        var manifestPath = Path.Combine(generation, "manifest.json");
        var manifest = FileContactRouteClosureManifestCodec.DecodeCanonical(
            File.ReadAllBytes(manifestPath));
        var entries = manifest.Artifacts.ToArray();
        entries[0] = entries[0] with { Sha256Hex = Lower(SHA256.HashData(other.Xir)) };
        File.WriteAllBytes(manifestPath,
            FileContactRouteClosureManifestCodec.EncodeCanonical(manifest with { Artifacts = entries }));
        using var source = store.Source();

        await Assert.ThrowsAsync<ContactRouteClosurePublicationRejectedException>(async () =>
            await source.ReadAsync(store.Network, store.Locator, default));
    }

    [Fact]
    public async Task CrossSelectorReplayIsRejectedBeforeProtectedLocatorStateMutation()
    {
        using var store = RouteStore.Create();
        var otherLocator = Bytes(32, 0x33);
        var replay = CanonicalTransportArtifacts.Create(
            store.Network,
            0x48,
            otherLocator);
        store.Publish(store.Locator, 1, replay);
        using var source = store.Source();

        await Assert.ThrowsAsync<ContactRouteClosurePublicationRejectedException>(async () =>
            await source.ReadAsync(store.Network, store.Locator, default));
        Assert.False(File.Exists(store.StatePath(store.Locator)));

        var current = CanonicalTransportArtifacts.Create(store.Network, 0x49, store.Locator);
        store.Publish(store.Locator, 1, current);
        var accepted = await source.ReadAsync(store.Network, store.Locator, default);

        Assert.Equal(current.Closure, accepted.ToArray());
        Assert.True(File.Exists(store.StatePath(store.Locator)));
    }

    [Fact]
    public async Task CanonicalManifestNullIsNormalizedToPublicationRejection()
    {
        using var store = RouteStore.Create();
        var fixture = CanonicalTransportArtifacts.Create(store.Network, 0x46);
        var generation = store.Publish(store.Locator, 1, fixture);
        var manifestPath = Path.Combine(generation, "manifest.json");
        var manifest = FileContactRouteClosureManifestCodec.DecodeCanonical(
            File.ReadAllBytes(manifestPath));
        File.WriteAllBytes(manifestPath,
            FileContactRouteClosureManifestCodec.EncodeCanonical(
                manifest with { NetworkIdHex = null! }));
        using var source = store.Source();

        await Assert.ThrowsAsync<ContactRouteClosurePublicationRejectedException>(async () =>
            await source.ReadAsync(store.Network, store.Locator, default));
    }

    [Fact]
    public async Task PredictableLegacyStateStagingSymlinkIsNeverFollowedWhereSupported()
    {
        using var store = RouteStore.Create();
        var fixture = CanonicalTransportArtifacts.Create(store.Network, 0x47);
        store.Publish(store.Locator, 1, fixture);
        var statePath = store.StatePath(store.Locator);
        Directory.CreateDirectory(Path.GetDirectoryName(statePath)!);
        var external = Path.Combine(store.BasePath, "external-state-target.bin");
        var sentinel = Bytes(64, 0x5a);
        File.WriteAllBytes(external, sentinel);
        try
        {
            File.CreateSymbolicLink(statePath + ".writing", external);
        }
        catch (Exception exception) when (exception is UnauthorizedAccessException or
            IOException or PlatformNotSupportedException)
        {
            return;
        }
        using var source = store.Source();

        _ = await source.ReadAsync(store.Network, store.Locator, default);

        Assert.Equal(sentinel, File.ReadAllBytes(external));
    }

    [Fact]
    public async Task EndpointRateLimitIsActiveBeforeSourceLookup()
    {
        await using var host = await StartAsync(new Dictionary<string, string?>());
        var network = Bytes(16, 0x51);
        var locator = Bytes(32, 0x52);
        var responses = await Task.WhenAll(Enumerable.Range(0, 513).Select(async _ =>
        {
            using var request = Request(network, locator);
            return await host.Client.SendAsync(request);
        }));
        try
        {
            Assert.Contains(responses, response =>
                response.StatusCode == HttpStatusCode.TooManyRequests);
            Assert.All(responses.Where(response =>
                    response.StatusCode == HttpStatusCode.TooManyRequests), response =>
                Assert.Contains("no-store", response.Headers.CacheControl?.ToString()));
        }
        finally
        {
            foreach (var response in responses) response.Dispose();
        }
    }

    [Fact]
    public async Task RollbackAndSameGenerationForkAreDurablyRejected()
    {
        using var store = RouteStore.Create();
        var first = CanonicalTransportArtifacts.Create(store.Network, 0x50);
        var second = CanonicalTransportArtifacts.Create(store.Network, 0x60);
        store.Publish(store.Locator, 1, first);
        using var source = store.Source();
        _ = await source.ReadAsync(store.Network, store.Locator, default);
        var secondPath = store.Publish(store.Locator, 2, second);
        _ = await source.ReadAsync(store.Network, store.Locator, default);

        store.PointCurrent(store.Locator, 1);
        await Assert.ThrowsAsync<ContactRouteClosurePublicationRejectedException>(async () =>
            await source.ReadAsync(store.Network, store.Locator, default));

        store.PointCurrent(store.Locator, 2);
        store.RewriteGeneration(secondPath,
            CanonicalTransportArtifacts.Create(store.Network, 0x70), 2, store.Locator);
        await Assert.ThrowsAsync<ContactRouteClosurePublicationRejectedException>(async () =>
            await source.ReadAsync(store.Network, store.Locator, default));
        await Assert.ThrowsAsync<ContactRouteClosurePublicationRejectedException>(async () =>
            await source.ReadAsync(store.Network, store.Locator, default));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task TraversalOrDuplicateInventoryIsRejectedBeforeFileAccess(bool traversal)
    {
        using var store = RouteStore.Create();
        var fixture = CanonicalTransportArtifacts.Create(store.Network, 0x78);
        var generation = store.Publish(store.Locator, 1, fixture);
        var manifestPath = Path.Combine(generation, "manifest.json");
        var manifest = FileContactRouteClosureManifestCodec.DecodeCanonical(
            File.ReadAllBytes(manifestPath));
        var entries = manifest.Artifacts.ToArray();
        entries[1] = traversal
            ? entries[1] with { FileName = "../xrr1.bin" }
            : entries[1] with { Role = "xir1", FileName = "xir1.bin" };
        File.WriteAllBytes(manifestPath,
            FileContactRouteClosureManifestCodec.EncodeCanonical(manifest with { Artifacts = entries }));
        using var source = store.Source();

        await Assert.ThrowsAsync<ContactRouteClosurePublicationRejectedException>(async () =>
            await source.ReadAsync(store.Network, store.Locator, default));
    }

    [Fact]
    public async Task ReparseArtifactIsRejectedWherePlatformAllowsCreatingIt()
    {
        using var store = RouteStore.Create();
        var fixture = CanonicalTransportArtifacts.Create(store.Network, 0x7c);
        var generation = store.Publish(store.Locator, 1, fixture);
        var artifactPath = Path.Combine(generation, "xrr1.bin");
        var external = Path.Combine(store.BasePath, "external-xrr1.bin");
        File.WriteAllBytes(external, fixture.Xrr);
        File.Delete(artifactPath);
        try
        {
            File.CreateSymbolicLink(artifactPath, external);
        }
        catch (Exception exception) when (exception is UnauthorizedAccessException or
            IOException or PlatformNotSupportedException)
        {
            return;
        }
        using var source = store.Source();

        await Assert.ThrowsAsync<ContactRouteClosurePublicationRejectedException>(async () =>
            await source.ReadAsync(store.Network, store.Locator, default));
    }

    private static async Task<TestHost> StartAsync(IReadOnlyDictionary<string, string?> values)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = "Testing",
        });
        builder.WebHost.UseTestServer();
        builder.Configuration.AddInMemoryCollection(values);
        var state = builder.Services.AddContactRouteClosureTransport(builder.Configuration);
        var app = builder.Build();
        app.MapContactRouteClosureTransportEndpoint(state);
        await app.StartAsync();
        return new TestHost(app, app.GetTestClient());
    }

    private static HttpRequestMessage Request(byte[] network, byte[] locator) =>
        RawRequest(EncodeRequest(network, locator));

    private static HttpRequestMessage RawRequest(byte[] encoded)
    {
        var request = new HttpRequestMessage(HttpMethod.Post,
            ContactRouteClosureHostingExtensions.EndpointPath)
        {
            Content = new ByteArrayContent(encoded),
        };
        request.Content.Headers.ContentType = MediaTypeHeaderValue.Parse(
            ContactRouteClosureTransportCodec.RequestMediaType);
        return request;
    }

    private static byte[] EncodeRequest(ReadOnlySpan<byte> network, ReadOnlySpan<byte> locator)
    {
        var result = new byte[ContactRouteClosureTransportCodec.RequestBytes];
        BinaryPrimitives.WriteUInt16BigEndian(result, ContactRouteClosureTransportCodec.Version);
        network.CopyTo(result.AsSpan(2));
        locator.CopyTo(result.AsSpan(18));
        return result;
    }

    private static byte[] Bytes(int length, byte value) => Enumerable.Repeat(value, length).ToArray();

    private static string Lower(ReadOnlySpan<byte> value) =>
        Convert.ToHexString(value).ToLowerInvariant();

    private sealed class TestHost(WebApplication app, HttpClient client) : IAsyncDisposable
    {
        internal HttpClient Client { get; } = client;

        public async ValueTask DisposeAsync()
        {
            Client.Dispose();
            await app.DisposeAsync();
        }
    }

    private sealed class RouteStore : IDisposable
    {
        private readonly byte[] key = Bytes(32, 0xa5);

        private RouteStore(string basePath)
        {
            BasePath = basePath;
            Root = Path.Combine(basePath, "readonly");
            State = Path.Combine(basePath, "state");
            KeyPath = Path.Combine(basePath, "integrity.key");
            Network = Bytes(16, 0x11);
            Locator = Bytes(32, 0x22);
            Directory.CreateDirectory(Path.Combine(Root, "publications", Lower(Network)));
            File.WriteAllBytes(KeyPath, key);
        }

        internal string BasePath { get; }
        internal string Root { get; }
        internal string State { get; }
        internal string KeyPath { get; }
        internal byte[] Network { get; }
        internal byte[] Locator { get; }

        internal static RouteStore Create()
        {
            var path = Path.Combine(Path.GetTempPath(), $"deep-route-closure-{Guid.NewGuid():N}");
            Directory.CreateDirectory(path);
            return new RouteStore(path);
        }

        internal Dictionary<string, string?> Configuration() => new()
        {
            ["ContactRouteClosureTransport:ReadOnlyRoot"] = Root,
            ["ContactRouteClosureTransport:StateRoot"] = State,
            ["ContactRouteClosureTransport:IntegrityKeyPath"] = KeyPath,
            ["ContactRouteClosureTransport:NetworkIdHex"] = Lower(Network),
        };

        internal FileContactRouteClosureSource Source() =>
            new(Root, State, Network, key);

        internal string StatePath(byte[] locator)
        {
            var locatorHex = Lower(locator);
            return Path.Combine(State, Lower(Network), locatorHex[..2],
                locatorHex.Substring(2, 2), $"{locatorHex}.state");
        }

        internal string Publish(
            byte[] locator,
            ulong generation,
            CanonicalTransportArtifacts fixture)
        {
            var locatorHex = Lower(locator);
            var publication = Path.Combine(Root, "publications", Lower(Network),
                locatorHex[..2], locatorHex.Substring(2, 2), locatorHex);
            var generationPath = Path.Combine(publication, "generations", generation.ToString("D20"));
            Directory.CreateDirectory(generationPath);
            RewriteGeneration(generationPath, fixture, generation, locator);
            Directory.CreateDirectory(publication);
            PointCurrent(locator, generation);
            return generationPath;
        }

        internal void RewriteGeneration(
            string generationPath,
            CanonicalTransportArtifacts fixture,
            ulong generation,
            byte[] locator)
        {
            var values = new Dictionary<string, byte[]>(StringComparer.Ordinal)
            {
                ["xir1"] = fixture.Xir,
                ["xrr1"] = fixture.Xrr,
                ["xra1"] = fixture.Xra,
                ["xrc1"] = fixture.Xrc,
                ["xss1"] = fixture.Xss,
                ["pmt2"] = fixture.Pmt,
                ["pms2"] = fixture.Pms,
            };
            var entries = values.Select(item =>
            {
                File.WriteAllBytes(Path.Combine(generationPath, $"{item.Key}.bin"), item.Value);
                return new FileContactRouteClosureManifestEntry(
                    item.Key, $"{item.Key}.bin", item.Value.Length,
                    Lower(SHA256.HashData(item.Value)));
            }).ToArray();
            var manifest = new FileContactRouteClosureManifest(
                FileContactRouteClosureManifestCodec.CurrentFormat,
                Lower(Network), Lower(locator), generation, entries);
            File.WriteAllBytes(Path.Combine(generationPath, "manifest.json"),
                FileContactRouteClosureManifestCodec.EncodeCanonical(manifest));
        }

        internal void PointCurrent(byte[] locator, ulong generation)
        {
            var locatorHex = Lower(locator);
            var publication = Path.Combine(Root, "publications", Lower(Network),
                locatorHex[..2], locatorHex.Substring(2, 2), locatorHex);
            Directory.CreateDirectory(publication);
            File.WriteAllBytes(Path.Combine(publication, "current"),
                Encoding.ASCII.GetBytes(generation.ToString("D20")));
        }

        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(key);
            try { Directory.Delete(BasePath, recursive: true); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }

        private static string Lower(ReadOnlySpan<byte> value) =>
            Convert.ToHexString(value).ToLowerInvariant();
    }

    private sealed class CanonicalTransportArtifacts
    {
        private CanonicalTransportArtifacts(
            ContactRecord xir,
            ContactRecord xrr,
            ContactRecord xra,
            ContactRecord xrc,
            ContactRecord xss,
            ContactRecord pmt,
            ContactRecord pms)
        {
            Xir = xir.CanonicalBytes.ToArray();
            Xrr = xrr.CanonicalBytes.ToArray();
            Xra = xra.CanonicalBytes.ToArray();
            Xrc = xrc.CanonicalBytes.ToArray();
            Xss = xss.CanonicalBytes.ToArray();
            Pmt = pmt.CanonicalBytes.ToArray();
            Pms = pms.CanonicalBytes.ToArray();
            Closure = EncodeClosure(Xrr, Xra, Xrc, Xss, Pmt, Pms);
        }

        internal byte[] Xir { get; }
        internal byte[] Xrr { get; }
        internal byte[] Xra { get; }
        internal byte[] Xrc { get; }
        internal byte[] Xss { get; }
        internal byte[] Pmt { get; }
        internal byte[] Pms { get; }
        internal byte[] Closure { get; }

        internal static CanonicalTransportArtifacts Create(
            byte[] network,
            byte seed,
            byte[]? locator = null)
        {
            locator ??= Bytes(32, 0x22);
            var witnessReceipts = Join(
                Join(Bytes(32, 0x01), Bytes(64, 0x81)),
                Join(Bytes(32, 0x02), Bytes(64, 0x82)));
            var nodes = new[] { Bytes(136, 0x20), Bytes(136, 0x40) }
                .OrderBy(static value => value, ByteArrayComparer.Instance).ToArray();
            var pmt = Record("PMT2",
            [
                network, U64(0), new byte[32], Reference("PMA2", Bytes(32, 0xa2)),
                Reference("XNV1", Bytes(32, 0xa3)), U64(40), new byte[] { 2 }, U16(2),
                Join(nodes), U64(20), U64(20), U64(80), Bytes(32, 0xa4),
                Reference("ADH1", Bytes(32, 0xa5)), new byte[] { 2 }, witnessReceipts,
            ]);
            var pmtReference = ContactCodec.ArtifactReference("PMT2", pmt).CanonicalBytes.ToArray();
            var placement = Bytes(32, checked((byte)(seed + 1)));
            var epoch = U64(40);
            var ranked = nodes.Select(static row => row[..32])
                .Select(node => (Node: node, Score: Rendezvous(network, pmtReference, epoch, placement, node)))
                .OrderBy(static value => value.Score, ByteArrayComparer.Instance)
                .ThenBy(static value => value.Node, ByteArrayComparer.Instance)
                .Select(static value => value.Node).ToArray();
            ReadOnlyMemory<byte>[] pmsFields =
            [
                network, pmtReference, placement, epoch, new byte[] { 2 }, Join(ranked),
                new byte[32], U64(20), U64(80), new byte[] { 2 }, witnessReceipts,
            ];
            pmsFields[6] = ContactCodec.Sha256Domain(
                "Deep/XPoint/V1/PMS2/selection", ProjectRaw(Write("PMS2", pmsFields), 6));
            var pms = Record("PMS2", pmsFields);

            var dpd = Reference("DPD1", Bytes(32, 0xb1));
            var dca = Reference("DCA1", Bytes(32, 0xb2));
            var xra = Record("XRA1",
            [
                network, Bytes(32, seed), U64(0), new byte[32], pmtReference,
                placement, U16(1), U32(10), Bytes(32, 0xb3), Bytes(32, 0xb4),
                Bytes(32, 0xb5), U64(20), U64(90), Bytes(32, 0xb6), dpd, Bytes(64, 0xb7),
            ]);
            var replicaEntries = new byte[128];
            for (var index = 0; index < 2; index++)
            {
                ranked[index].CopyTo(replicaEntries, index * 64);
                Bytes(32, checked((byte)(0xc0 + index))).CopyTo(replicaEntries, index * 64 + 32);
            }
            var xrc = Record("XRC1",
            [
                network, Bytes(32, checked((byte)(seed + 2))), U64(0), new byte[32],
                ContactCodec.ArtifactReference("XRA1", xra).CanonicalBytes, pmtReference,
                pms.ArtifactHash, pmt.Field(5), Reference("XNH1", Bytes(32, 0xc2)),
                Bytes(32, 0xc3), xra.Field(10), xra.Field(11), U64(1), new byte[] { 2 },
                replicaEntries, U64(20), U64(20), U64(80), pmt.Field(14),
                new byte[] { 2 }, witnessReceipts,
            ]);
            var xss = Record("XSS1",
            [
                network, xrc.Field(2), U64(1), xrc.CoreHash,
                ContactCodec.ArtifactReference("XRC1", xrc).CanonicalBytes,
                ContactCodec.ArtifactReference("XRC1", xrc).CanonicalBytes,
                pmtReference, pmt.Field(5), pms.ArtifactHash, U64(20), U64(80),
                pmt.Field(14), new byte[] { 2 }, witnessReceipts,
            ]);
            var xrr = Record("XRR1",
            [
                network, Bytes(32, checked((byte)(seed + 3))), U64(0), new byte[32],
                ContactCodec.ArtifactReference("XRA1", xra).CanonicalBytes,
                ContactCodec.ArtifactReference("XRC1", xrc).CanonicalBytes,
                ContactCodec.ArtifactReference("XSS1", xss).CanonicalBytes,
                pmtReference, pms.ArtifactHash, Bytes(32, 0xc4), xra.Field(9),
                new byte[] { 1 }, U32(1), U16(1), U64(20), U64(20), U64(80),
                dpd, Bytes(64, 0xc5), new byte[2],
            ]);
            var xir = Record("XIR1",
            [
                network, locator, U64(0), new byte[32],
                pmtReference, xra.Field(6), xra.Field(10), xra.Field(11), new byte[] { 1 },
                U32(0), U16(2), xra.Field(9), U64(20), U64(90), dpd, dca,
                Bytes(64, 0xc6), ContactCodec.ArtifactReference("XRA1", xra).CanonicalBytes,
            ]);
            return new CanonicalTransportArtifacts(xir, xrr, xra, xrc, xss, pmt, pms);
        }

        private static ContactRecord Record(string magic, IReadOnlyList<ReadOnlyMemory<byte>> fields) =>
            ContactCodecValidation.AuthorRecord(magic, fields);

        private static byte[] EncodeClosure(params byte[][] artifacts)
        {
            var result = new byte[1 + artifacts.Sum(static value => 4 + value.Length)];
            result[0] = checked((byte)artifacts.Length);
            var offset = 1;
            foreach (var artifact in artifacts)
            {
                BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(offset), checked((uint)artifact.Length));
                offset += 4;
                artifact.CopyTo(result, offset);
                offset += artifact.Length;
            }
            return result;
        }

        private static byte[] Rendezvous(
            byte[] network, byte[] pmtReference, byte[] epoch, byte[] placement, byte[] node)
        {
            var domain = Encoding.ASCII.GetBytes("Deep/XPoint/V1/PMS2/rendezvous-sha256/v2");
            return SHA256.HashData(Join(domain, [0], network, pmtReference, epoch, placement, node));
        }

        private static byte[] ProjectRaw(byte[] canonical, int count)
        {
            var end = 12;
            for (var index = 0; index < count; index++)
                end += 8 + checked((int)BinaryPrimitives.ReadUInt32BigEndian(canonical.AsSpan(end + 4)));
            var projection = canonical[..end];
            BinaryPrimitives.WriteUInt16BigEndian(projection.AsSpan(8), checked((ushort)count));
            return projection;
        }

        private static byte[] Reference(string magic, byte[] hash)
        {
            var result = new byte[38];
            Encoding.ASCII.GetBytes(magic).CopyTo(result, 0);
            BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(4), 1);
            hash.CopyTo(result, 6);
            return result;
        }

        private static byte[] Write(string magic, IReadOnlyList<ReadOnlyMemory<byte>> fields)
        {
            var result = new byte[12 + fields.Sum(static value => 8 + value.Length)];
            Encoding.ASCII.GetBytes(magic).CopyTo(result, 0);
            BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(4), 1);
            BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(6), 0x0201);
            BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(8), checked((ushort)fields.Count));
            var offset = 12;
            for (var index = 0; index < fields.Count; index++)
            {
                BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(offset), checked((ushort)(index + 1)));
                BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(offset + 4),
                    checked((uint)fields[index].Length));
                offset += 8;
                fields[index].Span.CopyTo(result.AsSpan(offset));
                offset += fields[index].Length;
            }
            return result;
        }

        private static byte[] U16(ushort value)
        {
            var result = new byte[2];
            BinaryPrimitives.WriteUInt16BigEndian(result, value);
            return result;
        }

        private static byte[] U32(uint value)
        {
            var result = new byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(result, value);
            return result;
        }

        private static byte[] U64(ulong value)
        {
            var result = new byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(result, value);
            return result;
        }

        private static byte[] Bytes(int length, byte value) => Enumerable.Repeat(value, length).ToArray();

        private static byte[] Join(params byte[][] values)
        {
            var result = new byte[values.Sum(static value => value.Length)];
            var offset = 0;
            foreach (var value in values)
            {
                value.CopyTo(result, offset);
                offset += value.Length;
            }
            return result;
        }

        private sealed class ByteArrayComparer : IComparer<byte[]>
        {
            internal static readonly ByteArrayComparer Instance = new();
            public int Compare(byte[]? left, byte[]? right) =>
                (left ?? []).AsSpan().SequenceCompareTo(right ?? []);
        }
    }
}
#endif
