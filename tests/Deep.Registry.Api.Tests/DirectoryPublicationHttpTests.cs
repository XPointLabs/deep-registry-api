using System.Buffers.Binary;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Deep.Registry.Api.DirectoryPublication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Deep.Registry.Api.Tests;

public sealed class DirectoryPublicationHttpTests
{
    [Fact]
    public async Task Default_composition_exposes_no_directory_routes_and_old_package_rejects_write_activation()
    {
        var configuration = new ConfigurationBuilder().Build();
        var services = new ServiceCollection();
        var state = services.AddDirectoryPublication(configuration);
        Assert.False(state.MirrorEnabled);
        Assert.False(state.WriteEnabled);

        await using var app = await StartBareAppAsync(state, services);
        Assert.Equal(HttpStatusCode.NotFound,
            (await Client(app).GetAsync("/api/v1/directory/manifest")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound,
            (await Client(app).PostAsync("/api/v1/directory/publications", null)).StatusCode);

        using (var directory = new TemporaryDirectory())
        {
            var mirrorConfiguration = new ConfigurationBuilder().AddInMemoryCollection(
                new Dictionary<string, string?>
                {
                    ["DirectoryPublication:MirrorEnabled"] = "true",
                    ["DirectoryPublication:StatePath"] = directory.CatalogPath,
                    ["DirectoryPublication:NetworkIdHex"] = Convert.ToHexString(Bytes(20, 16))
                }).Build();
            var mirrorServices = new ServiceCollection();
            var mirrorState = mirrorServices.AddDirectoryPublication(mirrorConfiguration);
            Assert.True(mirrorState.MirrorEnabled);
            Assert.False(mirrorState.WriteEnabled);
            using var provider = mirrorServices.BuildServiceProvider();
            Assert.NotNull(provider.GetRequiredService<DirectoryPublicationCatalog>());
        }

        if (!ProductionDirectoryCanonicalPublicationVerifier.HasRequiredProtocolSurface)
        {
            using var directory = new TemporaryDirectory();
            var enabled = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["DirectoryPublication:MirrorEnabled"] = "true",
                ["DirectoryPublication:WriteEnabled"] = "true",
                ["DirectoryPublication:StatePath"] = Path.Combine(directory.Path, "catalog.bin"),
                ["DirectoryPublication:NetworkIdHex"] = Convert.ToHexString(Bytes(1, 16))
            }).Build();
            var exception = Assert.Throws<InvalidOperationException>(() =>
                new ServiceCollection().AddDirectoryPublication(enabled));
            Assert.Contains("fail-closed", exception.Message, StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task Mirror_returns_byte_identical_immutable_generation_manifest_and_head_with_cache_contracts()
    {
        using var directory = new TemporaryDirectory();
        var network = Bytes(2, 16);
        var verifier = new ConsumingSyntheticVerifier(network);
        var catalog = new DirectoryPublicationCatalog(directory.CatalogPath, network, verifier);
        var fixture = Fixture(network, 1, Challenge());
        await catalog.PublishAsync(fixture.Candidate(), DirectoryCatalogAnchor.Empty);

        await using var app = await StartAppAsync(
            catalog, new ControlledClock(fixture.Ticket.BootId.ToArray(), 100),
            new NullChallengeIssuer(), new AllowAuthorizer(), writeEnabled: false);
        var client = Client(app);

        var manifest = await client.GetAsync("/api/v1/directory/manifest");
        Assert.Equal(HttpStatusCode.OK, manifest.StatusCode);
        Assert.Equal(catalog.GetManifestArtifact().Bytes.ToArray(), await manifest.Content.ReadAsByteArrayAsync());
        Assert.Contains("no-store", manifest.Headers.CacheControl!.ToString(), StringComparison.Ordinal);

        var generation = await client.GetAsync("/api/v1/directory/generations/1");
        Assert.Equal(catalog.GetGenerationArtifact(1)!.Bytes.ToArray(), await generation.Content.ReadAsByteArrayAsync());
        Assert.True(generation.Headers.CacheControl!.Public);
        Assert.Contains("immutable", generation.Headers.CacheControl.Extensions.Select(value => value.Name));
        Assert.NotNull(generation.Headers.ETag);

        using var conditional = new HttpRequestMessage(HttpMethod.Get, "/api/v1/directory/generations/1");
        conditional.Headers.IfNoneMatch.Add(generation.Headers.ETag!);
        Assert.Equal(HttpStatusCode.NotModified, (await client.SendAsync(conditional)).StatusCode);

        var head = await client.GetAsync("/api/v1/directory/head");
        Assert.Equal(fixture.Head, await head.Content.ReadAsByteArrayAsync());
        Assert.Contains("no-store", head.Headers.CacheControl!.ToString(), StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.NotFound,
            (await client.PostAsync("/api/v1/directory/publications", null)).StatusCode);
    }

    [Fact]
    public async Task Write_requires_authenticated_publisher_before_body_or_verifier()
    {
        using var directory = new TemporaryDirectory();
        var network = Bytes(3, 16);
        var verifier = new ConsumingSyntheticVerifier(network);
        var catalog = new DirectoryPublicationCatalog(directory.CatalogPath, network, verifier);
        var clock = new ControlledClock(Bytes(4, 16), 100);
        await using var app = await StartAppAsync(
            catalog, clock, new NullChallengeIssuer(), new DenyAuthorizer(), writeEnabled: true);

        var response = await Client(app).PostAsync(
            "/api/v1/directory/publications",
            new ByteArrayContent(new byte[1]));
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(0, verifier.Calls);
        Assert.Null(catalog.GetCurrent());
    }

    [Fact]
    public async Task Malformed_and_max_plus_one_artifacts_fail_before_verifier_or_commit()
    {
        using var directory = new TemporaryDirectory();
        var network = Bytes(5, 16);
        var verifier = new ConsumingSyntheticVerifier(network);
        var catalog = new DirectoryPublicationCatalog(directory.CatalogPath, network, verifier);
        var clock = new ControlledClock(Bytes(6, 16), 100);
        await using var app = await StartAppAsync(
            catalog, clock, new NullChallengeIssuer(), new AllowAuthorizer(), writeEnabled: true);
        var client = Client(app);

        var malformed = await client.PostAsync("/api/v1/directory/publications", Content([1, 2, 3]));
        Assert.Equal(HttpStatusCode.BadRequest, malformed.StatusCode);

        var tooLarge = await client.PostAsync(
            "/api/v1/directory/publications",
            Content(MaxPlusOneEnvelope()));
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, tooLarge.StatusCode);
        Assert.Equal(0, verifier.Calls);
        Assert.Null(catalog.GetCurrent());
    }

    [Fact]
    public async Task Verifier_rejection_occurs_before_catalog_commit_and_is_sanitized()
    {
        using var directory = new TemporaryDirectory();
        var network = Bytes(7, 16);
        var verifier = new ConsumingSyntheticVerifier(network, reject: true);
        var catalog = new DirectoryPublicationCatalog(directory.CatalogPath, network, verifier);
        var ticket = Challenge();
        var clock = new ControlledClock(ticket.BootId.ToArray(), 100);
        await using var app = await StartAppAsync(
            catalog, clock, new NullChallengeIssuer(), new AllowAuthorizer(), writeEnabled: true);

        var response = await Client(app).PostAsync(
            "/api/v1/directory/publications",
            Content(Fixture(network, 1, ticket).Envelope));
        Assert.Equal(HttpStatusCode.UnprocessableEntity, response.StatusCode);
        var json = await response.Content.ReadAsStringAsync();
        Assert.Contains("canonical-publication-rejected", json, StringComparison.Ordinal);
        Assert.DoesNotContain("synthetic hostile detail", json, StringComparison.Ordinal);
        Assert.Equal(1, verifier.Calls);
        Assert.Null(catalog.GetCurrent());
    }

    [Fact]
    public async Task Consumed_challenge_remains_replay_protected_after_restart()
    {
        using var directory = new TemporaryDirectory();
        var network = Bytes(8, 16);
        var key = Bytes(9, 32);
        var clock = new ControlledClock(Bytes(10, 16), 100);
        var first = new DurableDirectoryPublicationChallengeLedger(
            directory.ChallengePath, network, key, clock);
        var ticket = await first.IssueAsync(default);

        var restarted = new DurableDirectoryPublicationChallengeLedger(
            directory.ChallengePath, network, key, clock);
        await restarted.VerifyAndConsumeAsync(
            ticket.Nonce, ticket.BootId, ticket.CreatedAtMonotonicSeconds, 100, 100, default);

        var restartedAgain = new DurableDirectoryPublicationChallengeLedger(
            directory.ChallengePath, network, key, clock);
        await Assert.ThrowsAsync<CryptographicException>(() => restartedAgain.VerifyAndConsumeAsync(
            ticket.Nonce, ticket.BootId, ticket.CreatedAtMonotonicSeconds, 100, 100, default).AsTask());
    }

    [Fact]
    public async Task Concurrent_same_challenge_publish_has_one_commit_and_one_fail_closed_replay()
    {
        using var directory = new TemporaryDirectory();
        var network = Bytes(11, 16);
        var key = Bytes(12, 32);
        var clock = new ControlledClock(Bytes(13, 16), 100);
        var ledger = new DurableDirectoryPublicationChallengeLedger(
            directory.ChallengePath, network, key, clock);
        var ticket = await ledger.IssueAsync(default);
        var verifier = new ConsumingSyntheticVerifier(network, challengeAuthority: ledger);
        var catalog = new DirectoryPublicationCatalog(directory.CatalogPath, network, verifier);
        await using var app = await StartAppAsync(
            catalog, clock, ledger, new AllowAuthorizer(), writeEnabled: true);
        var envelope = Fixture(network, 1, ticket).Envelope;
        var client = Client(app);

        var responses = await Task.WhenAll(
            client.PostAsync("/api/v1/directory/publications", Content(envelope)),
            client.PostAsync("/api/v1/directory/publications", Content(envelope)));
        Assert.Single(responses, response => response.StatusCode == HttpStatusCode.Created);
        Assert.Single(responses, response => response.StatusCode == HttpStatusCode.UnprocessableEntity);
        Assert.Equal((ulong)1, catalog.GetCurrent()!.Generation);
        Assert.Equal(2, verifier.Calls);
    }

    [Fact]
    public async Task Challenge_endpoint_is_authenticated_and_issued_ticket_survives_ledger_reopen()
    {
        using var directory = new TemporaryDirectory();
        var network = Bytes(14, 16);
        var key = Bytes(15, 32);
        var clock = new ControlledClock(Bytes(16, 16), 200);
        var ledger = new DurableDirectoryPublicationChallengeLedger(
            directory.ChallengePath, network, key, clock);
        var catalog = new DirectoryPublicationCatalog(
            directory.CatalogPath, network, new ConsumingSyntheticVerifier(network));
        await using var denied = await StartAppAsync(
            catalog, clock, ledger, new DenyAuthorizer(), writeEnabled: true);
        Assert.Equal(HttpStatusCode.Unauthorized,
            (await Client(denied).PostAsync(
                "/api/v1/directory/publication-challenges", null)).StatusCode);

        await using var allowed = await StartAppAsync(
            catalog, clock, ledger, new AllowAuthorizer(), writeEnabled: true);
        var response = await Client(allowed).PostAsync(
            "/api/v1/directory/publication-challenges", null);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var nonce = Convert.FromBase64String(json.RootElement.GetProperty("nonceBase64").GetString()!);
        var boot = Convert.FromBase64String(json.RootElement.GetProperty("bootIdBase64").GetString()!);
        var created = json.RootElement.GetProperty("createdAtMonotonicSeconds").GetUInt64();
        var reopened = new DurableDirectoryPublicationChallengeLedger(
            directory.ChallengePath, network, key, clock);
        await reopened.VerifyAndConsumeAsync(nonce, boot, created, 200, 200, default);
    }

    [Fact]
    public async Task Protected_lkg_source_authenticates_independent_bounded_state_and_network()
    {
        using var directory = new TemporaryDirectory();
        var network = Bytes(21, 16);
        var key = Bytes(22, 32);
        var encoded = ProtectedLkg(network, key);
        File.WriteAllBytes(directory.LkgPath, encoded);
        var source = new ProtectedFileDirectoryPublicationNetworkLkgSource(directory.LkgPath, key);

        var value = await source.ReadAsync(network, default);
        Assert.NotNull(value);
        Assert.Equal((ulong)7, value!.ViewGeneration);
        await Assert.ThrowsAsync<CryptographicException>(() =>
            source.ReadAsync(Bytes(23, 16), default).AsTask());

        encoded[40] ^= 0x80;
        File.WriteAllBytes(directory.LkgPath, encoded);
        await Assert.ThrowsAsync<CryptographicException>(() =>
            source.ReadAsync(network, default).AsTask());
    }

    private static async Task<WebApplication> StartBareAppAsync(
        DirectoryPublicationHostingState state,
        IServiceCollection configuredServices)
    {
        var builder = WebApplication.CreateBuilder();
        builder.Environment.EnvironmentName = "Development";
        builder.WebHost.UseTestServer();
        foreach (var service in configuredServices) builder.Services.Add(service);
        var app = builder.Build();
        app.MapDirectoryPublicationEndpoints(state);
        await app.StartAsync();
        return app;
    }

    private static async Task<WebApplication> StartAppAsync(
        DirectoryPublicationCatalog catalog,
        IDirectoryPublicationMonotonicClock clock,
        IDirectoryPublicationChallengeIssuer issuer,
        IDirectoryPublicationPublisherAuthorizer authorizer,
        bool writeEnabled)
    {
        var builder = WebApplication.CreateBuilder();
        builder.Environment.EnvironmentName = "Development";
        builder.WebHost.UseTestServer();
        builder.Services.AddSingleton(catalog);
        builder.Services.AddSingleton(clock);
        builder.Services.AddSingleton(issuer);
        builder.Services.AddSingleton(authorizer);
        var app = builder.Build();
        app.MapDirectoryPublicationEndpoints(new DirectoryPublicationHostingState(true, writeEnabled));
        await app.StartAsync();
        return app;
    }

    private static ByteArrayContent Content(byte[] bytes)
    {
        var content = new ByteArrayContent(bytes);
        content.Headers.ContentType = MediaTypeHeaderValue.Parse(
            DirectoryPublicationWriteEnvelopeCodec.MediaType);
        return content;
    }

    private static HttpClient Client(WebApplication app)
    {
        var client = app.GetTestClient();
        client.BaseAddress = new Uri("https://localhost");
        return client;
    }

    private static FixtureData Fixture(
        byte[] network,
        ulong generation,
        DirectoryPublicationChallengeTicket ticket)
    {
        var view = Artifact("XNV1", network, generation, 1);
        var head = Artifact("XNH1", network, generation, 2);
        var mailbox = Artifact("PMT2", network, generation, 3);
        var authority = Artifact("XNA1", network, generation, 4);
        var time = Artifact("DTS1", network, generation, 5);
        var policy = Artifact("XVP1", network, generation, 6);
        var nodes = new[]
        {
            Artifact("XND1", network, generation, 7),
            Artifact("XND1", network, generation, 8),
            Artifact("XND1", network, generation, 9)
        };
        var adh = Artifact("ADH1", network, generation, 10);
        var dtt = Artifact("DTT1", network, generation, 11);
        var adp = Artifact("ADP1", network, generation, 12);
        var envelope = EncodeEnvelope(
            ticket, [authority], [time], [policy], [view], [head], nodes, [mailbox],
            [], [], adh, dtt, adp, view, head, mailbox, [], []);
        var closure = new DirectoryPublicationVerificationClosure(
            [authority], [time], [policy], [view], [head],
            nodes.Select(static value => (ReadOnlyMemory<byte>)value).ToArray(), [mailbox],
            adh, dtt, adp, ticket.Nonce.Span, Bytes(17, 32), ticket.BootId.Span,
            ticket.CreatedAtMonotonicSeconds, ticket.CreatedAtMonotonicSeconds,
            ticket.CreatedAtMonotonicSeconds, 1);
        return new FixtureData(
            ticket, envelope, head,
            () => new DirectoryPublicationCandidate(view, head, mailbox, closure));
    }

    private static byte[] EncodeEnvelope(
        DirectoryPublicationChallengeTicket ticket,
        IReadOnlyList<byte[]> authority,
        IReadOnlyList<byte[]> time,
        IReadOnlyList<byte[]> policy,
        IReadOnlyList<byte[]> views,
        IReadOnlyList<byte[]> heads,
        IReadOnlyList<byte[]> nodes,
        IReadOnlyList<byte[]> mailbox,
        IReadOnlyList<byte[]> resetAuthority,
        IReadOnlyList<byte[]> forward,
        byte[] adh,
        byte[] dtt,
        byte[] adp,
        byte[] currentView,
        byte[] currentHead,
        byte[] currentMailbox,
        byte[] xnf,
        byte[] nfp)
    {
        using var stream = new MemoryStream();
        stream.Write("DPW1"u8);
        WriteUInt16(stream, 1);
        stream.WriteByte(0);
        stream.Write(ticket.Nonce.Span);
        stream.Write(ticket.BootId.Span);
        WriteUInt64(stream, ticket.CreatedAtMonotonicSeconds);
        WriteUInt16(stream, 1);
        stream.Write(Bytes(17, 32));
        foreach (var chain in new[] { authority, time, policy, views, heads, nodes, mailbox, resetAuthority, forward })
            WriteChain(stream, chain);
        foreach (var artifact in new[] { adh, dtt, adp, currentView, currentHead, currentMailbox, xnf, nfp })
            WriteArtifact(stream, artifact);
        return stream.ToArray();
    }

    private static byte[] MaxPlusOneEnvelope()
    {
        using var stream = new MemoryStream();
        stream.Write("DPW1"u8);
        WriteUInt16(stream, 1);
        stream.WriteByte(0);
        stream.Write(Bytes(1, 32));
        stream.Write(Bytes(2, 16));
        WriteUInt64(stream, 1);
        WriteUInt16(stream, 1);
        stream.Write(Bytes(3, 32));
        for (var index = 0; index < 9; index++) WriteUInt16(stream, 0);
        WriteUInt32(stream, DirectoryCatalogLimits.AbsoluteMaximumArtifactBytes + 1u);
        return stream.ToArray();
    }

    private static byte[] ProtectedLkg(byte[] network, byte[] key)
    {
        var payload = new byte[185];
        "DPL1"u8.CopyTo(payload);
        BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(4), 1);
        network.CopyTo(payload, 6);
        CoreReference("XNH1", 1).CopyTo(payload, 22);
        BinaryPrimitives.WriteUInt64BigEndian(payload.AsSpan(60), 9);
        Bytes(24, 32).CopyTo(payload, 68);
        CoreReference("XNV1", 2).CopyTo(payload, 100);
        BinaryPrimitives.WriteUInt64BigEndian(payload.AsSpan(138), 7);
        CoreReference("XNA1", 3).CopyTo(payload, 146);
        payload[184] = 0;
        var encoded = new byte[payload.Length + 32];
        payload.CopyTo(encoded, 0);
        HMACSHA256.HashData(key, payload, encoded.AsSpan(payload.Length));
        return encoded;
    }

    private static byte[] CoreReference(string magic, byte marker)
    {
        var result = new byte[38];
        Encoding.ASCII.GetBytes(magic).CopyTo(result, 0);
        result[5] = 1;
        result.AsSpan(6).Fill(marker);
        return result;
    }

    private static void WriteChain(Stream stream, IReadOnlyList<byte[]> values)
    {
        WriteUInt16(stream, checked((ushort)values.Count));
        foreach (var value in values) WriteArtifact(stream, value);
    }

    private static void WriteArtifact(Stream stream, byte[] value)
    {
        WriteUInt32(stream, checked((uint)value.Length));
        stream.Write(value);
    }

    private static void WriteUInt16(Stream stream, ushort value)
    {
        Span<byte> bytes = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(bytes, value);
        stream.Write(bytes);
    }

    private static void WriteUInt32(Stream stream, uint value)
    {
        Span<byte> bytes = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, value);
        stream.Write(bytes);
    }

    private static void WriteUInt64(Stream stream, ulong value)
    {
        Span<byte> bytes = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(bytes, value);
        stream.Write(bytes);
    }

    private static DirectoryPublicationChallengeTicket Challenge() =>
        new(Bytes(18, 32), Bytes(19, 16), 100);

    private static byte[] Artifact(string magic, byte[] network, ulong generation, byte marker)
    {
        var output = new byte[29];
        Encoding.ASCII.GetBytes(magic).CopyTo(output, 0);
        network.CopyTo(output, 4);
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(20), generation);
        output[28] = marker;
        return output;
    }

    private static byte[] Bytes(byte value, int count) =>
        Enumerable.Repeat(value, count).ToArray();

    private sealed record FixtureData(
        DirectoryPublicationChallengeTicket Ticket,
        byte[] Envelope,
        byte[] Head,
        Func<DirectoryPublicationCandidate> Candidate);

    private sealed class ControlledClock(byte[] bootId, ulong sample) : IDirectoryPublicationMonotonicClock
    {
        public ValueTask<DirectoryPublicationMonotonicReading> ReadAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(new DirectoryPublicationMonotonicReading(bootId, sample));
        }
    }

    private sealed class ConsumingSyntheticVerifier(
        byte[] network,
        bool reject = false,
        IDirectoryPublicationLiveChallengeAuthority? challengeAuthority = null)
        : IDirectoryCanonicalPublicationVerifier
    {
        private int calls;
        internal int Calls => Volatile.Read(ref calls);

        public async ValueTask<VerifiedDirectoryPublication> VerifyAsync(
            FrozenDirectoryPublicationCandidate candidate,
            CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref calls);
            if (reject) throw new FormatException("synthetic hostile detail");
            var closure = candidate.VerificationClosure;
            if (challengeAuthority is not null)
            {
                await challengeAuthority.VerifyAndConsumeAsync(
                    closure.CallerNonce, closure.MonotonicBootId,
                    closure.NonceCreatedAtMonotonicSeconds,
                    closure.ResponseReceivedAtMonotonicSeconds,
                    closure.CurrentMonotonicSeconds,
                    cancellationToken);
            }
            var artifacts = candidate.Artifacts().Select(value => new VerifiedDirectoryArtifact(
                value.Kind, value.Bytes.Span, SHA256.HashData(value.Bytes.Span))).ToArray();
            var generation = BinaryPrimitives.ReadUInt64BigEndian(
                candidate.CurrentNetworkView.Span.Slice(20, 8));
            return new VerifiedDirectoryPublication(
                network,
                generation,
                new DirectoryPublicationRetentionAuthority(
                    1_000 + generation,
                    SHA256.HashData(candidate.CurrentNetworkView.Span)),
                artifacts[0], artifacts[1], artifacts[2],
                artifacts.Length == 5 ? artifacts[3] : null,
                artifacts.Length == 5 ? artifacts[4] : null);
        }
    }

    private sealed class AllowAuthorizer : IDirectoryPublicationPublisherAuthorizer
    {
        public ValueTask<bool> IsAuthorizedAsync(HttpContext context, CancellationToken cancellationToken) =>
            ValueTask.FromResult(true);
    }

    private sealed class DenyAuthorizer : IDirectoryPublicationPublisherAuthorizer
    {
        public ValueTask<bool> IsAuthorizedAsync(HttpContext context, CancellationToken cancellationToken) =>
            ValueTask.FromResult(false);
    }

    private sealed class NullChallengeIssuer : IDirectoryPublicationChallengeIssuer
    {
        public ValueTask<DirectoryPublicationChallengeTicket> IssueAsync(CancellationToken cancellationToken) =>
            ValueTask.FromException<DirectoryPublicationChallengeTicket>(new InvalidOperationException());
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        internal TemporaryDirectory()
        {
            Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "deep-directory-http-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Path);
        }
        internal string Path { get; }
        internal string CatalogPath => System.IO.Path.Combine(Path, "catalog.bin");
        internal string ChallengePath => System.IO.Path.Combine(Path, "challenges.bin");
        internal string LkgPath => System.IO.Path.Combine(Path, "network-lkg.bin");
        public void Dispose() => Directory.Delete(Path, recursive: true);
    }
}
