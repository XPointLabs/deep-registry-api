using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Deep.Protocol.DeepExtension.Membership;
using Deep.Registry.Api.Tests.Fixtures;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Deep.Registry.Api.Tests;

public sealed class MembershipProjectionApiTests
{
    [Fact]
    public async Task DefaultDisabled_HasNoMutationOrMembershipEndpoints()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var bridge = await client.GetAsync("/api/v1/checkpoints/bridge");
        var ready = await client.GetAsync("/health/ready");
        var mutation = await client.PostAsJsonAsync(
            "/api/v1/checkpoints/bridge",
            new { value = "fixture" });
        var membership = await client.GetAsync("/api/v1/checkpoints/membership");

        Assert.Equal(HttpStatusCode.ServiceUnavailable, bridge.StatusCode);
        Assert.Equal("disabled", (await bridge.Content.ReadFromJsonAsync<JsonElement>())
            .GetProperty("code").GetString());
        Assert.Equal(HttpStatusCode.OK, ready.StatusCode);
        Assert.Equal(HttpStatusCode.MethodNotAllowed, mutation.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, membership.StatusCode);
    }

    [Fact]
    public async Task AcceptedBridge_IsByteIdenticalVersionedAndConditional()
    {
        var fixture = new P04ProjectionFixture();
        var statePath = Path.Combine(
            Path.GetTempPath(),
            $"p06-api-{Guid.NewGuid():N}.json");
        try
        {
            await using var factory = EnabledFactory(fixture, statePath);
            var service = factory.Services.GetRequiredService<MembershipProjectionService>();
            fixture.SeedAuthority(service);
            var expected = fixture.Bridge();
            var applied = service.ApplyBridge(expected);
            Assert.True(applied.Success, applied.Code.ToString());
            using var client = factory.CreateClient();

            var response = await client.GetAsync("/api/v1/checkpoints/bridge");
            var responseBytes = await response.Content.ReadAsByteArrayAsync();

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(MembershipProjectionEndpoints.BridgeContentType, response.Content.Headers.ContentType?.MediaType);
            Assert.Equal(expected, responseBytes);
            Assert.NotNull(response.Headers.ETag);
            Assert.True(response.Headers.CacheControl?.Private);
            Assert.True(response.Headers.CacheControl?.NoStore);
            Assert.True(response.Headers.CacheControl?.MustRevalidate);
            Assert.Equal(TimeSpan.Zero, response.Headers.CacheControl?.MaxAge);

            using var conditional = new HttpRequestMessage(
                HttpMethod.Get,
                "/api/v1/checkpoints/bridge");
            conditional.Headers.IfNoneMatch.Add(response.Headers.ETag);
            var notModified = await client.SendAsync(conditional);
            Assert.Equal(HttpStatusCode.NotModified, notModified.StatusCode);
            Assert.Empty(await notModified.Content.ReadAsByteArrayAsync());

            using var wildcard = new HttpRequestMessage(HttpMethod.Get, "/api/v1/checkpoints/bridge");
            wildcard.Headers.TryAddWithoutValidation("If-None-Match", "*");
            Assert.Equal(
                HttpStatusCode.NotModified,
                (await client.SendAsync(wildcard)).StatusCode);

            using var weak = new HttpRequestMessage(HttpMethod.Get, "/api/v1/checkpoints/bridge");
            weak.Headers.TryAddWithoutValidation(
                "If-None-Match",
                $"\"other\", W/{response.Headers.ETag}");
            Assert.Equal(
                HttpStatusCode.NotModified,
                (await client.SendAsync(weak)).StatusCode);
        }
        finally
        {
            DeleteStateFiles(statePath);
        }
    }

    [Fact]
    public async Task StatusAndProblemResponses_DoNotLeakContactsOrTopology()
    {
        var fixture = new P04ProjectionFixture();
        var statePath = Path.Combine(
            Path.GetTempPath(),
            $"p06-privacy-{Guid.NewGuid():N}.json");
        try
        {
            await using var factory = EnabledFactory(fixture, statePath);
            var service = factory.Services.GetRequiredService<MembershipProjectionService>();
            fixture.SeedAuthority(service);
            var applied = service.ApplyBridge(fixture.Bridge());
            Assert.True(applied.Success, applied.Code.ToString());
            using var client = factory.CreateClient();

            var status = await client.GetStringAsync("/api/v1/checkpoints/status");

            Assert.DoesNotContain("bridge.example", status, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("entryContacts", status, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("signerId", status, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("statePath", status, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("nodeId", status, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("operator", status, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("membershipSequence", status, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("membershipSha256", status, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            DeleteStateFiles(statePath);
        }
    }

    private static WebApplicationFactory<Program> EnabledFactory(
        P04ProjectionFixture fixture,
        string statePath) =>
        new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.ConfigureAppConfiguration((_, configuration) =>
            {
                configuration.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["MembershipProjection:Enabled"] = "true",
                    ["MembershipProjection:StatePath"] = statePath,
                    ["MembershipProjection:ExpectedNetworkIdHex"] =
                        Convert.ToHexString(fixture.Genesis.NetworkId.Span).ToLowerInvariant(),
                    ["MembershipProjection:ExpectedGenesisSha256Hex"] =
                        Convert.ToHexString(fixture.GenesisHash).ToLowerInvariant(),
                    ["MembershipProjection:AllowedClockSkewSeconds"] = "30",
                    ["MembershipProjection:ClientProtocol"] = "2"
                });
            });
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<TimeProvider>();
                services.AddSingleton<TimeProvider>(fixture.Time);
                services.AddSingleton<IMembershipSignatureVerifier>(fixture.Verifier);
                services.AddSingleton<IMembershipProjectionMonotonicAnchor>(
                    new MemoryMonotonicAnchor());
            });
        });

    private static void DeleteStateFiles(string statePath)
    {
        var directory = Path.GetDirectoryName(statePath)!;
        var prefix = Path.GetFileName(statePath);
        foreach (var file in Directory.GetFiles(directory, $"{prefix}*"))
        {
            File.Delete(file);
        }
    }
}
