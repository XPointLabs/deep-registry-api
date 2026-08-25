using System.Globalization;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using Deep.Registry.Api.Tests.Fixtures;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Sodium;

namespace Deep.Registry.Api.Tests;

public sealed class CallEndpointsTests
{
    [Fact]
    public async Task MissingCallConfigurationFailsReadinessClosed()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/health/ready");

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
    }

    [Fact]
    public async Task CallEndpointsRejectMissingAuthenticationWith401()
    {
        var statePath = TemporaryStatePath();
        try
        {
            var now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
            var identity = CreateIdentity();
            await using var factory = Factory(statePath, now, includeSecret: true);
            using var client = factory.CreateClient();
            var unsigned = new CallSignalRequest(
                "call-unauthorized",
                identity.SessionId,
                new CallParty(identity.SessionId),
                new CallParty(identity.SessionId),
                CallSignalType.Offer,
                "sealed-v1:AAAA",
                now,
                Convert.ToHexStringLower(identity.Keys.PublicKey),
                null,
                Nonce(1));

            var signal = await client.PostAsJsonAsync("/api/calls/signal", unsigned);
            var inbox = await client.GetAsync($"/api/calls/inbox/{identity.SessionId}");
            var ice = await client.GetAsync($"/api/calls/ice-servers/{identity.SessionId}");

            Assert.Equal(HttpStatusCode.Unauthorized, signal.StatusCode);
            Assert.Equal(HttpStatusCode.Unauthorized, inbox.StatusCode);
            Assert.Equal(HttpStatusCode.Unauthorized, ice.StatusCode);
        }
        finally
        {
            DeleteState(statePath);
        }
    }

    [Fact]
    public async Task IceRequestReplayReturns409()
    {
        var statePath = TemporaryStatePath();
        try
        {
            var now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
            var identity = CreateIdentity();
            await using var factory = Factory(statePath, now, includeSecret: true);
            using var client = factory.CreateClient();
            using var first = SignedGet(identity, now, "ice-servers", CallSignalStore.IcePurpose, Nonce(2));
            using var replay = SignedGet(identity, now, "ice-servers", CallSignalStore.IcePurpose, Nonce(2));

            var accepted = await client.SendAsync(first);
            var rejected = await client.SendAsync(replay);

            Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
            Assert.Equal(HttpStatusCode.Conflict, rejected.StatusCode);
        }
        finally
        {
            DeleteState(statePath);
        }
    }

    [Fact]
    public async Task RequiredIncompleteCallConfigurationFailsReadinessClosed()
    {
        var statePath = TemporaryStatePath();
        try
        {
            await using var factory = Factory(
                statePath,
                DateTimeOffset.FromUnixTimeSeconds(1_800_000_000),
                includeSecret: false);
            using var client = factory.CreateClient();

            var response = await client.GetAsync("/health/ready");

            Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        }
        finally
        {
            DeleteState(statePath);
        }
    }

    private static WebApplicationFactory<Program> Factory(
        string statePath,
        DateTimeOffset now,
        bool includeSecret) =>
        new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.ConfigureAppConfiguration((_, configuration) =>
            {
                var values = new Dictionary<string, string?>
                {
                    ["Calls:Enabled"] = "true",
                    ["Calls:Required"] = "true",
                    ["Calls:StatePath"] = statePath,
                    ["Calls:CredentialLifetimeSeconds"] = "300",
                    ["Calls:IceUrls:0"] = "turn:registry.example:3478?transport=udp"
                };
                if (includeSecret)
                {
                    values["Calls:TurnSharedSecret"] = "integration-test-only-secret";
                }

                configuration.AddInMemoryCollection(values);
            });
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<TimeProvider>();
                services.AddSingleton<TimeProvider>(new ManualTimeProvider(now));
            });
        });

    private static HttpRequestMessage SignedGet(
        (KeyPair Keys, string SessionId) identity,
        DateTimeOffset now,
        string route,
        string purpose,
        string nonce)
    {
        var timestamp = now.ToUnixTimeSeconds();
        var path = $"/api/calls/{route}/{identity.SessionId}";
        var payload = Encoding.UTF8.GetBytes(
            $"{purpose}\nGET\n{path}\n{identity.SessionId}\n{timestamp}\n{nonce}");
        var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.TryAddWithoutValidation(
            "X-Deep-Ed25519",
            Convert.ToHexStringLower(identity.Keys.PublicKey));
        request.Headers.TryAddWithoutValidation(
            "X-Deep-Timestamp",
            timestamp.ToString(CultureInfo.InvariantCulture));
        request.Headers.TryAddWithoutValidation(CallSignalStore.NonceHeader, nonce);
        request.Headers.TryAddWithoutValidation(
            "X-Deep-Signature",
            Convert.ToBase64String(PublicKeyAuth.SignDetached(payload, identity.Keys.PrivateKey)));
        return request;
    }

    private static (KeyPair Keys, string SessionId) CreateIdentity()
    {
        var keys = PublicKeyAuth.GenerateKeyPair();
        var x25519 = PublicKeyAuth.ConvertEd25519PublicKeyToCurve25519PublicKey(keys.PublicKey);
        return (keys, "05" + Convert.ToHexStringLower(x25519));
    }

    private static string Nonce(int value) => value.ToString("x32", CultureInfo.InvariantCulture);

    private static string TemporaryStatePath() =>
        Path.Combine(Path.GetTempPath(), $"deep-call-api-{Guid.NewGuid():N}.json");

    private static void DeleteState(string path)
    {
        foreach (var candidate in Directory.GetFiles(
                     Path.GetDirectoryName(path)!,
                     Path.GetFileName(path) + "*"))
        {
            File.Delete(candidate);
        }
    }
}
