using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Rebex.Security.Cryptography;

namespace Deep.Registry.Api.Tests;

public sealed class RegistryApiTests
{
    [Fact]
    public async Task MembershipRouteArtifact_IsOpaqueAndFailsClosedWhenUnconfigured()
    {
        await using var unconfigured = new WebApplicationFactory<Program>();
        using var unconfiguredClient = unconfigured.CreateClient();
        Assert.Equal(
            HttpStatusCode.ServiceUnavailable,
            (await unconfiguredClient.GetAsync("/api/network/membership-route-catalog")).StatusCode);

        var directory = Path.Combine(
            Path.GetTempPath(),
            "registry-membership-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "catalog.bin");
        var expected = Enumerable.Range(0, 256).Select(static value => (byte)value).ToArray();
        try
        {
            await File.WriteAllBytesAsync(path, expected);
            await using var configured = unconfigured.WithWebHostBuilder(builder =>
                builder.ConfigureAppConfiguration((_, configuration) =>
                    configuration.AddInMemoryCollection(new Dictionary<string, string?>
                    {
                        ["Registry:MembershipRouteArtifactPath"] = path,
                        ["Registry:MembershipRouteArtifactMaximumBytes"] = expected.Length.ToString()
                    })));
            using var configuredClient = configured.CreateClient();
            var response = await configuredClient.GetAsync("/api/network/membership-route-catalog");

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(
                "application/vnd.deep.membership-route-catalog",
                response.Content.Headers.ContentType?.MediaType);
            Assert.Equal(expected, await response.Content.ReadAsByteArrayAsync());
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task RelayCatalog_RequiresFreshRegisteredNodeSignature_AndRejectsReplay()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var scope = factory.Services.CreateScope();
        var registry = scope.ServiceProvider.GetRequiredService<NodeRegistry>();
        var seed = Enumerable.Range(1, 32).Select(static value => (byte)value).ToArray();
        var signer = new Ed25519();
        signer.FromSeed(seed);
        var nodeId = Convert.ToHexString(signer.GetPublicKey()).ToLowerInvariant();
        var signedAt = DateTimeOffset.UtcNow.AddSeconds(-1);
        var expiresAt = signedAt.AddDays(30);
        var capabilities = new[] { "session-rpc", "onion-v1" };
        var contactPayload = JsonSerializer.SerializeToUtf8Bytes(new
        {
            version = "deep-relay-contact-v1",
            routerId = nodeId,
            publicHost = "node.example",
            publicIp = "93.184.216.34",
            publicPort = 443,
            x25519PublicKey = new string('1', 64),
            rpcEndpoint = "http://93.184.216.34:22020/api/peer/onion",
            signedAtUnixMs = signedAt.ToUnixTimeMilliseconds(),
            expiresAtUnixMs = expiresAt.ToUnixTimeMilliseconds(),
            routerVersion = "1.0.0",
            isReachable = true,
            capabilities = capabilities.Order(StringComparer.Ordinal).ToArray()
        }, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        var contactSignature = Convert.ToHexString(signer.SignMessage(contactPayload)).ToLowerInvariant();
        var registration = registry.Register(new RegisterNodeRequest
        {
            NodeId = nodeId,
            Ed25519PublicKey = nodeId,
            OperatorAddress = "0x1111111111111111111111111111111111111111",
            RewardsAddress = "0x1111111111111111111111111111111111111111",
            BlsPublicKey = new BlsPublicKey { X = "0x01", Y = "0x02" },
            TransportStatus = new TransportStatus { Enabled = true, Running = true, Mode = "running" },
            RelayContact = new RelayContactDocument
            {
                RouterId = nodeId,
                PublicHost = "node.example",
                PublicIp = "93.184.216.34",
                PublicPort = 443,
                X25519PublicKey = new string('1', 64),
                RpcEndpoint = "http://93.184.216.34:22020/api/peer/onion",
                SignedAt = signedAt,
                ExpiresAt = expiresAt,
                RouterVersion = "1.0.0",
                IsReachable = true,
                Capabilities = capabilities,
                SignatureAlgorithm = "ed25519",
                Signature = contactSignature
            }
        });
        Assert.True(registration.Success, registration.Error);

        using var client = factory.CreateClient();
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/relay-contacts")).StatusCode);

        var now = DateTimeOffset.UtcNow;
        var nonce = Guid.NewGuid().ToString("N");
        var requestPayload = JsonSerializer.SerializeToUtf8Bytes(new
        {
            version = "xpoint-registry-catalog-v1",
            method = "GET",
            path = "/api/relay-contacts",
            nodeId,
            timestampUnixMs = now.ToUnixTimeMilliseconds(),
            nonce
        }, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        var requestSignature = Convert.ToHexString(signer.SignMessage(requestPayload)).ToLowerInvariant();

        using var authenticated = SignedCatalogRequest(nodeId, now, nonce, requestSignature);
        var response = await client.SendAsync(authenticated);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Single((await response.Content.ReadFromJsonAsync<JsonElement>()).EnumerateArray());

        using var replay = SignedCatalogRequest(nodeId, now, nonce, requestSignature);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(replay)).StatusCode);
    }

    [Fact]
    public async Task RegisterNodeWithVlessTransport_PublicViewHidesTransportSecrets()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var request = new
        {
            nodeId = "node-test-1",
            operatorAddress = "0x1111111111111111111111111111111111111111",
            rewardsAddress = "0x2222222222222222222222222222222222222222",
            blsPublicKey = new { x = "0x01", y = "0x02" },
            ed25519PublicKey = "ed25519",
            ed25519Signature1 = "sig1",
            ed25519Signature2 = "sig2",
            operatorFeeBps = 1250,
            stakeAtomic = 25_000L * 1_000_000_000L,
            signingEndpoint = "http://node.example:8080/api/staking/quorum/sign",
            transport = new
            {
                protocol = "vless",
                host = "node.example",
                port = 443,
                uuid = "00000000-0000-4000-8000-000000000001",
                security = "reality",
                sni = "node.example",
                publicKey = "reality-public-key",
                shortId = "abcd"
            },
            transportStatus = new
            {
                enabled = true,
                running = true,
                degraded = false,
                mode = "running",
                mocked = false,
                restartCount = 0,
                consecutiveFailures = 0,
                lastStartedAt = DateTimeOffset.UtcNow
            }
        };

        var register = await client.PostAsJsonAsync("/api/nodes/register", request);
        Assert.Equal(HttpStatusCode.Created, register.StatusCode);

        var node = await client.GetFromJsonAsync<JsonElement>("/api/nodes/node-test-1");
        Assert.False(node.TryGetProperty("signingEndpoint", out _));
        Assert.False(node.TryGetProperty("transport", out _));
        Assert.False(node.TryGetProperty("relayContact", out _));
        Assert.False(node.TryGetProperty("blsSignature", out _));
        Assert.False(node.TryGetProperty("ed25519Signature1", out _));
        Assert.False(node.TryGetProperty("ed25519Signature2", out _));
        Assert.True(node.GetProperty("transportStatus").GetProperty("running").GetBoolean());
        Assert.False(node.GetProperty("transportStatus").GetProperty("mocked").GetBoolean());
        Assert.NotEqual(JsonValueKind.Null, node.GetProperty("transportHealthySince").ValueKind);
        Assert.Equal(JsonValueKind.Null, node.GetProperty("transportUnhealthySince").ValueKind);

        var controlNodes = await client.GetFromJsonAsync<JsonElement>("/api/internal/nodes");
        var controlNode = Assert.Single(
            controlNodes.EnumerateArray(),
            item => item.GetProperty("nodeId").GetString() == "node-test-1");
        Assert.Equal(
            "http://node.example:8080/api/staking/quorum/sign",
            controlNode.GetProperty("signingEndpoint").GetString());
        Assert.False(controlNode.TryGetProperty("transport", out _));
        Assert.False(controlNode.TryGetProperty("relayContact", out _));

        var stakeState = await client.GetFromJsonAsync<JsonElement>("/api/nodes/node-test-1/stake-state");
        Assert.Equal("XPNT", stakeState.GetProperty("tokenSymbol").GetString());
        Assert.Equal("registered", stakeState.GetProperty("status").GetString());
        Assert.Equal(1250, stakeState.GetProperty("operatorFeeBps").GetInt32());

        var combined = await client.GetFromJsonAsync<JsonElement>("/api/nodes/node-test-1/rewards-stake-state");
        Assert.Equal("XPNT", combined.GetProperty("rewards").GetProperty("tokenSymbol").GetString());
        Assert.Equal("registered", combined.GetProperty("stake").GetProperty("status").GetString());
    }

    [Fact]
    public async Task RegisterNode_RejectsInvalidSigningEndpoint()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/nodes/register", new
        {
            nodeId = "node-test-invalid-signing",
            operatorAddress = "0x1111111111111111111111111111111111111111",
            rewardsAddress = "0x1111111111111111111111111111111111111111",
            blsPublicKey = new { x = "0x01", y = "0x02" },
            operatorFeeBps = 0,
            stakeAtomic = 0,
            signingEndpoint = "xnode-1:8080/api/staking/quorum/sign"
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("signingEndpoint must be an absolute http(s) URL", body.GetProperty("error").GetString());
    }

    [Fact]
    public async Task UpdateTransportBundle_IsNotPubliclyExposed()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        await client.PostAsJsonAsync("/api/nodes/register", new
        {
            nodeId = "node-test-2",
            operatorAddress = "0x1111111111111111111111111111111111111111",
            rewardsAddress = "0x1111111111111111111111111111111111111111",
            blsPublicKey = new { x = "0x01", y = "0x02" },
            operatorFeeBps = 0,
            stakeAtomic = 0
        });

        var update = await client.PutAsJsonAsync("/api/nodes/node-test-2/transport", new
        {
            protocol = "vless",
            host = "127.0.0.1",
            port = 8443,
            uuid = "00000000-0000-4000-8000-000000000002",
            security = "reality"
        });

        Assert.Equal(HttpStatusCode.NotFound, update.StatusCode);
    }

    [Fact]
    public async Task UpdateTransportBundle_DoesNotExposeLegacyMutationEndpoint()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        await client.PostAsJsonAsync("/api/nodes/register", new
        {
            nodeId = "node-test-transport-boundary",
            operatorAddress = "0x1111111111111111111111111111111111111111",
            rewardsAddress = "0x1111111111111111111111111111111111111111",
            blsPublicKey = new { x = "0x01", y = "0x02" },
            operatorFeeBps = 0,
            stakeAtomic = 0
        });

        var update = await client.PutAsJsonAsync("/api/nodes/node-test-transport-boundary/transport", new
        {
            protocol = "http",
            host = "127.0.0.1",
            port = 8443,
            uuid = "00000000-0000-4000-8000-000000000002"
        });

        Assert.Equal(HttpStatusCode.NotFound, update.StatusCode);
    }

    [Fact]
    public async Task RegisterRejectsNonVlessTransport()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/nodes/register", new
        {
            nodeId = "node-test-3",
            operatorAddress = "0x1111111111111111111111111111111111111111",
            blsPublicKey = new { x = "0x01", y = "0x02" },
            transport = new { protocol = "http", host = "node.example", port = 80, uuid = "bad" }
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task ReconciliationReport_FlagsStakeAndTransportIssues()
    {
        var statePath = Path.Combine(Path.GetTempPath(), $"deep-registry-reconcile-{Guid.NewGuid():N}.json");
        try
        {
            await using var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
            {
                builder.ConfigureAppConfiguration((_, config) =>
                {
                    config.AddInMemoryCollection(new Dictionary<string, string?>
                    {
                        ["Registry:StatePath"] = statePath
                    });
                });
            });

            using var client = factory.CreateClient();

            await client.PostAsJsonAsync("/api/nodes/register", new
            {
                nodeId = "node-reconcile-1",
                operatorAddress = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                rewardsAddress = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                blsPublicKey = new { x = "0x01", y = "0x02" },
                stakeAtomic = 10,
                contributors = new[]
                {
                    new { address = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", beneficiary = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", amountAtomic = 5L }
                }
            });

            await client.PostAsJsonAsync("/api/nodes/register", new
            {
                nodeId = "node-reconcile-2",
                operatorAddress = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                rewardsAddress = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                blsPublicKey = new { x = "0x03", y = "0x04" },
                stakeAtomic = 20_000L * 1_000_000_000L
            });

            var report = await client.GetFromJsonAsync<JsonElement>("/api/nodes/reconciliation");
            Assert.Equal(2, report.GetProperty("totalNodes").GetInt32());

            var codes = report.GetProperty("issues")
                .EnumerateArray()
                .Select(item => item.GetProperty("code").GetString())
                .Where(code => code is not null)
                .ToArray();

            Assert.Contains("stake-contributor-mismatch", codes);
            Assert.Contains("stake-below-requirement", codes);
            Assert.Contains("transport-missing", codes);
            Assert.Contains("transport-status-missing", codes);
        }
        finally
        {
            if (File.Exists(statePath))
            {
                File.Delete(statePath);
            }
        }
    }

    [Fact]
    public async Task ReconciliationReport_FlagsUnhealthyTransportStatus()
    {
        var statePath = Path.Combine(Path.GetTempPath(), $"deep-registry-status-{Guid.NewGuid():N}.json");
        try
        {
            await using var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
            {
                builder.ConfigureAppConfiguration((_, config) =>
                {
                    config.AddInMemoryCollection(new Dictionary<string, string?>
                    {
                        ["Registry:StatePath"] = statePath
                    });
                });
            });

            using var client = factory.CreateClient();

            await client.PostAsJsonAsync("/api/nodes/register", new
            {
                nodeId = "node-status-1",
                operatorAddress = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                rewardsAddress = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                blsPublicKey = new { x = "0x01", y = "0x02" },
                stakeAtomic = 20_000L * 1_000_000_000L,
                transport = new
                {
                    protocol = "vless",
                    host = "node-status.example",
                    port = 443,
                    uuid = "00000000-0000-4000-8000-000000000099"
                },
                transportStatus = new
                {
                    enabled = true,
                    running = false,
                    degraded = true,
                    mode = "degraded",
                    mocked = true,
                    restartCount = 4,
                    consecutiveFailures = 3,
                    lastExitReason = "xray-exited:1",
                    degradedUntil = DateTimeOffset.UtcNow.AddMinutes(5)
                }
            });

            var report = await client.GetFromJsonAsync<JsonElement>("/api/nodes/reconciliation");
            var codes = report.GetProperty("issues")
                .EnumerateArray()
                .Select(item => item.GetProperty("code").GetString())
                .Where(code => code is not null)
                .ToArray();

            Assert.Contains("transport-mocked", codes);
            Assert.Contains("transport-not-running", codes);
            Assert.Contains("transport-degraded", codes);

            var node = await client.GetFromJsonAsync<JsonElement>("/api/nodes/node-status-1");
            Assert.NotEqual(JsonValueKind.Null, node.GetProperty("transportUnhealthySince").ValueKind);
            Assert.Equal(JsonValueKind.Null, node.GetProperty("transportHealthySince").ValueKind);
        }
        finally
        {
            if (File.Exists(statePath))
            {
                File.Delete(statePath);
            }
        }
    }

    [Theory]
    [InlineData("not-a-number", "0x02")]
    [InlineData("-1", "0x02")]
    [InlineData("0x10000000000000000000000000000000000000000000000000000000000000000", "0x02")]
    public async Task RegisterRejectsBlsCoordinatesOutsideUint256Boundaries(string x, string y)
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/nodes/register", new
        {
            nodeId = "node-test-bls-boundary",
            operatorAddress = "0x1111111111111111111111111111111111111111",
            blsPublicKey = new { x, y },
            transport = new
            {
                protocol = "vless",
                host = "node.example",
                port = 443,
                uuid = "00000000-0000-4000-8000-000000000003"
            }
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public void NodeRegistry_PersistsAndReloadsFromSnapshot()
    {
        var statePath = Path.Combine(Path.GetTempPath(), $"deep-registry-{Guid.NewGuid():N}.json");
        try
        {
            var options = Options.Create(new RegistryOptions
            {
                StatePath = statePath,
                StakingRequirementAtomic = 20_000L * 1_000_000_000L
            });

            var first = new NodeRegistry(options);
            var registerResult = first.Register(new RegisterNodeRequest
            {
                NodeId = "node-persist-1",
                OperatorAddress = "0x1111111111111111111111111111111111111111",
                RewardsAddress = "0x2222222222222222222222222222222222222222",
                BlsPublicKey = new BlsPublicKey { X = "0x01", Y = "0x02" },
                StakeAtomic = 20_000L * 1_000_000_000L,
                Transport = new TransportBundle
                {
                    Protocol = "vless",
                    Host = "persist.example",
                    Port = 443,
                    Uuid = "00000000-0000-4000-8000-000000000004"
                }
            });

            Assert.True(registerResult.Success);
            var updateResult = first.UpdateTransport("node-persist-1", new TransportBundle
            {
                Protocol = "vless",
                Host = "updated.example",
                Port = 8443,
                Uuid = "00000000-0000-4000-8000-000000000005"
            });

            Assert.True(updateResult.Success);
            Assert.True(File.Exists(statePath));

            var reloaded = new NodeRegistry(options);
            var node = reloaded.GetNode("node-persist-1");

            Assert.NotNull(node);
            Assert.Equal("updated.example", node!.Transport?.Host);
            Assert.Equal(2, node.Revision);
        }
        finally
        {
            if (File.Exists(statePath))
            {
                File.Delete(statePath);
            }
        }
    }

    [Fact]
    public void NodeRegistry_ReconciliationJob_TracksLastReportAndRuns()
    {
        var statePath = Path.Combine(Path.GetTempPath(), $"deep-registry-job-{Guid.NewGuid():N}.json");
        try
        {
            var options = Options.Create(new RegistryOptions
            {
                StatePath = statePath,
                StakingRequirementAtomic = 20_000L * 1_000_000_000L
            });

            var registry = new NodeRegistry(options);
            var registerResult = registry.Register(new RegisterNodeRequest
            {
                NodeId = "node-reconcile-job-1",
                OperatorAddress = "0x1111111111111111111111111111111111111111",
                RewardsAddress = "0x1111111111111111111111111111111111111111",
                BlsPublicKey = new BlsPublicKey { X = "0x01", Y = "0x02" },
                StakeAtomic = 1,
                Contributors =
                [
                    new ContributorStake
                    {
                        Address = "0x1111111111111111111111111111111111111111",
                        Beneficiary = "0x1111111111111111111111111111111111111111",
                        AmountAtomic = 0
                    }
                ]
            });

            Assert.True(registerResult.Success);

            var first = registry.RunReconciliationJob();
            var second = registry.RunReconciliationJob();
            var status = registry.GetReconciliationJobStatus();
            var last = registry.GetLastReconciliationReport();

            Assert.True(first.Issues.Count > 0);
            Assert.True(second.Issues.Count > 0);
            Assert.Equal(2, status.Runs);
            Assert.NotNull(status.LastRunAt);
            Assert.Equal(1, status.LastTotalNodes);
            Assert.True(status.LastIssueCount > 0);
            Assert.NotNull(last);
            Assert.Equal(status.LastIssueCount, last!.Issues.Count);
        }
        finally
        {
            if (File.Exists(statePath))
            {
                File.Delete(statePath);
            }
        }
    }

    [Fact]
    public void NodeRegistry_RecoversFromCorruptedStateFile()
    {
        var statePath = Path.Combine(Path.GetTempPath(), $"deep-registry-corrupt-{Guid.NewGuid():N}.json");
        File.WriteAllText(statePath, "{ invalid json");

        try
        {
            var options = Options.Create(new RegistryOptions
            {
                StatePath = statePath,
                StakingRequirementAtomic = 20_000L * 1_000_000_000L
            });

            var registry = new NodeRegistry(options);
            var stats = registry.GetRuntimeStats();

            Assert.Equal(0, stats.TotalNodes);
            Assert.Equal(1, stats.CorruptedStateRecoveries);
            Assert.False(File.Exists(statePath));

            var directory = Path.GetDirectoryName(statePath)!;
            var fileName = Path.GetFileName(statePath);
            var backups = Directory.GetFiles(directory, $"{fileName}.corrupt-*.bak");
            Assert.Single(backups);
        }
        finally
        {
            if (File.Exists(statePath))
            {
                File.Delete(statePath);
            }

            var directory = Path.GetDirectoryName(statePath)!;
            var fileName = Path.GetFileName(statePath);
            foreach (var backup in Directory.GetFiles(directory, $"{fileName}.corrupt-*.bak"))
            {
                File.Delete(backup);
            }
        }
    }

    [Fact]
    public async Task RuntimeEndpoint_ReturnsRegistryStats()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var runtime = await client.GetFromJsonAsync<JsonElement>("/api/nodes/runtime");

        Assert.True(runtime.TryGetProperty("totalNodes", out _));
        Assert.True(runtime.TryGetProperty("corruptedStateRecoveries", out _));
    }

    [Fact]
    public async Task ReconciliationMutationEndpoints_AreNotExposed()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var manualResponse = await client.PostAsJsonAsync("/api/nodes/reconciliation/actions", new
        {
            action = "reset-contributors-to-stake",
            nodeId = "node-1"
        });
        var autoResponse = await client.PostAsJsonAsync("/api/nodes/reconciliation/actions/auto", new { dryRun = false });
        var historyResponse = await client.GetAsync("/api/nodes/reconciliation/actions/history?take=20");

        Assert.Equal(HttpStatusCode.NotFound, manualResponse.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, autoResponse.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, historyResponse.StatusCode);
    }

    [Fact]
    public async Task RewardsEndpoint_UsesStakingProjection_WhenAvailable()
    {
        var projectedRewards = new RegistrationRewardState(
            "0x1111111111111111111111111111111111111111",
            "XPNT",
            9,
            250,
            40,
            210);

        await using var factory = CreateFactoryWithProjectionClient(new FakeStakingProjectionClient(
            nodes: [],
            rewards: new Dictionary<string, RegistrationRewardState>(StringComparer.OrdinalIgnoreCase)
            {
                [projectedRewards.Address] = projectedRewards
            }));

        using var client = factory.CreateClient();
        var response = await client.GetFromJsonAsync<JsonElement>($"/api/rewards/{projectedRewards.Address}");

        Assert.Equal(250, response.GetProperty("lifetimeRewardsAtomic").GetInt64());
        Assert.Equal(40, response.GetProperty("claimedRewardsAtomic").GetInt64());
        Assert.Equal(210, response.GetProperty("claimableRewardsAtomic").GetInt64());
    }

    [Fact]
    public async Task ProjectionReconciliationReport_FlagsRegistryAndStakingDivergence()
    {
        var statePath = Path.Combine(Path.GetTempPath(), $"deep-registry-projections-{Guid.NewGuid():N}.json");
        try
        {
            var fakeNodes = new[]
            {
                new StakingProjectedNode
                {
                    NodeId = "node-proj-1",
                    OperatorAddress = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    RewardsAddress = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    StakeAtomic = 200,
                    Status = "active"
                },
                new StakingProjectedNode
                {
                    NodeId = "node-only-in-staking",
                    OperatorAddress = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    RewardsAddress = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    StakeAtomic = 50,
                    Status = "active"
                }
            };

            await using var factory = CreateFactoryWithProjectionClient(
                new FakeStakingProjectionClient(
                    fakeNodes,
                    new Dictionary<string, RegistrationRewardState>(StringComparer.OrdinalIgnoreCase)),
                statePath);
            using var client = factory.CreateClient();

            await client.PostAsJsonAsync("/api/nodes/register", new
            {
                nodeId = "node-proj-1",
                operatorAddress = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                rewardsAddress = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                blsPublicKey = new { x = "0x01", y = "0x02" },
                stakeAtomic = 100
            });

            await client.PostAsJsonAsync("/api/nodes/register", new
            {
                nodeId = "node-only-in-registry",
                operatorAddress = "0xcccccccccccccccccccccccccccccccccccccccc",
                rewardsAddress = "0xcccccccccccccccccccccccccccccccccccccccc",
                blsPublicKey = new { x = "0x03", y = "0x04" },
                stakeAtomic = 100
            });

            var report = await client.GetFromJsonAsync<JsonElement>("/api/nodes/reconciliation/projections");
            var codes = report.GetProperty("issues")
                .EnumerateArray()
                .Select(item => item.GetProperty("code").GetString())
                .Where(code => code is not null)
                .ToArray();

            Assert.Contains("stake-divergence", codes);
            Assert.Contains("staking-node-missing", codes);
            Assert.Contains("registry-node-missing", codes);
        }
        finally
        {
            if (File.Exists(statePath))
            {
                File.Delete(statePath);
            }
        }
    }

    private static WebApplicationFactory<Program> CreateFactoryWithProjectionClient(IStakingProjectionClient projectionClient, string? statePath = null)
    {
        return new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.ConfigureAppConfiguration((_, config) =>
            {
                if (!string.IsNullOrWhiteSpace(statePath))
                {
                    config.AddInMemoryCollection(new Dictionary<string, string?>
                    {
                        ["Registry:StatePath"] = statePath
                    });
                }
            });

            builder.ConfigureServices(services =>
            {
                services.AddSingleton(projectionClient);
            });
        });
    }

    private static HttpRequestMessage SignedCatalogRequest(
        string nodeId,
        DateTimeOffset timestamp,
        string nonce,
        string signature)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "/api/relay-contacts");
        request.Headers.Add("X-XPoint-Node-Id", nodeId);
        request.Headers.Add("X-XPoint-Timestamp", timestamp.ToUnixTimeMilliseconds().ToString(System.Globalization.CultureInfo.InvariantCulture));
        request.Headers.Add("X-XPoint-Nonce", nonce);
        request.Headers.Add("X-XPoint-Signature", signature);
        return request;
    }

    private sealed class FakeStakingProjectionClient : IStakingProjectionClient
    {
        private readonly IReadOnlyList<StakingProjectedNode> _nodes;
        private readonly IReadOnlyDictionary<string, RegistrationRewardState> _rewards;

        public FakeStakingProjectionClient(
            IReadOnlyList<StakingProjectedNode> nodes,
            IReadOnlyDictionary<string, RegistrationRewardState> rewards)
        {
            _nodes = nodes;
            _rewards = rewards;
        }

        public Task<IReadOnlyList<StakingProjectedNode>> GetNodesAsync(CancellationToken cancellationToken = default)
        {
            return Task.FromResult(_nodes);
        }

        public Task<StakingProjectedNode?> GetNodeAsync(string nodeId, CancellationToken cancellationToken = default)
        {
            var node = _nodes.FirstOrDefault(item => string.Equals(item.NodeId, nodeId, StringComparison.OrdinalIgnoreCase));
            return Task.FromResult(node);
        }

        public Task<RegistrationRewardState?> GetRewardsAsync(string address, CancellationToken cancellationToken = default)
        {
            _rewards.TryGetValue(address, out var reward);
            return Task.FromResult(reward);
        }
    }
}
