#if DEEP_PROTOCOL_DIRECTORY_V1
extern alias xnode;
using System.Net;
using System.Net.Sockets;
using System.Diagnostics;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using Deep.Registry.Api.DirectoryPublication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Npgsql;
using XNode.Core;
using XNode.Core.Mailbox;
using XNode.Core.Mailbox.Client;

namespace Deep.Registry.Api.Tests;

public sealed partial class DeepIdV2RouteThresholdIssuerTests
{
    // Actual configured source and native owners, not the signed fixture-source
    // used by older peer tests. The client envelope/holder remains test-owned;
    // this is a connected issuer/native data boundary, NOT owned client E2E.
    private async Task ExerciseIssuedGrantsNativeCycleAsync(VerifiedDeepIdV2MailboxGrant grant,
        VerifiedDeepIdV2MailboxGrant readGrant,
        ControlSocketTls registryTls, Uri origin, Clock clock, GrantPeerLayout peers, Signer[] nodes,
        MailboxRevocationAuthority revocations, byte[] network, ReadOnlyMemory<byte> observer, string directory,
        string bundlePath, XPointNetworkGenesisPin genesisPin, ReadOnlyMemory<byte> genesisHeadHash)
    {
        var deposit = await revocations.ReadRetainedAsync(MailboxCapabilityDomain.Deposit, 1, default);
        var retrieve = await revocations.ReadRetainedAsync(MailboxCapabilityDomain.Retrieve, 1, default);
        var policyHash = ContactCodec.Decode("PMA2", grant.ExactPma2.Span).CoreHash;
        var running = new List<WebApplication>();
        var reopen = new List<Func<Task<WebApplication>>>();
        var peerRequests = new int[nodes.Length];
        var peerStatuses = new int[nodes.Length];
        var peerResponseBytes = new long?[nodes.Length];
        var observedPeers = nodes.Select(_ => new ObservedNativePeer()).ToArray();
        var observedSources = new ObservedNativeSource?[nodes.Length];
        var observedDurability = nodes.Select(_ => new ObservedNativeDurability()).ToArray();
        var observedSecurity = nodes.Select(_ => new ObservedNativeSecurity()).ToArray();
        try
        {
            for (var i = 0; i < nodes.Length; i++)
            {
                var nodeRoot = Path.Combine(directory, "grant-native-" + i);
                var security = observedSecurity[i];
                var keys = Path.Combine(nodeRoot, "keys"); security.SecureDirectory(keys);
                var provisioning = new ServiceCollection();
                provisioning.AddDataProtection().PersistKeysToFileSystem(new DirectoryInfo(keys))
                    .SetApplicationName(xnode::XNode.CurrentMailboxHostComposition.ProtectionApplication).DisableAutomaticKeyGeneration();
                using (var provider = provisioning.BuildServiceProvider())
                    provider.GetRequiredService<IKeyManager>().CreateNewKey(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(90));
                foreach (var file in Directory.GetFiles(keys)) security.SecureFile(file);
                var node = new RouterNodeOptions
                {
                    RouterId = Convert.ToHexString(nodes[i].SignerId.Span), Ed25519PrivateKey = Convert.ToHexString(Bytes(32, nodes[i].Marker)),
                    DataDirectory = Path.Combine(nodeRoot, "data"), PrivacyPeerH2ListenUrl = "https://127.0.0.1:" + peers.Ports[i]
                };
                var mailbox = new ReplicatedMailboxOptions { Enabled = true };
                var custody = new xnode::XNode.CurrentMailboxCustodyOptions
                {
                    NetworkIdHex = Convert.ToHexString(network).ToLowerInvariant(),
                    MailboxAuthorityCoreHashHex = Convert.ToHexString(policyHash.Span).ToLowerInvariant(),
                    IndependentCustodyDirectory = Path.Combine(nodeRoot, "custody"), DataProtectionKeysDirectory = keys
                }.Validate(node, mailbox)!;
                var proof = new xnode::XNode.DeepIdV2DirectoryProofOptions
                {
                    Enabled = true, RegistryOrigin = origin.AbsoluteUri, NetworkIdHex = Convert.ToHexString(network),
                    GenesisAuthorityCoreHashHex = Convert.ToHexString(genesisPin.AuthorityCoreHash.Span),
                    ExactAuthorityPaths = [Path.Combine(directory, "root.xna1")], ExactTimePolicyPaths = [Path.Combine(directory, "time.dts1")],
                    GenesisHeadPath = Path.Combine(directory, "genesis.adh1"), GenesisHeadCoreHashHex = Convert.ToHexString(genesisHeadHash.Span),
                    StateRelativeDirectory = "proof-head", DataProtectionKeysRelativeDirectory = "proof-keys", DeploymentProfileId = 1, RequestTimeoutSeconds = 5
                }.ValidateAndLoad(node, developmentOrUat: true)!;
                var observerPath = Path.Combine(nodeRoot, "observer.did2"); await File.WriteAllBytesAsync(observerPath, observer.ToArray());
                var placement = new xnode::XNode.DeepIdV2NetworkPlacementOptions
                { Enabled = true, PublicBundlePath = bundlePath, PublicObservationDid2Path = observerPath }
                    .ValidateAndLoad(did2ProofEnabled: true, developmentOrUat: true)!;
                var index = i;
                async Task<WebApplication> OpenAsync(bool initialEnrollment)
                {
                    var builder = WebApplication.CreateBuilder(); builder.Logging.ClearProviders();
                    builder.WebHost.ConfigureKestrel(options => options.Listen(IPAddress.Loopback, peers.Ports[index], listen =>
                    { listen.Protocols = HttpProtocols.Http2; listen.UseHttps(peers.Tls[index].Server); }));
                    builder.Services.AddSingleton(node); builder.Services.AddSingleton(mailbox);
                    builder.Services.AddSingleton<IOnionMonotonicClock>(clock);
                    builder.Services.AddSingleton<IMailboxStorageSecurity>(security);
                    builder.Services.AddSingleton<IMailboxDurabilityBarrier>(observedDurability[index]);
                    xnode::XNode.DeepIdV2DirectoryProofHostComposition.AddDeepIdV2DirectoryProof(builder.Services, proof);
                    builder.Services.AddHttpClient("did2-directory-proof").ConfigurePrimaryHttpMessageHandler(() => registryTls.CreateHandler());
                    xnode::XNode.DeepIdV2NetworkPlacementHostComposition.AddDeepIdV2NetworkPlacement(builder.Services, placement);
                    builder.Services.AddSingleton<xnode::XNode.IDeepIdV2ContactStoreAuthoritySource>(provider =>
                        observedSources[index] = new ObservedNativeSource(
                            provider.GetRequiredService<xnode::XNode.DeepIdV2NetworkPlacementRuntime>()));
                    xnode::XNode.CurrentMailboxHostComposition.AddCurrentMailboxHost(builder.Services, custody, node, mailbox);
                    // Observe the actual descriptor-pinned production client;
                    // no transport substitution or extra retry is introduced.
                    builder.Services.AddSingleton<xnode::XNode.ICurrentMailboxReplicaPeerClient>(observedPeers[index]);
                    builder.Services.AddSingleton<xnode::XNode.NativeMailboxExitDispatcher>();
                    var app = builder.Build();
                    try
                    {
                        app.Use(async (context, next) =>
                        {
                            var isPeer = context.Request.Path.Value is MailboxWireHttpContract.PeerStoreRoute or MailboxWireHttpContract.PeerTombstoneRoute;
                            if (isPeer)
                                Interlocked.Increment(ref peerRequests[index]);
                            await next(context);
                            if (isPeer)
                            {
                                peerStatuses[index] = context.Response.StatusCode;
                                peerResponseBytes[index] = context.Response.ContentLength;
                            }
                        });
                        app.Services.GetRequiredService<xnode::XNode.CurrentMailboxPeerHttpEndpoint>().Map(app);
                        if (initialEnrollment)
                            await xnode::XNode.CurrentMailboxEnrollmentCommand.EnrollConfiguredAsync(app.Services, deposit, retrieve, default);
                        else
                        {
                            await Assert.ThrowsAsync<CryptographicException>(() => app.Services
                                .GetRequiredService<xnode::XNode.CurrentMailboxReplicaReceiver>().InitializeHostAsync().AsTask());
                            await app.Services.GetRequiredService<xnode::XNode.DeepIdV2DirectoryProofRuntime>().RestoreHeadAsync(default);
                            await app.Services.GetRequiredService<xnode::XNode.DeepIdV2NetworkPlacementRuntime>().AcquireObservationAsync(default);
                        }
                        await app.StartAsync();
                        await app.Services.GetRequiredService<xnode::XNode.CurrentMailboxReplicaReceiver>().InitializeHostAsync();
                        return app;
                    }
                    catch { await app.DisposeAsync(); throw; }
                }
                reopen.Add(() => OpenAsync(initialEnrollment: false));
                running.Add(await OpenAsync(initialEnrollment: true));
            }
            var firstSource = running[0].Services.GetRequiredService<xnode::XNode.IDeepIdV2ContactStoreAuthoritySource>();
            var current = await firstSource.ReadPublicationAuthorityAsync(default);
            var host = await MailboxHostAuthorityV2Verifier.VerifyAsync(current.Network, current.Authority, grant.ExactPma2, current.TrustedTime);
            var replicas = await host.ResolveGrantReplicasAsync(grant.ExactGrant);
            var writer = running.Single(app => app.Services.GetRequiredService<RouterNodeOptions>().GetRouterId().ToBytes()
                .AsSpan().SequenceEqual(replicas[0].NodeId.Span));
            var decoded = MailboxAuthenticatedCapabilityCodec.DecodeGrant(grant.ExactGrant.Span);
            var envelope = new MailboxEncryptedEnvelope
            {
                Epoch = host.SelectionEpoch, MailboxId = new(Bytes(32, 0x54)),
                PlacementId = new(ContactCodec.Decode("XMG2", grant.ExactXmg2.Span).Field(4).Span),
                OperationId = Bytes(16, 0x58), DeduplicationDigest = Bytes(32, 0x59),
                CreatedAtUnixSeconds = decoded.NotBeforeUnixSeconds, ExpiresAtUnixSeconds = decoded.ExpiresAtUnixSeconds,
                Ciphertext = Bytes(64, 0x60)
            };
            var binding = MailboxAuthenticatedRequestTranscript.ForStore(envelope);
            var request = MailboxAuthenticatedClientRequestCodec.Encode(new()
            {
                Binding = binding, Presentation = new SodiumMailboxCapabilityCrypto().SignPresentation(decoded, binding, 1, Bytes(32, 0x57))
            });
            var dispatcher = (xnode::XNode.ILocalNativeMailboxExitDispatcher)writer.Services.GetRequiredService<xnode::XNode.NativeMailboxExitDispatcher>();
            var storeWatch = Stopwatch.StartNew();
            foreach (var source in observedSources) source!.Reset();
            foreach (var durability in observedDurability) durability.Reset();
            foreach (var security in observedSecurity) security.Reset();
            using var exceptions = new NativeStoreExceptions();
            var result = await dispatcher.DispatchAsync(OnionOperation.Store, request, default);
            exceptions.Dispose();
            var localSummary = $"sources={string.Join(';', observedSources.Select(source => source!.Summary))}; " +
                $"durability={string.Join(';', observedDurability.Select(durability => durability.Summary))}; " +
                $"security={string.Join(';', observedSecurity.Select(security => security.Summary))}; " +
                $"exceptions={exceptions.Summary}";
            output.WriteLine($"Initial Store elapsed-ms={storeWatch.ElapsedMilliseconds}; {localSummary}");
            Assert.True(result.Certainty == xnode::XNode.NativeMailboxDispatchCertainty.Completed,
                $"Initial native Store={result.Certainty}; status={result.StatusCode}; elapsed-ms={storeWatch.ElapsedMilliseconds}; " +
                $"peer requests={peerRequests.Sum()}; server statuses={string.Join(',', peerStatuses)}; " +
                $"server response bytes={string.Join(',', peerResponseBytes)}; " +
                $"client observations={string.Join(';', observedPeers.Select(peer => peer.Summary))}; {localSummary}.");
            Assert.Equal(200, result.StatusCode);
            Assert.Equal(1, peerRequests.Sum());
            var quorum = MailboxReceiptV3Codec.DecodeDurableQuorum(result.CanonicalBody.Span);
            // MQR3 is byte-ID sorted, independently of PMS2 writer ranking.
            var expectedIds = replicas.Select(replica => replica.NodeId.ToArray())
                .OrderBy(id => Convert.ToHexString(id), StringComparer.Ordinal).ToArray();
            Assert.Equal(expectedIds[0], quorum.FirstReplica.ReplicaId.ToArray());
            Assert.Equal(expectedIds[1], quorum.SecondReplica.ReplicaId.ToArray());
            Assert.False(quorum.FirstReplica.ReplicaId.Span.SequenceEqual(quorum.SecondReplica.ReplicaId.Span));
            var retry = await dispatcher.DispatchAsync(OnionOperation.Store, request, default);
            Assert.Equal(xnode::XNode.NativeMailboxDispatchCertainty.Completed, retry.Certainty);
            Assert.Equal(result.CanonicalBody.ToArray(), retry.CanonicalBody.ToArray());
            Assert.Equal(1, peerRequests.Sum());
            byte[] PresentRead(MailboxAuthenticatedRequestBinding readBinding, ulong counter = 1) =>
                MailboxAuthenticatedClientRequestCodec.Encode(new()
                {
                    Binding = readBinding, Presentation = new SodiumMailboxCapabilityCrypto().SignPresentation(
                        MailboxAuthenticatedCapabilityCodec.DecodeGrant(readGrant.ExactGrant.Span), readBinding, counter, Bytes(32, 0x57))
                });
            MailboxRetrievePage DecodePage(ReadOnlyMemory<byte> exact) => MailboxClientCodec.DecodeRetrievePage(exact.Span, new()
            {
                NowUnixSeconds = current.Freshness.TrustedUpperUnixSeconds,
                EpochWindow = new() { CurrentEpoch = host.SelectionEpoch, CurrentNotBeforeUnixSeconds = decoded.NotBeforeUnixSeconds,
                    CurrentExpiresAtUnixSeconds = decoded.ExpiresAtUnixSeconds, NextEpoch = 0, NextNotBeforeUnixSeconds = 0, NextExpiresAtUnixSeconds = 0 },
                CapabilityPolicy = new() { CurrentBucket = 0, MinimumGeneration = 1 }
            });
            var readFrame = PresentRead(MailboxAuthenticatedRequestTranscript.ForRetrieve(envelope.Epoch, Bytes(16, 0x71),
                envelope.MailboxId, envelope.PlacementId, 0, 10, []));
            var read = await dispatcher.DispatchAsync(OnionOperation.Retrieve, readFrame, default);
            Assert.Equal(xnode::XNode.NativeMailboxDispatchCertainty.Completed, read.Certainty); Assert.Equal(200, read.StatusCode);
            var page = DecodePage(read.CanonicalBody);
            Assert.Equal(envelope.Ciphertext.ToArray(), Assert.Single(page.Items).Envelope.Ciphertext.ToArray());
            var ackFrame = PresentRead(MailboxAuthenticatedRequestTranscript.ForAck(envelope.Epoch, Bytes(16, 0x74),
                envelope.MailboxId, envelope.PlacementId, !page.HasMore, page.ContinuationToken.Span,
                page.Items.Select(item => item.ToAcknowledgement()).ToArray()));
            var ack = await dispatcher.DispatchAsync(OnionOperation.Acknowledge, ackFrame, default);
            Assert.Equal(xnode::XNode.NativeMailboxDispatchCertainty.Completed, ack.Certainty); Assert.Equal(200, ack.StatusCode);
            Assert.Equal(2, peerRequests.Sum());
            var ackRetry = await dispatcher.DispatchAsync(OnionOperation.Acknowledge, ackFrame, default);
            Assert.Equal(ack.CanonicalBody.ToArray(), ackRetry.CanonicalBody.ToArray());
            var freshRead = PresentRead(MailboxAuthenticatedRequestTranscript.ForRetrieve(envelope.Epoch, Bytes(16, 0x72),
                envelope.MailboxId, envelope.PlacementId, 0, 10, []), 2);
            foreach (var replica in replicas)
            {
                var peer = running.Single(app => app.Services.GetRequiredService<RouterNodeOptions>().GetRouterId().ToBytes()
                    .AsSpan().SequenceEqual(replica.NodeId.Span));
                var empty = await ((xnode::XNode.ILocalNativeMailboxExitDispatcher)peer.Services
                    .GetRequiredService<xnode::XNode.NativeMailboxExitDispatcher>()).DispatchAsync(OnionOperation.Retrieve, freshRead, default);
                Assert.Equal(xnode::XNode.NativeMailboxDispatchCertainty.Completed, empty.Certainty); Assert.Equal(200, empty.StatusCode);
                Assert.Empty(DecodePage(empty.CanonicalBody).Items);
            }
            // Retained native data/custody/key rings, same signed origins/identity.
            // No enrollment, schema repair, new key generation or account reset.
            for (var i = 0; i < running.Count; i++)
            {
                await running[i].DisposeAsync();
                running[i] = await reopen[i]();
            }
            writer = running.Single(app => app.Services.GetRequiredService<RouterNodeOptions>().GetRouterId().ToBytes()
                .AsSpan().SequenceEqual(replicas[0].NodeId.Span));
            dispatcher = (xnode::XNode.ILocalNativeMailboxExitDispatcher)writer.Services.GetRequiredService<xnode::XNode.NativeMailboxExitDispatcher>();
            var coldStore = await dispatcher.DispatchAsync(OnionOperation.Store, request, default);
            Assert.Equal(xnode::XNode.NativeMailboxDispatchCertainty.Completed, coldStore.Certainty);
            Assert.Equal(200, coldStore.StatusCode); Assert.Equal(result.CanonicalBody.ToArray(), coldStore.CanonicalBody.ToArray());
            var coldAck = await dispatcher.DispatchAsync(OnionOperation.Acknowledge, ackFrame, default);
            Assert.Equal(xnode::XNode.NativeMailboxDispatchCertainty.Completed, coldAck.Certainty);
            Assert.Equal(200, coldAck.StatusCode); Assert.Equal(ack.CanonicalBody.ToArray(), coldAck.CanonicalBody.ToArray());
            Assert.Equal(2, peerRequests.Sum());
            var coldReadFrame = PresentRead(MailboxAuthenticatedRequestTranscript.ForRetrieve(envelope.Epoch, Bytes(16, 0x75),
                envelope.MailboxId, envelope.PlacementId, 0, 10, []), 3);
            foreach (var replica in replicas)
            {
                var peer = running.Single(app => app.Services.GetRequiredService<RouterNodeOptions>().GetRouterId().ToBytes()
                    .AsSpan().SequenceEqual(replica.NodeId.Span));
                var empty = await ((xnode::XNode.ILocalNativeMailboxExitDispatcher)peer.Services
                    .GetRequiredService<xnode::XNode.NativeMailboxExitDispatcher>()).DispatchAsync(OnionOperation.Retrieve, coldReadFrame, default);
                Assert.Equal(xnode::XNode.NativeMailboxDispatchCertainty.Completed, empty.Certainty); Assert.Equal(200, empty.StatusCode);
                Assert.Empty(DecodePage(empty.CanonicalBody).Items);
            }
        }
        finally { foreach (var app in running) await app.DisposeAsync(); }
    }

    private static async Task<MailboxRevocationAuthority> ProvisionGrantRevocationsAsync(DeepIdV2MailboxAuthorityContextSource contexts,
        MailboxTestCustody custody, NpgsqlConnection db, string scoped, byte[] network, ReadOnlyMemory<byte> exactPma)
    {
        await using (var ddl = new NpgsqlCommand(await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory,
            "Fixtures", "mailbox-revocation-journal.sql")), db)) await ddl.ExecuteNonQueryAsync();
        var policy = ContactCodec.Decode("PMA2", exactPma.Span);
        byte[] reference = [.. "PMA2"u8, 0, 1, .. policy.CoreHash.Span];
        foreach (var role in new[] { MailboxCapabilityDomain.Deposit, MailboxCapabilityDomain.Retrieve })
        {
            await using var provision = new NpgsqlCommand("INSERT INTO deep_mailbox_revocation_scope VALUES ($1,$2,$3,$4,0,0,8,$5)", db);
            foreach (var value in new object[] { network, reference, (short)role, custody.For(role).Ed25519PublicKey.ToArray(), Array.Empty<byte>() })
                provision.Parameters.Add(new() { Value = value });
            await provision.ExecuteNonQueryAsync();
        }
        var authority = new MailboxRevocationAuthority(contexts, custody, scoped, network);
        await authority.RefreshAsync(default); await authority.RequireReadyAsync(default); return authority;
    }

    private sealed class ObservedNativePeer : xnode::XNode.ICurrentMailboxReplicaPeerClient
    {
        private readonly xnode::XNode.CurrentMailboxReplicaPeerClient inner = new();
        private int calls;
        private string failure = "none";
        private long elapsed;
        private bool cancelled;
        private int? responseBytes;
        // Closed types/counters only: never exception messages, URLs, node IDs,
        // request bytes, grants, credentials or filesystem paths.
        internal string Summary => $"calls={calls},failure={failure},elapsed-ms={elapsed},cancelled={cancelled},bytes={responseBytes}";
        public async ValueTask<ReadOnlyMemory<byte>?> SendAsync(VerifiedOnionNextHopTransport recipient,
            MailboxPeerReplicationOperation operation, ReadOnlyMemory<byte> exactRequest, CancellationToken token)
        {
            calls++; var watch = Stopwatch.StartNew();
            try
            {
                var result = await inner.SendAsync(recipient, operation, exactRequest, token);
                responseBytes = result?.Length;
                failure = result.HasValue ? "none" : "noncanonical-response";
                return result;
            }
            catch (Exception error)
            {
                failure = error.GetType().Name + "/" + error.HResult;
                throw;
            }
            finally { elapsed = watch.ElapsedMilliseconds; cancelled = token.IsCancellationRequested; }
        }
    }

    private sealed class GrantPeerLayout : IDisposable
    {
        internal ControlSocketTls[] Tls { get; } = [new(), new(), new()];
        internal byte[][] Pins { get; }
        internal int[] Ports { get; }
        internal GrantPeerLayout()
        {
            Pins = Tls.Select(tls => SHA256.HashData(tls.Server.PublicKey.ExportSubjectPublicKeyInfo())).ToArray();
            var listeners = Enumerable.Range(0, 3).Select(_ => new TcpListener(IPAddress.Loopback, 0)).ToArray();
            try
            {
                foreach (var listener in listeners) listener.Start();
                Ports = listeners.Select(listener => ((IPEndPoint)listener.LocalEndpoint).Port).ToArray();
            }
            finally { foreach (var listener in listeners) listener.Stop(); }
        }
        public void Dispose() { foreach (var tls in Tls) tls.Dispose(); }
    }
}
#endif
