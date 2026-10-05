#if DEEP_PROTOCOL_DIRECTORY_V1
extern alias xnode;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.XPointNetworkV1;
using Deep.Registry.Api.DirectoryPublication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Logging;
using Npgsql;
using Sodium;

namespace Deep.Registry.Api.Tests;

// Reuses the real Registry DID2 admission/ADA2/floor/witness/network ceremony.
// The early-return mailbox fact is separate; the three route cases retain
// every original assertion. No replacement source/host capability constructor.
public sealed partial class DeepIdV2RouteThresholdIssuerTests
{
    [Fact]
    public Task ActualMailboxRenewalRecoversExactIntentAndRetainedCumulativeWinners() =>
        ExerciseRegistryCeremonyAsync(crashMode: 0, mailboxLifecycle: true);

    [Fact]
    public Task ActualTlsProofAcquisitionAndSignedControlReachNodeConsumers() =>
        ExerciseRegistryCeremonyAsync(crashMode: 0, mailboxLifecycle: true, socketControl: true);

    private static async Task ExerciseMailboxLifecycleAsync(DeepIdV2DurableGenesisAuthority admission, DeepIdV2DirectoryProofIssuer proofs,
        DeepIdV2XPointAuthoritySource roots, XPointNetworkClosureDistribution distribution, Clock clock,
        NpgsqlConnection db, string scoped, byte[] network, ReadOnlyMemory<byte> observer,
        ReadOnlyMemory<byte> exactPma, string bundlePath, string directory,
        XPointNetworkGenesisPin genesisPin, ReadOnlyMemory<byte> genesisHeadHash, bool socketControl)
    {
        await using (var ddl = new NpgsqlCommand(await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory,
            "Fixtures", "mailbox-revocation-journal.sql")), db)) await ddl.ExecuteNonQueryAsync();
        var pma = ContactCodec.Decode("PMA2", exactPma.Span);
        var reference = new byte[] { (byte)'P', (byte)'M', (byte)'A', (byte)'2', 0, 1 }.Concat(pma.CoreHash.ToArray()).ToArray();
        using var custody = new MailboxTestCustody();
        foreach (var role in new[] { MailboxCapabilityDomain.Deposit, MailboxCapabilityDomain.Retrieve })
        {
            await using var provision = new NpgsqlCommand("INSERT INTO deep_mailbox_revocation_scope VALUES ($1,$2,$3,$4,0,0,80,$5)", db);
            foreach (var value in new object[] { network, reference, (short)role, custody.For(role).Ed25519PublicKey.ToArray(), Array.Empty<byte>() })
                provision.Parameters.Add(new() { Value = value });
            await provision.ExecuteNonQueryAsync();
        }
        var contexts = new DeepIdV2MailboxAuthorityContextSource(proofs, roots, distribution, clock, DeepIdV2Codec.DecodeDid2(observer.Span));
        var authority = new MailboxRevocationAuthority(contexts, custody, scoped, network);
        await Assert.ThrowsAsync<IOException>(() => authority.RequireReadyAsync(default).AsTask());
        custody.Deposit.BeforeSign = (_, _) => throw new IOException("Interrupted role custody after reservation.");
        await Assert.ThrowsAsync<IOException>(() => authority.RefreshAsync(default).AsTask());
        var intent = Assert.Single(custody.Deposit.Inputs); Assert.Empty(custody.Retrieve.Inputs);
        await Assert.ThrowsAsync<IOException>(() => authority.RequireReadyAsync(default).AsTask());
        custody.Deposit.BeforeSign = null;
        // Old reserved genesis expired; complete current root/PMA2/PMT2 still valid.
        clock.UnixTime = 1_410; clock.Sample = 410;
        var reopened = new MailboxRevocationAuthority(contexts, custody, scoped, network);
        using var tls = socketControl ? new ControlSocketTls() : null;
        var builder = WebApplication.CreateBuilder(); builder.Logging.ClearProviders();
        if (tls is null) builder.WebHost.UseTestServer();
        else builder.WebHost.ConfigureKestrel(options =>
        {
            options.Listen(IPAddress.Loopback, 0, listen => listen.UseHttps(tls.Server));
            options.Listen(IPAddress.Loopback, 0);
        });
        builder.Services.AddSingleton(admission); builder.Services.AddSingleton(proofs); builder.Services.AddSingleton(reopened);
        builder.Services.AddSingleton(TimeProvider.System);
        builder.Services.AddSingleton<IDeepIdV2GenesisAuthority>(admission);
        builder.Services.AddSingleton<DeepIdV2IssuanceAdmissionGate>();
        var controlAdmission = new MailboxRevocationDistributionAdmission();
        builder.Services.AddSingleton(controlAdmission);
        await using var app = builder.Build();
        var proofStatus = 0;
        app.Use((context, next) =>
        {
            if (context.Request.Path.Value == DeepIdV2DirectoryAuthorityHostingExtensions.ProofEndpointPath)
                context.Response.OnStarting(() => { Volatile.Write(ref proofStatus, context.Response.StatusCode); return Task.CompletedTask; });
            return next(context);
        });
        if (!socketControl) app.Use((context, next) =>
        {
            var feature = context.Features.Get<Microsoft.AspNetCore.Http.Features.IHttpRequestFeature>()!;
            // TestServer provides decoded Path/Query but no RawTarget. Supply
            // this transport field for ordinary canonical fixture requests;
            // this is not real-socket/escaped-target qualification.
            Assert.True(string.IsNullOrEmpty(feature.RawTarget), "TestServer raw-target behavior changed.");
            feature.RawTarget = context.Request.Path.Value + context.Request.QueryString.Value;
            return next(context);
        });
        app.MapDeepIdV2DirectoryAuthorityEndpoint(new(Enabled: true, ProofEnabled: true));
        app.MapMailboxRevocationDistribution(enabled: true); await app.StartAsync();
        using var http = tls is null ? app.GetTestClient() : tls.CreateClient();
        var addresses = socketControl ? app.Services.GetRequiredService<IServer>()
            .Features.Get<IServerAddressesFeature>()!.Addresses : [];
        http.BaseAddress = new Uri(socketControl ? addresses.Single(address => address.StartsWith("https://", StringComparison.Ordinal)) : "https://authority.example/");
        http.DefaultRequestHeaders.Accept.Add(new(MailboxRevocationDistributionHosting.MediaType));
        var controlPath = MailboxRevocationDistributionHosting.Prefix + "/" + Convert.ToHexString(network).ToLowerInvariant() +
            "/" + Convert.ToHexString(pma.CoreHash.Span).ToLowerInvariant() + "/1/";
        async Task RequireHttpReadinessAsync(bool ready)
        {
            using var response = await http.GetAsync(DeepIdV2DirectoryAuthorityHostingExtensions.ReadinessEndpointPath);
            Assert.Equal(ready ? HttpStatusCode.OK : HttpStatusCode.ServiceUnavailable, response.StatusCode);
        }
        await RequireHttpReadinessAsync(false); // Cold context is not authority.
        using (var cold = await http.GetAsync(controlPath + "latest")) Assert.Equal(HttpStatusCode.ServiceUnavailable, cold.StatusCode);
        await reopened.RefreshAsync(default);
        Assert.Equal(3, custody.Deposit.Inputs.Count); Assert.Equal(intent, custody.Deposit.Inputs[1]);
        Assert.Single(custody.Retrieve.Inputs);
        var historical = await reopened.ReadRetainedAsync(MailboxCapabilityDomain.Deposit, 1, default);
        Assert.Equal(intent, MailboxGrantRevocationV1Codec.Decode(historical.Span).SignatureInput.ToArray());
        var deposit = await reopened.ReadRetainedAsync(MailboxCapabilityDomain.Deposit, 2, default);
        var retrieve = await reopened.ReadRetainedAsync(MailboxCapabilityDomain.Retrieve, 1, default);
        await contexts.WithCurrentAsync(async (context, ct) =>
        {
            await Assert.ThrowsAsync<CryptographicException>(() => MailboxGrantRevocationV1Verifier.PlanInitialEnrollmentAsync(context.Host, historical, ct).AsTask());
            _ = await MailboxGrantRevocationV1Verifier.PlanAdvanceAsync(context.Host, historical, deposit, ct);
            _ = await MailboxGrantRevocationV1Verifier.PlanInitialEnrollmentAsync(context.Host, retrieve, ct); return true;
        }, default);
        var requestsRoot = Path.Combine(directory, "proof-nonces");
        var nonceCount = Directory.EnumerateFiles(requestsRoot, "*.request", SearchOption.AllDirectories).Count();
        if (socketControl)
        {
            using (var untrusted = tls!.CreateClient(trustRoot: false))
            {
                var failure = await Assert.ThrowsAsync<HttpRequestException>(() => untrusted.GetAsync(http.BaseAddress));
                Assert.Equal(HttpRequestError.SecureConnectionError, failure.HttpRequestError);
                Assert.Equal(nonceCount, Directory.EnumerateFiles(requestsRoot, "*.request", SearchOption.AllDirectories).Count());
            }
            // Actual configured node runtime, native verifier and protected head,
            // not a replacement proof source or a callback granting TLS trust.
            var node = new XNode.Core.RouterNodeOptions { DataDirectory = Path.Combine(directory, "socket-node") };
            var settings = new xnode::XNode.DeepIdV2DirectoryProofOptions
            {
                Enabled = true, RegistryOrigin = http.BaseAddress.AbsoluteUri,
                NetworkIdHex = Convert.ToHexString(network),
                GenesisAuthorityCoreHashHex = Convert.ToHexString(genesisPin.AuthorityCoreHash.Span),
                ExactAuthorityPaths = [Path.Combine(directory, "root.xna1")],
                ExactTimePolicyPaths = [Path.Combine(directory, "time.dts1")],
                GenesisHeadPath = Path.Combine(directory, "genesis.adh1"),
                GenesisHeadCoreHashHex = Convert.ToHexString(genesisHeadHash.Span),
                StateRelativeDirectory = "proof-head", DataProtectionKeysRelativeDirectory = "proof-keys",
                DeploymentProfileId = 1, RequestTimeoutSeconds = 5
            };
            using var runtime = new xnode::XNode.DeepIdV2DirectoryProofRuntime(settings.ValidateAndLoad(node, developmentOrUat: true)!,
                http, clock, new XNode.Core.Mailbox.MailboxStorageSecurity(), new XNode.Core.Mailbox.MailboxDurabilityBarrier());
            _ = await runtime.RestoreHeadAsync(default);
            VerifiedDeepIdV2DirectoryFreshness freshness;
            try { freshness = await runtime.ReadCurrentAsync(DeepIdV2Codec.DecodeDid2(observer.Span), default); }
            catch (InvalidDataException error) { throw new InvalidDataException($"Proof endpoint status: {Volatile.Read(ref proofStatus)}; transport status: {tls!.LastStatus}.", error); }
            Assert.NotNull(freshness.CurrentCheckpoint);
            Assert.True(freshness.IsCurrentAtMonotonic(clock.Boot, clock.Sample));
            Assert.Equal(nonceCount + 1, Directory.EnumerateFiles(requestsRoot, "*.request", SearchOption.AllDirectories).Count());
            for (var check = 0; check < 130; check++) await runtime.ValidateObservedAsync(freshness, default);
            var consumer = new xnode::XNode.HttpsMailboxGrantRevocationArtifactSource(http, http.BaseAddress.AbsoluteUri);
            Assert.Equal(deposit.ToArray(), (await consumer.FetchAsync(network, reference, MailboxCapabilityDomain.Deposit, null, default)).ToArray());
            Assert.Equal(historical.ToArray(), (await consumer.FetchAsync(network, reference, MailboxCapabilityDomain.Deposit, 1, default)).ToArray());
            Assert.Equal(retrieve.ToArray(), (await consumer.FetchAsync(network, reference, MailboxCapabilityDomain.Retrieve, 1, default)).ToArray());
            // Escaped RawTarget must not become the canonical route after Kestrel decoding.
            var escapedTarget = new Uri(http.BaseAddress.AbsoluteUri.TrimEnd('/') + controlPath + "%31",
                new UriCreationOptions { DangerousDisablePathAndQueryCanonicalization = true });
            using var escaped = await http.GetAsync(escapedTarget);
            Assert.Equal(HttpStatusCode.BadRequest, escaped.StatusCode);
            nonceCount++;
        }
        foreach (var (selector, expected) in new[] { ("1", historical), ("2", deposit), ("latest", deposit) })
        {
            using var response = await http.GetAsync(controlPath + selector);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(MailboxRevocationDistributionHosting.MediaType, response.Content.Headers.ContentType!.ToString());
            Assert.Equal(expected.Length, response.Content.Headers.ContentLength);
            Assert.True(response.Headers.CacheControl!.NoStore);
            Assert.Equal("nosniff", Assert.Single(response.Headers.GetValues("X-Content-Type-Options")));
            Assert.Equal(expected.ToArray(), await response.Content.ReadAsByteArrayAsync());
        }
        foreach (var bad in new[] { "0", "01", "1048577", "Latest", "1?alias=1" })
        {
            using var response = await http.GetAsync(controlPath + bad);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        }
        using (var missing = await http.GetAsync(controlPath + "3")) Assert.Equal(HttpStatusCode.ServiceUnavailable, missing.StatusCode);
        using (var foreign = await http.GetAsync(controlPath.Replace(Convert.ToHexString(network).ToLowerInvariant(), new string('f', 32)) + "1"))
            Assert.Equal(HttpStatusCode.ServiceUnavailable, foreign.StatusCode);
        var plainOrigin = socketControl ? addresses.Single(address => address.StartsWith("http://", StringComparison.Ordinal)) : "http://authority.example";
        using (var nonHttps = await http.GetAsync(plainOrigin.TrimEnd('/') + controlPath + "latest"))
            Assert.Equal(HttpStatusCode.Forbidden, nonHttps.StatusCode);
        using (var wrongRole = await http.GetAsync(controlPath.Replace("/1/", "/0/") + "latest"))
            Assert.Equal(HttpStatusCode.BadRequest, wrongRole.StatusCode);
        using (var bodyRequest = new HttpRequestMessage(HttpMethod.Get, controlPath + "latest") { Content = new ByteArrayContent([1]) })
        using (var badBody = await http.SendAsync(bodyRequest)) Assert.Equal(HttpStatusCode.BadRequest, badBody.StatusCode);
        Assert.True(controlAdmission.TryEnter());
        try { using var busy = await http.GetAsync(controlPath + "latest"); Assert.Equal(HttpStatusCode.TooManyRequests, busy.StatusCode); }
        finally { controlAdmission.Exit(); }
        for (var check = 0; check < 5; check++)
        { await reopened.RequireReadyAsync(default); await RequireHttpReadinessAsync(true); }
        Assert.Equal(nonceCount, Directory.EnumerateFiles(requestsRoot, "*.request", SearchOption.AllDirectories).Count());
        Assert.Equal(3, custody.Deposit.Inputs.Count); Assert.Single(custody.Retrieve.Inputs);
        await reopened.RefreshAsync(default); // Fresh unchanged ledger: no extra generation/signature.
        Assert.Equal(3, custody.Deposit.Inputs.Count); Assert.Single(custody.Retrieve.Inputs);

        // New cumulative revocation plus a source change during signing: exact
        // intent survives, but changed authority cannot release/commit a winner.
        var frame = await File.ReadAllBytesAsync(bundlePath);
        custody.Deposit.BeforeSign = async (_, ct) =>
        { var changed = frame.ToArray(); changed[^1] ^= 1; await File.WriteAllBytesAsync(bundlePath, changed, ct); };
        await contexts.WithCurrentAsync(async (context, ct) =>
        {
            var current = await context.ReadIntervalAsync(ct);
            using var journal = new MailboxRevocationJournal(scoped, network, reference, MailboxCapabilityDomain.Deposit,
                custody.Deposit.Ed25519PublicKey.Span);
            await Assert.ThrowsAsync<CryptographicException>(() => journal.GetOrIssueNextAsync(context.Host,
                [Bytes(16, 0x51)], context.GuardSigner(custody.Resolve(current.Policy, MailboxCapabilityDomain.Deposit)), ct).AsTask());
            // Restore the same valid test-owned bundle, not a new authority.
            await File.WriteAllBytesAsync(bundlePath, frame, ct); return true;
        }, default);
        var pending = custody.Deposit.Inputs[^1];
        await Assert.ThrowsAsync<IOException>(() => reopened.RequireReadyAsync(default).AsTask());
        await RequireHttpReadinessAsync(false);
        // A pending unsigned successor must not replace the last signed response.
        using (var response = await http.GetAsync(controlPath + "latest"))
        { Assert.Equal(HttpStatusCode.OK, response.StatusCode); Assert.Equal(deposit.ToArray(), await response.Content.ReadAsByteArrayAsync()); }
        custody.Deposit.BeforeSign = null;
        await reopened.RefreshAsync(default);
        Assert.Equal(pending, custody.Deposit.Inputs[^1]);
        var revoked = MailboxGrantRevocationV1Codec.Decode((await reopened.ReadRetainedAsync(MailboxCapabilityDomain.Deposit, 3, default)).Span);
        Assert.Equal(Bytes(16, 0x51), revoked.Field(11).ToArray());
        await reopened.RequireReadyAsync(default);

        if (socketControl)
            await ExerciseConfiguredNodeEnrollmentAsync(tls!, http.BaseAddress, clock, network, observer,
                genesisPin, genesisHeadHash, bundlePath, directory, pma.CoreHash,
                deposit, retrieve, revoked.CanonicalBytes);

        // Actual BackgroundService start/observe/stop, not a fake renewal loop.
        var requestsBeforeWorker = Directory.EnumerateFiles(requestsRoot, "*.request", SearchOption.AllDirectories).Count();
        using (var worker = new MailboxRevocationRenewalWorker(reopened, NullLogger<MailboxRevocationRenewalWorker>.Instance))
        {
            await worker.StartAsync(default);
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            while (Directory.EnumerateFiles(requestsRoot, "*.request", SearchOption.AllDirectories).Count() == requestsBeforeWorker)
                await Task.Delay(25, deadline.Token);
            // Wait for the same single-flight refresh to release its owner.
            while (true)
            {
                try { await reopened.RequireReadyAsync(deadline.Token); break; }
                catch (IOException) { await Task.Delay(25, deadline.Token); }
            }
            await worker.StopAsync(deadline.Token);
        }
        await Assert.ThrowsAsync<IOException>(() => reopened.RequireReadyAsync(default).AsTask());
        await RequireHttpReadinessAsync(false);
        using (var stopped = await http.GetAsync(controlPath + "latest")) Assert.Equal(HttpStatusCode.ServiceUnavailable, stopped.StatusCode);
        var afterStop = custody.Deposit.Inputs.Count + custody.Retrieve.Inputs.Count;
        await Assert.ThrowsAsync<IOException>(() => reopened.RefreshAsync(default).AsTask());
        Assert.Equal(afterStop, custody.Deposit.Inputs.Count + custody.Retrieve.Inputs.Count);
        var restarted = new MailboxRevocationAuthority(contexts, custody, scoped, network);
        await restarted.RefreshAsync(default); await restarted.RequireReadyAsync(default);
        Assert.Equal(afterStop, custody.Deposit.Inputs.Count + custody.Retrieve.Inputs.Count);
        Assert.Equal(revoked.CanonicalBytes.ToArray(), (await restarted.ReadRetainedAsync(MailboxCapabilityDomain.Deposit, 3, default)).ToArray());

        await using (var corrupt = new NpgsqlCommand("UPDATE deep_mailbox_revocation_snapshot SET exact_snapshot = " +
            "set_byte(exact_snapshot, octet_length(exact_snapshot)-1, get_byte(exact_snapshot, octet_length(exact_snapshot)-1) # 1) " +
            "WHERE role = 1 AND generation = 3", db)) await corrupt.ExecuteNonQueryAsync();
        await Assert.ThrowsAsync<CryptographicException>(() => restarted.RequireReadyAsync(default).AsTask());
        await Assert.ThrowsAsync<CryptographicException>(() => restarted.RefreshAsync(default).AsTask());
        Assert.Equal(afterStop, custody.Deposit.Inputs.Count + custody.Retrieve.Inputs.Count);
    }

    private static async Task ExerciseConfiguredNodeEnrollmentAsync(ControlSocketTls tls, Uri origin, Clock clock,
        byte[] network, ReadOnlyMemory<byte> observer, XPointNetworkGenesisPin genesisPin,
        ReadOnlyMemory<byte> genesisHeadHash, string bundlePath, string directory, ReadOnlyMemory<byte> pmaHash,
        ReadOnlyMemory<byte> deposit, ReadOnlyMemory<byte> retrieve, ReadOnlyMemory<byte> latestDeposit)
    {
        var node = new XNode.Core.RouterNodeOptions
        {
            DataDirectory = Path.Combine(directory, "native-socket-node"), RouterId = Convert.ToHexString(PublicKey(0x70)),
            Ed25519PrivateKey = Convert.ToHexString(Bytes(32, 0x70))
        };
        var security = new XNode.Core.Mailbox.MailboxStorageSecurity();
        var mailbox = new XNode.Core.Mailbox.ReplicatedMailboxOptions { Enabled = true };
        var custodyOptions = new xnode::XNode.CurrentMailboxCustodyOptions
        {
            NetworkIdHex = Convert.ToHexString(network).ToLowerInvariant(),
            MailboxAuthorityCoreHashHex = Convert.ToHexString(pmaHash.Span).ToLowerInvariant(),
            IndependentCustodyDirectory = Path.Combine(directory, "native-socket-custody"),
            DataProtectionKeysDirectory = Path.Combine(directory, "native-socket-keys")
        };
        var custody = custodyOptions.Validate(node, mailbox)!;
        var proof = new xnode::XNode.DeepIdV2DirectoryProofOptions
        {
            Enabled = true, RegistryOrigin = origin.AbsoluteUri, NetworkIdHex = Convert.ToHexString(network),
            GenesisAuthorityCoreHashHex = Convert.ToHexString(genesisPin.AuthorityCoreHash.Span),
            ExactAuthorityPaths = [Path.Combine(directory, "root.xna1")], ExactTimePolicyPaths = [Path.Combine(directory, "time.dts1")],
            GenesisHeadPath = Path.Combine(directory, "genesis.adh1"), GenesisHeadCoreHashHex = Convert.ToHexString(genesisHeadHash.Span),
            StateRelativeDirectory = "proof-head", DataProtectionKeysRelativeDirectory = "proof-keys", DeploymentProfileId = 1, RequestTimeoutSeconds = 5
        }.ValidateAndLoad(node, developmentOrUat: true)!;
        var observerPath = Path.Combine(directory, "native-socket-observer.did2");
        await File.WriteAllBytesAsync(observerPath, observer.ToArray());
        var placement = new xnode::XNode.DeepIdV2NetworkPlacementOptions
        { Enabled = true, PublicBundlePath = bundlePath, PublicObservationDid2Path = observerPath }
            .ValidateAndLoad(did2ProofEnabled: true, developmentOrUat: true)!;
        security.SecureDirectory(custodyOptions.DataProtectionKeysDirectory);
        var provisionServices = new ServiceCollection();
        provisionServices.AddDataProtection().PersistKeysToFileSystem(new DirectoryInfo(custodyOptions.DataProtectionKeysDirectory))
            .SetApplicationName(xnode::XNode.CurrentMailboxHostComposition.ProtectionApplication).DisableAutomaticKeyGeneration();
        using (var provision = provisionServices.BuildServiceProvider())
            provision.GetRequiredService<IKeyManager>().CreateNewKey(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(90));
        foreach (var key in Directory.GetFiles(custodyOptions.DataProtectionKeysDirectory)) security.SecureFile(key);
        ServiceProvider Open()
        {
            var services = new ServiceCollection(); services.AddLogging(logging => logging.ClearProviders());
            services.AddSingleton(node); services.AddSingleton(mailbox);
            services.AddSingleton<Deep.Protocol.DeepExtension.PrivacyRouting.IOnionMonotonicClock>(clock);
            services.AddSingleton<XNode.Core.Mailbox.IMailboxStorageSecurity>(security);
            services.AddSingleton<XNode.Core.Mailbox.IMailboxDurabilityBarrier, XNode.Core.Mailbox.MailboxDurabilityBarrier>();
            xnode::XNode.DeepIdV2DirectoryProofHostComposition.AddDeepIdV2DirectoryProof(services, proof);
            services.AddHttpClient("did2-directory-proof").ConfigurePrimaryHttpMessageHandler(() => tls.CreateHandler());
            xnode::XNode.DeepIdV2NetworkPlacementHostComposition.AddDeepIdV2NetworkPlacement(services, placement);
            xnode::XNode.CurrentMailboxHostComposition.AddCurrentMailboxHost(services, custody, node, mailbox);
            xnode::XNode.CurrentMailboxHostRecoveryComposition.AddCurrentMailboxHostRecovery(services);
            return services.BuildServiceProvider();
        }
        var requestsRoot = Path.Combine(directory, "proof-nonces");
        var before = Directory.EnumerateFiles(requestsRoot, "*.request", SearchOption.AllDirectories).Count();
        await using (var first = Open())
        {
            var receiver = first.GetRequiredService<xnode::XNode.CurrentMailboxReplicaReceiver>();
            await Assert.ThrowsAsync<CryptographicException>(() => receiver.InitializeHostAsync().AsTask());
            var recovery = first.GetRequiredService<xnode::XNode.CurrentMailboxHostRecovery>();
            await recovery.StartAsync(default);
            Assert.False((await recovery.CheckAsync()).Recovered);
            Assert.Equal(before, Directory.EnumerateFiles(requestsRoot, "*.request", SearchOption.AllDirectories).Count());
            Assert.Empty(Directory.GetFiles(custodyOptions.IndependentCustodyDirectory, "enrollment.bin", SearchOption.AllDirectories));
            using (var cancelled = new CancellationTokenSource())
            {
                cancelled.Cancel();
                await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                    xnode::XNode.CurrentMailboxEnrollmentCommand.EnrollConfiguredAsync(first, deposit, retrieve, cancelled.Token).AsTask());
            }
            await Assert.ThrowsAsync<ApplicationCoreFormatException>(() =>
                xnode::XNode.CurrentMailboxEnrollmentCommand.EnrollConfiguredAsync(first, new byte[1], retrieve, default).AsTask());
            Assert.Equal(before, Directory.EnumerateFiles(requestsRoot, "*.request", SearchOption.AllDirectories).Count());
            Assert.False(File.Exists(Path.Combine(node.DataDirectory, "proof-head", "latest.floor")));
            using var budget = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var callerDeposit = deposit.ToArray(); var callerRetrieve = retrieve.ToArray();
            clock.OnMonotonicRead = () => { Array.Clear(callerDeposit); Array.Clear(callerRetrieve); };
            try { await xnode::XNode.CurrentMailboxEnrollmentCommand.EnrollConfiguredAsync(first, callerDeposit, callerRetrieve, budget.Token); }
            finally { clock.OnMonotonicRead = null; }
            Assert.All(callerDeposit, value => Assert.Equal((byte)0, value));
            Assert.All(callerRetrieve, value => Assert.Equal((byte)0, value));
            Assert.Equal(before + 1, Directory.EnumerateFiles(requestsRoot, "*.request", SearchOption.AllDirectories).Count());
            await receiver.InitializeHostAsync();
            var admission = first.GetRequiredService<xnode::XNode.CurrentMailboxAdmission>();
            await admission.RefreshRevocationsAsync(first.GetRequiredService<xnode::XNode.IMailboxGrantRevocationArtifactSource>(), default);
            Assert.Equal(latestDeposit.ToArray(), (await first.GetRequiredKeyedService<xnode::XNode.FileMailboxGrantRevocationStore>(MailboxCapabilityDomain.Deposit).ReadProtectedAsync()).ToArray());
            Assert.Equal(retrieve.ToArray(), (await first.GetRequiredKeyedService<xnode::XNode.FileMailboxGrantRevocationStore>(MailboxCapabilityDomain.Retrieve).ReadProtectedAsync()).ToArray());
            await receiver.InitializeHostAsync();
            Assert.True((await recovery.CheckAsync()).Recovered);
            Assert.Equal(before + 1, Directory.EnumerateFiles(requestsRoot, "*.request", SearchOption.AllDirectories).Count());
            await recovery.StopAsync(default);
        }
        await using (var cold = Open())
        {
            var recovery = cold.GetRequiredService<xnode::XNode.CurrentMailboxHostRecovery>();
            await recovery.StartAsync(default);
            Assert.False((await recovery.CheckAsync()).Recovered);
            Assert.Equal(before + 1, Directory.EnumerateFiles(requestsRoot, "*.request", SearchOption.AllDirectories).Count());
            var source = cold.GetRequiredService<xnode::XNode.DeepIdV2NetworkPlacementRuntime>();
            await source.AcquireObservationAsync(default);
            Assert.True((await recovery.CheckAsync()).Recovered);
            Assert.Equal(latestDeposit.ToArray(), (await cold.GetRequiredKeyedService<xnode::XNode.FileMailboxGrantRevocationStore>(MailboxCapabilityDomain.Deposit).ReadProtectedAsync()).ToArray());
            Assert.Equal(retrieve.ToArray(), (await cold.GetRequiredKeyedService<xnode::XNode.FileMailboxGrantRevocationStore>(MailboxCapabilityDomain.Retrieve).ReadProtectedAsync()).ToArray());
            Assert.Equal(before + 2, Directory.EnumerateFiles(requestsRoot, "*.request", SearchOption.AllDirectories).Count());
            source.StopObservations();
            Assert.False((await recovery.CheckAsync()).Recovered);
            Assert.Equal(latestDeposit.ToArray(), (await cold.GetRequiredKeyedService<xnode::XNode.FileMailboxGrantRevocationStore>(MailboxCapabilityDomain.Deposit).ReadProtectedAsync()).ToArray());
            Assert.Equal(before + 2, Directory.EnumerateFiles(requestsRoot, "*.request", SearchOption.AllDirectories).Count());
            await recovery.StopAsync(default);
        }
        // Reuse the enrolled custody in the actual Program. No native endpoint,
        // authority source or hosted service is replaced. Only fixture time and
        // isolated TLS trust are supplied; Xray/heartbeat are explicitly disabled,
        // so this closes host composition, not carrier/physical qualification.
        var privacyKeyPath = Path.Combine(directory, "program-onion.key");
        await File.WriteAllTextAsync(privacyKeyPath, Convert.ToHexString(Bytes(32, 0xe0)).ToLowerInvariant());
        security.SecureFile(privacyKeyPath);
        var nextPrivacyKeyPath = Path.Combine(directory, "program-onion-next.key");
        await File.WriteAllTextAsync(nextPrivacyKeyPath, Convert.ToHexString(Bytes(32, 0xe8)).ToLowerInvariant());
        security.SecureFile(nextPrivacyKeyPath);
        var privacyProtectionPath = Path.Combine(directory, "program-onion-protection.key");
        await File.WriteAllBytesAsync(privacyProtectionPath, RandomNumberGenerator.GetBytes(32));
        security.SecureFile(privacyProtectionPath);
        var certificatePath = Path.Combine(directory, "program-tls.pfx");
        var certificateBytes = tls.Server.Export(X509ContentType.Pfx);
        try { await File.WriteAllBytesAsync(certificatePath, certificateBytes); }
        finally { CryptographicOperations.ZeroMemory(certificateBytes); }
        security.SecureFile(certificatePath);
        var reservations = Enumerable.Range(0, 3).Select(_ => new TcpListener(IPAddress.Loopback, 0)).ToArray();
        int[] ports;
        try
        {
            foreach (var listener in reservations) listener.Start();
            ports = reservations.Select(listener => ((IPEndPoint)listener.LocalEndpoint).Port).ToArray();
        }
        finally { foreach (var listener in reservations) listener.Stop(); }
        var settings = new Dictionary<string, string?>
        {
            ["Node:DataDirectory"] = node.DataDirectory, ["Node:RouterId"] = node.RouterId,
            ["Node:Ed25519PrivateKey"] = node.Ed25519PrivateKey,
            ["Node:ApiListenUrl"] = "http://127.0.0.1:" + ports[0],
            ["Node:PeerRpcListenUrl"] = "http://127.0.0.1:" + ports[1],
            ["Node:PrivacyPeerH2ListenUrl"] = "https://127.0.0.1:" + ports[2],
            ["Kestrel:Certificates:Default:Path"] = certificatePath,
            ["Vless:Enabled"] = "false", ["RegistryHeartbeat:Enabled"] = "false",
            ["Mailbox:Enabled"] = "true",
            ["CurrentMailboxCustody:NetworkIdHex"] = custodyOptions.NetworkIdHex,
            ["CurrentMailboxCustody:MailboxAuthorityCoreHashHex"] = custodyOptions.MailboxAuthorityCoreHashHex,
            ["CurrentMailboxCustody:IndependentCustodyDirectory"] = custodyOptions.IndependentCustodyDirectory,
            ["CurrentMailboxCustody:DataProtectionKeysDirectory"] = custodyOptions.DataProtectionKeysDirectory,
            ["DeepIdV2DirectoryProof:Enabled"] = "true",
            ["DeepIdV2DirectoryProof:RegistryOrigin"] = origin.AbsoluteUri,
            ["DeepIdV2DirectoryProof:NetworkIdHex"] = Convert.ToHexString(network),
            ["DeepIdV2DirectoryProof:GenesisAuthorityCoreHashHex"] = Convert.ToHexString(genesisPin.AuthorityCoreHash.Span),
            ["DeepIdV2DirectoryProof:ExactAuthorityPaths:0"] = Path.Combine(directory, "root.xna1"),
            ["DeepIdV2DirectoryProof:ExactTimePolicyPaths:0"] = Path.Combine(directory, "time.dts1"),
            ["DeepIdV2DirectoryProof:GenesisHeadPath"] = Path.Combine(directory, "genesis.adh1"),
            ["DeepIdV2DirectoryProof:GenesisHeadCoreHashHex"] = Convert.ToHexString(genesisHeadHash.Span),
            ["DeepIdV2DirectoryProof:StateRelativeDirectory"] = "proof-head",
            ["DeepIdV2DirectoryProof:DataProtectionKeysRelativeDirectory"] = "proof-keys",
            ["DeepIdV2DirectoryProof:DeploymentProfileId"] = "1",
            ["DeepIdV2DirectoryProof:RequestTimeoutSeconds"] = "5",
            ["DeepIdV2NetworkPlacement:Enabled"] = "true",
            ["DeepIdV2NetworkPlacement:PublicBundlePath"] = bundlePath,
            ["DeepIdV2NetworkPlacement:PublicObservationDid2Path"] = observerPath,
            ["PrivacyRouting:Enabled"] = "true",
            ["PrivacyRouting:X25519PrivateKeyPath"] = privacyKeyPath,
            ["PrivacyRouting:NextX25519PrivateKeyPath"] = nextPrivacyKeyPath,
            ["PrivacyRouting:StateProtectionKeyPath"] = privacyProtectionPath,
            ["PrivacyRouting:PublicPeerBaseUrl"] = "https://127.0.0.1:" + ports[2],
            ["PrivacyRouting:ReplayStateRelativePath"] = "program-onion/replay",
            ["PrivacyRouting:EntropyStateRelativePath"] = "program-onion/entropy",
            ["PrivacyRouting:KeyVaultDirectoryRelativePath"] = "program-onion/vault",
            ["PrivacyRouting:Peers:0:RouterId"] = Convert.ToHexString(PublicKey(0x71)).ToLowerInvariant(),
            ["PrivacyRouting:Peers:0:BaseUrl"] = "https://192.0.2.2/",
            ["PrivacyRouting:Peers:0:CurrentSpkiSha256"] = Convert.ToHexString(Bytes(32, 0xd1)).ToLowerInvariant(),
            ["PrivacyRouting:Peers:0:NextSpkiSha256"] = Convert.ToHexString(Bytes(32, 0xd9)).ToLowerInvariant()
        };
        var beforeProgram = Directory.EnumerateFiles(requestsRoot, "*.request", SearchOption.AllDirectories).Count();
        await using var program = new ConfiguredNodeProgram(settings, tls, clock);
        program.UseKestrel(); program.StartServer();
        Assert.True(program.Services.GetRequiredService<xnode::XNode.PrivacyRoutingRuntime>().ProductionCapabilityAvailable);
        Assert.Equal(beforeProgram + 1, Directory.EnumerateFiles(requestsRoot, "*.request", SearchOption.AllDirectories).Count());
        using var health = new HttpClient(new SocketsHttpHandler { UseProxy = false }) { Timeout = TimeSpan.FromSeconds(10) };
        var healthUri = new Uri("http://127.0.0.1:" + ports[0] + "/health/ready");
        using (var ready = await health.GetAsync(healthUri))
        {
            Assert.Equal(HttpStatusCode.OK, ready.StatusCode);
            using var json = JsonDocument.Parse(await ready.Content.ReadAsByteArrayAsync());
            Assert.True(json.RootElement.GetProperty("currentMailboxHost").GetProperty("recovered").GetBoolean());
            Assert.Equal("ready", json.RootElement.GetProperty("privacyRouting").GetString());
            Assert.Equal("disabled", json.RootElement.GetProperty("transportMode").GetString());
        }
        var sample = clock.Sample;
        try
        {
            clock.Sample = checked(sample - 1);
            using var unavailable = await health.GetAsync(healthUri);
            Assert.Equal(HttpStatusCode.ServiceUnavailable, unavailable.StatusCode);
            Assert.Equal(latestDeposit.ToArray(), (await program.Services.GetRequiredKeyedService<xnode::XNode.FileMailboxGrantRevocationStore>(MailboxCapabilityDomain.Deposit).ReadProtectedAsync()).ToArray());
            Assert.Equal(retrieve.ToArray(), (await program.Services.GetRequiredKeyedService<xnode::XNode.FileMailboxGrantRevocationStore>(MailboxCapabilityDomain.Retrieve).ReadProtectedAsync()).ToArray());
        }
        finally { clock.Sample = sample; }
        Assert.Equal(beforeProgram + 1, Directory.EnumerateFiles(requestsRoot, "*.request", SearchOption.AllDirectories).Count());
    }

    private sealed class ConfiguredNodeProgram(Dictionary<string, string?> settings, ControlSocketTls tls, Clock clock)
        : WebApplicationFactory<xnode::Program>
    {
        protected override IHost CreateHost(IHostBuilder builder)
        {
            builder.ConfigureHostConfiguration(configuration => configuration.AddInMemoryCollection(settings));
            return base.CreateHost(builder);
        }
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Development");
            builder.ConfigureLogging(logging => logging.ClearProviders());
            builder.ConfigureServices(services =>
            {
                services.Replace(ServiceDescriptor.Singleton<Deep.Protocol.DeepExtension.PrivacyRouting.IOnionMonotonicClock>(clock));
                services.AddHttpClient("did2-directory-proof").ConfigurePrimaryHttpMessageHandler(() => tls.CreateHandler());
            });
        }
    }

    // Test-owned PKI is confined to this client and the owned temporary Program
    // certificate file. Standard chain/validity/EKU/name checks remain enabled;
    // no OS trust import. Its fresh synthetic server key is exportable only to
    // supply the real Program's file-based listener configuration.
    private sealed class ControlSocketTls : IDisposable
    {
        private readonly X509Certificate2 root;
        internal int LastStatus;
        internal X509Certificate2 Server { get; }
        internal ControlSocketTls()
        {
            using var rootKey = RSA.Create(2048);
            var rootRequest = new CertificateRequest("CN=Deep isolated control test root", rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            rootRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
            root = rootRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
            using var serverKey = RSA.Create(2048);
            var request = new CertificateRequest("CN=localhost", serverKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var san = new SubjectAlternativeNameBuilder(); san.AddIpAddress(IPAddress.Loopback); request.CertificateExtensions.Add(san.Build());
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.1") }, true));
            using var signed = request.Create(root, DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddMinutes(30), RandomNumberGenerator.GetBytes(16));
            using var withKey = signed.CopyWithPrivateKey(serverKey);
            var pfx = withKey.Export(X509ContentType.Pfx);
            try { Server = X509CertificateLoader.LoadPkcs12(pfx, null,
                X509KeyStorageFlags.DefaultKeySet | X509KeyStorageFlags.Exportable); }
            finally { CryptographicOperations.ZeroMemory(pfx); }
        }
        internal SocketsHttpHandler CreateHandler(bool trustRoot = true)
        {
            var policy = new X509ChainPolicy { TrustMode = X509ChainTrustMode.CustomRootTrust, RevocationMode = X509RevocationMode.NoCheck };
            if (trustRoot) policy.CustomTrustStore.Add(root);
            var handler = new SocketsHttpHandler { AllowAutoRedirect = false, UseCookies = false, UseProxy = false, AutomaticDecompression = DecompressionMethods.None };
            handler.SslOptions.CertificateChainPolicy = policy;
            return handler;
        }
        internal HttpClient CreateClient(bool trustRoot = true) =>
            new(new StatusHandler(CreateHandler(trustRoot), this)) { Timeout = TimeSpan.FromSeconds(10) };
        private sealed class StatusHandler(HttpMessageHandler inner, ControlSocketTls owner) : DelegatingHandler(inner)
        {
            protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
            {
                var response = await base.SendAsync(request, ct);
                Volatile.Write(ref owner.LastStatus, (int)response.StatusCode);
                return response;
            }
        }
        public void Dispose() { Server.Dispose(); root.Dispose(); }
    }

    private sealed class MailboxTestCustody : IDeepIdV2MailboxGrantSignerCustody, IDisposable
    {
        internal readonly MailboxTestSigner Deposit = new(0x31), Retrieve = new(0x32);
        internal MailboxTestSigner For(MailboxCapabilityDomain role) => role == MailboxCapabilityDomain.Deposit ? Deposit : Retrieve;
        public IMailboxGrantIssuerSigner Resolve(VerifiedMailboxAuthorityV2 authority, MailboxCapabilityDomain role)
        {
            var signer = For(role); Assert.Equal(authority.ResolveIssuer(role).PublicKey.ToArray(), signer.Ed25519PublicKey.ToArray()); return signer;
        }
        public void Dispose() { Deposit.Dispose(); Retrieve.Dispose(); }
    }
    private sealed class MailboxTestSigner(byte marker) : IMailboxGrantIssuerSigner, IDisposable
    {
        private readonly KeyPair key = PublicKeyAuth.GenerateKeyPair(Bytes(32, marker));
        internal readonly List<byte[]> Inputs = [];
        internal Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask>? BeforeSign;
        public ReadOnlyMemory<byte> Ed25519PublicKey => key.PublicKey.ToArray();
        public async ValueTask<ReadOnlyMemory<byte>> SignAsync(ReadOnlyMemory<byte> bytes, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested(); Inputs.Add(bytes.ToArray());
            if (BeforeSign is { } action) await action(bytes, ct); ct.ThrowIfCancellationRequested();
            return PublicKeyAuth.SignDetached(bytes.ToArray(), key.PrivateKey);
        }
        public void Dispose() => CryptographicOperations.ZeroMemory(key.PrivateKey);
    }
}
#endif
