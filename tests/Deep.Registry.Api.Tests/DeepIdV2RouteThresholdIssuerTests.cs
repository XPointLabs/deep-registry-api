#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using Deep.Client.Shared.Persistence;
using Deep.Client.Shared.Persistence.DeviceV2;
using Deep.Client.Shared.Services;
using Deep.Client.Shared.Services.AccountDirectoryV2;
using Deep.Client.Shared.Services.ContactV2;
using Deep.Client.Shared.Services.XPointNetworkV1;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using Deep.Registry.Api.DirectoryPublication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Sodium;

namespace Deep.Registry.Api.Tests;

public sealed class DeepIdV2RouteThresholdIssuerTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public async Task ActualPqAccountAda2FloorWitnessCustodyAndJournalCloseOwnedRouteOverHttp(int crashMode)
    {
        // Real signatures/native verifier/SQLCipher/PostgreSQL; TestServer HTTP
        // and manually advanced test time, NOT physical devices or socket TLS.
        var database = Environment.GetEnvironmentVariable("DEEP_TEST_DID2_ROUTE_POSTGRES");
        Assert.False(string.IsNullOrWhiteSpace(database), "Set the isolated route-test database.");
        var schema = "did2_route_issuer_" + Guid.NewGuid().ToString("N");
        var scoped = new NpgsqlConnectionStringBuilder(database) { SearchPath = schema }.ConnectionString;
        var directory = Path.Combine(Path.GetTempPath(), "deep-route-issuer-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        await using var admin = new NpgsqlConnection(database);
        await admin.OpenAsync();
        await using (var create = new NpgsqlCommand($"CREATE SCHEMA \"{schema}\"", admin))
            await create.ExecuteNonQueryAsync();
        try
        {
            await using var db = new NpgsqlConnection(scoped);
            await db.OpenAsync();
            foreach (var name in new[] { "did2-latest-head-floor.sql", "did2-route-threshold-journal.sql", "did2-publication-journal.sql" })
            {
                await using var ddl = new NpgsqlCommand(await File.ReadAllTextAsync(
                    Path.Combine(AppContext.BaseDirectory, "Fixtures", name)), db);
                await ddl.ExecuteNonQueryAsync();
            }
            var network = Bytes(16, 0x11);
            using var root = new Signer(0x20);
            using var w1 = new Signer(0x30); using var w2 = new Signer(0x31); using var w3 = new Signer(0x32);
            Signer[] witnesses = [w1, w2, w3];
            using var n1 = new Signer(0x70); using var n2 = new Signer(0x71); using var n3 = new Signer(0x72);
            Signer[] nodes = [n1, n2, n3];
            var bootstrap = await XPointNetworkBootstrapAuthor.AuthorGenesisAsync(new(
                Bytes(32, 0x12), network,
                [new(root.RootKeyId.Span, 0, root.Ed25519PublicKey.Span, root.CustodyDomainHash.Span)], 1,
                witnesses.Select(w => new XPointNetworkBootstrapWitnessKey(w.SignerId.Span, 0,
                    w.Ed25519PublicKey.Span, w.FailureDomainHash.Span)).ToArray(), 2,
                [new(Bytes(32, 0x60), Bytes(32, 0x61), 1, "time1.invalid", 4460, Bytes(32, 0x62), 5),
                 new(Bytes(32, 0x63), Bytes(32, 0x64), 1, "time2.invalid", 4460, Bytes(32, 0x65), 5)],
                5, 10, 900, 900, 10_000, 900, 9_000, 1, 1), [root]);
            var descriptors = nodes.Select((node, i) => new XPointNetworkOperationalNode(node,
                Bytes(32, (byte)(0x80 + i)), Bytes(32, (byte)(0x90 + i)), Bytes(32, (byte)(0xa0 + i)),
                Bytes(32, (byte)(0xb0 + i)), (uint)(64_500 + i), 840, Bytes(32, (byte)(0xc0 + i)),
                IPAddress.Parse($"192.0.2.{i + 1}"), 443, Bytes(32, (byte)(0xd0 + i)),
                Bytes(32, (byte)(0xd8 + i)), ScalarMult.Base(Bytes(32, (byte)(0xe0 + i))),
                ScalarMult.Base(Bytes(32, (byte)(0xe8 + i))), Enumerable.Range(0, 5).Select(role =>
                    (ReadOnlyMemory<byte>)PublicKey((byte)(0x10 + i * 5 + role))).ToArray())).ToArray();
            var clock = new Clock();
            var pendingOperational = await XPointNetworkOperationalGenesisAuthor.AuthorNetworkCandidateAsync(new(
                Bytes(32, 0x12), bootstrap, [root], witnesses, descriptors, Bytes(32, 0xf1),
                Bytes(32, 0xf5), Bytes(32, 0xf6), PublicKey(0x31), PublicKey(0x32),
                990, 1_000, 1_500));
            var genesis = await DeepIdV2DirectoryHeadAuthor.AuthorGenesisAsync(bootstrap.Authority,
                990, 4_600, witnesses);
            var xnaPath = Path.Combine(directory, "root.xna1"); var dtsPath = Path.Combine(directory, "time.dts1");
            var headPath = Path.Combine(directory, "genesis.adh1"); var statePath = Path.Combine(directory, "state.ada2");
            var viewPath = Path.Combine(directory, "view.xnv1"); var bundlePath = Path.Combine(directory, "network.ncp2");
            await File.WriteAllBytesAsync(xnaPath, bootstrap.ExactXna1.ToArray());
            await File.WriteAllBytesAsync(dtsPath, bootstrap.ExactDts1.ToArray());
            await File.WriteAllBytesAsync(headPath, genesis.ExactAdh1.ToArray());
            await File.WriteAllBytesAsync(viewPath, pendingOperational.ExactXnv1.ToArray());
            var integrity = Bytes(32, 0x55);
            await File.WriteAllBytesAsync(statePath, DirectoryPublicationProtectedFile.Protect(
                DeepIdV2DirectoryStateCodec.Encode(network, new([new(genesis.ExactAdh1, genesis.CoreHash)], [], [])), integrity));
            var rootSource = new DeepIdV2XPointAuthoritySource(network, bootstrap.GenesisPin.AuthorityCoreHash.Span,
                [xnaPath], [dtsPath]);
            var headSource = new DeepIdV2DirectoryBootstrapSource(headPath, genesis.CoreHash.Span);
            using var floor = new DeepIdV2PostgreSqlLatestHeadFloor(scoped, network);
            await floor.ProvisionGenesisAsync(genesis.ProtectedHead);
            await using (var provision = new NpgsqlCommand("INSERT INTO deep_did2_route_journal_network " +
                             "(network_id, entry_count, maximum_entries) VALUES ($1, 0, 128)", db))
            { provision.Parameters.Add(new() { Value = network }); await provision.ExecuteNonQueryAsync(); }
            await using (var provision = new NpgsqlCommand("INSERT INTO deep_did2_publication_journal_network " +
                             "(network_id, entry_count, maximum_entries) VALUES ($1, 0, 128)", db))
            { provision.Parameters.Add(new() { Value = network }); await provision.ExecuteNonQueryAsync(); }
            var custodyOptions = new List<ContactResolveWitnessCustodyOptions>();
            foreach (var witness in witnesses)
            {
                var seedPath = Path.Combine(directory, "witness-" + witness.Marker + ".seed");
                await File.WriteAllBytesAsync(seedPath, Bytes(32, witness.Marker));
                custodyOptions.Add(new() { WitnessIdHex = Convert.ToHexString(witness.WitnessId.Span),
                    KeyGeneration = 0, Ed25519SeedPath = seedPath });
            }
            using var custody = new FileContactResolveDtt1WitnessCustody(network, custodyOptions);
            using var admission = new DeepIdV2DurableGenesisAuthority(rootSource, headSource, custody, clock,
                statePath, network, integrity, 1, 3_600, floor);
            using var storage = new InMemoryDeepSecureStorage();
            var accounts = new DeepIdV2AccountService(storage, directory, network, 1,
                new FrozenClock(DateTimeOffset.FromUnixTimeSeconds(1_000)), DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess);
            await accounts.CreateAsync("Real route QA");
            using var pq = DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess();
            var admissionRequest = DeepIdV2GenesisAdmissionWireCodec.DecodeRequest(await accounts.PrepareGenesisAdmissionAsync());
            var checkpoint = DeepIdV2GenesisAdmissionVerifier.Verify(admissionRequest.Admission, 1_000, 1, 2, pq);
            var admitted = await admission.AdmitAsync(admissionRequest);
            using var nonceLedger = new ProtectedFileContactResolveOneUseRequestLedger(
                Path.Combine(directory, "proof-nonces"), network, Bytes(32, 0x56));
            using var proofs = new DeepIdV2DirectoryProofIssuer(rootSource, headSource,
                new DeepIdV2FileCurrentViewSource(viewPath), custody, nonceLedger, clock,
                statePath, network, integrity, 1, floor);
            // DR70: signed candidate view precedes independently current DID2
            // proof; only that proof allows topology/network completion.
            var networkProof = await proofs.IssueAsync(new(network, Bytes(32, 0xf2), clock.Boot, clock.Sample,
                checkpoint.Checkpoint.DirectoryLeafKey.Span, genesis.ProtectedHead.LogGeneration, genesis.CoreHash.Span), default);
            var operational = await XPointNetworkOperationalGenesisAuthor.CompleteDid2Async(pendingOperational,
                networkProof.Freshness, new OnionTrustedTimeAuthority(clock));
            var networkBytes = XPointNetworkClosureWireCodec.EncodeResponse(network,
                [bootstrap.ExactXna1], [bootstrap.ExactDts1], [operational.ExactXvp1],
                [operational.ExactXnv1], [operational.ExactXnh1], operational.ExactXnd1,
                [operational.ExactPmt2], [operational.ExactPma2]);
            await File.WriteAllBytesAsync(bundlePath, networkBytes);
            using var distribution = new XPointNetworkClosureDistribution(new()
                { NetworkIdHex = Convert.ToHexString(network), BundlePath = bundlePath });
            using var journal = new DeepIdV2PostgreSqlRouteThresholdJournal(scoped, network);
            var countedCustody = new CountingRouteCustody(custody);
            var issuer = new ProductionContactRouteThresholdIssuer(proofs, rootSource, distribution, countedCustody, clock, journal);
            using var publicationJournal = new DeepIdV2PostgreSqlPublicationJournal(scoped, network);
            var publicationIssuer = new ProductionContactPublicationThresholdIssuer(proofs, rootSource, distribution, custody, clock, publicationJournal);
            var builder = WebApplication.CreateBuilder(); builder.WebHost.UseTestServer();
            builder.Services.AddSingleton<IContactRouteThresholdIssuer>(issuer);
            builder.Services.AddSingleton<IContactPublicationThresholdIssuer>(publicationIssuer);
            var admissionTime = new AdmissionClock();
            builder.Services.AddSingleton<TimeProvider>(admissionTime);
            builder.Services.AddSingleton<ContactResolveIssuanceAdmissionGate>();
            await using var app = builder.Build();
            app.MapContactRouteAuthorityEndpoint(new(network, PeerAuthenticationFixture.Access()));
            app.MapContactPublicationAuthorityEndpoint(new(network, PeerAuthenticationFixture.Access())); await app.StartAsync();
            using var client = app.GetTestClient(); client.BaseAddress = new Uri("https://authority.example/");
            using var handler = new DirectoryHandler(proofs, networkBytes);
            var accountFloor = await accounts.OpenDirectoryLkgStoreAsync(bootstrap.Authority, genesis.ExactAdh1, genesis.CoreHash);
            using var proofClient = new DeepIdV2DirectoryProofClient(new HttpServiceRequestTransport(
                new HttpClient(handler, false), DeepIdV2DirectoryProofClient.CreateTransportOptions("https://authority.example/"),
                HttpServiceEndpointPolicy.Production), new HttpServiceRequestTransport(new HttpClient(handler, false),
                DeepIdV2DirectoryProofClient.CreateHistoryTransportOptions("https://authority.example/"),
                HttpServiceEndpointPolicy.Production), clock, pq, accountFloor);
            using var closure = new HttpDeepIdV2NetworkClosureArtifactSource(new HttpServiceRequestTransport(
                new HttpClient(handler, false), HttpDeepIdV2NetworkClosureArtifactSource.CreateTransportOptions("https://authority.example/"),
                HttpServiceEndpointPolicy.Production));
            var source = new DeepIdV2ContactPathAuthoritySource(bootstrap.GenesisPin, accounts, proofClient, closure,
                await accounts.OpenNetworkLkgStoreAsync(bootstrap.GenesisPin), clock);
            var exchange = new RouteHttpExchange(client) { LoseFirstResponse = crashMode == 1 };
            var intent = Bytes(32, 0xd1); var config = new Did2ContactRouteConfiguration(100, 2, Bytes(32, 0xd2));
            if (crashMode != 0)
            {
                using (Did2ContactRouteTestHooks.Push(point =>
                { if (crashMode == 2 && point == Did2ContactRouteFailpoint.AfterThreshold) throw new IOException("Crash after exact issuance custody."); }))
                    await Assert.ThrowsAsync<IOException>(() => accounts.EnsureOwnContactRouteAsync(intent, source, config, exchange));
                var firstRequest = ContactRouteAuthorityWireCodec.EncodeRequest(exchange.Request!);
                var firstResponse = exchange.Response!.ToArray();
                var firstHead = ContactRouteAuthorityWireCodec.DecodeResponse(exchange.Request!, firstResponse).ExactIssuanceAdh1;
                Assert.Equal(admitted.ExactAdh1.ToArray(), firstHead.ToArray());
                Assert.Equal(1, countedCustody.Calls);
                using (var owned = await storage.ReadOwnedAsync(ProtectedDid2ContactRouteJournal.Slot, default))
                {
                    Assert.NotNull(owned);
                    owned.Use(bytes =>
                    {
                        Assert.Equal((byte)7, bytes[0]);
                        Assert.Equal(crashMode == 1 ? (byte)1 : (byte)2,
                            bytes[ProtectedDid2ContactRouteJournal.HeaderBytes + 4 + 32]);
                        return true;
                    });
                }
                // Real independent DID2 admission, ADA2 write and permanent
                // PostgreSQL floor advance, not a synthetic fresh proof/head.
                using var peerStorage = new InMemoryDeepSecureStorage();
                var peerDirectory = Path.Combine(directory, "head-advance-peer");
                Directory.CreateDirectory(peerDirectory);
                var peerAccounts = new DeepIdV2AccountService(peerStorage, peerDirectory, network, 1,
                    new FrozenClock(DateTimeOffset.FromUnixTimeSeconds(1_000)), DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess);
                await peerAccounts.CreateAsync("Independent head advance QA");
                var peerAdmission = DeepIdV2GenesisAdmissionWireCodec.DecodeRequest(await peerAccounts.PrepareGenesisAdmissionAsync());
                var advanced = await admission.AdmitAsync(peerAdmission);
                Assert.Equal(2UL, AccountDirectoryAdh1Codec.Decode(advanced.ExactAdh1.Span).LogGeneration);
                var recoveredRoute = await accounts.EnsureOwnContactRouteAsync(intent, source, config, exchange);
                await recoveredRoute.EnsureCurrentAsync();
                Assert.Equal(2UL, recoveredRoute.Recipient.Freshness.NextProtectedLkg.LogGeneration);
                Assert.Equal(firstRequest, ContactRouteAuthorityWireCodec.EncodeRequest(exchange.Request!));
                Assert.Equal(firstResponse, exchange.Response);
                Assert.Equal(1, countedCustody.Calls);
                using var replayJournal = new DeepIdV2PostgreSqlRouteThresholdJournal(scoped, network);
                var retainedReplay = new ProductionContactRouteThresholdIssuer(proofs, rootSource, distribution,
                    new NeverSignRouteCustody(), clock, replayJournal);
                Assert.Equal(firstResponse, ContactRouteAuthorityWireCodec.EncodeResponse(exchange.Request!,
                    await retainedReplay.IssueAsync(exchange.Request!, default)));
                if (crashMode == 1)
                {
                    // Retry used both slots. Begin a new scheduling window,
                    // then consume one genuine authenticated exact route replay
                    // so the publication admission assertions below stay exact.
                    admissionTime.Advance(TimeSpan.FromSeconds(ContactResolveIssuanceAdmissionGate.WindowSeconds));
                    using var body = new ByteArrayContent(firstRequest);
                    body.Headers.ContentType = MediaTypeHeaderValue.Parse(ContactRouteAuthorityWireCodec.RequestMediaType);
                    using var message = new HttpRequestMessage(HttpMethod.Post, ContactRouteAuthorityHostingExtensions.EndpointPath) { Content = body };
                    PeerAuthenticationFixture.Authenticate(message, network, ContactCoordinationTarget.Route, firstRequest,
                        admissionTime.GetUtcNow().ToUnixTimeMilliseconds());
                    using var replayResponse = await client.SendAsync(message);
                    Assert.Equal(HttpStatusCode.OK, replayResponse.StatusCode);
                    Assert.Equal(firstResponse, await replayResponse.Content.ReadAsByteArrayAsync());
                    Assert.Equal(1, countedCustody.Calls);
                }
            }
            var route = await accounts.EnsureOwnContactRouteAsync(Bytes(32, 0xd1), source,
                new(100, 2, Bytes(32, 0xd2)), exchange);
            await route.EnsureCurrentAsync();
            Assert.Equal(crashMode == 0 ? 1UL : 2UL, route.Recipient.Freshness.NextProtectedLkg.LogGeneration);
            Assert.NotNull(exchange.Request); Assert.NotNull(exchange.Response);
            var conflictingRoute = new ContactRouteAuthorityWireRequest(exchange.Request.NetworkId.Span,
                Bytes(32, 0xe1), exchange.Request.DirectoryLookupKey.Span, exchange.Request.MinimumAdh1Generation,
                exchange.Request.MinimumAdh1CoreHash.Span, exchange.Request.ExactDca1.Span, exchange.Request.ExactXra1.Span);
            var routeSignerCalls = countedCustody.Calls;
            // Genuine current DID2/device-signed XRA; only the coordination nonce
            // differs. The durable generation reservation rejects before custody.
            await Assert.ThrowsAsync<ContactRouteAuthorityRejectedException>(async () => await issuer.IssueAsync(conflictingRoute, default));
            Assert.Equal(routeSignerCalls, countedCustody.Calls);
            await using (var count = new NpgsqlCommand("SELECT entry_count FROM deep_did2_route_journal_network WHERE network_id=$1", db))
            { count.Parameters.Add(new() { Value = network }); Assert.Equal(1L, await count.ExecuteScalarAsync()); }
            var publicationExchange = new PublicationHttpExchange(client, admissionTime) { LoseFirstResponse = true };
            await Assert.ThrowsAsync<IOException>(() => accounts.EnsureOwnContactPublicationAsync(Bytes(32, 0xd1), source,
                new(100, 2, Bytes(32, 0xd2)), exchange, "Real route QA", publicationExchange));
            Assert.NotNull(publicationExchange.Request); Assert.NotNull(publicationExchange.Response);
            var firstPublicationRequest = ContactPublicationAuthorityWireCodec.EncodeRequest(publicationExchange.Request!);
            // Route + committed publication consume the shared source budget.
            // An immediate retry must remain throttled, preserving the exact
            // durable request. Advance only the test scheduling clock; never
            // remove the production limiter or invent signed authority time.
            await Assert.ThrowsAsync<RateLimitedTestException>(() => accounts.EnsureOwnContactPublicationAsync(Bytes(32, 0xd1), source,
                new(100, 2, Bytes(32, 0xd2)), exchange, "Real route QA", publicationExchange));
            Assert.Equal(firstPublicationRequest, ContactPublicationAuthorityWireCodec.EncodeRequest(publicationExchange.Request!));
            admissionTime.Advance(TimeSpan.FromSeconds(ContactResolveIssuanceAdmissionGate.WindowSeconds));
            var publication = await accounts.EnsureOwnContactPublicationAsync(Bytes(32, 0xd1), source,
                new(100, 2, Bytes(32, 0xd2)), exchange, "Real route QA", publicationExchange);
            Assert.Equal(firstPublicationRequest, ContactPublicationAuthorityWireCodec.EncodeRequest(publicationExchange.Request!));
            var publicationWire = ContactPublicationAuthorityWireCodec.DecodeResponse(publicationExchange.Request!, publicationExchange.Response!);
            Assert.Equal(publicationWire.ExactXpu1.ToArray(), publication.ExactXpu1.ToArray());
            Assert.Equal(3, publicationExchange.Calls);
            // Protected phase 6 returns exact verified winner without HTTP.
            var protectedReplay = await accounts.EnsureOwnContactPublicationAsync(Bytes(32, 0xd1), source,
                new(100, 2, Bytes(32, 0xd2)), exchange, "Real route QA", publicationExchange);
            Assert.Equal(publication.ExactXpu1.ToArray(), protectedReplay.ExactXpu1.ToArray()); Assert.Equal(3, publicationExchange.Calls);
            var publicationRestart = new ProductionContactPublicationThresholdIssuer(proofs, rootSource, distribution, custody, clock, publicationJournal);
            var publicationReplay = await publicationRestart.IssueAsync(publicationExchange.Request!, default);
            Assert.Equal(publicationExchange.Response, ContactPublicationAuthorityWireCodec.EncodeResponse(publicationExchange.Request!, publicationReplay));
            var substituted = firstPublicationRequest.ToArray(); substituted[24] ^= 1;
            await Assert.ThrowsAsync<ContactPublicationAuthorityRejectedException>(async () => await publicationRestart.IssueAsync(
                ContactPublicationAuthorityWireCodec.DecodeRequest(substituted), default));
            await using (var pending = new NpgsqlCommand("SELECT entry_count FROM deep_did2_publication_journal_network WHERE network_id = $1", db))
            { pending.Parameters.Add(new() { Value = network }); Assert.Equal(1L, await pending.ExecuteScalarAsync()); }
            var downgraded = firstPublicationRequest.ToArray(); downgraded[1] = 1;
            Assert.Throws<FormatException>(() => ContactPublicationAuthorityWireCodec.DecodeRequest(downgraded));
            var signingInput = ContactPublicationAuthorityWireCodec.CreatePublisherSigningInput(publicationExchange.Request!);
            Assert.NotEqual(signingInput, ContactPublicationAuthorityWireCodec.CreatePublisherSigningInput(
                ContactPublicationAuthorityWireCodec.DecodeRequest(substituted)));
            var opOffset = 609 + publicationExchange.Request!.ExactDcr1.Length + publicationExchange.Request.ExactRouteClosure.Length;
            var cipherOffset = opOffset + 76;
            foreach (var offset in new[] { 24, 56, 95, 96, opOffset, cipherOffset, firstPublicationRequest.Length - 96 })
            {
                var altered = firstPublicationRequest.ToArray(); altered[offset] ^= 1;
                Assert.NotEqual(signingInput, ContactPublicationAuthorityWireCodec.CreatePublisherSigningInput(
                    ContactPublicationAuthorityWireCodec.DecodeRequest(altered)));
            }
            foreach (var mode in Enumerable.Range(0, 5))
            {
                var malformed = firstPublicationRequest.ToArray();
                if (mode == 0) malformed[3] = 1;
                if (mode == 1) malformed[7] ^= 1;
                if (mode == 2) malformed = malformed[..^1];
                if (mode == 3) malformed = malformed.Append((byte)0).ToArray();
                if (mode == 4) malformed.AsSpan(601, 4).Fill(255);
                Assert.ThrowsAny<Exception>(() => ContactPublicationAuthorityWireCodec.DecodeRequest(malformed));
            }
            // Independent journal instances/connections replay one already
            // authenticated winner; this is not authority supplied by fixtures.
            using (var journalRestart = new DeepIdV2PostgreSqlPublicationJournal(scoped, network))
            {
                var concurrent = await Task.WhenAll(Enumerable.Range(0, 8).Select(async index =>
                    await journalRestart.GetOrIssueAsync(publicationExchange.Request!,
                        _ => throw new InvalidOperationException("Exact replay must not sign again."), default)));
                foreach (var exact in concurrent) Assert.Equal(publicationExchange.Response, exact.ToArray());
                var changedBody = firstPublicationRequest.ToArray(); changedBody[opOffset] ^= 1;
                await Assert.ThrowsAsync<ContactPublicationAuthorityRejectedException>(async () => await journalRestart.GetOrIssueAsync(
                    ContactPublicationAuthorityWireCodec.DecodeRequest(changedBody),
                    _ => throw new InvalidOperationException("Changed replay must not sign."), default));
            }
            foreach (var url in new[] { "http://authority.example/api/v2/contact-publication-authority", "https://authority.example/api/v2/contact-publication-authority?x=1" })
            {
                using var body = new ByteArrayContent(firstPublicationRequest);
                body.Headers.ContentType = MediaTypeHeaderValue.Parse(ContactPublicationAuthorityWireCodec.RequestMediaType);
                using var invalidHttp = await client.PostAsync(url, body);
                Assert.Equal(HttpStatusCode.BadRequest, invalidHttp.StatusCode);
                Assert.Empty(await invalidHttp.Content.ReadAsByteArrayAsync());
            }
            var restarted = new ProductionContactRouteThresholdIssuer(proofs, rootSource, distribution, custody, clock, journal);
            var replay = await restarted.IssueAsync(exchange.Request!, default);
            Assert.Equal(exchange.Response, ContactRouteAuthorityWireCodec.EncodeResponse(exchange.Request!, replay));
            var changed = new ContactRouteAuthorityWireRequest(network, exchange.Request!.RequestNonce.Span,
                exchange.Request.DirectoryLookupKey.Span, genesis.ProtectedHead.LogGeneration,
                genesis.CoreHash.Span, exchange.Request.ExactDca1.Span, exchange.Request.ExactXra1.Span);
            await Assert.ThrowsAsync<ContactRouteAuthorityRejectedException>(async () => await restarted.IssueAsync(changed, default));
            // Target the placement authority used by this route. PMA2 is now
            // the eighth chain, so corrupting the frame's final byte no longer
            // corrupts PMT2; mailbox-access verification is a separate owner.
            var corruptPlacement = operational.ExactPmt2.ToArray(); corruptPlacement[^1] ^= 1;
            var corrupt = XPointNetworkClosureWireCodec.EncodeResponse(network,
                [bootstrap.ExactXna1], [bootstrap.ExactDts1], [operational.ExactXvp1],
                [operational.ExactXnv1], [operational.ExactXnh1], operational.ExactXnd1,
                [corruptPlacement], [operational.ExactPma2]);
            await File.WriteAllBytesAsync(bundlePath, corrupt);
            await Assert.ThrowsAnyAsync<CryptographicException>(async () => await restarted.IssueAsync(exchange.Request!, default));
            await File.WriteAllBytesAsync(bundlePath, networkBytes);
            // Callback-time expiry/view tests need a genuinely new device-signed
            // advertisement lineage. Changing an old winner's nonce must now
            // reject earlier and cannot exercise the signing callback.
            var interruptedDraft = new RouteHttpExchange(client) { InterruptBeforeSend = true };
            await Assert.ThrowsAsync<IOException>(() => accounts.EnsureOwnContactRouteAsync(Bytes(32, 0xe3), source,
                new(100, 2, Bytes(32, 0xd2)), interruptedDraft));
            Assert.NotNull(interruptedDraft.Request);
            var interrupted = interruptedDraft.Request!;
            var late = new ProductionContactRouteThresholdIssuer(proofs, rootSource, distribution,
                new DelayedCustody(custody, () => { clock.Sample = 500; clock.UnixTime = 1_500; }), clock, journal);
            await Assert.ThrowsAsync<ContactRouteAuthorityRejectedException>(async () => await late.IssueAsync(interrupted, default));
            await using (var pending = new NpgsqlCommand("SELECT exact_response IS NULL FROM " +
                             "deep_did2_route_threshold_journal WHERE request_nonce = $1", db))
            { pending.Parameters.Add(new() { Value = interrupted.RequestNonce.ToArray() }); Assert.Equal(true, await pending.ExecuteScalarAsync()); }
            clock.Sample = 100; clock.UnixTime = 1_100; // Controlled test clock only.
            // The same pending exact reservation can fail twice and recover;
            // neither failure frees its generation or consumes another client
            // intent. Do not exceed protected pending capacity for a fixture.
            var changedViewRequest = interrupted;
            var changedView = operational.ExactXnv1.ToArray(); changedView[^1] ^= 1;
            var switchingView = new ProductionContactRouteThresholdIssuer(proofs, rootSource, distribution,
                new DelayedCustody(custody, () => File.WriteAllBytes(viewPath, changedView)), clock, journal);
            await Assert.ThrowsAsync<ContactRouteAuthorityRejectedException>(async () =>
                await switchingView.IssueAsync(changedViewRequest, default));
            await using (var pending = new NpgsqlCommand("SELECT exact_response IS NULL FROM " +
                             "deep_did2_route_threshold_journal WHERE request_nonce = $1", db))
            { pending.Parameters.Add(new() { Value = changedViewRequest.RequestNonce.ToArray() }); Assert.Equal(true, await pending.ExecuteScalarAsync()); }
            await File.WriteAllBytesAsync(viewPath, operational.ExactXnv1.ToArray());
            Assert.NotEmpty((await restarted.IssueAsync(changedViewRequest, default)).ExactXrc1.ToArray());

            // Connected DR77 renewal: a genuinely device-signed short route
            // expires, then the same PQ account independently proves current
            // authority and carries its exact authenticated history over HTTP.
            // This fixture does NOT claim protected successor adoption/device E2E.
            var staged = await accounts.EnsureOwnInitialPreKeyInventoryAsync(source);
            var initial = await source.VerifyForOwnPreKeyAuthoringAsync(accounts, default);
            var currentCheckpoint = initial.Proof.CurrentCheckpoint!;
            var dca = DeepIdV2ContactAuthorizationCodec.Verify(DeepIdV2ContactAuthorizationCodec.Decode(staged.ExactDca1.Span),
                currentCheckpoint.Binding, currentCheckpoint.Directory);
            var recipient = DeepIdV2CurrentContactAuthorizationVerifier.Verify(initial.Proof, dca, clock.Boot, clock.Sample);
            using var device = await new ProtectedDeepIdV2GenesisDeviceSecretsStore(storage, network,
                currentCheckpoint.Directory.Record.DeepAccountId.Span).ReadVerifiedAsync(
                    currentCheckpoint.Binding.Identity.ActiveDevices.Single(), default);
            var routeTime = new OnionTrustedTimeAuthority(clock);
            var expiry = initial.Proof.TrustedUpperUnixSeconds + 20;
            var shortAdvertisement = await DeepIdV2ContactRouteAuthor.AuthorAdvertisementAsync(recipient, initial.Network,
                initial.Authority, device!, 100, Bytes(32, 0x91), Bytes(32, 0x92), PublicKey(0x93),
                initial.Proof.TrustedLowerUnixSeconds, expiry, routeTime);
            var shortRequest = new ContactRouteAuthorityWireRequest(network, Bytes(32, 0x94), initial.Proof.QueriedDirectoryLeafKey.Span,
                initial.Proof.NextProtectedLkg.LogGeneration, initial.Proof.NextProtectedLkg.CoreHash.Span,
                staged.ExactDca1.Span, shortAdvertisement.CanonicalBytes.Span);
            var shortResponse = await issuer.IssueAsync(shortRequest, default);
            var shortIssuance = await DeepIdV2ContactRouteVerifier.VerifyRetainedThresholdAsync(recipient, initial.Network,
                initial.Authority, shortRequest, Threshold(shortResponse), shortResponse.ExactIssuanceAdh1, routeTime);
            var shortRoute = await DeepIdV2ContactRouteAuthor.CompleteRetainedGenesisAsync(recipient, initial.Network,
                initial.Authority, device!, shortIssuance, 2, routeTime);
            clock.Sample += 40; clock.UnixTime += 40;
            var renewed = await source.VerifyForOwnPreKeyAuthoringAsync(accounts, default);
            recipient = DeepIdV2CurrentContactAuthorizationVerifier.Verify(renewed.Proof, dca, clock.Boot, clock.Sample);
            await Assert.ThrowsAsync<CryptographicException>(async () => await shortRoute.EnsureCurrentAsync());
            var predecessor = await DeepIdV2ContactRouteVerifier.VerifyPredecessorAsync(recipient, renewed.Network,
                renewed.Authority, shortRoute.ExactXir1V2, shortRoute.ExactRouteClosure, routeTime);
            var successorAdvertisement = await DeepIdV2ContactRouteAuthor.AuthorAdvertisementSuccessorAsync(recipient, renewed.Network,
                renewed.Authority, device!, shortAdvertisement.CanonicalBytes, Bytes(32, 0x95), Bytes(32, 0x96),
                PublicKey(0x97), renewed.Proof.TrustedUpperUnixSeconds + 40, routeTime);
            var successorRequest = new ContactRouteAuthorityWireRequest(network, Bytes(32, 0x98), renewed.Proof.QueriedDirectoryLeafKey.Span,
                renewed.Proof.NextProtectedLkg.LogGeneration, renewed.Proof.NextProtectedLkg.CoreHash.Span,
                staged.ExactDca1.Span, successorAdvertisement.CanonicalBytes.Span,
                predecessor.ExactXir1V2.Span, predecessor.ExactRouteClosure.Span);
            var exactSuccessor = ContactRouteAuthorityWireCodec.EncodeRequest(successorRequest);
            Assert.True(exactSuccessor.Length > ContactRouteAuthorityWireCodec.MinimumRequestBytes);
            var beforeHostile = countedCustody.Calls;
            // A parsed full predecessor with one forged issuer signature must
            // fail before durable reservation or custody callbacks.
            var forgedInvite = predecessor.ExactXir1V2.ToArray();
            var cursor = 12;
            while (System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian(forgedInvite.AsSpan(cursor)) != 17)
                cursor += 8 + checked((int)System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(forgedInvite.AsSpan(cursor + 4)));
            forgedInvite[cursor + 8] ^= 1;
            var forgedRequest = new ContactRouteAuthorityWireRequest(network, Bytes(32, 0x99), successorRequest.DirectoryLookupKey.Span,
                successorRequest.MinimumAdh1Generation, successorRequest.MinimumAdh1CoreHash.Span, staged.ExactDca1.Span,
                successorAdvertisement.CanonicalBytes.Span, forgedInvite, predecessor.ExactRouteClosure.Span);
            await Assert.ThrowsAsync<ContactRouteAuthorityRejectedException>(async () => await issuer.IssueAsync(forgedRequest, default));
            Assert.Equal(beforeHostile, countedCustody.Calls);
            await using (var missing = new NpgsqlCommand("SELECT count(*) FROM deep_did2_route_threshold_journal WHERE request_nonce=$1", db))
            { missing.Parameters.Add(new() { Value = forgedRequest.RequestNonce.ToArray() }); Assert.Equal(0L, await missing.ExecuteScalarAsync()); }

            admissionTime.Advance(TimeSpan.FromSeconds(ContactResolveIssuanceAdmissionGate.WindowSeconds));
            var successorExchange = new RouteHttpExchange(client) { LoseFirstResponse = true };
            await Assert.ThrowsAsync<IOException>(async () => await successorExchange.FetchAsync(successorRequest, recipient,
                renewed.Network, renewed.Authority, routeTime, null!, default));
            var winner = await successorExchange.FetchAsync(successorRequest, recipient, renewed.Network,
                renewed.Authority, routeTime, null!, default);
            Assert.Equal(exactSuccessor, ContactRouteAuthorityWireCodec.EncodeRequest(successorExchange.Request!));
            var issuance = await DeepIdV2ContactRouteVerifier.VerifyRetainedThresholdAsync(recipient, renewed.Network,
                renewed.Authority, successorRequest, Threshold(winner), winner.ExactIssuanceAdh1, routeTime);
            var successorRoute = await DeepIdV2ContactRouteAuthor.CompleteRetainedSuccessorAsync(recipient, renewed.Network,
                renewed.Authority, device!, predecessor, issuance, 2, routeTime);
            await successorRoute.EnsureCurrentAsync();
            Assert.Equal(1UL, System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(successorRoute.Route.Route.Field(3).Span));
            Assert.Equal(shortRoute.Route.Route.CoreHash.ToArray(), successorRoute.Route.Route.Field(4).ToArray());
            Assert.Equal(shortRoute.Route.Route.Field(10).ToArray(), successorRoute.Route.Route.Field(10).ToArray());
            Assert.Equal(shortRoute.Invite.Field(2).ToArray(), successorRoute.Invite.Field(2).ToArray());
            Assert.Equal(beforeHostile + 1, countedCustody.Calls);
            var competingSuccessor = new ContactRouteAuthorityWireRequest(network, Bytes(32, 0x9a), successorRequest.DirectoryLookupKey.Span,
                successorRequest.MinimumAdh1Generation, successorRequest.MinimumAdh1CoreHash.Span, successorRequest.ExactDca1.Span,
                successorRequest.ExactXra1.Span, predecessor.ExactXir1V2.Span, predecessor.ExactRouteClosure.Span);
            await Assert.ThrowsAsync<ContactRouteAuthorityRejectedException>(async () => await restarted.IssueAsync(competingSuccessor, default));
            Assert.Equal(beforeHostile + 1, countedCustody.Calls);

            clock.UnixTime = 1_600; clock.Sample = 600;
            await Assert.ThrowsAnyAsync<CryptographicException>(async () => await restarted.IssueAsync(exchange.Request!, default));
            await Assert.ThrowsAnyAsync<CryptographicException>(async () => await publicationRestart.IssueAsync(publicationExchange.Request!, default));

            static ParsedDeepIdV2RouteThreshold Threshold(ContactRouteAuthorityWireResponse response) =>
                new(response.ExactPms2.Span, response.ExactXrc1.Span, response.ExactXss1.Span);
        }
        finally
        {
            await using var cleanup = new NpgsqlCommand($"DROP SCHEMA \"{schema}\" CASCADE", admin);
            await cleanup.ExecuteNonQueryAsync();
            Directory.Delete(directory, recursive: true); // Exact test-created directory only.
        }
    }

    private sealed class DirectoryHandler(DeepIdV2DirectoryProofIssuer issuer, byte[] closure) : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var networkRequest = request.RequestUri!.AbsolutePath == HttpDeepIdV2NetworkClosureArtifactSource.EndpointPath;
            var historyRequest = request.RequestUri.AbsolutePath == "/api/v2/account-directory/history";
            var response = networkRequest ? closure : historyRequest
                ? await issuer.ReadHistoryAsync(await request.Content!.ReadAsByteArrayAsync(ct), ct)
                : await issuer.IssueWireAsync(DeepIdV2DirectoryProofWireCodec.DecodeRequest(await request.Content!.ReadAsByteArrayAsync(ct)), ct);
            var result = new HttpResponseMessage(HttpStatusCode.OK)
                { Content = new ByteArrayContent(response), RequestMessage = request };
            result.Content.Headers.ContentType = MediaTypeHeaderValue.Parse(networkRequest ?
                XPointNetworkClosureWireCodec.ResponseMediaType : historyRequest
                    ? DeepIdV2DirectoryHistoryWireCodec.ResponseMediaType : DeepIdV2DirectoryProofWireCodec.ResponseMediaType);
            return result;
        }
    }
    private sealed class RateLimitedTestException : IOException;
    private sealed class AdmissionClock : TimeProvider
    {
        private DateTimeOffset now = DateTimeOffset.UtcNow;
        public override DateTimeOffset GetUtcNow() => now;
        internal void Advance(TimeSpan elapsed) => now += elapsed;
    }
    private sealed class PublicationHttpExchange(HttpClient client, TimeProvider admissionTime) : IDid2ContactPublicationSource
    {
        internal ContactPublicationAuthorityWireRequest? Request; internal byte[]? Response;
        internal bool LoseFirstResponse; internal int Calls;
        public async ValueTask<ReadOnlyMemory<byte>> FetchAsync(ContactPublicationAuthorityWireRequest request, Did2OwnedContactTransportContext operation, CancellationToken ct)
        {
            Calls++; Request = request;
            var exact = ContactPublicationAuthorityWireCodec.EncodeRequest(request);
            using var body = new ByteArrayContent(exact);
            body.Headers.ContentType = MediaTypeHeaderValue.Parse(ContactPublicationAuthorityWireCodec.RequestMediaType);
            using var message = new HttpRequestMessage(HttpMethod.Post, ContactPublicationAuthorityHostingExtensions.EndpointPath) { Content = body };
            PeerAuthenticationFixture.Authenticate(message, request.NetworkId.ToArray(), ContactCoordinationTarget.Publication, exact,
                admissionTime.GetUtcNow().ToUnixTimeMilliseconds());
            using var response = await client.SendAsync(message, ct);
            if (response.StatusCode == HttpStatusCode.TooManyRequests)
            {
                Assert.Equal(TimeSpan.FromSeconds(ContactResolveIssuanceAdmissionGate.WindowSeconds), response.Headers.RetryAfter?.Delta);
                Assert.Empty(await response.Content.ReadAsByteArrayAsync(ct));
                throw new RateLimitedTestException();
            }
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Response = await response.Content.ReadAsByteArrayAsync(ct);
            if (LoseFirstResponse) { LoseFirstResponse = false; throw new IOException("Deliberate committed response loss."); }
            return Response;
        }
    }

    private sealed class RouteHttpExchange(HttpClient client) : IDid2ContactRouteThresholdSource
    {
        internal ContactRouteAuthorityWireRequest? Request; internal byte[]? Response;
        internal bool LoseFirstResponse;
        internal bool InterruptBeforeSend;
        public async ValueTask<ContactRouteAuthorityWireResponse> FetchAsync(ContactRouteAuthorityWireRequest exactPendingRequest,
            DeepIdV2CurrentContactAuthorization auth, VerifiedOnionNetworkContext network,
            VerifiedXPointNetworkAuthority authority, OnionTrustedTimeAuthority time,
            Did2OwnedContactTransportContext operation, CancellationToken ct)
        {
            Did2ContactRouteRequestCustody.RequireCurrent(exactPendingRequest, auth, network);
            Request = exactPendingRequest;
            if (InterruptBeforeSend) throw new IOException("Capture genuine pending request before transport.");
            var exact = ContactRouteAuthorityWireCodec.EncodeRequest(Request);
            using var body = new ByteArrayContent(exact);
            body.Headers.ContentType = MediaTypeHeaderValue.Parse(ContactRouteAuthorityWireCodec.RequestMediaType);
            using var message = new HttpRequestMessage(HttpMethod.Post, ContactRouteAuthorityHostingExtensions.EndpointPath) { Content = body };
            PeerAuthenticationFixture.Authenticate(message, authority.NetworkId.ToArray(), ContactCoordinationTarget.Route, exact);
            using var response = await client.SendAsync(message, ct);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Response = await response.Content.ReadAsByteArrayAsync(ct);
            if (LoseFirstResponse) { LoseFirstResponse = false; throw new IOException("Lose signed route response before adoption."); }
            return ContactRouteAuthorityWireCodec.DecodeResponse(Request, Response);
        }
    }
    private sealed class CountingRouteCustody(IContactRouteAuthorityWitnessCustody source) : IContactRouteAuthorityWitnessCustody
    {
        internal int Calls;
        public ValueTask<IReadOnlyList<IContactRouteAuthorityWitnessSigner>> GetRouteSignersAsync(VerifiedXPointNetworkAuthority authority, CancellationToken ct)
        { Calls++; return source.GetRouteSignersAsync(authority, ct); }
    }
    private sealed class NeverSignRouteCustody : IContactRouteAuthorityWitnessCustody
    {
        public ValueTask<IReadOnlyList<IContactRouteAuthorityWitnessSigner>> GetRouteSignersAsync(VerifiedXPointNetworkAuthority authority, CancellationToken ct) =>
            throw new InvalidOperationException("Retained issuance replay must never sign again.");
    }
    private sealed class Clock : IContactResolveTrustedTimeContextSource, IOnionMonotonicClock
    {
        internal byte[] Boot { get; } = Bytes(16, 0xf3);
        internal ulong UnixTime { get; set; } = 1_100;
        internal ulong Sample { get; set; } = 100;
        ValueTask<ContactResolveTrustedTimeContext> IContactResolveTrustedTimeContextSource.ReadAsync(CancellationToken ct)
        { ct.ThrowIfCancellationRequested(); return ValueTask.FromResult(new ContactResolveTrustedTimeContext(Boot, Sample, UnixTime, 5)); }
        public ValueTask<OnionMonotonicReading> ReadAsync(CancellationToken ct)
        { ct.ThrowIfCancellationRequested(); return ValueTask.FromResult(new OnionMonotonicReading(Boot, Sample)); }
    }
    private sealed class DelayedCustody(IContactRouteAuthorityWitnessCustody source, Action delay) : IContactRouteAuthorityWitnessCustody
    {
        public async ValueTask<IReadOnlyList<IContactRouteAuthorityWitnessSigner>> GetRouteSignersAsync(
            VerifiedXPointNetworkAuthority authority, CancellationToken ct) =>
            (await source.GetRouteSignersAsync(authority, ct)).Select(s =>
                (IContactRouteAuthorityWitnessSigner)new DelayedSigner(s, delay)).ToArray();
    }
    private sealed class DelayedSigner(IContactRouteAuthorityWitnessSigner source, Action delay) : IContactRouteAuthorityWitnessSigner
    {
        public ReadOnlyMemory<byte> WitnessId => source.WitnessId;
        public async ValueTask<int> SignAsync(ContactRouteAuthoritySigningRequest request,
            Memory<byte> signature64, CancellationToken ct)
        { var result = await source.SignAsync(request, signature64, ct); delay(); return result; }
    }
    private sealed class Signer : IDisposable, IXPointNetworkBootstrapRootSigner,
        IXPointNetworkWitnessSigner, IAccountDirectoryAdh1WitnessSigner
    {
        private readonly KeyPair key;
        internal byte Marker { get; }
        internal Signer(byte marker) { Marker = marker; key = PublicKeyAuth.GenerateKeyPair(Bytes(32, marker)); }
        public ReadOnlyMemory<byte> RootKeyId => Bytes(32, Marker);
        public ReadOnlyMemory<byte> SignerId => Marker >= 0x70 ? key.PublicKey : RootKeyId;
        public ReadOnlyMemory<byte> WitnessId => SignerId;
        public ulong KeyGeneration => 0;
        public ReadOnlyMemory<byte> Ed25519PublicKey => key.PublicKey;
        public ReadOnlyMemory<byte> CustodyDomainHash => Bytes(32, (byte)(Marker + 0x40));
        public ReadOnlyMemory<byte> FailureDomainHash => CustodyDomainHash;
        public ValueTask<int> SignAsync(XPointNetworkRootSigningRequest request, Memory<byte> signature, CancellationToken ct) =>
            Sign(request.SigningInput, signature, ct);
        public ValueTask<int> SignAsync(XPointNetworkOperationalSigningRequest request, Memory<byte> signature, CancellationToken ct) =>
            Sign(request.SigningInput, signature, ct);
        private ValueTask<int> Sign(ReadOnlyMemory<byte> input, Memory<byte> destination, CancellationToken ct)
        { ct.ThrowIfCancellationRequested(); PublicKeyAuth.SignDetached(input.ToArray(), key.PrivateKey).CopyTo(destination); return ValueTask.FromResult(64); }
        public ValueTask<ReadOnlyMemory<byte>> SignAdh1Async(ReadOnlyMemory<byte> input, CancellationToken ct)
        { ct.ThrowIfCancellationRequested(); return ValueTask.FromResult<ReadOnlyMemory<byte>>(PublicKeyAuth.SignDetached(input.ToArray(), key.PrivateKey)); }
        public ValueTask<ReadOnlyMemory<byte>> SignDtt1Async(ReadOnlyMemory<byte> input, CancellationToken ct) => SignAdh1Async(input, ct);
        public void Dispose() => CryptographicOperations.ZeroMemory(key.PrivateKey);
    }
    private static byte[] Bytes(int count, byte value) => Enumerable.Repeat(value, count).ToArray();
    private static byte[] PublicKey(byte marker)
    { var key = PublicKeyAuth.GenerateKeyPair(Bytes(32, marker)); try { return key.PublicKey.ToArray(); } finally { CryptographicOperations.ZeroMemory(key.PrivateKey); } }
}
#endif
