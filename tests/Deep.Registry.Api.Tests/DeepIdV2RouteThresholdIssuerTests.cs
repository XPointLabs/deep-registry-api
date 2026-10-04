#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Buffers.Binary;
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

public sealed partial class DeepIdV2RouteThresholdIssuerTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public Task ActualPqAccountAda2FloorWitnessCustodyAndJournalCloseOwnedRouteOverHttp(int crashMode) =>
        ExerciseRegistryCeremonyAsync(crashMode, mailboxLifecycle: false);

    private async Task ExerciseRegistryCeremonyAsync(int crashMode, bool mailboxLifecycle, bool socketControl = false)
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
            if (mailboxLifecycle)
            {
                await ExerciseMailboxLifecycleAsync(admission, proofs, rootSource, distribution, clock, db, scoped,
                    network, admissionRequest.Admission.ExactDid2, operational.ExactPma2, bundlePath, directory,
                    bootstrap.GenesisPin, genesis.CoreHash, socketControl);
                return;
            }
            using var journal = new DeepIdV2PostgreSqlRouteThresholdJournal(scoped, network);
            var countedCustody = new CountingRouteCustody(custody);
            var issuer = new ProductionContactRouteThresholdIssuer(proofs, rootSource, distribution, countedCustody, clock, journal);
            using var publicationJournal = new DeepIdV2PostgreSqlPublicationJournal(scoped, network);
            var countedPublication = new CountingPublicationCustody(custody);
            var publicationIssuer = new ProductionContactPublicationThresholdIssuer(proofs, rootSource, distribution, countedPublication, clock, publicationJournal);
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
                        Assert.Equal(ProtectedDid2ContactRouteJournal.Version, bytes[0]);
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
            downgraded[1] = 2;
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
                await Assert.ThrowsAsync<ContactPublicationAuthorityRejectedException>(async () => await journalRestart.GetOrIssueAsync(
                    ContactPublicationAuthorityWireCodec.DecodeRequest(substituted),
                    _ => throw new InvalidOperationException("Competing generation must not sign."), default));
                await using (var corruptProjection = new NpgsqlCommand("UPDATE deep_did2_publication_journal SET request_generation=$2 WHERE request_nonce=$1", db))
                {
                    corruptProjection.Parameters.Add(new() { Value = publicationExchange.Request!.RequestNonce.ToArray() });
                    corruptProjection.Parameters.Add(new() { Value = Enumerable.Repeat((byte)255, 8).ToArray() }); await corruptProjection.ExecuteNonQueryAsync();
                }
                await Assert.ThrowsAsync<InvalidDataException>(async () => await journalRestart.GetOrIssueAsync(publicationExchange.Request!,
                    _ => throw new InvalidOperationException("Corrupted projection must not sign."), default));
                await using (var restore = new NpgsqlCommand("UPDATE deep_did2_publication_journal SET request_generation=$2 WHERE request_nonce=$1", db))
                {
                    restore.Parameters.Add(new() { Value = publicationExchange.Request!.RequestNonce.ToArray() });
                    restore.Parameters.Add(new() { Value = new byte[8] }); await restore.ExecuteNonQueryAsync();
                }
                await using (var corruptMarker = new NpgsqlCommand("ALTER TABLE deep_did2_publication_journal_network DROP CONSTRAINT " +
                    "did2_publication_request_version_check; " +
                    "UPDATE deep_did2_publication_journal_network SET request_envelope_version=2", db)) await corruptMarker.ExecuteNonQueryAsync();
                await Assert.ThrowsAsync<InvalidDataException>(async () => await journalRestart.GetOrIssueAsync(publicationExchange.Request!,
                    _ => throw new InvalidOperationException("Unprovisioned marker must not sign."), default));
                await using (var restore = new NpgsqlCommand("UPDATE deep_did2_publication_journal_network SET request_envelope_version=4; " +
                    "ALTER TABLE deep_did2_publication_journal_network ADD CONSTRAINT " +
                    "did2_publication_request_version_check CHECK(request_envelope_version=4)", db)) await restore.ExecuteNonQueryAsync();
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
            // Independent actual PQ account/leaf: publication generation zero of
            // the earlier account cannot be replaced by another route/nonce.
            using var shortStorage = new InMemoryDeepSecureStorage();
            var shortDirectory = Path.Combine(directory, "publication-successor"); Directory.CreateDirectory(shortDirectory);
            var shortAccounts = new DeepIdV2AccountService(shortStorage, shortDirectory, network, 1,
                new FrozenClock(DateTimeOffset.FromUnixTimeSeconds(1_000)), DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess);
            await shortAccounts.CreateAsync("Real publication successor QA");
            var shortAdmission = DeepIdV2GenesisAdmissionWireCodec.DecodeRequest(await shortAccounts.PrepareGenesisAdmissionAsync());
            _ = await admission.AdmitAsync(shortAdmission);
            using var shortProofClient = new DeepIdV2DirectoryProofClient(new HttpServiceRequestTransport(
                new HttpClient(handler, false), DeepIdV2DirectoryProofClient.CreateTransportOptions("https://authority.example/"),
                HttpServiceEndpointPolicy.Production), new HttpServiceRequestTransport(new HttpClient(handler, false),
                DeepIdV2DirectoryProofClient.CreateHistoryTransportOptions("https://authority.example/"),
                HttpServiceEndpointPolicy.Production), clock, pq,
                await shortAccounts.OpenDirectoryLkgStoreAsync(bootstrap.Authority, genesis.ExactAdh1, genesis.CoreHash));
            var shortSource = new DeepIdV2ContactPathAuthoritySource(bootstrap.GenesisPin, shortAccounts, shortProofClient, closure,
                await shortAccounts.OpenNetworkLkgStoreAsync(bootstrap.GenesisPin), clock);
            var staged = await shortAccounts.EnsureOwnInitialPreKeyInventoryAsync(shortSource);
            var initial = await shortSource.VerifyForOwnPreKeyAuthoringAsync(shortAccounts, default);
            var currentCheckpoint = initial.Proof.CurrentCheckpoint!;
            var dca = DeepIdV2ContactAuthorizationCodec.Verify(DeepIdV2ContactAuthorizationCodec.Decode(staged.ExactDca1.Span),
                currentCheckpoint.Binding, currentCheckpoint.Directory);
            var recipient = DeepIdV2CurrentContactAuthorizationVerifier.Verify(initial.Proof, dca, clock.Boot, clock.Sample);
            using var device = await new ProtectedDeepIdV2GenesisDeviceSecretsStore(shortStorage, network,
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
            var resolverCapability = (await shortAccounts.GetCurrentAsync())!.PermanentId.ResolverReadCapability.ToArray();
            var services = new[] { DeepIdV2PreKeyServiceCodec.Decode(staged.ExactXps1.Span) };
            var shortObject = await DeepIdV2ContactObjectAuthor.AuthorGenesisAsync(shortRoute, device!, services,
                "Real publication successor QA", resolverCapability);
            var shortPublication = await DeepIdV2PublicationAuthorityAuthor.AuthorGenesisRequestAsync(shortRoute, shortObject,
                device!, Bytes(32, 0x81), Bytes(32, 0x82), Bytes(32, 0x83));
            var shortPublicationResponse = await publicationIssuer.IssueAsync(shortPublication.WireRequest, default);
            var shortXpo = PublicationResult(shortRoute, shortPublicationResponse.ExactXpu1, nodes);
            _ = await DeepIdV2PublicationCommitVerifier.VerifyCommittedAsync(shortRoute, shortObject,
                shortPublication.WireRequest, shortPublicationResponse.ExactXpu1, shortXpo);

            // DR89: two genuine independently encrypted invitations of the same
            // account/generation coexist with its reusable publication. Registry
            // sees only public locators, and exact lost-response retry never signs twice.
            var oneTimeRoute = await DeepIdV2ContactRouteAuthor.CompleteOneTimeGenesisAsync(recipient, initial.Network,
                initial.Authority, device!, shortAdvertisement.CanonicalBytes, Threshold(shortResponse), 2, routeTime);
            using var inviteA = await DeepIdV2ContactObjectAuthor.AuthorOneTimeGenesisAsync(oneTimeRoute, device!, services, "Invitation A QA");
            using var inviteB = await DeepIdV2ContactObjectAuthor.AuthorOneTimeGenesisAsync(oneTimeRoute, device!, services, "Invitation B QA");
            var publicationA = await DeepIdV2PublicationAuthorityAuthor.AuthorOneTimeGenesisRequestAsync(oneTimeRoute, inviteA,
                device!, Bytes(32, 0xa1), Bytes(32, 0xa2), Bytes(32, 0xa3));
            var publicationB = await DeepIdV2PublicationAuthorityAuthor.AuthorOneTimeGenesisRequestAsync(oneTimeRoute, inviteB,
                device!, Bytes(32, 0xa4), Bytes(32, 0xa5), Bytes(32, 0xa6));
            Assert.NotEqual(publicationA.WireRequest.LocatorHash.ToArray(), publicationB.WireRequest.LocatorHash.ToArray());
            var beforeInvitations = countedPublication.Calls;
            await Assert.ThrowsAsync<IOException>(async () => await publicationJournal.GetOrIssueAsync(publicationA.WireRequest,
                _ => throw new IOException("Lose one-time signing after durable scope reservation."), default));
            var pendingInviteConflict = SignPublicationCopy(publicationA.WireRequest, device!, recipient, Bytes(32, 0xa7));
            await Assert.ThrowsAsync<ContactPublicationAuthorityRejectedException>(async () => await publicationIssuer.IssueAsync(pendingInviteConflict, default));
            Assert.Equal(beforeInvitations, countedPublication.Calls);
            admissionTime.Advance(TimeSpan.FromSeconds(ContactResolveIssuanceAdmissionGate.WindowSeconds));
            var inviteExchange = new PublicationHttpExchange(client, admissionTime) { LoseFirstResponse = true };
            await Assert.ThrowsAsync<IOException>(async () => await inviteExchange.FetchAsync(publicationA.WireRequest, null!, default));
            var exactInviteWinner = await inviteExchange.FetchAsync(publicationA.WireRequest, null!, default);
            _ = await publicationA.VerifyResponseAsync(ContactPublicationAuthorityWireCodec.DecodeResponse(publicationA.WireRequest,
                exactInviteWinner.Span).ExactXpu1);
            var responseB = await publicationIssuer.IssueAsync(publicationB.WireRequest, default);
            _ = await publicationB.VerifyResponseAsync(responseB.ExactXpu1);
            Assert.Equal(beforeInvitations + 2, countedPublication.Calls);
            using (var inviteRestart = new DeepIdV2PostgreSqlPublicationJournal(scoped, network))
            {
                var neverInvite = new ProductionContactPublicationThresholdIssuer(proofs, rootSource, distribution,
                    new NeverSignPublicationCustody(), clock, inviteRestart);
                Assert.Equal(exactInviteWinner.ToArray(), ContactPublicationAuthorityWireCodec.EncodeResponse(publicationA.WireRequest,
                    await neverInvite.IssueAsync(publicationA.WireRequest, default)));
                var concurrentlyReplayed = await Task.WhenAll(Enumerable.Range(0, 6).Select(async _ =>
                    await inviteRestart.GetOrIssueAsync(publicationB.WireRequest,
                        _ => throw new InvalidOperationException("Concurrent exact replay must not sign."), default)));
                foreach (var replayed in concurrentlyReplayed)
                    Assert.Equal(ContactPublicationAuthorityWireCodec.EncodeResponse(publicationB.WireRequest, responseB), replayed.ToArray());
                await using (var corruptOneTimeScope = new NpgsqlCommand("UPDATE deep_did2_publication_journal SET locator_hash=$2 WHERE request_nonce=$1", db))
                {
                    corruptOneTimeScope.Parameters.Add(new() { Value = publicationB.WireRequest.RequestNonce.ToArray() });
                    corruptOneTimeScope.Parameters.Add(new() { Value = Bytes(32, 0xad) }); await corruptOneTimeScope.ExecuteNonQueryAsync();
                }
                await Assert.ThrowsAsync<InvalidDataException>(async () => await inviteRestart.GetOrIssueAsync(publicationB.WireRequest,
                    _ => throw new InvalidOperationException("Corrupted locator projection must not sign."), default));
                await using (var restore = new NpgsqlCommand("UPDATE deep_did2_publication_journal SET locator_hash=$2 WHERE request_nonce=$1", db))
                {
                    restore.Parameters.Add(new() { Value = publicationB.WireRequest.RequestNonce.ToArray() });
                    restore.Parameters.Add(new() { Value = publicationB.WireRequest.LocatorHash.ToArray() }); await restore.ExecuteNonQueryAsync();
                }
            }
            clock.Sample += 40; clock.UnixTime += 40;
            var renewed = await shortSource.VerifyForOwnPreKeyAuthoringAsync(shortAccounts, default);
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

            // DR79 joins current account, signed historical request/XPU, real
            // two-node crypto, PostgreSQL fence and authenticated TestServer HTTP.
            // Receipts are in-process results, NOT actual node persistence.
            var priorObject = await DeepIdV2ContactObjectAuthor.VerifyPredecessorAsync(recipient, renewed.Network,
                renewed.Authority, predecessor, shortObject.Closure.CanonicalBytes, shortObject.ProtectedDcr1, resolverCapability, routeTime);
            var priorPublication = await DeepIdV2PublicationCommitVerifier.VerifyPredecessorAsync(recipient, renewed.Network,
                renewed.Authority, priorObject, shortPublication.WireRequest, shortPublicationResponse.ExactXpu1, shortXpo, routeTime);
            var successorObject = await DeepIdV2ContactObjectAuthor.AuthorRetainedSuccessorAsync(successorRoute, issuance,
                priorObject, device!, services, "Real publication successor QA", resolverCapability);
            var successorPublication = await DeepIdV2PublicationAuthorityAuthor.AuthorSuccessorRequestAsync(successorRoute,
                successorObject, device!, priorPublication, Bytes(32, 0x84), Bytes(32, 0x85));
            var publicationCalls = countedPublication.Calls;
            var badReceipt = shortXpo.ToArray();
            var receiptOffset = 12;
            while (BinaryPrimitives.ReadUInt16BigEndian(badReceipt.AsSpan(receiptOffset)) != 19)
                receiptOffset += 8 + checked((int)BinaryPrimitives.ReadUInt32BigEndian(badReceipt.AsSpan(receiptOffset + 4)));
            badReceipt[receiptOffset + 8 + 192] ^= 1;
            var forgedPublication = SignPublicationCopy(successorPublication.WireRequest, device!, recipient,
                Bytes(32, 0x86), badReceipt);
            await Assert.ThrowsAsync<ContactPublicationAuthorityRejectedException>(async () => await publicationIssuer.IssueAsync(forgedPublication, default));
            Assert.Equal(publicationCalls, countedPublication.Calls);
            await using (var missing = new NpgsqlCommand("SELECT count(*) FROM deep_did2_publication_journal WHERE request_nonce=$1", db))
            { missing.Parameters.Add(new() { Value = forgedPublication.RequestNonce.ToArray() }); Assert.Equal(0L, await missing.ExecuteScalarAsync()); }
            admissionTime.Advance(TimeSpan.FromSeconds(ContactResolveIssuanceAdmissionGate.WindowSeconds));
            await Assert.ThrowsAsync<IOException>(async () => await publicationJournal.GetOrIssueAsync(successorPublication.WireRequest,
                _ => throw new IOException("Lose signing attempt after durable generation reservation."), default));
            var pendingCompetitor = SignPublicationCopy(successorPublication.WireRequest, device!, recipient, Bytes(32, 0x88));
            await Assert.ThrowsAsync<ContactPublicationAuthorityRejectedException>(async () => await publicationIssuer.IssueAsync(pendingCompetitor, default));
            Assert.Equal(publicationCalls, countedPublication.Calls);
            var publicationSuccessorExchange = new PublicationHttpExchange(client, admissionTime) { LoseFirstResponse = true };
            await Assert.ThrowsAsync<IOException>(async () => await publicationSuccessorExchange.FetchAsync(successorPublication.WireRequest, null!, default));
            var publicationWinner = await publicationSuccessorExchange.FetchAsync(successorPublication.WireRequest, null!, default);
            Assert.Equal(ContactPublicationAuthorityWireCodec.EncodeRequest(successorPublication.WireRequest),
                ContactPublicationAuthorityWireCodec.EncodeRequest(publicationSuccessorExchange.Request!));
            var successorPublicationResponse = ContactPublicationAuthorityWireCodec.DecodeResponse(successorPublication.WireRequest, publicationWinner.Span);
            _ = await DeepIdV2PublicationAuthorityAuthor.VerifySuccessorResponseAsync(successorRoute, successorPublication.WireRequest,
                priorPublication, successorPublicationResponse.ExactXpu1);
            Assert.Equal(publicationCalls + 1, countedPublication.Calls);
            var competingPublication = SignPublicationCopy(successorPublication.WireRequest, device!, recipient, Bytes(32, 0x87));
            await Assert.ThrowsAsync<ContactPublicationAuthorityRejectedException>(async () => await publicationIssuer.IssueAsync(competingPublication, default));
            Assert.Equal(publicationCalls + 1, countedPublication.Calls);
            using (var publicationJournalRestart = new DeepIdV2PostgreSqlPublicationJournal(scoped, network))
            {
                var neverPublication = new ProductionContactPublicationThresholdIssuer(proofs, rootSource, distribution,
                    new NeverSignPublicationCustody(), clock, publicationJournalRestart);
                Assert.Equal(publicationWinner.ToArray(), ContactPublicationAuthorityWireCodec.EncodeResponse(successorPublication.WireRequest,
                    await neverPublication.IssueAsync(successorPublication.WireRequest, default)));
                var history = await publicationJournalRestart.ReadCompletedPredecessorAsync(successorPublication.WireRequest, default);
                Assert.Equal(ContactPublicationAuthorityWireCodec.EncodeRequest(shortPublication.WireRequest), history.Request.ToArray());
                Assert.Equal(ContactPublicationAuthorityWireCodec.EncodeResponse(shortPublication.WireRequest, shortPublicationResponse), history.Response.ToArray());
            }
            var successorXpo = PublicationResult(successorRoute, successorPublicationResponse.ExactXpu1, nodes);
            Assert.Equal(1UL, (await DeepIdV2PublicationCommitVerifier.VerifyCommittedAsync(successorRoute, successorObject,
                successorPublication.WireRequest, successorPublicationResponse.ExactXpu1, successorXpo)).Generation);
            await using (var count = new NpgsqlCommand("SELECT entry_count FROM deep_did2_publication_journal_network WHERE network_id=$1", db))
            { count.Parameters.Add(new() { Value = network }); Assert.Equal(5L, await count.ExecuteScalarAsync()); }
            CryptographicOperations.ZeroMemory(resolverCapability);
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
            byte[] response;
            try
            {
                response = networkRequest ? closure : historyRequest
                    ? await issuer.ReadHistoryAsync(await request.Content!.ReadAsByteArrayAsync(ct), ct)
                    : await issuer.IssueWireAsync(DeepIdV2DirectoryProofWireCodec.DecodeRequest(await request.Content!.ReadAsByteArrayAsync(ct)), ct);
            }
            catch (CryptographicException) when (!networkRequest && !historyRequest)
            {
                // Match the real proof endpoint's unavailable translation. The
                // client must catch up through authenticated signed history;
                // do not inject a new floor or waive forward-proof verification.
                return new(HttpStatusCode.ServiceUnavailable) { Content = new ByteArrayContent([]), RequestMessage = request };
            }
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
    private sealed class CountingPublicationCustody(IContactPublicationAuthorityWitnessCustody source) : IContactPublicationAuthorityWitnessCustody
    {
        internal int Calls;
        public ValueTask<IReadOnlyList<IXpa1PublicationAuthorizationWitnessSigner>> GetPublicationSignersAsync(VerifiedXPointNetworkAuthority authority, CancellationToken ct)
        { Calls++; return source.GetPublicationSignersAsync(authority, ct); }
    }
    private sealed class NeverSignPublicationCustody : IContactPublicationAuthorityWitnessCustody
    {
        public ValueTask<IReadOnlyList<IXpa1PublicationAuthorizationWitnessSigner>> GetPublicationSignersAsync(VerifiedXPointNetworkAuthority authority, CancellationToken ct) =>
            throw new InvalidOperationException("Retained publication replay must never sign again.");
    }

    private static ContactPublicationAuthorityWireRequest SignPublicationCopy(ContactPublicationAuthorityWireRequest r,
        Deep.Protocol.Identity.OwnedGenesisDeviceSecrets device, DeepIdV2CurrentContactAuthorization recipient,
        byte[] nonce, byte[]? priorXpo = null)
    {
        var unsigned = Copy(r.PublisherSignature.Span);
        var signature = device.SignCurrentContactPublicationRequest(unsigned, recipient.Authorization);
        try { return Copy(signature); }
        finally { CryptographicOperations.ZeroMemory(signature); }
        ContactPublicationAuthorityWireRequest Copy(ReadOnlySpan<byte> sig) =>
            new(r.NetworkId.Span, nonce, r.DirectoryLookupKey.Span, r.MinimumAdh1Generation,
                r.MinimumAdh1CoreHash.Span, r.ExactDca1.Span, r.ExactDcr1.Span, r.ExactRouteClosure.Span,
                r.OperationId.Span, r.Generation, r.PredecessorObjectHash.Span, r.ObjectCiphertext.Span,
                r.IssuedAtUnixSeconds, r.ExpiresAtUnixSeconds, r.EffectiveExpiresAtUnixSeconds,
                r.OwnerRetrieveCapability.Span, sig, priorXpo ?? r.ExactPriorXpo1.ToArray(), r.OneTimeLocator.Span);
    }

    private static byte[] PublicationResult(VerifiedDeepIdV2ContactRouteClosure route, ReadOnlyMemory<byte> xpu, Signer[] nodes)
    {
        var request = Xpu1Codec.Decode(xpu.Span);
        var placement = ContactServicePlacementFactory.Create(route.Network, ContactServiceRequestKind.PublishInvite, request.LocatorHash);
        var next = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(next, checked(request.Generation + 1));
        var tuple = request.RequestHash.ToArray().Concat(request.ObjectCiphertextHash.ToArray()).Concat(next).ToArray();
        var input = ContactCodec.SignatureInput("Deep/ContactResolver/V1/publish-commit", tuple);
        var rows = new byte[193]; rows[0] = 2;
        var ids = placement.RankedReplicaNodeIds.OrderBy(id => Convert.ToHexString(id.Span), StringComparer.Ordinal).ToArray();
        for (var i = 0; i < 2; i++)
        {
            ids[i].Span.CopyTo(rows.AsSpan(1 + i * 96));
            nodes.Single(node => node.SignerId.Span.SequenceEqual(ids[i].Span)).SignReceipt(input).CopyTo(rows, 33 + i * 96);
        }
        var generation = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(generation, request.Generation);
        return Xpo1Codec.Encode(xpu.Span, Xpo1Status.Committed, ContactServiceMutationOutcome.DurablyCommitted,
            1_100, 0, ContactServicePaddingClass.Bytes1024, [generation, request.ObjectCiphertextHash, next, rows]);
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
        internal byte[] SignReceipt(byte[] input) => PublicKeyAuth.SignDetached(input, key.PrivateKey);
        public void Dispose() => CryptographicOperations.ZeroMemory(key.PrivateKey);
    }
    private static byte[] Bytes(int count, byte value) => Enumerable.Repeat(value, count).ToArray();
    private static byte[] PublicKey(byte marker)
    { var key = PublicKeyAuth.GenerateKeyPair(Bytes(32, marker)); try { return key.PublicKey.ToArray(); } finally { CryptographicOperations.ZeroMemory(key.PrivateKey); } }
}
#endif
