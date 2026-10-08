#if DEEP_PROTOCOL_DIRECTORY_V1
extern alias xnode;
using System.Buffers.Binary;
using System.Net;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.XPointNetworkV1;
using Deep.Registry.Api.DirectoryPublication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Npgsql;
using Sodium;

namespace Deep.Registry.Api.Tests;

public sealed partial class DeepIdV2RouteThresholdIssuerTests
{
    [Fact]
    public Task ActualPrivateIssuerHttpsForwarderClientVerifierAndConfiguredNativeMailboxCycle() =>
        ExerciseRegistryCeremonyAsync(0, mailboxLifecycle: false, grantExchange: true);

    // Actual Registry issuer/journal, compiled XNode HTTPS forwarder and independent
    // client verifier. The route comes from the real PQ account ceremony. Replica
    // attestations and holder custody are test-owned: this is NOT resolver storage,
    // owned client dispatch, ONION or device E2E. The continuation uses actual
    // configured/native Store/Retrieve/ACK, including real peer TLS/H2.
    private async Task ExercisePrivateGrantExchangeAsync(VerifiedDeepIdV2ContactRouteClosure route,
        DeepIdV2DurableGenesisAuthority admission, DeepIdV2DirectoryProofIssuer proofs, DeepIdV2XPointAuthoritySource roots,
        XPointNetworkClosureDistribution distribution, Clock clock, NpgsqlConnection db, string scoped,
        byte[] network, ReadOnlyMemory<byte> observer, ReadOnlyMemory<byte> exactPma, Signer[] nodes,
        GrantPeerLayout peers, string directory, string bundlePath, XPointNetworkGenesisPin genesisPin,
        ReadOnlyMemory<byte> genesisHeadHash, bool retainedExchange = false)
    {
        await using (var ddl = new NpgsqlCommand(await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory,
            "Fixtures", "did2-mailbox-grant-journal.sql")), db)) await ddl.ExecuteNonQueryAsync();
        await using (var provision = new NpgsqlCommand("INSERT INTO deep_did2_grant_journal_network VALUES ($1,0,$2)", db))
        {
            provision.Parameters.Add(new() { Value = network });
            provision.Parameters.Add(new() { Value = retainedExchange ? 3L : 2L }); await provision.ExecuteNonQueryAsync();
        }
        using var journal = new DeepIdV2PostgreSqlMailboxGrantJournal(scoped, network);
        using var custody = new MailboxTestCustody();
        var contexts = new DeepIdV2MailboxAuthorityContextSource(proofs, roots, distribution, clock,
            DeepIdV2Codec.DecodeDid2(observer.Span));
        var issuer = new DeepIdV2MailboxGrantIssuer(contexts, journal, custody, new());
        using var revocationCustody = new MailboxTestCustody();
        var revocations = await ProvisionGrantRevocationsAsync(contexts, revocationCustody, db, scoped, network, exactPma);
        using var tls = new ControlSocketTls();
        var builder = WebApplication.CreateBuilder(); builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(options => options.Listen(IPAddress.Loopback, 0,
            listen => listen.UseHttps(tls.Server)));
        builder.Services.AddSingleton(issuer); builder.Services.AddSingleton<DeepIdV2MailboxGrantAdmission>();
        builder.Services.AddSingleton(revocations);
        builder.Services.AddSingleton<MailboxRevocationDistributionAdmission>();
        builder.Services.AddSingleton(admission); builder.Services.AddSingleton<IDeepIdV2GenesisAuthority>(admission);
        builder.Services.AddSingleton(proofs); builder.Services.AddSingleton<DeepIdV2IssuanceAdmissionGate>();
        builder.Services.AddSingleton(TimeProvider.System);
        await using var app = builder.Build(); app.MapDeepIdV2MailboxGrants(enabled: true);
        app.MapDeepIdV2DirectoryAuthorityEndpoint(new(Enabled: true, ProofEnabled: true)); await app.StartAsync();
        var origin = new Uri(app.Services.GetRequiredService<IServer>().Features
            .Get<IServerAddressesFeature>()!.Addresses.Single());
        using var http = tls.CreateClient();
        using var holder = new GrantHolder();
        var authored = await DeepIdV2MailboxGrantRequestAuthor.AuthorDepositAsync(route, Bytes(32, 0x49), holder);
        var placement = ContactServicePlacementFactory.Create(route.Network, ContactServiceRequestKind.ResolveInvite,
            authored.Record.Field(3));
        var effective = BinaryPrimitives.ReadUInt64BigEndian(route.Route.Reachability.Field(17).Span);
        var tuple = MailboxGrantRouteEvidenceAuthentication.CreateTuple(SHA256.HashData(authored.ExactXmg2.Span),
            authored.Record.Field(3).Span, MailboxGrantCapabilityDigest.Compute(authored.Record.Field(4).Span, authored.Domain),
            (byte)authored.Domain, 1, route.Route.ExactHash.Span, effective);
        var signing = MailboxGrantRouteEvidenceAuthentication.GetSigningBytes(tuple);
        var evidence = placement.RankedReplicaNodeIds.Select(id =>
        {
            var signer = nodes.Single(node => node.SignerId.Span.SequenceEqual(id.Span));
            return new xnode::XNode.MailboxGrantReplicaEvidence(id, signer.SignReceipt(signing));
        }).ToArray();
        var forwarder = nodes.Single(node => node.SignerId.Span.SequenceEqual(placement.RankedReplicaNodeIds[0].Span));
        var nodeOptions = new XNode.Core.RouterNodeOptions
        {
            RouterId = Convert.ToHexString(forwarder.SignerId.Span),
            Ed25519PrivateKey = Convert.ToHexString(Bytes(32, forwarder.Marker))
        };
        var client = new xnode::XNode.HttpsMailboxGrantAuthorityClient(http, nodeOptions, origin, new GrantClock(clock));
        var request = new xnode::XNode.MailboxGrantAuthorityRequest(placement, authored.ExactXmg2,
            MailboxGrantAcquisitionResultCode.Success, route.ExactRouteClosure, 1, effective,
            BinaryPrimitives.ReadUInt64BigEndian(authored.Record.Field(10).Span), evidence,
            xnode::XNode.MailboxGrantAuthorityEvidenceKind.CurrentRoute, 0);
        using (var untrusted = tls.CreateClient(trustRoot: false))
        {
            var refused = new xnode::XNode.HttpsMailboxGrantAuthorityClient(untrusted, nodeOptions, origin, new GrantClock(clock));
            await Assert.ThrowsAsync<xnode::XNode.ContactServiceUnavailableException>(async () =>
                await refused.AuthorizeAsync(request, default));
        }
        var corrupted = evidence[0].Signature.ToArray(); corrupted[^1] ^= 1;
        await Assert.ThrowsAsync<xnode::XNode.ContactServiceUnavailableException>(async () => await client.AuthorizeAsync(
            request with { ReplicaEvidence = [new(evidence[0].ReplicaId, corrupted), evidence[1]] }, default));
        // Valid holder and BOTH valid replica signatures still cannot substitute
        // another exact route intent before reservation or role-key callbacks.
        var wrongIntentBytes = authored.ExactXmg2.ToArray();
        Assert.Equal(435, wrongIntentBytes.Length);
        Bytes(32, 0xad).CopyTo(wrongIntentBytes, 331);
        var wrongIntent = ContactCodec.Decode("XMG2", wrongIntentBytes);
        var wrongIntentProof = new byte[64];
        await holder.SignMailboxGrantRequestAsync(wrongIntent.SignatureInput, wrongIntentProof, default);
        wrongIntentProof.CopyTo(wrongIntentBytes, 371);
        ContactCodec.VerifyMailboxGrantHolderSignature(ContactCodec.Decode("XMG2", wrongIntentBytes));
        var wrongTuple = MailboxGrantRouteEvidenceAuthentication.CreateTuple(SHA256.HashData(wrongIntentBytes),
            authored.Record.Field(3).Span, MailboxGrantCapabilityDigest.Compute(authored.Record.Field(4).Span, authored.Domain),
            (byte)authored.Domain, 1, route.Route.ExactHash.Span, effective);
        var wrongSigning = MailboxGrantRouteEvidenceAuthentication.GetSigningBytes(wrongTuple);
        var wrongEvidence = placement.RankedReplicaNodeIds.Select(id => new xnode::XNode.MailboxGrantReplicaEvidence(id,
            nodes.Single(node => node.SignerId.Span.SequenceEqual(id.Span)).SignReceipt(wrongSigning))).ToArray();
        await Assert.ThrowsAsync<xnode::XNode.ContactServiceUnavailableException>(async () => await client.AuthorizeAsync(
            request with { ExactXmg2 = wrongIntentBytes, ReplicaEvidence = wrongEvidence }, default));
        CryptographicOperations.ZeroMemory(wrongIntentProof);
        Assert.Empty(custody.Deposit.Inputs); Assert.Empty(custody.Retrieve.Inputs);
        await using (var empty = new NpgsqlCommand("SELECT entry_count FROM deep_did2_grant_journal_network WHERE network_id=$1", db))
        {
            empty.Parameters.Add(new() { Value = network }); Assert.Equal(0L, await empty.ExecuteScalarAsync());
        }
        var exact = await client.AuthorizeAsync(request, default);
        var verified = await DeepIdV2MailboxGrantResultVerifier.VerifySuccessAsync(route, authored, exact, exactPma);
        await verified.EnsureCurrentAsync();
        Assert.Equal(MailboxCapabilityDomain.Deposit, verified.Domain);
        Assert.Single(custody.Deposit.Inputs); Assert.Empty(custody.Retrieve.Inputs);
        // New authenticated forwarding nonce, same exact XMG2: permanent winner
        // is replayed without another signature or journal reservation.
        var replay = await client.AuthorizeAsync(request, default);
        Assert.Equal(exact.ToArray(), replay.ToArray()); Assert.Single(custody.Deposit.Inputs);
        await using var count = new NpgsqlCommand("SELECT entry_count FROM deep_did2_grant_journal_network WHERE network_id=$1", db);
        count.Parameters.Add(new() { Value = network }); Assert.Equal(1L, await count.ExecuteScalarAsync());
        var changed = exact.ToArray(); changed[^1] ^= 1;
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await DeepIdV2MailboxGrantResultVerifier.VerifySuccessAsync(route, authored, changed, exactPma));
        // Test-owned resolver attestations authorize this retrieval capability.
        // This does not prove real resolver authorization or Shared holder custody.
        var readRequest = await DeepIdV2MailboxGrantRequestAuthor.AuthorRetrieveAsync(route,
            authored.Record.Field(3), Bytes(32, 0x56), holder);
        var readTuple = MailboxGrantRouteEvidenceAuthentication.CreateTuple(SHA256.HashData(readRequest.ExactXmg2.Span),
            readRequest.Record.Field(3).Span, MailboxGrantCapabilityDigest.Compute(readRequest.Record.Field(4).Span, readRequest.Domain),
            (byte)readRequest.Domain, 1, route.Route.ExactHash.Span, effective);
        var readSigning = MailboxGrantRouteEvidenceAuthentication.GetSigningBytes(readTuple);
        var readEvidence = placement.RankedReplicaNodeIds.Select(id => new xnode::XNode.MailboxGrantReplicaEvidence(id,
            nodes.Single(node => node.SignerId.Span.SequenceEqual(id.Span)).SignReceipt(readSigning))).ToArray();
        var readResult = await client.AuthorizeAsync(request with
        {
            ExactXmg2 = readRequest.ExactXmg2, ReplicaEvidence = readEvidence,
            ResultExpiresAtUnixSeconds = BinaryPrimitives.ReadUInt64BigEndian(readRequest.Record.Field(10).Span)
        }, default);
        var readGrant = await DeepIdV2MailboxGrantResultVerifier.VerifySuccessAsync(route, readRequest, readResult, exactPma);
        Assert.Equal(MailboxCapabilityDomain.Retrieve, readGrant.Domain); Assert.Single(custody.Retrieve.Inputs);
        Assert.Equal(2L, await count.ExecuteScalarAsync());
        if (retainedExchange)
            await ExerciseRetainedPrivateGrantExchangeAsync(route, readRequest, request, placement, contexts,
                issuer, custody, client, http, origin, holder, forwarder, nodes, clock, scoped, network, count);
        await ExerciseIssuedGrantsNativeCycleAsync(verified, readGrant, tls, origin, clock, peers, nodes, revocations,
            network, observer, directory, bundlePath, genesisPin, genesisHeadHash);
    }

    private sealed class GrantClock(Clock source) : XNode.Core.IClock
    { public DateTimeOffset UtcNow => DateTimeOffset.FromUnixTimeSeconds(checked((long)source.UnixTime)); }

    private sealed class GrantHolder : IReachabilityMailboxHolderSigner, IDisposable
    {
        private readonly KeyPair key = PublicKeyAuth.GenerateKeyPair(Bytes(32, 0x57));
        public ReadOnlyMemory<byte> Ed25519PublicKey => key.PublicKey.ToArray();
        public ValueTask<int> SignMailboxGrantRequestAsync(ReadOnlyMemory<byte> signingBytes, Memory<byte> signature64,
            CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested(); PublicKeyAuth.SignDetached(signingBytes.ToArray(), key.PrivateKey).CopyTo(signature64);
            return ValueTask.FromResult(64);
        }
        public void Dispose() => CryptographicOperations.ZeroMemory(key.PrivateKey);
    }
}
#endif
