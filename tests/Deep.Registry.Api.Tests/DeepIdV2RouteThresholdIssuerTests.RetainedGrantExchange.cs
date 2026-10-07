#if DEEP_PROTOCOL_DIRECTORY_V1
extern alias xnode;
using System.Buffers.Binary;
using System.Net;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.XPointNetworkV1;
using Deep.Registry.Api.DirectoryPublication;
using Npgsql;

namespace Deep.Registry.Api.Tests;

public sealed partial class DeepIdV2RouteThresholdIssuerTests
{
    [Fact]
    public Task RetainedPrivateIssuerUsesDistinctAdmissionAndPermanentKindHorizonScopeOverRealTlsPostgres() =>
        ExerciseRegistryCeremonyAsync(0, mailboxLifecycle: false, grantExchange: true, retainedExchange: true);

    // Actual Registry context/proof, SQL journal, role signer and HTTPS client.
    // Both store signatures are synthetic key-backed inputs; they are NOT
    // independent native custody, elapsed original routes, Shared or device E2E.
    private static async Task ExerciseRetainedPrivateGrantExchangeAsync(VerifiedDeepIdV2ContactRouteClosure route,
        AuthoredMailboxGrantRequest currentRead, xnode::XNode.MailboxGrantAuthorityRequest template,
        VerifiedContactServicePlacement placement, DeepIdV2MailboxAuthorityContextSource contexts,
        DeepIdV2MailboxGrantIssuer issuer, MailboxTestCustody custody,
        xnode::XNode.HttpsMailboxGrantAuthorityClient client, HttpClient realTls, Uri origin,
        GrantHolder holder, Signer forwarder, Signer[] nodes, Clock clock,
        string scoped, byte[] network, NpgsqlCommand count)
    {
        var original = route.Route;
        var readUntil = checked(new[] {
            U64(original.Reachability.Field(17)), U64(original.Authorization.Field(13)),
            U64(original.Route.Field(18)), U64(original.Successor.Field(11)),
            U64(original.Projection.Field(12)), U64(original.Selection.Field(9)) }.Min() + 2_592_000);
        xnode::XNode.MailboxGrantAuthorityRequest Retained(AuthoredMailboxGrantRequest request, ulong horizon) => template with
        {
            ExactXmg2 = request.ExactXmg2, EvidenceKind = xnode::XNode.MailboxGrantAuthorityEvidenceKind.RetainedRead,
            ReadUntilUnixSeconds = horizon, RouteEffectiveExpiresAtUnixSeconds = 0,
            ResultExpiresAtUnixSeconds = U64(request.Record.Field(10)),
            ReplicaEvidence = Evidence(request, horizon)
        };
        xnode::XNode.MailboxGrantReplicaEvidence[] Evidence(AuthoredMailboxGrantRequest request, ulong horizon)
        {
            var tuple = MailboxRetainedReadEvidenceAuthentication.CreateTuple(SHA256.HashData(request.ExactXmg2.Span),
                request.Record.Field(3).Span, MailboxGrantCapabilityDigest.Compute(request.Record.Field(4).Span, MailboxCapabilityDomain.Retrieve),
                original.ExactHash.Span, horizon);
            var input = MailboxRetainedReadEvidenceAuthentication.GetSigningBytes(tuple);
            return placement.RankedReplicaNodeIds.Select(id => new xnode::XNode.MailboxGrantReplicaEvidence(id,
                nodes.Single(node => node.SignerId.Span.SequenceEqual(id.Span)).SignReceipt(input))).ToArray();
        }
        DeepIdV2MailboxGrantInput Forward(xnode::XNode.MailboxGrantAuthorityRequest request, byte nonceMarker, bool currentDomain = false)
        {
            var nonce = Bytes(32, nonceMarker);
            var bytes = currentDomain
                ? MailboxGrantAuthorityAuthentication.GetSigningBytes(request.ExactXmg2.Span, request.ResultCode,
                    request.ExactRouteClosure.Span, request.ResultExpiresAtUnixSeconds, forwarder.SignerId.Span, clock.UnixTime, nonce)
                : MailboxRetainedReadAuthorityAuthentication.GetSigningBytes(request.ExactXmg2.Span,
                    request.ExactRouteClosure.Span, request.ReadUntilUnixSeconds, request.ResultExpiresAtUnixSeconds,
                    forwarder.SignerId.Span, clock.UnixTime, nonce);
            return new(request.ExactXmg2.Span, request.ExactRouteClosure.Span, DeepIdV2MailboxGrantEvidenceKind.RetainedRead,
                request.ReadUntilUnixSeconds, 0,
                request.ReplicaEvidence.Select(e => new DeepIdV2MailboxGrantReplicaEvidence(e.ReplicaId.Span, e.Signature.Span)).ToArray(),
                forwarder.SignerId.Span, clock.UnixTime, nonce, forwarder.SignReceipt(bytes));
        }

        // Same exact operation already has a current-kind winner: even both
        // genuine retained signatures cannot change its permanent scope.
        await Assert.ThrowsAsync<xnode::XNode.ContactServiceUnavailableException>(async () =>
            await client.AuthorizeAsync(Retained(currentRead, readUntil), default));
        Assert.Single(custody.Retrieve.Inputs); Assert.Equal(2L, await count.ExecuteScalarAsync());
        var authored = await contexts.WithCurrentAsync(async (context, ct) =>
            await context.Host.AuthorRetainedReadRequestAsync(original.ExactBytes, currentRead.Record.Field(3),
                currentRead.Record.Field(4), holder, ct), default);
        var request = Retained(authored, readUntil);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(async () =>
            await issuer.IssueAsync(Forward(request, 0xa1, currentDomain: true), default));
        // Current139-byte signatures cannot satisfy retained136-byte evidence.
        var tuple139 = MailboxGrantRouteEvidenceAuthentication.CreateTuple(SHA256.HashData(authored.ExactXmg2.Span),
            authored.Record.Field(3).Span, MailboxGrantCapabilityDigest.Compute(authored.Record.Field(4).Span, MailboxCapabilityDomain.Retrieve),
            2, 1, original.ExactHash.Span, template.RouteEffectiveExpiresAtUnixSeconds);
        var signing139 = MailboxGrantRouteEvidenceAuthentication.GetSigningBytes(tuple139);
        var currentEvidence = placement.RankedReplicaNodeIds.Select(id => new xnode::XNode.MailboxGrantReplicaEvidence(id,
            nodes.Single(node => node.SignerId.Span.SequenceEqual(id.Span)).SignReceipt(signing139))).ToArray();
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await issuer.IssueAsync(Forward(request with { ReplicaEvidence = currentEvidence }, 0xa2), default));
        Assert.Single(custody.Retrieve.Inputs); Assert.Equal(2L, await count.ExecuteScalarAsync());

        // Lose an actual TLS success after Registry commits; retry carries a new
        // forwarding nonce but preserves the exact holder request and winner.
        using var loss = new LoseCommittedGrantReply(realTls);
        using var losingHttp = new HttpClient(loss);
        var options = new XNode.Core.RouterNodeOptions { RouterId = Convert.ToHexString(forwarder.SignerId.Span),
            Ed25519PrivateKey = Convert.ToHexString(Bytes(32, forwarder.Marker)) };
        var losingClient = new xnode::XNode.HttpsMailboxGrantAuthorityClient(losingHttp, options, origin, new GrantClock(clock));
        await Assert.ThrowsAsync<xnode::XNode.ContactServiceUnavailableException>(async () =>
            await losingClient.AuthorizeAsync(request, default));
        Assert.NotNull(loss.CommittedReply); Assert.Equal(2, custody.Retrieve.Inputs.Count);
        var exact = await client.AuthorizeAsync(request, default);
        Assert.Equal(loss.CommittedReply, exact.ToArray()); Assert.Equal(2, custody.Retrieve.Inputs.Count);
        Assert.Equal(3L, await count.ExecuteScalarAsync());
        await contexts.WithCurrentAsync(async (context, ct) => {
            var verified = await context.Host.VerifyRetainedReadSuccessAsync(original.ExactBytes, authored.ExactXmg2, exact, ct);
            await verified.EnsureCurrentAsync(ct); Assert.Equal(MailboxCapabilityDomain.Retrieve, verified.Domain); return true;
        }, default);

        // A different horizon with correctly recomputed signatures is not exact
        // retry, even though the original still-current grant covers both.
        await Assert.ThrowsAsync<xnode::XNode.ContactServiceUnavailableException>(async () =>
            await client.AuthorizeAsync(Retained(authored, readUntil - 1), default));
        Assert.Equal(2, custody.Retrieve.Inputs.Count); Assert.Equal(3L, await count.ExecuteScalarAsync());
        using var reopenedJournal = new DeepIdV2PostgreSqlMailboxGrantJournal(scoped, network);
        using var coldCustody = new MailboxTestCustody();
        var reopenedIssuer = new DeepIdV2MailboxGrantIssuer(contexts, reopenedJournal, coldCustody, new());
        Assert.Equal(exact.ToArray(), (await reopenedIssuer.IssueAsync(Forward(request, 0xa3), default)).ToArray());
        Assert.Empty(coldCustody.Deposit.Inputs); Assert.Empty(coldCustody.Retrieve.Inputs);
        Assert.Equal(3L, await count.ExecuteScalarAsync());
    }
    private static ulong U64(ReadOnlyMemory<byte> bytes) => BinaryPrimitives.ReadUInt64BigEndian(bytes.Span);
    private sealed class LoseCommittedGrantReply(HttpClient realTls) : HttpMessageHandler
    {
        internal byte[]? CommittedReply;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            // HttpClient marks the outer message sent before invoking a handler;
            // preserve exact bytes/headers in a fresh message for the real TLS hop.
            using var forwarded = new HttpRequestMessage(request.Method, request.RequestUri) {
                Version = request.Version, VersionPolicy = request.VersionPolicy,
                Content = new ByteArrayContent(await request.Content!.ReadAsByteArrayAsync(ct))
            };
            foreach (var header in request.Headers) forwarded.Headers.TryAddWithoutValidation(header.Key, header.Value);
            forwarded.Content.Headers.Clear();
            foreach (var header in request.Content.Headers) forwarded.Content.Headers.TryAddWithoutValidation(header.Key, header.Value);
            using var response = await realTls.SendAsync(forwarded, HttpCompletionOption.ResponseHeadersRead, ct);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            CommittedReply = await response.Content.ReadAsByteArrayAsync(ct);
            throw new IOException("Injected loss after real TLS reply and durable winner.");
        }
    }
}
#endif
