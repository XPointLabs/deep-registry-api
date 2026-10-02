#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Registry.Api.DirectoryPublication;

internal sealed class ProductionContactPublicationThresholdIssuer(
    DeepIdV2DirectoryProofIssuer proofIssuer,
    DeepIdV2XPointAuthoritySource rootSource,
    XPointNetworkClosureDistribution networkSource,
    IContactPublicationAuthorityWitnessCustody custody,
    IContactResolveTrustedTimeContextSource timeSource,
    IDeepIdV2PublicationJournal journal) : IContactPublicationThresholdIssuer
{
    public async ValueTask<ContactPublicationAuthorityWireResponse> IssueAsync(
        ContactPublicationAuthorityWireRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(30));
        var ct = timeout.Token;
        if (!networkSource.TryEnter()) throw new ContactPublicationAuthorityUnavailableException();
        try
        {
            await proofIssuer.RequireReadyAsync(ct).ConfigureAwait(false);
            var trusted = await timeSource.ReadAsync(ct).ConfigureAwait(false);
            trusted.Validate();
            // Coordination nonce is durable request identity, not a DTT challenge.
            var challenge = RandomNumberGenerator.GetBytes(32);
            var proof = await proofIssuer.IssueAsync(new DeepIdV2DirectoryProofRequest(
                request.NetworkId.Span, challenge, trusted.ServerBootId.Span,
                trusted.ServerMonotonicSample, request.DirectoryLookupKey.Span,
                request.MinimumAdh1Generation, request.MinimumAdh1CoreHash.Span), ct).ConfigureAwait(false);
            var freshness = proof.Freshness;
            var checkpoint = freshness.CurrentCheckpoint ?? throw new ContactPublicationAuthorityRejectedException();
            var reading = await timeSource.ReadAsync(ct).ConfigureAwait(false);
            reading.Validate();
            var recipient = DeepIdV2CurrentContactAuthorizationVerifier.Verify(freshness,
                DeepIdV2ContactAuthorizationCodec.Verify(
                    DeepIdV2ContactAuthorizationCodec.Decode(request.ExactDca1.Span),
                    checkpoint.Binding, checkpoint.Directory),
                reading.ServerBootId.Span, reading.ServerMonotonicSample);
            var authority = rootSource.Read();
            var frame = await networkSource.ReadAsync(ct).ConfigureAwait(false);
            var raw = XPointNetworkClosureWireCodec.DecodeResponse(frame);
            var time = new OnionTrustedTimeAuthority(new CurrentClock(timeSource));
            var network = await OnionNetworkContextVerifier.VerifyAsync(authority, freshness,
                raw.ExactNetworkPolicyChain, raw.ExactViewChain, raw.ExactHeadChain,
                raw.ExactActiveNodeDescriptors, raw.ExactPlacementTopologyChain,
                null, time, ct).ConfigureAwait(false);
            var dcr = DeepIdV2ResolverClosureCodec.Decode(request.ExactDcr1.Span);
            var route = await DeepIdV2ContactRouteVerifier.VerifyAsync(recipient, network, authority,
                dcr.Bundle.Field(14).Slice(40), request.ExactRouteClosure, time, ct).ConfigureAwait(false);
            await DeepIdV2PublicationAuthorityAuthor.VerifyRequestAsync(route, request, ct).ConfigureAwait(false);

            var encoded = await journal.GetOrIssueAsync(request, async token =>
            {
                var signers = await custody.GetPublicationSignersAsync(authority, token).ConfigureAwait(false);
                var candidate = await DeepIdV2PublicationAuthorityAuthor.AuthorThresholdAsync(
                    route, request, signers, token).ConfigureAwait(false);
                await RequireSourcesCurrentAsync(freshness, frame, raw.ExactViewChain[^1], authority, token).ConfigureAwait(false);
                return ContactPublicationAuthorityWireCodec.EncodeResponse(request,
                    new ContactPublicationAuthorityWireResponse(request.NetworkId.Span,
                        request.RequestNonce.Span, candidate.ExactXpu1.Span));
            }, ct).ConfigureAwait(false);

            var winner = ContactPublicationAuthorityWireCodec.DecodeResponse(request, encoded.Span);
            _ = await DeepIdV2PublicationAuthorityAuthor.VerifyResponseAsync(
                route, request, winner.ExactXpu1, ct).ConfigureAwait(false);
            await RequireSourcesCurrentAsync(freshness, frame, raw.ExactViewChain[^1], authority, ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested();
            return winner;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        { throw new ContactPublicationAuthorityUnavailableException(); }
        catch (Exception error) when (error is ArgumentException or FormatException or
            CryptographicException or OverflowException or OnionBoundaryException or
            ContactResolveDirectoryTargetNotFoundException)
        { throw new ContactPublicationAuthorityRejectedException(); }
        finally { networkSource.Exit(); }
    }

    private async ValueTask RequireSourcesCurrentAsync(VerifiedDeepIdV2DirectoryFreshness proof,
        byte[] expectedFrame, ReadOnlyMemory<byte> expectedView,
        VerifiedXPointNetworkAuthority authority, CancellationToken ct)
    {
        await proofIssuer.RequireStillCurrentAsync(proof, expectedView, ct).ConfigureAwait(false);
        var currentRoot = rootSource.Read();
        if (!CryptographicOperations.FixedTimeEquals(currentRoot.AuthorityCoreReference.Span,
                authority.AuthorityCoreReference.Span) ||
            !CryptographicOperations.FixedTimeEquals(currentRoot.Dts1PolicyCoreReference.Span,
                authority.Dts1PolicyCoreReference.Span) ||
            !CryptographicOperations.FixedTimeEquals(currentRoot.TimeSourcePolicyHash.Span,
                authority.TimeSourcePolicyHash.Span) ||
            !CryptographicOperations.FixedTimeEquals(await networkSource.ReadAsync(ct).ConfigureAwait(false),
                expectedFrame))
            throw new CryptographicException("Route authority context changed before release.");
    }

    internal static IContactPublicationThresholdIssuer CreateFailClosed(IServiceProvider services)
    {
        var proof = services.GetService<DeepIdV2DirectoryProofIssuer>();
        var root = services.GetService<DeepIdV2XPointAuthoritySource>();
        var network = services.GetService<XPointNetworkClosureDistribution>();
        var witnesses = services.GetService<IContactPublicationAuthorityWitnessCustody>();
        var time = services.GetService<IContactResolveTrustedTimeContextSource>();
        var journal = services.GetService<IDeepIdV2PublicationJournal>();
        return proof is null || root is null || network is null || witnesses is null || time is null || journal is null
            ? new UnavailableContactPublicationThresholdIssuer()
            : new ProductionContactPublicationThresholdIssuer(proof, root, network, witnesses, time, journal);
    }

    private sealed class CurrentClock(IContactResolveTrustedTimeContextSource source) : IOnionMonotonicClock
    {
        public async ValueTask<OnionMonotonicReading> ReadAsync(CancellationToken cancellationToken)
        {
            var now = await source.ReadAsync(cancellationToken).ConfigureAwait(false);
            now.Validate();
            return new(now.ServerBootId.Span, now.ServerMonotonicSample);
        }
    }
}
#endif
