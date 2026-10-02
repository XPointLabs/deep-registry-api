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

internal sealed class ProductionContactRouteThresholdIssuer(
    DeepIdV2DirectoryProofIssuer proofIssuer,
    DeepIdV2XPointAuthoritySource rootSource,
    XPointNetworkClosureDistribution networkSource,
    IContactRouteAuthorityWitnessCustody custody,
    IContactResolveTrustedTimeContextSource timeSource,
    IDeepIdV2RouteThresholdJournal journal) : IContactRouteThresholdIssuer
{
    public async ValueTask<ContactRouteAuthorityWireResponse> IssueAsync(
        ContactRouteAuthorityWireRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(30));
        var ct = timeout.Token;
        if (!networkSource.TryEnter()) throw new ContactRouteAuthorityUnavailableException();
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
            var checkpoint = freshness.CurrentCheckpoint ?? throw new ContactRouteAuthorityRejectedException();
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
            await DeepIdV2ContactRouteVerifier.VerifyAdvertisementAsync(recipient,
                network, authority, request.ExactXra1, time, ct).ConfigureAwait(false);
            VerifiedDeepIdV2ContactRoutePredecessor? predecessor = null;
            if (request.HasPredecessor)
            {
                predecessor = await DeepIdV2ContactRouteVerifier.VerifyPredecessorAsync(recipient, network, authority,
                    request.ExactPredecessorXir1V2, request.ExactPredecessorRouteClosure, time, ct).ConfigureAwait(false);
                await DeepIdV2ContactRouteVerifier.VerifyAdvertisementSuccessorAsync(recipient, network, authority,
                    predecessor, request.ExactXra1, time, ct).ConfigureAwait(false);
            }

            var encoded = await journal.GetOrIssueAsync(request, async token =>
            {
                var now = await timeSource.ReadAsync(token).ConfigureAwait(false);
                now.Validate();
                var current = DeepIdV2CurrentContactAuthorizationVerifier.Verify(freshness,
                    recipient.Authorization, now.ServerBootId.Span, now.ServerMonotonicSample);
                var xra = ContactCodec.Decode("XRA1", request.ExactXra1.Span);
                // Both contexts were verified from this exact freshness proof.
                var issued = current.TrustedLowerUnixSeconds;
                var expires = new[] { checked(issued + 86_400),
                    BinaryPrimitives.ReadUInt64BigEndian(xra.Field(13).Span),
                    network.MaximumRecordExpiryUnixSeconds,
                    current.Authorization.Record.ExpiresAtUnixSeconds }.Min();
                var signers = await custody.GetRouteSignersAsync(authority, token).ConfigureAwait(false);
                var candidate = predecessor is null ? await DeepIdV2ContactRouteAuthor.AuthorThresholdAsync(current,
                    network, authority, request.ExactXra1, signers, issued, expires,
                    time, token).ConfigureAwait(false) :
                    await DeepIdV2ContactRouteAuthor.AuthorThresholdSuccessorAsync(current, network, authority,
                        predecessor, request.ExactXra1, signers, expires, time, token).ConfigureAwait(false);
                await RequireSourcesCurrentAsync(freshness, frame, raw.ExactViewChain[^1], authority, token).ConfigureAwait(false);
                return ContactRouteAuthorityWireCodec.EncodeResponse(request,
                    new ContactRouteAuthorityWireResponse(request.NetworkId.Span,
                        request.RequestNonce.Span, candidate.Selection.CanonicalBytes.Span,
                        candidate.LiveRoute.CanonicalBytes.Span, candidate.Successor.CanonicalBytes.Span,
                        freshness.ExactAdh1.Span));
            }, ct).ConfigureAwait(false);

            var winner = ContactRouteAuthorityWireCodec.DecodeResponse(request, encoded.Span);
            _ = await DeepIdV2ContactRouteVerifier.VerifyRetainedThresholdAsync(recipient, network,
                authority, request, new ParsedDeepIdV2RouteThreshold(
                    winner.ExactPms2.Span, winner.ExactXrc1.Span, winner.ExactXss1.Span),
                winner.ExactIssuanceAdh1, time, ct).ConfigureAwait(false);
            await RequireSourcesCurrentAsync(freshness, frame, raw.ExactViewChain[^1], authority, ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested();
            return winner;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        { throw new ContactRouteAuthorityUnavailableException(); }
        catch (Exception error) when (error is ArgumentException or FormatException or
            CryptographicException or OverflowException or OnionBoundaryException or
            ContactResolveDirectoryTargetNotFoundException)
        { throw new ContactRouteAuthorityRejectedException(); }
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

    internal static IContactRouteThresholdIssuer CreateFailClosed(IServiceProvider services)
    {
        var proof = services.GetService<DeepIdV2DirectoryProofIssuer>();
        var root = services.GetService<DeepIdV2XPointAuthoritySource>();
        var network = services.GetService<XPointNetworkClosureDistribution>();
        var witnesses = services.GetService<IContactRouteAuthorityWitnessCustody>();
        var time = services.GetService<IContactResolveTrustedTimeContextSource>();
        var journal = services.GetService<IDeepIdV2RouteThresholdJournal>();
        return proof is null || root is null || network is null || witnesses is null || time is null || journal is null
            ? new UnavailableContactRouteThresholdIssuer()
            : new ProductionContactRouteThresholdIssuer(proof, root, network, witnesses, time, journal);
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
