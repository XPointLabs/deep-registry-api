#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Registry.Api.DirectoryPublication;

internal sealed class ProductionContactPublicationLeaseIssuer(
    DeepIdV2DirectoryProofIssuer proofIssuer, DeepIdV2XPointAuthoritySource rootSource,
    XPointNetworkClosureDistribution networkSource, IContactPublicationLeaseWitnessCustody custody,
    IContactResolveTrustedTimeContextSource timeSource, IDeepIdV2PublicationJournal journal,
    ILogger<ProductionContactPublicationLeaseIssuer>? logger = null) : IContactPublicationLeaseIssuer
{
    private enum IssuePhase { Readiness, OriginalWinner, CurrentOwner, CurrentNetwork, OriginalIntent, Publisher, Signers, Threshold, Release }
    public async ValueTask<ParsedDeepIdV2PublicationLease> IssueAsync(PublicationLeaseWireRequest candidate, CancellationToken cancellation)
    {
        ArgumentNullException.ThrowIfNull(candidate); cancellation.ThrowIfCancellationRequested();
        var request = DeepIdV2PublicationLeaseWireCodec.DecodeRequest(candidate.CanonicalBytes.Span);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellation); deadline.CancelAfter(TimeSpan.FromSeconds(30));
        var ct = deadline.Token;
        if (!networkSource.TryEnter()) throw new ContactPublicationAuthorityUnavailableException();
        var phase = IssuePhase.Readiness;
        try
        {
            await proofIssuer.RequireReadyAsync(ct).ConfigureAwait(false);
            phase = IssuePhase.OriginalWinner;
            var winner = await journal.ReadCompletedWinnerAsync(request.OriginalCoordinationNonce, request.DirectoryLookupKey,
                request.OriginalRequestHash, ct).ConfigureAwait(false);
            var original = ContactPublicationAuthorityWireCodec.DecodeRequest(winner.Request.Span);
            var oldResponse = ContactPublicationAuthorityWireCodec.DecodeResponse(original, winner.Response.Span);
            phase = IssuePhase.CurrentOwner;
            var trusted = await timeSource.ReadAsync(ct).ConfigureAwait(false); trusted.Validate();
            // The fresh coordination nonce is not a reusable DTT challenge.
            var proof = await proofIssuer.IssueAsync(new DeepIdV2DirectoryProofRequest(request.NetworkId.Span,
                RandomNumberGenerator.GetBytes(32), trusted.ServerBootId.Span, trusted.ServerMonotonicSample,
                request.DirectoryLookupKey.Span, request.MinimumDirectoryGeneration, request.MinimumDirectoryHash.Span), ct).ConfigureAwait(false);
            var freshness = proof.Freshness;
            var checkpoint = freshness.CurrentCheckpoint ?? throw new ContactPublicationAuthorityRejectedException();
            var now = await timeSource.ReadAsync(ct).ConfigureAwait(false); now.Validate();
            var recipient = DeepIdV2CurrentContactAuthorizationVerifier.Verify(freshness,
                DeepIdV2ContactAuthorizationCodec.Verify(DeepIdV2ContactAuthorizationCodec.Decode(original.ExactDca1.Span),
                    checkpoint.Binding, checkpoint.Directory), now.ServerBootId.Span, now.ServerMonotonicSample);
            var authority = rootSource.Read();
            phase = IssuePhase.CurrentNetwork;
            var frame = await networkSource.ReadAsync(ct).ConfigureAwait(false);
            var raw = XPointNetworkClosureWireCodec.DecodeResponse(frame);
            var time = new OnionTrustedTimeAuthority(new CurrentClock(timeSource));
            var network = await OnionNetworkContextVerifier.VerifyAsync(authority, freshness, raw.ExactNetworkPolicyChain,
                raw.ExactViewChain, raw.ExactHeadChain, raw.ExactActiveNodeDescriptors, raw.ExactPlacementTopologyChain,
                null, time, ct).ConfigureAwait(false);
            var contact = DeepIdV2ResolverClosureCodec.Decode(original.ExactDcr1.Span);
            phase = IssuePhase.OriginalIntent;
            var route = await DeepIdV2ContactRouteVerifier.VerifyAsync(recipient, network, authority,
                contact.Bundle.Field(14)[40..], original.ExactRouteClosure, time, ct).ConfigureAwait(false);
            var intent = await DeepIdV2PublicationCommitVerifier.VerifyIssuerRetainedIntentAsync(route,
                original, oldResponse.ExactXpu1, ct).ConfigureAwait(false);
            // Current owner signature is checked before witness acquisition.
            phase = IssuePhase.Publisher;
            await DeepIdV2PublicationLeaseAuthor.VerifyIssuerRequestAsync(intent, request, ct).ConfigureAwait(false);
            await RequireUnchangedAsync(ct).ConfigureAwait(false);
            phase = IssuePhase.Signers;
            var signers = await custody.GetPublicationLeaseSignersAsync(authority, ct).ConfigureAwait(false);
            var guarded = signers.Select(value => (IDeepIdV2PublicationLeaseWitnessSigner)
                new CurrentWinnerWitness(value, RequireUnchangedAsync)).ToArray();
            phase = IssuePhase.Threshold;
            var lease = await DeepIdV2PublicationLeaseAuthor.AuthorThresholdAsync(intent, request, guarded, ct).ConfigureAwait(false);
            phase = IssuePhase.Release;
            await RequireUnchangedAsync(ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested(); return lease;

            async ValueTask RequireUnchangedAsync(CancellationToken token)
            {
                await proofIssuer.RequireStillCurrentAsync(freshness, raw.ExactViewChain[^1], token).ConfigureAwait(false);
                var currentRoot = rootSource.Read();
                if (!Fixed(currentRoot.AuthorityCoreReference.Span, authority.AuthorityCoreReference.Span) ||
                    !Fixed(currentRoot.Dts1PolicyCoreReference.Span, authority.Dts1PolicyCoreReference.Span) ||
                    !Fixed(currentRoot.TimeSourcePolicyHash.Span, authority.TimeSourcePolicyHash.Span) ||
                    !Fixed(await networkSource.ReadAsync(token).ConfigureAwait(false), frame))
                    throw new CryptographicException("Publication lease authority changed during issuance.");
                var retained = await journal.ReadCompletedWinnerAsync(request.OriginalCoordinationNonce,
                    request.DirectoryLookupKey, request.OriginalRequestHash, token).ConfigureAwait(false);
                if (!Fixed(retained.Request.Span, winner.Request.Span) || !Fixed(retained.Response.Span, winner.Response.Span))
                    throw new CryptographicException("Publication lease original permanent winner changed.");
                token.ThrowIfCancellationRequested();
            }
        }
        catch (OperationCanceledException) when (!cancellation.IsCancellationRequested)
        { logger?.LogWarning("Publication lease rejected: phase={Phase}, category=deadline.", phase); throw new ContactPublicationAuthorityUnavailableException(); }
        catch (Exception error) when (error is ArgumentException or FormatException or CryptographicException or OverflowException or
            OnionBoundaryException or ContactResolveDirectoryTargetNotFoundException)
        { logger?.LogWarning("Publication lease rejected: phase={Phase}, category=authority.", phase); throw new ContactPublicationAuthorityRejectedException(); }
        catch (Exception error) when (error is IOException or InvalidOperationException or Npgsql.NpgsqlException)
        { logger?.LogWarning("Publication lease rejected: phase={Phase}, category=unavailable.", phase); throw; }
        finally { networkSource.Exit(); }
    }

    private sealed class CurrentWinnerWitness(IDeepIdV2PublicationLeaseWitnessSigner signer,
        Func<CancellationToken, ValueTask> requireCurrent) : IDeepIdV2PublicationLeaseWitnessSigner
    {
        public ReadOnlyMemory<byte> WitnessId => signer.WitnessId.ToArray();
        public async ValueTask<ReadOnlyMemory<byte>> SignPublicationLeaseAsync(PublicationLeaseSigningRequest request, CancellationToken ct)
        {
            await requireCurrent(ct).ConfigureAwait(false);
            var signature = (await signer.SignPublicationLeaseAsync(request, ct).ConfigureAwait(false)).ToArray();
            try { await requireCurrent(ct).ConfigureAwait(false); ct.ThrowIfCancellationRequested(); return signature.ToArray(); }
            finally { CryptographicOperations.ZeroMemory(signature); }
        }
    }
    private sealed class CurrentClock(IContactResolveTrustedTimeContextSource source) : IOnionMonotonicClock
    {
        public async ValueTask<OnionMonotonicReading> ReadAsync(CancellationToken ct)
        { var reading = await source.ReadAsync(ct).ConfigureAwait(false); reading.Validate(); return new(reading.ServerBootId.Span, reading.ServerMonotonicSample); }
    }
    internal static IContactPublicationLeaseIssuer CreateFailClosed(IServiceProvider services)
    {
        var proof = services.GetService<DeepIdV2DirectoryProofIssuer>(); var root = services.GetService<DeepIdV2XPointAuthoritySource>();
        var network = services.GetService<XPointNetworkClosureDistribution>(); var custody = services.GetService<IContactPublicationLeaseWitnessCustody>();
        var time = services.GetService<IContactResolveTrustedTimeContextSource>(); var journal = services.GetService<IDeepIdV2PublicationJournal>();
        return proof is null || root is null || network is null || custody is null || time is null || journal is null
            ? new UnavailableContactPublicationLeaseIssuer() : new ProductionContactPublicationLeaseIssuer(proof, root, network, custody, time, journal,
                services.GetService<ILogger<ProductionContactPublicationLeaseIssuer>>());
    }
    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}
#endif
