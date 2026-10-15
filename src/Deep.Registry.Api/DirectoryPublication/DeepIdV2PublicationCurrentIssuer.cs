#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Registry.Api.DirectoryPublication;

internal interface IContactPublicationCurrentIssuer
{
    ValueTask<ParsedDeepIdV2PublicationLease> IssueAsync(PublicationCurrentWireRequest request, CancellationToken ct);
}

internal sealed class ProductionContactPublicationCurrentIssuer(
    DeepIdV2DirectoryProofIssuer proofs, DeepIdV2XPointAuthoritySource roots,
    XPointNetworkClosureDistribution distribution, IContactPublicationAuthorityWitnessCustody approvals,
    IContactPublicationLeaseWitnessCustody leases, IContactResolveTrustedTimeContextSource timeSource,
    IDeepIdV2PublicationJournal journal, ILogger<ProductionContactPublicationCurrentIssuer>? logger = null)
    : IContactPublicationCurrentIssuer
{
    private enum IssuePhase { Admission, Readiness, Proof, Recipient, Network, Route, Predecessor, Publisher, Journal, Approval, Winner, Lease, Release }
    private readonly long[] failureLogTimestamps = new long[(int)IssuePhase.Release + 1];

    public async ValueTask<ParsedDeepIdV2PublicationLease> IssueAsync(PublicationCurrentWireRequest candidate, CancellationToken cancellation)
    {
        ArgumentNullException.ThrowIfNull(candidate); cancellation.ThrowIfCancellationRequested();
        var request = DeepIdV2PublicationCurrentWireCodec.DecodeRequest(candidate.CanonicalBytes.Span);
        var original = request.OriginalRequest;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellation); deadline.CancelAfter(TimeSpan.FromSeconds(30));
        var ct = deadline.Token;
        if (!distribution.TryEnter())
        { Report(IssuePhase.Admission, "busy"); throw new ContactPublicationAuthorityUnavailableException(); }
        var phase = IssuePhase.Readiness;
        try
        {
            await proofs.RequireReadyAsync(ct).ConfigureAwait(false);
            phase = IssuePhase.Proof;
            var trusted = await timeSource.ReadAsync(ct).ConfigureAwait(false); trusted.Validate();
            var issuedProof = await proofs.IssueAsync(new DeepIdV2DirectoryProofRequest(request.NetworkId.Span,
                RandomNumberGenerator.GetBytes(32), trusted.ServerBootId.Span, trusted.ServerMonotonicSample,
                request.DirectoryLookupKey.Span, request.MinimumDirectoryGeneration, request.MinimumDirectoryHash.Span), ct).ConfigureAwait(false);
            var freshness = issuedProof.Freshness;
            var checkpoint = freshness.CurrentCheckpoint ?? throw new ContactPublicationAuthorityRejectedException();
            var now = await timeSource.ReadAsync(ct).ConfigureAwait(false); now.Validate();
            phase = IssuePhase.Recipient;
            var recipient = DeepIdV2CurrentContactAuthorizationVerifier.Verify(freshness,
                DeepIdV2ContactAuthorizationCodec.Verify(DeepIdV2ContactAuthorizationCodec.Decode(original.ExactDca1.Span),
                    checkpoint.Binding, checkpoint.Directory), now.ServerBootId.Span, now.ServerMonotonicSample);
            phase = IssuePhase.Network;
            var authority = roots.Read(); var frame = await distribution.ReadAsync(ct).ConfigureAwait(false);
            var raw = XPointNetworkClosureWireCodec.DecodeResponse(frame);
            var time = new OnionTrustedTimeAuthority(new CurrentClock(timeSource));
            var network = await OnionNetworkContextVerifier.VerifyAsync(authority, freshness, raw.ExactNetworkPolicyChain,
                raw.ExactViewChain, raw.ExactHeadChain, raw.ExactActiveNodeDescriptors, raw.ExactPlacementTopologyChain,
                null, time, ct).ConfigureAwait(false);
            phase = IssuePhase.Route;
            var contact = DeepIdV2ResolverClosureCodec.Decode(original.ExactDcr1.Span);
            var route = await DeepIdV2ContactRouteVerifier.VerifyAsync(recipient, network, authority,
                contact.Bundle.Field(14)[40..], original.ExactRouteClosure, time, ct).ConfigureAwait(false);
            VerifiedDeepIdV2PublicationIssuerPredecessor? predecessor = null;
            if (original.Generation != 0)
            {
                phase = IssuePhase.Predecessor;
                var prior = await journal.ReadCompletedPredecessorAsync(original, ct).ConfigureAwait(false);
                var priorRequest = ContactPublicationAuthorityWireCodec.DecodeRequest(prior.Request.Span);
                var priorResponse = ContactPublicationAuthorityWireCodec.DecodeResponse(priorRequest, prior.Response.Span);
                predecessor = await DeepIdV2PublicationCommitVerifier.VerifyIssuerPredecessorAsync(recipient, network, authority,
                    priorRequest, priorResponse.ExactXpu1, original.ExactPriorXpo1, time, ct).ConfigureAwait(false);
            }
            phase = IssuePhase.Publisher;
            var submission = await DeepIdV2PublicationCurrentAuthor.VerifyIssuerRequestAsync(route, request, predecessor, ct).ConfigureAwait(false);
            await RequireAuthorityAsync(ct).ConfigureAwait(false);
            phase = IssuePhase.Journal;
            var response = await journal.GetOrIssueAsync(original, async token =>
            {
                phase = IssuePhase.Approval;
                await RequireAuthorityAsync(token).ConfigureAwait(false);
                var signers = await approvals.GetPublicationSignersAsync(authority, token).ConfigureAwait(false);
                var guarded = signers.Select(value => (IXpa1PublicationAuthorizationWitnessSigner)
                    new CurrentApprovalWitness(value, RequireAuthorityAsync)).ToArray();
                var approval = await DeepIdV2PublicationCurrentAuthor.AuthorApprovalAsync(submission, guarded, token).ConfigureAwait(false);
                await RequireAuthorityAsync(token).ConfigureAwait(false);
                return ContactPublicationAuthorityWireCodec.EncodeResponse(original,
                    new(original.NetworkId.Span, original.RequestNonce.Span, approval.CanonicalBytes.Span));
            }, ct).ConfigureAwait(false);
            phase = IssuePhase.Winner;
            var winner = ContactPublicationAuthorityWireCodec.DecodeResponse(original, response.Span);
            var intent = await DeepIdV2PublicationCommitVerifier.VerifyIssuerRetainedIntentAsync(route, original, winner.ExactXpu1, ct).ConfigureAwait(false);
            await RequireWinnerAsync(ct).ConfigureAwait(false);
            phase = IssuePhase.Lease;
            var leaseSigners = await leases.GetPublicationLeaseSignersAsync(authority, ct).ConfigureAwait(false);
            var guardedLease = leaseSigners.Select(value => (IDeepIdV2PublicationLeaseWitnessSigner)
                new CurrentLeaseWitness(value, RequireWinnerAsync)).ToArray();
            var lease = await DeepIdV2PublicationCurrentAuthor.AuthorLeaseAsync(submission, intent, guardedLease, ct).ConfigureAwait(false);
            phase = IssuePhase.Release;
            await RequireWinnerAsync(ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested(); return lease;

            async ValueTask RequireAuthorityAsync(CancellationToken token)
            {
                await proofs.RequireStillCurrentAsync(freshness, raw.ExactViewChain[^1], token).ConfigureAwait(false);
                var root = roots.Read();
                if (!Fixed(root.AuthorityCoreReference.Span, authority.AuthorityCoreReference.Span) ||
                    !Fixed(root.Dts1PolicyCoreReference.Span, authority.Dts1PolicyCoreReference.Span) ||
                    !Fixed(root.TimeSourcePolicyHash.Span, authority.TimeSourcePolicyHash.Span) ||
                    !Fixed(await distribution.ReadAsync(token).ConfigureAwait(false), frame))
                    throw new CryptographicException("Current publication authority changed before release.");
                token.ThrowIfCancellationRequested();
            }
            async ValueTask RequireWinnerAsync(CancellationToken token)
            {
                await RequireAuthorityAsync(token).ConfigureAwait(false);
                var retained = await journal.ReadCompletedWinnerAsync(original.RequestNonce, original.DirectoryLookupKey,
                    intent.RequestHash, token).ConfigureAwait(false);
                var expected = ContactPublicationAuthorityWireCodec.EncodeRequest(original);
                try
                {
                    if (!Fixed(retained.Request.Span, expected) || !Fixed(retained.Response.Span, response.Span))
                        throw new CryptographicException("Current publication permanent original winner changed.");
                }
                finally { CryptographicOperations.ZeroMemory(expected); }
            }
        }
        catch (OperationCanceledException) when (!cancellation.IsCancellationRequested)
        { Report(phase, "deadline"); throw new ContactPublicationAuthorityUnavailableException(); }
        catch (OperationCanceledException) { Report(phase, "caller-cancelled"); throw; }
        catch (Exception error) when (error is ArgumentException or FormatException or CryptographicException or OverflowException or
            OnionBoundaryException or ContactResolveDirectoryTargetNotFoundException)
        { Report(phase, "authority"); throw new ContactPublicationAuthorityRejectedException(); }
        catch (Exception error) when (error is IOException or InvalidOperationException or Npgsql.NpgsqlException)
        { Report(phase, error is ContactResolveDirectoryAdmissionException ? "proof-rate-limited" : "unavailable"); throw; }
        finally { distribution.Exit(); }
    }

    private void Report(IssuePhase phase, string category)
    {
        ref var timestamp = ref failureLogTimestamps[(int)phase]; var previous = Volatile.Read(ref timestamp);
        if (previous != 0 && System.Diagnostics.Stopwatch.GetElapsedTime(previous) < TimeSpan.FromSeconds(10)) return;
        if (Interlocked.CompareExchange(ref timestamp, System.Diagnostics.Stopwatch.GetTimestamp(), previous) != previous) return;
        logger?.LogWarning("Current publication rejected: phase={Phase}, category={Category}.", phase, category);
    }
    private sealed class CurrentApprovalWitness(IXpa1PublicationAuthorizationWitnessSigner signer,
        Func<CancellationToken, ValueTask> requireAuthority) : IXpa1PublicationAuthorizationWitnessSigner
    {
        public ReadOnlyMemory<byte> WitnessId => signer.WitnessId.ToArray();
        public async ValueTask<ReadOnlyMemory<byte>> SignXpa1Async(ReadOnlyMemory<byte> input, CancellationToken ct)
        {
            // The journal already holds its network transaction during XPA
            // creation. Never recursively read that journal from this callback.
            await requireAuthority(ct).ConfigureAwait(false);
            var signature = (await signer.SignXpa1Async(input, ct).ConfigureAwait(false)).ToArray();
            try { await requireAuthority(ct).ConfigureAwait(false); ct.ThrowIfCancellationRequested(); return signature.ToArray(); }
            finally { CryptographicOperations.ZeroMemory(signature); }
        }
    }
    private sealed class CurrentLeaseWitness(IDeepIdV2PublicationLeaseWitnessSigner signer,
        Func<CancellationToken, ValueTask> requireWinner) : IDeepIdV2PublicationLeaseWitnessSigner
    {
        public ReadOnlyMemory<byte> WitnessId => signer.WitnessId.ToArray();
        public async ValueTask<ReadOnlyMemory<byte>> SignPublicationLeaseAsync(PublicationLeaseSigningRequest request, CancellationToken ct)
        {
            await requireWinner(ct).ConfigureAwait(false);
            var signature = (await signer.SignPublicationLeaseAsync(request, ct).ConfigureAwait(false)).ToArray();
            try { await requireWinner(ct).ConfigureAwait(false); ct.ThrowIfCancellationRequested(); return signature.ToArray(); }
            finally { CryptographicOperations.ZeroMemory(signature); }
        }
    }
    private sealed class CurrentClock(IContactResolveTrustedTimeContextSource source) : IOnionMonotonicClock
    {
        public async ValueTask<OnionMonotonicReading> ReadAsync(CancellationToken ct)
        { var reading = await source.ReadAsync(ct).ConfigureAwait(false); reading.Validate(); return new(reading.ServerBootId.Span, reading.ServerMonotonicSample); }
    }
    internal static IContactPublicationCurrentIssuer CreateFailClosed(IServiceProvider services)
    {
        var proofs = services.GetService<DeepIdV2DirectoryProofIssuer>(); var roots = services.GetService<DeepIdV2XPointAuthoritySource>();
        var distribution = services.GetService<XPointNetworkClosureDistribution>(); var approvals = services.GetService<IContactPublicationAuthorityWitnessCustody>();
        var leases = services.GetService<IContactPublicationLeaseWitnessCustody>(); var time = services.GetService<IContactResolveTrustedTimeContextSource>();
        var journal = services.GetService<IDeepIdV2PublicationJournal>();
        return proofs is null || roots is null || distribution is null || approvals is null || leases is null || time is null || journal is null
            ? new Unavailable() : new ProductionContactPublicationCurrentIssuer(proofs, roots, distribution, approvals, leases, time, journal,
                services.GetService<ILogger<ProductionContactPublicationCurrentIssuer>>());
    }
    private sealed class Unavailable : IContactPublicationCurrentIssuer
    {
        public ValueTask<ParsedDeepIdV2PublicationLease> IssueAsync(PublicationCurrentWireRequest request, CancellationToken ct)
        { ct.ThrowIfCancellationRequested(); return ValueTask.FromException<ParsedDeepIdV2PublicationLease>(new ContactPublicationAuthorityUnavailableException()); }
    }
    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}
#endif
