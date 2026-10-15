#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Registry.Api.DirectoryPublication;

internal interface IContactPublicationWinnerReader
{
    ValueTask<ReadOnlyMemory<byte>> ReadAsync(PublicationWinnerReadWireRequest request, CancellationToken ct);
}

internal sealed class ProductionContactPublicationWinnerReader(
    DeepIdV2DirectoryProofIssuer proofs, DeepIdV2XPointAuthoritySource roots,
    XPointNetworkClosureDistribution distribution, IContactResolveTrustedTimeContextSource timeSource,
    IDeepIdV2PublicationJournal journal,
    ILogger<ProductionContactPublicationWinnerReader>? logger = null) : IContactPublicationWinnerReader
{
    private enum ReadPhase { Admission, Readiness, Winner, Original, TrustedTime, Proof, Recipient, Network, Route, Intent, Request, ProofRecheck, RootRecheck, WinnerRecheck, Release }
    private readonly long[] failureLogTimestamps = new long[(int)ReadPhase.Release + 1];

    public async ValueTask<ReadOnlyMemory<byte>> ReadAsync(PublicationWinnerReadWireRequest candidate, CancellationToken cancellation)
    {
        ArgumentNullException.ThrowIfNull(candidate); cancellation.ThrowIfCancellationRequested();
        var request = DeepIdV2PublicationWinnerReadWireCodec.DecodeRequest(candidate.CanonicalBytes.Span);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellation); deadline.CancelAfter(TimeSpan.FromSeconds(30));
        var ct = deadline.Token;
        if (!distribution.TryEnter())
        { ReportRejection(ReadPhase.Admission, "busy"); throw new ContactPublicationAuthorityUnavailableException(); }
        var phase = ReadPhase.Readiness;
        try
        {
            await proofs.RequireReadyAsync(ct).ConfigureAwait(false);
            phase = ReadPhase.Winner;
            var winner = await ReadWinnerAsync(ct).ConfigureAwait(false);
            phase = ReadPhase.Original;
            var original = Deep.Protocol.ContactV1.ContactPublicationAuthorityWireCodec.DecodeRequest(winner.Request.Span);
            var response = Deep.Protocol.ContactV1.ContactPublicationAuthorityWireCodec.DecodeResponse(original, winner.Response.Span);
            phase = ReadPhase.TrustedTime;
            var trusted = await timeSource.ReadAsync(ct).ConfigureAwait(false); trusted.Validate();
            phase = ReadPhase.Proof;
            var issued = await proofs.IssueAsync(new DeepIdV2DirectoryProofRequest(request.NetworkId.Span,
                RandomNumberGenerator.GetBytes(32), trusted.ServerBootId.Span, trusted.ServerMonotonicSample,
                request.DirectoryLookupKey.Span, request.MinimumDirectoryGeneration, request.MinimumDirectoryHash.Span), ct).ConfigureAwait(false);
            var freshness = issued.Freshness;
            var checkpoint = freshness.CurrentCheckpoint ?? throw new ContactPublicationAuthorityRejectedException();
            var now = await timeSource.ReadAsync(ct).ConfigureAwait(false); now.Validate();
            phase = ReadPhase.Recipient;
            var recipient = DeepIdV2CurrentContactAuthorizationVerifier.Verify(freshness,
                DeepIdV2ContactAuthorizationCodec.Verify(DeepIdV2ContactAuthorizationCodec.Decode(original.ExactDca1.Span),
                    checkpoint.Binding, checkpoint.Directory), now.ServerBootId.Span, now.ServerMonotonicSample);
            phase = ReadPhase.Network;
            var authority = roots.Read(); var frame = await distribution.ReadAsync(ct).ConfigureAwait(false);
            var raw = XPointNetworkClosureWireCodec.DecodeResponse(frame);
            var time = new OnionTrustedTimeAuthority(new CurrentClock(timeSource));
            var network = await OnionNetworkContextVerifier.VerifyAsync(authority, freshness, raw.ExactNetworkPolicyChain,
                raw.ExactViewChain, raw.ExactHeadChain, raw.ExactActiveNodeDescriptors, raw.ExactPlacementTopologyChain,
                null, time, ct).ConfigureAwait(false);
            var contact = DeepIdV2ResolverClosureCodec.Decode(original.ExactDcr1.Span);
            phase = ReadPhase.Route;
            var route = await DeepIdV2ContactRouteVerifier.VerifyAsync(recipient, network, authority,
                contact.Bundle.Field(14)[40..], original.ExactRouteClosure, time, ct).ConfigureAwait(false);
            phase = ReadPhase.Intent;
            var intent = await DeepIdV2PublicationCommitVerifier.VerifyIssuerRetainedIntentAsync(route, original, response.ExactXpu1, ct).ConfigureAwait(false);
            phase = ReadPhase.Request;
            await DeepIdV2PublicationWinnerReadAuthor.VerifyIssuerRequestAsync(intent, request, ct).ConfigureAwait(false);
            phase = ReadPhase.ProofRecheck;
            await proofs.RequireStillCurrentAsync(freshness, raw.ExactViewChain[^1], ct).ConfigureAwait(false);
            phase = ReadPhase.RootRecheck;
            var currentRoot = roots.Read();
            if (!Fixed(currentRoot.AuthorityCoreReference.Span, authority.AuthorityCoreReference.Span) ||
                !Fixed(currentRoot.Dts1PolicyCoreReference.Span, authority.Dts1PolicyCoreReference.Span) ||
                !Fixed(currentRoot.TimeSourcePolicyHash.Span, authority.TimeSourcePolicyHash.Span) ||
                !Fixed(await distribution.ReadAsync(ct).ConfigureAwait(false), frame))
                throw new CryptographicException("Publication winner read authority changed before release.");
            phase = ReadPhase.WinnerRecheck;
            var final = await ReadWinnerAsync(ct).ConfigureAwait(false);
            if (!Fixed(final.Request.Span, winner.Request.Span) || !Fixed(final.Response.Span, winner.Response.Span))
                throw new CryptographicException("Publication winner read changed its original permanent winner.");
            phase = ReadPhase.Release;
            await DeepIdV2PublicationWinnerReadAuthor.VerifyIssuerRequestAsync(intent, request, ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested(); return winner.Response.ToArray();

            ValueTask<(ReadOnlyMemory<byte> Request, ReadOnlyMemory<byte> Response)> ReadWinnerAsync(CancellationToken token) =>
                journal.ReadCompletedCoordinationWinnerAsync(request.OriginalCoordinationNonce, request.DirectoryLookupKey,
                    request.OriginalCoordinationRequestHash, token);
        }
        catch (OperationCanceledException) when (!cancellation.IsCancellationRequested)
        { ReportRejection(phase, "deadline"); throw new ContactPublicationAuthorityUnavailableException(); }
        catch (OperationCanceledException)
        { ReportRejection(phase, "caller-cancelled"); throw; }
        catch (ContactPublicationAuthorityRejectedException)
        { ReportRejection(phase, "rejected"); throw; }
        catch (Exception error) when (error is ArgumentException or FormatException or CryptographicException or OverflowException or
            OnionBoundaryException or ContactResolveDirectoryTargetNotFoundException)
        { ReportRejection(phase, "authority"); throw new ContactPublicationAuthorityRejectedException(); }
        catch (Exception error) when (error is IOException or InvalidOperationException or Npgsql.NpgsqlException)
        { ReportRejection(phase, error is ContactResolveDirectoryAdmissionException ? "proof-rate-limited" : "unavailable"); throw; }
        finally { distribution.Exit(); }
    }

    private void ReportRejection(ReadPhase phase, string category)
    {
        // Fixed bounded buckets only; never log requests, exceptions, identifiers,
        // capabilities or caller-controlled values. Diagnostics grant no authority.
        ref var timestamp = ref failureLogTimestamps[(int)phase];
        var previous = Volatile.Read(ref timestamp);
        if (previous != 0 && System.Diagnostics.Stopwatch.GetElapsedTime(previous) < TimeSpan.FromSeconds(10)) return;
        if (Interlocked.CompareExchange(ref timestamp, System.Diagnostics.Stopwatch.GetTimestamp(), previous) != previous) return;
        logger?.LogWarning("Publication winner read rejected: phase={Phase}, category={Category}.", phase, category);
    }

    internal static IContactPublicationWinnerReader CreateFailClosed(IServiceProvider services)
    {
        var proofs = services.GetService<DeepIdV2DirectoryProofIssuer>(); var roots = services.GetService<DeepIdV2XPointAuthoritySource>();
        var distribution = services.GetService<XPointNetworkClosureDistribution>();
        var time = services.GetService<IContactResolveTrustedTimeContextSource>(); var journal = services.GetService<IDeepIdV2PublicationJournal>();
        return proofs is null || roots is null || distribution is null || time is null || journal is null
            ? new Unavailable() : new ProductionContactPublicationWinnerReader(proofs, roots, distribution, time, journal,
                services.GetService<ILogger<ProductionContactPublicationWinnerReader>>());
    }
    private sealed class Unavailable : IContactPublicationWinnerReader
    {
        public ValueTask<ReadOnlyMemory<byte>> ReadAsync(PublicationWinnerReadWireRequest request, CancellationToken ct)
        { ct.ThrowIfCancellationRequested(); return ValueTask.FromException<ReadOnlyMemory<byte>>(new ContactPublicationAuthorityUnavailableException()); }
    }
    private sealed class CurrentClock(IContactResolveTrustedTimeContextSource source) : IOnionMonotonicClock
    {
        public async ValueTask<OnionMonotonicReading> ReadAsync(CancellationToken ct)
        { var value = await source.ReadAsync(ct).ConfigureAwait(false); value.Validate(); return new(value.ServerBootId.Span, value.ServerMonotonicSample); }
    }
    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}
#endif
