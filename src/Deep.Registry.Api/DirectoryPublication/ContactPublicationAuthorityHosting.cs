#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection.Extensions;
using ProtocolMagic = Deep.Protocol.Registry.DeepProtocolIdentifiers.Magic;

namespace Deep.Registry.Api.DirectoryPublication;

internal interface IContactPublicationAuthorityWitnessCustody
{
    ValueTask<IReadOnlyList<IXpa1PublicationAuthorizationWitnessSigner>>
        GetPublicationSignersAsync(
            VerifiedXPointNetworkAuthority authority,
            CancellationToken cancellationToken);
}

internal interface IContactPublicationThresholdIssuer
{
    ValueTask<ContactPublicationAuthorityWireResponse> IssueAsync(
        ContactPublicationAuthorityWireRequest request,
        CancellationToken cancellationToken);
}

internal sealed class ContactPublicationAuthorityUnavailableException : IOException;
internal sealed class ContactPublicationAuthorityRejectedException : CryptographicException;

internal sealed class ProductionContactPublicationThresholdIssuer :
    IContactPublicationThresholdIssuer
{
    private readonly IContactResolveCanonicalDirectorySnapshotSource snapshotSource;
    private readonly IContactResolveDirectoryProofMaterialSource proofSource;
    private readonly IContactResolveDtt1WitnessCustody directoryWitnessCustody;
    private readonly IContactPublicationAuthorityWitnessCustody publicationWitnessCustody;
    private readonly IContactResolveOneUseRequestLedger requestLedger;
    private readonly IContactResolveTrustedTimeContextSource trustedTimeSource;

    internal ProductionContactPublicationThresholdIssuer(
        IContactResolveCanonicalDirectorySnapshotSource snapshotSource,
        IContactResolveDirectoryProofMaterialSource proofSource,
        IContactResolveDtt1WitnessCustody directoryWitnessCustody,
        IContactPublicationAuthorityWitnessCustody publicationWitnessCustody,
        IContactResolveOneUseRequestLedger requestLedger,
        IContactResolveTrustedTimeContextSource trustedTimeSource)
    {
        this.snapshotSource = snapshotSource ?? throw new ArgumentNullException(nameof(snapshotSource));
        this.proofSource = proofSource ?? throw new ArgumentNullException(nameof(proofSource));
        this.directoryWitnessCustody = directoryWitnessCustody ??
            throw new ArgumentNullException(nameof(directoryWitnessCustody));
        this.publicationWitnessCustody = publicationWitnessCustody ??
            throw new ArgumentNullException(nameof(publicationWitnessCustody));
        this.requestLedger = requestLedger ?? throw new ArgumentNullException(nameof(requestLedger));
        this.trustedTimeSource = trustedTimeSource ??
            throw new ArgumentNullException(nameof(trustedTimeSource));
    }

    public async ValueTask<ContactPublicationAuthorityWireResponse> IssueAsync(
        ContactPublicationAuthorityWireRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            var trusted = await trustedTimeSource.ReadAsync(cancellationToken).ConfigureAwait(false);
            trusted.Validate();
            var directoryRequest = new ContactResolveDirectoryPackageRequest(
                request.NetworkId.ToArray(), request.RequestNonce.ToArray(),
                trusted.ServerBootId.ToArray(), trusted.ServerMonotonicSample,
                null, null, null,
                request.DirectoryLookupKey.ToArray(),
                request.MinimumAdh1Generation,
                request.MinimumAdh1CoreHash.ToArray(),
                requireCurrentValue: true);
            var snapshot = await snapshotSource.ReadAsync(directoryRequest, cancellationToken)
                .ConfigureAwait(false) ?? throw new ContactPublicationAuthorityUnavailableException();
            if (!Fixed(snapshot.NetworkId.Span, request.NetworkId.Span))
                throw new ContactPublicationAuthorityRejectedException();
            var proof = await proofSource.ReadAsync(snapshot, directoryRequest, cancellationToken)
                .ConfigureAwait(false) ?? throw new ContactPublicationAuthorityUnavailableException();
            if (proof.ResultKind != AccountDirectoryAdp1ResultKind.CurrentValue ||
                !Fixed(proof.QueriedDirectoryLeafKey.Span, request.DirectoryLookupKey.Span) ||
                proof.CurrentCheckpoint is not { } checkpoint)
                throw new ContactPublicationAuthorityRejectedException();

            var parsedDca = ApplicationCoreCodec.DecodeDca1(request.ExactDca1.Span);
            var verifiedDca = ApplicationCoreVerifier.VerifyDca1(
                parsedDca, checkpoint.Binding, checkpoint.Directory);
            if (checkpoint.IsDcaAuthorizationRevoked(parsedDca.AuthorizationId.Span))
                throw new ContactPublicationAuthorityRejectedException();
            var recipientDevice = checkpoint.Directory.Identity.ActiveDevices.SingleOrDefault(
                device => Fixed(device.Certificate.DeviceId.Span, parsedDca.PublisherDeviceId.Span)) ??
                throw new ContactPublicationAuthorityRejectedException();

            var issuanceEpoch = AccountDirectoryDtt1IssuanceEpoch.Derive(
                snapshot.Authority, trusted.ObservedUnixTime, trusted.UncertaintySeconds);
            await requestLedger.ConsumeAsync(
                directoryRequest, trusted, issuanceEpoch, cancellationToken).ConfigureAwait(false);
            var directorySigners = await directoryWitnessCustody.GetSignersAsync(
                snapshot.Authority, cancellationToken).ConfigureAwait(false);
            var lower = trusted.ObservedUnixTime - trusted.UncertaintySeconds;
            var upper = trusted.ObservedUnixTime + trusted.UncertaintySeconds;
            var proofRequest = new AccountDirectoryProofAuthoringRequest(
                request.NetworkId.Span,
                request.RequestNonce.Span,
                trusted.ServerBootId.Span,
                trusted.ServerMonotonicSample,
                snapshot.CurrentDirectoryHead.ExactAdh1.Span,
                snapshot.ExactCurrentXnv1.Span,
                trusted.ObservedUnixTime,
                trusted.UncertaintySeconds,
                lower,
                upper,
                issuanceEpoch,
                snapshot.SupportedReader);
            var authoredProof = await AccountDirectoryProofAuthor.IssueAsync(
                snapshot.Authority,
                snapshot.CurrentDirectoryHead,
                proofRequest,
                proof,
                directorySigners,
                cancellationToken).ConfigureAwait(false);
            var freshness = AccountDirectoryCurrentProofVerifier.Verify(
                snapshot.Authority,
                authoredProof.ExactAdh1,
                authoredProof.ExactDtt1,
                authoredProof.ExactAdp1,
                request.RequestNonce.Span,
                request.DirectoryLookupKey.Span,
                new AccountDirectoryMonotonicRequestWindow(
                    trusted.ServerBootId.Span,
                    trusted.ServerMonotonicSample,
                    trusted.ServerMonotonicSample,
                    trusted.ServerMonotonicSample),
                proof.CallerProtectedLkg,
                checkpoint,
                snapshot.SupportedReader);
            var currentDca = ApplicationCoreVerifier.RequireDca1CurrentlyAuthoritative(
                verifiedDca, freshness.TrustedUpperUnixSeconds);
            var monotonicClock = new FixedOnionMonotonicClock(
                trusted.ServerBootId.Span, trusted.ServerMonotonicSample);
            var trustedTimeAuthority = new OnionTrustedTimeAuthority(monotonicClock);
            var currentNetwork = await OnionNetworkContextVerifier.VerifyAsync(
                snapshot.Authority,
                freshness,
                snapshot.ExactOrderedXvp1Chain,
                snapshot.ExactOrderedXnv1Chain,
                snapshot.ExactOrderedXnh1Chain,
                snapshot.ExactActiveXnd1,
                snapshot.ExactOrderedPmt2Chain,
                protectedPrevious: null,
                trustedTimeAuthority,
                cancellationToken).ConfigureAwait(false);
            var proposal = await ContactNetworkAuthorityVerifier.VerifyProposalAsync(
                snapshot.Authority,
                currentNetwork,
                freshness,
                recipientDevice,
                currentDca,
                snapshot.ExactOrderedXnv1Chain[^1],
                snapshot.ExactOrderedXnh1Chain[^1],
                authoredProof.ExactAdh1,
                snapshot.ExactOrderedPmt2Chain[^1],
                trustedTimeAuthority,
                cancellationToken).ConfigureAwait(false);

            var parsedRoute = ContactRouteClosureCodec.Decode(request.ExactRouteClosure.Span);
            var advertisement = ContactRouteAdvertisementVerifier.VerifyExact(
                proposal, parsedRoute.Authorization.CanonicalBytes);
            var threshold = await ContactRouteThresholdVerifier.VerifyExactAsync(
                proposal,
                advertisement,
                parsedRoute.Selection.CanonicalBytes,
                parsedRoute.Route.CanonicalBytes,
                parsedRoute.Successor.CanonicalBytes,
                cancellationToken).ConfigureAwait(false);
            var dcr = ContactCodec.Decode(ProtocolMagic.DCR1, request.ExactDcr1.Span);
            var contact = ContactCodec.VerifyDcr1Closure(
                dcr,
                currentDca,
                freshness,
                trusted.ServerBootId.Span,
                trusted.ServerMonotonicSample);
            var descriptor = contact.Bundle.Field(14);
            if (descriptor.Length != 651)
                throw new ContactPublicationAuthorityRejectedException();
            var invite = ContactCodec.Decode(ProtocolMagic.XIR1, descriptor.Span.Slice(40, 611));
            var route = ContactCodec.VerifyRouteUpdateClosure(
                invite,
                parsedRoute.Reachability,
                parsedRoute.Authorization,
                parsedRoute.Route,
                parsedRoute.Successor,
                parsedRoute.Projection,
                parsedRoute.Selection,
                threshold.Authority);
            using var resolution = PermanentContactResolutionDerivation.Derive(
                snapshot.Authority.NetworkId.Span, contact.Binding.DeepId);
            var placement = ContactServicePlacementFactory.Create(
                currentNetwork, ContactServiceRequestKind.PublishInvite,
                resolution.LocatorHash);
            var authoringRequest = new PermanentAddressPublicationAuthorizationRequest(
                request.OperationId.Span,
                request.Generation,
                request.PredecessorObjectHash.Span,
                request.ObjectCiphertext.Span,
                request.IssuedAtUnixSeconds,
                request.ExpiresAtUnixSeconds,
                request.EffectiveExpiresAtUnixSeconds,
                request.OwnerRetrieveCapability.Span,
                request.PublisherSignature.Span);
            var signers = await publicationWitnessCustody.GetPublicationSignersAsync(
                snapshot.Authority, cancellationToken).ConfigureAwait(false);
            var authored = await Xpa1PublicationAuthorizationAuthor.AuthorPermanentAsync(
                authoringRequest,
                contact,
                route,
                snapshot.Authority,
                placement,
                trustedTimeAuthority,
                signers,
                cancellationToken).ConfigureAwait(false);
            return new ContactPublicationAuthorityWireResponse(
                request.NetworkId.Span,
                request.RequestNonce.Span,
                authored.ExactXpu1.Span);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (ContactPublicationAuthorityRejectedException)
        {
            throw;
        }
        catch (Exception exception) when (exception is
            ContactResolveDirectoryTargetNotFoundException or
            ContactNetworkAuthorityVerificationException or
            ContactPublicationAuthoringException or
            Xpa1PublicationAuthorizationAuthoringException or
            AccountDirectoryFreshnessVerificationException)
        {
            throw new ContactPublicationAuthorityRejectedException();
        }
        catch (Exception exception) when (exception is ArgumentException or FormatException or
            CryptographicException or OverflowException or InvalidOperationException)
        {
            throw new ContactPublicationAuthorityRejectedException();
        }
    }

    internal static IContactPublicationThresholdIssuer CreateFailClosed(IServiceProvider services)
    {
        ArgumentNullException.ThrowIfNull(services);
        var probe = services.GetService<IServiceProviderIsService>();
        if (probe is null ||
            !probe.IsService(typeof(IContactResolveCanonicalDirectorySnapshotSource)) ||
            !probe.IsService(typeof(IContactResolveDirectoryProofMaterialSource)) ||
            !probe.IsService(typeof(IContactResolveDtt1WitnessCustody)) ||
            !probe.IsService(typeof(IContactPublicationAuthorityWitnessCustody)) ||
            !probe.IsService(typeof(IContactResolveOneUseRequestLedger)) ||
            !probe.IsService(typeof(IContactResolveTrustedTimeContextSource)))
            return new UnavailableContactPublicationThresholdIssuer();
        return new ProductionContactPublicationThresholdIssuer(
            services.GetRequiredService<IContactResolveCanonicalDirectorySnapshotSource>(),
            services.GetRequiredService<IContactResolveDirectoryProofMaterialSource>(),
            services.GetRequiredService<IContactResolveDtt1WitnessCustody>(),
            services.GetRequiredService<IContactPublicationAuthorityWitnessCustody>(),
            services.GetRequiredService<IContactResolveOneUseRequestLedger>(),
            services.GetRequiredService<IContactResolveTrustedTimeContextSource>());
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    private sealed class FixedOnionMonotonicClock : IOnionMonotonicClock
    {
        private readonly byte[] bootId;
        private readonly ulong sample;

        internal FixedOnionMonotonicClock(ReadOnlySpan<byte> bootId, ulong sample)
        {
            this.bootId = bootId.ToArray();
            this.sample = sample;
        }

        public ValueTask<OnionMonotonicReading> ReadAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(new OnionMonotonicReading(bootId, sample));
        }
    }
}

internal sealed class UnavailableContactPublicationThresholdIssuer :
    IContactPublicationThresholdIssuer
{
    public ValueTask<ContactPublicationAuthorityWireResponse> IssueAsync(
        ContactPublicationAuthorityWireRequest request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromException<ContactPublicationAuthorityWireResponse>(
            new ContactPublicationAuthorityUnavailableException());
    }
}

internal sealed class ContactPublicationAuthorityOptions
{
    public bool Enabled { get; set; }
}

internal readonly struct ContactPublicationAuthorityHostingState
{
    private readonly byte[]? networkId;
    internal ContactPublicationAuthorityHostingState(ReadOnlySpan<byte> networkId) =>
        this.networkId = networkId.ToArray();
    internal ReadOnlyMemory<byte> NetworkId => networkId?.ToArray() ?? [];
}

internal static class ContactPublicationAuthorityHostingExtensions
{
    internal const string EndpointPath = "/api/v1/contact-publication-authority";

    internal static ContactPublicationAuthorityHostingState AddContactPublicationAuthority(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<ContactResolveIssuanceAdmissionGate>();
        services.RemoveAll<IContactPublicationThresholdIssuer>();
        services.AddSingleton(ProductionContactPublicationThresholdIssuer.CreateFailClosed);
        var options = configuration.GetSection("ContactPublicationAuthority")
            .Get<ContactPublicationAuthorityOptions>() ?? new();
        if (!options.Enabled) return default;
        var authority = ContactResolveProductionAuthorityServiceCollectionExtensions
            .ReadRequiredOptions(configuration);
        var network = DirectoryPublicationHostingExtensions.Hex(
            authority.NetworkIdHex, 16, "Contact publication-authority network ID");
        return new ContactPublicationAuthorityHostingState(network);
    }

    internal static void MapContactPublicationAuthorityEndpoint(
        this WebApplication app,
        ContactPublicationAuthorityHostingState state)
    {
        ArgumentNullException.ThrowIfNull(app);
        app.MapPost(EndpointPath, (
                HttpContext context,
                IContactPublicationThresholdIssuer issuer,
                ContactResolveIssuanceAdmissionGate admission,
                CancellationToken cancellationToken) =>
                HandleAsync(context, issuer, admission, state, cancellationToken))
            .WithMetadata(new RequestSizeLimitAttribute(
                ContactPublicationAuthorityWireCodec.MaximumRequestBytes));
    }

    private static async Task<IResult> HandleAsync(
        HttpContext context,
        IContactPublicationThresholdIssuer issuer,
        ContactResolveIssuanceAdmissionGate admission,
        ContactPublicationAuthorityHostingState state,
        CancellationToken cancellationToken)
    {
        SetNoStore(context.Response);
        var decision = admission.TryAcquire(context.Connection.RemoteIpAddress);
        if (!decision.IsAccepted)
        {
            context.Response.Headers.RetryAfter = decision.RetryAfterSeconds.ToString(
                System.Globalization.CultureInfo.InvariantCulture);
            return Empty(context.Response, StatusCodes.Status429TooManyRequests);
        }
        if (!string.Equals(context.Request.ContentType,
                ContactPublicationAuthorityWireCodec.RequestMediaType,
                StringComparison.OrdinalIgnoreCase))
            return Empty(context.Response, StatusCodes.Status415UnsupportedMediaType);
        if (context.Request.ContentLength is null)
            return Empty(context.Response, StatusCodes.Status411LengthRequired);
        if (context.Request.ContentLength > ContactPublicationAuthorityWireCodec.MaximumRequestBytes)
            return Empty(context.Response, StatusCodes.Status413PayloadTooLarge);
        if (context.Request.ContentLength < ContactPublicationAuthorityWireCodec.MinimumRequestBytes)
            return Empty(context.Response, StatusCodes.Status400BadRequest);
        var encoded = GC.AllocateUninitializedArray<byte>(checked((int)context.Request.ContentLength));
        try
        {
            await context.Request.Body.ReadExactlyAsync(encoded, cancellationToken)
                .ConfigureAwait(false);
            var request = ContactPublicationAuthorityWireCodec.DecodeRequest(encoded);
            if (state.NetworkId.IsEmpty)
                return Empty(context.Response, StatusCodes.Status503ServiceUnavailable);
            if (!CryptographicOperations.FixedTimeEquals(
                    request.NetworkId.Span, state.NetworkId.Span))
                return Empty(context.Response, StatusCodes.Status404NotFound);
            try
            {
                var response = await issuer.IssueAsync(request, cancellationToken)
                    .ConfigureAwait(false);
                var body = ContactPublicationAuthorityWireCodec.EncodeResponse(request, response);
                context.Response.ContentLength = body.Length;
                return Results.Bytes(body, ContactPublicationAuthorityWireCodec.ResponseMediaType,
                    enableRangeProcessing: false);
            }
            catch (ContactPublicationAuthorityRejectedException)
            {
                return Empty(context.Response, StatusCodes.Status404NotFound);
            }
            catch (ContactResolveDirectoryAdmissionException)
            {
                context.Response.Headers.RetryAfter = "10";
                return Empty(context.Response, StatusCodes.Status429TooManyRequests);
            }
            catch (Exception exception) when (exception is
                ContactPublicationAuthorityUnavailableException or IOException or
                UnauthorizedAccessException or InvalidDataException or InvalidOperationException)
            {
                return Empty(context.Response, StatusCodes.Status503ServiceUnavailable);
            }
        }
        catch (EndOfStreamException)
        {
            return Empty(context.Response, StatusCodes.Status400BadRequest);
        }
        catch (Exception exception) when (exception is ArgumentException or FormatException or
            CryptographicException or OverflowException)
        {
            return Empty(context.Response, StatusCodes.Status400BadRequest);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encoded);
        }
    }

    private static IResult Empty(HttpResponse response, int statusCode)
    {
        response.ContentLength = 0;
        response.ContentType = null;
        return Results.StatusCode(statusCode);
    }

    private static void SetNoStore(HttpResponse response)
    {
        response.Headers.CacheControl = "no-store, private, max-age=0";
        response.Headers.Pragma = "no-cache";
        response.Headers.Expires = "0";
        response.Headers["X-Content-Type-Options"] = "nosniff";
    }
}
#else
namespace Deep.Registry.Api.DirectoryPublication;

internal readonly struct ContactPublicationAuthorityHostingState;

internal static class ContactPublicationAuthorityHostingExtensions
{
    internal const string EndpointPath = "/api/v1/contact-publication-authority";

    internal static ContactPublicationAuthorityHostingState AddContactPublicationAuthority(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);
        return default;
    }

    internal static void MapContactPublicationAuthorityEndpoint(
        this WebApplication app,
        ContactPublicationAuthorityHostingState state)
    {
        ArgumentNullException.ThrowIfNull(app);
        app.MapPost(EndpointPath, static (HttpContext context) =>
        {
            context.Response.Headers.CacheControl = "no-store, private, max-age=0";
            context.Response.ContentLength = 0;
            return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
        });
    }
}
#endif
