#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Deep.Registry.Api.DirectoryPublication;

internal interface IContactRouteAuthorityWitnessCustody
{
    ValueTask<IReadOnlyList<IContactRouteAuthorityWitnessSigner>> GetRouteSignersAsync(
        Deep.Protocol.XPointNetworkV1.VerifiedXPointNetworkAuthority authority,
        CancellationToken cancellationToken);
}

internal interface IContactRouteThresholdIssuer
{
    ValueTask<ContactRouteAuthorityWireResponse> IssueAsync(
        ContactRouteAuthorityWireRequest request,
        CancellationToken cancellationToken);
}

internal sealed class ContactRouteAuthorityUnavailableException : IOException;
internal sealed class ContactRouteAuthorityRejectedException : CryptographicException;

internal sealed class ProductionContactRouteThresholdIssuer : IContactRouteThresholdIssuer
{
    private readonly IContactResolveCanonicalDirectorySnapshotSource snapshotSource;
    private readonly IContactResolveDirectoryProofMaterialSource proofSource;
    private readonly IContactResolveDtt1WitnessCustody directoryWitnessCustody;
    private readonly IContactRouteAuthorityWitnessCustody routeWitnessCustody;
    private readonly IContactResolveOneUseRequestLedger requestLedger;
    private readonly IContactResolveTrustedTimeContextSource trustedTimeSource;

    internal ProductionContactRouteThresholdIssuer(
        IContactResolveCanonicalDirectorySnapshotSource snapshotSource,
        IContactResolveDirectoryProofMaterialSource proofSource,
        IContactResolveDtt1WitnessCustody directoryWitnessCustody,
        IContactRouteAuthorityWitnessCustody routeWitnessCustody,
        IContactResolveOneUseRequestLedger requestLedger,
        IContactResolveTrustedTimeContextSource trustedTimeSource)
    {
        this.snapshotSource = snapshotSource ?? throw new ArgumentNullException(nameof(snapshotSource));
        this.proofSource = proofSource ?? throw new ArgumentNullException(nameof(proofSource));
        this.directoryWitnessCustody = directoryWitnessCustody ??
            throw new ArgumentNullException(nameof(directoryWitnessCustody));
        this.routeWitnessCustody = routeWitnessCustody ??
            throw new ArgumentNullException(nameof(routeWitnessCustody));
        this.requestLedger = requestLedger ?? throw new ArgumentNullException(nameof(requestLedger));
        this.trustedTimeSource = trustedTimeSource ??
            throw new ArgumentNullException(nameof(trustedTimeSource));
    }

    public async ValueTask<ContactRouteAuthorityWireResponse> IssueAsync(
        ContactRouteAuthorityWireRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            var trusted = await trustedTimeSource.ReadAsync(cancellationToken).ConfigureAwait(false);
            trusted.Validate();
            var directoryRequest = new ContactResolveDirectoryPackageRequest(
                request.NetworkId.ToArray(),
                request.RequestNonce.ToArray(),
                trusted.ServerBootId.ToArray(),
                trusted.ServerMonotonicSample,
                null,
                null,
                null,
                request.DirectoryLookupKey.ToArray(),
                request.MinimumAdh1Generation,
                request.MinimumAdh1CoreHash.ToArray(),
                requireCurrentValue: true);
            var snapshot = await snapshotSource.ReadAsync(directoryRequest, cancellationToken)
                .ConfigureAwait(false) ?? throw new ContactRouteAuthorityUnavailableException();
            if (!Fixed(snapshot.NetworkId.Span, request.NetworkId.Span))
                throw new ContactRouteAuthorityRejectedException();
            var proof = await proofSource.ReadAsync(snapshot, directoryRequest, cancellationToken)
                .ConfigureAwait(false) ?? throw new ContactRouteAuthorityUnavailableException();
            if (proof.ResultKind != AccountDirectoryAdp1ResultKind.CurrentValue ||
                !Fixed(proof.QueriedDirectoryLeafKey.Span, request.DirectoryLookupKey.Span) ||
                proof.CurrentCheckpoint is not { } checkpoint)
                throw new ContactRouteAuthorityRejectedException();

            var parsedDca = ApplicationCoreCodec.DecodeDca1(request.ExactDca1.Span);
            var verifiedDca = ApplicationCoreVerifier.VerifyDca1(
                parsedDca, checkpoint.Binding, checkpoint.Directory);
            if (checkpoint.IsDcaAuthorizationRevoked(parsedDca.AuthorizationId.Span))
                throw new ContactRouteAuthorityRejectedException();
            var recipientDevice = checkpoint.Directory.Identity.ActiveDevices.SingleOrDefault(
                device => Fixed(
                    device.Certificate.DeviceId.Span, parsedDca.PublisherDeviceId.Span)) ??
                throw new ContactRouteAuthorityRejectedException();

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
            var advertisement = ContactRouteAdvertisementVerifier.VerifyExact(
                proposal, request.ExactXra1);
            var issuedAt = proposal.TrustedLowerUnixSeconds;
            var advertisementExpires = System.Buffers.Binary.BinaryPrimitives
                .ReadUInt64BigEndian(advertisement.Record.Field(13).Span);
            var oneDay = issuedAt > ulong.MaxValue - 86_400
                ? ulong.MaxValue
                : issuedAt + 86_400;
            var expiresAt = Math.Min(
                Math.Min(proposal.ExpiresAtUnixSeconds, advertisementExpires), oneDay);
            if (expiresAt <= proposal.TrustedUpperUnixSeconds)
                throw new ContactRouteAuthorityRejectedException();
            var routeSigners = await routeWitnessCustody.GetRouteSignersAsync(
                snapshot.Authority, cancellationToken).ConfigureAwait(false);
            var threshold = await ContactRouteThresholdAuthor.AuthorAsync(
                new ContactRouteThresholdAuthoringRequest(
                    proposal, advertisement, issuedAt, expiresAt),
                routeSigners,
                cancellationToken).ConfigureAwait(false);
            return new ContactRouteAuthorityWireResponse(
                request.NetworkId.Span,
                request.RequestNonce.Span,
                threshold.ExactPms2.Span,
                threshold.ExactXrc1.Span,
                threshold.ExactXss1.Span);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (ContactRouteAuthorityRejectedException)
        {
            throw;
        }
        catch (Exception exception) when (exception is
            ContactResolveDirectoryTargetNotFoundException or
            ContactNetworkAuthorityVerificationException or
            ContactPublicationAuthoringException or
            AccountDirectoryFreshnessVerificationException)
        {
            throw new ContactRouteAuthorityRejectedException();
        }
        catch (Exception exception) when (exception is ArgumentException or FormatException or
            CryptographicException or OverflowException)
        {
            throw new ContactRouteAuthorityRejectedException();
        }
    }

    internal static IContactRouteThresholdIssuer CreateFailClosed(IServiceProvider services)
    {
        ArgumentNullException.ThrowIfNull(services);
        var probe = services.GetService<IServiceProviderIsService>();
        if (probe is null ||
            !probe.IsService(typeof(IContactResolveCanonicalDirectorySnapshotSource)) ||
            !probe.IsService(typeof(IContactResolveDirectoryProofMaterialSource)) ||
            !probe.IsService(typeof(IContactResolveDtt1WitnessCustody)) ||
            !probe.IsService(typeof(IContactRouteAuthorityWitnessCustody)) ||
            !probe.IsService(typeof(IContactResolveOneUseRequestLedger)) ||
            !probe.IsService(typeof(IContactResolveTrustedTimeContextSource)))
            return new UnavailableContactRouteThresholdIssuer();
        return new ProductionContactRouteThresholdIssuer(
            services.GetRequiredService<IContactResolveCanonicalDirectorySnapshotSource>(),
            services.GetRequiredService<IContactResolveDirectoryProofMaterialSource>(),
            services.GetRequiredService<IContactResolveDtt1WitnessCustody>(),
            services.GetRequiredService<IContactRouteAuthorityWitnessCustody>(),
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

internal sealed class UnavailableContactRouteThresholdIssuer : IContactRouteThresholdIssuer
{
    public ValueTask<ContactRouteAuthorityWireResponse> IssueAsync(
        ContactRouteAuthorityWireRequest request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromException<ContactRouteAuthorityWireResponse>(
            new ContactRouteAuthorityUnavailableException());
    }
}

internal sealed class ContactRouteAuthorityOptions
{
    public bool Enabled { get; set; }
}

internal readonly struct ContactRouteAuthorityHostingState
{
    private readonly byte[]? networkId;

    internal ContactRouteAuthorityHostingState(ReadOnlySpan<byte> networkId) =>
        this.networkId = networkId.ToArray();

    internal ReadOnlyMemory<byte> NetworkId => networkId?.ToArray() ?? [];
}

internal static class ContactRouteAuthorityHostingExtensions
{
    internal const string EndpointPath = "/api/v1/contact-route-authority";

    internal static ContactRouteAuthorityHostingState AddContactRouteAuthority(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<ContactResolveIssuanceAdmissionGate>();
        services.RemoveAll<IContactRouteThresholdIssuer>();
        services.AddSingleton(ProductionContactRouteThresholdIssuer.CreateFailClosed);
        var options = configuration.GetSection("ContactRouteAuthority")
            .Get<ContactRouteAuthorityOptions>() ?? new();
        if (!options.Enabled) return default;
        var authority = ContactResolveProductionAuthorityServiceCollectionExtensions
            .ReadRequiredOptions(configuration);
        var network = DirectoryPublicationHostingExtensions.Hex(
            authority.NetworkIdHex, 16, "ContactRouteAuthority network ID");
        return new ContactRouteAuthorityHostingState(network);
    }

    internal static void MapContactRouteAuthorityEndpoint(
        this WebApplication app,
        ContactRouteAuthorityHostingState state)
    {
        ArgumentNullException.ThrowIfNull(app);
        app.MapPost(EndpointPath, (
                HttpContext context,
                IContactRouteThresholdIssuer issuer,
                ContactResolveIssuanceAdmissionGate admission,
                CancellationToken cancellationToken) =>
                HandleAsync(context, issuer, admission, state, cancellationToken))
            .WithMetadata(new RequestSizeLimitAttribute(
                ContactRouteAuthorityWireCodec.RequestBytes));
    }

    private static async Task<IResult> HandleAsync(
        HttpContext context,
        IContactRouteThresholdIssuer issuer,
        ContactResolveIssuanceAdmissionGate admission,
        ContactRouteAuthorityHostingState state,
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
                ContactRouteAuthorityWireCodec.RequestMediaType,
                StringComparison.OrdinalIgnoreCase))
            return Empty(context.Response, StatusCodes.Status415UnsupportedMediaType);
        if (context.Request.ContentLength is null)
            return Empty(context.Response, StatusCodes.Status411LengthRequired);
        if (context.Request.ContentLength > ContactRouteAuthorityWireCodec.RequestBytes)
            return Empty(context.Response, StatusCodes.Status413PayloadTooLarge);
        if (context.Request.ContentLength != ContactRouteAuthorityWireCodec.RequestBytes)
            return Empty(context.Response, StatusCodes.Status400BadRequest);
        var encoded = GC.AllocateUninitializedArray<byte>(
            ContactRouteAuthorityWireCodec.RequestBytes);
        try
        {
            await context.Request.Body.ReadExactlyAsync(encoded, cancellationToken)
                .ConfigureAwait(false);
            var request = ContactRouteAuthorityWireCodec.DecodeRequest(encoded);
            if (state.NetworkId.IsEmpty)
                return Empty(context.Response, StatusCodes.Status503ServiceUnavailable);
            if (!CryptographicOperations.FixedTimeEquals(
                    request.NetworkId.Span, state.NetworkId.Span))
                return Empty(context.Response, StatusCodes.Status404NotFound);
            try
            {
                var response = await issuer.IssueAsync(request, cancellationToken)
                    .ConfigureAwait(false);
                var body = ContactRouteAuthorityWireCodec.EncodeResponse(request, response);
                context.Response.ContentLength = body.Length;
                return Results.Bytes(body, ContactRouteAuthorityWireCodec.ResponseMediaType,
                    enableRangeProcessing: false);
            }
            catch (ContactRouteAuthorityRejectedException)
            {
                return Empty(context.Response, StatusCodes.Status404NotFound);
            }
            catch (ContactResolveDirectoryAdmissionException)
            {
                context.Response.Headers.RetryAfter = "10";
                return Empty(context.Response, StatusCodes.Status429TooManyRequests);
            }
            catch (Exception exception) when (exception is
                ContactRouteAuthorityUnavailableException or IOException or
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

internal readonly struct ContactRouteAuthorityHostingState;

internal static class ContactRouteAuthorityHostingExtensions
{
    internal const string EndpointPath = "/api/v1/contact-route-authority";

    internal static ContactRouteAuthorityHostingState AddContactRouteAuthority(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);
        return default;
    }

    internal static void MapContactRouteAuthorityEndpoint(
        this WebApplication app,
        ContactRouteAuthorityHostingState state)
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
