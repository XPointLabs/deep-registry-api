#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Deep.Registry.Api.DirectoryPublication;

internal interface IContactPublicationAuthorityWitnessCustody
{
    ValueTask<IReadOnlyList<IXpa1PublicationAuthorizationWitnessSigner>> GetPublicationSignersAsync(
        Deep.Protocol.XPointNetworkV1.VerifiedXPointNetworkAuthority authority,
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


internal sealed class UnavailableContactPublicationThresholdIssuer : IContactPublicationThresholdIssuer
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

    internal ContactPublicationAuthorityHostingState(ReadOnlySpan<byte> networkId, ContactCoordinationIngressAuthenticator access)
    { this.networkId = networkId.ToArray(); Access = access ?? throw new ArgumentNullException(nameof(access)); }

    internal ReadOnlyMemory<byte> NetworkId => networkId?.ToArray() ?? [];
    internal ContactCoordinationIngressAuthenticator? Access { get; }
}

internal static class ContactPublicationAuthorityHostingExtensions
{
    internal const string EndpointPath = "/api/v2/contact-publication-authority";

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
            authority.NetworkIdHex, 16, "ContactPublicationAuthority network ID");
        var did2 = configuration.GetSection("DeepIdV2DirectoryAuthority")
            .Get<DeepIdV2DirectoryAuthorityOptions>() ?? new();
        if (!did2.Enabled || !did2.ProofEnabled ||
            !string.Equals(did2.NetworkIdHex, authority.NetworkIdHex, StringComparison.OrdinalIgnoreCase) ||
            string.IsNullOrWhiteSpace(did2.LatestHeadFloorPostgreSqlConnectionString))
            throw new InvalidOperationException("DID2 route authority requires current proof and independent floor/journal configuration.");
        services.TryAddSingleton<IDeepIdV2PublicationJournal>(_ =>
            new DeepIdV2PostgreSqlPublicationJournal(
                did2.LatestHeadFloorPostgreSqlConnectionString, network));
        return new ContactPublicationAuthorityHostingState(network, ContactCoordinationIngressAuthenticator.FromConfiguration(configuration));
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
        if (!context.Request.IsHttps || context.Request.Path != EndpointPath ||
            context.Request.QueryString.HasValue)
            return Empty(context.Response, StatusCodes.Status400BadRequest);
        if (state.NetworkId.IsEmpty || state.Access is null)
            return Empty(context.Response, StatusCodes.Status503ServiceUnavailable);
        var time = context.RequestServices.GetRequiredService<TimeProvider>();
        var peer = state.Access.ReadAdmittedHeaders(context.Request, time.GetUtcNow());
        if (peer is null) return Empty(context.Response, StatusCodes.Status401Unauthorized);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(30));
        var ct = timeout.Token;
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
            await context.Request.Body.ReadExactlyAsync(encoded, ct)
                .ConfigureAwait(false);
            if (await context.Request.Body.ReadAsync(new byte[1], ct).ConfigureAwait(false) != 0)
                return Empty(context.Response, StatusCodes.Status400BadRequest);
            if (!ContactCoordinationPeerAuthentication.Verify(peer, state.NetworkId.Span, ContactCoordinationTarget.Publication, encoded, time.GetUtcNow()))
                return Empty(context.Response, StatusCodes.Status401Unauthorized);
            var request = ContactPublicationAuthorityWireCodec.DecodeRequest(encoded);
            if (state.NetworkId.IsEmpty)
                return Empty(context.Response, StatusCodes.Status503ServiceUnavailable);
            if (!CryptographicOperations.FixedTimeEquals(
                    request.NetworkId.Span, state.NetworkId.Span))
                return Empty(context.Response, StatusCodes.Status404NotFound);
            try
            {
                var response = await issuer.IssueAsync(request, ct)
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
                UnauthorizedAccessException or InvalidDataException or InvalidOperationException or Npgsql.NpgsqlException)
            {
                return Empty(context.Response, StatusCodes.Status503ServiceUnavailable);
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return Empty(context.Response, StatusCodes.Status503ServiceUnavailable);
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
    internal const string EndpointPath = "/api/v2/contact-publication-authority";

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
