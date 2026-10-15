#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Security.Cryptography;
using Deep.Protocol.ContactV2;
using Microsoft.AspNetCore.Mvc;

namespace Deep.Registry.Api.DirectoryPublication;

internal static class ContactPublicationWinnerReadHosting
{
    internal static void MapContactPublicationWinnerReadEndpoint(this WebApplication app, ContactPublicationAuthorityHostingState state)
    {
        app.MapPost(DeepIdV2PublicationWinnerReadWireCodec.EndpointPath,
            (HttpContext context, CancellationToken ct) => HandleAsync(context, state, ct))
            .WithMetadata(new RequestSizeLimitAttribute(DeepIdV2PublicationWinnerReadWireCodec.RequestBytes));
    }

    private static async Task<IResult> HandleAsync(HttpContext context, ContactPublicationAuthorityHostingState state, CancellationToken cancellation)
    {
        context.Response.Headers.CacheControl = "no-store, private, max-age=0";
        context.Response.Headers.Pragma = "no-cache"; context.Response.Headers.Expires = "0";
        context.Response.Headers["X-Content-Type-Options"] = "nosniff";
        if (!context.Request.IsHttps || context.Request.Path != DeepIdV2PublicationWinnerReadWireCodec.EndpointPath || context.Request.QueryString.HasValue)
            return Empty(context, StatusCodes.Status400BadRequest);
        var reader = context.RequestServices.GetService<IContactPublicationWinnerReader>();
        if (state.NetworkId.IsEmpty || state.Access is null || reader is null) return Empty(context, StatusCodes.Status503ServiceUnavailable);
        var time = context.RequestServices.GetRequiredService<TimeProvider>();
        var peer = state.Access.ReadAdmittedHeaders(context.Request, time.GetUtcNow());
        if (peer is null) return Empty(context, StatusCodes.Status401Unauthorized);
        var decision = context.RequestServices.GetRequiredService<ContactResolveIssuanceAdmissionGate>().TryAcquire(context.Connection.RemoteIpAddress);
        if (!decision.IsAccepted)
        {
            context.Response.Headers.RetryAfter = decision.RetryAfterSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture);
            return Empty(context, StatusCodes.Status429TooManyRequests);
        }
        if (!string.Equals(context.Request.ContentType, DeepIdV2PublicationWinnerReadWireCodec.RequestMediaType, StringComparison.OrdinalIgnoreCase))
            return Empty(context, StatusCodes.Status415UnsupportedMediaType);
        if (context.Request.ContentLength is null) return Empty(context, StatusCodes.Status411LengthRequired);
        if (context.Request.ContentLength > DeepIdV2PublicationWinnerReadWireCodec.RequestBytes) return Empty(context, StatusCodes.Status413PayloadTooLarge);
        if (context.Request.ContentLength != DeepIdV2PublicationWinnerReadWireCodec.RequestBytes) return Empty(context, StatusCodes.Status400BadRequest);
        var encoded = new byte[DeepIdV2PublicationWinnerReadWireCodec.RequestBytes];
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellation); deadline.CancelAfter(TimeSpan.FromSeconds(30));
        var ct = deadline.Token;
        try
        {
            await context.Request.Body.ReadExactlyAsync(encoded, ct).ConfigureAwait(false);
            if (await context.Request.Body.ReadAsync(new byte[1], ct).ConfigureAwait(false) != 0) return Empty(context, StatusCodes.Status400BadRequest);
            if (!ContactCoordinationPeerAuthentication.Verify(peer, state.NetworkId.Span, ContactCoordinationTarget.PublicationWinnerRead, encoded, time.GetUtcNow()))
                return Empty(context, StatusCodes.Status401Unauthorized);
            var request = DeepIdV2PublicationWinnerReadWireCodec.DecodeRequest(encoded);
            if (!CryptographicOperations.FixedTimeEquals(request.NetworkId.Span, state.NetworkId.Span)) return Empty(context, StatusCodes.Status404NotFound);
            var original = await reader.ReadAsync(request, ct).ConfigureAwait(false);
            var body = DeepIdV2PublicationWinnerReadWireCodec.EncodeResponse(request, original.Span);
            context.Response.ContentLength = body.Length;
            return Results.Bytes(body, DeepIdV2PublicationWinnerReadWireCodec.ResponseMediaType, enableRangeProcessing: false);
        }
        catch (ContactPublicationAuthorityRejectedException) { return Empty(context, StatusCodes.Status404NotFound); }
        catch (ContactResolveDirectoryAdmissionException)
        { context.Response.Headers.RetryAfter = "10"; return Empty(context, StatusCodes.Status429TooManyRequests); }
        catch (OperationCanceledException) when (!cancellation.IsCancellationRequested) { return Empty(context, StatusCodes.Status503ServiceUnavailable); }
        catch (EndOfStreamException) { return Empty(context, StatusCodes.Status400BadRequest); }
        catch (Exception error) when (error is ArgumentException or FormatException or CryptographicException or OverflowException)
        { return Empty(context, StatusCodes.Status400BadRequest); }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or InvalidOperationException or Npgsql.NpgsqlException)
        { return Empty(context, StatusCodes.Status503ServiceUnavailable); }
        finally { CryptographicOperations.ZeroMemory(encoded); }
    }
    private static IResult Empty(HttpContext context, int status)
    { context.Response.ContentLength = 0; context.Response.ContentType = null; return Results.StatusCode(status); }
}
#endif
