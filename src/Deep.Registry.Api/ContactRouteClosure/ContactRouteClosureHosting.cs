using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Registry.Api.DirectoryPublication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Deep.Registry.Api.ContactRouteClosure;

internal sealed class ContactRouteClosureTransportOptions
{
    public string ReadOnlyRoot { get; set; } = string.Empty;
    public string StateRoot { get; set; } = string.Empty;
    public string IntegrityKeyPath { get; set; } = string.Empty;
    public string NetworkIdHex { get; set; } = string.Empty;
}

internal interface IContactRouteClosureSource
{
    ValueTask<ReadOnlyMemory<byte>> ReadAsync(
        ReadOnlyMemory<byte> networkId,
        ReadOnlyMemory<byte> locatorHash,
        CancellationToken cancellationToken);
}

internal sealed class ContactRouteClosureNotFoundException : Exception { }
internal sealed class ContactRouteClosureSourceUnavailableException : Exception { }
internal sealed class ContactRouteClosurePublicationRejectedException : Exception
{
    internal ContactRouteClosurePublicationRejectedException(string message, Exception? inner = null)
        : base(message, inner) { }
}

internal static class ContactRouteClosureTransportCodec
{
    internal const ushort Version = 1;
    internal const int RequestBytes = 2 + 16 + 32;
    internal const int MinimumClosureBytes = 4_143;
    internal const int MaximumClosureBytes = 23_295;
    internal const string RequestMediaType =
        "application/vnd.deep.contact-route-closure-request.v1+octet-stream";
    internal const string ResponseMediaType =
        "application/vnd.deep.contact-route-closure.v1+octet-stream";

    internal static (byte[] NetworkId, byte[] LocatorHash) DecodeRequest(ReadOnlySpan<byte> value)
    {
        if (value.Length != RequestBytes ||
            BinaryPrimitives.ReadUInt16BigEndian(value) != Version)
            throw new FormatException("The contact route closure request is not canonical.");
        var network = value.Slice(2, 16).ToArray();
        var locator = value.Slice(18, 32).ToArray();
        if (network.AsSpan().IndexOfAnyExcept((byte)0) < 0 ||
            locator.AsSpan().IndexOfAnyExcept((byte)0) < 0)
            throw new FormatException("The contact route closure request contains a zero identifier.");
        return (network, locator);
    }
}

internal readonly struct ContactRouteClosureHostingState
{
    private readonly byte[]? networkId;

    internal ContactRouteClosureHostingState(ReadOnlySpan<byte> networkId)
    {
        if (networkId.Length != 16 || networkId.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("A non-zero 16-byte network ID is required.", nameof(networkId));
        this.networkId = networkId.ToArray();
    }

    internal ReadOnlyMemory<byte> NetworkId => networkId?.ToArray() ?? [];
}

internal static class ContactRouteClosureHostingExtensions
{
    internal const string EndpointPath = "/api/v1/contact-route-closures";
    internal static ContactRouteClosureHostingState AddContactRouteClosureTransport(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<ContactRouteClosureAdmissionGate>();

        var options = configuration.GetSection("ContactRouteClosureTransport")
            .Get<ContactRouteClosureTransportOptions>() ?? new();
        var configured = new[]
        {
            options.ReadOnlyRoot,
            options.StateRoot,
            options.IntegrityKeyPath,
            options.NetworkIdHex,
        };
        if (configured.All(string.IsNullOrWhiteSpace))
        {
            services.TryAddSingleton<IContactRouteClosureSource,
                UnavailableContactRouteClosureSource>();
            return default;
        }
        if (configured.Any(string.IsNullOrWhiteSpace))
            throw new InvalidOperationException(
                "ContactRouteClosureTransport configuration must explicitly provide read-only root, protected state root, integrity key and network ID.");

        var network = ParseLowerHex(options.NetworkIdHex, 16, "contact route closure network ID");
#if DEEP_PROTOCOL_DIRECTORY_V1
        services.TryAddSingleton<IContactRouteClosureSource>(_ =>
        {
            byte[]? key = null;
            try
            {
                key = DirectoryPublication.DirectoryPublicationProtectedFile.ReadKey(
                    options.IntegrityKeyPath);
                return new FileContactRouteClosureSource(
                    options.ReadOnlyRoot, options.StateRoot, network, key);
            }
            catch (Exception exception) when (exception is IOException or
                UnauthorizedAccessException or CryptographicException or InvalidDataException or
                InvalidOperationException or ArgumentException)
            {
                return new UnavailableContactRouteClosureSource();
            }
            finally
            {
                if (key is not null) CryptographicOperations.ZeroMemory(key);
            }
        });
        return new ContactRouteClosureHostingState(network);
#else
        throw new InvalidOperationException(
            "ContactRouteClosureTransport requires the local Protocol cutover surface.");
#endif
    }

    internal static void MapContactRouteClosureTransportEndpoint(
        this WebApplication app,
        ContactRouteClosureHostingState state)
    {
        ArgumentNullException.ThrowIfNull(app);
        app.MapPost(EndpointPath, (HttpContext context,
                IContactRouteClosureSource source,
                ContactRouteClosureAdmissionGate admission,
                CancellationToken cancellationToken) =>
                HandleAsync(context, source, admission, state, cancellationToken))
            .WithMetadata(new RequestSizeLimitAttribute(ContactRouteClosureTransportCodec.RequestBytes));
    }

    private static async Task<IResult> HandleAsync(
        HttpContext context,
        IContactRouteClosureSource source,
        ContactRouteClosureAdmissionGate admission,
        ContactRouteClosureHostingState state,
        CancellationToken cancellationToken)
    {
        SetNoStoreHeaders(context.Response);
        var decision = admission.TryAcquire(context.Connection.RemoteIpAddress);
        if (!decision.IsAccepted)
        {
            context.Response.Headers.RetryAfter = decision.RetryAfterSeconds.ToString(
                System.Globalization.CultureInfo.InvariantCulture);
            return Empty(context.Response, StatusCodes.Status429TooManyRequests);
        }
        if (!string.Equals(context.Request.ContentType,
                ContactRouteClosureTransportCodec.RequestMediaType,
                StringComparison.OrdinalIgnoreCase))
            return Empty(context.Response, StatusCodes.Status415UnsupportedMediaType);
        if (context.Request.ContentLength is null)
            return Empty(context.Response, StatusCodes.Status411LengthRequired);
        if (context.Request.ContentLength > ContactRouteClosureTransportCodec.RequestBytes)
            return Empty(context.Response, StatusCodes.Status413PayloadTooLarge);
        if (context.Request.ContentLength != ContactRouteClosureTransportCodec.RequestBytes)
            return Empty(context.Response, StatusCodes.Status400BadRequest);

        var encoded = GC.AllocateUninitializedArray<byte>(ContactRouteClosureTransportCodec.RequestBytes);
        try
        {
            await context.Request.Body.ReadExactlyAsync(encoded, cancellationToken).ConfigureAwait(false);
            var request = ContactRouteClosureTransportCodec.DecodeRequest(encoded);
            if (state.NetworkId.IsEmpty)
                return Empty(context.Response, StatusCodes.Status503ServiceUnavailable);
            if (!CryptographicOperations.FixedTimeEquals(
                    request.NetworkId, state.NetworkId.Span))
                return Empty(context.Response, StatusCodes.Status404NotFound);

            ReadOnlyMemory<byte> closure;
            try
            {
                closure = await source.ReadAsync(
                    request.NetworkId, request.LocatorHash, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (ContactRouteClosureNotFoundException)
            {
                return Empty(context.Response, StatusCodes.Status404NotFound);
            }
            catch (ContactRouteClosurePublicationRejectedException)
            {
                // A malformed per-locator publication is intentionally indistinguishable from absence.
                return Empty(context.Response, StatusCodes.Status404NotFound);
            }
            catch (Exception exception) when (exception is
                ContactRouteClosureSourceUnavailableException or IOException or
                UnauthorizedAccessException or CryptographicException or InvalidDataException or
                InvalidOperationException)
            {
                return Empty(context.Response, StatusCodes.Status503ServiceUnavailable);
            }

            if (closure.Length is < ContactRouteClosureTransportCodec.MinimumClosureBytes or
                > ContactRouteClosureTransportCodec.MaximumClosureBytes)
                return Empty(context.Response, StatusCodes.Status503ServiceUnavailable);
            context.Response.ContentLength = closure.Length;
            return Results.Bytes(
                closure.ToArray(), ContactRouteClosureTransportCodec.ResponseMediaType,
                enableRangeProcessing: false);
        }
        catch (EndOfStreamException)
        {
            return Empty(context.Response, StatusCodes.Status400BadRequest);
        }
        catch (FormatException)
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

    internal static void SetNoStoreHeaders(HttpResponse response)
    {
        response.Headers.CacheControl = "no-store, private, max-age=0";
        response.Headers.Pragma = "no-cache";
        response.Headers.Expires = "0";
    }

    private static byte[] ParseLowerHex(string value, int expectedBytes, string name)
    {
        if (value.Length != expectedBytes * 2 ||
            value.Any(static character => character is not (>= '0' and <= '9') and
                not (>= 'a' and <= 'f')))
            throw new InvalidOperationException(
                $"The {name} must be exactly {expectedBytes * 2} lowercase hexadecimal characters.");
        var result = Convert.FromHexString(value);
        if (result.AsSpan().IndexOfAnyExcept((byte)0) < 0)
            throw new InvalidOperationException($"The {name} cannot be all-zero.");
        return result;
    }

    private sealed class UnavailableContactRouteClosureSource : IContactRouteClosureSource
    {
        public ValueTask<ReadOnlyMemory<byte>> ReadAsync(
            ReadOnlyMemory<byte> networkId,
            ReadOnlyMemory<byte> locatorHash,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            throw new ContactRouteClosureSourceUnavailableException();
        }
    }
}
