#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Deep.Registry.Api.DirectoryPublication;

internal sealed class TargetedCurrentValueDirectoryPackageOptions
{
    public bool Enabled { get; set; }
}

internal static class TargetedCurrentValueDirectoryPackageCodec
{
    internal const ushort Version = 1;
    internal const int ExactAdl1Bytes = 228;
    internal const int RequestBytes = 2 + ExactAdl1Bytes + 32 + 16 + 8;
    internal const int MaximumResponseBytes =
        (int)ContactResolveDirectoryIssuedPackage.MaximumPackageBytes + 256;
    internal const string RequestMediaType =
        "application/vnd.deep.directory-current-value-request.v1+octet-stream";
    internal const string ResponseMediaType =
        "application/vnd.deep.directory-current-value.v1+octet-stream";

    internal static ContactResolveDirectoryPackageRequest DecodeRequest(ReadOnlySpan<byte> value)
    {
        if (value.Length != RequestBytes ||
            BinaryPrimitives.ReadUInt16BigEndian(value) != Version)
            throw new FormatException("The targeted current-value request is not canonical.");

        var adlBytes = value.Slice(2, ExactAdl1Bytes);
        var adl = AccountDirectoryAdl1Codec.Decode(adlBytes);
        if (!adlBytes.SequenceEqual(AccountDirectoryAdl1Codec.Encode(adl)))
            throw new FormatException("The embedded ADL1 is not byte-canonical.");
        var nonce = value.Slice(2 + ExactAdl1Bytes, 32).ToArray();
        var boot = value.Slice(2 + ExactAdl1Bytes + 32, 16).ToArray();
        if (nonce.AsSpan().IndexOfAnyExcept((byte)0) < 0 ||
            boot.AsSpan().IndexOfAnyExcept((byte)0) < 0)
            throw new FormatException("The targeted current-value request has a zero nonce or boot ID.");
        var sample = BinaryPrimitives.ReadUInt64BigEndian(value[^8..]);

        return new ContactResolveDirectoryPackageRequest(
            adl.NetworkId.ToArray(), nonce, boot, sample,
            null, null, null,
            adl.DirectoryLookupKey.ToArray(), adl.MinimumAdhGeneration,
            adl.MinimumAdhHash.ToArray(), requireCurrentValue: true);
    }

    internal static byte[] EncodeResponse(
        ContactResolveDirectoryPackageRequest request,
        ContactResolveDirectoryIssuedPackage package)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(package);
        RequireExact(package.NetworkId.Span, request.NetworkId.Span);
        RequireExact(package.Nonce.Span, request.Nonce.Span);
        RequireExact(package.BootId.Span, request.BootId.Span);
        RequireExact(package.QueriedDirectoryLeafKey.Span,
            request.ExpectedDirectoryLookupKey.Span);
        if (package.NonceCreatedAt != request.NonceCreatedAt)
            throw new InvalidOperationException("The issued monotonic sample changed.");

        var adp = AccountDirectoryAdp1Codec.Decode(package.ExactAdp1.Span);
        if (adp.ResultKind != AccountDirectoryAdp1ResultKind.CurrentValue ||
            !Fixed(adp.NetworkId.Span, request.NetworkId.Span) ||
            !Fixed(adp.QueriedDirectoryLeafKey.Span,
                request.ExpectedDirectoryLookupKey.Span))
            throw new ContactResolveDirectoryTargetNotFoundException();

        using var stream = new MemoryStream();
        WriteU16(stream, Version);
        WriteU16(stream, 0);
        WriteU32(stream, 0);
        stream.Write(request.NetworkId.Span);
        stream.Write(request.ExpectedDirectoryLookupKey.Span);
        stream.Write(request.Nonce.Span);
        stream.Write(request.BootId.Span);
        WriteU64(stream, request.NonceCreatedAt);
        WriteArtifact(stream, package.ExactXna1AuthorityChain[^1].Span);
        WriteArtifact(stream, package.ExactDts1PolicyChain[^1].Span);
        WriteArtifact(stream, package.ExactAdh1.Span);
        WriteArtifact(stream, package.ExactDtt1.Span);
        WriteArtifact(stream, package.ExactAdp1.Span);
        WriteArtifact(stream, package.ExactOrderedXnv1Chain[^1].Span);
        WriteArtifact(stream, package.ExactOrderedXnh1Chain[^1].Span);
        WriteArtifact(stream, package.ExactOrderedPmt2Chain[^1].Span);
        if (stream.Length > MaximumResponseBytes)
            throw new InvalidOperationException("The targeted current-value response exceeds its bound.");
        var result = stream.ToArray();
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(4), checked((uint)result.Length));
        return result;
    }

    private static void WriteArtifact(Stream stream, ReadOnlySpan<byte> value)
    {
        if (value.IsEmpty || value.Length > ContactResolveDirectoryIssuedPackage.MaximumSingleArtifactBytes)
            throw new InvalidOperationException("A response artifact is outside its bound.");
        WriteU32(stream, checked((uint)value.Length));
        stream.Write(value);
    }

    private static void WriteU16(Stream stream, ushort value)
    {
        Span<byte> encoded = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(encoded, value);
        stream.Write(encoded);
    }

    private static void WriteU32(Stream stream, uint value)
    {
        Span<byte> encoded = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(encoded, value);
        stream.Write(encoded);
    }

    private static void WriteU64(Stream stream, ulong value)
    {
        Span<byte> encoded = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(encoded, value);
        stream.Write(encoded);
    }

    private static void RequireExact(ReadOnlySpan<byte> actual, ReadOnlySpan<byte> expected)
    {
        if (!Fixed(actual, expected))
            throw new ContactResolveDirectoryTargetNotFoundException();
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}

internal readonly struct TargetedCurrentValueDirectoryPackageHostingState
{
    private readonly byte[]? networkId;

    internal TargetedCurrentValueDirectoryPackageHostingState(ReadOnlySpan<byte> networkId)
    {
        if (networkId.Length != 16 || networkId.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("A non-zero 16-byte network ID is required.", nameof(networkId));
        this.networkId = networkId.ToArray();
    }

    internal ReadOnlyMemory<byte> NetworkId => networkId?.ToArray() ?? [];
}

internal static class TargetedCurrentValueDirectoryPackageHostingExtensions
{
    internal const string EndpointPath = "/api/v1/directory/current-values";
    internal static TargetedCurrentValueDirectoryPackageHostingState
        AddTargetedCurrentValueDirectoryPackages(
            this IServiceCollection services,
            IConfiguration configuration,
            ContactResolveDirectoryPackageHostingState contactResolveState)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<ContactResolveIssuanceAdmissionGate>();

        var options = configuration.GetSection("TargetedCurrentValueDirectoryPackages")
            .Get<TargetedCurrentValueDirectoryPackageOptions>() ?? new();
        if (!options.Enabled) return default;
        if (contactResolveState.NetworkId.IsEmpty)
            throw new InvalidOperationException(
                "TargetedCurrentValueDirectoryPackages requires DirectoryPublication:NetworkIdHex.");
        return new TargetedCurrentValueDirectoryPackageHostingState(
            contactResolveState.NetworkId.Span);
    }

    internal static void MapTargetedCurrentValueDirectoryPackageEndpoint(
        this WebApplication app,
        TargetedCurrentValueDirectoryPackageHostingState state)
    {
        ArgumentNullException.ThrowIfNull(app);
        app.MapPost(EndpointPath, (HttpContext context,
                IContactResolveDirectoryPackageIssuer issuer,
                ContactResolveIssuanceAdmissionGate admission,
                CancellationToken cancellationToken) =>
                HandleAsync(context, issuer, admission, state, cancellationToken))
            .WithMetadata(new RequestSizeLimitAttribute(
                TargetedCurrentValueDirectoryPackageCodec.RequestBytes));
    }

    private static async Task<IResult> HandleAsync(
        HttpContext context,
        IContactResolveDirectoryPackageIssuer issuer,
        ContactResolveIssuanceAdmissionGate admission,
        TargetedCurrentValueDirectoryPackageHostingState state,
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
                TargetedCurrentValueDirectoryPackageCodec.RequestMediaType,
                StringComparison.OrdinalIgnoreCase))
            return Empty(context.Response, StatusCodes.Status415UnsupportedMediaType);
        if (context.Request.ContentLength is null)
            return Empty(context.Response, StatusCodes.Status411LengthRequired);
        if (context.Request.ContentLength > TargetedCurrentValueDirectoryPackageCodec.RequestBytes)
            return Empty(context.Response, StatusCodes.Status413PayloadTooLarge);
        if (context.Request.ContentLength != TargetedCurrentValueDirectoryPackageCodec.RequestBytes)
            return Empty(context.Response, StatusCodes.Status400BadRequest);

        var encoded = GC.AllocateUninitializedArray<byte>(
            TargetedCurrentValueDirectoryPackageCodec.RequestBytes);
        try
        {
            await context.Request.Body.ReadExactlyAsync(encoded, cancellationToken)
                .ConfigureAwait(false);
            var request = TargetedCurrentValueDirectoryPackageCodec.DecodeRequest(encoded);
            if (state.NetworkId.IsEmpty)
                return Empty(context.Response, StatusCodes.Status503ServiceUnavailable);
            if (!CryptographicOperations.FixedTimeEquals(
                    request.NetworkId.Span, state.NetworkId.Span))
                return Empty(context.Response, StatusCodes.Status404NotFound);

            ContactResolveDirectoryIssuedPackage package;
            try
            {
                package = await issuer.IssueAsync(request, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (ContactResolveDirectoryAdmissionException)
            {
                context.Response.Headers.RetryAfter = "10";
                return Empty(context.Response, StatusCodes.Status429TooManyRequests);
            }
            catch (ContactResolveDirectoryTargetNotFoundException)
            {
                return Empty(context.Response, StatusCodes.Status404NotFound);
            }
            catch (Exception exception) when (exception is
                ContactResolveDirectoryPackageUnavailableException or IOException or
                UnauthorizedAccessException or CryptographicException or InvalidDataException or
                InvalidOperationException or ArgumentException or FormatException or OverflowException)
            {
                return Empty(context.Response, StatusCodes.Status503ServiceUnavailable);
            }

            try
            {
                var response = TargetedCurrentValueDirectoryPackageCodec.EncodeResponse(
                    request, package);
                context.Response.ContentLength = response.Length;
                return Results.Bytes(response,
                    TargetedCurrentValueDirectoryPackageCodec.ResponseMediaType,
                    enableRangeProcessing: false);
            }
            catch (ContactResolveDirectoryTargetNotFoundException)
            {
                return Empty(context.Response, StatusCodes.Status404NotFound);
            }
            catch (Exception exception) when (exception is CryptographicException or
                InvalidDataException or InvalidOperationException or ArgumentException or
                FormatException or OverflowException)
            {
                return Empty(context.Response, StatusCodes.Status503ServiceUnavailable);
            }
        }
        catch (EndOfStreamException)
        {
            return Empty(context.Response, StatusCodes.Status400BadRequest);
        }
        catch (Exception exception) when (exception is FormatException or ArgumentException)
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

    private static void SetNoStoreHeaders(HttpResponse response)
    {
        response.Headers.CacheControl = "no-store, private, max-age=0";
        response.Headers.Pragma = "no-cache";
        response.Headers.Expires = "0";
        response.Headers["X-Content-Type-Options"] = "nosniff";
    }
}
#else
namespace Deep.Registry.Api.DirectoryPublication;

internal readonly struct TargetedCurrentValueDirectoryPackageHostingState
{
}

internal static class TargetedCurrentValueDirectoryPackageHostingExtensions
{
    internal const string EndpointPath = "/api/v1/directory/current-values";

    internal static TargetedCurrentValueDirectoryPackageHostingState
        AddTargetedCurrentValueDirectoryPackages(
            this IServiceCollection services,
            IConfiguration configuration,
            ContactResolveDirectoryPackageHostingState contactResolveState)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);
        return default;
    }

    internal static void MapTargetedCurrentValueDirectoryPackageEndpoint(
        this WebApplication app,
        TargetedCurrentValueDirectoryPackageHostingState state)
    {
        ArgumentNullException.ThrowIfNull(app);
        app.MapPost(EndpointPath, static (HttpContext context) =>
        {
            context.Response.Headers.CacheControl = "no-store, private, max-age=0";
            context.Response.Headers.Pragma = "no-cache";
            context.Response.Headers.Expires = "0";
            context.Response.Headers["X-Content-Type-Options"] = "nosniff";
            context.Response.ContentLength = 0;
            return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
        });
    }
}
#endif
