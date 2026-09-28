using System.Security.Cryptography;
#if DEEP_PROTOCOL_DIRECTORY_V1
using Deep.Protocol.XPointNetworkV1;
#endif

namespace Deep.Registry.Api.DirectoryPublication;

internal sealed class XPointNetworkClosureDistributionOptions
{
    public bool Enabled { get; set; }
    public string NetworkIdHex { get; set; } = string.Empty;
    public string BundlePath { get; set; } = string.Empty;
}

internal static class XPointNetworkClosureDistributionHosting
{
    internal const string EndpointPath = "/api/v2/network/closure";

    internal static bool AddXPointNetworkClosureDistribution(
        this IServiceCollection services, IConfiguration configuration)
    {
        var options = configuration.GetSection("XPointNetworkClosureDistribution")
            .Get<XPointNetworkClosureDistributionOptions>() ?? new();
        if (!options.Enabled) return false;
#if DEEP_PROTOCOL_DIRECTORY_V1
        // A public byte cache needs no root key, witness signer, account state or
        // legacy proof issuer. All verification/freshness remains client-owned.
        services.AddSingleton(_ => new XPointNetworkClosureDistribution(options));
        return true;
#else
        throw new InvalidOperationException("Network closure distribution requires the current Protocol cutover.");
#endif
    }

    internal static void MapXPointNetworkClosureDistribution(this WebApplication app, bool enabled)
    {
        if (!enabled) return;
#if DEEP_PROTOCOL_DIRECTORY_V1
        _ = app.Services.GetRequiredService<XPointNetworkClosureDistribution>();
        app.MapPost(EndpointPath, HandleAsync);
#else
        throw new InvalidOperationException("Network closure distribution requires the current Protocol cutover.");
#endif
    }

#if DEEP_PROTOCOL_DIRECTORY_V1
    private static async Task<IResult> HandleAsync(HttpContext context,
        XPointNetworkClosureDistribution distribution)
    {
        // Forwarded scheme is accepted only through the host's known-proxy policy.
        // No cleartext physical/UAT exception or caller-selected bundle is exposed.
        if (!context.Request.IsHttps) return Results.StatusCode(StatusCodes.Status403Forbidden);
        if (context.Request.Path.Value != EndpointPath || context.Request.QueryString.HasValue)
            return Results.StatusCode(StatusCodes.Status400BadRequest);
        if (context.Request.ContentType != XPointNetworkClosureWireCodec.RequestMediaType)
            return Results.StatusCode(StatusCodes.Status415UnsupportedMediaType);
        if (context.Request.ContentLength is null)
            return Results.StatusCode(StatusCodes.Status411LengthRequired);
        if (context.Request.ContentLength != XPointNetworkClosureWireCodec.RequestLength)
            return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);
        // One in-flight bounded file/frame, no queue and no per-caller cache.
        if (!distribution.TryEnter()) return Results.StatusCode(StatusCodes.Status429TooManyRequests);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(context.RequestAborted);
        timeout.CancelAfter(TimeSpan.FromSeconds(30));
        try
        {
            var bytes = new byte[XPointNetworkClosureWireCodec.RequestLength];
            await context.Request.Body.ReadExactlyAsync(bytes, timeout.Token);
            var trailing = new byte[1];
            if (await context.Request.Body.ReadAsync(trailing, timeout.Token) != 0)
                return Results.StatusCode(StatusCodes.Status400BadRequest);
            var network = XPointNetworkClosureWireCodec.DecodeRequest(bytes);
            if (!distribution.Matches(network)) return Results.StatusCode(StatusCodes.Status404NotFound);
            var frame = await distribution.ReadAsync(timeout.Token);
            context.Response.Headers.CacheControl = "no-store";
            context.Response.Headers.XContentTypeOptions = "nosniff";
            // Execute under the gate: hold the permit through response-body write,
            // not just through file read. Release only once the bounded send ends.
            context.Response.StatusCode = StatusCodes.Status200OK;
            context.Response.ContentType = XPointNetworkClosureWireCodec.ResponseMediaType;
            context.Response.ContentLength = frame.Length;
            await context.Response.Body.WriteAsync(frame, timeout.Token);
            return Results.Empty;
        }
        catch (FormatException) { return Results.StatusCode(StatusCodes.Status400BadRequest); }
        catch (EndOfStreamException) { return Results.StatusCode(StatusCodes.Status400BadRequest); }
        catch (OperationCanceledException) when (!context.Response.HasStarted)
        { return Results.StatusCode(StatusCodes.Status503ServiceUnavailable); }
        catch (IOException) when (!context.Response.HasStarted)
        { return Results.StatusCode(StatusCodes.Status503ServiceUnavailable); }
        finally { distribution.Exit(); }
    }
#endif
}

#if DEEP_PROTOCOL_DIRECTORY_V1
internal sealed class XPointNetworkClosureDistribution : IDisposable
{
    private readonly byte[] network;
    private readonly string path;
    private readonly SemaphoreSlim gate = new(1, 1);

    internal XPointNetworkClosureDistribution(XPointNetworkClosureDistributionOptions options)
    {
        if (options.NetworkIdHex.Length != 32 ||
            options.NetworkIdHex.Any(static c => !Uri.IsHexDigit(c)))
            throw new InvalidOperationException("Network closure distribution scope is invalid.");
        network = Convert.FromHexString(options.NetworkIdHex);
        if (network.AsSpan().IndexOfAnyExcept((byte)0) < 0 ||
            string.IsNullOrWhiteSpace(options.BundlePath) ||
            !Path.IsPathFullyQualified(options.BundlePath))
            throw new InvalidOperationException("Network closure distribution public bundle configuration is invalid.");
        path = Path.GetFullPath(options.BundlePath);
        RequireRegularPublicFile();
    }

    internal bool TryEnter() => gate.Wait(0);
    internal void Exit() => gate.Release();
    internal bool Matches(ReadOnlySpan<byte> value) =>
        value.Length == network.Length && CryptographicOperations.FixedTimeEquals(value, network);

    internal async Task<byte[]> ReadAsync(CancellationToken ct)
    {
        RequireRegularPublicFile();
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read,
            FileShare.Read | FileShare.Delete, 4096, FileOptions.Asynchronous | FileOptions.SequentialScan);
        if (stream.Length < XPointNetworkClosureWireCodec.RequestLength ||
            stream.Length > XPointNetworkClosureWireCodec.MaximumResponseLength)
            throw new IOException("Network closure public bundle is unavailable.");
        var frame = new byte[(int)stream.Length];
        await stream.ReadExactlyAsync(frame, ct);
        var trailing = new byte[1];
        if (await stream.ReadAsync(trailing, ct) != 0)
            throw new IOException("Network closure public bundle changed while reading.");
        try
        {
            var raw = XPointNetworkClosureWireCodec.DecodeResponse(frame);
            if (!Matches(raw.NetworkId.Span))
                throw new IOException("Network closure public bundle scope differs from configuration.");
        }
        catch (FormatException)
        { throw new IOException("Network closure public bundle is malformed."); }
        return frame;
    }

    private void RequireRegularPublicFile()
    {
        // Only an operator-configured existing regular file; request fields cannot
        // select paths. Reject links (including parent links) before opening.
        FileSystemInfo? item = new FileInfo(path);
        while (item is not null)
        {
            if (!item.Exists || (item.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Network closure public bundle is unavailable.");
            item = item is FileInfo file ? file.Directory : ((DirectoryInfo)item).Parent;
        }
    }

    public void Dispose() => gate.Dispose();
}
#endif
