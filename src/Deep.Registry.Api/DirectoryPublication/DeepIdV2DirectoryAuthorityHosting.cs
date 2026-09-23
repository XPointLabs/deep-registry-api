#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Deep.Registry.Api.DirectoryPublication;

internal sealed class DeepIdV2DirectoryAuthorityOptions
{
    public bool Enabled { get; set; }
    public string NetworkIdHex { get; set; } = string.Empty;
    public string GenesisAuthorityCoreHashHex { get; set; } = string.Empty;
    public List<string> ExactAuthorityPaths { get; set; } = [];
    public List<string> ExactTimePolicyPaths { get; set; } = [];
    public string GenesisHeadPath { get; set; } = string.Empty;
    public string GenesisHeadCoreHashHex { get; set; } = string.Empty;
    public string StatePath { get; set; } = string.Empty;
    public string IntegrityKeyPath { get; set; } = string.Empty;
    public ushort DeploymentProfileId { get; set; } = 1;
    public ulong HeadValiditySeconds { get; set; } = 3_600;
}

internal readonly record struct DeepIdV2DirectoryAuthorityHostingState(bool Enabled);

internal static class DeepIdV2DirectoryAuthorityHostingExtensions
{
    internal const string EndpointPath =
        "/api/v2/account-directory/genesis-admissions";

    internal static DeepIdV2DirectoryAuthorityHostingState
        AddDeepIdV2DirectoryAuthority(this IServiceCollection services,
            IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);
        var options = configuration.GetSection("DeepIdV2DirectoryAuthority")
            .Get<DeepIdV2DirectoryAuthorityOptions>() ?? new();
        if (!options.Enabled) return default;
        var (network, networkPin, headPin) = Validate(options, configuration);
        services.TryAddSingleton(_ => new DeepIdV2XPointAuthoritySource(
            network, networkPin, options.ExactAuthorityPaths,
            options.ExactTimePolicyPaths));
        services.TryAddSingleton(_ => new DeepIdV2DirectoryBootstrapSource(
            options.GenesisHeadPath, headPin));
        services.TryAddSingleton<DeepIdV2DurableGenesisAuthority>(provider =>
        {
            var key = DirectoryPublicationProtectedFile.ReadKey(
                options.IntegrityKeyPath);
            try
            {
                return new DeepIdV2DurableGenesisAuthority(
                    provider.GetRequiredService<DeepIdV2XPointAuthoritySource>(),
                    provider.GetRequiredService<DeepIdV2DirectoryBootstrapSource>(),
                    provider.GetRequiredService<FileContactResolveDtt1WitnessCustody>(),
                    provider.GetRequiredService<IContactResolveTrustedTimeContextSource>(),
                    options.StatePath, network, key,
                    options.DeploymentProfileId, options.HeadValiditySeconds);
            }
            finally { CryptographicOperations.ZeroMemory(key); }
        });
        services.TryAddSingleton<IDeepIdV2GenesisAuthority>(provider =>
            provider.GetRequiredService<DeepIdV2DurableGenesisAuthority>());
        services.TryAddSingleton<ContactResolveIssuanceAdmissionGate>();
        return new DeepIdV2DirectoryAuthorityHostingState(true);
    }

    internal static void MapDeepIdV2DirectoryAuthorityEndpoint(
        this WebApplication app,
        DeepIdV2DirectoryAuthorityHostingState state)
    {
        ArgumentNullException.ThrowIfNull(app);
        if (!state.Enabled) return;
        app.MapPost(EndpointPath, HandleAsync)
            .WithMetadata(new RequestSizeLimitAttribute(
                DeepIdV2GenesisAdmissionWireCodec.MaximumRequestLength));
    }

    private static async Task<IResult> HandleAsync(HttpContext context,
        IDeepIdV2GenesisAuthority authority,
        ContactResolveIssuanceAdmissionGate admission,
        ILogger<DeepIdV2DurableGenesisAuthority> logger,
        CancellationToken cancellationToken)
    {
        context.Response.Headers.CacheControl = "no-store";
        var decision = admission.TryAcquire(context.Connection.RemoteIpAddress);
        if (!decision.IsAccepted)
        {
            context.Response.Headers.RetryAfter =
                decision.RetryAfterSeconds.ToString(
                    System.Globalization.CultureInfo.InvariantCulture);
            return Failure(StatusCodes.Status429TooManyRequests,
                "admission-rate-limited");
        }
        if (!string.Equals(context.Request.ContentType,
                DeepIdV2GenesisAdmissionWireCodec.RequestMediaType,
                StringComparison.OrdinalIgnoreCase))
            return Failure(StatusCodes.Status415UnsupportedMediaType,
                "unsupported-media-type");
        if (context.Request.ContentLength is not { } length)
            return Failure(StatusCodes.Status411LengthRequired,
                "content-length-required");
        if (length is < 1 or >
            DeepIdV2GenesisAdmissionWireCodec.MaximumRequestLength)
            return Failure(StatusCodes.Status413PayloadTooLarge,
                "admission-request-too-large");
        byte[]? encoded = null;
        try
        {
            encoded = new byte[checked((int)length)];
            await context.Request.Body.ReadExactlyAsync(encoded,
                cancellationToken).ConfigureAwait(false);
            var request = DeepIdV2GenesisAdmissionWireCodec.DecodeRequest(
                encoded);
            var receipt = await authority.AdmitAsync(request,
                cancellationToken).ConfigureAwait(false);
            return Results.Bytes(
                DeepIdV2GenesisAdmissionWireCodec.EncodeReceipt(receipt),
                DeepIdV2GenesisAdmissionWireCodec.ResponseMediaType);
        }
        catch (OperationCanceledException) when (
            cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (DeepIdV2AuthorityConflictException)
        {
            return Failure(StatusCodes.Status409Conflict,
                "admission-conflict");
        }
        catch (AccountDirectoryGenesisAdmissionException exception)
        {
            logger.LogWarning("DID2 genesis rejected with code {AdmissionCode}.",
                exception.Code);
            return Failure(StatusCodes.Status400BadRequest,
                "admission-rejected");
        }
        catch (Exception exception) when (exception is
            ArgumentException or FormatException or EndOfStreamException)
        {
            return Failure(StatusCodes.Status400BadRequest,
                "admission-rejected");
        }
        catch (Exception exception) when (exception is
            CryptographicException or InvalidDataException or IOException or
            InvalidOperationException or PlatformNotSupportedException or
            UnauthorizedAccessException)
        {
            logger.LogError(exception,
                "DID2 directory authority is unavailable.");
            return Failure(StatusCodes.Status503ServiceUnavailable,
                "authority-unavailable");
        }
        finally
        {
            if (encoded is not null)
                CryptographicOperations.ZeroMemory(encoded);
        }
    }

    private static IResult Failure(int status, string code) =>
        Results.Json(new { code }, statusCode: status);

    private static (byte[] Network, byte[] NetworkPin, byte[] HeadPin)
        Validate(DeepIdV2DirectoryAuthorityOptions options,
            IConfiguration configuration)
    {
        if (configuration.GetValue<bool>("AccountDirectoryAuthority:Enabled"))
            throw new InvalidOperationException(
                "DID2 and legacy account-directory admission cannot run together.");
        if (!configuration.GetValue<bool>(
                "ContactResolveProductionAuthority:Enabled"))
            throw new InvalidOperationException(
                "DID2 admission requires protected trusted time and witness custody.");
        var network = DirectoryPublicationHostingExtensions.Hex(
            options.NetworkIdHex, 16, "DID2 directory network ID");
        var networkPin = DirectoryPublicationHostingExtensions.Hex(
            options.GenesisAuthorityCoreHashHex, 32,
            "DID2 genesis XNA1 core hash");
        var headPin = DirectoryPublicationHostingExtensions.Hex(
            options.GenesisHeadCoreHashHex, 32,
            "DID2 genesis ADH1 core hash");
        if (!string.Equals(options.NetworkIdHex,
                configuration["ContactResolveProductionAuthority:NetworkIdHex"],
                StringComparison.OrdinalIgnoreCase) ||
            string.IsNullOrWhiteSpace(options.GenesisHeadPath) ||
            string.IsNullOrWhiteSpace(options.StatePath) ||
            string.IsNullOrWhiteSpace(options.IntegrityKeyPath) ||
            options.DeploymentProfileId == 0 ||
            options.HeadValiditySeconds is < 300 or > 86_400)
            throw new InvalidOperationException(
                "DID2 directory authority configuration is incomplete.");
        var source = new DeepIdV2XPointAuthoritySource(network,
            networkPin, options.ExactAuthorityPaths,
            options.ExactTimePolicyPaths);
        var authority = source.Read();
        _ = new DeepIdV2DirectoryBootstrapSource(
            options.GenesisHeadPath, headPin).Read(authority);
        var protectedPaths = options.ExactAuthorityPaths
            .Concat(options.ExactTimePolicyPaths)
            .Append(options.GenesisHeadPath)
            .Append(options.StatePath)
            .Append(options.IntegrityKeyPath)
            .Concat(new[]
            {
                configuration["AccountDirectoryAuthority:StatePath"],
                configuration["AccountDirectoryAuthority:IntegrityKeyPath"],
                configuration["ContactResolveProductionAuthority:TrustedTimeStatePath"],
                configuration["ContactResolveProductionAuthority:TrustedTimeIntegrityKeyPath"],
                configuration["ContactResolveProductionAuthority:RequestLedgerIntegrityKeyPath"],
                configuration["ContactResolveDirectoryArtifacts:StatePath"],
                configuration["ContactResolveDirectoryArtifacts:IntegrityKeyPath"]
            }.Where(static path => !string.IsNullOrWhiteSpace(path))
             .Select(static path => path!))
            .Select(Path.GetFullPath).ToArray();
        var comparer = OperatingSystem.IsWindows()
            ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;
        if (protectedPaths.Distinct(comparer).Count() != protectedPaths.Length ||
            !File.Exists(Path.GetFullPath(options.StatePath)))
            throw new InvalidOperationException(
                "DID2 state must be separately provisioned and all paths distinct.");
        var key = DirectoryPublicationProtectedFile.ReadKey(
            options.IntegrityKeyPath);
        CryptographicOperations.ZeroMemory(key);
        return (network, networkPin, headPin);
    }
}
#endif
