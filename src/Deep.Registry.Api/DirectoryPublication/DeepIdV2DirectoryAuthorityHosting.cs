#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Net;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Npgsql;

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
    public string LatestHeadFloorPostgreSqlConnectionString { get; set; } = string.Empty;
    public bool ProductionCutoverAttested { get; set; }
    public bool ProofEnabled { get; set; }
    public string CurrentXnv1Path { get; set; } = string.Empty;
    public string ProofRequestLedgerRootPath { get; set; } = string.Empty;
    public string ProofRequestLedgerIntegrityKeyPath { get; set; } = string.Empty;
    public ushort DeploymentProfileId { get; set; } = 1;
    public ulong HeadValiditySeconds { get; set; } = 3_600;
}

internal readonly record struct DeepIdV2DirectoryAuthorityHostingState(
    bool Enabled, bool ProofEnabled);

internal static class DeepIdV2DirectoryAuthorityHostingExtensions
{
    internal const string EndpointPath =
        "/api/v2/account-directory/genesis-admissions";
    internal const string ProofEndpointPath =
        "/api/v2/account-directory/proofs";

    internal static DeepIdV2DirectoryAuthorityHostingState
        AddDeepIdV2DirectoryAuthority(this IServiceCollection services,
            IConfiguration configuration, IHostEnvironment? environment = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);
        var options = configuration.GetSection("DeepIdV2DirectoryAuthority")
            .Get<DeepIdV2DirectoryAuthorityOptions>() ?? new();
        if (options.ProofEnabled && !options.Enabled)
            throw new InvalidOperationException(
                "DID2 proof publication requires DID2 admission in the same authority.");
        if (!options.Enabled) return default;
        if (environment is null)
            throw new InvalidOperationException(
                "DID2 admission requires an explicit hosting environment.");
        if (environment.IsProduction())
            RequireProductionCutover(options);
        else if (!(environment.IsDevelopment() || environment.IsEnvironment("UAT")))
            throw new InvalidOperationException(
                "DID2 admission is unavailable in an unrecognized environment.");
        var (network, networkPin, headPin) = Validate(options, configuration);
        if (!string.IsNullOrWhiteSpace(
                options.LatestHeadFloorPostgreSqlConnectionString))
            services.TryAddSingleton<IDeepIdV2DirectoryLatestHeadFloor>(_ =>
                new DeepIdV2PostgreSqlLatestHeadFloor(
                    options.LatestHeadFloorPostgreSqlConnectionString, network));
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
                    options.DeploymentProfileId, options.HeadValiditySeconds,
                    provider.GetService<IDeepIdV2DirectoryLatestHeadFloor>());
            }
            finally { CryptographicOperations.ZeroMemory(key); }
        });
        services.TryAddSingleton<IDeepIdV2GenesisAuthority>(provider =>
            provider.GetRequiredService<DeepIdV2DurableGenesisAuthority>());
        services.TryAddSingleton<ContactResolveIssuanceAdmissionGate>();
        if (options.ProofEnabled)
        {
            services.TryAddSingleton<IDeepIdV2CurrentViewSource>(_ =>
                new DeepIdV2FileCurrentViewSource(options.CurrentXnv1Path));
            services.TryAddSingleton<ProtectedFileContactResolveOneUseRequestLedger>(_ =>
            {
                var key = DirectoryPublicationProtectedFile.ReadKey(
                    options.ProofRequestLedgerIntegrityKeyPath);
                try
                {
                    return new ProtectedFileContactResolveOneUseRequestLedger(
                        options.ProofRequestLedgerRootPath, network, key);
                }
                finally { CryptographicOperations.ZeroMemory(key); }
            });
            services.TryAddSingleton<DeepIdV2DirectoryProofIssuer>(provider =>
            {
                var key = DirectoryPublicationProtectedFile.ReadKey(
                    options.IntegrityKeyPath);
                try
                {
                    return new DeepIdV2DirectoryProofIssuer(
                        provider.GetRequiredService<DeepIdV2XPointAuthoritySource>(),
                        provider.GetRequiredService<DeepIdV2DirectoryBootstrapSource>(),
                        provider.GetRequiredService<IDeepIdV2CurrentViewSource>(),
                        provider.GetRequiredService<FileContactResolveDtt1WitnessCustody>(),
                        provider.GetRequiredService<ProtectedFileContactResolveOneUseRequestLedger>(),
                        provider.GetRequiredService<IContactResolveTrustedTimeContextSource>(),
                        options.StatePath, network, key, options.DeploymentProfileId,
                        provider.GetService<IDeepIdV2DirectoryLatestHeadFloor>());
                }
                finally { CryptographicOperations.ZeroMemory(key); }
            });
        }
        return new DeepIdV2DirectoryAuthorityHostingState(true,
            options.ProofEnabled);
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
        if (state.ProofEnabled)
            app.MapPost(ProofEndpointPath, HandleProofAsync)
                .WithMetadata(new RequestSizeLimitAttribute(
                    DeepIdV2DirectoryProofWireCodec.RequestLength));
    }

    private static async Task<IResult> HandleProofAsync(HttpContext context,
        DeepIdV2DirectoryProofIssuer issuer,
        ContactResolveIssuanceAdmissionGate admission,
        ILogger<DeepIdV2DirectoryProofIssuer> logger,
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
                "proof-rate-limited");
        }
        if (!string.Equals(context.Request.ContentType,
                DeepIdV2DirectoryProofWireCodec.RequestMediaType,
                StringComparison.OrdinalIgnoreCase))
            return Failure(StatusCodes.Status415UnsupportedMediaType,
                "unsupported-media-type");
        if (context.Request.ContentLength is null)
            return Failure(StatusCodes.Status411LengthRequired,
                "content-length-required");
        if (context.Request.ContentLength !=
            DeepIdV2DirectoryProofWireCodec.RequestLength)
            return Failure(StatusCodes.Status413PayloadTooLarge,
                "proof-request-length-invalid");
        byte[]? encoded = null;
        try
        {
            encoded = new byte[DeepIdV2DirectoryProofWireCodec.RequestLength];
            await context.Request.Body.ReadExactlyAsync(encoded,
                cancellationToken).ConfigureAwait(false);
            var request = DeepIdV2DirectoryProofWireCodec.DecodeRequest(
                encoded);
            return Results.Bytes(await issuer.IssueWireAsync(request,
                    cancellationToken).ConfigureAwait(false),
                DeepIdV2DirectoryProofWireCodec.ResponseMediaType);
        }
        catch (OperationCanceledException) when (
            cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (ContactResolveDirectoryTargetNotFoundException)
        {
            return Failure(StatusCodes.Status409Conflict,
                "proof-floor-conflict");
        }
        catch (Exception exception) when (exception is
            ArgumentException or FormatException or EndOfStreamException)
        {
            return Failure(StatusCodes.Status400BadRequest,
                "proof-request-invalid");
        }
        catch (Exception exception) when (exception is
            CryptographicException or InvalidDataException or IOException or
            InvalidOperationException or PlatformNotSupportedException or
            UnauthorizedAccessException or AccountDirectoryProofAuthoringException or
            NpgsqlException)
        {
            logger.LogError(exception,
                "DID2 directory proof authority is unavailable.");
            return Failure(StatusCodes.Status503ServiceUnavailable,
                "proof-authority-unavailable");
        }
        finally
        {
            if (encoded is not null)
                CryptographicOperations.ZeroMemory(encoded);
        }
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
            UnauthorizedAccessException or NpgsqlException)
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

    private static void RequireProductionCutover(
        DeepIdV2DirectoryAuthorityOptions options)
    {
        if (!options.ProductionCutoverAttested || !options.ProofEnabled ||
            string.IsNullOrWhiteSpace(
                options.LatestHeadFloorPostgreSqlConnectionString))
            throw new InvalidOperationException(
                "Production DID2 requires an attested independent rollback floor and current proof publication.");
        NpgsqlConnectionStringBuilder connection;
        try
        {
            connection = new NpgsqlConnectionStringBuilder(
                options.LatestHeadFloorPostgreSqlConnectionString);
        }
        catch (ArgumentException exception)
        {
            throw new InvalidOperationException(
                "Production DID2 floor connection configuration is invalid.",
                exception);
        }
        var hosts = (connection.Host ?? string.Empty).Split(',',
            StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        if (hosts.Length != 1 || IsLocalFloorHost(hosts[0]) ||
            connection.SslMode != SslMode.VerifyFull ||
            (connection.TryGetValue("Trust Server Certificate", out var trust) &&
             trust is true) ||
            string.IsNullOrWhiteSpace(connection.RootCertificate) ||
            !Path.IsPathFullyQualified(connection.RootCertificate) ||
            !File.Exists(connection.RootCertificate))
            throw new InvalidOperationException(
                "Production DID2 rollback floor requires one remote PostgreSQL host and VerifyFull TLS with an exact local root certificate.");
    }

    private static bool IsLocalFloorHost(string host)
    {
        var canonical = host.TrimEnd('.').Trim('[', ']');
        return canonical.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
            canonical.StartsWith("/", StringComparison.Ordinal) ||
            (IPAddress.TryParse(canonical, out var address) &&
             (IPAddress.IsLoopback(address) ||
              address.Equals(IPAddress.Any) ||
              address.Equals(IPAddress.IPv6Any)));
    }

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
        if (options.ProofEnabled &&
            (string.IsNullOrWhiteSpace(options.CurrentXnv1Path) ||
             string.IsNullOrWhiteSpace(options.ProofRequestLedgerRootPath) ||
             string.IsNullOrWhiteSpace(options.ProofRequestLedgerIntegrityKeyPath) ||
             !File.Exists(Path.GetFullPath(options.CurrentXnv1Path))))
            throw new InvalidOperationException(
                "DID2 proof publication requires an exact XNV1 and a separate protected nonce ledger.");
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
            .Concat(options.ProofEnabled
                ? [options.CurrentXnv1Path,
                    options.ProofRequestLedgerRootPath,
                    options.ProofRequestLedgerIntegrityKeyPath]
                : [])
            .Concat(new[]
            {
                configuration["AccountDirectoryAuthority:StatePath"],
                configuration["AccountDirectoryAuthority:IntegrityKeyPath"],
                configuration["ContactResolveProductionAuthority:TrustedTimeStatePath"],
                configuration["ContactResolveProductionAuthority:TrustedTimeIntegrityKeyPath"],
                configuration["ContactResolveProductionAuthority:RequestLedgerIntegrityKeyPath"],
                configuration["ContactResolveProductionAuthority:RequestLedgerRootPath"],
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
        if (options.ProofEnabled)
        {
            var proofKey = DirectoryPublicationProtectedFile.ReadKey(
                options.ProofRequestLedgerIntegrityKeyPath);
            CryptographicOperations.ZeroMemory(proofKey);
            _ = DeepIdV2XPointAuthoritySource.ReadExact(
                options.CurrentXnv1Path);
        }
        return (network, networkPin, headPin);
    }
}
#endif
