using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxTopology;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Deep.Registry.Api.ProductionMailbox;

public interface IProductionMailboxInternalAuthorizer
{
    ValueTask<bool> IsAuthorizedAsync(HttpContext context, CancellationToken cancellationToken);
}

public sealed class CertificateProductionMailboxInternalAuthorizer(
    IOptions<ProductionMailboxOptions> options) : IProductionMailboxInternalAuthorizer
{
    public ValueTask<bool> IsAuthorizedAsync(HttpContext context, CancellationToken cancellationToken)
    {
        var certificate = context.Connection.ClientCertificate;
        if (certificate is null ||
            !string.Equals(context.User.Identity?.AuthenticationType,
                options.Value.InternalAdminAuthenticationType, StringComparison.Ordinal))
            return ValueTask.FromResult(false);
        byte[] expected;
        try
        {
            expected = ProductionMailboxArtifacts.Hex(
            options.Value.InternalAdminClientCertificateSha256, 32, false);
        }
        catch (InvalidOperationException) { return ValueTask.FromResult(false); }
        return ValueTask.FromResult(CryptographicOperations.FixedTimeEquals(
            SHA256.HashData(certificate.RawData), expected));
    }
}

public static class ProductionMailboxHostingExtensions
{
    public static bool AddProductionMailbox(
        this IServiceCollection services,
        IConfiguration configuration,
        IHostEnvironment environment)
    {
        var configured = configuration.GetSection("ProductionMailbox").Get<ProductionMailboxOptions>()
            ?? new ProductionMailboxOptions();
        services.Configure<ProductionMailboxOptions>(configuration.GetSection("ProductionMailbox"));
        if (!configured.Enabled) return false;
        services.AddSingleton<ProductionMailboxMetrics>();
        services.AddSingleton(sp => new ProductionMailboxArtifactProvider(
            sp.GetRequiredService<IOptions<ProductionMailboxOptions>>().Value,
            sp.GetRequiredService<TimeProvider>()));
        services.AddHostedService<ProductionMailboxArtifactsStartupValidator>();
        services.AddSingleton<IEd25519ExternalSigner>(sp => ProductionMailboxSignerFactory.Create(
            sp.GetRequiredService<IOptions<ProductionMailboxOptions>>().Value, environment));
        services.AddSingleton<IProductionMailboxClosurePublisherSigner>(sp =>
            ProductionMailboxClosurePublisherSignerFactory.Create(
                sp.GetRequiredService<IOptions<ProductionMailboxOptions>>().Value,
                environment));
        services.TryAddSingleton<IProductionMailboxClosureTransport,
            HttpsProductionMailboxClosureTransport>();
        services.AddSingleton<IProductionMailboxStateStore>(sp =>
        {
            var options = sp.GetRequiredService<IOptions<ProductionMailboxOptions>>().Value;
            if (environment.IsProduction())
            {
                if (options.UseDevelopmentInMemoryState || string.IsNullOrWhiteSpace(options.PostgreSqlConnectionString))
                    throw new InvalidOperationException("Production mailbox state requires PostgreSQL; in-memory state is forbidden.");
                return new PostgreSqlProductionMailboxStateStore(
                    options.PostgreSqlConnectionString,
                    ProductionMailboxV2PreparedIntegrity.ReadProtectedKey(
                        options.RouteStateHmacKeyPath), OwnerControlLimits(options));
            }
            if (!environment.IsDevelopment() || !options.UseDevelopmentInMemoryState)
                throw new InvalidOperationException("Non-production mailbox state requires explicit Development in-memory opt-in.");
            return new InMemoryProductionMailboxStateStore(ownerControlLimits:
                OwnerControlLimits(options));
        });
        services.AddSingleton(sp =>
            (IProductionMailboxRouteContinuityStateStore)
                sp.GetRequiredService<IProductionMailboxStateStore>());
        services.AddSingleton(sp =>
            (IProductionMailboxOwnerControlStateStore)
                sp.GetRequiredService<IProductionMailboxStateStore>());
        services.TryAddSingleton<IProductionMailboxOwnerChannelAuthorizer,
            CertificateProductionMailboxOwnerChannelAuthorizer>();
        services.AddSingleton<IProductionMailboxOwnerControlKeyStore>(sp =>
            ProductionMailboxOwnerControlKeyStoreFactory.Create(
                sp.GetRequiredService<IOptions<ProductionMailboxOptions>>().Value,
                environment));
        services.AddHostedService<ProductionMailboxOwnerKeyCleanupService>();
        services.AddSingleton(sp =>
        {
            var options = sp.GetRequiredService<IOptions<ProductionMailboxOptions>>().Value;
            var key = ProductionMailboxV2PreparedIntegrity.ReadProtectedKey(
                options.RouteStateHmacKeyPath);
            return new ProductionMailboxOwnerControlRateGate(
                sp.GetRequiredService<TimeProvider>(), key,
                options.MaximumOwnerControlRequestsPerWindow,
                options.OwnerControlRequestWindowSeconds);
        });
        services.AddTransient(sp =>
        {
            var options = sp.GetRequiredService<IOptions<ProductionMailboxOptions>>().Value;
            return new ProductionMailboxOwnerControlService(
                sp.GetRequiredService<IProductionMailboxRouteContinuityStateStore>(),
                sp.GetRequiredService<IProductionMailboxOwnerControlStateStore>(),
                sp.GetRequiredService<ProductionMailboxArtifactProvider>(),
                sp.GetRequiredService<IEd25519ExternalSigner>(),
                sp.GetRequiredService<IProductionMailboxOwnerControlKeyStore>(),
                sp.GetRequiredService<TimeProvider>(),
                ProductionMailboxV2PreparedIntegrity.ReadProtectedKey(
                    options.RouteStateHmacKeyPath), options.ClockSkewSeconds);
        });
        services.TryAddSingleton<IProductionMailboxInternalAuthorizer, CertificateProductionMailboxInternalAuthorizer>();
        services.AddTransient(sp => new ProductionMailboxCoordinator(
            sp.GetRequiredService<IOptions<ProductionMailboxOptions>>(),
            sp.GetRequiredService<ProductionMailboxArtifactProvider>().Current,
            sp.GetRequiredService<IEd25519ExternalSigner>(),
            sp.GetRequiredService<IProductionMailboxStateStore>(),
            sp.GetRequiredService<TimeProvider>(),
            sp.GetRequiredService<ProductionMailboxMetrics>(),
            sp.GetRequiredService<IProductionMailboxClosurePublisherSigner>(),
            sp.GetRequiredService<IProductionMailboxClosureTransport>()));
        services.AddHostedService<ProductionMailboxPublicationDrainer>();
        return true;
    }

    public static void MapProductionMailboxEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/api/production-mailbox");
        group.AddEndpointFilter(async (context, next) =>
        {
            var request = context.HttpContext.Request;
            if (!app.Environment.IsDevelopment() && !request.IsHttps)
                return Results.Problem("HTTPS is required.", statusCode: StatusCodes.Status400BadRequest);
            if (request.ContentLength > 16 * 1024)
                return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);
            return await next(context);
        });
        group.MapGet("/artifacts/{sha256}/{fileName}", (
            string sha256,
            string fileName,
            HttpRequest request,
            ProductionMailboxArtifactProvider provider) =>
        {
            if (!provider.TryGetArtifact(sha256, fileName, out var bytes, out var mediaType))
                return Results.NotFound();
            return ArtifactResult(request, bytes, SHA256.HashData(bytes), mediaType, fileName);
        });
        group.MapPost("/challenges", async (ProductionMailboxCoordinator coordinator, CancellationToken cancellationToken) =>
        {
            try { return Results.Ok(await coordinator.CreateChallengeAsync(cancellationToken)); }
            catch (ProductionMailboxIssueException exception) when (exception.Error == ProductionMailboxIssueError.RateLimited)
            { return Results.StatusCode(StatusCodes.Status429TooManyRequests); }
            catch (ProductionMailboxIssueException exception) when (exception.Error == ProductionMailboxIssueError.IssuerUnavailable)
            { return Results.StatusCode(StatusCodes.Status503ServiceUnavailable); }
        });
        group.MapPost("/credentials", async (
            ProductionMailboxIssueRequest request,
            ProductionMailboxCoordinator coordinator,
            CancellationToken cancellationToken) =>
        {
            try { return Results.Ok(await coordinator.IssueAsync(request, cancellationToken)); }
            catch (ProductionMailboxIssueException exception)
            {
                return exception.Error switch
                {
                    ProductionMailboxIssueError.InvalidChallenge => Results.BadRequest(),
                    ProductionMailboxIssueError.InvalidRequest => Results.BadRequest(),
                    ProductionMailboxIssueError.InvalidHolderProof => Results.StatusCode(StatusCodes.Status403Forbidden),
                    ProductionMailboxIssueError.InvalidEntitlement => Results.StatusCode(StatusCodes.Status403Forbidden),
                    ProductionMailboxIssueError.RouteAdvertisementRequired =>
                        Results.Conflict(new { error = "route-advertisement-required" }),
                    ProductionMailboxIssueError.Revoked => Results.StatusCode(StatusCodes.Status403Forbidden),
                    ProductionMailboxIssueError.RateLimited => Results.StatusCode(StatusCodes.Status429TooManyRequests),
                    _ => Results.StatusCode(StatusCodes.Status503ServiceUnavailable)
                };
            }
        }).WithMetadata(new RequestSizeLimitAttribute(16 * 1024));
        group.MapPost("/route-enrollments", async (
            ProductionMailboxIssueRequest request,
            ProductionMailboxCoordinator coordinator,
            CancellationToken cancellationToken) =>
        {
            try { return Results.Ok(await coordinator.EnrollRouteAsync(request, cancellationToken)); }
            catch (ProductionMailboxIssueException exception)
            {
                return exception.Error switch
                {
                    ProductionMailboxIssueError.InvalidChallenge => Results.BadRequest(),
                    ProductionMailboxIssueError.InvalidRequest => Results.BadRequest(),
                    ProductionMailboxIssueError.InvalidHolderProof =>
                        Results.StatusCode(StatusCodes.Status403Forbidden),
                    ProductionMailboxIssueError.InvalidEntitlement =>
                        Results.StatusCode(StatusCodes.Status403Forbidden),
                    ProductionMailboxIssueError.Revoked =>
                        Results.StatusCode(StatusCodes.Status403Forbidden),
                    ProductionMailboxIssueError.RateLimited =>
                        Results.StatusCode(StatusCodes.Status429TooManyRequests),
                    _ => Results.StatusCode(StatusCodes.Status503ServiceUnavailable)
                };
            }
        }).WithMetadata(new RequestSizeLimitAttribute(16 * 1024));

        var ownerControl = group.MapGroup("/owner-control");
        ownerControl.MapPost("/enroll", async (HttpContext context,
            IProductionMailboxOwnerChannelAuthorizer authorizer,
            ProductionMailboxOwnerControlRateGate rateGate,
            ProductionMailboxOwnerControlService service,
            CancellationToken cancellationToken) =>
            await OwnerControlAsync(context, authorizer, rateGate,
                ProductionMailboxMediaTypes.OwnerEnrollmentRequest,
                ProductionMailboxMediaTypes.OwnerEnrollmentResponse,
                ProductionMailboxOwnerControlHostCodec.EnrollmentRequestLength,
                async (body, owner, token) =>
                    await service.EnrollAsync(body, owner, token), cancellationToken));
        ownerControl.MapPost("/requests", async (HttpContext context,
            IProductionMailboxOwnerChannelAuthorizer authorizer,
            ProductionMailboxOwnerControlRateGate rateGate,
            ProductionMailboxOwnerControlService service,
            CancellationToken cancellationToken) =>
        {
            var result = await OwnerControlAsync(context, authorizer, rateGate,
                ProductionMailboxMediaTypes.OwnerControlRequest,
                ProductionMailboxMediaTypes.OwnerControlResponse,
                ProductionMailboxOwnerControlConstants.RequestLength,
                async (body, owner, token) =>
                {
                    var value = await service.NoChangeAsync(body, owner, token);
                    var response = new byte[value.Header.Length + value.Payload.Length];
                    value.Header.CopyTo(response, 0); value.Payload.CopyTo(response,
                        value.Header.Length); return response;
                }, cancellationToken);
            return result;
        });
        ownerControl.MapPost("/revocations", async (HttpContext context,
            IProductionMailboxOwnerChannelAuthorizer authorizer,
            ProductionMailboxOwnerControlRateGate rateGate,
            ProductionMailboxOwnerControlService service,
            CancellationToken cancellationToken) =>
            await OwnerControlAsync(context, authorizer, rateGate,
                ProductionMailboxMediaTypes.OwnerRevocationRequest,
                null, ProductionMailboxOwnerControlHostCodec.RevocationRequestLength,
                async (body, owner, token) =>
                {
                    await service.RevokeAsync(body, owner, token); return [];
                }, cancellationToken));

        var admin = app.MapGroup("/api/internal/production-mailbox");
        admin.MapPost("/artifacts/reload", async (
            HttpContext context,
            IProductionMailboxInternalAuthorizer authorizer,
            ProductionMailboxArtifactProvider provider,
            ProductionMailboxCoordinator coordinator,
            TimeProvider timeProvider,
            CancellationToken cancellationToken) =>
        {
            if (!await authorizer.IsAuthorizedAsync(context, cancellationToken)) return Results.Unauthorized();
            try
            {
                var loaded = await coordinator.PromoteConfiguredArtifactsAsync(
                    provider, timeProvider, cancellationToken);
                return Results.Ok(new
                {
                    authoritySha256 = Convert.ToHexStringLower(loaded.AuthoritySha256),
                    revocationSha256 = Convert.ToHexStringLower(loaded.RevocationSha256),
                    topologySha256 = Convert.ToHexStringLower(loaded.TopologySha256)
                });
            }
            catch (Exception exception) when (exception is InvalidDataException or InvalidOperationException or IOException)
            { return Results.Conflict(); }
        });
        admin.MapPost("/revocations/holders/{holder}", async (
            string holder,
            HttpContext context,
            IProductionMailboxInternalAuthorizer authorizer,
            ProductionMailboxCoordinator coordinator,
            CancellationToken cancellationToken) =>
        {
            if (!await authorizer.IsAuthorizedAsync(context, cancellationToken)) return Results.Unauthorized();
            try
            {
                var bytes = DecodeBase64Url(holder, 32);
                await coordinator.RevokeHolderAsync(bytes, cancellationToken);
                return Results.NoContent();
            }
            catch (FormatException) { return Results.BadRequest(); }
        });
        admin.MapGet("/runtime", async (
            HttpContext context,
            IProductionMailboxInternalAuthorizer authorizer,
            ProductionMailboxMetrics metrics,
            CancellationToken cancellationToken) =>
            await authorizer.IsAuthorizedAsync(context, cancellationToken)
                ? Results.Ok(metrics.Snapshot())
                : Results.Unauthorized());
    }

    private static IResult ArtifactResult(
        HttpRequest request, byte[] bytes, byte[] hash, string mediaType, string fileName)
    {
        var etag = $"\"{Convert.ToHexStringLower(hash)}\"";
        if (request.Headers.IfNoneMatch.Any(value => string.Equals(value, etag, StringComparison.Ordinal)))
            return Results.StatusCode(StatusCodes.Status304NotModified);
        return Results.File(bytes, mediaType, fileName, entityTag: new Microsoft.Net.Http.Headers.EntityTagHeaderValue(etag));
    }

    private static byte[] DecodeBase64Url(string value, int length)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Contains('=')) throw new FormatException();
        var padded = value.Replace('-', '+').Replace('_', '/');
        padded += new string('=', (4 - padded.Length % 4) % 4);
        var bytes = Convert.FromBase64String(padded);
        var canonical = Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        if (bytes.Length != length || canonical != value || bytes.AsSpan().IndexOfAnyExcept((byte)0) < 0)
            throw new FormatException();
        return bytes;
    }

    private static ProductionMailboxOwnerControlStoreLimits OwnerControlLimits(
        ProductionMailboxOptions options) => new(
        options.MaximumOwnerControlEntriesPerRoute,
        options.MaximumOwnerControlEntriesGlobal,
        options.MaximumOwnerControlStateBytes,
        options.MaximumOwnerControlGcBatch,
        options.OwnerControlStatementTimeoutSeconds,
        options.OwnerControlLockTimeoutSeconds,
        options.OwnerControlIdleTransactionTimeoutSeconds);

    private static async ValueTask<IResult> OwnerControlAsync(
        HttpContext context, IProductionMailboxOwnerChannelAuthorizer authorizer,
        ProductionMailboxOwnerControlRateGate rateGate, string requestMediaType,
        string? responseMediaType, int exactLength,
        Func<ReadOnlyMemory<byte>, ReadOnlyMemory<byte>, CancellationToken,
            ValueTask<byte[]>> action, CancellationToken cancellationToken)
    {
        var owner = await authorizer.GetAuthenticatedOwnerAsync(context, cancellationToken);
        if (owner is null) return Results.StatusCode(StatusCodes.Status403Forbidden);
        if (!rateGate.TryAcquire(owner))
            return Results.StatusCode(StatusCodes.Status429TooManyRequests);
        var request = context.Request;
        if (!string.Equals(request.ContentType, requestMediaType, StringComparison.Ordinal)
            || request.ContentLength != exactLength)
            return Results.BadRequest();
        var body = new byte[exactLength]; var offset = 0;
        while (offset < body.Length)
        {
            var read = await request.Body.ReadAsync(body.AsMemory(offset), cancellationToken);
            if (read == 0) return Results.BadRequest();
            offset += read;
        }
        if (await request.Body.ReadAsync(new byte[1], cancellationToken) != 0)
            return Results.BadRequest();
        try
        {
            var response = await action(body, owner, cancellationToken);
            context.Response.Headers.CacheControl = "no-store";
            context.Response.Headers.Pragma = "no-cache";
            context.Response.Headers["X-Content-Type-Options"] = "nosniff";
            if (responseMediaType is null) return Results.NoContent();
            return Results.Bytes(response, responseMediaType);
        }
        catch (UnauthorizedAccessException)
        { return Results.StatusCode(StatusCodes.Status403Forbidden); }
        catch (Exception exception) when (exception is InvalidDataException or FormatException)
        { return Results.BadRequest(); }
        catch (InvalidOperationException)
        { return Results.Conflict(); }
        catch (Exception exception) when (exception is IOException or CryptographicException
            or OperationCanceledException)
        { return Results.StatusCode(StatusCodes.Status503ServiceUnavailable); }
    }
}
