using System.Security.Cryptography;
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
                return new PostgreSqlProductionMailboxStateStore(options.PostgreSqlConnectionString);
            }
            if (!environment.IsDevelopment() || !options.UseDevelopmentInMemoryState)
                throw new InvalidOperationException("Non-production mailbox state requires explicit Development in-memory opt-in.");
            return new InMemoryProductionMailboxStateStore();
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
}
