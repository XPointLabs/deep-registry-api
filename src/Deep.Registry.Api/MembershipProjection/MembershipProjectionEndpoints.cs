namespace Deep.Registry.Api;

public static class MembershipProjectionEndpoints
{
    public const string BridgeContentType =
        "application/vnd.deep.p04.signed-bridge.v1+octet-stream";

    public static void MapMembershipProjectionEndpoints(this WebApplication app)
    {
        app.MapGet("/health/ready", (MembershipProjectionService service) =>
        {
            var status = service.GetStatus();
            return !status.Enabled || status.Ready
                ? Results.Ok(new { ok = true })
                : Results.Json(
                    new { code = status.State },
                    statusCode: StatusCodes.Status503ServiceUnavailable);
        });

        app.MapGet(
            "/api/v1/checkpoints/status",
            (MembershipProjectionService service) => Results.Ok(service.GetStatus()));

        app.MapGet(
            "/api/v1/checkpoints/bridge",
            (
                HttpRequest request,
                HttpResponse response,
                MembershipProjectionService service,
                TimeProvider timeProvider) =>
            {
                if (!service.TryGetBridge(out var artifact) || artifact is null)
                {
                    var status = service.GetStatus();
                    return Results.Json(
                        new { code = status.State },
                        statusCode: StatusCodes.Status503ServiceUnavailable,
                        contentType: "application/problem+json");
                }

                var etag = $"\"sha256-{artifact.Sha256}\"";
                response.Headers.ETag = etag;
                var maxAge = Math.Max(
                        0,
                        (long)Math.Floor(
                            (artifact.ValidUntil - timeProvider.GetUtcNow()).TotalSeconds));
                response.Headers.CacheControl = $"public,max-age={maxAge}";
                if (request.Headers.IfNoneMatch.Any(value =>
                        string.Equals(value, etag, StringComparison.Ordinal)))
                {
                    return Results.StatusCode(StatusCodes.Status304NotModified);
                }

                return Results.Bytes(artifact.Bytes, BridgeContentType);
            });
    }
}
