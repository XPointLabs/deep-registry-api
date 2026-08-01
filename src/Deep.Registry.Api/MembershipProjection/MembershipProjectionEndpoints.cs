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
                MembershipProjectionService service) =>
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
                response.Headers.CacheControl =
                    "private,no-store,max-age=0,must-revalidate";
                if (MatchesIfNoneMatch(request.Headers.IfNoneMatch, etag))
                {
                    return Results.StatusCode(StatusCodes.Status304NotModified);
                }

                return Results.Bytes(artifact.Bytes, BridgeContentType);
            });
    }

    private static bool MatchesIfNoneMatch(
        IEnumerable<string> headerValues,
        string currentEtag)
    {
        foreach (var value in headerValues)
        {
            foreach (var candidateValue in value.Split(','))
            {
                var candidate = candidateValue.Trim();
                if (candidate == "*")
                {
                    return true;
                }

                if (candidate.StartsWith("W/", StringComparison.OrdinalIgnoreCase))
                {
                    candidate = candidate[2..].TrimStart();
                }

                if (string.Equals(candidate, currentEtag, StringComparison.Ordinal))
                {
                    return true;
                }
            }
        }

        return false;
    }
}
