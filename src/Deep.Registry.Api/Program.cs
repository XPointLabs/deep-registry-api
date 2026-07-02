using Deep.Registry.Api;

var builder = WebApplication.CreateBuilder(args);

builder.Services.Configure<RegistryOptions>(builder.Configuration.GetSection("Registry"));
builder.Services.AddHttpClient<IStakingProjectionClient, StakingProjectionClient>((services, client) =>
{
    var options = services.GetRequiredService<Microsoft.Extensions.Options.IOptions<RegistryOptions>>().Value;
    var timeoutSeconds = Math.Max(1, options.StakingProjectionTimeoutSeconds);
    client.Timeout = TimeSpan.FromSeconds(timeoutSeconds);

    if (!string.IsNullOrWhiteSpace(options.StakingBackendBaseUrl))
    {
        client.BaseAddress = new Uri(options.StakingBackendBaseUrl.EndsWith('/')
            ? options.StakingBackendBaseUrl
            : options.StakingBackendBaseUrl + "/");
    }
});
builder.Services.AddSingleton<NodeRegistry>();
builder.Services.AddSingleton<CallSignalStore>();
builder.Services.AddSingleton<RegistryCatalogReplayGuard>();
builder.Services.AddTransient<ProjectionConsistencyService>();
builder.Services.AddHostedService<RegistryReconciliationWorker>();

var app = builder.Build();

app.UseDefaultFiles();
app.UseStaticFiles();

app.MapGet("/", () => Results.Redirect("/index.html"));
app.MapGet("/health/live", () => Results.Ok(new { ok = true, service = "deep-registry-api" }));

var api = app.MapGroup("/api");

var calls = api.MapGroup("/calls");
calls.MapPost("/signal", (CallSignalRequest request, CallSignalStore store) =>
    store.Enqueue(request, DateTimeOffset.UtcNow) switch
    {
        CallSignalEnqueueResult.Accepted => Results.Accepted(),
        CallSignalEnqueueResult.Unauthorized => Results.Unauthorized(),
        CallSignalEnqueueResult.QueueFull => Results.StatusCode(StatusCodes.Status429TooManyRequests),
        _ => Results.BadRequest(new { error = "invalid call signal" })
    });
calls.MapGet("/inbox/{recipient}", (string recipient, HttpRequest request, CallSignalStore store) =>
    store.VerifyInboxRequest(recipient, request.Headers, DateTimeOffset.UtcNow)
        ? Results.Ok(store.Drain(recipient, DateTimeOffset.UtcNow))
        : Results.Unauthorized());

api.MapPost("/nodes/register", (RegisterNodeRequest request, NodeRegistry registry) =>
{
    var result = registry.Register(request);
    return result.Success
        ? Results.Created($"/api/nodes/{result.Value!.NodeId}", result.Value)
        : Results.BadRequest(new { error = result.Error });
});

api.MapGet("/nodes/{nodeId}", (string nodeId, NodeRegistry registry) =>
{
    var node = registry.GetPublicNode(nodeId);
    return node is null ? Results.NotFound(new { error = "node not found" }) : Results.Ok(node);
});

api.MapGet("/nodes/runtime", (NodeRegistry registry) => Results.Ok(registry.GetRuntimeStats()));

api.MapGet("/nodes/{nodeId}/stake-state", (string nodeId, NodeRegistry registry) =>
{
    var state = registry.GetStakeState(nodeId);
    return state is null ? Results.NotFound(new { error = "node not found" }) : Results.Ok(state);
});

api.MapGet("/nodes/{nodeId}/rewards-stake-state", async (string nodeId, NodeRegistry registry, IStakingProjectionClient projections, CancellationToken cancellationToken) =>
{
    var stake = registry.GetStakeState(nodeId);
    if (stake is null)
    {
        return Results.NotFound(new { error = "node not found" });
    }

    var projected = await projections.GetRewardsAsync(stake.RewardsAddress, cancellationToken);
    return Results.Ok(new RewardsStakeState(nodeId, stake, projected ?? registry.GetRewards(stake.RewardsAddress)));
});

api.MapGet("/rewards/{address}", async (string address, NodeRegistry registry, IStakingProjectionClient projections, CancellationToken cancellationToken) =>
{
    var projected = await projections.GetRewardsAsync(address, cancellationToken);
    return Results.Ok(projected ?? registry.GetRewards(address));
});

api.MapGet("/nodes", (NodeRegistry registry) => Results.Ok(registry.GetPublicNodes()));
api.MapGet("/relay-contacts", (HttpRequest request, NodeRegistry registry, RegistryCatalogReplayGuard replayGuard) =>
{
    return RegistryCatalogRequestAuthenticator.Verify(request, registry, replayGuard, DateTimeOffset.UtcNow)
        ? Results.Ok(registry.GetRelayContacts())
        : Results.Unauthorized();
});
api.MapGet("/nodes/{nodeId}/projection-consistency", async (string nodeId, ProjectionConsistencyService consistency, CancellationToken cancellationToken) =>
{
    var report = await consistency.BuildNodeReportAsync(nodeId, cancellationToken);
    return Results.Ok(report);
});
api.MapGet("/nodes/reconciliation/projections", async (ProjectionConsistencyService consistency, CancellationToken cancellationToken) =>
{
    var report = await consistency.BuildReportAsync(cancellationToken);
    return Results.Ok(report);
});
api.MapGet("/nodes/reconciliation", (NodeRegistry registry) => Results.Ok(registry.GetReconciliationReport()));
api.MapGet("/nodes/reconciliation/job", (NodeRegistry registry) => Results.Ok(registry.GetReconciliationJobStatus()));
api.MapGet("/nodes/reconciliation/last", (NodeRegistry registry) =>
{
    var report = registry.GetLastReconciliationReport();
    return report is null
        ? Results.NotFound(new { error = "reconciliation job has not completed yet" })
        : Results.Ok(report);
});

app.Run();

public partial class Program
{
}
