using Deep.Registry.Api;

var builder = WebApplication.CreateBuilder(args);

builder.Services.Configure<RegistryOptions>(builder.Configuration.GetSection("Registry"));
builder.Services.Configure<CallInfrastructureOptions>(builder.Configuration.GetSection("Calls"));
builder.Services.Configure<MembershipProjectionOptions>(
    builder.Configuration.GetSection("MembershipProjection"));
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton(services =>
    P04MembershipArtifactVerifier.Create(
        services.GetServices<Deep.Protocol.DeepExtension.Membership.IMembershipSignatureVerifier>()));
builder.Services.AddSingleton(services =>
    MembershipProjectionMonotonicBoundary.Create(
        services.GetServices<IMembershipProjectionMonotonicAnchor>()));
builder.Services.AddSingleton<IMembershipProjectionPersistence>(services =>
    new FileMembershipProjectionPersistence(
        MembershipProjectionService.ResolveStatePath(
            services
                .GetRequiredService<
                    Microsoft.Extensions.Options.IOptions<MembershipProjectionOptions>>()
                .Value)));
builder.Services.AddSingleton<MembershipProjectionService>();
builder.Services.AddHostedService<MembershipProjectionWorker>();
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
builder.Services.AddSingleton<CallIceCredentialIssuer>();
builder.Services.AddHttpClient<CallPushNotifier>();
builder.Services.AddSingleton<RegistryCatalogReplayGuard>();
builder.Services.AddTransient<ProjectionConsistencyService>();
builder.Services.AddHostedService<RegistryReconciliationWorker>();

var app = builder.Build();

app.UseDefaultFiles();
app.UseStaticFiles();

app.MapGet("/", () => Results.Redirect("/index.html"));
app.MapGet("/health/live", () => Results.Ok(new { ok = true, service = "deep-registry-api" }));
app.MapMembershipProjectionEndpoints();

var api = app.MapGroup("/api");

var calls = api.MapGroup("/calls");
calls.MapPost("/signal", async (CallSignalRequest request, CallSignalStore store, CallPushNotifier push, CancellationToken cancellationToken) =>
{
    var result = store.Enqueue(request, DateTimeOffset.UtcNow);
    if (result == CallSignalEnqueueResult.Accepted)
    {
        await push.NotifyOfferAsync(request, cancellationToken);
    }

    return result switch
    {
        CallSignalEnqueueResult.Accepted => Results.Accepted(),
        CallSignalEnqueueResult.Unauthorized => Results.Unauthorized(),
        CallSignalEnqueueResult.QueueFull => Results.StatusCode(StatusCodes.Status429TooManyRequests),
        _ => Results.BadRequest(new { error = "invalid call signal" })
    };
});
calls.MapGet("/inbox/{recipient}", (string recipient, HttpRequest request, CallSignalStore store) =>
    store.VerifyInboxRequest(recipient, request.Headers, DateTimeOffset.UtcNow)
        ? Results.Ok(store.Drain(recipient, DateTimeOffset.UtcNow))
        : Results.Unauthorized());
calls.MapGet("/ice-servers/{recipient}", (string recipient, HttpRequest request, CallSignalStore store, CallIceCredentialIssuer issuer) =>
{
    var now = DateTimeOffset.UtcNow;
    if (!store.VerifyIceRequest(recipient, request.Headers, now))
    {
        return Results.Unauthorized();
    }

    var configuration = issuer.Issue(recipient, now);
    return configuration is null
        ? Results.Problem("TURN infrastructure is not configured.", statusCode: StatusCodes.Status503ServiceUnavailable)
        : Results.Ok(configuration);
});

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
api.MapGet("/internal/nodes", (NodeRegistry registry) => Results.Ok(registry.GetControlNodes()));
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
