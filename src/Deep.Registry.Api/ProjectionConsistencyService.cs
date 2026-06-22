namespace Deep.Registry.Api;

public sealed class ProjectionConsistencyService
{
    private readonly NodeRegistry _registry;
    private readonly IStakingProjectionClient _stakingProjectionClient;

    public ProjectionConsistencyService(NodeRegistry registry, IStakingProjectionClient stakingProjectionClient)
    {
        _registry = registry;
        _stakingProjectionClient = stakingProjectionClient;
    }

    public async Task<ProjectionConsistencyReport> BuildReportAsync(CancellationToken cancellationToken = default)
    {
        var registryNodes = _registry.GetNodes();
        var stakingNodes = await _stakingProjectionClient.GetNodesAsync(cancellationToken);

        var registryById = registryNodes.ToDictionary(node => Normalize(node.NodeId), StringComparer.OrdinalIgnoreCase);
        var stakingById = stakingNodes
            .Where(node => !string.IsNullOrWhiteSpace(node.NodeId))
            .ToDictionary(node => Normalize(node.NodeId), StringComparer.OrdinalIgnoreCase);

        var issues = new List<ProjectionConsistencyIssue>();

        foreach (var registryNode in registryNodes)
        {
            var nodeId = Normalize(registryNode.NodeId);
            if (!stakingById.TryGetValue(nodeId, out var projected))
            {
                issues.Add(new ProjectionConsistencyIssue(
                    registryNode.NodeId,
                    "staking-node-missing",
                    "Node exists in registry but was not found in staking backend projection."));
                continue;
            }

            if (registryNode.StakeAtomic != projected.StakeAtomic)
            {
                issues.Add(new ProjectionConsistencyIssue(
                    registryNode.NodeId,
                    "stake-divergence",
                    $"Registry stakeAtomic={registryNode.StakeAtomic}, staking stakeAtomic={projected.StakeAtomic}."));
            }

            if (!string.Equals(Normalize(registryNode.OperatorAddress), Normalize(projected.OperatorAddress), StringComparison.OrdinalIgnoreCase))
            {
                issues.Add(new ProjectionConsistencyIssue(
                    registryNode.NodeId,
                    "operator-divergence",
                    $"Registry operatorAddress={registryNode.OperatorAddress}, staking operatorAddress={projected.OperatorAddress}."));
            }

            if (!string.Equals(Normalize(registryNode.RewardsAddress), Normalize(projected.RewardsAddress), StringComparison.OrdinalIgnoreCase))
            {
                issues.Add(new ProjectionConsistencyIssue(
                    registryNode.NodeId,
                    "rewards-divergence",
                    $"Registry rewardsAddress={registryNode.RewardsAddress}, staking rewardsAddress={projected.RewardsAddress}."));
            }
        }

        foreach (var projected in stakingNodes)
        {
            if (!registryById.ContainsKey(Normalize(projected.NodeId)))
            {
                issues.Add(new ProjectionConsistencyIssue(
                    projected.NodeId,
                    "registry-node-missing",
                    "Node exists in staking backend projection but is not registered in registry."));
            }
        }

        return new ProjectionConsistencyReport(
            DateTimeOffset.UtcNow,
            registryNodes.Count,
            stakingNodes.Count,
            issues);
    }

    public async Task<ProjectionConsistencyReport> BuildNodeReportAsync(string nodeId, CancellationToken cancellationToken = default)
    {
        var full = await BuildReportAsync(cancellationToken);
        var normalized = Normalize(nodeId);
        var filtered = full.Issues
            .Where(issue => string.Equals(Normalize(issue.NodeId), normalized, StringComparison.OrdinalIgnoreCase))
            .ToArray();

        return new ProjectionConsistencyReport(full.GeneratedAt, full.TotalRegistryNodes, full.TotalStakingNodes, filtered);
    }

    private static string Normalize(string value)
    {
        return value.Trim().ToLowerInvariant();
    }
}
