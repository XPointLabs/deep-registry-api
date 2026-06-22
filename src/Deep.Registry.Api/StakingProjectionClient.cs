using System.Net;
using System.Text.Json;
using Microsoft.Extensions.Options;

namespace Deep.Registry.Api;

public interface IStakingProjectionClient
{
    Task<IReadOnlyList<StakingProjectedNode>> GetNodesAsync(CancellationToken cancellationToken = default);

    Task<StakingProjectedNode?> GetNodeAsync(string nodeId, CancellationToken cancellationToken = default);

    Task<RegistrationRewardState?> GetRewardsAsync(string address, CancellationToken cancellationToken = default);
}

public sealed record StakingProjectedNode
{
    public string NodeId { get; init; } = "";

    public string OperatorAddress { get; init; } = "";

    public string RewardsAddress { get; init; } = "";

    public long StakeAtomic { get; init; }

    public string Status { get; init; } = "";
}

public sealed class StakingProjectionClient : IStakingProjectionClient
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web);
    private readonly HttpClient _httpClient;
    private readonly RegistryOptions _options;

    public StakingProjectionClient(HttpClient httpClient, IOptions<RegistryOptions> options)
    {
        _httpClient = httpClient;
        _options = options.Value;
    }

    public async Task<IReadOnlyList<StakingProjectedNode>> GetNodesAsync(CancellationToken cancellationToken = default)
    {
        if (!IsEnabled())
        {
            return [];
        }

        try
        {
            using var response = await _httpClient.GetAsync("api/staking/nodes", cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                return [];
            }

            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
            var nodes = await JsonSerializer.DeserializeAsync<List<StakingProjectedNode>>(stream, SerializerOptions, cancellationToken);
            return nodes ?? [];
        }
        catch
        {
            return [];
        }
    }

    public async Task<StakingProjectedNode?> GetNodeAsync(string nodeId, CancellationToken cancellationToken = default)
    {
        if (!IsEnabled())
        {
            return null;
        }

        try
        {
            using var response = await _httpClient.GetAsync($"api/staking/nodes/{Uri.EscapeDataString(nodeId)}", cancellationToken);
            if (response.StatusCode == HttpStatusCode.NotFound)
            {
                return null;
            }

            if (!response.IsSuccessStatusCode)
            {
                return null;
            }

            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
            return await JsonSerializer.DeserializeAsync<StakingProjectedNode>(stream, SerializerOptions, cancellationToken);
        }
        catch
        {
            return null;
        }
    }

    public async Task<RegistrationRewardState?> GetRewardsAsync(string address, CancellationToken cancellationToken = default)
    {
        if (!IsEnabled())
        {
            return null;
        }

        try
        {
            using var response = await _httpClient.GetAsync($"api/staking/rewards/{Uri.EscapeDataString(address)}", cancellationToken);
            if (response.StatusCode == HttpStatusCode.NotFound)
            {
                return null;
            }

            if (!response.IsSuccessStatusCode)
            {
                return null;
            }

            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
            var projection = await JsonSerializer.DeserializeAsync<StakingRewardProjection>(stream, SerializerOptions, cancellationToken);
            if (projection is null)
            {
                return null;
            }

            return new RegistrationRewardState(
                projection.Address,
                projection.TokenSymbol,
                projection.TokenDecimals,
                projection.LifetimeRewardsAtomic,
                projection.ClaimedRewardsAtomic,
                projection.ClaimableRewardsAtomic);
        }
        catch
        {
            return null;
        }
    }

    private bool IsEnabled()
    {
        return _httpClient.BaseAddress is not null && !string.IsNullOrWhiteSpace(_options.StakingBackendBaseUrl);
    }

    private sealed record StakingRewardProjection
    {
        public string Address { get; init; } = "";

        public string TokenSymbol { get; init; } = "XPNT";

        public int TokenDecimals { get; init; } = 9;

        public long LifetimeRewardsAtomic { get; init; }

        public long ClaimedRewardsAtomic { get; init; }

        public long ClaimableRewardsAtomic { get; init; }
    }
}
