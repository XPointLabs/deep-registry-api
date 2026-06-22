namespace Deep.Registry.Api;

public sealed record RegisterNodeRequest
{
    public string NodeId { get; init; } = "";
    public string OperatorAddress { get; init; } = "";
    public string RewardsAddress { get; init; } = "";
    public BlsPublicKey BlsPublicKey { get; init; } = new();
    public string BlsSignature { get; init; } = "";
    public string Ed25519PublicKey { get; init; } = "";
    public string Ed25519Signature1 { get; init; } = "";
    public string Ed25519Signature2 { get; init; } = "";
    public int OperatorFeeBps { get; init; }
    public long StakeAtomic { get; init; }
    public IReadOnlyList<ContributorStake> Contributors { get; init; } = Array.Empty<ContributorStake>();
    public TransportBundle? Transport { get; init; }
    public TransportStatus? TransportStatus { get; init; }
    public string SigningEndpoint { get; init; } = "";
    public RelayContactDocument? RelayContact { get; init; }
}

public sealed record BlsPublicKey
{
    public string Data { get; init; } = "";
    public string X { get; init; } = "";
    public string Y { get; init; } = "";
}

public sealed record ContributorStake
{
    public string Address { get; init; } = "";
    public string Beneficiary { get; init; } = "";
    public long AmountAtomic { get; init; }
}

public sealed record TransportBundle
{
    public string Protocol { get; init; } = "vless";
    public string Host { get; init; } = "";
    public int Port { get; init; }
    public string Uuid { get; init; } = "";
    public string Flow { get; init; } = "";
    public string Security { get; init; } = "reality";
    public string Sni { get; init; } = "";
    public string PublicKey { get; init; } = "";
    public string ShortId { get; init; } = "";
    public string Fingerprint { get; init; } = "chrome";
    public string Path { get; init; } = "";
    public IReadOnlyList<string> Alpn { get; init; } = Array.Empty<string>();
}

public sealed record TransportStatus
{
    public bool Enabled { get; init; }
    public bool Running { get; init; }
    public bool Degraded { get; init; }
    public string Mode { get; init; } = "";
    public bool Mocked { get; init; }
    public int RestartCount { get; init; }
    public int ConsecutiveFailures { get; init; }
    public string? LastExitReason { get; init; }
    public DateTimeOffset? LastStartedAt { get; init; }
    public DateTimeOffset? DegradedUntil { get; init; }
}

public sealed record RegisteredNode
{
    public string NodeId { get; init; } = "";
    public string OperatorAddress { get; init; } = "";
    public string RewardsAddress { get; init; } = "";
    public BlsPublicKey BlsPublicKey { get; init; } = new();
    public string BlsSignature { get; init; } = "";
    public string Ed25519PublicKey { get; init; } = "";
    public string Ed25519Signature1 { get; init; } = "";
    public string Ed25519Signature2 { get; init; } = "";
    public int OperatorFeeBps { get; init; }
    public long StakeAtomic { get; init; }
    public IReadOnlyList<ContributorStake> Contributors { get; init; } = Array.Empty<ContributorStake>();
    public TransportBundle? Transport { get; init; }
    public TransportStatus? TransportStatus { get; init; }
    public DateTimeOffset? TransportHealthySince { get; init; }
    public DateTimeOffset? TransportUnhealthySince { get; init; }
    public string SigningEndpoint { get; init; } = "";
    public RelayContactDocument? RelayContact { get; init; }
    public DateTimeOffset CreatedAt { get; init; }
    public DateTimeOffset UpdatedAt { get; init; }
    public long Revision { get; init; }
}

public sealed record RelayContactDocument
{
    public string RouterId { get; init; } = "";
    public string PublicHost { get; init; } = "";
    public string? PublicIp { get; init; }
    public int PublicPort { get; init; }
    public string X25519PublicKey { get; init; } = "";
    public string RpcEndpoint { get; init; } = "";
    public DateTimeOffset SignedAt { get; init; }
    public DateTimeOffset ExpiresAt { get; init; }
    public string RouterVersion { get; init; } = "";
    public bool IsReachable { get; init; }
    public IReadOnlyList<string> Capabilities { get; init; } = Array.Empty<string>();
    public string? Serialized { get; init; }
    public string SignatureAlgorithm { get; init; } = "";
    public string Signature { get; init; } = "";
}

public sealed record TransportProfile(
    string NodeId,
    string Protocol,
    string Endpoint,
    TransportBundle Bundle,
    DateTimeOffset UpdatedAt);

public sealed record StakeState(
    string NodeId,
    string TokenName,
    string TokenSymbol,
    int TokenDecimals,
    long StakingRequirementAtomic,
    long StakeAtomic,
    int OperatorFeeBps,
    string OperatorAddress,
    string RewardsAddress,
    IReadOnlyList<ContributorStake> Contributors,
    string Status);

public sealed record RegistrationRewardState(
    string Address,
    string TokenSymbol,
    int TokenDecimals,
    long LifetimeRewardsAtomic,
    long ClaimedRewardsAtomic,
    long ClaimableRewardsAtomic);

public sealed record RewardsStakeState(
    string NodeId,
    StakeState Stake,
    RegistrationRewardState Rewards);

public sealed record ReconciliationIssue(
    string NodeId,
    string Code,
    string Message);

public sealed record ReconciliationReport(
    DateTimeOffset GeneratedAt,
    int TotalNodes,
    IReadOnlyList<ReconciliationIssue> Issues);

public sealed record ReconciliationJobStatus(
    DateTimeOffset? LastRunAt,
    int LastTotalNodes,
    int LastIssueCount,
    long Runs);

public sealed record RegistryRuntimeStats(
    int TotalNodes,
    long CorruptedStateRecoveries);

public sealed record ProjectionConsistencyIssue(
    string NodeId,
    string Code,
    string Message);

public sealed record ProjectionConsistencyReport(
    DateTimeOffset GeneratedAt,
    int TotalRegistryNodes,
    int TotalStakingNodes,
    IReadOnlyList<ProjectionConsistencyIssue> Issues);

public sealed record RegistryOptions
{
    public long StakingRequirementAtomic { get; init; } = 25_000L * 1_000_000_000L;

    public bool ReconciliationJobEnabled { get; init; } = true;

    public int ReconciliationIntervalSeconds { get; init; } = 60;

    public string? StakingBackendBaseUrl { get; init; }

    public int StakingProjectionTimeoutSeconds { get; init; } = 5;

    public string? StatePath { get; init; }
}

public sealed record RegistryResult<T>(bool Success, T? Value, string? Error)
{
    public static RegistryResult<T> Ok(T value) => new(true, value, null);

    public static RegistryResult<T> Fail(string error) => new(false, default, error);
}
