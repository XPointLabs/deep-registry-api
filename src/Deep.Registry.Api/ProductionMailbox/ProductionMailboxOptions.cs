using Deep.Protocol.DeepExtension.MailboxTopology;

namespace Deep.Registry.Api.ProductionMailbox;

public sealed class ProductionMailboxOptions
{
    public bool Enabled { get; set; }
    public string AuthorityPath { get; set; } = "";
    public string RevocationPath { get; set; } = "";
    public string TopologyPath { get; set; } = "";
    public string MembershipProofDirectory { get; set; } = "";
    public string PinnedMrXPublicKeySha256 { get; set; } = "";
    public string ExpectedNetworkId { get; set; } = "";
    public ulong PreviousAuthorityGeneration { get; set; }
    public string PreviousAuthorityHash { get; set; } = new('0', 64);
    public ulong PreviousRevocationGeneration { get; set; }
    public string PreviousRevocationHeadHash { get; set; } = new('0', 64);
    public string PreviousRevocationSnapshotHash { get; set; } = new('0', 64);
    public ulong PreviousTopologyGeneration { get; set; }
    public string PreviousTopologyHash { get; set; } = new('0', 64);
    public uint ClockSkewSeconds { get; set; } = 60;
    public uint SelectionLifetimeSeconds { get; set; } = 900;
    public uint ChallengeLifetimeSeconds { get; set; } = 300;
    public int ProofOfWorkLeadingZeroBits { get; set; } = 18;
    public int MaximumChallengesPerWindow { get; set; } = 4096;
    public int MaximumChallengesPerSourceWindow { get; set; } = 32;
    public int MaximumActiveChallengesGlobal { get; set; } = 8192;
    public int MaximumActiveChallengesPerSource { get; set; } = 32;
    public uint ChallengeWindowSeconds { get; set; } = 60;
    public string[] ChallengeTrustedProxyCidrs { get; set; } = [];
    public string ExternalSignerSocketPath { get; set; } = "";
    public uint ExternalSignerTimeoutSeconds { get; set; } = 5;
    public string ClosurePublisherSignerSocketPath { get; set; } = "";
    public uint ClosurePublisherSignerTimeoutSeconds { get; set; } = 5;
    public string ClosurePublisherEd25519PublicKey { get; set; } = "";
    public int MaximumRetainedArtifactClosures { get; set; } = 16;
    public uint CapacityReservationLifetimeSeconds { get; set; } = 3600;
    public uint CapacityReservationRenewalMarginSeconds { get; set; } = 300;
    public ulong ClosureScheduleAccountingOverheadBytes { get; set; } = 1024;
    public int MaximumCapacityPlanTargets { get; set; } = 4096;
    public string ArtifactCatalogDirectory { get; set; } = "";
    public string DevelopmentSoftwareSignerSeedPath { get; set; } = "";
    public string DevelopmentClosurePublisherSeedPath { get; set; } = "";
    public string PostgreSqlConnectionString { get; set; } = "";
    public string RouteStateHmacKeyPath { get; set; } = "";
    public string OwnerControlHsmSocketPath { get; set; } = "";
    public uint OwnerControlHsmTimeoutSeconds { get; set; } = 5;
    public string DevelopmentOwnerControlSeedPath { get; set; } = "";
    public bool OwnerControlSigningEnabled { get; set; } = true;
    public int MaximumOwnerControlRequestsPerWindow { get; set; } = 64;
    public uint OwnerControlRequestWindowSeconds { get; set; } = 60;
    public int MaximumOwnerControlEntriesPerRoute { get; set; } = 1024;
    public int MaximumOwnerControlEntriesGlobal { get; set; } = 1_000_000;
    public long MaximumOwnerControlStateBytes { get; set; } = 512L * 1024 * 1024;
    public int MaximumOwnerControlGcBatch { get; set; } = 256;
    public uint OwnerControlStatementTimeoutSeconds { get; set; } = 5;
    public uint OwnerControlLockTimeoutSeconds { get; set; } = 2;
    public uint OwnerControlIdleTransactionTimeoutSeconds { get; set; } = 5;
    public int MaximumOwnerControlDeliveriesGlobal { get; set; } = 16;
    public int MaximumOwnerControlDeliveriesPerOwner { get; set; } = 2;
    public int MaximumOwnerControlDeliveriesPerRoute { get; set; } = 1;
    public long MaximumOwnerControlDeliveryBytes { get; set; } = 64L * 1024 * 1024;
    public uint OwnerControlAuthorizationReplayTimeoutSeconds { get; set; } = 20;
    public uint OwnerControlResponseWriteTimeoutSeconds { get; set; } = 30;
    public uint OwnerControlDeliveryCleanupTimeoutSeconds { get; set; } = 5;
    public bool UseDevelopmentInMemoryState { get; set; }
    public string InternalAdminAuthenticationType { get; set; } = "Certificate";
    public string InternalAdminClientCertificateSha256 { get; set; } = "";
}

public sealed record ProductionMailboxOwnerControlStoreLimits(
    int MaximumEntriesPerRoute = 1024,
    int MaximumEntriesGlobal = 1_000_000,
    long MaximumStateBytes = 512L * 1024 * 1024,
    int MaximumGcBatch = 256,
    uint StatementTimeoutSeconds = 5,
    uint LockTimeoutSeconds = 2,
    uint IdleTransactionTimeoutSeconds = 5,
    int MaximumDeliveryLeasesGlobal = 16,
    int MaximumDeliveryLeasesPerOwner = 2,
    int MaximumDeliveryLeasesPerRoute = 1,
    long MaximumDeliveryLeaseBytes = 64L * 1024 * 1024)
{
    internal void Validate()
    {
        if (MaximumEntriesPerRoute is < 4 or > 1_000_000
            || MaximumEntriesGlobal < MaximumEntriesPerRoute
            || MaximumEntriesGlobal > 10_000_000
            || MaximumStateBytes is < 1_048_576 or > 16L * 1024 * 1024 * 1024
            || MaximumGcBatch is < 1 or > 4096
            || StatementTimeoutSeconds is < 1 or > 30
            || LockTimeoutSeconds is < 1 or > 30
            || IdleTransactionTimeoutSeconds is < 1 or > 30)
            throw new InvalidOperationException("Owner-control durable limits are invalid.");
        if (MaximumDeliveryLeasesGlobal is < 1 or > 4096 ||
            MaximumDeliveryLeasesPerOwner < 1 ||
            MaximumDeliveryLeasesPerOwner > MaximumDeliveryLeasesGlobal ||
            MaximumDeliveryLeasesPerRoute < 1 ||
            MaximumDeliveryLeasesPerRoute > MaximumDeliveryLeasesPerOwner ||
            MaximumDeliveryLeaseBytes <
                ProductionMailboxOwnerControlConstants.ResponseHeaderLength +
                ProductionMailboxProtectedHistoryResponseReference.MinimumPayloadLength ||
            MaximumDeliveryLeaseBytes > 4L * 1024 * 1024 * 1024)
            throw new InvalidOperationException("Owner-control durable limits are invalid.");
    }
}

public static class ProductionMailboxMediaTypes
{
    public const string Authority = "application/vnd.deep.production-mailbox-authority";
    public const string Revocation = "application/vnd.deep.production-mailbox-revocation-snapshot";
    public const string Topology = "application/vnd.deep.production-mailbox-topology";
    public const string Selection = "application/vnd.deep.production-mailbox-selection";
    public const string Grant = "application/vnd.deep.mailbox-authenticated-grant";
    public const string RouteCertificate = "application/vnd.deep.production-mailbox-route-certificate";
    public const string RouteAdvertisement = "application/vnd.deep.production-mailbox-route-advertisement";
    public const string SelectionSuccessor = "application/vnd.deep.production-mailbox-selection-successor";
    public const string OwnerEnrollmentRequest =
        "application/vnd.deep.production-mailbox-owner-enrollment";
    public const string OwnerEnrollmentResponse =
        "application/vnd.deep.production-mailbox-owner-enrollment-response";
    public const string OwnerControlRequest =
        "application/vnd.deep.production-mailbox-owner-control-request";
    public const string OwnerControlResponse =
        "application/vnd.deep.production-mailbox-owner-control-response";
    public const string OwnerRevocationRequest =
        "application/vnd.deep.production-mailbox-owner-revocation";
}
