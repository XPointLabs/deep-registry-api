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
    public uint ChallengeWindowSeconds { get; set; } = 60;
    public string ExternalSignerSocketPath { get; set; } = "";
    public uint ExternalSignerTimeoutSeconds { get; set; } = 5;
    public string ClosurePublisherSignerSocketPath { get; set; } = "";
    public uint ClosurePublisherSignerTimeoutSeconds { get; set; } = 5;
    public string ClosurePublisherEd25519PublicKey { get; set; } = "";
    public int MaximumRetainedArtifactClosures { get; set; } = 16;
    public string ArtifactCatalogDirectory { get; set; } = "";
    public string DevelopmentSoftwareSignerSeedPath { get; set; } = "";
    public string DevelopmentClosurePublisherSeedPath { get; set; } = "";
    public string PostgreSqlConnectionString { get; set; } = "";
    public string RouteStateHmacKeyPath { get; set; } = "";
    public bool UseDevelopmentInMemoryState { get; set; }
    public string InternalAdminAuthenticationType { get; set; } = "Certificate";
    public string InternalAdminClientCertificateSha256 { get; set; } = "";
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
}
