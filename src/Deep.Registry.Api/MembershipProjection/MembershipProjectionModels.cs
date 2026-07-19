using Deep.Protocol.DeepExtension.Membership;

namespace Deep.Registry.Api;

public sealed record MembershipProjectionOptions
{
    public bool Enabled { get; init; }
    public string ContractIdentifier { get; init; } = MembershipContractVersion.Identifier;
    public string PackageVersion { get; init; } = "0.3.0-p04.b887fa0";
    public string? StatePath { get; init; }
    public string ExpectedNetworkIdHex { get; init; } = "";
    public string ExpectedGenesisSha256Hex { get; init; } = "";
    public int MaximumArtifactBytes { get; init; } = 128 * 1024;
    public int MaximumStateBytes { get; init; } = 512 * 1024;
    public uint AllowedClockSkewSeconds { get; init; } = 30;
    public ushort ClientProtocol { get; init; } = 2;
    public bool FixtureSourceWorkerEnabled { get; init; }
}

public enum MembershipProjectionCode
{
    Accepted,
    Idempotent,
    Disabled,
    VerifierUnavailable,
    MonotonicAnchorUnavailable,
    MonotonicAnchorTransient,
    MonotonicConflict,
    ContinuityBusy,
    StateUnavailable,
    InvalidLength,
    InvalidArtifact,
    InvalidSignature,
    InvalidSigner,
    WrongNetwork,
    WrongPolicy,
    WrongProtocol,
    Rollback,
    SequenceGap,
    SequenceOverflow,
    ForkDetected,
    Expired,
    NotYetValid,
    ClockSkew,
    TimestampOutOfRange,
    RevokedDelegation,
    PersistenceFailure,
    CorruptState,
    SourceFailure
}

public sealed record MembershipProjectionApplyResult(
    bool Success,
    MembershipProjectionCode Code)
{
    public static MembershipProjectionApplyResult Accepted() =>
        new(true, MembershipProjectionCode.Accepted);

    public static MembershipProjectionApplyResult Idempotent() =>
        new(true, MembershipProjectionCode.Idempotent);

    public static MembershipProjectionApplyResult Rejected(MembershipProjectionCode code) =>
        new(false, code);
}

public sealed record MembershipProjectionCounters(
    long Accepted,
    long Idempotent,
    long VerifierUnavailable,
    long InvalidArtifact,
    long InvalidSigner,
    long Rollback,
    long SequenceGap,
    long Fork,
    long Expired,
    long ClockSkew,
    long CorruptStateRecoveries,
    long PersistenceFailures,
    long SourceFailures,
    long MonotonicAnchorTransient,
    long ContinuityBusy,
    long MonotonicConflicts);

public sealed record MembershipProjectionStatus(
    bool Enabled,
    bool Ready,
    bool VerifierAvailable,
    string State,
    ulong? BridgeSequence,
    string? BridgeSha256,
    DateTimeOffset? BridgeValidUntil,
    MembershipProjectionCounters Counters);

public sealed record MembershipProjectionBridgeArtifact(
    byte[] Bytes,
    string Sha256,
    DateTimeOffset ValidUntil);

public interface IMembershipArtifactSource
{
    Task PollAsync(MembershipProjectionService service, CancellationToken cancellationToken);
}
