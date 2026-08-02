using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxAuthority;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.MailboxTopology;
using Microsoft.Extensions.Options;

namespace Deep.Registry.Api.ProductionMailbox;

public sealed class ProductionMailboxArtifacts
{
    private const int MaximumAuthorityBytes = 64 * 1024;
    private readonly string proofDirectory;

    private ProductionMailboxArtifacts(
        byte[] authorityBytes,
        byte[] revocationBytes,
        byte[] topologyBytes,
        VerifiedProductionMailboxAuthority authority,
        VerifiedProductionMailboxRevocationSnapshot revocation,
        VerifiedProductionMailboxTopology topology,
        string proofDirectory)
    {
        AuthorityBytes = authorityBytes;
        RevocationBytes = revocationBytes;
        TopologyBytes = topologyBytes;
        Authority = authority;
        Revocation = revocation;
        Topology = topology;
        AuthoritySha256 = SHA256.HashData(authorityBytes);
        RevocationSha256 = SHA256.HashData(revocationBytes);
        TopologySha256 = SHA256.HashData(topologyBytes);
        this.proofDirectory = Path.GetFullPath(proofDirectory);
    }

    public byte[] AuthorityBytes { get; }
    public byte[] RevocationBytes { get; }
    public byte[] TopologyBytes { get; }
    public byte[] AuthoritySha256 { get; }
    public byte[] RevocationSha256 { get; }
    public byte[] TopologySha256 { get; }
    public VerifiedProductionMailboxAuthority Authority { get; }
    public VerifiedProductionMailboxRevocationSnapshot Revocation { get; }
    public VerifiedProductionMailboxTopology Topology { get; }

    public static ProductionMailboxArtifacts Load(
        ProductionMailboxOptions options,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(timeProvider);
        if (!options.Enabled)
            throw new InvalidOperationException("Production mailbox artifacts are disabled.");
        var now = checked((ulong)timeProvider.GetUtcNow().ToUnixTimeSeconds());
        var authorityBytes = ReadExact(options.AuthorityPath, MaximumAuthorityBytes);
        var authorityModel = ProductionMailboxAuthorityCodec.Decode(authorityBytes);
        var authority = ProductionMailboxAuthorityVerifier.Verify(
            authorityModel,
            new ProductionMailboxAuthorityVerificationContext
            {
                PinnedMrXPublicKeySha256 = Hex(options.PinnedMrXPublicKeySha256, 32, false),
                ExpectedNetworkId = Hex(options.ExpectedNetworkId, 16, false),
                LastCommittedGeneration = options.PreviousAuthorityGeneration,
                LastCommittedAuthorityHash = Hex(options.PreviousAuthorityHash, 32, false),
                LastCommittedRevocationGeneration = options.PreviousRevocationGeneration,
                LastCommittedRevocationHeadHash = Hex(options.PreviousRevocationHeadHash, 32, false),
                LastCommittedRevocationSnapshotHash = Hex(options.PreviousRevocationSnapshotHash, 32, false),
                NowUnixSeconds = now,
                ClockSkewSeconds = options.ClockSkewSeconds
            },
            new SodiumProductionMailboxAuthoritySignatureVerifier());

        var revocationBytes = ReadExact(options.RevocationPath, 1024 * 1024);
        var revocation = ProductionMailboxRevocationSnapshotVerifier.Verify(
            revocationBytes, authority, now, options.ClockSkewSeconds,
            new SodiumProductionMailboxRevocationSnapshotSignatureVerifier());

        var topologyBytes = ReadExact(options.TopologyPath,
            ProductionMailboxTopologyConstants.MaximumTopologyArtifactBytes);
        var topology = ProductionMailboxTopologyVerifier.Verify(
            topologyBytes, authority,
            new ProductionMailboxTopologyVerificationContext
            {
                LastCommittedTopologyGeneration = options.PreviousTopologyGeneration,
                LastCommittedTopologyHash = Hex(options.PreviousTopologyHash, 32, true),
                NowUnixSeconds = now,
                ClockSkewSeconds = options.ClockSkewSeconds
            },
            new SodiumProductionMailboxTopologySignatureVerifier());
        if (!Directory.Exists(options.MembershipProofDirectory))
            throw new InvalidOperationException("Production mailbox MIP1 directory is missing.");
        return new ProductionMailboxArtifacts(
            authorityBytes, revocationBytes, topologyBytes,
            authority, revocation, topology, options.MembershipProofDirectory);
    }

    public byte[] ReadMembershipProof(ulong epoch, ReadOnlySpan<byte> replicaId)
    {
        if (replicaId.Length != 32) throw new ArgumentException("Replica ID is invalid.");
        var fileName = $"{epoch}-{Convert.ToHexStringLower(replicaId)}.mip1";
        var path = Path.GetFullPath(Path.Combine(proofDirectory, fileName));
        if (!path.StartsWith(proofDirectory + Path.DirectorySeparatorChar, StringComparison.Ordinal))
            throw new InvalidOperationException("MIP1 path escaped its protected directory.");
        var bytes = ReadExact(path,
            MailboxPeerReplicationLimits.MembershipProofFixedLength +
            MailboxPeerReplicationLimits.MaximumInclusionProofLength);
        var decoded = MailboxPeerReplicationCodec.DecodeMembershipProof(bytes);
        if (decoded.Epoch != epoch ||
            !CryptographicOperations.FixedTimeEquals(decoded.ReplicaId.Span, replicaId) ||
            !bytes.AsSpan().SequenceEqual(MailboxPeerReplicationCodec.EncodeMembershipProof(decoded)))
            throw new InvalidDataException("Configured MIP1 does not match its epoch/replica filename.");
        return bytes;
    }

    internal static byte[] Hex(string value, int bytes, bool allowZero)
    {
        if (value.Length != bytes * 2 || value.Any(static c => c is not (>= '0' and <= '9') and not (>= 'a' and <= 'f')))
            throw new InvalidOperationException("Production mailbox hexadecimal configuration is not canonical lowercase.");
        var result = Convert.FromHexString(value);
        if (!allowZero && result.AsSpan().IndexOfAnyExcept((byte)0) < 0)
            throw new InvalidOperationException("Production mailbox hexadecimal configuration must be non-zero.");
        return result;
    }

    private static byte[] ReadExact(string configuredPath, int maximumBytes)
    {
        if (string.IsNullOrWhiteSpace(configuredPath))
            throw new InvalidOperationException("Production mailbox artifact path is missing.");
        var path = Path.GetFullPath(configuredPath);
        var info = new FileInfo(path);
        if (!info.Exists || info.Length <= 0 || info.Length > maximumBytes ||
            info.Attributes.HasFlag(FileAttributes.ReparsePoint))
            throw new InvalidOperationException("Production mailbox artifact is missing, linked, empty or oversized.");
        var bytes = File.ReadAllBytes(path);
        if (bytes.Length != info.Length)
            throw new IOException("Production mailbox artifact changed while being read.");
        return bytes;
    }
}

public sealed class ProductionMailboxArtifactsStartupValidator(
    ProductionMailboxArtifactProvider provider) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        _ = provider.Current;
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}

public sealed class ProductionMailboxArtifactProvider
{
    private readonly object gate = new();
    private readonly ProductionMailboxOptions baseline;
    private ProductionMailboxArtifacts current;
    private ArtifactCatalogEntry[] catalog;

    public ProductionMailboxArtifactProvider(ProductionMailboxOptions options, TimeProvider timeProvider)
    {
        baseline = options;
        if (options.MaximumRetainedArtifactClosures is < 1 or > 64)
            throw new InvalidOperationException("Retained production mailbox artifact closure bound is invalid.");
        current = ProductionMailboxArtifacts.Load(options, timeProvider);
        catalog = [Entry(current)];
    }

    public ProductionMailboxArtifacts Current => Volatile.Read(ref current);

    public bool TryGetArtifact(
        string sha256,
        string fileName,
        out byte[] bytes,
        out string mediaType)
    {
        bytes = [];
        mediaType = "";
        if (sha256.Length != 64 || sha256.Any(static value => value is not (>= '0' and <= '9') and not (>= 'a' and <= 'f')))
            return false;
        foreach (var entry in Volatile.Read(ref catalog))
        {
            var snapshot = entry.Artifacts;
            if (fileName == "authority.pma1" &&
                sha256 == Convert.ToHexStringLower(snapshot.AuthoritySha256))
            {
                bytes = snapshot.AuthorityBytes;
                mediaType = ProductionMailboxMediaTypes.Authority;
                return true;
            }
            if (fileName == "revocations.pmr1" &&
                sha256 == Convert.ToHexStringLower(snapshot.RevocationSha256))
            {
                bytes = snapshot.RevocationBytes;
                mediaType = ProductionMailboxMediaTypes.Revocation;
                return true;
            }
            if (fileName == "topology.pmt1" &&
                sha256 == Convert.ToHexStringLower(snapshot.TopologySha256))
            {
                bytes = snapshot.TopologyBytes;
                mediaType = ProductionMailboxMediaTypes.Topology;
                return true;
            }
        }
        return false;
    }

    public ProductionMailboxArtifacts Reload(TimeProvider timeProvider)
    {
        lock (gate)
        {
            var previous = current;
            var authority = previous.Authority.Authority;
            var revocation = previous.Revocation.Snapshot;
            var options = new ProductionMailboxOptions
            {
                Enabled = true,
                AuthorityPath = baseline.AuthorityPath,
                RevocationPath = baseline.RevocationPath,
                TopologyPath = baseline.TopologyPath,
                MembershipProofDirectory = baseline.MembershipProofDirectory,
                PinnedMrXPublicKeySha256 = baseline.PinnedMrXPublicKeySha256,
                ExpectedNetworkId = baseline.ExpectedNetworkId,
                PreviousAuthorityGeneration = authority.AuthorityGeneration,
                PreviousAuthorityHash = Convert.ToHexStringLower(previous.Authority.CanonicalAuthorityHash.Span),
                PreviousRevocationGeneration = revocation.RevocationGeneration,
                PreviousRevocationHeadHash = Convert.ToHexStringLower(revocation.RevocationHeadHash.Span),
                PreviousRevocationSnapshotHash = Convert.ToHexStringLower(previous.Revocation.CanonicalSnapshotHash.Span),
                PreviousTopologyGeneration = previous.Topology.CommittedTopologyGeneration,
                PreviousTopologyHash = Convert.ToHexStringLower(previous.Topology.CanonicalTopologyHash.Span),
                ClockSkewSeconds = baseline.ClockSkewSeconds
            };
            var replacement = ProductionMailboxArtifacts.Load(options, timeProvider);
            if (replacement.Authority.Authority.AuthorityGeneration < previous.Authority.Authority.AuthorityGeneration ||
                replacement.Topology.CommittedTopologyGeneration < previous.Topology.CommittedTopologyGeneration)
                throw new InvalidOperationException("Production mailbox artifact reload would roll back committed state.");
            PublishVerifiedUnderLock(replacement,
                checked((ulong)timeProvider.GetUtcNow().ToUnixTimeSeconds()));
            return replacement;
        }
    }

    internal void PublishVerified(ProductionMailboxArtifacts replacement, ulong nowUnixSeconds)
    {
        ArgumentNullException.ThrowIfNull(replacement);
        lock (gate) PublishVerifiedUnderLock(replacement, nowUnixSeconds);
    }

    private void PublishVerifiedUnderLock(
        ProductionMailboxArtifacts replacement,
        ulong nowUnixSeconds)
    {
        var retained = Volatile.Read(ref catalog)
            .Where(entry => entry.RetainUntilUnixSeconds >= nowUnixSeconds)
            .ToList();
        var duplicate = retained.Any(entry =>
            entry.Artifacts.AuthoritySha256.AsSpan().SequenceEqual(replacement.AuthoritySha256) &&
            entry.Artifacts.RevocationSha256.AsSpan().SequenceEqual(replacement.RevocationSha256) &&
            entry.Artifacts.TopologySha256.AsSpan().SequenceEqual(replacement.TopologySha256));
        if (!duplicate)
        {
            if (retained.Count >= baseline.MaximumRetainedArtifactClosures)
                throw new InvalidOperationException(
                    "Retained production mailbox artifact catalog is at its configured bound.");
            retained.Add(Entry(replacement));
        }
        Volatile.Write(ref catalog, retained.ToArray());
        Volatile.Write(ref current, replacement);
    }

    private ArtifactCatalogEntry Entry(ProductionMailboxArtifacts artifacts)
    {
        var expires = artifacts.Topology.Snapshot.CurrentEpoch.NotAfterUnixSeconds;
        var retainUntil = ulong.MaxValue - expires < baseline.ClockSkewSeconds
            ? ulong.MaxValue
            : expires + baseline.ClockSkewSeconds;
        return new(artifacts, retainUntil);
    }

    private sealed record ArtifactCatalogEntry(
        ProductionMailboxArtifacts Artifacts,
        ulong RetainUntilUnixSeconds);
}
