using System.Security.Cryptography;
using System.Buffers.Binary;
using System.Text;
using System.Text.Json;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using Deep.Protocol.DeepExtension.MailboxAuthority;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.MailboxTopology;
using Deep.Protocol.DeepExtension.MembershipRoutes;
using Microsoft.Extensions.Options;

namespace Deep.Registry.Api.ProductionMailbox;

public sealed class ProductionMailboxArtifacts
{
    private const int MaximumAuthorityBytes = 64 * 1024;
    private readonly string proofDirectory;
    private readonly byte[] authorityBytes;
    private readonly byte[] revocationBytes;
    private readonly byte[] topologyBytes;
    private readonly byte[] authoritySha256;
    private readonly byte[] revocationSha256;
    private readonly byte[] topologySha256;

    private ProductionMailboxArtifacts(
        byte[] authorityBytes,
        byte[] revocationBytes,
        byte[] topologyBytes,
        VerifiedProductionMailboxAuthority authority,
        VerifiedProductionMailboxRevocationSnapshot revocation,
        VerifiedProductionMailboxTopology topology,
        string proofDirectory)
    {
        this.authorityBytes = authorityBytes.ToArray();
        this.revocationBytes = revocationBytes.ToArray();
        this.topologyBytes = topologyBytes.ToArray();
        Authority = authority;
        Revocation = revocation;
        Topology = topology;
        authoritySha256 = SHA256.HashData(this.authorityBytes);
        revocationSha256 = SHA256.HashData(this.revocationBytes);
        topologySha256 = SHA256.HashData(this.topologyBytes);
        this.proofDirectory = Path.GetFullPath(proofDirectory);
    }

    public byte[] AuthorityBytes => authorityBytes.ToArray();
    public byte[] RevocationBytes => revocationBytes.ToArray();
    public byte[] TopologyBytes => topologyBytes.ToArray();
    public byte[] AuthoritySha256 => authoritySha256.ToArray();
    public byte[] RevocationSha256 => revocationSha256.ToArray();
    public byte[] TopologySha256 => topologySha256.ToArray();
    internal VerifiedProductionMailboxAuthority Authority { get; }
    internal VerifiedProductionMailboxRevocationSnapshot Revocation { get; }
    internal VerifiedProductionMailboxTopology Topology { get; }

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

    internal byte[] ReadMembershipProof(ulong epoch, ReadOnlySpan<byte> replicaId)
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
        var topologyEpoch = epoch == Topology.Snapshot.CurrentEpoch.Epoch
            ? Topology.Snapshot.CurrentEpoch
            : epoch == Topology.Snapshot.NextEpoch.Epoch
                ? Topology.Snapshot.NextEpoch
                : throw new InvalidDataException(
                    "Configured MIP1 epoch is outside the verified topology.");
        ValidateMembershipProof(bytes, decoded, topologyEpoch, replicaId);
        return bytes;
    }

    private static void ValidateMembershipProof(
        ReadOnlySpan<byte> canonicalBytes,
        MailboxReplicaMembershipProof proof,
        ProductionMailboxTopologyEpoch epoch,
        ReadOnlySpan<byte> replicaId)
    {
        if (proof.Epoch != epoch.Epoch
            || !CryptographicOperations.FixedTimeEquals(proof.ReplicaId.Span, replicaId)
            || !CryptographicOperations.FixedTimeEquals(
                proof.MembershipCommitment.Span, epoch.MembershipCommitment.Span)
            || !canonicalBytes.SequenceEqual(
                MailboxPeerReplicationCodec.EncodeMembershipProof(proof)))
            throw new InvalidDataException(
                "Configured MIP1 does not match its topology epoch and replica.");
        var decoded = MailboxReplicaRouteProofCodec.Decode(
            proof.CanonicalInclusionProof.Span);
        if (decoded.Descriptor.Epoch != epoch.Epoch
            || decoded.Descriptor.ValidFromUnixSeconds > epoch.NotBeforeUnixSeconds
            || decoded.Descriptor.ValidUntilUnixSeconds < epoch.NotAfterUnixSeconds
            || !decoded.Descriptor.Roles.HasFlag(MembershipRouteRole.Storage)
            || !decoded.Descriptor.Capabilities.HasFlag(MembershipRouteCapability.Storage)
            || !CryptographicOperations.FixedTimeEquals(
                decoded.Descriptor.RouterId.Span, replicaId)
            || !CryptographicOperations.FixedTimeEquals(
                decoded.Descriptor.Ed25519PublicKey.Span, proof.SigningPublicKey.Span)
            || !MembershipRouteDescriptorCodec.VerifyInclusion(
                decoded.Descriptor, decoded.Proof, epoch.MembershipCommitment.Span))
            throw new InvalidDataException(
                "Configured MIP1 does not prove the topology storage replica.");
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
        return ProductionMailboxProtectedFile.ReadStable(
            path, maximumBytes, exactLength: null,
            () => ProductionMailboxArtifactProvider.EnsureNoReparseAncestors(path));
    }
}

public sealed class ProductionMailboxArtifactsStartupValidator(
    ProductionMailboxArtifactProvider provider,
    IProductionMailboxStateStore state) : IHostedService
{
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        var currentHash = ProductionMailboxArtifactProvider.ComputeArtifactClosureHash(
            provider.Current);
        var publishedHash = await state.GetOrInitializePublishedArtifactClosureAsync(
            currentHash, cancellationToken);
        if (CryptographicOperations.FixedTimeEquals(publishedHash, currentHash)) return;
        var promotion = await state.GetActiveArtifactPromotionAsync(cancellationToken);
        if (promotion is null || !promotion.SweepCompleted
            || !CryptographicOperations.FixedTimeEquals(
                promotion.OldArtifactClosureHash, publishedHash)
            || !CryptographicOperations.FixedTimeEquals(
                promotion.NewArtifactClosureHash, currentHash)
            || !await state.MarkArtifactPromotionPublishedAsync(
                promotion.PromotionStateKey, cancellationToken))
            throw new InvalidDataException(
                "Active production mailbox artifact pointer conflicts with durable published state.");
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}

public sealed class ProductionMailboxArtifactProvider
{
    private static readonly JsonSerializerOptions CatalogJson = new(JsonSerializerDefaults.Web);
    private readonly object gate = new();
    private readonly ProductionMailboxOptions baseline;
    private readonly TimeProvider timeProvider;
    private readonly string catalogDirectory;
    private readonly string activePointerPath;
    private readonly byte[] catalogIntegrityKey;
    private ProductionMailboxArtifacts current;
    private ArtifactCatalogEntry[] catalog;
    internal Action<string>? CatalogMutationFaultForTests { get; set; }

    public ProductionMailboxArtifactProvider(ProductionMailboxOptions options, TimeProvider timeProvider)
    {
        baseline = options;
        this.timeProvider = timeProvider;
        catalogIntegrityKey = ReadExactFile(options.RouteStateHmacKeyPath, 32);
        if (options.MaximumRetainedArtifactClosures is < 1 or > 64)
            throw new InvalidOperationException("Retained production mailbox artifact closure bound is invalid.");
        catalogDirectory = ResolveCatalogDirectory(options);
        Directory.CreateDirectory(catalogDirectory);
        EnsureNoReparseAncestors(catalogDirectory);
        activePointerPath = Path.Combine(catalogDirectory, "active.pmac1");
        var activeId = File.Exists(activePointerPath)
            ? ReadActivePointer()
            : null;
        CleanupCatalogDebris(activeId);
        if (activeId is not null)
        {
            current = LoadPersisted(activeId);
        }
        else
        {
            current = ProductionMailboxArtifacts.Load(options, timeProvider);
            var bootstrapId = Persist(current, VerificationContext.FromBaseline(options));
            WriteActivePointer(bootstrapId);
        }
        PruneExpiredCatalogUnderLock(
            checked((ulong)timeProvider.GetUtcNow().ToUnixTimeSeconds()),
            ClosureId(current));
        catalog = LoadRetainedCatalog(current);
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

    public ProductionMailboxArtifacts LoadVerifiedSuccessor(TimeProvider timeProvider)
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
            _ = Persist(replacement, VerificationContext.FromPrevious(previous));
            return replacement;
        }
    }

    internal void StageVerifiedSuccessor(ProductionMailboxArtifacts replacement)
    {
        ArgumentNullException.ThrowIfNull(replacement);
        lock (gate)
            _ = Persist(replacement, VerificationContext.FromPrevious(current));
    }

    internal void PruneExpiredForTests(ulong nowUnixSeconds)
    {
        lock (gate)
            PruneExpiredCatalogUnderLock(nowUnixSeconds, ClosureId(current));
    }

    internal ProductionMailboxArtifacts LoadStaged(ReadOnlySpan<byte> closureId)
    {
        lock (gate) return LoadPersisted(closureId);
    }

    internal ProductionMailboxArtifacts LoadStagedByArtifactClosureHash(
        ReadOnlySpan<byte> artifactClosureHash)
    {
        if (artifactClosureHash.Length != 32)
            throw new InvalidDataException(
                "Staged production mailbox artifact closure hash is invalid.");
        lock (gate)
        {
            ProductionMailboxArtifacts? match = null;
            var manifests = Directory.EnumerateFiles(
                    catalogDirectory, "*.pmac1.json", SearchOption.TopDirectoryOnly)
                .Take(baseline.MaximumRetainedArtifactClosures + 1).ToArray();
            if (manifests.Length > baseline.MaximumRetainedArtifactClosures)
                throw new InvalidDataException(
                    "Persisted production mailbox artifact catalog exceeds its configured bound.");
            foreach (var manifestPath in manifests)
            {
                var candidate = LoadPersisted(Convert.FromHexString(
                    ManifestId(manifestPath)));
                if (!CryptographicOperations.FixedTimeEquals(
                        ArtifactClosureHash(candidate), artifactClosureHash))
                    continue;
                if (match is not null && !SameClosure(match, candidate))
                    throw new InvalidDataException(
                        "Staged production mailbox artifact closure hash is ambiguous.");
                match = candidate;
            }
            return match ?? throw new InvalidDataException(
                "Staged production mailbox artifact closure is unavailable.");
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
        var closureId = Persist(replacement, VerificationContext.FromPrevious(current));
        WriteActivePointer(closureId);
        Volatile.Write(ref catalog, retained.ToArray());
        Volatile.Write(ref current, replacement);
    }

    private ArtifactCatalogEntry[] LoadRetainedCatalog(ProductionMailboxArtifacts active)
    {
        var now = checked((ulong)timeProvider.GetUtcNow().ToUnixTimeSeconds());
        var entries = new List<ArtifactCatalogEntry> { Entry(active) };
        var activeId = Convert.ToHexStringLower(ClosureId(active));
        var manifests = Directory.EnumerateFiles(catalogDirectory, "*.pmac1.json",
                SearchOption.TopDirectoryOnly)
            .Take(baseline.MaximumRetainedArtifactClosures + 1).ToArray();
        if (manifests.Length > baseline.MaximumRetainedArtifactClosures)
            throw new InvalidOperationException(
                "Persisted production mailbox artifact catalog exceeds its configured bound.");
        foreach (var manifestPath in manifests)
        {
            var id = ManifestId(manifestPath);
            try
            {
                var manifest = ReadManifest(manifestPath);
                if (manifest.RetainUntilUnixSeconds < now) continue;
                var snapshot = LoadPersisted(Convert.FromHexString(id));
                if (entries.Any(entry => SameClosure(entry.Artifacts, snapshot))) continue;
                entries.Add(Entry(snapshot));
            }
            catch (Exception exception) when (id != activeId && exception is
                       InvalidDataException or InvalidOperationException or IOException
                       or CryptographicException or FormatException
                       or ProductionMailboxAuthorityException
                       or ProductionMailboxRevocationSnapshotException
                       or ProductionMailboxTopologyException
                       or MailboxPeerReplicationException
                       or MembershipRouteDescriptorException)
            {
                DeleteCatalogClosure(id, manifestPath);
            }
        }
        if (entries.Count > baseline.MaximumRetainedArtifactClosures)
            throw new InvalidOperationException(
                "Persisted production mailbox artifact catalog exceeds its configured bound.");
        return entries.ToArray();
    }

    private byte[] Persist(ProductionMailboxArtifacts snapshot, VerificationContext context)
    {
        var now = checked((ulong)timeProvider.GetUtcNow().ToUnixTimeSeconds());
        var activeId = File.Exists(activePointerPath)
            ? ReadActivePointer()
            : null;
        PruneExpiredCatalogUnderLock(now, activeId);
        var closureId = ClosureId(snapshot);
        var id = Convert.ToHexStringLower(closureId);
        var manifestPath = Path.Combine(catalogDirectory, id + ".pmac1.json");
        var authorityPath = Path.Combine(catalogDirectory, id + ".pma1");
        var revocationPath = Path.Combine(catalogDirectory, id + ".pmr1");
        var topologyPath = Path.Combine(catalogDirectory, id + ".pmt1");
        var proofPath = Path.Combine(catalogDirectory, id + ".mip1");
        var retainUntil = Entry(snapshot).RetainUntilUnixSeconds;
        var proofClosure = FreezeMembershipProofClosure(snapshot);
        var unsignedManifest = new PersistedArtifactManifest(
            "production-mailbox-artifact-catalog.v1", id,
            Convert.ToHexStringLower(snapshot.AuthoritySha256),
            Convert.ToHexStringLower(snapshot.RevocationSha256),
            Convert.ToHexStringLower(snapshot.TopologySha256),
            proofClosure.Files.Count,
            Convert.ToHexStringLower(proofClosure.Sha256), retainUntil,
            context.PreviousAuthorityGeneration, context.PreviousAuthorityHash,
            context.PreviousRevocationGeneration, context.PreviousRevocationHeadHash,
            context.PreviousRevocationSnapshotHash, context.PreviousTopologyGeneration,
            context.PreviousTopologyHash, "");
        var manifest = unsignedManifest with
        {
            IntegrityTag = Convert.ToHexStringLower(ComputeCatalogHmac(
                "Deep/production-mailbox/artifact-catalog-manifest/v1",
                JsonSerializer.SerializeToUtf8Bytes(unsignedManifest, CatalogJson)))
        };
        if (File.Exists(manifestPath))
        {
            var existing = ReadManifest(manifestPath);
            if (existing != manifest)
                throw new InvalidDataException(
                    "Persisted production mailbox artifact manifest conflicts.");
            var persisted = LoadPersisted(closureId);
            if (!SameClosure(persisted, snapshot))
                throw new InvalidDataException(
                    "Persisted production mailbox artifact closure conflicts.");
            return closureId;
        }
        var existingManifests = Directory.EnumerateFiles(
            catalogDirectory, "*.pmac1.json", SearchOption.TopDirectoryOnly).Count();
        if (existingManifests >= baseline.MaximumRetainedArtifactClosures)
            throw new InvalidOperationException(
                "Persisted production mailbox artifact catalog is at its configured bound.");
        WriteAtomic(authorityPath, snapshot.AuthorityBytes);
        WriteAtomic(revocationPath, snapshot.RevocationBytes);
        WriteAtomic(topologyPath, snapshot.TopologyBytes);
        WriteMembershipProofClosure(proofPath, proofClosure);
        WriteAtomic(manifestPath, JsonSerializer.SerializeToUtf8Bytes(manifest, CatalogJson));
        return closureId;
    }

    private void CleanupCatalogDebris(ReadOnlySpan<byte> activeClosureId)
    {
        var activeId = activeClosureId.Length == 32
            ? Convert.ToHexStringLower(activeClosureId)
            : string.Empty;
        var maximumFiles = checked(baseline.MaximumRetainedArtifactClosures * 8 + 16);
        var files = Directory.EnumerateFiles(
                catalogDirectory, "*", SearchOption.TopDirectoryOnly)
            .Take(maximumFiles + 1).ToArray();
        if (files.Length > maximumFiles)
            throw new InvalidDataException(
                "Persisted production mailbox artifact catalog contains too many files.");
        var tombstones = files.Where(static path =>
                path.EndsWith(".pmac1.json.gc", StringComparison.Ordinal))
            .Take(baseline.MaximumRetainedArtifactClosures + 1).ToArray();
        if (tombstones.Length > baseline.MaximumRetainedArtifactClosures)
            throw new InvalidDataException(
                "Persisted production mailbox artifact catalog contains too many tombstones.");
        foreach (var tombstone in tombstones)
        {
            var name = Path.GetFileName(tombstone);
            if (name.Length != 64 + ".pmac1.json.gc".Length
                || name[..64].Any(static value =>
                    value is not (>= '0' and <= '9') and not (>= 'a' and <= 'f'))
                || name[..64] == activeId)
                throw new InvalidDataException(
                    "Persisted production mailbox artifact tombstone is invalid.");
            CompleteCatalogTombstone(name[..64]);
        }
        foreach (var path in files.Where(static path =>
                     path.EndsWith(".tmp", StringComparison.Ordinal)
                     || path.Contains(".tmp.", StringComparison.Ordinal)))
            File.Delete(path);

        var manifestIds = Directory.EnumerateFiles(
                catalogDirectory, "*.pmac1.json", SearchOption.TopDirectoryOnly)
            .Select(ManifestId)
            .ToHashSet(StringComparer.Ordinal);
        foreach (var path in Directory.EnumerateFiles(
                     catalogDirectory, "*", SearchOption.TopDirectoryOnly))
        {
            var name = Path.GetFileName(path);
            if (name == "active.pmac1" || name.EndsWith(".pmac1.json", StringComparison.Ordinal))
                continue;
            var separator = name.LastIndexOf('.');
            if (separator != 64 || !manifestIds.Contains(name[..64])
                || name[(separator + 1)..] is not ("pma1" or "pmr1" or "pmt1"))
                File.Delete(path);
        }
        var proofDirectories = Directory.EnumerateDirectories(
                catalogDirectory, "*.mip1*", SearchOption.TopDirectoryOnly)
            .Take(baseline.MaximumRetainedArtifactClosures + 2).ToArray();
        if (proofDirectories.Length > baseline.MaximumRetainedArtifactClosures + 1)
            throw new InvalidDataException(
                "Persisted production mailbox artifact catalog contains too many proof directories.");
        foreach (var directory in proofDirectories)
        {
            var name = Path.GetFileName(directory);
            if (name.EndsWith(".mip1.gc", StringComparison.Ordinal))
            {
                DeleteMembershipProofDirectory(directory);
                continue;
            }
            if (name.Length != 64 + ".mip1".Length
                || !manifestIds.Contains(name[..64]))
                DeleteMembershipProofDirectory(directory);
        }
        FlushCatalogDirectory();
    }

    private void PruneExpiredCatalogUnderLock(
        ulong nowUnixSeconds, ReadOnlySpan<byte> preservedClosureId)
    {
        var preserved = preservedClosureId.Length == 32
            ? Convert.ToHexStringLower(preservedClosureId)
            : string.Empty;
        var manifests = Directory.EnumerateFiles(
                catalogDirectory, "*.pmac1.json", SearchOption.TopDirectoryOnly)
            .Take(baseline.MaximumRetainedArtifactClosures + 1).ToArray();
        if (manifests.Length > baseline.MaximumRetainedArtifactClosures)
            throw new InvalidDataException(
                "Persisted production mailbox artifact catalog exceeds its configured bound.");
        var removed = false;
        foreach (var path in manifests)
        {
            var id = ManifestId(path);
            if (id == preserved) continue;
            var manifest = ReadManifest(path);
            if (manifest.RetainUntilUnixSeconds >= nowUnixSeconds) continue;
            DeleteCatalogClosure(id, path);
            removed = true;
        }
        if (removed) FlushCatalogDirectory();
    }

    private void DeleteCatalogClosure(string id, string manifestPath)
    {
        var manifestTombstone = manifestPath + ".gc";
        if (File.Exists(manifestPath))
            MoveCatalogEntryDurable(manifestPath, manifestTombstone);
        CatalogMutationFaultForTests?.Invoke("after-manifest-tombstone");
        CompleteCatalogTombstone(id);
    }

    private void CompleteCatalogTombstone(string id)
    {
        foreach (var extension in new[] { ".pma1", ".pmr1", ".pmt1" })
        {
            var path = Path.Combine(catalogDirectory, id + extension);
            var tombstone = path + ".gc";
            if (File.Exists(path)) MoveCatalogEntryDurable(path, tombstone);
            CatalogMutationFaultForTests?.Invoke("after-artifact-tombstone");
            if (File.Exists(tombstone)) File.Delete(tombstone);
        }
        var proofDirectory = Path.Combine(catalogDirectory, id + ".mip1");
        var proofTombstone = proofDirectory + ".gc";
        if (Directory.Exists(proofDirectory))
            MoveCatalogEntryDurable(proofDirectory, proofTombstone);
        CatalogMutationFaultForTests?.Invoke("after-proof-tombstone");
        DeleteMembershipProofDirectory(proofTombstone);
        var manifestTombstone = Path.Combine(
            catalogDirectory, id + ".pmac1.json.gc");
        CatalogMutationFaultForTests?.Invoke("before-manifest-tombstone-delete");
        if (File.Exists(manifestTombstone)) File.Delete(manifestTombstone);
        FlushCatalogDirectory();
    }

    private void MoveCatalogEntryDurable(string source, string tombstone)
    {
        if (File.Exists(tombstone) || Directory.Exists(tombstone))
            throw new InvalidDataException(
                "Production mailbox artifact tombstone already exists.");
        if (OperatingSystem.IsWindows() || File.Exists(source))
        {
            ReplaceAtomicDurable(source, tombstone);
            return;
        }
        Directory.Move(source, tombstone);
        FlushCatalogDirectory();
    }

    private void FlushCatalogDirectory()
    {
        if (OperatingSystem.IsWindows()) return;
        var descriptor = Open(catalogDirectory, 0);
        if (descriptor < 0) throw new Win32Exception(Marshal.GetLastPInvokeError());
        try
        {
            if (Fsync(descriptor) != 0)
                throw new Win32Exception(Marshal.GetLastPInvokeError());
        }
        finally { _ = Close(descriptor); }
    }

    private static void FlushDirectory(string directory)
    {
        if (OperatingSystem.IsWindows()) return;
        var descriptor = Open(directory, 0);
        if (descriptor < 0) throw new Win32Exception(Marshal.GetLastPInvokeError());
        try
        {
            if (Fsync(descriptor) != 0)
                throw new Win32Exception(Marshal.GetLastPInvokeError());
        }
        finally { _ = Close(descriptor); }
    }

    private static void DeleteMembershipProofDirectory(string directory)
    {
        if (!Directory.Exists(directory)) return;
        EnsureNoReparseAncestors(directory);
        var nested = Directory.EnumerateDirectories(
            directory, "*", SearchOption.TopDirectoryOnly).Take(1).Any();
        var files = Directory.EnumerateFiles(directory, "*", SearchOption.TopDirectoryOnly)
            .Take(ProductionMailboxTopologyConstants.MaximumNodesPerEpoch * 2 + 1)
            .ToArray();
        if (nested
            || files.Length > ProductionMailboxTopologyConstants.MaximumNodesPerEpoch * 2
            || files.Any(static path =>
                File.GetAttributes(path).HasFlag(FileAttributes.ReparsePoint)))
            throw new InvalidDataException(
                "Production mailbox membership proof directory is unsafe or oversized.");
        Directory.Delete(directory, recursive: true);
    }

    private static string ManifestId(string path)
    {
        var name = Path.GetFileName(path);
        if (name.Length != 64 + ".pmac1.json".Length
            || !name.EndsWith(".pmac1.json", StringComparison.Ordinal)
            || name[..64].Any(static value =>
                value is not (>= '0' and <= '9') and not (>= 'a' and <= 'f')))
            throw new InvalidDataException(
                "Persisted production mailbox artifact manifest name is invalid.");
        return name[..64];
    }

    private ProductionMailboxArtifacts LoadPersisted(ReadOnlySpan<byte> closureId)
    {
        if (closureId.Length != 32)
            throw new InvalidDataException("Persisted production mailbox artifact pointer is invalid.");
        var id = Convert.ToHexStringLower(closureId);
        var manifest = ReadManifest(Path.Combine(catalogDirectory, id + ".pmac1.json"));
        if (manifest.Schema != "production-mailbox-artifact-catalog.v1"
            || manifest.ClosureId != id)
            throw new InvalidDataException("Persisted production mailbox artifact manifest is invalid.");
        var options = new ProductionMailboxOptions
        {
            Enabled = true,
            AuthorityPath = Path.Combine(catalogDirectory, id + ".pma1"),
            RevocationPath = Path.Combine(catalogDirectory, id + ".pmr1"),
            TopologyPath = Path.Combine(catalogDirectory, id + ".pmt1"),
            MembershipProofDirectory = Path.Combine(catalogDirectory, id + ".mip1"),
            PinnedMrXPublicKeySha256 = baseline.PinnedMrXPublicKeySha256,
            ExpectedNetworkId = baseline.ExpectedNetworkId,
            PreviousAuthorityGeneration = manifest.PreviousAuthorityGeneration,
            PreviousAuthorityHash = manifest.PreviousAuthorityHash,
            PreviousRevocationGeneration = manifest.PreviousRevocationGeneration,
            PreviousRevocationHeadHash = manifest.PreviousRevocationHeadHash,
            PreviousRevocationSnapshotHash = manifest.PreviousRevocationSnapshotHash,
            PreviousTopologyGeneration = manifest.PreviousTopologyGeneration,
            PreviousTopologyHash = manifest.PreviousTopologyHash,
            ClockSkewSeconds = baseline.ClockSkewSeconds
        };
        var loaded = ProductionMailboxArtifacts.Load(options, timeProvider);
        if (!ClosureId(loaded).AsSpan().SequenceEqual(closureId)
            || Convert.ToHexStringLower(loaded.AuthoritySha256) != manifest.AuthoritySha256
            || Convert.ToHexStringLower(loaded.RevocationSha256) != manifest.RevocationSha256
            || Convert.ToHexStringLower(loaded.TopologySha256) != manifest.TopologySha256)
            throw new InvalidDataException(
                "Persisted production mailbox artifact bytes do not match their manifest.");
        VerifyMembershipProofClosure(loaded, manifest);
        return loaded;
    }

    private PersistedArtifactManifest ReadManifest(string path)
    {
        var bytes = ReadExactFile(path, 16 * 1024);
        var manifest = JsonSerializer.Deserialize<PersistedArtifactManifest>(bytes, CatalogJson)
            ?? throw new InvalidDataException(
                "Persisted production mailbox artifact manifest is invalid.");
        var canonical = JsonSerializer.SerializeToUtf8Bytes(manifest, CatalogJson);
        if (!bytes.AsSpan().SequenceEqual(canonical)
            || manifest.IntegrityTag.Length != 64)
            throw new InvalidDataException(
                "Persisted production mailbox artifact manifest is non-canonical.");
        var expected = ComputeCatalogHmac(
            "Deep/production-mailbox/artifact-catalog-manifest/v1",
            JsonSerializer.SerializeToUtf8Bytes(
                manifest with { IntegrityTag = "" }, CatalogJson));
        byte[] actual;
        try { actual = Convert.FromHexString(manifest.IntegrityTag); }
        catch (FormatException exception)
        {
            throw new InvalidDataException(
                "Persisted production mailbox artifact manifest tag is invalid.",
                exception);
        }
        if (!CryptographicOperations.FixedTimeEquals(expected, actual))
            throw new InvalidDataException(
                "Persisted production mailbox artifact manifest tag is invalid.");
        return manifest;
    }

    private MembershipProofClosure FreezeMembershipProofClosure(
        ProductionMailboxArtifacts snapshot)
    {
        var files = new List<MembershipProofFile>();
        foreach (var epoch in new[]
                 {
                     snapshot.Topology.Snapshot.CurrentEpoch,
                     snapshot.Topology.Snapshot.NextEpoch
                 })
        {
            foreach (var node in epoch.Nodes)
            {
                var bytes = snapshot.ReadMembershipProof(epoch.Epoch, node.NodeId.Span);
                files.Add(new(
                    $"{epoch.Epoch}-{Convert.ToHexStringLower(node.NodeId.Span)}.mip1",
                    bytes));
            }
        }
        var ordered = files.OrderBy(static file => file.FileName, StringComparer.Ordinal)
            .ToArray();
        if (ordered.Length is < 4 or > ProductionMailboxTopologyConstants.MaximumNodesPerEpoch * 2
            || ordered.Select(static file => file.FileName)
                .Distinct(StringComparer.Ordinal).Count() != ordered.Length)
            throw new InvalidDataException(
                "Production mailbox membership proof closure is not bounded and unique.");
        return new(ordered, MembershipProofClosureHash(ordered));
    }

    private void WriteMembershipProofClosure(
        string directory, MembershipProofClosure closure)
    {
        if (Directory.Exists(directory))
            DeleteMembershipProofDirectory(directory);
        Directory.CreateDirectory(directory);
        EnsureNoReparseAncestors(directory);
        foreach (var file in closure.Files)
            WriteAtomic(Path.Combine(directory, file.FileName), file.CanonicalBytes);
        FlushDirectory(directory);
    }

    private void VerifyMembershipProofClosure(
        ProductionMailboxArtifacts snapshot, PersistedArtifactManifest manifest)
    {
        var closure = FreezeMembershipProofClosure(snapshot);
        if (closure.Files.Count != manifest.MembershipProofCount
            || !CryptographicOperations.FixedTimeEquals(
                closure.Sha256, Convert.FromHexString(
                    manifest.MembershipProofClosureSha256)))
            throw new InvalidDataException(
                "Persisted production mailbox membership proof closure is invalid.");
        var directory = Path.Combine(catalogDirectory,
            Convert.ToHexStringLower(ClosureId(snapshot)) + ".mip1");
        var actual = Directory.EnumerateFiles(directory, "*", SearchOption.TopDirectoryOnly)
            .Select(Path.GetFileName)
            .OrderBy(static name => name, StringComparer.Ordinal)
            .ToArray();
        var expected = closure.Files.Select(static file => file.FileName).ToArray();
        if (!actual.SequenceEqual(expected, StringComparer.Ordinal))
            throw new InvalidDataException(
                "Persisted production mailbox membership proof filenames are invalid.");
    }

    private static byte[] MembershipProofClosureHash(
        IReadOnlyList<MembershipProofFile> files)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(Encoding.UTF8.GetBytes(
            "Deep/production-mailbox/artifact-membership-proof-closure/v1"));
        Span<byte> length = stackalloc byte[4];
        foreach (var file in files)
        {
            var name = Encoding.UTF8.GetBytes(file.FileName);
            BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)name.Length));
            hash.AppendData(length);
            hash.AppendData(name);
            BinaryPrimitives.WriteUInt32BigEndian(length,
                checked((uint)file.CanonicalBytes.Length));
            hash.AppendData(length);
            hash.AppendData(SHA256.HashData(file.CanonicalBytes));
        }
        return hash.GetHashAndReset();
    }

    private static byte[] ClosureId(ProductionMailboxArtifacts snapshot)
    {
        var bytes = new byte[96];
        snapshot.AuthoritySha256.CopyTo(bytes, 0);
        snapshot.RevocationSha256.CopyTo(bytes, 32);
        snapshot.TopologySha256.CopyTo(bytes, 64);
        return SHA256.HashData(bytes);
    }

    private static byte[] ArtifactClosureHash(ProductionMailboxArtifacts snapshot)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(Encoding.UTF8.GetBytes(
            "Deep/production-mailbox/challenge-artifact-closure/v1"));
        hash.AppendData(snapshot.AuthoritySha256);
        hash.AppendData(snapshot.RevocationSha256);
        hash.AppendData(snapshot.TopologySha256);
        return hash.GetHashAndReset();
    }

    internal static byte[] ComputeArtifactClosureHash(
        ProductionMailboxArtifacts snapshot) => ArtifactClosureHash(snapshot);

    private byte[] ReadActivePointer()
    {
        var encoded = ReadExactFile(activePointerPath, 64);
        var expected = ComputeCatalogHmac(
            "Deep/production-mailbox/artifact-catalog-active-pointer/v1",
            encoded.AsSpan(0, 32));
        if (!CryptographicOperations.FixedTimeEquals(
                expected, encoded.AsSpan(32, 32)))
            throw new InvalidDataException(
                "Persisted production mailbox artifact active pointer is invalid.");
        return encoded[..32];
    }

    private void WriteActivePointer(ReadOnlySpan<byte> closureId)
    {
        if (closureId.Length != 32)
            throw new InvalidDataException(
                "Persisted production mailbox artifact active pointer is invalid.");
        var encoded = new byte[64];
        closureId.CopyTo(encoded);
        ComputeCatalogHmac(
                "Deep/production-mailbox/artifact-catalog-active-pointer/v1",
                closureId)
            .CopyTo(encoded, 32);
        WriteAtomic(activePointerPath, encoded);
    }

    private byte[] ComputeCatalogHmac(string domain, ReadOnlySpan<byte> payload)
    {
        using var hmac = IncrementalHash.CreateHMAC(
            HashAlgorithmName.SHA256, catalogIntegrityKey);
        hmac.AppendData(Encoding.UTF8.GetBytes(domain));
        hmac.AppendData(payload);
        return hmac.GetHashAndReset();
    }

    private static bool SameClosure(
        ProductionMailboxArtifacts left, ProductionMailboxArtifacts right) =>
        left.AuthoritySha256.AsSpan().SequenceEqual(right.AuthoritySha256)
        && left.RevocationSha256.AsSpan().SequenceEqual(right.RevocationSha256)
        && left.TopologySha256.AsSpan().SequenceEqual(right.TopologySha256);

    private static string ResolveCatalogDirectory(ProductionMailboxOptions options)
    {
        if (!string.IsNullOrWhiteSpace(options.ArtifactCatalogDirectory))
            return Path.GetFullPath(options.ArtifactCatalogDirectory);
        var routeStateDirectory = Path.GetDirectoryName(
            Path.GetFullPath(options.RouteStateHmacKeyPath));
        if (routeStateDirectory is null)
            throw new InvalidOperationException(
                "Production mailbox artifact catalog directory is missing.");
        return Path.Combine(routeStateDirectory, "production-mailbox-artifact-catalog");
    }

    private static byte[] ReadExactFile(string path, int exactOrMaximumBytes)
    {
        var full = Path.GetFullPath(path);
        var exactLength = exactOrMaximumBytes is 32 or 64
            ? exactOrMaximumBytes
            : (int?)null;
        return ProductionMailboxProtectedFile.ReadStable(
            full, exactOrMaximumBytes, exactLength,
            () => EnsureNoReparseAncestors(full));
    }

    private static void WriteAtomic(string path, byte[] bytes)
    {
        var full = Path.GetFullPath(path);
        EnsureNoReparseAncestors(Path.GetDirectoryName(full)!);
        var temporary = full + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var stream = new FileStream(temporary, FileMode.CreateNew,
                       FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            {
                stream.Write(bytes);
                stream.Flush(flushToDisk: true);
            }
            ReplaceAtomicDurable(temporary, full);
        }
        finally
        {
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }

    private static void ReplaceAtomicDurable(string temporary, string final)
    {
        if (OperatingSystem.IsWindows())
        {
            if (!MoveFileEx(temporary, final, 0x1 | 0x8))
            {
                var error = Marshal.GetLastPInvokeError();
                throw new Win32Exception(error,
                    $"Production mailbox durable rename failed from '{temporary}' to '{final}'.");
            }
            return;
        }
        File.Move(temporary, final, overwrite: true);
        var parent = Path.GetDirectoryName(final)
            ?? throw new InvalidOperationException("Artifact catalog file has no parent.");
        var descriptor = Open(parent, 0);
        if (descriptor < 0) throw new Win32Exception(Marshal.GetLastPInvokeError());
        try
        {
            if (Fsync(descriptor) != 0)
                throw new Win32Exception(Marshal.GetLastPInvokeError());
        }
        finally { _ = Close(descriptor); }
    }

    internal static void EnsureNoReparseAncestors(string path)
    {
        for (var current = new DirectoryInfo(Path.GetFullPath(path)); current is not null;
             current = current.Parent)
        {
            if (current.Exists && current.Attributes.HasFlag(FileAttributes.ReparsePoint))
                throw new InvalidDataException(
                    "Production mailbox artifact catalog contains a reparse point.");
        }
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

    private sealed record MembershipProofFile(
        string FileName,
        byte[] CanonicalBytes);

    private sealed record MembershipProofClosure(
        IReadOnlyList<MembershipProofFile> Files,
        byte[] Sha256);

    private sealed record PersistedArtifactManifest(
        string Schema,
        string ClosureId,
        string AuthoritySha256,
        string RevocationSha256,
        string TopologySha256,
        int MembershipProofCount,
        string MembershipProofClosureSha256,
        ulong RetainUntilUnixSeconds,
        ulong PreviousAuthorityGeneration,
        string PreviousAuthorityHash,
        ulong PreviousRevocationGeneration,
        string PreviousRevocationHeadHash,
        string PreviousRevocationSnapshotHash,
        ulong PreviousTopologyGeneration,
        string PreviousTopologyHash,
        string IntegrityTag);

    private sealed record VerificationContext(
        ulong PreviousAuthorityGeneration,
        string PreviousAuthorityHash,
        ulong PreviousRevocationGeneration,
        string PreviousRevocationHeadHash,
        string PreviousRevocationSnapshotHash,
        ulong PreviousTopologyGeneration,
        string PreviousTopologyHash)
    {
        public static VerificationContext FromBaseline(ProductionMailboxOptions options) => new(
            options.PreviousAuthorityGeneration, options.PreviousAuthorityHash,
            options.PreviousRevocationGeneration, options.PreviousRevocationHeadHash,
            options.PreviousRevocationSnapshotHash, options.PreviousTopologyGeneration,
            options.PreviousTopologyHash);

        public static VerificationContext FromPrevious(ProductionMailboxArtifacts previous) => new(
            previous.Authority.Authority.AuthorityGeneration,
            Convert.ToHexStringLower(previous.Authority.CanonicalAuthorityHash.Span),
            previous.Revocation.Snapshot.RevocationGeneration,
            Convert.ToHexStringLower(previous.Revocation.Snapshot.RevocationHeadHash.Span),
            Convert.ToHexStringLower(previous.Revocation.CanonicalSnapshotHash.Span),
            previous.Topology.CommittedTopologyGeneration,
            Convert.ToHexStringLower(previous.Topology.CanonicalTopologyHash.Span));
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool MoveFileEx(string existingFileName,
        string newFileName, uint flags);

    [DllImport("libc", EntryPoint = "open", SetLastError = true)]
    private static extern int Open(string path, int flags);

    [DllImport("libc", EntryPoint = "fsync", SetLastError = true)]
    private static extern int Fsync(int descriptor);

    [DllImport("libc", EntryPoint = "close", SetLastError = true)]
    private static extern int Close(int descriptor);
}

internal static class ProductionMailboxProtectedFile
{
    private const uint GenericRead = 0x8000_0000;
    private const uint ShareRead = 0x1;
    private const uint ShareDelete = 0x4;
    private const uint OpenExisting = 3;
    private const uint FileAttributeNormal = 0x80;
    private const uint FileAttributeDirectory = 0x10;
    private const uint FileAttributeReparsePoint = 0x400;
    private const uint FileFlagOpenReparsePoint = 0x20_0000;
    private const int AtCurrentWorkingDirectory = -100;
    private const int AtEmptyPath = 0x1000;
    private const int AtSymlinkNoFollow = 0x100;
    private const int LinuxOpenReadOnly = 0;
    private const int LinuxCloseOnExec = 0x80_000;
    private const long LinuxOpenAt2SystemCall = 437;
    private const ulong LinuxResolveNoSymlinks = 0x04;
    private const uint StatxBasicStats = 0x7ff;
    private const ushort UnixRegularFile = 0x8000;
    private const ushort UnixFileTypeMask = 0xf000;

    internal static byte[] ReadStable(
        string path, int maximumLength, int? exactLength, Action validatePath,
        Action? afterActualOpen = null)
    {
        validatePath();
        using var before = OpenNoFollow(path);
        var identity = Identity(before.SafeFileHandle);
        using var actual = OpenNoFollow(path);
        if (Identity(actual.SafeFileHandle) != identity)
            throw new InvalidDataException(
                "Production mailbox protected file identity changed while opening.");
        afterActualOpen?.Invoke();
        validatePath();
        using var after = OpenNoFollow(path);
        if (Identity(after.SafeFileHandle) != identity)
            throw new InvalidDataException(
                "Production mailbox protected file identity changed during validation.");
        var length = actual.Length;
        if (length <= 0 || length > maximumLength
            || exactLength.HasValue && length != exactLength.Value)
            throw new InvalidDataException(
                "Production mailbox protected file length is invalid.");
        var bytes = new byte[checked((int)length)];
        actual.Position = 0;
        var offset = 0;
        while (offset < bytes.Length)
        {
            var read = actual.Read(bytes, offset, bytes.Length - offset);
            if (read == 0)
                throw new EndOfStreamException(
                    "Production mailbox protected file ended early.");
            offset += read;
        }
        if (actual.ReadByte() != -1 || Identity(actual.SafeFileHandle) != identity)
            throw new IOException(
                "Production mailbox protected file changed while reading.");
        return bytes;
    }

    private static FileStream OpenNoFollow(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            var handle = CreateFile(path, GenericRead, ShareRead | ShareDelete,
                IntPtr.Zero, OpenExisting,
                FileAttributeNormal | FileFlagOpenReparsePoint, IntPtr.Zero);
            if (handle.IsInvalid)
            {
                var error = Marshal.GetLastPInvokeError();
                handle.Dispose();
                throw new IOException(
                    "Production mailbox protected file could not be opened.",
                    new Win32Exception(error));
            }
            var information = WindowsIdentity(handle);
            if ((information.Attributes
                 & (FileAttributeDirectory | FileAttributeReparsePoint)) != 0)
            {
                handle.Dispose();
                throw new InvalidDataException(
                    "Production mailbox protected path is not a regular file.");
            }
            return new FileStream(handle, FileAccess.Read, 4096, isAsync: false);
        }
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException(
                "Production mailbox protected files support Windows and Linux only.");
        var how = new LinuxOpenHow
        {
            Flags = LinuxOpenReadOnly | LinuxCloseOnExec,
            Resolve = LinuxResolveNoSymlinks
        };
        var descriptorValue = LinuxSyscall(
            LinuxOpenAt2SystemCall, AtCurrentWorkingDirectory, path,
            ref how, checked((nuint)Marshal.SizeOf<LinuxOpenHow>()));
        var descriptor = checked((int)descriptorValue);
        if (descriptor < 0)
            throw new IOException(
                "Production mailbox protected file could not be opened.",
                new Win32Exception(Marshal.GetLastPInvokeError()));
        var safeHandle = new SafeFileHandle(new IntPtr(descriptor), ownsHandle: true);
        try
        {
            var information = LinuxIdentity(safeHandle);
            if ((information.Mode & UnixFileTypeMask) != UnixRegularFile)
                throw new InvalidDataException(
                    "Production mailbox protected path is not a regular file.");
            return new FileStream(safeHandle, FileAccess.Read, 4096, isAsync: false);
        }
        catch
        {
            safeHandle.Dispose();
            throw;
        }
    }

    private static FileIdentity Identity(SafeFileHandle handle)
    {
        if (OperatingSystem.IsWindows())
        {
            var value = WindowsIdentity(handle);
            return new(value.VolumeSerialNumber,
                ((ulong)value.FileIndexHigh << 32) | value.FileIndexLow,
                0, 0);
        }
        var stat = LinuxIdentity(handle);
        return new(((ulong)stat.DeviceMajor << 32) | stat.DeviceMinor,
            stat.Inode, stat.UserId, stat.Mode);
    }

    private static WindowsFileInformation WindowsIdentity(SafeFileHandle handle)
    {
        if (!GetFileInformationByHandle(handle, out var information))
            throw new IOException(
                "Production mailbox protected file identity is unavailable.",
                new Win32Exception(Marshal.GetLastPInvokeError()));
        return information;
    }

    private static LinuxStatx LinuxIdentity(SafeFileHandle handle)
    {
        if (Statx(handle.DangerousGetHandle().ToInt32(), "",
                AtEmptyPath | AtSymlinkNoFollow, StatxBasicStats, out var stat) != 0)
            throw new IOException(
                "Production mailbox protected file identity is unavailable.",
                new Win32Exception(Marshal.GetLastPInvokeError()));
        return stat;
    }

    private readonly record struct FileIdentity(
        ulong Device, ulong File, uint UserId, ushort Mode);

    [StructLayout(LayoutKind.Sequential)]
    private struct WindowsFileInformation
    {
        internal uint Attributes;
        internal System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        internal System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        internal System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        internal uint VolumeSerialNumber;
        internal uint FileSizeHigh;
        internal uint FileSizeLow;
        internal uint NumberOfLinks;
        internal uint FileIndexHigh;
        internal uint FileIndexLow;
    }

    [StructLayout(LayoutKind.Sequential, Size = 256)]
    private struct LinuxStatx
    {
        internal uint Mask;
        internal uint BlockSize;
        internal ulong Attributes;
        internal uint HardLinks;
        internal uint UserId;
        internal uint GroupId;
        internal ushort Mode;
        internal ushort Reserved;
        internal ulong Inode;
        internal ulong Size;
        internal ulong Blocks;
        internal ulong AttributesMask;
        internal LinuxStatxTimestamp AccessTime;
        internal LinuxStatxTimestamp BirthTime;
        internal LinuxStatxTimestamp ChangeTime;
        internal LinuxStatxTimestamp ModificationTime;
        internal uint RDeviceMajor;
        internal uint RDeviceMinor;
        internal uint DeviceMajor;
        internal uint DeviceMinor;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LinuxStatxTimestamp
    {
        internal long Seconds;
        internal uint Nanoseconds;
        internal int Reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LinuxOpenHow
    {
        internal ulong Flags;
        internal ulong Mode;
        internal ulong Resolve;
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", SetLastError = true,
        CharSet = CharSet.Unicode)]
    private static extern SafeFileHandle CreateFile(
        string fileName, uint desiredAccess, uint shareMode,
        IntPtr securityAttributes, uint creationDisposition,
        uint flagsAndAttributes, IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle handle, out WindowsFileInformation information);

    [DllImport("libc", EntryPoint = "syscall", SetLastError = true,
        CharSet = CharSet.Ansi)]
    private static extern long LinuxSyscall(
        long number, int directoryDescriptor, string path,
        ref LinuxOpenHow how, nuint size);

    [DllImport("libc", EntryPoint = "statx", SetLastError = true,
        CharSet = CharSet.Ansi)]
    private static extern int Statx(
        int directoryDescriptor, string path, int flags,
        uint mask, out LinuxStatx stat);
}
