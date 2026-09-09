#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.XPointNetworkV1;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Deep.Registry.Api.DirectoryPublication;

internal sealed class FileContactResolveDirectoryArtifactSourceOptions
{
    public string ReadOnlyRoot { get; set; } = string.Empty;
    public string StatePath { get; set; } = string.Empty;
    public string IntegrityKeyPath { get; set; } = string.Empty;
    public string NetworkIdHex { get; set; } = string.Empty;
    public string GenesisAuthorityCoreHashHex { get; set; } = string.Empty;
}

internal sealed record FileContactResolveDirectoryArtifactInventory(
    string Format,
    string NetworkIdHex,
    string GenesisAuthorityCoreHashHex,
    ushort SupportedReader,
    string SnapshotNonceHex,
    string SnapshotQueryLeafHex,
    string SnapshotBootIdHex,
    ulong SnapshotNonceCreatedAt,
    ulong SnapshotResponseReceivedAt,
    ulong SnapshotCurrentSample,
    IReadOnlyList<FileContactResolveDirectoryArtifactInventoryEntry> Artifacts);

internal sealed record FileContactResolveDirectoryArtifactInventoryEntry(
    string Role,
    int Ordinal,
    string FileName,
    int Length,
    string Sha256Hex);

internal static class FileContactResolveDirectoryArtifactInventoryCodec
{
    internal const string CurrentFormat = "deep-contact-resolve-readonly-v1";
    internal const int MaximumInventoryBytes = 512 * 1024;

    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        WriteIndented = false,
    };

    internal static byte[] EncodeCanonical(FileContactResolveDirectoryArtifactInventory value) =>
        JsonSerializer.SerializeToUtf8Bytes(value, Options);

    internal static FileContactResolveDirectoryArtifactInventory DecodeCanonical(
        ReadOnlySpan<byte> canonical)
    {
        if (canonical.IsEmpty || canonical.Length > MaximumInventoryBytes)
            throw new InvalidDataException("The ContactResolve artifact inventory has an invalid length.");
        FileContactResolveDirectoryArtifactInventory value;
        try
        {
            value = JsonSerializer.Deserialize<FileContactResolveDirectoryArtifactInventory>(
                canonical, Options) ?? throw new InvalidDataException("The artifact inventory is empty.");
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("The ContactResolve artifact inventory is invalid.", exception);
        }
        var encoded = EncodeCanonical(value);
        if (!canonical.SequenceEqual(encoded))
            throw new InvalidDataException("The ContactResolve artifact inventory is not canonical JSON.");
        return value;
    }
}

/// <summary>
/// Reads publisher-prepared exact canonical artifacts from a read-only tree. The tree is never
/// trusted as state: Protocol verifies authority, directory freshness, proof and network closure,
/// while a separately protected file prevents rollback and same-generation forks.
/// </summary>
internal sealed class FileContactResolveDirectoryArtifactSource :
    IContactResolveCanonicalDirectorySnapshotSource,
    IContactResolveDirectoryProofMaterialSource,
    IDisposable
{
    private const int MaximumArtifacts = 4_096;
    private static ReadOnlySpan<byte> StateMagic => "CRS1"u8;
    private const int StatePayloadBytes = 4 + 2 + 16 + 8 + 32 + 8 + 32 + 1;
    private readonly string rootPath;
    private readonly string requestsPath;
    private readonly string currentValuesPath;
    private readonly string statePath;
    private readonly byte[] networkId;
    private readonly byte[] genesisAuthorityCoreHash;
    private readonly byte[] integrityKey;
    private readonly IContactResolveTrustedTimeContextSource trustedTimeSource;
    private readonly IContactResolveVerifiedAccountDirectoryCheckpointSource? checkpointSource;
    private readonly SemaphoreSlim gate = new(1, 1);
    private readonly ConditionalWeakTable<ContactResolveCanonicalDirectorySnapshot, VerifiedOperation>
        operations = new();

    internal FileContactResolveDirectoryArtifactSource(
        string readOnlyRoot,
        string statePath,
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> genesisAuthorityCoreHash,
        ReadOnlySpan<byte> integrityKey,
        IContactResolveTrustedTimeContextSource trustedTimeSource,
        IContactResolveVerifiedAccountDirectoryCheckpointSource? checkpointSource = null)
    {
        if (string.IsNullOrWhiteSpace(readOnlyRoot))
            throw new ArgumentException("A read-only ContactResolve artifact root is required.", nameof(readOnlyRoot));
        if (string.IsNullOrWhiteSpace(statePath))
            throw new ArgumentException("A protected ContactResolve artifact state path is required.", nameof(statePath));
        if (networkId.Length != 16 || networkId.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("A non-zero 16-byte network ID is required.", nameof(networkId));
        if (genesisAuthorityCoreHash.Length != 32 || genesisAuthorityCoreHash.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("A non-zero genesis authority core hash is required.", nameof(genesisAuthorityCoreHash));
        if (integrityKey.Length != 32 || integrityKey.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("A non-zero 32-byte integrity key is required.", nameof(integrityKey));

        rootPath = Path.TrimEndingDirectorySeparator(Path.GetFullPath(readOnlyRoot));
        requestsPath = Child(rootPath, "requests");
        currentValuesPath = Child(rootPath, "current-values");
        this.statePath = Path.GetFullPath(statePath);
        if (IsWithin(this.statePath, rootPath))
            throw new ArgumentException("Protected rollback state must be outside the read-only artifact root.", nameof(statePath));
        this.networkId = networkId.ToArray();
        this.genesisAuthorityCoreHash = genesisAuthorityCoreHash.ToArray();
        this.integrityKey = integrityKey.ToArray();
        this.trustedTimeSource = trustedTimeSource ?? throw new ArgumentNullException(nameof(trustedTimeSource));
        this.checkpointSource = checkpointSource;
    }

    public async ValueTask<ContactResolveCanonicalDirectorySnapshot> ReadAsync(
        ContactResolveDirectoryPackageRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        if (!Fixed(request.NetworkId.Span, networkId))
            throw new CryptographicException("The ContactResolve artifact source rejected a different network.");

        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var lease = DirectoryPublicationProtectedFile.AcquireLease(statePath, cancellationToken);
            var operation = await LoadAndVerifyAsync(request, cancellationToken).ConfigureAwait(false);
            operations.Add(operation.Snapshot, operation);
            return operation.Snapshot;
        }
        finally
        {
            gate.Release();
        }
    }

    public ValueTask<AccountDirectoryAdp1ProofMaterial> ReadAsync(
        ContactResolveCanonicalDirectorySnapshot snapshot,
        ContactResolveDirectoryPackageRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        if (!operations.TryGetValue(snapshot, out var operation) ||
            !Fixed(operation.RequestNonce, request.Nonce.Span) ||
            !Fixed(operation.RequestBootId, request.BootId.Span) ||
            operation.RequestNonceCreatedAt != request.NonceCreatedAt)
        {
            throw new CryptographicException(
                "Proof material is not bound to this source-produced snapshot and request.");
        }
        return ValueTask.FromResult(operation.ProofMaterial);
    }

    private async ValueTask<VerifiedOperation> LoadAndVerifyAsync(
        ContactResolveDirectoryPackageRequest request,
        CancellationToken cancellationToken)
    {
        EnsureDirectory(rootPath);
        string operationPath;
        string? currentPointerPath = null;
        byte[]? firstPointer = null;
        ulong? publicationGeneration = null;
        if (request.ExpectedDirectoryLookupKey.IsEmpty)
        {
            EnsureDirectory(requestsPath);
            operationPath = Child(requestsPath, Convert.ToHexString(request.Nonce.Span));
            EnsureDirectory(operationPath);
        }
        else
        {
            EnsureDirectory(currentValuesPath);
            var lookup = Convert.ToHexString(request.ExpectedDirectoryLookupKey.Span).ToLowerInvariant();
            var lookupPath = Child(currentValuesPath, lookup);
            if (!Directory.Exists(lookupPath)) throw new ContactResolveDirectoryTargetNotFoundException();
            EnsureDirectory(lookupPath);
            currentPointerPath = Child(lookupPath, "current.bin");
            if (!File.Exists(currentPointerPath)) throw new ContactResolveDirectoryTargetNotFoundException();
            firstPointer = ReadExactFile(currentPointerPath, sizeof(ulong), sizeof(ulong));
            publicationGeneration = BinaryPrimitives.ReadUInt64BigEndian(firstPointer);
            var generationsPath = Child(lookupPath, "generations");
            if (!Directory.Exists(generationsPath)) throw new ContactResolveDirectoryTargetNotFoundException();
            EnsureDirectory(generationsPath);
            operationPath = Child(generationsPath, publicationGeneration.Value.ToString("D20"));
            if (!Directory.Exists(operationPath)) throw new ContactResolveDirectoryTargetNotFoundException();
            EnsureDirectory(operationPath);
        }
        var first = ReadBundle(operationPath);
        ValidateInventory(first.Inventory);

        var trustedTime = await trustedTimeSource.ReadAsync(cancellationToken).ConfigureAwait(false);
        trustedTime.Validate();
        var bootId = Hex(first.Inventory.SnapshotBootIdHex, 16, "snapshot boot ID");
        if (!Fixed(bootId, trustedTime.ServerBootId.Span) ||
            trustedTime.ServerMonotonicSample < first.Inventory.SnapshotCurrentSample)
        {
            throw new CryptographicException("The artifact snapshot is outside the current trusted monotonic boot/sample.");
        }

        var xna = first.Chain("xna1");
        var dts = first.Chain("dts1");
        var authority = XPointNetworkAuthorityVerifier.Verify(
            new XPointNetworkGenesisPin(networkId, genesisAuthorityCoreHash), xna, dts);
        if (!Fixed(authority.NetworkId.Span, networkId))
            throw new CryptographicException("The verified artifact authority belongs to another network.");

        var exactAdh = first.Single("adh1");
        var snapshotDtt = first.Single("snapshot-dtt1");
        var snapshotAdp = first.Single("snapshot-adp1");
        var snapshotNonce = Hex(first.Inventory.SnapshotNonceHex, 32, "snapshot nonce");
        var snapshotQuery = Hex(first.Inventory.SnapshotQueryLeafHex, 32, "snapshot query leaf");
        var window = new AccountDirectoryMonotonicRequestWindow(
            bootId,
            first.Inventory.SnapshotNonceCreatedAt,
            first.Inventory.SnapshotResponseReceivedAt,
            first.Inventory.SnapshotCurrentSample);
        var freshness = AccountDirectoryCurrentProofVerifier.Verify(
            authority,
            exactAdh,
            snapshotDtt,
            snapshotAdp,
            snapshotNonce,
            snapshotQuery,
            window,
            protectedLkg: null,
            currentCheckpoint: null,
            first.Inventory.SupportedReader);
        if (!freshness.IsCurrentAtMonotonic(
                trustedTime.ServerBootId.Span, trustedTime.ServerMonotonicSample))
        {
            throw new CryptographicException("The verified directory snapshot is no longer current.");
        }
        var trustedLower = trustedTime.ObservedUnixTime - trustedTime.UncertaintySeconds;
        var trustedUpper = trustedTime.ObservedUnixTime + trustedTime.UncertaintySeconds;
        if (trustedLower < freshness.TrustedLowerUnixSeconds ||
            trustedUpper > freshness.TrustedUpperUnixSeconds)
        {
            throw new CryptographicException(
                "The threshold DTT1 interval does not contain the independent trusted-time interval.");
        }

        var xvp = first.Chain("xvp1");
        var xnv = first.Chain("xnv1");
        var xnh = first.Chain("xnh1");
        var xnd = first.Chain("xnd1");
        var pmt = first.Chain("pmt2");
        var closure = new DirectoryPublicationVerificationClosure(
            xna, dts, xvp, xnv, xnh, xnd, pmt,
            exactAdh.Span, snapshotDtt.Span, snapshotAdp.Span,
            snapshotNonce, snapshotQuery, bootId,
            first.Inventory.SnapshotNonceCreatedAt,
            first.Inventory.SnapshotResponseReceivedAt,
            first.Inventory.SnapshotCurrentSample,
            first.Inventory.SupportedReader);
        var candidate = new DirectoryPublicationCandidate(
            xnv[^1].Span, xnh[^1].Span, pmt[^1].Span, closure);
        var networkVerifier = new ProductionDirectoryCanonicalPublicationVerifier(
            new DirectoryPublicationTrustAnchor(networkId, 0, genesisAuthorityCoreHash),
            new TrustedTimeClock(trustedTime),
            new ExactChallenge(first.Inventory));
        var verifiedNetwork = await networkVerifier.VerifyAsync(candidate.Freeze(), cancellationToken)
            .ConfigureAwait(false);
        ValidateNetworkFloor(request.NetworkFloor, verifiedNetwork);

        var responseAdpBytes = first.Single("response-adp1");
        var responseAdp = AccountDirectoryAdp1Codec.Decode(responseAdpBytes.Span);
        if (publicationGeneration is not null &&
            publicationGeneration.Value != freshness.NextProtectedLkg.LogGeneration)
            throw new ContactResolveDirectoryTargetNotFoundException();
        ValidateTargetedCurrentValue(request, responseAdp, freshness.NextProtectedLkg);
        var callerLkg = ResolveCallerLkg(first, request, responseAdp, authority);
        VerifiedAccountDirectoryCheckpoint? currentCheckpoint = null;
        if (responseAdp.ResultKind == AccountDirectoryAdp1ResultKind.CurrentValue)
        {
            if (checkpointSource is null)
                throw new ContactResolveDirectoryPackageUnavailableException();
            currentCheckpoint = await checkpointSource.ReadAsync(
                responseAdp.QueriedDirectoryLeafKey, cancellationToken).ConfigureAwait(false)
                ?? throw new ContactResolveDirectoryPackageUnavailableException();
            var exactProofAdc = AccountDirectoryAdc1Codec.Encode(
                responseAdp.CurrentValue?.Adc1 ?? throw new CryptographicException(
                    "The current-value ADP1 has no exact ADC1 closure."));
            var exactCapabilityAdc = AccountDirectoryAdc1Codec.Encode(currentCheckpoint.Checkpoint);
            if (!Fixed(exactProofAdc, exactCapabilityAdc))
                throw new CryptographicException(
                    "The verified ADC1 capability differs from the canonical response proof.");
        }
        var responseFreshness = AccountDirectoryCurrentProofVerifier.Verify(
            authority,
            exactAdh,
            snapshotDtt,
            responseAdpBytes,
            snapshotNonce,
            responseAdp.QueriedDirectoryLeafKey.Span,
            window,
            callerLkg,
            currentCheckpoint,
            first.Inventory.SupportedReader);
        if (responseFreshness.ResultKind != responseAdp.ResultKind ||
            !Fixed(responseFreshness.NextProtectedLkg.ExactAdh1.Span, freshness.NextProtectedLkg.ExactAdh1.Span))
        {
            throw new CryptographicException("The response proof does not close over the current directory snapshot.");
        }
        var proof = responseAdp.ResultKind == AccountDirectoryAdp1ResultKind.NonMembership
            ? AccountDirectoryAdp1ProofMaterial.NonMembership(
                responseAdp.QueriedDirectoryLeafKey.Span,
                callerLkg,
                responseAdp.ConsistencyProofNodes,
                responseAdp.ExactAfp1,
                responseAdp.SparseMapBitmap.Span,
                responseAdp.SparseMapSiblings)
            : AccountDirectoryAdp1ProofMaterial.CurrentValue(
                currentCheckpoint!,
                callerLkg,
                responseAdp.ConsistencyProofNodes,
                responseAdp.ExactAfp1,
                responseAdp.SparseMapBitmap.Span,
                responseAdp.SparseMapSiblings,
                responseAdp.CurrentValue!.ExactTransitionBytes,
                responseAdp.CurrentValue.AppendLogIndex,
                responseAdp.CurrentValue.InclusionProofNodes);

        var second = ReadBundle(operationPath);
        first.RequireExact(second);
        if (currentPointerPath is not null && firstPointer is not null)
        {
            var secondPointer = ReadExactFile(currentPointerPath, sizeof(ulong), sizeof(ulong));
            if (!Fixed(firstPointer, secondPointer))
                throw new CryptographicException(
                    "The targeted current-value publication changed during verification.");
        }

        var currentView = verifiedNetwork.Artifacts.Single(
            static artifact => artifact.Kind == DirectoryArtifactKind.CurrentNetworkView);
        CheckAndAdvanceState(
            freshness.NextProtectedLkg.LogGeneration,
            freshness.ExactAdh1CoreHash.Span,
            verifiedNetwork.Generation,
            currentView.CoreHash.Span);

        var snapshot = new ContactResolveCanonicalDirectorySnapshot(
            networkId,
            authority,
            freshness.NextProtectedLkg,
            xnv[^1],
            first.Inventory.SupportedReader,
            xna, dts, xvp, xnv, xnh, xnd, pmt);
        return new VerifiedOperation(
            snapshot,
            proof,
            request.Nonce.Span,
            request.BootId.Span,
            request.NonceCreatedAt);
    }

    private AccountDirectoryProtectedLkg? ResolveCallerLkg(
        ArtifactBundle bundle,
        ContactResolveDirectoryPackageRequest request,
        AccountDirectoryAdp1 responseAdp,
        VerifiedXPointNetworkAuthority authority)
    {
        if (!request.ExpectedDirectoryLookupKey.IsEmpty)
        {
            if (!responseAdp.HasLkg)
            {
                if (bundle.Count("caller-adh1") != 0 ||
                    request.MinimumAdhGeneration is not null &&
                    request.MinimumAdhGeneration.Value <
                        AccountDirectoryAdh1Codec.Decode(bundle.Single("adh1").Span).LogGeneration)
                    throw new ContactResolveDirectoryTargetNotFoundException();
                return null;
            }
            if (request.MinimumAdhGeneration is null || request.MinimumAdhHash.Length != 32 ||
                !Fixed(responseAdp.CallerLkgAdh1CoreHash.Span, request.MinimumAdhHash.Span) ||
                bundle.Count("caller-adh1") != 1)
                throw new ContactResolveDirectoryTargetNotFoundException();
            var targetedExact = bundle.Single("caller-adh1");
            var targetedFloor = AccountDirectoryProtectedLkgFactory.Restore(
                authority, targetedExact, request.MinimumAdhHash.Span);
            if (targetedFloor.LogGeneration != request.MinimumAdhGeneration.Value ||
                targetedFloor.TreeSize != responseAdp.CallerLkgTreeSize)
                throw new ContactResolveDirectoryTargetNotFoundException();
            return targetedFloor;
        }
        if (request.DirectoryTreeSize is null)
        {
            if (!request.DirectoryCoreHash.IsEmpty || responseAdp.HasLkg || bundle.Count("caller-adh1") != 0)
                throw new CryptographicException("The no-LKG request and response proof shape differ.");
            return null;
        }
        if (request.DirectoryCoreHash.Length != 32 || !responseAdp.HasLkg ||
            responseAdp.CallerLkgTreeSize != request.DirectoryTreeSize.Value ||
            !Fixed(responseAdp.CallerLkgAdh1CoreHash.Span, request.DirectoryCoreHash.Span) ||
            bundle.Count("caller-adh1") != 1)
        {
            throw new CryptographicException("The caller directory floor is incomplete or differs from the response proof.");
        }
        var exact = bundle.Single("caller-adh1");
        var restored = AccountDirectoryProtectedLkgFactory.Restore(
            authority, exact, request.DirectoryCoreHash.Span);
        if (restored.TreeSize != request.DirectoryTreeSize.Value)
            throw new CryptographicException("The exact caller ADH1 tree size differs from the request floor.");
        return restored;
    }

    private static void ValidateTargetedCurrentValue(
        ContactResolveDirectoryPackageRequest request,
        AccountDirectoryAdp1 responseAdp,
        AccountDirectoryProtectedLkg currentHead)
    {
        if (request.ExpectedDirectoryLookupKey.IsEmpty) return;
        if (request.ExpectedDirectoryLookupKey.Length != 32 ||
            request.MinimumAdhGeneration is null || request.MinimumAdhHash.Length != 32 ||
            !request.RequireCurrentValue)
            throw new CryptographicException("The targeted current-value request is incomplete.");
        if (!Fixed(request.ExpectedDirectoryLookupKey.Span,
                responseAdp.QueriedDirectoryLeafKey.Span) ||
            responseAdp.ResultKind != AccountDirectoryAdp1ResultKind.CurrentValue ||
            currentHead.LogGeneration < request.MinimumAdhGeneration.Value ||
            currentHead.LogGeneration == request.MinimumAdhGeneration.Value &&
                !Fixed(currentHead.CoreHash.Span, request.MinimumAdhHash.Span))
            throw new ContactResolveDirectoryTargetNotFoundException();
    }

    private void ValidateInventory(FileContactResolveDirectoryArtifactInventory inventory)
    {
        if (!StringComparer.Ordinal.Equals(inventory.Format, FileContactResolveDirectoryArtifactInventoryCodec.CurrentFormat) ||
            !Fixed(Hex(inventory.NetworkIdHex, 16, "inventory network ID"), networkId) ||
            !Fixed(Hex(inventory.GenesisAuthorityCoreHashHex, 32, "inventory genesis authority hash"), genesisAuthorityCoreHash) ||
            inventory.SupportedReader == 0 ||
            inventory.Artifacts is null || inventory.Artifacts.Count is < 10 or > MaximumArtifacts ||
            inventory.SnapshotNonceCreatedAt > inventory.SnapshotResponseReceivedAt ||
            inventory.SnapshotResponseReceivedAt > inventory.SnapshotCurrentSample)
        {
            throw new InvalidDataException("The ContactResolve artifact inventory header is invalid.");
        }
        _ = Hex(inventory.SnapshotNonceHex, 32, "snapshot nonce");
        _ = Hex(inventory.SnapshotQueryLeafHex, 32, "snapshot query leaf");
        _ = Hex(inventory.SnapshotBootIdHex, 16, "snapshot boot ID");

        var allowed = new HashSet<string>(StringComparer.Ordinal)
        {
            "xna1", "dts1", "adh1", "snapshot-dtt1", "snapshot-adp1",
            "xvp1", "xnv1", "xnh1", "xnd1", "pmt2", "response-adp1", "caller-adh1",
        };
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var priorRole = string.Empty;
        var priorOrdinal = -1;
        foreach (var entry in inventory.Artifacts)
        {
            if (entry is null || !allowed.Contains(entry.Role) || entry.Ordinal < 0 ||
                entry.Length is < 1 or > ContactResolveDirectoryIssuedPackage.MaximumSingleArtifactBytes ||
                !StringComparer.Ordinal.Equals(entry.FileName, $"{entry.Role}.{entry.Ordinal:D4}.bin") ||
                !seen.Add(entry.FileName))
            {
                throw new InvalidDataException("The ContactResolve artifact inventory contains an invalid entry.");
            }
            _ = Hex(entry.Sha256Hex, 32, "artifact SHA-256");
            var roleOrder = RoleOrder(entry.Role);
            var previousRoleOrder = priorRole.Length == 0 ? -1 : RoleOrder(priorRole);
            if (roleOrder < previousRoleOrder ||
                roleOrder == previousRoleOrder && entry.Ordinal != priorOrdinal + 1 ||
                roleOrder > previousRoleOrder && entry.Ordinal != 0)
            {
                throw new InvalidDataException("The ContactResolve artifact inventory is not in canonical role/ordinal order.");
            }
            priorRole = entry.Role;
            priorOrdinal = entry.Ordinal;
        }
        RequireCount(inventory, "xna1", minimum: 1);
        RequireCount(inventory, "dts1", minimum: 1);
        RequireCount(inventory, "adh1", exact: 1);
        RequireCount(inventory, "snapshot-dtt1", exact: 1);
        RequireCount(inventory, "snapshot-adp1", exact: 1);
        RequireCount(inventory, "xvp1", minimum: 1);
        RequireCount(inventory, "xnv1", minimum: 1);
        RequireCount(inventory, "xnh1", exact: inventory.Artifacts.Count(x => x.Role == "xnv1"));
        RequireCount(inventory, "xnd1", minimum: 3);
        RequireCount(inventory, "pmt2", minimum: 1);
        RequireCount(inventory, "response-adp1", exact: 1);
        if (inventory.Artifacts.Count(x => x.Role == "caller-adh1") > 1)
            throw new InvalidDataException("At most one exact caller ADH1 may be present.");
    }

    private static void ValidateNetworkFloor(
        ContactResolveNetworkFloor? floor,
        VerifiedDirectoryPublication current)
    {
        if (floor is null) return;
        if (!floor.LastForwardCheckpointCoreReference.IsEmpty)
            throw new CryptographicException(
                "This bounded artifact source has no verified network-forward checkpoint package.");
        if (floor.ViewGeneration > current.Generation)
            throw new CryptographicException("The canonical network snapshot is below the caller rollback floor.");
        if (floor.ViewGeneration != current.Generation) return;

        var view = current.Artifacts.Single(
            static artifact => artifact.Kind == DirectoryArtifactKind.CurrentNetworkView);
        var head = current.Artifacts.Single(
            static artifact => artifact.Kind == DirectoryArtifactKind.CurrentNetworkViewHead);
        RequireReference(floor.ViewCoreReference.Span, "XNV1", view.CoreHash.Span);
        RequireReference(floor.HeadCoreReference.Span, "XNH1", head.CoreHash.Span);
    }

    private static void RequireReference(
        ReadOnlySpan<byte> actual,
        string magic,
        ReadOnlySpan<byte> coreHash)
    {
        Span<byte> expected = stackalloc byte[38];
        Encoding.ASCII.GetBytes(magic, expected);
        expected[4] = 0;
        expected[5] = 1;
        coreHash.CopyTo(expected[6..]);
        if (!Fixed(actual, expected))
            throw new CryptographicException($"The caller {magic} rollback floor is a same-generation fork.");
    }

    private ArtifactBundle ReadBundle(string operationPath)
    {
        EnsureDirectory(rootPath);
        EnsureDirectory(operationPath);
        var inventoryPath = Child(operationPath, "inventory.json");
        var inventoryBytes = ReadExactFile(inventoryPath, null,
            FileContactResolveDirectoryArtifactInventoryCodec.MaximumInventoryBytes);
        var inventory = FileContactResolveDirectoryArtifactInventoryCodec.DecodeCanonical(inventoryBytes);
        ValidateInventory(inventory);
        long total = inventoryBytes.Length;
        var artifacts = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        foreach (var entry in inventory.Artifacts)
        {
            var path = Child(operationPath, entry.FileName);
            var bytes = ReadExactFile(path, entry.Length,
                ContactResolveDirectoryIssuedPackage.MaximumSingleArtifactBytes);
            var hash = SHA256.HashData(bytes);
            if (!Fixed(hash, Hex(entry.Sha256Hex, 32, "artifact SHA-256")))
                throw new CryptographicException("An exact canonical artifact differs from its inventory hash.");
            total = checked(total + bytes.Length);
            if (total > ContactResolveDirectoryIssuedPackage.MaximumPackageBytes)
                throw new InvalidDataException("The ContactResolve artifact inventory exceeds the package bound.");
            artifacts.Add(entry.FileName, bytes);
        }
        return new ArtifactBundle(inventoryBytes, inventory, artifacts);
    }

    private void CheckAndAdvanceState(
        ulong directoryGeneration,
        ReadOnlySpan<byte> directoryCoreHash,
        ulong networkGeneration,
        ReadOnlySpan<byte> networkCoreHash)
    {
        var previous = ReadState();
        if (previous is { Forked: true })
            throw new CryptographicException("The ContactResolve artifact source is latched on a prior fork.");
        if (previous is not null)
        {
            if (directoryGeneration < previous.DirectoryGeneration ||
                networkGeneration < previous.NetworkGeneration)
                throw new CryptographicException("The ContactResolve artifact source rejected rollback.");
            var directoryFork = directoryGeneration == previous.DirectoryGeneration &&
                !Fixed(directoryCoreHash, previous.DirectoryCoreHash);
            var networkFork = networkGeneration == previous.NetworkGeneration &&
                !Fixed(networkCoreHash, previous.NetworkCoreHash);
            if (directoryFork || networkFork)
            {
                WriteState(new SourceState(
                    previous.DirectoryGeneration, previous.DirectoryCoreHash,
                    previous.NetworkGeneration, previous.NetworkCoreHash, true));
                throw new CryptographicException("The ContactResolve artifact source detected a same-generation fork.");
            }
            if (directoryGeneration == previous.DirectoryGeneration &&
                networkGeneration == previous.NetworkGeneration)
                return;
        }
        WriteState(new SourceState(
            directoryGeneration, directoryCoreHash.ToArray(),
            networkGeneration, networkCoreHash.ToArray(), false));
    }

    private SourceState? ReadState()
    {
        if (!File.Exists(statePath)) return null;
        var encoded = DirectoryPublicationProtectedFile.ReadBounded(statePath, StatePayloadBytes + 32);
        var payload = DirectoryPublicationProtectedFile.Verify(encoded, integrityKey);
        if (payload.Length != StatePayloadBytes || !payload[..4].SequenceEqual(StateMagic) ||
            BinaryPrimitives.ReadUInt16BigEndian(payload[4..]) != 1 ||
            !Fixed(payload.Slice(6, 16), networkId) || payload[^1] > 1)
            throw new InvalidDataException("The protected ContactResolve artifact state is invalid.");
        return new SourceState(
            BinaryPrimitives.ReadUInt64BigEndian(payload[22..]), payload.Slice(30, 32).ToArray(),
            BinaryPrimitives.ReadUInt64BigEndian(payload[62..]), payload.Slice(70, 32).ToArray(),
            payload[102] == 1);
    }

    private void WriteState(SourceState state)
    {
        Span<byte> payload = stackalloc byte[StatePayloadBytes];
        StateMagic.CopyTo(payload);
        BinaryPrimitives.WriteUInt16BigEndian(payload[4..], 1);
        networkId.CopyTo(payload[6..]);
        BinaryPrimitives.WriteUInt64BigEndian(payload[22..], state.DirectoryGeneration);
        state.DirectoryCoreHash.CopyTo(payload[30..]);
        BinaryPrimitives.WriteUInt64BigEndian(payload[62..], state.NetworkGeneration);
        state.NetworkCoreHash.CopyTo(payload[70..]);
        payload[102] = state.Forked ? (byte)1 : (byte)0;
        var protectedBytes = DirectoryPublicationProtectedFile.Protect(payload, integrityKey);
        try { DirectoryPublicationProtectedFile.WriteAtomic(statePath, protectedBytes); }
        finally { CryptographicOperations.ZeroMemory(protectedBytes); }
    }

    private static byte[] ReadExactFile(string path, int? expectedLength, int maximumLength)
    {
        RejectReparseAncestors(Path.GetDirectoryName(path) ?? path);
        RejectReparse(path);
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read,
            64 * 1024, FileOptions.SequentialScan);
        if (stream.Length < 1 || stream.Length > maximumLength || stream.Length > int.MaxValue ||
            expectedLength is not null && stream.Length != expectedLength.Value)
            throw new InvalidDataException("A ContactResolve artifact has an invalid length.");
        var bytes = GC.AllocateUninitializedArray<byte>(checked((int)stream.Length));
        stream.ReadExactly(bytes);
        if (stream.ReadByte() != -1 || expectedLength is not null && bytes.Length != expectedLength.Value)
            throw new InvalidDataException("A ContactResolve artifact changed while it was read.");
        RejectReparse(path);
        RejectReparseAncestors(Path.GetDirectoryName(path) ?? path);
        return bytes;
    }

    private static string Child(string parent, string name)
    {
        if (string.IsNullOrWhiteSpace(name) || Path.IsPathRooted(name) ||
            name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 ||
            name.Contains(Path.DirectorySeparatorChar) || name.Contains(Path.AltDirectorySeparatorChar) ||
            name is "." or "..")
            throw new InvalidDataException("A ContactResolve artifact path component is invalid.");
        var child = Path.GetFullPath(Path.Combine(parent, name));
        if (!IsWithin(child, parent))
            throw new InvalidDataException("A ContactResolve artifact path escapes its configured root.");
        return child;
    }

    private static bool IsWithin(string candidate, string root)
    {
        var comparison = OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        var prefix = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root)) + Path.DirectorySeparatorChar;
        return Path.GetFullPath(candidate).StartsWith(prefix, comparison);
    }

    private static void EnsureDirectory(string path)
    {
        if (!Directory.Exists(path))
            throw new DirectoryNotFoundException("The configured read-only ContactResolve artifact directory is unavailable.");
        RejectReparseAncestors(path);
        RejectReparse(path);
    }

    private static StringComparer StringComparerForPaths => OperatingSystem.IsWindows()
        ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;

    private static void RejectReparseAncestors(string path)
    {
        var current = Path.GetFullPath(path);
        while (!string.IsNullOrWhiteSpace(current))
        {
            if (Directory.Exists(current) || File.Exists(current)) RejectReparse(current);
            var parent = Directory.GetParent(current)?.FullName;
            if (string.IsNullOrWhiteSpace(parent) || StringComparerForPaths.Equals(parent, current))
                break;
            current = parent;
        }
    }

    private static void RejectReparse(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException("Reparse points are forbidden in the ContactResolve artifact tree.");
    }

    private static byte[] Hex(string value, int expectedBytes, string name)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length != expectedBytes * 2)
            throw new InvalidDataException($"The {name} must contain exactly {expectedBytes * 2} hexadecimal characters.");
        try
        {
            var bytes = Convert.FromHexString(value);
            if (bytes.AsSpan().IndexOfAnyExcept((byte)0) < 0)
                throw new InvalidDataException($"The {name} cannot be all-zero.");
            return bytes;
        }
        catch (FormatException exception)
        {
            throw new InvalidDataException($"The {name} is not hexadecimal.", exception);
        }
    }

    private static void RequireCount(
        FileContactResolveDirectoryArtifactInventory inventory,
        string role,
        int? exact = null,
        int minimum = 0)
    {
        var count = inventory.Artifacts.Count(entry => entry.Role == role);
        if (exact is not null ? count != exact.Value : count < minimum)
            throw new InvalidDataException($"The ContactResolve inventory has an invalid {role} count.");
    }

    private static int RoleOrder(string role) => role switch
    {
        "xna1" => 0,
        "dts1" => 1,
        "adh1" => 2,
        "snapshot-dtt1" => 3,
        "snapshot-adp1" => 4,
        "xvp1" => 5,
        "xnv1" => 6,
        "xnh1" => 7,
        "xnd1" => 8,
        "pmt2" => 9,
        "response-adp1" => 10,
        "caller-adh1" => 11,
        _ => int.MaxValue,
    };

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(integrityKey);
        gate.Dispose();
    }

    private sealed class TrustedTimeClock(ContactResolveTrustedTimeContext value) :
        IDirectoryPublicationMonotonicClock
    {
        public ValueTask<DirectoryPublicationMonotonicReading> ReadAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(new DirectoryPublicationMonotonicReading(
                value.ServerBootId, value.ServerMonotonicSample));
        }
    }

    private sealed class ExactChallenge(FileContactResolveDirectoryArtifactInventory inventory) :
        IDirectoryPublicationLiveChallengeAuthority
    {
        public ValueTask<VerifiedDirectoryPublicationChallenge> VerifyAndConsumeAsync(
            ReadOnlyMemory<byte> nonce,
            ReadOnlyMemory<byte> bootId,
            ulong nonceCreatedAtMonotonicSeconds,
            ulong responseReceivedAtMonotonicSeconds,
            ulong currentMonotonicSeconds,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var expectedNonce = Hex(inventory.SnapshotNonceHex, 32, "snapshot nonce");
            var expectedBoot = Hex(inventory.SnapshotBootIdHex, 16, "snapshot boot ID");
            if (!Fixed(nonce.Span, expectedNonce) || !Fixed(bootId.Span, expectedBoot) ||
                nonceCreatedAtMonotonicSeconds != inventory.SnapshotNonceCreatedAt ||
                responseReceivedAtMonotonicSeconds != inventory.SnapshotResponseReceivedAt ||
                currentMonotonicSeconds != inventory.SnapshotCurrentSample)
                throw new CryptographicException("The exact artifact challenge tuple changed.");
            return ValueTask.FromResult(new VerifiedDirectoryPublicationChallenge(
                nonce.Span, bootId.Span, nonceCreatedAtMonotonicSeconds,
                responseReceivedAtMonotonicSeconds, currentMonotonicSeconds));
        }
    }

    private sealed class ArtifactBundle
    {
        private readonly byte[] inventoryBytes;
        private readonly Dictionary<string, byte[]> artifacts;

        internal ArtifactBundle(
            byte[] inventoryBytes,
            FileContactResolveDirectoryArtifactInventory inventory,
            Dictionary<string, byte[]> artifacts)
        {
            this.inventoryBytes = inventoryBytes;
            Inventory = inventory;
            this.artifacts = artifacts;
        }

        internal FileContactResolveDirectoryArtifactInventory Inventory { get; }

        internal int Count(string role) => Inventory.Artifacts.Count(entry => entry.Role == role);

        internal ReadOnlyMemory<byte> Single(string role)
        {
            var entry = Inventory.Artifacts.Single(value => value.Role == role);
            return artifacts[entry.FileName].ToArray();
        }

        internal IReadOnlyList<ReadOnlyMemory<byte>> Chain(string role) => Inventory.Artifacts
            .Where(entry => entry.Role == role)
            .Select(entry => (ReadOnlyMemory<byte>)artifacts[entry.FileName].ToArray())
            .ToArray();

        internal void RequireExact(ArtifactBundle other)
        {
            if (!Fixed(inventoryBytes, other.inventoryBytes) || artifacts.Count != other.artifacts.Count)
                throw new CryptographicException("The artifact inventory changed during verification.");
            foreach (var (name, bytes) in artifacts)
            {
                if (!other.artifacts.TryGetValue(name, out var second) || !Fixed(bytes, second))
                    throw new CryptographicException("An exact artifact changed during verification.");
            }
        }
    }

    private sealed class VerifiedOperation(
        ContactResolveCanonicalDirectorySnapshot snapshot,
        AccountDirectoryAdp1ProofMaterial proofMaterial,
        ReadOnlySpan<byte> requestNonce,
        ReadOnlySpan<byte> requestBootId,
        ulong requestNonceCreatedAt)
    {
        internal ContactResolveCanonicalDirectorySnapshot Snapshot { get; } = snapshot;
        internal AccountDirectoryAdp1ProofMaterial ProofMaterial { get; } = proofMaterial;
        internal byte[] RequestNonce { get; } = requestNonce.ToArray();
        internal byte[] RequestBootId { get; } = requestBootId.ToArray();
        internal ulong RequestNonceCreatedAt { get; } = requestNonceCreatedAt;
    }

    private sealed record SourceState(
        ulong DirectoryGeneration,
        byte[] DirectoryCoreHash,
        ulong NetworkGeneration,
        byte[] NetworkCoreHash,
        bool Forked);
}

internal static class FileContactResolveDirectoryArtifactSourceServiceCollectionExtensions
{
    internal static IServiceCollection AddFileContactResolveDirectoryArtifactSources(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);
        var section = configuration.GetSection("ContactResolveDirectoryArtifacts");
        var options = section.Get<FileContactResolveDirectoryArtifactSourceOptions>() ?? new();
        var configured = new[]
        {
            options.ReadOnlyRoot, options.StatePath, options.IntegrityKeyPath,
            options.NetworkIdHex, options.GenesisAuthorityCoreHashHex,
        };
        if (configured.All(string.IsNullOrWhiteSpace)) return services;
        if (configured.Any(string.IsNullOrWhiteSpace))
            throw new InvalidOperationException(
                "ContactResolveDirectoryArtifacts configuration must explicitly provide read-only root, protected state, integrity key, network and genesis authority hash.");

        var network = DirectoryPublicationHostingExtensions.Hex(
            options.NetworkIdHex, 16, "ContactResolve artifact network ID");
        var genesis = DirectoryPublicationHostingExtensions.Hex(
            options.GenesisAuthorityCoreHashHex, 32, "ContactResolve genesis authority core hash");
        services.TryAddSingleton<FileContactResolveDirectoryArtifactSource>(provider =>
            CreateSource(provider, options, network, genesis));
        services.TryAddSingleton<IContactResolveCanonicalDirectorySnapshotSource>(provider =>
            provider.GetRequiredService<FileContactResolveDirectoryArtifactSource>());
        services.TryAddSingleton<IContactResolveDirectoryProofMaterialSource>(provider =>
            provider.GetRequiredService<FileContactResolveDirectoryArtifactSource>());
        return services;
    }

    private static FileContactResolveDirectoryArtifactSource CreateSource(
        IServiceProvider provider,
        FileContactResolveDirectoryArtifactSourceOptions options,
        byte[] network,
        byte[] genesis)
    {
        var key = DirectoryPublicationProtectedFile.ReadKey(options.IntegrityKeyPath);
        try
        {
            return new FileContactResolveDirectoryArtifactSource(
                options.ReadOnlyRoot,
                options.StatePath,
                network,
                genesis,
                key,
                provider.GetRequiredService<IContactResolveTrustedTimeContextSource>(),
                provider.GetService<IContactResolveVerifiedAccountDirectoryCheckpointSource>());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }
}
#endif
