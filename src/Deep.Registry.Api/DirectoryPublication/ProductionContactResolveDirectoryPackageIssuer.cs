#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.XPointNetworkV1;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Deep.Registry.Api.DirectoryPublication;

internal readonly record struct ContactResolveTrustedTimeContext(
    ReadOnlyMemory<byte> ServerBootId,
    ulong ServerMonotonicSample,
    ulong ObservedUnixTime,
    uint UncertaintySeconds)
{
    internal void Validate()
    {
        if (ServerBootId.Length != 16 || ServerBootId.Span.IndexOfAnyExcept((byte)0) < 0)
            throw new CryptographicException("The trusted-time server boot ID is invalid.");
        if (ObservedUnixTime == 0 || UncertaintySeconds is < 1 or > 30 ||
            ObservedUnixTime <= UncertaintySeconds ||
            ObservedUnixTime > ulong.MaxValue - UncertaintySeconds)
            throw new CryptographicException("The trusted-time interval is invalid.");
    }
}

/// <summary>
/// Supplies an authenticated UTC interval advanced by a protected monotonic clock. OS wall time
/// alone is not a valid implementation of this boundary.
/// </summary>
internal interface IContactResolveTrustedTimeContextSource
{
    ValueTask<ContactResolveTrustedTimeContext> ReadAsync(CancellationToken cancellationToken);
}

/// <summary>
/// Atomically and durably consumes one client request. Implementations must reject a nonce that
/// was already consumed, regardless of a changed client boot ID or monotonic sample.
/// </summary>
internal interface IContactResolveOneUseRequestLedger
{
    ValueTask ConsumeAsync(
        ContactResolveDirectoryPackageRequest request,
        ContactResolveTrustedTimeContext trustedTime,
        AccountDirectoryDtt1IssuanceEpoch issuanceEpoch,
        CancellationToken cancellationToken);
}

/// <summary>
/// Supplies the exact current canonical directory/network closure and already-verified protocol
/// capabilities. It never derives authority from request bytes or from the publication catalog.
/// </summary>
internal interface IContactResolveCanonicalDirectorySnapshotSource
{
    ValueTask<ContactResolveCanonicalDirectorySnapshot> ReadAsync(
        ContactResolveDirectoryPackageRequest request,
        CancellationToken cancellationToken);
}

/// <summary>
/// Selects canonical sparse-map/append-log proof material from the current snapshot. A current
/// value can only be returned through the non-constructible VerifiedAccountDirectoryCheckpoint
/// capability carried by AccountDirectoryAdp1ProofMaterial.
/// </summary>
internal interface IContactResolveDirectoryProofMaterialSource
{
    ValueTask<AccountDirectoryAdp1ProofMaterial> ReadAsync(
        ContactResolveCanonicalDirectorySnapshot snapshot,
        ContactResolveDirectoryPackageRequest request,
        CancellationToken cancellationToken);
}

/// <summary>
/// Supplies a Protocol-verified ADC1 identity capability. Implementations are expected to verify
/// account identity/revocation/device closure outside the file transport; canonical bytes alone
/// can never be promoted to this capability.
/// </summary>
internal interface IContactResolveVerifiedAccountDirectoryCheckpointSource
{
    ValueTask<VerifiedAccountDirectoryCheckpoint?> ReadAsync(
        ReadOnlyMemory<byte> queriedDirectoryLeafKey,
        CancellationToken cancellationToken);
}

/// <summary>
/// Returns custody-backed witnesses for the exact current authority. The protocol author checks
/// membership, unique witness IDs, signatures and distinct failure-domain threshold.
/// </summary>
internal interface IContactResolveDtt1WitnessCustody
{
    ValueTask<IReadOnlyList<IAccountDirectoryDtt1WitnessSigner>> GetSignersAsync(
        VerifiedXPointNetworkAuthority authority,
        CancellationToken cancellationToken);
}

internal sealed class ContactResolveCanonicalDirectorySnapshot
{
    private readonly byte[] networkId;

    internal ContactResolveCanonicalDirectorySnapshot(
        ReadOnlySpan<byte> networkId,
        VerifiedXPointNetworkAuthority authority,
        AccountDirectoryProtectedLkg currentDirectoryHead,
        ReadOnlyMemory<byte> exactCurrentXnv1,
        ushort supportedReader,
        IReadOnlyList<ReadOnlyMemory<byte>> exactOrderedXna1AuthorityChain,
        IReadOnlyList<ReadOnlyMemory<byte>> exactOrderedDts1PolicyChain,
        IReadOnlyList<ReadOnlyMemory<byte>> exactOrderedXvp1Chain,
        IReadOnlyList<ReadOnlyMemory<byte>> exactOrderedXnv1Chain,
        IReadOnlyList<ReadOnlyMemory<byte>> exactOrderedXnh1Chain,
        IReadOnlyList<ReadOnlyMemory<byte>> exactActiveXnd1,
        IReadOnlyList<ReadOnlyMemory<byte>> exactOrderedPmt2Chain,
        ContactResolveForwardCheckpointPackage? forwardCheckpoint = null)
    {
        if (networkId.Length != 16 || networkId.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("The snapshot network ID must be 16 non-zero bytes.", nameof(networkId));
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(currentDirectoryHead);
        if (supportedReader == 0)
            throw new ArgumentOutOfRangeException(nameof(supportedReader));
        if (!CryptographicOperations.FixedTimeEquals(networkId, authority.NetworkId.Span) ||
            !CryptographicOperations.FixedTimeEquals(networkId, currentDirectoryHead.Head.NetworkId.Span))
            throw new CryptographicException("The verified authority and directory head are cross-network.");

        this.networkId = networkId.ToArray();
        Authority = authority;
        CurrentDirectoryHead = currentDirectoryHead;
        ExactCurrentXnv1 = CopyArtifact(exactCurrentXnv1, nameof(exactCurrentXnv1));
        SupportedReader = supportedReader;
        ExactOrderedXna1AuthorityChain = CopyChain(exactOrderedXna1AuthorityChain, nameof(exactOrderedXna1AuthorityChain));
        ExactOrderedDts1PolicyChain = CopyChain(exactOrderedDts1PolicyChain, nameof(exactOrderedDts1PolicyChain));
        ExactOrderedXvp1Chain = CopyChain(exactOrderedXvp1Chain, nameof(exactOrderedXvp1Chain));
        ExactOrderedXnv1Chain = CopyChain(exactOrderedXnv1Chain, nameof(exactOrderedXnv1Chain));
        ExactOrderedXnh1Chain = CopyChain(exactOrderedXnh1Chain, nameof(exactOrderedXnh1Chain));
        ExactActiveXnd1 = CopyChain(exactActiveXnd1, nameof(exactActiveXnd1));
        ExactOrderedPmt2Chain = CopyChain(exactOrderedPmt2Chain, nameof(exactOrderedPmt2Chain));
        if (ExactOrderedXnv1Chain.Count != ExactOrderedXnh1Chain.Count)
            throw new ArgumentException("The exact XNV1/XNH1 chains must be positionally complete.");
        ForwardCheckpoint = forwardCheckpoint;
    }

    internal ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    internal VerifiedXPointNetworkAuthority Authority { get; }
    internal AccountDirectoryProtectedLkg CurrentDirectoryHead { get; }
    internal ReadOnlyMemory<byte> ExactCurrentXnv1 { get; }
    internal ushort SupportedReader { get; }
    internal IReadOnlyList<ReadOnlyMemory<byte>> ExactOrderedXna1AuthorityChain { get; }
    internal IReadOnlyList<ReadOnlyMemory<byte>> ExactOrderedDts1PolicyChain { get; }
    internal IReadOnlyList<ReadOnlyMemory<byte>> ExactOrderedXvp1Chain { get; }
    internal IReadOnlyList<ReadOnlyMemory<byte>> ExactOrderedXnv1Chain { get; }
    internal IReadOnlyList<ReadOnlyMemory<byte>> ExactOrderedXnh1Chain { get; }
    internal IReadOnlyList<ReadOnlyMemory<byte>> ExactActiveXnd1 { get; }
    internal IReadOnlyList<ReadOnlyMemory<byte>> ExactOrderedPmt2Chain { get; }
    internal ContactResolveForwardCheckpointPackage? ForwardCheckpoint { get; }

    private static ReadOnlyMemory<byte> CopyArtifact(ReadOnlyMemory<byte> value, string name) =>
        ContactResolveDirectoryIssuedPackage.CopyArtifact(value, name);

    private static IReadOnlyList<ReadOnlyMemory<byte>> CopyChain(
        IReadOnlyList<ReadOnlyMemory<byte>> values,
        string name) => ContactResolveDirectoryIssuedPackage.CopyChain(
            values, ContactResolveDirectoryIssuedPackage.MaximumChainArtifacts, name);
}

internal sealed class ProductionContactResolveDirectoryPackageIssuer :
    IContactResolveDirectoryPackageIssuer
{
    private readonly IContactResolveCanonicalDirectorySnapshotSource snapshotSource;
    private readonly IContactResolveDirectoryProofMaterialSource proofSource;
    private readonly IContactResolveDtt1WitnessCustody witnessCustody;
    private readonly IContactResolveOneUseRequestLedger requestLedger;
    private readonly IContactResolveTrustedTimeContextSource trustedTimeSource;

    internal ProductionContactResolveDirectoryPackageIssuer(
        IContactResolveCanonicalDirectorySnapshotSource snapshotSource,
        IContactResolveDirectoryProofMaterialSource proofSource,
        IContactResolveDtt1WitnessCustody witnessCustody,
        IContactResolveOneUseRequestLedger requestLedger,
        IContactResolveTrustedTimeContextSource trustedTimeSource)
    {
        this.snapshotSource = snapshotSource ?? throw new ArgumentNullException(nameof(snapshotSource));
        this.proofSource = proofSource ?? throw new ArgumentNullException(nameof(proofSource));
        this.witnessCustody = witnessCustody ?? throw new ArgumentNullException(nameof(witnessCustody));
        this.requestLedger = requestLedger ?? throw new ArgumentNullException(nameof(requestLedger));
        this.trustedTimeSource = trustedTimeSource ?? throw new ArgumentNullException(nameof(trustedTimeSource));
    }

    public async ValueTask<ContactResolveDirectoryIssuedPackage> IssueAsync(
        ContactResolveDirectoryPackageRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();

        var trustedTime = await trustedTimeSource.ReadAsync(cancellationToken).ConfigureAwait(false);
        trustedTime.Validate();

        var snapshot = await snapshotSource.ReadAsync(request, cancellationToken).ConfigureAwait(false)
            ?? throw new ContactResolveDirectoryPackageUnavailableException();
        RequireExact(snapshot.NetworkId.Span, request.NetworkId.Span, "canonical snapshot network");
        var issuanceEpoch = AccountDirectoryDtt1IssuanceEpoch.Derive(
            snapshot.Authority, trustedTime.ObservedUnixTime, trustedTime.UncertaintySeconds);

        // The endpoint admission gate bounds read-only snapshot work. Durable one-use/quota
        // consumption still precedes proof construction and every witness-custody access.
        await requestLedger.ConsumeAsync(
            request, trustedTime, issuanceEpoch, cancellationToken).ConfigureAwait(false);
        var proof = await proofSource.ReadAsync(snapshot, request, cancellationToken).ConfigureAwait(false)
            ?? throw new ContactResolveDirectoryPackageUnavailableException();
        ValidateTargetedCurrentValue(request, snapshot, proof);
        var signers = await witnessCustody.GetSignersAsync(snapshot.Authority, cancellationToken)
            .ConfigureAwait(false) ?? throw new ContactResolveDirectoryPackageUnavailableException();

        var issuedAt = trustedTime.ObservedUnixTime - trustedTime.UncertaintySeconds;
        var expiresAt = trustedTime.ObservedUnixTime + trustedTime.UncertaintySeconds;
        var authorRequest = new AccountDirectoryProofAuthoringRequest(
            request.NetworkId.Span,
            request.Nonce.Span,
            request.BootId.Span,
            request.NonceCreatedAt,
            snapshot.CurrentDirectoryHead.ExactAdh1.Span,
            snapshot.ExactCurrentXnv1.Span,
            trustedTime.ObservedUnixTime,
            trustedTime.UncertaintySeconds,
            issuedAt,
            expiresAt,
            issuanceEpoch,
            snapshot.SupportedReader);
        var authored = await AccountDirectoryProofAuthor.IssueAsync(
            snapshot.Authority,
            snapshot.CurrentDirectoryHead,
            authorRequest,
            proof,
            signers,
            cancellationToken).ConfigureAwait(false);

        RequireExact(authored.NetworkId.Span, request.NetworkId.Span, "authored network");
        RequireExact(authored.Nonce.Span, request.Nonce.Span, "authored nonce");
        RequireExact(authored.BootId.Span, request.BootId.Span, "authored client boot ID");
        if (authored.ClientMonotonicSendSample != request.NonceCreatedAt)
            throw new CryptographicException("The authored proof changed the client monotonic echo.");

        return new ContactResolveDirectoryIssuedPackage(
            authored.NetworkId,
            authored.Nonce,
            authored.BootId,
            authored.ClientMonotonicSendSample,
            authored.QueriedDirectoryLeafKey,
            snapshot.ExactOrderedXna1AuthorityChain,
            snapshot.ExactOrderedDts1PolicyChain,
            authored.ExactAdh1,
            authored.ExactDtt1,
            authored.ExactAdp1,
            snapshot.ExactOrderedXvp1Chain,
            snapshot.ExactOrderedXnv1Chain,
            snapshot.ExactOrderedXnh1Chain,
            snapshot.ExactActiveXnd1,
            snapshot.ExactOrderedPmt2Chain,
            snapshot.ForwardCheckpoint);
    }

    internal static IContactResolveDirectoryPackageIssuer CreateFailClosed(
        IServiceProvider services)
    {
        ArgumentNullException.ThrowIfNull(services);
        var serviceProbe = services.GetService<IServiceProviderIsService>();
        if (serviceProbe is null ||
            !serviceProbe.IsService(typeof(IContactResolveCanonicalDirectorySnapshotSource)) ||
            !serviceProbe.IsService(typeof(IContactResolveDirectoryProofMaterialSource)) ||
            !serviceProbe.IsService(typeof(IContactResolveDtt1WitnessCustody)) ||
            !serviceProbe.IsService(typeof(IContactResolveOneUseRequestLedger)) ||
            !serviceProbe.IsService(typeof(IContactResolveTrustedTimeContextSource)))
            return new UnavailableContactResolveDirectoryPackageIssuer();

        return new ProductionContactResolveDirectoryPackageIssuer(
            services.GetRequiredService<IContactResolveCanonicalDirectorySnapshotSource>(),
            services.GetRequiredService<IContactResolveDirectoryProofMaterialSource>(),
            services.GetRequiredService<IContactResolveDtt1WitnessCustody>(),
            services.GetRequiredService<IContactResolveOneUseRequestLedger>(),
            services.GetRequiredService<IContactResolveTrustedTimeContextSource>());
    }

    /// <summary>
    /// Explicit offline/operator-only composition. This method is never registered in the HTTP
    /// service graph and requires every verified artifact, custody, clock and ledger boundary.
    /// </summary>
    internal static IContactResolveDirectoryPackageIssuer CreateForOfflineOperator(
        IServiceProvider services)
    {
        ArgumentNullException.ThrowIfNull(services);
        return new ProductionContactResolveDirectoryPackageIssuer(
            services.GetRequiredService<IContactResolveCanonicalDirectorySnapshotSource>(),
            services.GetRequiredService<IContactResolveDirectoryProofMaterialSource>(),
            services.GetRequiredService<IContactResolveDtt1WitnessCustody>(),
            services.GetRequiredService<IContactResolveOneUseRequestLedger>(),
            services.GetRequiredService<IContactResolveTrustedTimeContextSource>());
    }

    private static void ValidateTargetedCurrentValue(
        ContactResolveDirectoryPackageRequest request,
        ContactResolveCanonicalDirectorySnapshot snapshot,
        AccountDirectoryAdp1ProofMaterial proof)
    {
        if (request.ExpectedDirectoryLookupKey.IsEmpty)
        {
            if (request.RequireCurrentValue || request.MinimumAdhGeneration is not null ||
                !request.MinimumAdhHash.IsEmpty)
                throw new CryptographicException("The targeted current-value request is incomplete.");
            return;
        }
        if (request.ExpectedDirectoryLookupKey.Length != 32 ||
            request.MinimumAdhGeneration is null || request.MinimumAdhHash.Length != 32 ||
            !request.RequireCurrentValue)
            throw new CryptographicException("The targeted current-value request is incomplete.");
        if (!CryptographicOperations.FixedTimeEquals(
                request.ExpectedDirectoryLookupKey.Span, proof.QueriedDirectoryLeafKey.Span) ||
            proof.ResultKind != AccountDirectoryAdp1ResultKind.CurrentValue)
            throw new ContactResolveDirectoryTargetNotFoundException();

        var head = snapshot.CurrentDirectoryHead;
        if (head.LogGeneration < request.MinimumAdhGeneration.Value)
            throw new ContactResolveDirectoryTargetNotFoundException();
        if (head.LogGeneration == request.MinimumAdhGeneration.Value &&
            !CryptographicOperations.FixedTimeEquals(
                head.CoreHash.Span, request.MinimumAdhHash.Span))
            throw new ContactResolveDirectoryTargetNotFoundException();
        if (head.LogGeneration > request.MinimumAdhGeneration.Value)
        {
            var callerFloor = proof.CallerProtectedLkg;
            if (callerFloor is null ||
                callerFloor.LogGeneration != request.MinimumAdhGeneration.Value ||
                !CryptographicOperations.FixedTimeEquals(
                    callerFloor.CoreHash.Span, request.MinimumAdhHash.Span))
                throw new ContactResolveDirectoryTargetNotFoundException();
        }
    }

    private static void RequireExact(ReadOnlySpan<byte> actual, ReadOnlySpan<byte> expected, string name)
    {
        if (actual.Length != expected.Length || !CryptographicOperations.FixedTimeEquals(actual, expected))
            throw new CryptographicException($"The {name} is not bound to the request.");
    }
}

internal static class ProductionContactResolveDirectoryPackageServiceCollectionExtensions
{
    /// <summary>
    /// Activates the production issuer only when every authority/custody/persistence dependency
    /// has been explicitly registered. Otherwise requests deterministically remain unavailable.
    /// </summary>
    internal static IServiceCollection AddProductionContactResolveDirectoryPackageIssuer(
        this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.RemoveAll<IContactResolveDirectoryPackageIssuer>();
        services.AddSingleton(ProductionContactResolveDirectoryPackageIssuer.CreateFailClosed);
        return services;
    }

    /// <summary>
    /// UAT/test composition uses the exact production issuer and requires every dependency from
    /// the caller. It creates no signer, proof, clock or persistence fallback.
    /// </summary>
    internal static IServiceCollection AddContactResolveDirectoryPackageIssuerForUat(
        this IServiceCollection services,
        IContactResolveCanonicalDirectorySnapshotSource snapshotSource,
        IContactResolveDirectoryProofMaterialSource proofSource,
        IContactResolveDtt1WitnessCustody witnessCustody,
        IContactResolveOneUseRequestLedger requestLedger,
        IContactResolveTrustedTimeContextSource trustedTimeSource)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.RemoveAll<IContactResolveDirectoryPackageIssuer>();
        services.AddSingleton(snapshotSource ?? throw new ArgumentNullException(nameof(snapshotSource)));
        services.AddSingleton(proofSource ?? throw new ArgumentNullException(nameof(proofSource)));
        services.AddSingleton(witnessCustody ?? throw new ArgumentNullException(nameof(witnessCustody)));
        services.AddSingleton(requestLedger ?? throw new ArgumentNullException(nameof(requestLedger)));
        services.AddSingleton(trustedTimeSource ?? throw new ArgumentNullException(nameof(trustedTimeSource)));
        services.AddSingleton<IContactResolveDirectoryPackageIssuer>(serviceProvider =>
            new ProductionContactResolveDirectoryPackageIssuer(
                serviceProvider.GetRequiredService<IContactResolveCanonicalDirectorySnapshotSource>(),
                serviceProvider.GetRequiredService<IContactResolveDirectoryProofMaterialSource>(),
                serviceProvider.GetRequiredService<IContactResolveDtt1WitnessCustody>(),
                serviceProvider.GetRequiredService<IContactResolveOneUseRequestLedger>(),
                serviceProvider.GetRequiredService<IContactResolveTrustedTimeContextSource>()));
        return services;
    }
}

/// <summary>
/// Protected, exact and process-safe one-use ledger. Every nonce becomes a sharded authenticated
/// marker. Marker existence is authoritative even after a partial crash write, so corruption can
/// reduce availability but can never reopen a consumed nonce.
/// </summary>
internal sealed class ProtectedFileContactResolveOneUseRequestLedger :
    IContactResolveOneUseRequestLedger,
    IDisposable
{
    private static ReadOnlySpan<byte> Magic => "CRL1"u8;
    private static ReadOnlySpan<byte> StateMagic => "CRS1"u8;
    private const int PayloadBytes = 4 + 2 + 16 + 8 + 32 + 32 + 16 + 8 + 16 + 8 + 8;
    private const int StatePayloadBytes = 4 + 2 + 16 + 8 + 32 + 4 + 8;
    private readonly string rootPath;
    private readonly string statePath;
    private readonly byte[] networkId;
    private readonly byte[] integrityKey;
    private readonly int capacity;
    private readonly int compactionInterval;

    internal ProtectedFileContactResolveOneUseRequestLedger(
        string rootPath,
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> integrityKey,
        int capacity = 65_536,
        int compactionInterval = 1_024)
    {
        if (string.IsNullOrWhiteSpace(rootPath))
            throw new ArgumentException("A ContactResolve request-ledger path is required.", nameof(rootPath));
        if (networkId.Length != 16 || networkId.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("A non-zero 16-byte network ID is required.", nameof(networkId));
        if (integrityKey.Length != 32 || integrityKey.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("A non-zero 32-byte integrity key is required.", nameof(integrityKey));
        // The production options enforce the operational floor. Smaller values keep the bounded
        // state machine directly testable without thousands of durable filesystem mutations.
        if (capacity is < 16 or > 1_000_000)
            throw new ArgumentOutOfRangeException(nameof(capacity));
        if (compactionInterval is < 1 or > 16_384)
            throw new ArgumentOutOfRangeException(nameof(compactionInterval));
        this.rootPath = Path.GetFullPath(rootPath);
        RejectReparseDirectoryIfPresent(this.rootPath);
        statePath = Path.Combine(this.rootPath, ".quota.state");
        this.networkId = networkId.ToArray();
        this.integrityKey = integrityKey.ToArray();
        this.capacity = capacity;
        this.compactionInterval = compactionInterval;
    }

    public ValueTask ConsumeAsync(
        ContactResolveDirectoryPackageRequest request,
        ContactResolveTrustedTimeContext trustedTime,
        AccountDirectoryDtt1IssuanceEpoch issuanceEpoch,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        trustedTime.Validate();
        ArgumentNullException.ThrowIfNull(issuanceEpoch);
        if (!CryptographicOperations.FixedTimeEquals(request.NetworkId.Span, networkId))
            throw new CryptographicException("The request ledger rejected a different network.");

        Span<byte> digestInput = stackalloc byte[88];
        networkId.CopyTo(digestInput);
        BinaryPrimitives.WriteUInt64BigEndian(digestInput[16..], issuanceEpoch.Number);
        issuanceEpoch.Id.Span.CopyTo(digestInput[24..]);
        request.Nonce.Span.CopyTo(digestInput[56..]);
        var digest = HMACSHA256.HashData(integrityKey, digestInput);
        var hex = Convert.ToHexString(digest);
        var firstShard = Path.Combine(rootPath, hex[..2]);
        var shard = Path.Combine(firstShard, hex.Substring(2, 2));
        var marker = Path.Combine(shard, hex[4..] + ".request");
        var payload = new byte[PayloadBytes];
        Magic.CopyTo(payload);
        BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(4), 2);
        networkId.CopyTo(payload, 6);
        BinaryPrimitives.WriteUInt64BigEndian(payload.AsSpan(22), issuanceEpoch.Number);
        issuanceEpoch.Id.Span.CopyTo(payload.AsSpan(30));
        digest.CopyTo(payload, 62);
        request.BootId.Span.CopyTo(payload.AsSpan(94));
        BinaryPrimitives.WriteUInt64BigEndian(payload.AsSpan(110), request.NonceCreatedAt);
        trustedTime.ServerBootId.Span.CopyTo(payload.AsSpan(118));
        BinaryPrimitives.WriteUInt64BigEndian(payload.AsSpan(134), trustedTime.ServerMonotonicSample);
        BinaryPrimitives.WriteUInt64BigEndian(payload.AsSpan(142), trustedTime.ObservedUnixTime);
        var protectedMarker = DirectoryPublicationProtectedFile.Protect(payload, integrityKey);

        try
        {
            Directory.CreateDirectory(rootPath);
            RejectReparseDirectory(rootPath);
            using var lease = DirectoryPublicationProtectedFile.AcquireLease(statePath, cancellationToken);
            if (File.Exists(marker))
            {
                if ((File.GetAttributes(marker) & FileAttributes.ReparsePoint) != 0)
                    throw new InvalidDataException(
                        "Reparse points are forbidden in the ContactResolve request ledger.");
                throw new CryptographicException("The ContactResolve request nonce was already consumed.");
            }

            var state = ReadStateOrCompact(issuanceEpoch);
            if (state.Count >= capacity || state.Revision % (ulong)compactionInterval == 0)
                state = Compact(issuanceEpoch, state.Revision);
            if (state.Count >= capacity)
                throw new ContactResolveDirectoryAdmissionException(
                    "The ContactResolve request ledger reached its bounded capacity.");

            // Reserve quota first. A crash after this write can only over-count and reduce
            // availability; it cannot create an unaccounted marker or reopen a nonce.
            var reserved = new LedgerState(state.Count + 1, checked(state.Revision + 1));
            WriteState(reserved, issuanceEpoch);

            Directory.CreateDirectory(firstShard);
            RejectReparseDirectory(firstShard);
            Directory.CreateDirectory(shard);
            RejectReparseDirectory(shard);
            using var stream = new FileStream(
                marker,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                4096,
                FileOptions.WriteThrough);
            stream.Write(protectedMarker);
            stream.Flush(true);
        }
        catch (IOException) when (File.Exists(marker))
        {
            throw new CryptographicException("The ContactResolve request nonce was already consumed.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(digestInput);
            CryptographicOperations.ZeroMemory(digest);
            CryptographicOperations.ZeroMemory(payload);
            CryptographicOperations.ZeroMemory(protectedMarker);
        }
        return ValueTask.CompletedTask;
    }

    public void Dispose() => CryptographicOperations.ZeroMemory(integrityKey);

    private LedgerState ReadStateOrCompact(AccountDirectoryDtt1IssuanceEpoch issuanceEpoch)
    {
        if (!File.Exists(statePath)) return Compact(issuanceEpoch, 0);
        var encoded = DirectoryPublicationProtectedFile.ReadBounded(
            statePath, StatePayloadBytes + 32);
        try
        {
            var payload = DirectoryPublicationProtectedFile.Verify(encoded, integrityKey);
            if (payload.Length != StatePayloadBytes || !payload[..4].SequenceEqual(StateMagic) ||
                BinaryPrimitives.ReadUInt16BigEndian(payload[4..]) != 2 ||
                !CryptographicOperations.FixedTimeEquals(payload.Slice(6, 16), networkId))
                throw new InvalidDataException("The ContactResolve request-ledger quota state is invalid.");
            var storedEpochNumber = BinaryPrimitives.ReadUInt64BigEndian(payload[22..]);
            var revision = BinaryPrimitives.ReadUInt64BigEndian(payload[66..]);
            var sameEpochId = CryptographicOperations.FixedTimeEquals(
                payload.Slice(30, 32), issuanceEpoch.Id.Span);
            if (storedEpochNumber > issuanceEpoch.Number ||
                storedEpochNumber == issuanceEpoch.Number && !sameEpochId)
                throw new CryptographicException(
                    "The ContactResolve request ledger rejected an issuance-epoch rollback or fork.");
            if (storedEpochNumber < issuanceEpoch.Number)
                return Compact(issuanceEpoch, revision);
            var count = BinaryPrimitives.ReadUInt32BigEndian(payload[62..]);
            if (count > capacity || revision < count)
                throw new InvalidDataException("The ContactResolve request-ledger quota state is invalid.");
            return new LedgerState(checked((int)count), revision);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encoded);
        }
    }

    private LedgerState Compact(
        AccountDirectoryDtt1IssuanceEpoch issuanceEpoch,
        ulong priorRevision)
    {
        var count = 0;
        var inspected = 0;
        var enumeration = new EnumerationOptions
        {
            RecurseSubdirectories = true,
            IgnoreInaccessible = false,
            AttributesToSkip = FileAttributes.ReparsePoint,
            MatchType = MatchType.Simple,
        };
        foreach (var marker in Directory.EnumerateFiles(rootPath, "*.request", enumeration))
        {
            if (++inspected > checked(capacity * 2))
                throw new InvalidDataException(
                    "The ContactResolve request ledger exceeds its bounded recovery scan.");
            var encoded = DirectoryPublicationProtectedFile.ReadBounded(marker, PayloadBytes + 32);
            try
            {
                var payload = DirectoryPublicationProtectedFile.Verify(encoded, integrityKey);
                var isCurrent = ValidateMarker(payload, marker, issuanceEpoch);
                if (isCurrent)
                {
                    count++;
                }
                else
                {
                    File.Delete(marker);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(encoded);
            }
        }
        var nextRevision = Math.Max(checked(priorRevision + 1), checked((ulong)count));
        var compacted = new LedgerState(count, nextRevision);
        WriteState(compacted, issuanceEpoch);
        return compacted;
    }

    private bool ValidateMarker(
        ReadOnlySpan<byte> payload,
        string marker,
        AccountDirectoryDtt1IssuanceEpoch issuanceEpoch)
    {
        if (payload.Length != PayloadBytes || !payload[..4].SequenceEqual(Magic) ||
            BinaryPrimitives.ReadUInt16BigEndian(payload[4..]) != 2 ||
            !CryptographicOperations.FixedTimeEquals(payload.Slice(6, 16), networkId))
            throw new InvalidDataException("A ContactResolve request-ledger marker is invalid.");
        var relative = Path.GetRelativePath(rootPath, marker);
        var parts = relative.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (parts.Length != 3 || parts[0].Length != 2 || parts[1].Length != 2 ||
            !parts[2].EndsWith(".request", StringComparison.Ordinal) || parts[2].Length != 68)
            throw new InvalidDataException("A ContactResolve request-ledger marker path is invalid.");
        byte[] pathDigest;
        try
        {
            pathDigest = Convert.FromHexString(parts[0] + parts[1] + parts[2][..^8]);
        }
        catch (FormatException exception)
        {
            throw new InvalidDataException(
                "A ContactResolve request-ledger marker path is invalid.", exception);
        }
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(pathDigest, payload.Slice(62, 32)))
                throw new InvalidDataException(
                    "A ContactResolve request-ledger marker path is not bound to its payload.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pathDigest);
        }
        var markerEpochNumber = BinaryPrimitives.ReadUInt64BigEndian(payload[22..]);
        if (markerEpochNumber > issuanceEpoch.Number ||
            markerEpochNumber == issuanceEpoch.Number &&
            !CryptographicOperations.FixedTimeEquals(payload.Slice(30, 32), issuanceEpoch.Id.Span))
            throw new CryptographicException(
                "The ContactResolve request ledger rejected an issuance-epoch rollback or fork.");
        return markerEpochNumber == issuanceEpoch.Number;
    }

    private void WriteState(
        LedgerState state,
        AccountDirectoryDtt1IssuanceEpoch issuanceEpoch)
    {
        Span<byte> payload = stackalloc byte[StatePayloadBytes];
        StateMagic.CopyTo(payload);
        BinaryPrimitives.WriteUInt16BigEndian(payload[4..], 2);
        networkId.CopyTo(payload[6..]);
        BinaryPrimitives.WriteUInt64BigEndian(payload[22..], issuanceEpoch.Number);
        issuanceEpoch.Id.Span.CopyTo(payload[30..]);
        BinaryPrimitives.WriteUInt32BigEndian(payload[62..], checked((uint)state.Count));
        BinaryPrimitives.WriteUInt64BigEndian(payload[66..], state.Revision);
        var encoded = DirectoryPublicationProtectedFile.Protect(payload, integrityKey);
        try
        {
            DirectoryPublicationProtectedFile.WriteAtomic(statePath, encoded);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(payload);
            CryptographicOperations.ZeroMemory(encoded);
        }
    }

    private static void RejectReparseDirectoryIfPresent(string path)
    {
        if (Directory.Exists(path)) RejectReparseDirectory(path);
    }

    private static void RejectReparseDirectory(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException(
                "Reparse points are forbidden in the ContactResolve request ledger.");
    }

    private readonly record struct LedgerState(int Count, ulong Revision);
}
#endif
