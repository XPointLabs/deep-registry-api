#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;

namespace Deep.Registry.Api.DirectoryPublication;

/// <summary>
/// A DID2-only leaf query. The public reader must still verify an ADL1 V2
/// against an independently verified DAB2 before trusting the result.
/// </summary>
internal sealed class DeepIdV2DirectoryProofRequest
{
    private readonly byte[] networkId;
    private readonly byte[] nonce;
    private readonly byte[] bootId;
    private readonly byte[] leaf;
    private readonly byte[]? minimumAdhHash;

    internal DeepIdV2DirectoryProofRequest(ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> bootId,
        ulong clientMonotonicSendSample, ReadOnlySpan<byte> directoryLeafKey,
        AccountDirectoryProtectedLkg? callerProtectedLkg = null)
    {
        this.networkId = Required(networkId, 16, nameof(networkId));
        this.nonce = Required(nonce, 32, nameof(nonce));
        this.bootId = Required(bootId, 16, nameof(bootId));
        leaf = Required(directoryLeafKey, 32, nameof(directoryLeafKey));
        ClientMonotonicSendSample = clientMonotonicSendSample;
        CallerProtectedLkg = callerProtectedLkg;
    }

    internal DeepIdV2DirectoryProofRequest(
        DeepIdV2DirectoryProofWireRequest wire)
        : this((wire ?? throw new ArgumentNullException(
                   nameof(wire))).NetworkId.Span, wire.Nonce.Span, wire.BootId.Span,
            wire.ClientMonotonicSendSample, wire.DirectoryLeafKey.Span)
    {
        MinimumAdhGeneration = wire.Lookup.MinimumAdhGeneration;
        minimumAdhHash = wire.Lookup.MinimumAdhHash.ToArray();
    }

    internal ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    internal ReadOnlyMemory<byte> Nonce => nonce.ToArray();
    internal ReadOnlyMemory<byte> BootId => bootId.ToArray();
    internal ReadOnlyMemory<byte> DirectoryLeafKey => leaf.ToArray();
    internal ulong ClientMonotonicSendSample { get; }
    internal AccountDirectoryProtectedLkg? CallerProtectedLkg { get; }
    internal ulong? MinimumAdhGeneration { get; }
    internal ReadOnlyMemory<byte> MinimumAdhHash =>
        minimumAdhHash?.ToArray() ?? [];

    private static byte[] Required(ReadOnlySpan<byte> value, int length,
        string name)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException(
                $"{name} must be {length} nonzero bytes.", name);
        return value.ToArray();
    }
}

internal interface IDeepIdV2CurrentViewSource
{
    ValueTask<ReadOnlyMemory<byte>> ReadExactXnv1Async(
        CancellationToken cancellationToken);
}

internal sealed class DeepIdV2FileCurrentViewSource :
    IDeepIdV2CurrentViewSource
{
    private readonly string exactXnv1Path;

    internal DeepIdV2FileCurrentViewSource(string exactXnv1Path)
    {
        if (string.IsNullOrWhiteSpace(exactXnv1Path))
            throw new ArgumentException("A DID2 current XNV1 path is required.",
                nameof(exactXnv1Path));
        this.exactXnv1Path = Path.GetFullPath(exactXnv1Path);
    }

    public ValueTask<ReadOnlyMemory<byte>> ReadExactXnv1Async(
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult<ReadOnlyMemory<byte>>(
            DeepIdV2XPointAuthoritySource.ReadExact(exactXnv1Path));
    }
}

/// <summary>
/// Issues a nonce-bound V2 proof only from authenticated ADA2 state, an
/// independently verified XNA1/DTS1 authority, signed XNV1, trusted time,
/// a durable one-use ledger and custody-backed threshold witnesses. It is
/// exposed over HTTP only in Development/UAT. Production registration still
/// requires an independent ADA2 latest-head floor and client cutover.
/// </summary>
internal sealed class DeepIdV2DirectoryProofIssuer : IDisposable
{
    private readonly DeepIdV2XPointAuthoritySource networkAuthoritySource;
    private readonly DeepIdV2DirectoryBootstrapSource bootstrapSource;
    private readonly IDeepIdV2CurrentViewSource currentViewSource;
    private readonly IContactResolveDtt1WitnessCustody witnessCustody;
    private readonly IContactResolveOneUseRequestLedger requestLedger;
    private readonly IContactResolveTrustedTimeContextSource trustedTimeSource;
    private readonly string statePath;
    private readonly byte[] networkId;
    private readonly byte[] integrityKey;
    private readonly IDeepIdV2DirectoryLatestHeadFloor? latestHeadFloor;
    private readonly ushort deploymentProfileId;
    private bool disposed;

    internal DeepIdV2DirectoryProofIssuer(
        DeepIdV2XPointAuthoritySource networkAuthoritySource,
        DeepIdV2DirectoryBootstrapSource bootstrapSource,
        IDeepIdV2CurrentViewSource currentViewSource,
        IContactResolveDtt1WitnessCustody witnessCustody,
        IContactResolveOneUseRequestLedger requestLedger,
        IContactResolveTrustedTimeContextSource trustedTimeSource,
        string statePath, ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> integrityKey, ushort deploymentProfileId,
        IDeepIdV2DirectoryLatestHeadFloor? latestHeadFloor = null)
    {
        this.networkAuthoritySource = networkAuthoritySource ??
            throw new ArgumentNullException(nameof(networkAuthoritySource));
        this.bootstrapSource = bootstrapSource ??
            throw new ArgumentNullException(nameof(bootstrapSource));
        this.currentViewSource = currentViewSource ??
            throw new ArgumentNullException(nameof(currentViewSource));
        this.witnessCustody = witnessCustody ??
            throw new ArgumentNullException(nameof(witnessCustody));
        this.requestLedger = requestLedger ??
            throw new ArgumentNullException(nameof(requestLedger));
        this.trustedTimeSource = trustedTimeSource ??
            throw new ArgumentNullException(nameof(trustedTimeSource));
        if (string.IsNullOrWhiteSpace(statePath) || networkId.Length != 16 ||
            networkId.IndexOfAnyExcept((byte)0) < 0 ||
            integrityKey.Length != 32 ||
            integrityKey.IndexOfAnyExcept((byte)0) < 0 ||
            deploymentProfileId == 0)
            throw new ArgumentException("DID2 proof issuer configuration is invalid.");
        this.statePath = Path.GetFullPath(statePath);
        this.networkId = networkId.ToArray();
        this.integrityKey = integrityKey.ToArray();
        this.latestHeadFloor = latestHeadFloor;
        this.deploymentProfileId = deploymentProfileId;
    }

    internal async ValueTask<AuthoredDeepIdV2DirectoryProofPackage> IssueAsync(
        DeepIdV2DirectoryProofRequest request,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        if (!Fixed(request.NetworkId.Span, networkId))
            throw new CryptographicException("DID2 proof request belongs to another network.");
        var trusted = await trustedTimeSource.ReadAsync(cancellationToken)
            .ConfigureAwait(false);
        trusted.Validate();
        var upper = checked(trusted.ObservedUnixTime + trusted.UncertaintySeconds);
        var authority = networkAuthoritySource.Read();
        var epoch = AccountDirectoryDtt1IssuanceEpoch.Derive(authority,
            trusted.ObservedUnixTime, trusted.UncertaintySeconds);

        // The one-use marker is durable before witness custody or PQ proof work.
        var ledgerRequest = new ContactResolveDirectoryPackageRequest(
            networkId, request.Nonce.ToArray(), request.BootId.ToArray(),
            request.ClientMonotonicSendSample, null, null, null);
        await requestLedger.ConsumeAsync(ledgerRequest, trusted, epoch,
            cancellationToken).ConfigureAwait(false);

        using var mlDsa65 = DeepMlDsa65CandidateVerifierFactory
            .OpenForCurrentProcess();
        using var store = new DeepIdV2DirectoryStateStore(statePath,
            integrityKey, networkId, bootstrapSource, authority,
            mlDsa65, deploymentProfileId, latestHeadFloor);
        using var lease = store.Open(cancellationToken);
        var restored = await lease.ReadAsync(upper, cancellationToken)
            .ConfigureAwait(false);
        var callerFloor = ResolveCallerFloor(restored, request);
        var material = lease.CreateProofMaterial(request.DirectoryLeafKey.Span,
            callerFloor);
        var exactXnv1 = await currentViewSource.ReadExactXnv1Async(
            cancellationToken).ConfigureAwait(false);
        var authorRequest = new AccountDirectoryProofAuthoringRequest(
            networkId, request.Nonce.Span, request.BootId.Span,
            request.ClientMonotonicSendSample,
            restored.CurrentHead.ExactAdh1.Span, exactXnv1.Span,
            trusted.ObservedUnixTime, trusted.UncertaintySeconds,
            trusted.ObservedUnixTime - trusted.UncertaintySeconds,
            upper, epoch, supportedReader: 2);
        var signers = await witnessCustody.GetSignersAsync(authority,
            cancellationToken).ConfigureAwait(false);
        return await DeepIdV2DirectoryProofAuthor.IssueGenesisAsync(
            authority, authorRequest, material, signers,
            deploymentProfileId, mlDsa65, cancellationToken)
            .ConfigureAwait(false);
    }

    internal async ValueTask<byte[]> IssueWireAsync(
        DeepIdV2DirectoryProofWireRequest wire,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(wire);
        var issued = await IssueAsync(new DeepIdV2DirectoryProofRequest(wire),
            cancellationToken).ConfigureAwait(false);
        return DeepIdV2DirectoryProofWireCodec.EncodeResponse(wire, issued);
    }

    private static AccountDirectoryProtectedLkg? ResolveCallerFloor(
        DeepIdV2RestoredAuthorityState restored,
        DeepIdV2DirectoryProofRequest request)
    {
        if (request.MinimumAdhGeneration is not { } generation)
            return request.CallerProtectedLkg;
        var hash = request.MinimumAdhHash.ToArray();
        var matching = restored.Heads.FirstOrDefault(head =>
            head.LogGeneration == generation &&
            Fixed(head.CoreHash.Span, hash));
        if (matching is null)
            throw new ContactResolveDirectoryTargetNotFoundException();
        return matching.LogGeneration == restored.CurrentHead.LogGeneration
            ? null : matching;
    }

    public void Dispose()
    {
        if (disposed) return;
        disposed = true;
        CryptographicOperations.ZeroMemory(networkId);
        CryptographicOperations.ZeroMemory(integrityKey);
    }

    private static bool Fixed(ReadOnlySpan<byte> left,
        ReadOnlySpan<byte> right) => left.Length == right.Length &&
        CryptographicOperations.FixedTimeEquals(left, right);
}
#endif
