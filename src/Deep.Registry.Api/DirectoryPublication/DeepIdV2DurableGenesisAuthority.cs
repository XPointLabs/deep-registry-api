#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;

namespace Deep.Registry.Api.DirectoryPublication;

internal sealed class DeepIdV2AuthorityConflictException(string message)
    : CryptographicException(message);

internal interface IDeepIdV2GenesisAuthority
{
    ValueTask<DeepIdV2GenesisAdmissionReceipt> AdmitAsync(
        DeepIdV2GenesisAdmissionWireRequest request,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// DID2-only admission. The network lineage, empty head, ADA2 journal and
/// ML-DSA verifier are independently pinned; no ADA1 state is read or written.
/// HTTP publication and directory-proof issuance remain separate boundaries.
/// </summary>
internal sealed class DeepIdV2DurableGenesisAuthority :
    IDeepIdV2GenesisAuthority, IDisposable
{
    private readonly DeepIdV2XPointAuthoritySource networkAuthoritySource;
    private readonly DeepIdV2DirectoryBootstrapSource bootstrapSource;
    private readonly FileContactResolveDtt1WitnessCustody witnessCustody;
    private readonly IContactResolveTrustedTimeContextSource trustedTimeSource;
    private readonly string statePath;
    private readonly byte[] networkId;
    private readonly byte[] integrityKey;
    private readonly IDeepIdV2DirectoryLatestHeadFloor? latestHeadFloor;
    private readonly ushort deploymentProfileId;
    private readonly ulong headValiditySeconds;
    private readonly SemaphoreSlim gate = new(1, 1);
    private bool disposed;

    internal DeepIdV2DurableGenesisAuthority(
        DeepIdV2XPointAuthoritySource networkAuthoritySource,
        DeepIdV2DirectoryBootstrapSource bootstrapSource,
        FileContactResolveDtt1WitnessCustody witnessCustody,
        IContactResolveTrustedTimeContextSource trustedTimeSource,
        string statePath, ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> integrityKey, ushort deploymentProfileId,
        ulong headValiditySeconds,
        IDeepIdV2DirectoryLatestHeadFloor? latestHeadFloor = null)
    {
        this.networkAuthoritySource = networkAuthoritySource ??
            throw new ArgumentNullException(nameof(networkAuthoritySource));
        this.bootstrapSource = bootstrapSource ??
            throw new ArgumentNullException(nameof(bootstrapSource));
        this.witnessCustody = witnessCustody ??
            throw new ArgumentNullException(nameof(witnessCustody));
        this.trustedTimeSource = trustedTimeSource ??
            throw new ArgumentNullException(nameof(trustedTimeSource));
        if (string.IsNullOrWhiteSpace(statePath) || networkId.Length != 16 ||
            networkId.IndexOfAnyExcept((byte)0) < 0 ||
            integrityKey.Length != 32 ||
            integrityKey.IndexOfAnyExcept((byte)0) < 0 ||
            deploymentProfileId == 0 || headValiditySeconds is < 300 or > 86_400)
            throw new ArgumentException("DID2 durable authority configuration is invalid.");
        this.statePath = Path.GetFullPath(statePath);
        this.networkId = networkId.ToArray();
        this.integrityKey = integrityKey.ToArray();
        this.latestHeadFloor = latestHeadFloor;
        this.deploymentProfileId = deploymentProfileId;
        this.headValiditySeconds = headValiditySeconds;
    }

    /// <summary>
    /// Production startup barrier. No HTTP endpoint may open until the
    /// trusted time, signed authority, complete ADA2 journal and independent
    /// exact-head floor agree. This performs no admission or floor mutation.
    /// </summary>
    internal async ValueTask RequireReadyAsync(
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if (latestHeadFloor is null)
            throw new InvalidOperationException(
                "Production DID2 requires an independent latest-head floor.");
        var trusted = await trustedTimeSource.ReadAsync(cancellationToken)
            .ConfigureAwait(false);
        trusted.Validate();
        var lower = trusted.ObservedUnixTime - trusted.UncertaintySeconds;
        var upper = checked(trusted.ObservedUnixTime + trusted.UncertaintySeconds);
        var authority = networkAuthoritySource.Read();
        if (!CryptographicOperations.FixedTimeEquals(
                authority.NetworkId.Span, networkId) ||
            lower < authority.NotBefore || upper >= authority.ExpiresAt)
            throw new CryptographicException(
                "Production DID2 authority does not cover the trusted-time interval.");
        using var verifier = DeepMlDsa65CandidateVerifierFactory
            .OpenForCurrentProcess();
        using var store = new DeepIdV2DirectoryStateStore(statePath,
            integrityKey, networkId, bootstrapSource, authority, verifier,
            deploymentProfileId, latestHeadFloor);
        using var lease = store.Open(cancellationToken);
        var restored = await lease.ReadAsync(upper, cancellationToken)
            .ConfigureAwait(false);
        if (lower < restored.CurrentHead.Head.ValidFrom ||
            upper >= restored.CurrentHead.Head.ValidUntil - 1)
            throw new CryptographicException(
                "Production DID2 current head cannot cover a new proof.");
    }

    public async ValueTask<DeepIdV2GenesisAdmissionReceipt> AdmitAsync(
        DeepIdV2GenesisAdmissionWireRequest request,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        ArgumentNullException.ThrowIfNull(request);
        var exactRequest = DeepIdV2GenesisAdmissionWireCodec.EncodeRequest(request);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var trusted = await trustedTimeSource.ReadAsync(cancellationToken)
                .ConfigureAwait(false);
            trusted.Validate();
            var lower = trusted.ObservedUnixTime - trusted.UncertaintySeconds;
            var upper = checked(trusted.ObservedUnixTime + trusted.UncertaintySeconds);
            var authority = networkAuthoritySource.Read();
            if (!CryptographicOperations.FixedTimeEquals(
                    authority.NetworkId.Span, networkId) ||
                lower < authority.NotBefore || upper >= authority.ExpiresAt)
                throw new CryptographicException(
                    "DID2 network authority does not cover the trusted-time interval.");
            var validUntil = Math.Min(checked(lower + headValiditySeconds),
                authority.ExpiresAt);
            if (validUntil <= upper)
                throw new CryptographicException(
                    "DID2 network authority cannot cover a new directory head.");

            using var mlDsa65 = DeepMlDsa65CandidateVerifierFactory
                .OpenForCurrentProcess();
            using var store = new DeepIdV2DirectoryStateStore(statePath,
                integrityKey, networkId, bootstrapSource, authority,
                mlDsa65, deploymentProfileId, latestHeadFloor);
            using var lease = store.Open(cancellationToken);
            var prior = await lease.ReadAsync(upper, cancellationToken)
                .ConfigureAwait(false);
            foreach (var row in prior.AdmissionRows)
            {
                var previous = DeepIdV2GenesisAdmissionWireCodec.DecodeRequest(
                    row.ExactDga1V2.Span);
                if (!Fixed(previous.OperationId.Span, request.OperationId.Span))
                    continue;
                if (!Fixed(row.ExactDga1V2.Span, exactRequest))
                    throw new DeepIdV2AuthorityConflictException(
                        "DID2 operation ID is bound to different admission bytes.");
                var checkpoint = DeepIdV2GenesisAdmissionVerifier.Verify(
                    previous.Admission, row.VerifiedAtUnixSeconds,
                    deploymentProfileId, 2, mlDsa65);
                return Receipt(request.OperationId.Span, checkpoint,
                    prior.CurrentHead);
            }

            var admitted = DeepIdV2GenesisAdmissionVerifier.Verify(
                request.Admission, upper, deploymentProfileId, 2, mlDsa65);
            if (!Fixed(admitted.Checkpoint.NetworkId.Span, networkId))
                throw new CryptographicException(
                    "DID2 admission belongs to another network.");
            if (prior.CurrentCheckpoints.Any(checkpoint =>
                    Fixed(checkpoint.Checkpoint.DirectoryLeafKey.Span,
                        admitted.Checkpoint.DirectoryLeafKey.Span)))
                throw new DeepIdV2AuthorityConflictException(
                    "DID2 directory leaf is already admitted.");
            if (prior.AdmissionRows.Count >= DeepIdV2DirectoryStateCodec.MaximumEntries)
                throw new InvalidOperationException(
                    "DID2 directory admission bound is exhausted.");

            var signers = await witnessCustody.GetHeadSignersAsync(
                    authority, cancellationToken).ConfigureAwait(false);
            var authored = await DeepIdV2DirectoryHeadAuthor.AdvanceAsync(
                    authority, prior.CurrentHead,
                    new DeepIdV2DirectoryHeadMutationRequest(
                        prior.Transitions, prior.CurrentCheckpoints, [admitted],
                        lower, validUntil, 2),
                    signers, cancellationToken).ConfigureAwait(false);
            var rows = new DeepIdV2DirectoryStateRows(
                prior.Heads.Select(head => new DeepIdV2DirectoryHeadRow(
                        head.ExactAdh1, head.CoreHash))
                    .Append(new DeepIdV2DirectoryHeadRow(
                        authored.ExactAdh1, authored.CoreHash)).ToArray(),
                authored.ExactAllTransitions,
                prior.AdmissionRows.Append(new DeepIdV2DirectoryAdmissionRow(
                    upper, exactRequest)).ToArray());
            var committed = await lease.WriteAsync(rows, upper,
                cancellationToken).ConfigureAwait(false);
            return Receipt(request.OperationId.Span, admitted,
                committed.CurrentHead);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(exactRequest);
            gate.Release();
        }
    }

    private static DeepIdV2GenesisAdmissionReceipt Receipt(
        ReadOnlySpan<byte> operationId, VerifiedAdc1V2 checkpoint,
        AccountDirectoryProtectedLkg head) =>
        new(operationId, checkpoint.Checkpoint.DirectoryLeafKey.Span,
            head.ExactAdh1.Span);

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length &&
        CryptographicOperations.FixedTimeEquals(left, right);

    public void Dispose()
    {
        if (disposed) return;
        disposed = true;
        gate.Dispose();
        CryptographicOperations.ZeroMemory(networkId);
        CryptographicOperations.ZeroMemory(integrityKey);
    }
}
#endif
