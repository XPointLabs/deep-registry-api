#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Deep.Registry.Api.DirectoryPublication;

internal sealed class AccountDirectoryAuthorityOptions
{
    public bool Enabled { get; set; }
    public string NetworkIdHex { get; set; } = string.Empty;
    public string StatePath { get; set; } = string.Empty;
    public string IntegrityKeyPath { get; set; } = string.Empty;
    public ushort DeploymentProfileId { get; set; } = 1;
    public ushort SupportedReader { get; set; } = 1;
    public ulong HeadValiditySeconds { get; set; } = 43_200;
    public ulong RenewalLeadSeconds { get; set; } = 3_600;
}

internal sealed class AccountDirectoryAuthorityConflictException(string message)
    : CryptographicException(message);

internal interface IAccountDirectoryGenesisAuthority
{
    ValueTask<AccountDirectoryGenesisAdmissionReceipt> AdmitAsync(
        AccountDirectoryGenesisAdmissionWireRequest request,
        CancellationToken cancellationToken);
}

internal interface IAccountDirectoryAuthorityBootstrapSource
{
    ValueTask<ContactResolveCanonicalDirectorySnapshot> ReadAsync(
        ContactResolveDirectoryPackageRequest request,
        CancellationToken cancellationToken);
}

internal sealed class FileAccountDirectoryAuthorityBootstrapSource(
    FileContactResolveDirectoryArtifactSource source)
    : IAccountDirectoryAuthorityBootstrapSource
{
    public ValueTask<ContactResolveCanonicalDirectorySnapshot> ReadAsync(
        ContactResolveDirectoryPackageRequest request,
        CancellationToken cancellationToken) =>
        source.ReadAsync(request, cancellationToken);
}

/// <summary>
/// Authority-owned account-directory state. Registry publication consumes the
/// verified snapshot/proof interfaces, while mutation remains behind the
/// separate genesis-admission capability and protected state file.
/// </summary>
internal sealed class DurableAccountDirectoryAuthority :
    IAccountDirectoryGenesisAuthority,
    IContactResolveCanonicalDirectorySnapshotSource,
    IContactResolveDirectoryProofMaterialSource,
    IDisposable
{
    private static ReadOnlySpan<byte> StateMagic => "ADA1"u8;
    private const int MaximumStateBytes = 64 * 1024 * 1024;
    private const int MaximumEntries = 100_000;
    private readonly IAccountDirectoryAuthorityBootstrapSource bootstrap;
    private readonly FileContactResolveDtt1WitnessCustody witnessCustody;
    private readonly IContactResolveTrustedTimeContextSource trustedTimeSource;
    private readonly string statePath;
    private readonly byte[] networkId;
    private readonly byte[] integrityKey;
    private readonly ushort deploymentProfileId;
    private readonly ushort supportedReader;
    private readonly ulong headValiditySeconds;
    private readonly ulong renewalLeadSeconds;
    private readonly SemaphoreSlim gate = new(1, 1);
    private readonly ConditionalWeakTable<
        ContactResolveCanonicalDirectorySnapshot,
        VerifiedProofOperation> proofOperations = new();

    internal DurableAccountDirectoryAuthority(
        IAccountDirectoryAuthorityBootstrapSource bootstrap,
        FileContactResolveDtt1WitnessCustody witnessCustody,
        IContactResolveTrustedTimeContextSource trustedTimeSource,
        AccountDirectoryAuthorityOptions options,
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> integrityKey)
    {
        this.bootstrap = bootstrap ?? throw new ArgumentNullException(nameof(bootstrap));
        this.witnessCustody = witnessCustody ??
            throw new ArgumentNullException(nameof(witnessCustody));
        this.trustedTimeSource = trustedTimeSource ??
            throw new ArgumentNullException(nameof(trustedTimeSource));
        ArgumentNullException.ThrowIfNull(options);
        if (string.IsNullOrWhiteSpace(options.StatePath))
            throw new ArgumentException("An authority state path is required.", nameof(options));
        if (networkId.Length != 16 || networkId.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("A non-zero 16-byte network ID is required.", nameof(networkId));
        if (integrityKey.Length != 32 || integrityKey.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("A non-zero 32-byte integrity key is required.", nameof(integrityKey));
        statePath = Path.GetFullPath(options.StatePath);
        this.networkId = networkId.ToArray();
        this.integrityKey = integrityKey.ToArray();
        deploymentProfileId = options.DeploymentProfileId;
        supportedReader = options.SupportedReader;
        headValiditySeconds = options.HeadValiditySeconds;
        renewalLeadSeconds = options.RenewalLeadSeconds;
    }

    public async ValueTask<AccountDirectoryGenesisAdmissionReceipt> AdmitAsync(
        AccountDirectoryGenesisAdmissionWireRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        var exactRequest = AccountDirectoryGenesisAdmissionWireCodec.EncodeRequest(request);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var lease = DirectoryPublicationProtectedFile.AcquireLease(
                statePath, cancellationToken);
            var trusted = await trustedTimeSource.ReadAsync(cancellationToken)
                .ConfigureAwait(false);
            trusted.Validate();
            var baseSnapshot = await ReadBootstrapAsync(request.OperationId, cancellationToken)
                .ConfigureAwait(false);
            var state = ReadState(baseSnapshot, trusted.ObservedUnixTime);
            state = await RenewIfRequiredAsync(state, baseSnapshot, trusted, cancellationToken)
                .ConfigureAwait(false);

            var operation = state.Admissions.SingleOrDefault(value =>
                Fixed(value.OperationId, request.OperationId.Span));
            if (operation is not null)
            {
                if (!Fixed(operation.ExactRequest, exactRequest))
                    throw new AccountDirectoryAuthorityConflictException(
                        "The admission operation ID was already bound to different bytes.");
                return Receipt(request.OperationId.Span, operation.Checkpoint, state.CurrentHead);
            }

            var verified = AccountDirectoryGenesisAdmissionVerifier.Verify(
                request.Admission,
                trusted.ObservedUnixTime,
                deploymentProfileId,
                supportedReader);
            RequireNetwork(verified.Checkpoint.NetworkId.Span);
            var sameLeaf = state.Admissions.SingleOrDefault(value =>
                Fixed(value.Checkpoint.Checkpoint.DirectoryLeafKey.Span,
                    verified.Checkpoint.DirectoryLeafKey.Span));
            if (sameLeaf is not null)
            {
                if (!Fixed(
                        AccountDirectoryAdc1Codec.Encode(sameLeaf.Checkpoint.Checkpoint),
                        AccountDirectoryAdc1Codec.Encode(verified.Checkpoint)))
                    throw new AccountDirectoryAuthorityConflictException(
                        "The directory leaf already has a different genesis checkpoint.");
                return Receipt(request.OperationId.Span, sameLeaf.Checkpoint, state.CurrentHead);
            }
            if (state.Admissions.Count >= MaximumEntries)
                throw new InvalidOperationException("The authority admission bound is exhausted.");

            var signers = await witnessCustody.GetHeadSignersAsync(
                    baseSnapshot.Authority, cancellationToken)
                .ConfigureAwait(false);
            var window = CreateHeadWindow(baseSnapshot, trusted);
            var authored = await AccountDirectoryHeadAuthor.AdvanceAsync(
                    baseSnapshot.Authority,
                    state.CurrentHead,
                    new AccountDirectoryHeadMutationRequest(
                        state.ExactTransitions,
                        state.CurrentCheckpoints,
                        [verified],
                        window.ValidFrom,
                        window.ValidUntil,
                        supportedReader),
                    signers,
                    cancellationToken)
                .ConfigureAwait(false);
            var admission = new PersistedAdmission(
                request.OperationId.ToArray(),
                trusted.ObservedUnixTime,
                exactRequest,
                verified);
            var next = state.Advance(authored, admission);
            WriteState(next);
            return Receipt(request.OperationId.Span, verified, next.CurrentHead);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(exactRequest);
            gate.Release();
        }
    }

    public async ValueTask<ContactResolveCanonicalDirectorySnapshot> ReadAsync(
        ContactResolveDirectoryPackageRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        RequireNetwork(request.NetworkId.Span);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var lease = DirectoryPublicationProtectedFile.AcquireLease(
                statePath, cancellationToken);
            var trusted = await trustedTimeSource.ReadAsync(cancellationToken)
                .ConfigureAwait(false);
            trusted.Validate();
            var baseSnapshot = await ReadBootstrapAsync(request.Nonce, cancellationToken)
                .ConfigureAwait(false);
            var state = ReadState(baseSnapshot, trusted.ObservedUnixTime);
            state = await RenewIfRequiredAsync(state, baseSnapshot, trusted, cancellationToken)
                .ConfigureAwait(false);
            var caller = ResolveCallerLkg(request, state);
            var query = request.ExpectedDirectoryLookupKey.IsEmpty
                ? request.Nonce
                : request.ExpectedDirectoryLookupKey;
            var proof = AccountDirectoryProofMaterialAuthor.Create(
                state.CurrentHead,
                state.ExactTransitions,
                state.CurrentCheckpoints,
                query.Span,
                caller);
            if (request.RequireCurrentValue &&
                proof.ResultKind != AccountDirectoryAdp1ResultKind.CurrentValue)
                throw new ContactResolveDirectoryTargetNotFoundException();

            var snapshot = CopySnapshot(baseSnapshot, state.CurrentHead);
            proofOperations.Add(snapshot, new VerifiedProofOperation(
                request.Nonce.Span,
                request.BootId.Span,
                request.NonceCreatedAt,
                proof));
            return snapshot;
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
        if (!proofOperations.TryGetValue(snapshot, out var operation) ||
            !Fixed(operation.Nonce, request.Nonce.Span) ||
            !Fixed(operation.BootId, request.BootId.Span) ||
            operation.NonceCreatedAt != request.NonceCreatedAt)
            throw new CryptographicException(
                "The proof request is not bound to this authority-produced snapshot.");
        return ValueTask.FromResult(operation.Proof);
    }

    private async ValueTask<AuthorityState> RenewIfRequiredAsync(
        AuthorityState state,
        ContactResolveCanonicalDirectorySnapshot snapshot,
        ContactResolveTrustedTimeContext trusted,
        CancellationToken cancellationToken)
    {
        var upper = checked(trusted.ObservedUnixTime + trusted.UncertaintySeconds);
        if (state.CurrentHead.Head.ValidUntil > upper &&
            state.CurrentHead.Head.ValidUntil - upper > renewalLeadSeconds)
            return state;
        var signers = await witnessCustody.GetHeadSignersAsync(
                snapshot.Authority, cancellationToken)
            .ConfigureAwait(false);
        var window = CreateHeadWindow(snapshot, trusted);
        var authored = await AccountDirectoryHeadAuthor.AdvanceAsync(
                snapshot.Authority,
                state.CurrentHead,
                new AccountDirectoryHeadMutationRequest(
                    state.ExactTransitions,
                    state.CurrentCheckpoints,
                    [],
                    window.ValidFrom,
                    window.ValidUntil,
                    supportedReader),
                signers,
                cancellationToken)
            .ConfigureAwait(false);
        var next = state.Renew(authored);
        WriteState(next);
        return next;
    }

    private (ulong ValidFrom, ulong ValidUntil) CreateHeadWindow(
        ContactResolveCanonicalDirectorySnapshot snapshot,
        ContactResolveTrustedTimeContext trusted)
    {
        var lower = trusted.ObservedUnixTime - trusted.UncertaintySeconds;
        var desired = checked(lower + headValiditySeconds);
        var until = Math.Min(desired, snapshot.Authority.ExpiresAt);
        if (until <= checked(trusted.ObservedUnixTime + trusted.UncertaintySeconds))
            throw new CryptographicException(
                "The current XPoint authority cannot cover a renewed directory head.");
        return (lower, until);
    }

    private AuthorityState ReadState(
        ContactResolveCanonicalDirectorySnapshot bootstrapSnapshot,
        ulong trustedUnixSeconds)
    {
        if (!File.Exists(statePath))
        {
            if (bootstrapSnapshot.CurrentDirectoryHead.TreeSize != 0)
                throw new InvalidDataException(
                    "A missing authority state requires an empty bootstrap head.");
            return AuthorityState.Bootstrap(bootstrapSnapshot.CurrentDirectoryHead);
        }
        var encoded = DirectoryPublicationProtectedFile.ReadBounded(
            statePath, MaximumStateBytes + 32);
        try
        {
            var payload = DirectoryPublicationProtectedFile.Verify(encoded, integrityKey);
            return DecodeState(payload, bootstrapSnapshot, trustedUnixSeconds);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encoded);
        }
    }

    private AuthorityState DecodeState(
        ReadOnlySpan<byte> payload,
        ContactResolveCanonicalDirectorySnapshot bootstrapSnapshot,
        ulong trustedUnixSeconds)
    {
        var reader = new StateReader(payload);
        reader.ReadHeader(networkId);
        var heads = reader.ReadHeadRows(MaximumEntries + 1);
        var transitions = reader.ReadArtifacts(MaximumEntries, AccountDirectoryTransitionCodec.CanonicalLength);
        var rows = reader.ReadAdmissionRows(MaximumEntries);
        reader.EnsureComplete();
        if (heads.Count < 1 || !Fixed(
                heads[0].ExactAdh1,
                bootstrapSnapshot.CurrentDirectoryHead.ExactAdh1.Span) ||
            !Fixed(heads[0].CoreHash,
                bootstrapSnapshot.CurrentDirectoryHead.CoreHash.Span))
            throw new InvalidDataException(
                "The authority state is not rooted in the configured bootstrap head.");

        var protectedHeads = new List<AccountDirectoryProtectedLkg>(heads.Count)
        {
            bootstrapSnapshot.CurrentDirectoryHead
        };
        for (var index = 1; index < heads.Count; index++)
        {
            var restored = AccountDirectoryProtectedLkgFactory.Restore(
                bootstrapSnapshot.Authority,
                heads[index].ExactAdh1,
                heads[index].CoreHash);
            var predecessor = protectedHeads[^1];
            if (restored.LogGeneration != checked(predecessor.LogGeneration + 1) ||
                !Fixed(restored.Head.PredecessorAdh1CoreHash.Span, predecessor.CoreHash.Span))
                throw new InvalidDataException(
                    "The protected directory-head history is not contiguous.");
            protectedHeads.Add(restored);
        }

        var admissions = new List<PersistedAdmission>(rows.Count);
        var operationIds = new HashSet<string>(StringComparer.Ordinal);
        var leaves = new HashSet<string>(StringComparer.Ordinal);
        foreach (var row in rows)
        {
            var wire = AccountDirectoryGenesisAdmissionWireCodec.DecodeRequest(
                row.ExactRequest);
            if (!operationIds.Add(Convert.ToHexString(wire.OperationId.Span)))
                throw new InvalidDataException("The authority state repeats an operation ID.");
            var verifiedAt = Math.Min(row.VerifiedAtUnixSeconds, trustedUnixSeconds);
            if (verifiedAt == 0)
                throw new InvalidDataException("The admission verification time is invalid.");
            var checkpoint = AccountDirectoryGenesisAdmissionVerifier.Verify(
                wire.Admission,
                verifiedAt,
                deploymentProfileId,
                supportedReader);
            RequireNetwork(checkpoint.Checkpoint.NetworkId.Span);
            if (!leaves.Add(Convert.ToHexString(
                    checkpoint.Checkpoint.DirectoryLeafKey.Span)))
                throw new InvalidDataException("The authority state repeats a directory leaf.");
            admissions.Add(new PersistedAdmission(
                wire.OperationId.ToArray(),
                row.VerifiedAtUnixSeconds,
                row.ExactRequest,
                checkpoint));
        }

        var state = new AuthorityState(
            protectedHeads,
            transitions,
            admissions);
        var validationQuery = admissions.Count == 0
            ? Enumerable.Repeat((byte)1, 32).ToArray()
            : admissions[0].Checkpoint.Checkpoint.DirectoryLeafKey.ToArray();
        _ = AccountDirectoryProofMaterialAuthor.Create(
            state.CurrentHead,
            state.ExactTransitions,
            state.CurrentCheckpoints,
            validationQuery);
        return state;
    }

    private void WriteState(AuthorityState state)
    {
        using var stream = new MemoryStream();
        stream.Write(StateMagic);
        WriteU16(stream, 1);
        stream.Write(networkId);
        WriteU32(stream, checked((uint)state.Heads.Count));
        foreach (var head in state.Heads)
        {
            WriteArtifact(stream, head.ExactAdh1.Span);
            stream.Write(head.CoreHash.Span);
        }
        WriteArtifacts(stream, state.ExactTransitions);
        WriteU32(stream, checked((uint)state.Admissions.Count));
        foreach (var admission in state.Admissions)
        {
            WriteU64(stream, admission.VerifiedAtUnixSeconds);
            WriteArtifact(stream, admission.ExactRequest);
        }
        if (stream.Length > MaximumStateBytes)
            throw new InvalidOperationException("The protected authority state exceeds its bound.");
        var protectedState = DirectoryPublicationProtectedFile.Protect(
            stream.GetBuffer().AsSpan(0, checked((int)stream.Length)), integrityKey);
        try
        {
            DirectoryPublicationProtectedFile.WriteAtomic(statePath, protectedState);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(protectedState);
        }
    }

    private AccountDirectoryProtectedLkg? ResolveCallerLkg(
        ContactResolveDirectoryPackageRequest request,
        AuthorityState state)
    {
        if (request.DirectoryTreeSize is null)
        {
            if (!request.DirectoryCoreHash.IsEmpty)
                throw new CryptographicException("The caller directory floor is incomplete.");
            return null;
        }
        return state.Heads.SingleOrDefault(value =>
                   value.TreeSize == request.DirectoryTreeSize.Value &&
                   Fixed(value.CoreHash.Span, request.DirectoryCoreHash.Span))
               ?? throw new CryptographicException(
                   "The caller directory floor is outside retained authority history.");
    }

    private async ValueTask<ContactResolveCanonicalDirectorySnapshot> ReadBootstrapAsync(
        ReadOnlyMemory<byte> entropy,
        CancellationToken cancellationToken)
    {
        var nonce = SHA256.HashData(entropy.Span);
        if (nonce.AsSpan().IndexOfAnyExcept((byte)0) < 0)
            nonce[0] = 1;
        var request = new ContactResolveDirectoryPackageRequest(
            networkId,
            nonce,
            Enumerable.Repeat((byte)1, 16).ToArray(),
            1,
            null,
            null,
            null);
        return await bootstrap.ReadAsync(request, cancellationToken).ConfigureAwait(false);
    }

    private static ContactResolveCanonicalDirectorySnapshot CopySnapshot(
        ContactResolveCanonicalDirectorySnapshot source,
        AccountDirectoryProtectedLkg head) =>
        new(
            source.NetworkId.Span,
            source.Authority,
            head,
            source.ExactCurrentXnv1,
            source.SupportedReader,
            source.ExactOrderedXna1AuthorityChain,
            source.ExactOrderedDts1PolicyChain,
            source.ExactOrderedXvp1Chain,
            source.ExactOrderedXnv1Chain,
            source.ExactOrderedXnh1Chain,
            source.ExactActiveXnd1,
            source.ExactOrderedPmt2Chain,
            source.ForwardCheckpoint);

    private static AccountDirectoryGenesisAdmissionReceipt Receipt(
        ReadOnlySpan<byte> operationId,
        VerifiedAccountDirectoryCheckpoint checkpoint,
        AccountDirectoryProtectedLkg head) =>
        new(
            operationId,
            checkpoint.Checkpoint.DirectoryLeafKey.Span,
            head.ExactAdh1.Span);

    private void RequireNetwork(ReadOnlySpan<byte> value)
    {
        if (!Fixed(value, networkId))
            throw new CryptographicException("The authority rejected a different network.");
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length &&
        CryptographicOperations.FixedTimeEquals(left, right);

    private static void WriteArtifacts(
        Stream stream,
        IEnumerable<ReadOnlyMemory<byte>> values)
    {
        var array = values.ToArray();
        WriteU32(stream, checked((uint)array.Length));
        foreach (var value in array)
            WriteArtifact(stream, value.Span);
    }

    private static void WriteArtifact(Stream stream, ReadOnlySpan<byte> value)
    {
        WriteU32(stream, checked((uint)value.Length));
        stream.Write(value);
    }

    private static void WriteU16(Stream stream, ushort value)
    {
        Span<byte> encoded = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(encoded, value);
        stream.Write(encoded);
    }

    private static void WriteU32(Stream stream, uint value)
    {
        Span<byte> encoded = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(encoded, value);
        stream.Write(encoded);
    }

    private static void WriteU64(Stream stream, ulong value)
    {
        Span<byte> encoded = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(encoded, value);
        stream.Write(encoded);
    }

    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(networkId);
        CryptographicOperations.ZeroMemory(integrityKey);
        gate.Dispose();
    }

    private sealed record PersistedAdmission(
        byte[] OperationId,
        ulong VerifiedAtUnixSeconds,
        byte[] ExactRequest,
        VerifiedAccountDirectoryCheckpoint Checkpoint);

    private sealed record PersistedAdmissionRow(
        ulong VerifiedAtUnixSeconds,
        byte[] ExactRequest);

    private sealed record PersistedHeadRow(
        byte[] ExactAdh1,
        byte[] CoreHash);

    private sealed class AuthorityState
    {
        internal AuthorityState(
            IReadOnlyList<AccountDirectoryProtectedLkg> heads,
            IReadOnlyList<ReadOnlyMemory<byte>> transitions,
            IReadOnlyList<PersistedAdmission> admissions)
        {
            Heads = heads.ToArray();
            ExactTransitions = transitions.Select(static value =>
                (ReadOnlyMemory<byte>)value.ToArray()).ToArray();
            Admissions = admissions.ToArray();
        }

        internal IReadOnlyList<AccountDirectoryProtectedLkg> Heads { get; }
        internal IReadOnlyList<ReadOnlyMemory<byte>> ExactTransitions { get; }
        internal IReadOnlyList<PersistedAdmission> Admissions { get; }
        internal AccountDirectoryProtectedLkg CurrentHead => Heads[^1];
        internal IReadOnlyList<VerifiedAccountDirectoryCheckpoint> CurrentCheckpoints =>
            Admissions.Select(static value => value.Checkpoint).ToArray();

        internal static AuthorityState Bootstrap(AccountDirectoryProtectedLkg head) =>
            new([head], [], []);

        internal AuthorityState Advance(
            AuthoredAccountDirectoryHeadMutation authored,
            PersistedAdmission admission) =>
            new(
                Heads.Append(authored.ProtectedHead).ToArray(),
                authored.ExactAllTransitions,
                Admissions.Append(admission).ToArray());

        internal AuthorityState Renew(AuthoredAccountDirectoryHeadMutation authored) =>
            new(
                Heads.Append(authored.ProtectedHead).ToArray(),
                authored.ExactAllTransitions,
                Admissions);
    }

    private sealed record VerifiedProofOperation(
        byte[] Nonce,
        byte[] BootId,
        ulong NonceCreatedAt,
        AccountDirectoryAdp1ProofMaterial Proof)
    {
        internal VerifiedProofOperation(
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> bootId,
            ulong nonceCreatedAt,
            AccountDirectoryAdp1ProofMaterial proof)
            : this(nonce.ToArray(), bootId.ToArray(), nonceCreatedAt, proof)
        {
        }
    }

    private ref struct StateReader
    {
        private readonly ReadOnlySpan<byte> value;
        private int offset;

        internal StateReader(ReadOnlySpan<byte> value)
        {
            this.value = value;
            offset = 0;
        }

        internal void ReadHeader(ReadOnlySpan<byte> expectedNetwork)
        {
            if (!ReadSpan(4).SequenceEqual(StateMagic) || ReadU16() != 1 ||
                !Fixed(ReadSpan(16), expectedNetwork))
                throw new InvalidDataException("The protected authority state header is invalid.");
        }

        internal List<ReadOnlyMemory<byte>> ReadArtifacts(int maximumCount, int maximumLength)
        {
            var count = ReadU32();
            if (count > maximumCount)
                throw new InvalidDataException("A protected authority collection exceeds its bound.");
            var result = new List<ReadOnlyMemory<byte>>(checked((int)count));
            for (var index = 0U; index < count; index++)
                result.Add(ReadArtifact(maximumLength));
            return result;
        }

        internal List<PersistedHeadRow> ReadHeadRows(int maximumCount)
        {
            var count = ReadU32();
            if (count > maximumCount)
                throw new InvalidDataException("The protected head history exceeds its bound.");
            var result = new List<PersistedHeadRow>(checked((int)count));
            for (var index = 0U; index < count; index++)
                result.Add(new PersistedHeadRow(
                    ReadArtifact(65_535),
                    ReadSpan(32).ToArray()));
            return result;
        }

        internal List<PersistedAdmissionRow> ReadAdmissionRows(int maximumCount)
        {
            var count = ReadU32();
            if (count > maximumCount)
                throw new InvalidDataException("The protected admission collection exceeds its bound.");
            var result = new List<PersistedAdmissionRow>(checked((int)count));
            for (var index = 0U; index < count; index++)
                result.Add(new PersistedAdmissionRow(
                    ReadU64(),
                    ReadArtifact(AccountDirectoryGenesisAdmissionWireCodec.MaximumRequestLength)));
            return result;
        }

        internal void EnsureComplete()
        {
            if (offset != value.Length)
                throw new InvalidDataException("The protected authority state has trailing bytes.");
        }

        private ushort ReadU16() => BinaryPrimitives.ReadUInt16BigEndian(ReadSpan(2));
        private uint ReadU32() => BinaryPrimitives.ReadUInt32BigEndian(ReadSpan(4));
        private ulong ReadU64() => BinaryPrimitives.ReadUInt64BigEndian(ReadSpan(8));

        private byte[] ReadArtifact(int maximumLength)
        {
            var length = ReadU32();
            if (length == 0 || length > maximumLength || length > int.MaxValue)
                throw new InvalidDataException("A protected authority artifact length is invalid.");
            return ReadSpan(checked((int)length)).ToArray();
        }

        private ReadOnlySpan<byte> ReadSpan(int length)
        {
            if (length < 0 || offset > value.Length - length)
                throw new InvalidDataException("The protected authority state is truncated.");
            var result = value.Slice(offset, length);
            offset += length;
            return result;
        }
    }
}

internal readonly record struct AccountDirectoryAuthorityHostingState(bool Enabled);

internal static class AccountDirectoryAuthorityHostingExtensions
{
    internal const string EndpointPath = "/api/v1/account-directory/genesis-admissions";

    internal static AccountDirectoryAuthorityHostingState AddAccountDirectoryAuthority(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);
        var options = configuration.GetSection("AccountDirectoryAuthority")
            .Get<AccountDirectoryAuthorityOptions>() ?? new();
        if (!options.Enabled)
            return default;
        Validate(options, configuration);
        var network = DirectoryPublicationHostingExtensions.Hex(
            options.NetworkIdHex, 16, "account-directory authority network ID");
        services.TryAddSingleton<IAccountDirectoryAuthorityBootstrapSource>(provider =>
            new FileAccountDirectoryAuthorityBootstrapSource(
                provider.GetRequiredService<FileContactResolveDirectoryArtifactSource>()));
        services.TryAddSingleton<DurableAccountDirectoryAuthority>(provider =>
        {
            var key = DirectoryPublicationProtectedFile.ReadKey(options.IntegrityKeyPath);
            try
            {
                return new DurableAccountDirectoryAuthority(
                    provider.GetRequiredService<IAccountDirectoryAuthorityBootstrapSource>(),
                    provider.GetRequiredService<FileContactResolveDtt1WitnessCustody>(),
                    provider.GetRequiredService<IContactResolveTrustedTimeContextSource>(),
                    options,
                    network,
                    key);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
            }
        });
        services.TryAddSingleton<IAccountDirectoryGenesisAuthority>(provider =>
            provider.GetRequiredService<DurableAccountDirectoryAuthority>());
        services.RemoveAll<IContactResolveCanonicalDirectorySnapshotSource>();
        services.RemoveAll<IContactResolveDirectoryProofMaterialSource>();
        services.AddSingleton<IContactResolveCanonicalDirectorySnapshotSource>(provider =>
            provider.GetRequiredService<DurableAccountDirectoryAuthority>());
        services.AddSingleton<IContactResolveDirectoryProofMaterialSource>(provider =>
            provider.GetRequiredService<DurableAccountDirectoryAuthority>());
        return new AccountDirectoryAuthorityHostingState(true);
    }

    internal static void MapAccountDirectoryAuthorityEndpoint(
        this WebApplication app,
        AccountDirectoryAuthorityHostingState state)
    {
        if (!state.Enabled)
            return;
        app.MapPost(EndpointPath, HandleAsync)
            .WithMetadata(new RequestSizeLimitAttribute(
                AccountDirectoryGenesisAdmissionWireCodec.MaximumRequestLength));
    }

    private static async Task<IResult> HandleAsync(
        HttpContext context,
        IAccountDirectoryGenesisAuthority authority,
        ContactResolveIssuanceAdmissionGate admission,
        ILogger<DurableAccountDirectoryAuthority> logger,
        CancellationToken cancellationToken)
    {
        context.Response.Headers.CacheControl = "no-store";
        var decision = admission.TryAcquire(context.Connection.RemoteIpAddress);
        if (!decision.IsAccepted)
        {
            context.Response.Headers.RetryAfter = decision.RetryAfterSeconds.ToString(
                System.Globalization.CultureInfo.InvariantCulture);
            return Failure(StatusCodes.Status429TooManyRequests, "admission-rate-limited");
        }
        if (!string.Equals(
                context.Request.ContentType,
                AccountDirectoryGenesisAdmissionWireCodec.RequestMediaType,
                StringComparison.OrdinalIgnoreCase))
            return Failure(StatusCodes.Status415UnsupportedMediaType, "unsupported-media-type");
        if (context.Request.ContentLength is not { } length)
            return Failure(StatusCodes.Status411LengthRequired, "content-length-required");
        if (length is < 1 or > AccountDirectoryGenesisAdmissionWireCodec.MaximumRequestLength)
            return Failure(StatusCodes.Status413PayloadTooLarge, "admission-request-too-large");
        byte[]? encoded = null;
        try
        {
            encoded = new byte[checked((int)length)];
            await context.Request.Body.ReadExactlyAsync(encoded, cancellationToken)
                .ConfigureAwait(false);
            var request = AccountDirectoryGenesisAdmissionWireCodec.DecodeRequest(encoded);
            var receipt = await authority.AdmitAsync(request, cancellationToken)
                .ConfigureAwait(false);
            return Results.Bytes(
                AccountDirectoryGenesisAdmissionWireCodec.EncodeReceipt(receipt),
                AccountDirectoryGenesisAdmissionWireCodec.ResponseMediaType);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (AccountDirectoryAuthorityConflictException)
        {
            return Failure(StatusCodes.Status409Conflict, "admission-conflict");
        }
        catch (AccountDirectoryGenesisAdmissionException exception)
        {
            logger.LogWarning(
                "Account-directory genesis admission was rejected with code {AdmissionCode}; " +
                "inner type {FailureType}: {FailureMessage}",
                exception.Code,
                exception.InnerException?.GetType().Name ?? "none",
                exception.InnerException?.Message ?? "none");
            return Failure(StatusCodes.Status400BadRequest, "admission-rejected");
        }
        catch (Exception exception) when (exception is
            ArgumentException or FormatException)
        {
            logger.LogWarning(
                "Account-directory genesis admission could not be decoded: {FailureType}.",
                exception.GetType().Name);
            return Failure(StatusCodes.Status400BadRequest, "admission-rejected");
        }
        catch (Exception exception) when (exception is
            CryptographicException or InvalidDataException or IOException or
            InvalidOperationException)
        {
            return Failure(StatusCodes.Status503ServiceUnavailable, "authority-unavailable");
        }
        finally
        {
            if (encoded is not null)
                CryptographicOperations.ZeroMemory(encoded);
        }
    }

    private static IResult Failure(int statusCode, string code) =>
        Results.Json(new { code }, statusCode: statusCode);

    private static void Validate(
        AccountDirectoryAuthorityOptions options,
        IConfiguration configuration)
    {
        if (string.IsNullOrWhiteSpace(options.NetworkIdHex) ||
            string.IsNullOrWhiteSpace(options.StatePath) ||
            string.IsNullOrWhiteSpace(options.IntegrityKeyPath))
            throw new InvalidOperationException(
                "AccountDirectoryAuthority requires network, state and integrity-key paths.");
        if (options.DeploymentProfileId == 0 || options.SupportedReader == 0)
            throw new InvalidOperationException(
                "AccountDirectoryAuthority profile and reader must be non-zero.");
        if (options.HeadValiditySeconds is < 300 or > 86_400 ||
            options.RenewalLeadSeconds < 60 ||
            options.RenewalLeadSeconds >= options.HeadValiditySeconds)
            throw new InvalidOperationException(
                "AccountDirectoryAuthority head validity or renewal lead is invalid.");
        var contactNetwork = configuration["ContactResolveProductionAuthority:NetworkIdHex"];
        if (string.IsNullOrWhiteSpace(contactNetwork) ||
            !string.Equals(options.NetworkIdHex, contactNetwork,
                StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException(
                "AccountDirectoryAuthority and ContactResolve authority networks differ.");
        var protectedPaths = new[]
        {
            options.StatePath,
            options.IntegrityKeyPath,
            configuration["ContactResolveProductionAuthority:TrustedTimeStatePath"],
            configuration["ContactResolveProductionAuthority:TrustedTimeIntegrityKeyPath"],
            configuration["ContactResolveProductionAuthority:RequestLedgerIntegrityKeyPath"],
            configuration["ContactResolveDirectoryArtifacts:StatePath"],
            configuration["ContactResolveDirectoryArtifacts:IntegrityKeyPath"],
        }.Where(static value => !string.IsNullOrWhiteSpace(value))
         .Select(static value => Path.GetFullPath(value!))
         .ToArray();
        var comparer = OperatingSystem.IsWindows()
            ? StringComparer.OrdinalIgnoreCase
            : StringComparer.Ordinal;
        if (protectedPaths.Distinct(comparer).Count() != protectedPaths.Length)
            throw new InvalidOperationException(
                "AccountDirectoryAuthority protected files and keys must be independent.");
        var key = DirectoryPublicationProtectedFile.ReadKey(options.IntegrityKeyPath);
        CryptographicOperations.ZeroMemory(key);
    }
}
#endif
