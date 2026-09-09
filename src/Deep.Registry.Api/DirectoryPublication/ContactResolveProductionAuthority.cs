#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.XPointNetworkV1;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Sodium;

namespace Deep.Registry.Api.DirectoryPublication;

internal sealed class ContactResolveProductionAuthorityOptions
{
    public bool Enabled { get; set; }
    public string NetworkIdHex { get; set; } = string.Empty;
    public string TrustedTimeStatePath { get; set; } = string.Empty;
    public string TrustedTimeIntegrityKeyPath { get; set; } = string.Empty;
    public string RequestLedgerRootPath { get; set; } = string.Empty;
    public string RequestLedgerIntegrityKeyPath { get; set; } = string.Empty;
    public int RequestLedgerCapacity { get; set; } = 65_536;
    public int RequestLedgerCompactionInterval { get; set; } = 1_024;
    public List<ContactResolveWitnessCustodyOptions> Witnesses { get; set; } = [];
}

internal sealed class ContactResolveWitnessCustodyOptions
{
    public string WitnessIdHex { get; set; } = string.Empty;
    public ulong KeyGeneration { get; set; }
    public string Ed25519SeedPath { get; set; } = string.Empty;
}

/// <summary>
/// A custody-provisioned UTC anchor advanced only by the process-independent platform monotonic
/// sample. Runtime never bootstraps authority from wall time. A platform monotonic reset closes
/// the source until an operator explicitly rotates the protected anchor.
/// </summary>
internal sealed class ProtectedMonotonicContactResolveTrustedTimeSource :
    IContactResolveTrustedTimeContextSource,
    IDisposable
{
    private static ReadOnlySpan<byte> Magic => "CRT1"u8;
    private const int PayloadBytes = 4 + 2 + 16 + 8 + 32 + 16 + 8 + 8 + 8 + 4;
    private readonly string statePath;
    private readonly byte[] networkId;
    private readonly byte[] integrityKey;
    private readonly Func<ulong> monotonicSample;
    private readonly SemaphoreSlim gate = new(1, 1);

    internal ProtectedMonotonicContactResolveTrustedTimeSource(
        string statePath,
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> integrityKey,
        Func<ulong>? monotonicSample = null)
    {
        if (string.IsNullOrWhiteSpace(statePath))
            throw new ArgumentException("A trusted-time state path is required.", nameof(statePath));
        this.networkId = RequiredNonZero(networkId, 16, nameof(networkId));
        this.integrityKey = RequiredNonZero(integrityKey, 32, nameof(integrityKey));
        this.statePath = Path.GetFullPath(statePath);
        this.monotonicSample = monotonicSample ?? ReadPlatformMonotonicSeconds;
        RejectReparseIfPresent(this.statePath);
    }

    public async ValueTask<ContactResolveTrustedTimeContext> ReadAsync(
        CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var lease = DirectoryPublicationProtectedFile.AcquireLease(
                statePath, cancellationToken);
            var state = ReadState(statePath, networkId, integrityKey);
            var sample = monotonicSample();
            if (sample < state.AnchorMonotonicSample)
                throw new CryptographicException(
                    "The platform monotonic clock reset; trusted time requires a custody rotation.");
            var elapsed = sample - state.AnchorMonotonicSample;
            var observed = checked(state.ObservedUnixTime + elapsed);
            if (observed <= state.UncertaintySeconds ||
                observed > ulong.MaxValue - state.UncertaintySeconds ||
                observed + state.UncertaintySeconds > state.ValidUntilUnixTime)
                throw new CryptographicException("The protected trusted-time anchor is stale.");
            return new ContactResolveTrustedTimeContext(
                state.ServerBootId, sample, observed, state.UncertaintySeconds);
        }
        finally
        {
            gate.Release();
        }
    }

    internal static byte[] Provision(
        string statePath,
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> integrityKey,
        ulong observedUnixTime,
        ulong validUntilUnixTime,
        uint uncertaintySeconds,
        ReadOnlySpan<byte> expectedCurrentStateSha256,
        ulong monotonicSample,
        ReadOnlySpan<byte> serverBootId)
    {
        if (string.IsNullOrWhiteSpace(statePath))
            throw new ArgumentException("A trusted-time state path is required.", nameof(statePath));
        var exactNetwork = RequiredNonZero(networkId, 16, nameof(networkId));
        var exactKey = RequiredNonZero(integrityKey, 32, nameof(integrityKey));
        var exactBoot = RequiredNonZero(serverBootId, 16, nameof(serverBootId));
        if (observedUnixTime == 0 || uncertaintySeconds is < 1 or > 30 ||
            observedUnixTime <= uncertaintySeconds ||
            validUntilUnixTime <= observedUnixTime + uncertaintySeconds)
            throw new ArgumentException("The trusted-time provisioning interval is invalid.");
        if (!expectedCurrentStateSha256.IsEmpty &&
            (expectedCurrentStateSha256.Length != 32 ||
             expectedCurrentStateSha256.IndexOfAnyExcept((byte)0) < 0))
            throw new ArgumentException(
                "The expected trusted-time state hash must be exactly 32 non-zero bytes.",
                nameof(expectedCurrentStateSha256));

        var fullPath = Path.GetFullPath(statePath);
        RejectReparseIfPresent(fullPath);
        using var lease = DirectoryPublicationProtectedFile.AcquireLease(fullPath, CancellationToken.None);
        byte[]? previousEncoded = null;
        byte[] predecessorHash = new byte[32];
        ulong generation = 0;
        try
        {
            if (File.Exists(fullPath))
            {
                if (expectedCurrentStateSha256.IsEmpty)
                    throw new InvalidOperationException(
                        "Rotating trusted time requires the exact current protected-state SHA-256.");
                previousEncoded = DirectoryPublicationProtectedFile.ReadBounded(
                    fullPath, PayloadBytes + 32);
                var actualHash = SHA256.HashData(previousEncoded);
                try
                {
                    if (!CryptographicOperations.FixedTimeEquals(
                            actualHash, expectedCurrentStateSha256))
                        throw new CryptographicException(
                            "The trusted-time state changed before rotation.");
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(actualHash);
                }
                var previous = Decode(previousEncoded, exactNetwork, exactKey);
                if (monotonicSample >= previous.AnchorMonotonicSample)
                {
                    var previousNow = checked(
                        previous.ObservedUnixTime + monotonicSample - previous.AnchorMonotonicSample);
                    if (observedUnixTime < previousNow)
                        throw new CryptographicException(
                            "The replacement trusted-time anchor would move time backwards.");
                }
                if (observedUnixTime < previous.ObservedUnixTime)
                    throw new CryptographicException(
                        "The replacement trusted-time anchor is older than protected state.");
                generation = checked(previous.Generation + 1);
                predecessorHash = SHA256.HashData(previousEncoded);
            }
            else if (!expectedCurrentStateSha256.IsEmpty)
            {
                throw new InvalidOperationException(
                    "An expected trusted-time state hash was supplied, but no state exists.");
            }

            Span<byte> payload = stackalloc byte[PayloadBytes];
            Magic.CopyTo(payload);
            BinaryPrimitives.WriteUInt16BigEndian(payload[4..], 1);
            exactNetwork.CopyTo(payload[6..]);
            BinaryPrimitives.WriteUInt64BigEndian(payload[22..], generation);
            predecessorHash.CopyTo(payload[30..]);
            exactBoot.CopyTo(payload[62..]);
            BinaryPrimitives.WriteUInt64BigEndian(payload[78..], monotonicSample);
            BinaryPrimitives.WriteUInt64BigEndian(payload[86..], observedUnixTime);
            BinaryPrimitives.WriteUInt64BigEndian(payload[94..], validUntilUnixTime);
            BinaryPrimitives.WriteUInt32BigEndian(payload[102..], uncertaintySeconds);
            var protectedState = DirectoryPublicationProtectedFile.Protect(payload, exactKey);
            try
            {
                DirectoryPublicationProtectedFile.WriteAtomic(fullPath, protectedState);
                return SHA256.HashData(protectedState);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(protectedState);
            }
        }
        finally
        {
            if (previousEncoded is not null)
                CryptographicOperations.ZeroMemory(previousEncoded);
            CryptographicOperations.ZeroMemory(predecessorHash);
            CryptographicOperations.ZeroMemory(exactKey);
            CryptographicOperations.ZeroMemory(exactBoot);
        }
    }

    internal static ulong ReadPlatformMonotonicSeconds() =>
        checked((ulong)(Environment.TickCount64 / 1000));

    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(integrityKey);
        gate.Dispose();
    }

    private static TrustedTimeState ReadState(
        string path,
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> integrityKey)
    {
        if (!File.Exists(path))
            throw new ContactResolveDirectoryPackageUnavailableException();
        RejectReparseIfPresent(path);
        var encoded = DirectoryPublicationProtectedFile.ReadBounded(path, PayloadBytes + 32);
        try
        {
            return Decode(encoded, networkId, integrityKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encoded);
        }
    }

    private static TrustedTimeState Decode(
        ReadOnlySpan<byte> encoded,
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> integrityKey)
    {
        var payload = DirectoryPublicationProtectedFile.Verify(encoded, integrityKey);
        if (payload.Length != PayloadBytes || !payload[..4].SequenceEqual(Magic) ||
            BinaryPrimitives.ReadUInt16BigEndian(payload[4..]) != 1 ||
            !CryptographicOperations.FixedTimeEquals(payload.Slice(6, 16), networkId))
            throw new InvalidDataException("The protected trusted-time state is invalid.");
        var predecessor = payload.Slice(30, 32);
        var generation = BinaryPrimitives.ReadUInt64BigEndian(payload[22..]);
        if ((generation == 0) != (predecessor.IndexOfAnyExcept((byte)0) < 0))
            throw new InvalidDataException("The trusted-time predecessor chain is invalid.");
        var bootId = payload.Slice(62, 16);
        var uncertainty = BinaryPrimitives.ReadUInt32BigEndian(payload[102..]);
        if (bootId.IndexOfAnyExcept((byte)0) < 0 || uncertainty is < 1 or > 30)
            throw new InvalidDataException("The trusted-time state fields are invalid.");
        return new TrustedTimeState(
            generation,
            bootId.ToArray(),
            BinaryPrimitives.ReadUInt64BigEndian(payload[78..]),
            BinaryPrimitives.ReadUInt64BigEndian(payload[86..]),
            BinaryPrimitives.ReadUInt64BigEndian(payload[94..]),
            uncertainty);
    }

    private static byte[] RequiredNonZero(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException($"{name} must be exactly {length} non-zero bytes.", name);
        return value.ToArray();
    }

    private static void RejectReparseIfPresent(string path)
    {
        if (File.Exists(path) && (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException("Reparse points are forbidden for trusted-time state.");
    }

    private sealed record TrustedTimeState(
        ulong Generation,
        byte[] ServerBootId,
        ulong AnchorMonotonicSample,
        ulong ObservedUnixTime,
        ulong ValidUntilUnixTime,
        uint UncertaintySeconds);
}

internal sealed class FileContactResolveDtt1WitnessCustody :
    IContactResolveDtt1WitnessCustody,
    IDisposable
{
    private readonly byte[] networkId;
    private readonly WitnessSigner[] signers;

    internal FileContactResolveDtt1WitnessCustody(
        ReadOnlySpan<byte> networkId,
        IReadOnlyList<ContactResolveWitnessCustodyOptions> configured)
    {
        this.networkId = RequiredNonZero(networkId, 16, nameof(networkId));
        ArgumentNullException.ThrowIfNull(configured);
        if (configured.Count is < 1 or > 8)
            throw new InvalidOperationException("ContactResolve witness custody requires one to eight keys.");
        var ids = new HashSet<string>(StringComparer.Ordinal);
        var paths = new HashSet<string>(PathComparer);
        var created = new List<WitnessSigner>(configured.Count);
        try
        {
            foreach (var entry in configured)
            {
                if (entry is null || string.IsNullOrWhiteSpace(entry.Ed25519SeedPath))
                    throw new InvalidOperationException("Every ContactResolve witness requires a seed path.");
                var id = DirectoryPublicationHostingExtensions.Hex(
                    entry.WitnessIdHex, 32, "ContactResolve witness ID");
                var path = Path.GetFullPath(entry.Ed25519SeedPath);
                if (!ids.Add(Convert.ToHexString(id)) || !paths.Add(path))
                    throw new InvalidOperationException("ContactResolve witness IDs and custody paths must be unique.");
                RejectReparse(path);
                var seed = DirectoryPublicationProtectedFile.ReadKey(path);
                try
                {
                    var pair = PublicKeyAuth.GenerateKeyPair(seed);
                    try
                    {
                        created.Add(new WitnessSigner(
                            id, entry.KeyGeneration, pair.PublicKey, pair.PrivateKey));
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(pair.PrivateKey);
                    }
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(seed);
                }
            }
            signers = created.ToArray();
        }
        catch
        {
            foreach (var signer in created) signer.Dispose();
            throw;
        }
    }

    public ValueTask<IReadOnlyList<IAccountDirectoryDtt1WitnessSigner>> GetSignersAsync(
        VerifiedXPointNetworkAuthority authority,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authority);
        cancellationToken.ThrowIfCancellationRequested();
        if (!CryptographicOperations.FixedTimeEquals(authority.NetworkId.Span, networkId))
            throw new CryptographicException("Witness custody rejected a different network.");
        foreach (var signer in signers)
        {
            var witness = authority.WitnessKeys.SingleOrDefault(value =>
                CryptographicOperations.FixedTimeEquals(value.Id.Span, signer.WitnessId.Span));
            if (witness is null || witness.Generation != signer.KeyGeneration ||
                !CryptographicOperations.FixedTimeEquals(
                    witness.Ed25519PublicKey.Span, signer.PublicKey.Span))
                throw new CryptographicException(
                    "Configured witness custody does not match the current verified authority.");
        }
        if (signers.Length < authority.WitnessThreshold)
            throw new CryptographicException("Configured witness custody cannot satisfy the current threshold.");
        return ValueTask.FromResult<IReadOnlyList<IAccountDirectoryDtt1WitnessSigner>>(
            signers.Cast<IAccountDirectoryDtt1WitnessSigner>().ToArray());
    }

    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(networkId);
        foreach (var signer in signers) signer.Dispose();
    }

    private static StringComparer PathComparer => OperatingSystem.IsWindows()
        ? StringComparer.OrdinalIgnoreCase
        : StringComparer.Ordinal;

    private static void RejectReparse(string path)
    {
        if (!File.Exists(path))
            throw new FileNotFoundException("A configured ContactResolve witness seed is unavailable.", path);
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException("Reparse points are forbidden for witness custody.");
    }

    private static byte[] RequiredNonZero(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException($"{name} must be exactly {length} non-zero bytes.", name);
        return value.ToArray();
    }

    private sealed class WitnessSigner : IAccountDirectoryDtt1WitnessSigner, IDisposable
    {
        private readonly byte[] id;
        private readonly byte[] publicKey;
        private readonly byte[] privateKey;
        private int disposed;

        internal WitnessSigner(
            ReadOnlySpan<byte> id,
            ulong keyGeneration,
            ReadOnlySpan<byte> publicKey,
            ReadOnlySpan<byte> privateKey)
        {
            this.id = id.ToArray();
            KeyGeneration = keyGeneration;
            this.publicKey = publicKey.ToArray();
            this.privateKey = privateKey.ToArray();
        }

        public ReadOnlyMemory<byte> WitnessId => id.ToArray();
        internal ReadOnlyMemory<byte> PublicKey => publicKey.ToArray();
        internal ulong KeyGeneration { get; }

        public ValueTask<ReadOnlyMemory<byte>> SignDtt1Async(
            ReadOnlyMemory<byte> signingInput,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (Volatile.Read(ref disposed) != 0)
                throw new ObjectDisposedException(nameof(WitnessSigner));
            var owned = signingInput.ToArray();
            try
            {
                return ValueTask.FromResult<ReadOnlyMemory<byte>>(
                    PublicKeyAuth.SignDetached(owned, privateKey));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(owned);
            }
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref disposed, 1) == 0)
                CryptographicOperations.ZeroMemory(privateKey);
        }
    }
}

internal static class ContactResolveProductionAuthorityServiceCollectionExtensions
{
    private const string SectionName = "ContactResolveProductionAuthority";

    internal static IServiceCollection AddContactResolveProductionAuthority(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);
        var section = configuration.GetSection(SectionName);
        var options = section.Get<ContactResolveProductionAuthorityOptions>() ?? new();
        if (!options.Enabled) return services;

        Validate(options, configuration);
        var network = DirectoryPublicationHostingExtensions.Hex(
            options.NetworkIdHex, 16, "ContactResolve production authority network ID");

        // Validate all protected inputs before registering any production capability. This is
        // read-only and prevents a partial configuration from reaching request-time mutation.
        ValidateProtectedInputs(options, network);

        services.TryAddSingleton<IContactResolveTrustedTimeContextSource>(_ =>
        {
            var key = DirectoryPublicationProtectedFile.ReadKey(options.TrustedTimeIntegrityKeyPath);
            try
            {
                return new ProtectedMonotonicContactResolveTrustedTimeSource(
                    options.TrustedTimeStatePath, network, key);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
            }
        });
        services.TryAddSingleton<IContactResolveOneUseRequestLedger>(_ =>
        {
            var key = DirectoryPublicationProtectedFile.ReadKey(options.RequestLedgerIntegrityKeyPath);
            try
            {
                return new ProtectedFileContactResolveOneUseRequestLedger(
                    options.RequestLedgerRootPath, network, key,
                    options.RequestLedgerCapacity,
                    options.RequestLedgerCompactionInterval);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
            }
        });
        services.TryAddSingleton<IContactResolveDtt1WitnessCustody>(_ =>
            new FileContactResolveDtt1WitnessCustody(network, options.Witnesses));
        return services;
    }

    internal static ContactResolveProductionAuthorityOptions ReadRequiredOptions(
        IConfiguration configuration)
    {
        var options = configuration.GetSection(SectionName)
            .Get<ContactResolveProductionAuthorityOptions>() ?? new();
        if (!options.Enabled)
            throw new InvalidOperationException("ContactResolve production authority is disabled.");
        Validate(options, configuration);
        var network = DirectoryPublicationHostingExtensions.Hex(
            options.NetworkIdHex, 16, "ContactResolve production authority network ID");
        ValidateProtectedInputs(options, network);
        return options;
    }

    private static void Validate(
        ContactResolveProductionAuthorityOptions options,
        IConfiguration configuration)
    {
        var required = new Dictionary<string, string>
        {
            [nameof(options.NetworkIdHex)] = options.NetworkIdHex,
            [nameof(options.TrustedTimeStatePath)] = options.TrustedTimeStatePath,
            [nameof(options.TrustedTimeIntegrityKeyPath)] = options.TrustedTimeIntegrityKeyPath,
            [nameof(options.RequestLedgerRootPath)] = options.RequestLedgerRootPath,
            [nameof(options.RequestLedgerIntegrityKeyPath)] = options.RequestLedgerIntegrityKeyPath,
        };
        var missing = required.FirstOrDefault(value => string.IsNullOrWhiteSpace(value.Value));
        if (missing.Key is not null)
            throw new InvalidOperationException($"{SectionName}:{missing.Key} is required when enabled.");
        if (options.Witnesses is null || options.Witnesses.Count is < 1 or > 8)
            throw new InvalidOperationException(
                $"{SectionName}:Witnesses requires one to eight custody entries.");
        if (options.RequestLedgerCapacity is < 1_024 or > 1_000_000)
            throw new InvalidOperationException(
                $"{SectionName}:RequestLedgerCapacity must be between 1024 and 1000000.");
        if (options.RequestLedgerCompactionInterval is < 64 or > 16_384)
            throw new InvalidOperationException(
                $"{SectionName}:RequestLedgerCompactionInterval must be between 64 and 16384.");

        var network = DirectoryPublicationHostingExtensions.Hex(
            options.NetworkIdHex, 16, "ContactResolve production authority network ID");
        var directoryNetwork = configuration["DirectoryPublication:NetworkIdHex"];
        if (!string.IsNullOrWhiteSpace(directoryNetwork) &&
            !CryptographicOperations.FixedTimeEquals(
                network,
                DirectoryPublicationHostingExtensions.Hex(
                    directoryNetwork, 16, "directory publication network ID")))
            throw new InvalidOperationException(
                "ContactResolve production authority and directory publication networks differ.");

        var protectedPaths = new[]
        {
            options.TrustedTimeStatePath,
            options.TrustedTimeIntegrityKeyPath,
            options.RequestLedgerIntegrityKeyPath,
            configuration["ContactResolveDirectoryArtifacts:IntegrityKeyPath"] ?? string.Empty,
        }.Where(static value => !string.IsNullOrWhiteSpace(value))
         .Select(Path.GetFullPath)
         .ToArray();
        if (protectedPaths.Distinct(PathComparer).Count() != protectedPaths.Length)
            throw new InvalidOperationException(
                "ContactResolve time, replay and artifact state require independent protected files/keys.");
        if (Path.GetFullPath(options.RequestLedgerRootPath)
            .StartsWith(Path.TrimEndingDirectorySeparator(
                    Path.GetFullPath(configuration["ContactResolveDirectoryArtifacts:ReadOnlyRoot"] ??
                        options.RequestLedgerRootPath + ".readonly-sentinel")) +
                Path.DirectorySeparatorChar, PathComparison))
            throw new InvalidOperationException(
                "The request ledger must stay outside the read-only artifact root.");

        var custodyPaths = options.Witnesses
            .Select(value => Path.GetFullPath(value.Ed25519SeedPath))
            .ToArray();
        if (custodyPaths.Distinct(PathComparer).Count() != custodyPaths.Length ||
            custodyPaths.Any(path => protectedPaths.Contains(path, PathComparer)))
            throw new InvalidOperationException(
                "ContactResolve witness custody paths must be unique and independent from protected state keys.");
    }

    private static void ValidateProtectedInputs(
        ContactResolveProductionAuthorityOptions options,
        byte[] network)
    {
        ValidateKey(options.TrustedTimeIntegrityKeyPath);
        ValidateKey(options.RequestLedgerIntegrityKeyPath);
        using var custody = new FileContactResolveDtt1WitnessCustody(network, options.Witnesses);
    }

    private static void ValidateKey(string path)
    {
        var key = DirectoryPublicationProtectedFile.ReadKey(path);
        CryptographicOperations.ZeroMemory(key);
    }

    private static StringComparer PathComparer => OperatingSystem.IsWindows()
        ? StringComparer.OrdinalIgnoreCase
        : StringComparer.Ordinal;
    private static StringComparison PathComparison => OperatingSystem.IsWindows()
        ? StringComparison.OrdinalIgnoreCase
        : StringComparison.Ordinal;
}
#endif
