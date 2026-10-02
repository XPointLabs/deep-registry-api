#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Buffers.Binary;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Registry.Api.DirectoryPublication;

// NTS authentication is performed by the pinned local observation process.
// Policy/family/time/floor verification remains here, independently of its output.
internal sealed class AutomaticNtsTrustedTimeSource : BackgroundService,
    IContactResolveTrustedTimeContextSource
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };
    private readonly DeepIdV2XPointAuthoritySource authoritySource;
    private readonly string executable;
    private readonly string floorPath;
    private readonly byte[] network;
    private readonly byte[] integrityKey;
    private readonly byte[] bootId = RandomNumberGenerator.GetBytes(16);
    private readonly Func<ulong> sample;
    private readonly ILogger<AutomaticNtsTrustedTimeSource> logger;
    private readonly object gate = new();
    private Anchor? anchor;
    private Process? observer;
    private string? observerPolicy;

    internal AutomaticNtsTrustedTimeSource(DeepIdV2XPointAuthoritySource authoritySource,
        string executable, string floorPath, ReadOnlySpan<byte> network,
        ReadOnlySpan<byte> integrityKey, ILogger<AutomaticNtsTrustedTimeSource> logger,
        Func<ulong>? sample = null)
    {
        this.authoritySource = authoritySource;
        this.executable = Path.GetFullPath(executable);
        this.floorPath = Path.GetFullPath(floorPath);
        this.network = network.ToArray();
        this.integrityKey = integrityKey.ToArray();
        this.logger = logger;
        this.sample = sample ?? ProtectedMonotonicContactResolveTrustedTimeSource.ReadPlatformMonotonicSeconds;
        if (network.Length != 16 || network.IndexOfAnyExcept((byte)0) < 0 ||
            integrityKey.Length != 32 || integrityKey.IndexOfAnyExcept((byte)0) < 0 ||
            !File.Exists(this.executable))
            throw new ArgumentException("Automatic NTS custody configuration is incomplete.");
        RejectReparse(this.executable);
        RejectReparse(this.floorPath);
        if (File.Exists(this.floorPath + ".manual-upgrade-pending"))
            throw new InvalidDataException("NTS manual upgrade is unfinished; no runtime activation is allowed.");
        // Re-authenticate any retained floor before starting a process. No persisted
        // upper bound survives this instance's new boot ID, even if uptime increased.
        using var lease = DirectoryPublicationProtectedFile.AcquireLease(this.floorPath, default);
        _ = ReadFloor();
    }

    public ValueTask<ContactResolveTrustedTimeContext> ReadAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (gate)
        {
            var current = anchor ?? throw new ContactResolveDirectoryPackageUnavailableException();
            if (!Fixed(current.AuthorityCoreHash, authoritySource.Read().AuthorityCoreHash.Span))
                throw new ContactResolveDirectoryPackageUnavailableException();
            var now = sample();
            if (now < current.Sample || now - current.Sample > current.MaximumAge)
                throw new ContactResolveDirectoryPackageUnavailableException();
            var observed = checked(current.Center + now - current.Sample);
            if (observed <= current.Radius || observed + current.Radius >= current.PolicyExpiry)
                throw new ContactResolveDirectoryPackageUnavailableException();
            // Flush the greatest lower bound before it can be returned to a witness.
            PersistFloor(observed - current.Radius, cancellationToken);
            return ValueTask.FromResult(new ContactResolveTrustedTimeContext(
                bootId, now, observed, current.Radius));
        }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            ushort maximumAge = 30;
            var observerRestarted = false;
            try
            {
                var (authority, policy) = authoritySource.ReadWithTimePolicy();
                maximumAge = policy.MaximumSourceSampleAgeSeconds;
                var request = JsonSerializer.Serialize(new
                {
                    sources = policy.Sources.Select(source => new
                    {
                        id = Convert.ToHexString(source.SourceId.Span).ToLowerInvariant(),
                        host = source.HostAscii, port = source.Port,
                        pin = Convert.ToHexString(source.TlsSpkiSha256.Span).ToLowerInvariant(),
                        radius = source.MaximumRadiusSeconds,
                    }).ToArray(),
                }, JsonOptions);
                EnsureObserver(request);
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                timeout.CancelAfter(TimeSpan.FromSeconds(12));
                var before = sample();
                await observer!.StandardInput.WriteLineAsync(request.AsMemory(), timeout.Token).ConfigureAwait(false);
                await observer.StandardInput.FlushAsync(timeout.Token).ConfigureAwait(false);
                var line = await ReadBoundedLineAsync(observer.StandardOutput, timeout.Token).ConfigureAwait(false);
                var result = JsonSerializer.Deserialize<ObservationResponse>(line, JsonOptions) ??
                    throw new InvalidDataException("NTS observation envelope is absent.");
                AcceptObservations(authority, policy, result.Observations, before, sample());
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception error) when (error is IOException or CryptographicException or
                InvalidOperationException or JsonException or TimeoutException or OperationCanceledException or ArgumentException)
            {
                // Do not log process output, custody paths, pins or source identifiers.
                var reason = error.Message switch {
                    "NTS observation quorum or clock scope is invalid." => "scope-or-quorum",
                    "NTS observation interval is invalid or stale." => "source-interval",
                    "Independent NTS source intervals do not close the live signed policy." => "policy-interval",
                    "NTS observation conflicts with the advanced trusted interval." => "interval-conflict",
                    "Authenticated time would roll back its durable lower floor." => "floor-rollback",
                    _ => "acquisition-rejected"
                };
                logger.LogWarning("Authenticated time acquisition unavailable ({Category}; {Reason}).", error.GetType().Name, reason);
                if (error is not CryptographicException) { StopObserver(); observerRestarted = true; }
            }
            // An owned-process restart must not bypass NTS-KE's minimum
            // acquisition backoff by discarding the helper's session state.
            await Task.Delay(TimeSpan.FromSeconds(observerRestarted ? 10 : Math.Max(1, Math.Min(10, maximumAge / 3))),
                stoppingToken).ConfigureAwait(false);
        }
    }

    internal void AcceptObservations(VerifiedXPointNetworkAuthority authority,
        AccountDirectoryDts1 policy, IReadOnlyList<NtsObservation> observations,
        ulong started, ulong completed)
    {
        ArgumentNullException.ThrowIfNull(observations);
        var signed = authoritySource.ReadWithTimePolicy();
        if (!Fixed(authority.AuthorityCoreHash.Span, signed.Authority.AuthorityCoreHash.Span) ||
            !Fixed(AccountDirectoryDts1Codec.Encode(policy), AccountDirectoryDts1Codec.Encode(signed.Policy)) ||
            !Fixed(authority.NetworkId.Span, network) || !Fixed(policy.NetworkId.Span, network) ||
            completed < started || completed - started > policy.MaximumSourceSampleAgeSeconds ||
            observations.Count is < 2 or > 8)
            throw new CryptographicException("NTS observation quorum or clock scope is invalid.");
        ulong lower = 0, upper = ulong.MaxValue;
        var ids = new HashSet<string>(StringComparer.Ordinal);
        var families = new HashSet<string>(StringComparer.Ordinal);
        foreach (var observation in observations)
        {
            var source = policy.Sources.SingleOrDefault(source => string.Equals(
                Convert.ToHexString(source.SourceId.Span).ToLowerInvariant(), observation.Id, StringComparison.Ordinal)) ??
                throw new CryptographicException("NTS observation is outside signed source policy.");
            var radius = checked((ulong)observation.RadiusSeconds + completed - started);
            if (!ids.Add(observation.Id) || observation.UnixSeconds <= 0 || radius == 0 ||
                radius > source.MaximumRadiusSeconds || (ulong)observation.UnixSeconds <= radius)
                throw new CryptographicException("NTS observation interval is invalid or stale.");
            families.Add(Convert.ToHexString(source.FailureFamilyHash.Span));
            lower = Math.Max(lower, checked((ulong)observation.UnixSeconds - radius));
            upper = Math.Min(upper, checked((ulong)observation.UnixSeconds + radius));
        }
        if (families.Count < policy.RequiredDistinctFailureFamilies || upper < lower ||
            upper - lower > policy.MaximumIntervalWidthSeconds || lower < policy.NotBefore ||
            upper >= policy.ExpiresAt || lower < authority.NotBefore || upper >= authority.ExpiresAt)
            throw new CryptographicException("Independent NTS source intervals do not close the live signed policy.");
        lock (gate)
        {
            if (anchor is { } prior && completed >= prior.Sample && completed - prior.Sample <= prior.MaximumAge)
            {
                var previousNow = checked(prior.Center + completed - prior.Sample);
                lower = Math.Max(lower, previousNow - prior.Radius);
                upper = Math.Min(upper, checked(previousNow + prior.Radius));
            }
            if (upper < lower) throw new CryptographicException("NTS observation conflicts with the advanced trusted interval.");
            // Intersect new authenticated evidence with the retained lower
            // bound. An overlapping observation is not a rollback. Round the
            // enclosing integer interval upward, never one second below floor.
            using (var lease = DirectoryPublicationProtectedFile.AcquireLease(floorPath, default))
                lower = Math.Max(lower, ReadFloor().Lower);
            if (upper < lower) throw new CryptographicException("Authenticated time would roll back its durable lower floor.");
            var radius = checked((uint)Math.Max(1UL, (upper - lower + 1) / 2));
            var center = checked(lower + radius);
            if (radius > authority.MaximumWitnessUncertaintySeconds || center <= radius ||
                checked(center + radius) >= Math.Min(policy.ExpiresAt, authority.ExpiresAt) ||
                2UL * radius > policy.MaximumIntervalWidthSeconds)
                throw new CryptographicException("NTS interval cannot be represented within witness policy.");
            PersistFloor(center - radius, default);
            anchor = new(center, radius, completed, policy.MaximumSourceSampleAgeSeconds,
                Math.Min(policy.ExpiresAt, authority.ExpiresAt), authority.AuthorityCoreHash.ToArray());
        }
    }

    private void PersistFloor(ulong lower, CancellationToken cancellationToken)
    {
        RejectReparse(floorPath);
        using var lease = DirectoryPublicationProtectedFile.AcquireLease(floorPath, cancellationToken);
        var prior = ReadFloor();
        if (lower < prior.Lower) throw new CryptographicException("Authenticated time would roll back its durable lower floor.");
        if (lower == prior.Lower) return;
        Span<byte> payload = stackalloc byte[38];
        "NTF1"u8.CopyTo(payload);
        BinaryPrimitives.WriteUInt16BigEndian(payload[4..], 1);
        network.CopyTo(payload[6..]);
        BinaryPrimitives.WriteUInt64BigEndian(payload[22..], checked(prior.Generation + 1));
        BinaryPrimitives.WriteUInt64BigEndian(payload[30..], lower);
        var encoded = DirectoryPublicationProtectedFile.Protect(payload, integrityKey);
        try { DirectoryPublicationProtectedFile.WriteAtomic(floorPath, encoded); }
        finally { CryptographicOperations.ZeroMemory(encoded); }
    }

    private (ulong Generation, ulong Lower) ReadFloor()
    {
        if (!File.Exists(floorPath)) throw new InvalidDataException("Authenticated-time lower floor is missing; explicit provisioning is required.");
        var encoded = DirectoryPublicationProtectedFile.ReadBounded(floorPath, 70);
        try
        {
            var payload = DirectoryPublicationProtectedFile.Verify(encoded, integrityKey);
            if (payload.Length != 38 || !payload[..4].SequenceEqual("NTF1"u8) ||
                BinaryPrimitives.ReadUInt16BigEndian(payload[4..]) != 1 || !Fixed(payload.Slice(6,16),network))
                throw new InvalidDataException("Authenticated-time lower floor is invalid.");
            var generation = BinaryPrimitives.ReadUInt64BigEndian(payload[22..]);
            var lower = BinaryPrimitives.ReadUInt64BigEndian(payload[30..]);
            if (generation == 0 || lower == 0) throw new InvalidDataException("Authenticated-time lower floor is empty.");
            return (generation, lower);
        }
        finally { CryptographicOperations.ZeroMemory(encoded); }
    }

    internal static void ProvisionFloor(string path, ReadOnlySpan<byte> network,
        ReadOnlySpan<byte> integrityKey, ulong signedPolicyLowerBound,
        CancellationToken cancellationToken = default)
    {
        if (!Path.IsPathFullyQualified(path) || network.Length != 16 ||
            network.IndexOfAnyExcept((byte)0) < 0 || integrityKey.Length != 32 ||
            integrityKey.IndexOfAnyExcept((byte)0) < 0 || signedPolicyLowerBound == 0)
            throw new ArgumentException("Initial NTS floor custody is incomplete.");
        RejectReparse(path);
        using var lease = DirectoryPublicationProtectedFile.AcquireLease(path, cancellationToken);
        var encoded = EncodeInitialFloor(network, integrityKey, signedPolicyLowerBound);
        try
        {
            // CreateNew is explicit first-time custody, never recovery/reset.
            using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write,
                FileShare.None, 4096, FileOptions.WriteThrough);
            stream.Write(encoded); stream.Flush(true);
        }
        finally { CryptographicOperations.ZeroMemory(encoded); }
    }

    internal static byte[] EncodeInitialFloor(ReadOnlySpan<byte> network,
        ReadOnlySpan<byte> integrityKey, ulong lowerBound)
    {
        Span<byte> payload = stackalloc byte[38];
        "NTF1"u8.CopyTo(payload);
        BinaryPrimitives.WriteUInt16BigEndian(payload[4..], 1);
        network.CopyTo(payload[6..]);
        BinaryPrimitives.WriteUInt64BigEndian(payload[22..], 1);
        BinaryPrimitives.WriteUInt64BigEndian(payload[30..], lowerBound);
        return DirectoryPublicationProtectedFile.Protect(payload, integrityKey);
    }

    private void EnsureObserver(string request)
    {
        if (observer is { HasExited: false } && string.Equals(observerPolicy, request, StringComparison.Ordinal)) return;
        StopObserver();
        RejectReparse(executable);
        observer = Process.Start(new ProcessStartInfo(executable)
        {
            UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardInput = true, RedirectStandardOutput = true,
            // No stderr is returned/logged; the observer emits no diagnostics.
        }) ?? throw new IOException("NTS observation process did not start.");
        observerPolicy = request;
    }

    private static async Task<string> ReadBoundedLineAsync(StreamReader reader, CancellationToken cancellationToken)
    {
        var buffer = new char[8_192];
        for (var length = 0; length < buffer.Length; length++)
        {
            if (await reader.ReadAsync(buffer.AsMemory(length,1), cancellationToken).ConfigureAwait(false) != 1)
                throw new IOException("NTS observation process closed its output.");
            if (buffer[length] == '\n') return new string(buffer,0,length);
        }
        throw new InvalidDataException("NTS observation process output is oversized.");
    }
    private void StopObserver()
    {
        if (observer is null) return;
        if (!observer.HasExited) observer.Kill(entireProcessTree:true);
        observer.Dispose(); observer = null; observerPolicy = null;
    }
    public override void Dispose()
    {
        base.Dispose(); StopObserver(); CryptographicOperations.ZeroMemory(integrityKey);
    }
    private static void RejectReparse(string path)
    {
        var current = Path.GetPathRoot(path)!;
        foreach (var part in Path.GetRelativePath(current,path).Split(
            [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar], StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, part);
            if ((File.Exists(current) || Directory.Exists(current)) &&
                (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new CryptographicException("Reparse point in authenticated-time custody path.");
        }
    }
    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left,right);
    private sealed record Anchor(ulong Center, uint Radius, ulong Sample, ushort MaximumAge,
        ulong PolicyExpiry, byte[] AuthorityCoreHash);
    internal sealed record NtsObservation(string Id, long UnixSeconds, ushort RadiusSeconds);
    private sealed record ObservationResponse(IReadOnlyList<NtsObservation> Observations);
}
#endif
