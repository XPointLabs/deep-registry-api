using System.Net;

namespace Deep.Registry.Api.DirectoryPublication;

/// <summary>
/// Process-local admission only. Source buckets are short lived, bounded and never persisted;
/// the independent global bucket remains a final resource-safety ceiling.
/// </summary>
internal sealed class BoundedRequestAdmissionGate
{
    private readonly object sync = new();
    private readonly TimeProvider timeProvider;
    private readonly TimeSpan window;
    private readonly TimeSpan partitionLifetime;
    private readonly int perSourceLimit;
    private readonly int globalLimit;
    private readonly int maximumPartitions;
    private readonly Dictionary<string, Bucket> sources = new(StringComparer.Ordinal);
    private DateTimeOffset globalWindowStart;
    private DateTimeOffset nextPruneAt;
    private int globalCount;

    internal BoundedRequestAdmissionGate(
        TimeProvider timeProvider,
        int perSourceLimit,
        int globalLimit,
        TimeSpan window,
        TimeSpan partitionLifetime,
        int maximumPartitions = 4_096)
    {
        this.timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
        if (perSourceLimit < 1 || globalLimit < perSourceLimit)
            throw new ArgumentOutOfRangeException(nameof(perSourceLimit));
        if (window <= TimeSpan.Zero || partitionLifetime < window)
            throw new ArgumentOutOfRangeException(nameof(window));
        if (maximumPartitions is < 16 or > 65_536)
            throw new ArgumentOutOfRangeException(nameof(maximumPartitions));
        this.perSourceLimit = perSourceLimit;
        this.globalLimit = globalLimit;
        this.window = window;
        this.partitionLifetime = partitionLifetime;
        this.maximumPartitions = maximumPartitions;
        globalWindowStart = timeProvider.GetUtcNow();
        nextPruneAt = globalWindowStart + window;
    }

    internal BoundedAdmissionDecision TryAcquire(IPAddress? remoteAddress)
    {
        var now = timeProvider.GetUtcNow();
        var source = SourceKey(remoteAddress);
        lock (sync)
        {
            ResetGlobalIfNeeded(now);
            PruneExpired(now);

            if (!sources.TryGetValue(source, out var bucket))
            {
                if (sources.Count >= maximumPartitions)
                    return BoundedAdmissionDecision.Rejected(RetryAfter(now, globalWindowStart));
                bucket = new Bucket(now);
                sources.Add(source, bucket);
            }
            else if (now - bucket.WindowStart >= window)
            {
                bucket.WindowStart = now;
                bucket.Count = 0;
            }

            bucket.LastSeen = now;
            if (bucket.Count >= perSourceLimit || globalCount >= globalLimit)
            {
                var sourceRetry = RetryAfter(now, bucket.WindowStart);
                var globalRetry = RetryAfter(now, globalWindowStart);
                return BoundedAdmissionDecision.Rejected(Math.Max(sourceRetry, globalRetry));
            }

            bucket.Count++;
            globalCount++;
            return BoundedAdmissionDecision.Accepted;
        }
    }

    private void ResetGlobalIfNeeded(DateTimeOffset now)
    {
        if (now - globalWindowStart < window) return;
        globalWindowStart = now;
        globalCount = 0;
    }

    private void PruneExpired(DateTimeOffset now)
    {
        if (now < nextPruneAt) return;
        nextPruneAt = now + window;
        if (sources.Count == 0) return;
        foreach (var item in sources.Where(item => now - item.Value.LastSeen >= partitionLifetime).ToArray())
            sources.Remove(item.Key);
    }

    private uint RetryAfter(DateTimeOffset now, DateTimeOffset started)
    {
        var remaining = window - (now - started);
        return checked((uint)Math.Max(1, Math.Ceiling(remaining.TotalSeconds)));
    }

    private static string SourceKey(IPAddress? address)
    {
        if (address is null) return "unknown";
        var normalized = address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
        return Convert.ToHexString(normalized.GetAddressBytes());
    }

    private sealed class Bucket(DateTimeOffset now)
    {
        internal DateTimeOffset WindowStart { get; set; } = now;
        internal DateTimeOffset LastSeen { get; set; } = now;
        internal int Count { get; set; }
    }
}

internal readonly record struct BoundedAdmissionDecision(bool IsAccepted, uint RetryAfterSeconds)
{
    internal static BoundedAdmissionDecision Accepted => new(true, 0);
    internal static BoundedAdmissionDecision Rejected(uint retryAfterSeconds) =>
        new(false, retryAfterSeconds);
}

/// <summary>
/// Shared by both DTT1-backed directory issuance endpoints. If a future authority-bound epoch
/// permits a 24-hour replay horizon, the fixed-window boundary worst case is
/// (86400 / 10 + 1) * 6 = 51,846 admissions, leaving 13,690 entries of a 65,536-entry ledger for
/// crash over-count and operator recovery margin. This arithmetic does not activate production.
/// </summary>
internal sealed class ContactResolveIssuanceAdmissionGate(TimeProvider timeProvider)
{
    internal const int GlobalLimit = 6;
    internal const int WindowSeconds = 10;
    internal const int MinimumLedgerCapacity = 65_536;
    internal const int AdmissionSafetyHorizonSeconds = 86_400;
    internal const int CrashAndBoundaryMargin = 13_690;

    private readonly BoundedRequestAdmissionGate gate = new(
        timeProvider, perSourceLimit: 2, globalLimit: GlobalLimit,
        TimeSpan.FromSeconds(WindowSeconds), TimeSpan.FromMinutes(2));

    internal BoundedAdmissionDecision TryAcquire(IPAddress? address) => gate.TryAcquire(address);
}

internal sealed class ContactRouteClosureAdmissionGate(TimeProvider timeProvider)
{
    private readonly BoundedRequestAdmissionGate gate = new(
        timeProvider, perSourceLimit: 16, globalLimit: 256,
        TimeSpan.FromSeconds(10), TimeSpan.FromMinutes(2));

    internal BoundedAdmissionDecision TryAcquire(IPAddress? address) => gate.TryAcquire(address);
}
