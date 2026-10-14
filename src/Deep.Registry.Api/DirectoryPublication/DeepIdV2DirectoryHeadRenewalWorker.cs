#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Security.Cryptography;
using Npgsql;

namespace Deep.Registry.Api.DirectoryPublication;

/// <summary>
/// Keeps an already-provisioned DID2 authority usable while its protected
/// trusted-time anchor remains valid. It never provisions time or signs from
/// the operating-system wall clock.
/// </summary>
internal sealed class DeepIdV2DirectoryHeadRenewalWorker : BackgroundService
{
    internal static readonly TimeSpan RenewalTimeout = TimeSpan.FromSeconds(30);
    private readonly DeepIdV2DurableGenesisAuthority authority;
    private readonly ulong leadSeconds;
    private readonly TimeSpan interval;
    private readonly ILogger<DeepIdV2DirectoryHeadRenewalWorker> logger;

    internal DeepIdV2DirectoryHeadRenewalWorker(
        DeepIdV2DurableGenesisAuthority authority, ulong leadSeconds,
        TimeSpan interval,
        ILogger<DeepIdV2DirectoryHeadRenewalWorker> logger)
    {
        this.authority = authority ??
            throw new ArgumentNullException(nameof(authority));
        this.logger = logger ?? throw new ArgumentNullException(nameof(logger));
        if (leadSeconds is < 60 or > 3_600 ||
            interval < TimeSpan.FromSeconds(10) ||
            interval > TimeSpan.FromSeconds(300) ||
            interval.TotalSeconds * 2 >= leadSeconds)
            throw new ArgumentOutOfRangeException(nameof(interval));
        this.leadSeconds = leadSeconds;
        this.interval = interval;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await Task.Yield();
        var unavailable = false;
        var consecutiveFailures = 0;
        do
        {
            var delay = interval;
            try
            {
                if (await RenewOnceAsync(stoppingToken).ConfigureAwait(false))
                    logger.LogInformation(
                        "The protected DID2 directory head was renewed.");
                if (unavailable)
                    logger.LogInformation("Protected DID2 directory head renewal authority recovered.");
                unavailable = false;
                consecutiveFailures = 0;
            }
            catch (OperationCanceledException) when (
                stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception exception) when (exception is
                CryptographicException or InvalidDataException or IOException or
                InvalidOperationException or UnauthorizedAccessException or
                NpgsqlException or PlatformNotSupportedException or TimeoutException or
                OperationCanceledException)
            {
                // Do not put paths, identifiers or custody details in logs.
                unavailable = true;
                consecutiveFailures = Math.Min(7, consecutiveFailures + 1);
                delay = RecoveryDelay(exception, consecutiveFailures, interval);
                logger.Log(DirectoryPublicationDiagnostics.UnavailableLevel(exception), "DID2 directory head renewal failed closed ({Category}; {Reason}).",
                    exception.GetType().Name, DirectoryPublicationDiagnostics.UnavailableReason(exception));
            }
            delay = JitterDelay(delay, leadSeconds, Random.Shared.Next(0, 3));
            try { await Task.Delay(delay, stoppingToken).ConfigureAwait(false); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
        } while (!stoppingToken.IsCancellationRequested);
    }

    internal async ValueTask<bool> RenewOnceAsync(CancellationToken stoppingToken)
    {
        // One budget covers gate acquisition, trusted time, external custody
        // and durable completion. A timeout never creates a new signing intent
        // or repairs a floor; the next flight reopens the real retained state.
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
        deadline.CancelAfter(RenewalTimeout);
        return await authority.RenewHeadIfDueAsync(leadSeconds, deadline.Token)
            .ConfigureAwait(false);
    }

    internal static TimeSpan JitterDelay(TimeSpan delay, ulong leadSeconds, int jitterSeconds)
    {
        if (delay <= TimeSpan.Zero || leadSeconds is < 60 or > 3_600 ||
            jitterSeconds is < 0 or > 2)
            throw new ArgumentOutOfRangeException(nameof(jitterSeconds));
        // Jitter may not violate the configured half-lead safety margin or
        // the existing 300-second polling ceiling, including near a boundary.
        var ceiling = Math.Min(300UL, (leadSeconds - 1) / 2);
        return TimeSpan.FromSeconds(Math.Min(delay.TotalSeconds + jitterSeconds, ceiling));
    }

    internal static TimeSpan RecoveryDelay(Exception error, int consecutiveFailures, TimeSpan interval)
    {
        // On boot NTS/floor are often not available at the first attempt. Do
        // not leave an already-expired authenticated head unrenewed for the
        // normal maintenance interval after those dependencies return. Retry
        // only known transient unavailability, with bounded exponential delay;
        // crypto/custody/configuration failures keep the regular cadence.
        if (DirectoryPublicationDiagnostics.UnavailableLevel(error) != LogLevel.Warning)
            return interval;
        var seconds = 5 * (1 << Math.Clamp(consecutiveFailures - 1, 0, 6));
        return TimeSpan.FromSeconds(Math.Min(seconds, interval.TotalSeconds));
    }
}
#endif
