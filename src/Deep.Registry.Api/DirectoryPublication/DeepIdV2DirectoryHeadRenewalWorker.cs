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
        using var timer = new PeriodicTimer(interval);
        do
        {
            try
            {
                if (await authority.RenewHeadIfDueAsync(leadSeconds,
                        stoppingToken).ConfigureAwait(false))
                    logger.LogInformation(
                        "The protected DID2 directory head was renewed.");
            }
            catch (OperationCanceledException) when (
                stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception exception) when (exception is
                CryptographicException or InvalidDataException or IOException or
                InvalidOperationException or UnauthorizedAccessException or
                NpgsqlException or PlatformNotSupportedException or TimeoutException)
            {
                // Do not put paths, identifiers or custody details in logs.
                logger.LogError("DID2 directory head renewal failed closed ({Reason}).",
                    exception.GetType().Name);
            }
        } while (await timer.WaitForNextTickAsync(stoppingToken)
                     .ConfigureAwait(false));
    }
}
#endif
