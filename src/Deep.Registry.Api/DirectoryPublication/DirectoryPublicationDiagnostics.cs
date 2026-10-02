#if DEEP_PROTOCOL_DIRECTORY_V1
using Npgsql;

namespace Deep.Registry.Api.DirectoryPublication;

internal static class DirectoryPublicationDiagnostics
{
    // Missing live time/dependencies at startup is expected unready state, not
    // damaged authority. Cryptographic, custody and configuration failures keep
    // Error severity. No exception messages or custody values enter these logs.
    internal static LogLevel UnavailableLevel(Exception error) => error switch
    {
        ContactResolveDirectoryPackageUnavailableException => LogLevel.Warning,
        TimeoutException => LogLevel.Warning,
        OperationCanceledException => LogLevel.Warning,
        NpgsqlException { IsTransient: true } => LogLevel.Warning,
        _ => LogLevel.Error,
    };

    // Closed diagnostic vocabulary only: never return arbitrary exception
    // messages, inner exceptions, paths or protocol/request bytes. Severity
    // and all verification/HTTP outcomes remain independent of this label.
    internal static string UnavailableReason(Exception error) => error.Message switch
    {
        "The protected trusted-time anchor is stale." => "manual-time-anchor-stale",
        "The platform monotonic clock reset; trusted time requires a custody rotation." => "manual-time-clock-reset",
        "Production DID2 authority does not cover the trusted-time interval." => "authority-time-coverage",
        "Production DID2 current head cannot cover a new proof." => "head-time-coverage",
        "DID2 proof has no usable nonce-bound lifetime." => "proof-lifetime",
        "The trusted interval cannot identify a DTT1 issuance epoch." => "epoch-interval",
        "The trusted interval crosses an issuance-epoch or DTS1 policy boundary." => "epoch-boundary",
        "DID2 renewal authority does not cover protected time." => "renewal-authority-time",
        "DID2 signed authority cannot cover the renewal interval." => "renewal-lifetime",
        _ => "unclassified",
    };
}
#endif
