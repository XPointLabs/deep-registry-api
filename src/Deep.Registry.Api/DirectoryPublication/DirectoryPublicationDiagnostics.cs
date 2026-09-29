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
}
#endif
