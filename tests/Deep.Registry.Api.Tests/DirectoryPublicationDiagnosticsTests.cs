#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Security.Cryptography;
using Deep.Registry.Api.DirectoryPublication;
using Microsoft.Extensions.Logging;
using Npgsql;

namespace Deep.Registry.Api.Tests;

public sealed class DirectoryPublicationDiagnosticsTests
{
    [Fact]
    public void LiveAuthorityAndTransientDependencyLossAreWarnings()
    {
        foreach (var error in new Exception[] {
            new ContactResolveDirectoryPackageUnavailableException(),
            new TimeoutException(), new OperationCanceledException(),
            new NpgsqlException("private diagnostic", new IOException()) })
            Assert.Equal(LogLevel.Warning, DirectoryPublicationDiagnostics.UnavailableLevel(error));
    }

    [Fact]
    public void InvalidCryptoCustodyAndConfigurationRemainErrors()
    {
        foreach (var error in new Exception[] {
            new CryptographicException(), new InvalidDataException(),
            new UnauthorizedAccessException(), new IOException(),
            new InvalidOperationException(), new PlatformNotSupportedException(),
            new NpgsqlException("private diagnostic") })
            Assert.Equal(LogLevel.Error, DirectoryPublicationDiagnostics.UnavailableLevel(error));
    }
}
#endif
