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

    [Theory]
    [InlineData("Production DID2 authority does not cover the trusted-time interval.", "authority-time-coverage")]
    [InlineData("Production DID2 current head cannot cover a new proof.", "head-time-coverage")]
    [InlineData("DID2 proof has no usable nonce-bound lifetime.", "proof-lifetime")]
    [InlineData("The trusted interval cannot identify a DTT1 issuance epoch.", "epoch-interval")]
    [InlineData("The trusted interval crosses an issuance-epoch or DTS1 policy boundary.", "epoch-boundary")]
    [InlineData("DID2 renewal authority does not cover protected time.", "renewal-authority-time")]
    [InlineData("DID2 signed authority cannot cover the renewal interval.", "renewal-lifetime")]
    [InlineData("private path or request bytes", "unclassified")]
    [InlineData("DID2 proof has no usable nonce-bound lifetime. private suffix", "unclassified")]
    public void ClosedReasonCodesNeverEchoExceptionMessages(string message, string expected)
    {
        var error = new CryptographicException(message);
        Assert.Equal(expected, DirectoryPublicationDiagnostics.UnavailableReason(error));
        Assert.Equal(LogLevel.Error, DirectoryPublicationDiagnostics.UnavailableLevel(error));
    }

    [Fact]
    public void RenewalTransientRetriesBackOffAndNeverAccelerateInvalidAuthority()
    {
        var interval = TimeSpan.FromSeconds(60);
        var transient = new ContactResolveDirectoryPackageUnavailableException();
        Assert.Equal(new[] { 5d, 10d, 20d, 40d, 60d, 60d, 60d, 60d },
            Enumerable.Range(1, 8).Select(attempt =>
                DeepIdV2DirectoryHeadRenewalWorker.RecoveryDelay(transient, attempt, interval).TotalSeconds));
        Assert.Equal(TimeSpan.FromSeconds(10),
            DeepIdV2DirectoryHeadRenewalWorker.RecoveryDelay(transient, 8, TimeSpan.FromSeconds(10)));
        foreach (var error in new Exception[] { new CryptographicException(),
            new InvalidDataException(), new UnauthorizedAccessException(), new InvalidOperationException(), new IOException() })
            Assert.Equal(interval, DeepIdV2DirectoryHeadRenewalWorker.RecoveryDelay(error, 1, interval));
    }
}
#endif
