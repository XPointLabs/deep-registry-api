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
    [InlineData("The protected trusted-time anchor is stale.", "manual-time-anchor-stale")]
    [InlineData("The platform monotonic clock reset; trusted time requires a custody rotation.", "manual-time-clock-reset")]
    [InlineData("The protected trusted-time anchor is stale. private suffix", "unclassified")]
    [InlineData("Production DID2 authority does not cover the trusted-time interval.", "authority-time-coverage")]
    [InlineData("Production DID2 current head cannot cover a new proof.", "head-time-coverage")]
    [InlineData("Production DID2 current head requires authority renewal.", "head-authority-renewal")]
    [InlineData("DID2 prepared commit requires author recovery.", "directory-commit-pending")]
    [InlineData("DID2 proof has no usable nonce-bound lifetime.", "proof-lifetime")]
    [InlineData("The trusted interval cannot identify a DTT1 issuance epoch.", "epoch-interval")]
    [InlineData("The trusted interval crosses an issuance-epoch or DTS1 policy boundary.", "epoch-boundary")]
    [InlineData("DID2 renewal authority does not cover protected time.", "renewal-authority-time")]
    [InlineData("DID2 signed authority cannot cover the renewal interval.", "renewal-lifetime")]
    [InlineData("The ContactResolve request ledger rejected an issuance-epoch rollback or fork.", "issuance-epoch-rollback-or-fork")]
    [InlineData("The ContactResolve request ledger rejected an issuance-epoch rollback or fork. private suffix", "unclassified")]
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

    [Theory]
    [InlineData(60, 300, 0, 60)]
    [InlineData(60, 300, 2, 62)]
    [InlineData(60, 121, 2, 60)]
    [InlineData(300, 3600, 2, 300)]
    [InlineData(5, 300, 2, 7)]
    public void HeadRenewalJitterPreservesLeadAndPollingBounds(
        int delaySeconds, ulong leadSeconds, int jitterSeconds, int expectedSeconds)
    {
        var delay = DeepIdV2DirectoryHeadRenewalWorker.JitterDelay(
            TimeSpan.FromSeconds(delaySeconds), leadSeconds, jitterSeconds);
        Assert.Equal(TimeSpan.FromSeconds(expectedSeconds), delay);
        Assert.True(delay.TotalSeconds * 2 < leadSeconds);
        Assert.True(delay <= TimeSpan.FromSeconds(300));
    }

    [Theory]
    [InlineData(0, 300, 0)]
    [InlineData(60, 59, 0)]
    [InlineData(60, 3601, 0)]
    [InlineData(60, 300, -1)]
    [InlineData(60, 300, 3)]
    public void HeadRenewalJitterRejectsInvalidBounds(
        int delaySeconds, ulong leadSeconds, int jitterSeconds) =>
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            DeepIdV2DirectoryHeadRenewalWorker.JitterDelay(
                TimeSpan.FromSeconds(delaySeconds), leadSeconds, jitterSeconds));
}
#endif
