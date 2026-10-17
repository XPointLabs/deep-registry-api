#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Security.Cryptography;
using Deep.Registry.Api.DirectoryPublication;

namespace Deep.Registry.Api.Tests;

public sealed class RouteAuthorityFailureTests
{
    [Theory]
    [InlineData("The threshold route lifetime exceeds advertisement or issuing authority custody.", "ThresholdLifetime")]
    [InlineData("DID2 route time coverage failed (ThresholdAuthoring; NotBefore).", "ThresholdNotBefore")]
    [InlineData("DID2 route time coverage failed (ThresholdAuthoring; Expiry).", "ThresholdExpiry")]
    [InlineData("secret request data", "Unclassified")]
    [InlineData("DID2 route time coverage failed (ThresholdAuthoring; Expiry). secret", "Unclassified")]
    public void OnlyExactClosedProtocolFailuresAreReported(string message, string expected) =>
        Assert.Equal(expected, RouteAuthorityFailure.Classify(new CryptographicException(message)));

    [Fact]
    public void ForeignExceptionsAndMissingErrorsAreUnclassified()
    {
        Assert.Equal("Unclassified", RouteAuthorityFailure.Classify(null));
        Assert.Equal("Unclassified", RouteAuthorityFailure.Classify(new InvalidOperationException(
            "The threshold route lifetime exceeds advertisement or issuing authority custody.")));
    }

    [Fact]
    public void LocationNeverReadsForeignMessagesOrSourcePaths()
    {
        Exception error;
        try { throw new InvalidOperationException("secret request data"); }
        catch (Exception caught) { error = caught; }
        Assert.Equal(("Unclassified", -1), RouteAuthorityFailure.Locate(error));
        Assert.Equal(("Unclassified", -1), RouteAuthorityFailure.Locate(null));
    }

    [Theory]
    [InlineData("pmt-reference", "AdvertisementProjection")]
    [InlineData("device-or-delegation", "AdvertisementDevice")]
    [InlineData("secret request data", "AdvertisementScope")]
    public void OnlyFixedScopeDataValuesAreObserved(string data, string expected)
    {
        var error = new CryptographicException("The XRA1 proposal differs from current DID2 device/delegation scope.");
        error.Data["Deep.ContactRoute.Scope"] = data;
        Assert.Equal(expected, RouteAuthorityFailure.Classify(error));
    }
}
#endif
