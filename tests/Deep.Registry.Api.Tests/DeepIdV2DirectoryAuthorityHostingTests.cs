#if DEEP_PROTOCOL_DIRECTORY_V1
using Deep.Registry.Api.DirectoryPublication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Deep.Registry.Api.Tests;

public sealed class DeepIdV2DirectoryAuthorityHostingTests
{
    [Fact]
    public void LegacyAndDid2AdmissionCannotBeEnabledTogether()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["DeepIdV2DirectoryAuthority:Enabled"] = "true",
                ["AccountDirectoryAuthority:Enabled"] = "true"
            }).Build();
        Assert.Throws<InvalidOperationException>(() =>
            new ServiceCollection().AddDeepIdV2DirectoryAuthority(
                configuration));
    }

    [Fact]
    public void Did2AdmissionRequiresProtectedTimeAndWitnessCustody()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["DeepIdV2DirectoryAuthority:Enabled"] = "true"
            }).Build();
        Assert.Throws<InvalidOperationException>(() =>
            new ServiceCollection().AddDeepIdV2DirectoryAuthority(
                configuration));
    }
}
#endif
