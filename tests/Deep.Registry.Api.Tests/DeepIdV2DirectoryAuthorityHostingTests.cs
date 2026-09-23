#if DEEP_PROTOCOL_DIRECTORY_V1
using Deep.Registry.Api.DirectoryPublication;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

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
                configuration, new FixedEnvironment(Environments.Development)));
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
                configuration, new FixedEnvironment(Environments.Development)));
    }

    [Fact]
    public void UnfencedDid2CandidateCannotStartInProduction()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["DeepIdV2DirectoryAuthority:Enabled"] = "true"
            }).Build();
        var error = Assert.Throws<InvalidOperationException>(() =>
            new ServiceCollection().AddDeepIdV2DirectoryAuthority(
                configuration, new FixedEnvironment(Environments.Production)));
        Assert.Contains("rollback floor", error.Message,
            StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ProofPublicationCannotBeEnabledWithoutIsolatedUatAdmission()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["DeepIdV2DirectoryAuthority:ProofEnabled"] = "true"
            }).Build();
        var error = Assert.Throws<InvalidOperationException>(() =>
            new ServiceCollection().AddDeepIdV2DirectoryAuthority(
                configuration, new FixedEnvironment("UAT")));
        Assert.Contains("requires DID2 admission", error.Message,
            StringComparison.OrdinalIgnoreCase);
    }

    private sealed class FixedEnvironment(string name) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = name;
        public string ApplicationName { get; set; } = "Deep.Registry.Api.Tests";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } =
            new NullFileProvider();
    }
}
#endif
