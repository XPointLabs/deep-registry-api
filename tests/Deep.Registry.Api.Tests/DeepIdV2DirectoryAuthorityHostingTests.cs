#if DEEP_PROTOCOL_DIRECTORY_V1
using Deep.Registry.Api.DirectoryPublication;
using Deep.Protocol.AccountDirectoryV1;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
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

    [Fact]
    public async Task ProofRouteIsAbsentWhenAdmissionIsEnabledButProofIsNot()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddSingleton<IDeepIdV2GenesisAuthority>(
            new UnusedGenesisAuthority());
        builder.Services.AddSingleton(TimeProvider.System);
        builder.Services.AddSingleton<ContactResolveIssuanceAdmissionGate>();
        await using var app = builder.Build();
        app.MapDeepIdV2DirectoryAuthorityEndpoint(
            new DeepIdV2DirectoryAuthorityHostingState(true, false));
        await app.StartAsync();
        using var client = app.GetTestClient();
        using var response = await client.PostAsync(
            DeepIdV2DirectoryAuthorityHostingExtensions.ProofEndpointPath,
            new ByteArrayContent([]));
        Assert.Equal(System.Net.HttpStatusCode.NotFound, response.StatusCode);
    }

    private sealed class UnusedGenesisAuthority : IDeepIdV2GenesisAuthority
    {
        public ValueTask<DeepIdV2GenesisAdmissionReceipt> AdmitAsync(
            DeepIdV2GenesisAdmissionWireRequest request,
            CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException(
                "The default-off proof route must not invoke genesis admission.");
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
