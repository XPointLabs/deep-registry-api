using Deep.Protocol.DeepExtension.Membership;
using Microsoft.Extensions.Options;

namespace Deep.Registry.Api.Tests;

public sealed class MembershipProjectionRedTests
{
    [Fact]
    public void ProjectionDefaultsToDisabled_AndHasNoVerifier()
    {
        var options = new MembershipProjectionOptions();

        Assert.False(options.Enabled);
        Assert.Equal("Deep.Protocol/P04-canonical-v1", options.ContractIdentifier);
        Assert.Equal("0.3.0-p04.b887fa0", options.PackageVersion);
        Assert.False(P04MembershipArtifactVerifier.Create([]).IsAvailable);
    }

    [Fact]
    public void ApplicationAssembly_DoesNotShipMembershipSignatureVerifier()
    {
        var implementations = typeof(Program).Assembly.GetTypes()
            .Where(type => !type.IsAbstract
                           && !type.IsInterface
                           && typeof(IMembershipSignatureVerifier).IsAssignableFrom(type))
            .ToArray();

        Assert.Empty(implementations);
    }

    [Fact]
    public void DisabledProjectionRejectsRawBridgeWithoutTouchingNodeRegistry()
    {
        var statePath = Path.Combine(Path.GetTempPath(), $"p06-red-{Guid.NewGuid():N}.json");
        try
        {
            var options = Options.Create(new MembershipProjectionOptions
            {
                Enabled = false,
                StatePath = statePath
            });
            var service = new MembershipProjectionService(
                options,
                TimeProvider.System,
                P04MembershipArtifactVerifier.Create([]));

            var result = service.ApplyBridge([0x01, 0x02, 0x03]);

            Assert.False(result.Success);
            Assert.Equal(MembershipProjectionCode.Disabled, result.Code);
            Assert.False(File.Exists(statePath));
        }
        finally
        {
            if (File.Exists(statePath))
            {
                File.Delete(statePath);
            }
        }
    }
}
