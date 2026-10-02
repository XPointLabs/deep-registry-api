namespace Deep.Registry.Api.DirectoryPublication;

internal static class RetiredDirectoryConfiguration
{
    internal static void RequireAbsent(IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        foreach (var section in new[]
        {
            "AccountDirectoryAuthority",
            "ContactResolveDirectoryArtifacts",
            "TargetedCurrentValueDirectoryPackages"
        })
        {
            if (configuration.GetSection(section).Exists())
                throw new InvalidOperationException(
                    "Retired directory configuration is not accepted by the DID2 host.");
        }
    }
}
