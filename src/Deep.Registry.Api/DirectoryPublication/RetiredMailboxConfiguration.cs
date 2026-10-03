namespace Deep.Registry.Api.DirectoryPublication;

internal static class RetiredMailboxConfiguration
{
    internal static void RequireAbsent(IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        var section = configuration.GetSection("ProductionMailbox");
        if (section.Value is not null || section.GetChildren().Any())
            throw new InvalidOperationException("Retired ProductionMailbox configuration is not supported. Use the current DID2 issuer composition.");
    }
}
