#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Globalization;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;

namespace Deep.Registry.Api.DirectoryPublication;

internal static class DeepIdV2DirectoryOperatorCommand
{
    internal static int? TryRun(string[] args,
        IConfiguration configuration,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(configuration);
        if (args.Length == 0 ||
            !string.Equals(args[0], "did2-directory", StringComparison.Ordinal))
            return null;
        try
        {
            if (args.Length == 2 &&
                string.Equals(args[1], "provision-state",
                    StringComparison.Ordinal))
                Provision(configuration, cancellationToken);
            else if (args.Length == 4 &&
                string.Equals(args[1], "author-genesis-head",
                    StringComparison.Ordinal) &&
                ulong.TryParse(args[2], NumberStyles.None,
                    CultureInfo.InvariantCulture, out var validFrom) &&
                ulong.TryParse(args[3], NumberStyles.None,
                    CultureInfo.InvariantCulture, out var validUntil))
                AuthorGenesisHead(configuration, validFrom, validUntil,
                    cancellationToken);
            else
                throw new ArgumentException("Unknown DID2 directory operator action.");
            return 0;
        }
        catch (OperationCanceledException) when (
            cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (exception is
            ArgumentException or IOException or CryptographicException or
            InvalidDataException or InvalidOperationException or
            FormatException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine(
                $"DID2 directory operator action failed closed ({exception.GetType().Name}).");
            return 2;
        }
    }

    private static void AuthorGenesisHead(IConfiguration configuration,
        ulong validFromUnixSeconds, ulong validUntilUnixSeconds,
        CancellationToken cancellationToken)
    {
        if (configuration.GetValue<bool>("AccountDirectoryAuthority:Enabled"))
            throw new InvalidOperationException(
                "DID2 genesis cannot be authored while ADA1 admission is enabled.");
        var options = configuration.GetSection("DeepIdV2DirectoryAuthority")
            .Get<DeepIdV2DirectoryAuthorityOptions>() ?? new();
        var custodyOptions = configuration.GetSection(
                "ContactResolveProductionAuthority")
            .Get<ContactResolveProductionAuthorityOptions>() ?? new();
        if (string.IsNullOrWhiteSpace(options.GenesisHeadPath) ||
            !Path.IsPathFullyQualified(options.GenesisHeadPath))
            throw new ArgumentException(
                "The DID2 genesis output path must be absolute.");
        var rawPaths = options.ExactAuthorityPaths
            .Concat(options.ExactTimePolicyPaths)
            .Append(options.GenesisHeadPath)
            .Concat(custodyOptions.Witnesses.Select(static entry =>
                entry?.Ed25519SeedPath ?? string.Empty))
            .Concat(new[] { options.StatePath, options.IntegrityKeyPath })
            .Where(static path => !string.IsNullOrWhiteSpace(path))
            .ToArray();
        if (rawPaths.Any(static path => !Path.IsPathFullyQualified(path)))
            throw new ArgumentException(
                "DID2 genesis inputs and output must have absolute paths.");
        var allPaths = rawPaths.Select(Path.GetFullPath).ToArray();
        var pathComparer = OperatingSystem.IsWindows()
            ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;
        if (allPaths.Distinct(pathComparer).Count() != allPaths.Length)
            throw new ArgumentException(
                "DID2 genesis inputs and output must have distinct absolute paths.");
        var network = DirectoryPublicationHostingExtensions.Hex(
            options.NetworkIdHex, 16, "DID2 directory network ID");
        var custodyNetwork = DirectoryPublicationHostingExtensions.Hex(
            custodyOptions.NetworkIdHex, 16, "DID2 witness custody network ID");
        if (!CryptographicOperations.FixedTimeEquals(network, custodyNetwork))
            throw new CryptographicException(
                "DID2 genesis witness custody belongs to another network.");
        var networkPin = DirectoryPublicationHostingExtensions.Hex(
            options.GenesisAuthorityCoreHashHex, 32,
            "DID2 genesis XNA1 core hash");
        var authority = new DeepIdV2XPointAuthoritySource(network,
            networkPin, options.ExactAuthorityPaths,
            options.ExactTimePolicyPaths).Read();
        using var custody = new FileContactResolveDtt1WitnessCustody(
            network, custodyOptions.Witnesses);
        var signers = custody.GetHeadSignersAsync(authority,
                cancellationToken).AsTask().GetAwaiter().GetResult();
        var authored = DeepIdV2DirectoryHeadAuthor.AuthorGenesisAsync(
                authority, validFromUnixSeconds, validUntilUnixSeconds,
                signers, cancellationToken).AsTask().GetAwaiter().GetResult();
        if (!string.IsNullOrWhiteSpace(options.GenesisHeadCoreHashHex) &&
            !CryptographicOperations.FixedTimeEquals(
                DirectoryPublicationHostingExtensions.Hex(
                    options.GenesisHeadCoreHashHex, 32,
                    "DID2 genesis ADH1 core hash"),
                authored.CoreHash.Span))
            throw new CryptographicException(
                "The configured DID2 genesis head pin differs from the authored head.");
        var outputPath = Path.GetFullPath(options.GenesisHeadPath);
        var stagingPath = outputPath + ".authoring";
        if (File.Exists(outputPath) || File.Exists(stagingPath))
            throw new InvalidDataException(
                "DID2 genesis head or interrupted authoring already exists; no overwrite is allowed.");
        using (var stream = new FileStream(stagingPath, FileMode.CreateNew,
                   FileAccess.Write, FileShare.None, 4096,
                   FileOptions.WriteThrough))
        {
            stream.Write(authored.ExactAdh1.Span);
            stream.Flush(true);
        }
        File.Move(stagingPath, outputPath, overwrite: false);
        Console.Out.WriteLine(
            $"DID2 genesis ADH1 core hash: {Convert.ToHexString(authored.CoreHash.Span)}");
    }

    private static void Provision(IConfiguration configuration,
        CancellationToken cancellationToken)
    {
        if (configuration.GetValue<bool>("AccountDirectoryAuthority:Enabled"))
            throw new InvalidOperationException(
                "DID2 state cannot be provisioned while ADA1 admission is enabled.");
        var options = configuration.GetSection("DeepIdV2DirectoryAuthority")
            .Get<DeepIdV2DirectoryAuthorityOptions>() ?? new();
        if (string.IsNullOrWhiteSpace(options.StatePath) ||
            string.IsNullOrWhiteSpace(options.IntegrityKeyPath) ||
            string.IsNullOrWhiteSpace(options.GenesisHeadPath) ||
            !Path.IsPathFullyQualified(options.StatePath) ||
            !Path.IsPathFullyQualified(options.IntegrityKeyPath) ||
            !Path.IsPathFullyQualified(options.GenesisHeadPath))
            throw new ArgumentException(
                "DID2 state, key and pinned head paths must be absolute.");
        var allPaths = options.ExactAuthorityPaths
            .Concat(options.ExactTimePolicyPaths)
            .Append(options.GenesisHeadPath)
            .Append(options.StatePath)
            .Append(options.IntegrityKeyPath)
            .ToArray();
        if (allPaths.Any(static path =>
                string.IsNullOrWhiteSpace(path) ||
                !Path.IsPathFullyQualified(path)))
            throw new ArgumentException(
                "Every DID2 artifact, state and key path must be absolute.");
        var pathComparer = OperatingSystem.IsWindows()
            ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;
        if (allPaths.Select(Path.GetFullPath)
                .Distinct(pathComparer).Count() != allPaths.Length)
            throw new ArgumentException(
                "DID2 artifact, state and key paths must be distinct.");
        var network = DirectoryPublicationHostingExtensions.Hex(
            options.NetworkIdHex, 16, "DID2 directory network ID");
        var networkPin = DirectoryPublicationHostingExtensions.Hex(
            options.GenesisAuthorityCoreHashHex, 32,
            "DID2 genesis XNA1 core hash");
        var headPin = DirectoryPublicationHostingExtensions.Hex(
            options.GenesisHeadCoreHashHex, 32,
            "DID2 genesis ADH1 core hash");
        var authority = new DeepIdV2XPointAuthoritySource(network,
            networkPin, options.ExactAuthorityPaths,
            options.ExactTimePolicyPaths).Read();
        var genesis = new DeepIdV2DirectoryBootstrapSource(
            options.GenesisHeadPath, headPin).Read(authority);
        var statePath = Path.GetFullPath(options.StatePath);
        var key = DirectoryPublicationProtectedFile.ReadKey(
            options.IntegrityKeyPath);
        try
        {
            using var lease = DirectoryPublicationProtectedFile.AcquireLease(
                statePath, cancellationToken);
            var stagingPath = statePath + ".provisioning";
            if (File.Exists(statePath) || File.Exists(statePath + ".writing") ||
                File.Exists(stagingPath))
                throw new InvalidDataException(
                    "ADA2 state or interrupted write already exists; no overwrite is allowed.");
            var rows = new DeepIdV2DirectoryStateRows(
                [new DeepIdV2DirectoryHeadRow(
                    genesis.ExactAdh1, genesis.CoreHash)], [], []);
            var payload = DeepIdV2DirectoryStateCodec.Encode(network, rows);
            var protectedState = DirectoryPublicationProtectedFile.Protect(
                payload, key);
            try
            {
                using (var stream = new FileStream(stagingPath,
                           FileMode.CreateNew, FileAccess.Write, FileShare.None,
                           4096, FileOptions.WriteThrough))
                {
                    stream.Write(protectedState);
                    stream.Flush(true);
                }
                File.Move(stagingPath, statePath, overwrite: false);
                Console.Out.WriteLine(
                    $"DID2 ADA2 state provisioned: {Convert.ToHexString(SHA256.HashData(protectedState))}");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(payload);
                CryptographicOperations.ZeroMemory(protectedState);
            }
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }
}
#endif
