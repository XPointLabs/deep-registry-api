#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Npgsql;

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
            else if (args.Length == 2 &&
                string.Equals(args[1], "verify-genesis-head",
                    StringComparison.Ordinal))
                VerifyGenesisHead(configuration);
            else if (args.Length == 2 &&
                string.Equals(args[1], "provision-floor",
                    StringComparison.Ordinal))
                ProvisionFloor(configuration, cancellationToken);
            else if (args.Length == 4 &&
                string.Equals(args[1], "export-current-head",
                    StringComparison.Ordinal))
                ExportCurrentHead(configuration, args[2], args[3],
                    exportLineage: false, cancellationToken);
            else if (args.Length == 4 &&
                string.Equals(args[1], "export-covered-lineage",
                    StringComparison.Ordinal))
                ExportCurrentHead(configuration, args[2], args[3],
                    exportLineage: true, cancellationToken);
            else if (args.Length == 4 &&
                string.Equals(args[1], "refresh-current-head",
                    StringComparison.Ordinal) &&
                ulong.TryParse(args[2], NumberStyles.None,
                    CultureInfo.InvariantCulture, out var refreshFrom) &&
                ulong.TryParse(args[3], NumberStyles.None,
                    CultureInfo.InvariantCulture, out var refreshUntil))
            {
                var trusted = ReadOperatorTrustedTime(configuration,
                    cancellationToken);
                RefreshCurrentHead(configuration, refreshFrom, refreshUntil,
                    trusted.ObservedUnixTime, cancellationToken,
                    trusted.UncertaintySeconds);
            }
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
            FormatException or UnauthorizedAccessException or OverflowException or
            NpgsqlException)
        {
            Console.Error.WriteLine(
                $"DID2 directory operator action failed closed ({exception.GetType().Name}).");
            return 2;
        }
    }

    internal static void RefreshCurrentHead(IConfiguration configuration,
        ulong validFromUnixSeconds, ulong validUntilUnixSeconds,
        ulong observedUnixSeconds,
        CancellationToken cancellationToken,
        uint uncertaintySeconds = 0)
    {
        if (configuration.GetValue<bool>("AccountDirectoryAuthority:Enabled"))
            throw new InvalidOperationException(
                "DID2 head refresh cannot run while ADA1 admission is enabled.");
        var options = configuration.GetSection("DeepIdV2DirectoryAuthority")
            .Get<DeepIdV2DirectoryAuthorityOptions>() ?? new();
        var custodyOptions = configuration.GetSection(
                "ContactResolveProductionAuthority")
            .Get<ContactResolveProductionAuthorityOptions>() ?? new();
        if (string.IsNullOrWhiteSpace(options.StatePath) ||
            string.IsNullOrWhiteSpace(options.IntegrityKeyPath) ||
            string.IsNullOrWhiteSpace(options.GenesisHeadPath) ||
            string.IsNullOrWhiteSpace(
                options.LatestHeadFloorPostgreSqlConnectionString) ||
            options.DeploymentProfileId == 0 ||
            options.HeadValiditySeconds is < 60 or > 86_400)
            throw new ArgumentException(
                "DID2 refresh requires complete state, custody and independent floor configuration.");
        var paths = options.ExactAuthorityPaths
            .Concat(options.ExactTimePolicyPaths)
            .Concat([options.StatePath, options.IntegrityKeyPath,
                options.GenesisHeadPath])
            .Concat(custodyOptions.Witnesses.Select(static entry =>
                entry?.Ed25519SeedPath ?? string.Empty))
            .ToArray();
        if (paths.Any(static path => string.IsNullOrWhiteSpace(path) ||
                !Path.IsPathFullyQualified(path)))
            throw new ArgumentException(
                "DID2 refresh inputs must have distinct absolute paths.");
        var comparer = OperatingSystem.IsWindows()
            ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;
        if (paths.Select(Path.GetFullPath).Distinct(comparer).Count() !=
            paths.Length)
            throw new ArgumentException(
                "DID2 refresh paths must be distinct.");
        if (observedUnixSeconds <= uncertaintySeconds ||
            uncertaintySeconds > 30 ||
            validFromUnixSeconds >
                observedUnixSeconds - uncertaintySeconds ||
            checked(validFromUnixSeconds + 300) <
                checked(observedUnixSeconds + uncertaintySeconds) ||
            validUntilUnixSeconds <= validFromUnixSeconds ||
            validUntilUnixSeconds <=
                checked(observedUnixSeconds + uncertaintySeconds) ||
            validUntilUnixSeconds - validFromUnixSeconds >
                options.HeadValiditySeconds)
            throw new CryptographicException(
                "DID2 refresh interval is outside the current operator time window.");
        var network = DirectoryPublicationHostingExtensions.Hex(
            options.NetworkIdHex, 16, "DID2 directory network ID");
        var custodyNetwork = DirectoryPublicationHostingExtensions.Hex(
            custodyOptions.NetworkIdHex, 16, "DID2 witness custody network ID");
        if (!CryptographicOperations.FixedTimeEquals(network, custodyNetwork))
            throw new CryptographicException(
                "DID2 refresh witness custody belongs to another network.");
        var authorityPin = DirectoryPublicationHostingExtensions.Hex(
            options.GenesisAuthorityCoreHashHex, 32,
            "DID2 genesis XNA1 core hash");
        var genesisPin = DirectoryPublicationHostingExtensions.Hex(
            options.GenesisHeadCoreHashHex, 32,
            "DID2 genesis ADH1 core hash");
        var authority = new DeepIdV2XPointAuthoritySource(network,
            authorityPin, options.ExactAuthorityPaths,
            options.ExactTimePolicyPaths).Read();
        var trustedLower = observedUnixSeconds - uncertaintySeconds;
        var trustedUpper = checked(observedUnixSeconds + uncertaintySeconds);
        if (trustedLower < authority.NotBefore ||
            trustedUpper >= authority.ExpiresAt)
            throw new CryptographicException(
                "The DID2 operator trusted-time interval is outside the signed authority.");
        var genesis = new DeepIdV2DirectoryBootstrapSource(
            options.GenesisHeadPath, genesisPin);
        var key = DirectoryPublicationProtectedFile.ReadKey(
            options.IntegrityKeyPath);
        try
        {
            using var custody = new FileContactResolveDtt1WitnessCustody(
                network, custodyOptions.Witnesses);
            var signers = custody.GetHeadSignersAsync(authority,
                cancellationToken).AsTask().GetAwaiter().GetResult();
            using var verifier = DeepMlDsa65CandidateVerifierFactory
                .OpenForCurrentProcess();
            using var floor = new DeepIdV2PostgreSqlLatestHeadFloor(
                options.LatestHeadFloorPostgreSqlConnectionString, network);
            using var store = new DeepIdV2DirectoryStateStore(options.StatePath,
                key, network, genesis, authority, verifier,
                options.DeploymentProfileId, floor);
            using var lease = store.Open(cancellationToken);
            var prior = lease.ReadAsync(trustedUpper,
                cancellationToken).AsTask().GetAwaiter().GetResult();
            if (prior.CurrentHead.TreeSize == 0 ||
                prior.CurrentHead.Head.ValidUntil >
                checked(trustedUpper + 300))
                throw new InvalidOperationException(
                    "The DID2 nonempty current head does not yet need refresh.");
            var request = new DeepIdV2DirectoryHeadMutationRequest(
                prior.Transitions, prior.CurrentCheckpoints, [],
                validFromUnixSeconds, validUntilUnixSeconds,
                Math.Max((ushort)2, prior.CurrentHead.Head.MinimumReader));
            var authored = DeepIdV2DirectoryHeadAuthor.AdvanceAsync(
                authority, prior.CurrentHead, request, signers,
                cancellationToken).AsTask().GetAwaiter().GetResult();
            if (authored.ProtectedHead.TreeSize != prior.CurrentHead.TreeSize ||
                !CryptographicOperations.FixedTimeEquals(
                    authored.ProtectedHead.AppendLogMerkleRoot.Span,
                    prior.CurrentHead.AppendLogMerkleRoot.Span) ||
                !CryptographicOperations.FixedTimeEquals(
                    authored.ProtectedHead.CurrentValueMapRoot.Span,
                    prior.CurrentHead.CurrentValueMapRoot.Span))
                throw new CryptographicException(
                    "A DID2 head refresh changed directory content.");
            var heads = prior.Heads.Select(static head =>
                    new DeepIdV2DirectoryHeadRow(head.ExactAdh1,
                        head.CoreHash))
                .Append(new DeepIdV2DirectoryHeadRow(authored.ExactAdh1,
                    authored.CoreHash)).ToArray();
            var candidate = new DeepIdV2DirectoryStateRows(heads,
                prior.Transitions, prior.AdmissionRows);
            _ = lease.WriteAsync(candidate, trustedUpper,
                cancellationToken).AsTask().GetAwaiter().GetResult();
            Console.Out.WriteLine(
                $"Refreshed DID2 ADH1 generation/tree: {authored.ProtectedHead.LogGeneration}/{authored.ProtectedHead.TreeSize}");
            Console.Out.WriteLine(
                $"Refreshed DID2 ADH1 core hash: {Convert.ToHexString(authored.CoreHash.Span)}");
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    private static ContactResolveTrustedTimeContext ReadOperatorTrustedTime(
        IConfiguration configuration, CancellationToken cancellationToken)
    {
        var options = ContactResolveProductionAuthorityServiceCollectionExtensions
            .ReadRequiredOptions(configuration);
        var network = DirectoryPublicationHostingExtensions.Hex(
            options.NetworkIdHex, 16, "ContactResolve production authority network ID");
        var key = DirectoryPublicationProtectedFile.ReadKey(
            options.TrustedTimeIntegrityKeyPath);
        try
        {
            using var source = new ProtectedMonotonicContactResolveTrustedTimeSource(
                options.TrustedTimeStatePath, network, key);
            var trusted = source.ReadAsync(cancellationToken).AsTask()
                .GetAwaiter().GetResult();
            trusted.Validate();
            return trusted;
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    private static void ExportCurrentHead(IConfiguration configuration,
        string expectedFloorCoreHashHex, string outputPath,
        bool exportLineage, CancellationToken cancellationToken)
    {
        var options = configuration.GetSection("DeepIdV2DirectoryAuthority")
            .Get<DeepIdV2DirectoryAuthorityOptions>() ?? new();
        if (string.IsNullOrWhiteSpace(options.StatePath) ||
            string.IsNullOrWhiteSpace(options.IntegrityKeyPath) ||
            string.IsNullOrWhiteSpace(options.GenesisHeadPath) ||
            !Path.IsPathFullyQualified(options.StatePath) ||
            !Path.IsPathFullyQualified(options.IntegrityKeyPath) ||
            !Path.IsPathFullyQualified(options.GenesisHeadPath) ||
            !Path.IsPathFullyQualified(outputPath))
            throw new ArgumentException(
                "Current-head export requires exact absolute state, key, genesis and output paths.");
        var allPaths = options.ExactAuthorityPaths
            .Concat(options.ExactTimePolicyPaths)
            .Concat([options.StatePath, options.IntegrityKeyPath,
                options.GenesisHeadPath, outputPath])
            .Select(Path.GetFullPath).ToArray();
        var comparer = OperatingSystem.IsWindows()
            ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;
        if (allPaths.Distinct(comparer).Count() != allPaths.Length)
            throw new ArgumentException(
                "Current-head export inputs and output must be distinct.");
        var expectedFloorHash = DirectoryPublicationHostingExtensions.Hex(
            expectedFloorCoreHashHex, 32,
            "independently observed current DID2 floor core hash");
        var network = DirectoryPublicationHostingExtensions.Hex(
            options.NetworkIdHex, 16, "DID2 directory network ID");
        var authorityPin = DirectoryPublicationHostingExtensions.Hex(
            options.GenesisAuthorityCoreHashHex, 32,
            "DID2 genesis XNA1 core hash");
        var genesisPin = DirectoryPublicationHostingExtensions.Hex(
            options.GenesisHeadCoreHashHex, 32,
            "DID2 genesis ADH1 core hash");
        var authority = new DeepIdV2XPointAuthoritySource(network,
            authorityPin, options.ExactAuthorityPaths,
            options.ExactTimePolicyPaths).Read();
        var genesis = new DeepIdV2DirectoryBootstrapSource(
            options.GenesisHeadPath, genesisPin);
        var key = DirectoryPublicationProtectedFile.ReadKey(
            options.IntegrityKeyPath);
        try
        {
            using var verifier = DeepMlDsa65CandidateVerifierFactory
                .OpenForCurrentProcess();
            using var store = new DeepIdV2DirectoryStateStore(options.StatePath,
                key, network, genesis, authority, verifier,
                options.DeploymentProfileId);
            using var lease = store.Open(cancellationToken);
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (now <= 0)
                throw new InvalidOperationException("The operator clock is invalid.");
            var restored = lease.ReadAsync(checked((ulong)now),
                cancellationToken).AsTask().GetAwaiter().GetResult();
            var current = restored.CurrentHead;
            if (current.TreeSize == 0 ||
                !CryptographicOperations.FixedTimeEquals(
                    current.CoreHash.Span, expectedFloorHash))
                throw new CryptographicException(
                    "Authenticated ADA2 head differs from the independently observed current floor.");
            var exactOutput = Path.GetFullPath(outputPath);
            if (exportLineage)
            {
                ExportCoveredLineage(restored.Heads, current, exactOutput);
                return;
            }
            using var stream = new FileStream(exactOutput,
                FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096,
                FileOptions.WriteThrough);
            stream.Write(current.ExactAdh1.Span);
            stream.Flush(flushToDisk: true);
            Console.Out.WriteLine(
                $"Verified DID2 current ADH1 core hash: {Convert.ToHexString(current.CoreHash.Span)}");
            Console.Out.WriteLine(
                $"Verified DID2 current ADH1 generation/tree: {current.LogGeneration}/{current.TreeSize}");
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    private static void ExportCoveredLineage(
        IReadOnlyList<AccountDirectoryProtectedLkg> heads,
        AccountDirectoryProtectedLkg current, string outputDirectory)
    {
        if (heads.Count is < 2 or > 4097 ||
            !Directory.Exists(outputDirectory) ||
            (File.GetAttributes(outputDirectory) &
                FileAttributes.ReparsePoint) != 0 ||
            Directory.EnumerateFileSystemEntries(outputDirectory).Any() ||
            !CryptographicOperations.FixedTimeEquals(
                heads[^1].ExactAdh1.Span, current.ExactAdh1.Span))
            throw new InvalidOperationException(
                "DID2 covered-lineage export requires a complete nonempty history and a new empty output directory.");
        for (var index = 0; index < heads.Count - 1; index++)
            if (heads[index].LogGeneration != (ulong)index)
                throw new CryptographicException(
                    "The DID2 covered-head history is not contiguous.");
        var entries = new List<object>(heads.Count - 1);
        for (var index = 0; index < heads.Count - 1; index++)
        {
            var head = heads[index];
            var name = $"head-{index:D4}.adh1";
            var path = Path.Combine(outputDirectory, name);
            using (var stream = new FileStream(path, FileMode.CreateNew,
                FileAccess.Write, FileShare.None, 4096,
                FileOptions.WriteThrough))
            {
                stream.Write(head.ExactAdh1.Span);
                stream.Flush(flushToDisk: true);
            }
            entries.Add(new
            {
                generation = head.LogGeneration,
                fileName = name,
                coreHashHex = Convert.ToHexString(head.CoreHash.Span),
                sha256Hex = Convert.ToHexString(
                    SHA256.HashData(head.ExactAdh1.Span))
            });
        }
        var manifest = JsonSerializer.SerializeToUtf8Bytes(new
        {
            schema = "deep-did2-authenticated-covered-lineage.v1",
            currentFloorCoreHashHex = Convert.ToHexString(
                current.CoreHash.Span),
            coveredHeads = entries
        });
        using (var stream = new FileStream(Path.Combine(outputDirectory,
            "manifest.json"), FileMode.CreateNew, FileAccess.Write,
            FileShare.None, 4096, FileOptions.WriteThrough))
        {
            stream.Write(manifest);
            stream.Flush(flushToDisk: true);
        }
        Console.Out.WriteLine(
            $"Exported {entries.Count} exact DID2 covered heads under independently observed floor {Convert.ToHexString(current.CoreHash.Span)}");
    }

    private static void VerifyGenesisHead(IConfiguration configuration)
    {
        var options = configuration.GetSection("DeepIdV2DirectoryAuthority")
            .Get<DeepIdV2DirectoryAuthorityOptions>() ?? new();
        if (string.IsNullOrWhiteSpace(options.GenesisHeadPath) ||
            !Path.IsPathFullyQualified(options.GenesisHeadPath))
            throw new ArgumentException(
                "The DID2 genesis head path must be absolute.");
        var paths = options.ExactAuthorityPaths
            .Concat(options.ExactTimePolicyPaths)
            .Append(options.GenesisHeadPath)
            .ToArray();
        if (paths.Any(static path => string.IsNullOrWhiteSpace(path) ||
                !Path.IsPathFullyQualified(path)))
            throw new ArgumentException(
                "Every DID2 genesis input path must be absolute.");
        var comparer = OperatingSystem.IsWindows()
            ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;
        if (paths.Select(Path.GetFullPath).Distinct(comparer).Count() != paths.Length)
            throw new ArgumentException(
                "DID2 genesis input paths must be distinct.");
        var network = DirectoryPublicationHostingExtensions.Hex(
            options.NetworkIdHex, 16, "DID2 directory network ID");
        var networkPin = DirectoryPublicationHostingExtensions.Hex(
            options.GenesisAuthorityCoreHashHex, 32,
            "DID2 genesis XNA1 core hash");
        var authority = new DeepIdV2XPointAuthoritySource(network,
            networkPin, options.ExactAuthorityPaths,
            options.ExactTimePolicyPaths).Read();
        var head = DeepIdV2XPointAuthoritySource.ReadExact(
            Path.GetFullPath(options.GenesisHeadPath));
        if (head.Length > 4096)
            throw new InvalidDataException("DID2 genesis head is oversized.");
        var decoded = AccountDirectoryAdh1Codec.Decode(head);
        var unsigned = AccountDirectoryAdh1Codec.EncodeUnsigned(decoded);
        var domain = Encoding.ASCII.GetBytes(
            "Deep/AccountDirectory/V1/ADH1/core");
        var preimage = new byte[checked(domain.Length + 5 + unsigned.Length)];
        domain.CopyTo(preimage, 0);
        BinaryPrimitives.WriteUInt32BigEndian(
            preimage.AsSpan(domain.Length + 1), checked((uint)unsigned.Length));
        unsigned.CopyTo(preimage, domain.Length + 5);
        var coreHash = SHA256.HashData(preimage);
        if (!string.IsNullOrWhiteSpace(options.GenesisHeadCoreHashHex) &&
            !CryptographicOperations.FixedTimeEquals(coreHash,
                DirectoryPublicationHostingExtensions.Hex(
                    options.GenesisHeadCoreHashHex, 32,
                    "DID2 genesis ADH1 core hash")))
            throw new CryptographicException(
                "The configured DID2 genesis head pin differs from the signed head.");
        _ = DeepIdV2DirectoryBootstrapVerifier.RestoreGenesis(
            authority, head, coreHash);
        Console.Out.WriteLine(
            $"Verified DID2 genesis ADH1 core hash: {Convert.ToHexString(coreHash)}");
    }

    private static void ProvisionFloor(IConfiguration configuration,
        CancellationToken cancellationToken)
    {
        if (configuration.GetValue<bool>("AccountDirectoryAuthority:Enabled"))
            throw new InvalidOperationException(
                "DID2 floor cannot be provisioned while ADA1 admission is enabled.");
        var options = configuration.GetSection("DeepIdV2DirectoryAuthority")
            .Get<DeepIdV2DirectoryAuthorityOptions>() ?? new();
        if (string.IsNullOrWhiteSpace(
                options.LatestHeadFloorPostgreSqlConnectionString) ||
            string.IsNullOrWhiteSpace(options.GenesisHeadPath) ||
            !Path.IsPathFullyQualified(options.GenesisHeadPath))
            throw new ArgumentException(
                "DID2 floor connection and absolute signed genesis path are required.");
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
        using var floor = new DeepIdV2PostgreSqlLatestHeadFloor(
            options.LatestHeadFloorPostgreSqlConnectionString, network);
        floor.ProvisionGenesisAsync(genesis, cancellationToken).AsTask()
            .GetAwaiter().GetResult();
        Console.Out.WriteLine(
            $"DID2 external genesis floor provisioned: {Convert.ToHexString(genesis.CoreHash.Span)}");
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
