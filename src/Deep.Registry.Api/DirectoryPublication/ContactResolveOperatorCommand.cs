#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Globalization;
using System.Security.Cryptography;

namespace Deep.Registry.Api.DirectoryPublication;

internal static class ContactResolveOperatorCommand
{
    private const string Command = "contact-resolve-authority";

    internal static async ValueTask<int?> TryRunAsync(
        string[] args,
        IConfiguration configuration,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(configuration);
        if (args.Length == 0 || !string.Equals(args[0], Command, StringComparison.Ordinal))
            return null;

        try
        {
            if (args.Length < 2)
                throw new ArgumentException("A ContactResolve operator action is required.");
            var values = Parse(args.AsSpan(2));
            return args[1] switch
            {
                "provision-time" => ProvisionTime(configuration, values),
                "author-package" => await AuthorPackageAsync(
                    configuration, values, cancellationToken).ConfigureAwait(false),
                _ => throw new ArgumentException("The ContactResolve operator action is unknown."),
            };
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (exception is ArgumentException or IOException or
            CryptographicException or InvalidDataException or InvalidOperationException or
            FormatException or OverflowException)
        {
            Console.Error.WriteLine("ContactResolve operator action failed closed.");
            return 2;
        }
    }

    private static int ProvisionTime(
        IConfiguration configuration,
        IReadOnlyDictionary<string, string> values)
    {
        RequireExactOptions(values,
            required: ["observed-unix-time", "valid-until-unix", "uncertainty-seconds"],
            optional: ["expected-state-sha256"]);
        var options = ContactResolveProductionAuthorityServiceCollectionExtensions
            .ReadRequiredOptions(configuration);
        var network = DirectoryPublicationHostingExtensions.Hex(
            options.NetworkIdHex, 16, "ContactResolve production authority network ID");
        var key = DirectoryPublicationProtectedFile.ReadKey(options.TrustedTimeIntegrityKeyPath);
        var bootId = RandomNumberGenerator.GetBytes(16);
        try
        {
            var expected = values.TryGetValue("expected-state-sha256", out var expectedHex)
                ? DirectoryPublicationHostingExtensions.Hex(
                    expectedHex, 32, "expected trusted-time state SHA-256")
                : [];
            var hash = ProtectedMonotonicContactResolveTrustedTimeSource.Provision(
                options.TrustedTimeStatePath,
                network,
                key,
                U64(values["observed-unix-time"], "observed Unix time"),
                U64(values["valid-until-unix"], "valid-until Unix time"),
                U32(values["uncertainty-seconds"], "uncertainty seconds"),
                expected,
                ProtectedMonotonicContactResolveTrustedTimeSource.ReadPlatformMonotonicSeconds(),
                bootId);
            try
            {
                Console.Out.WriteLine($"ContactResolve trusted-time state ready: {Convert.ToHexString(hash)}");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(hash);
                if (expected.Length != 0) CryptographicOperations.ZeroMemory(expected);
            }
            return 0;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(bootId);
        }
    }

    private static async ValueTask<int> AuthorPackageAsync(
        IConfiguration configuration,
        IReadOnlyDictionary<string, string> values,
        CancellationToken cancellationToken)
    {
        RequireExactOptions(values, required: ["request", "output"], optional: []);
        var inputPath = ExistingRegularFile(values["request"]);
        var outputPath = NewRegularFile(values["output"]);
        var encodedRequest = DirectoryPublicationProtectedFile.ReadBounded(
            inputPath, ContactResolveDirectoryPackageCodec.AbsoluteMaximumRequestBytes);
        try
        {
            var request = ContactResolveDirectoryPackageCodec.DecodeRequest(encodedRequest);
            var services = new ServiceCollection();
            _ = services.AddContactResolveDirectoryPackages(configuration);
            await using var provider = services.BuildServiceProvider(new ServiceProviderOptions
            {
                ValidateOnBuild = true,
                ValidateScopes = true,
            });
            var issuer = ProductionContactResolveDirectoryPackageIssuer
                .CreateForOfflineOperator(provider);
            var package = await issuer.IssueAsync(request, cancellationToken).ConfigureAwait(false);
            var encodedResponse = ContactResolveDirectoryPackageCodec.EncodeResponse(request, package);
            try
            {
                WriteNew(outputPath, encodedResponse);
                var digest = SHA256.HashData(encodedResponse);
                try
                {
                    Console.Out.WriteLine(
                        $"ContactResolve CDR1 package ready: {encodedResponse.Length} bytes, SHA-256 {Convert.ToHexString(digest)}");
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(digest);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(encodedResponse);
            }
            return 0;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encodedRequest);
        }
    }

    private static Dictionary<string, string> Parse(ReadOnlySpan<string> args)
    {
        if ((args.Length & 1) != 0)
            throw new ArgumentException("ContactResolve operator options require exact name/value pairs.");
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var index = 0; index < args.Length; index += 2)
        {
            var name = args[index];
            if (!name.StartsWith("--", StringComparison.Ordinal) || name.Length < 3 ||
                string.IsNullOrWhiteSpace(args[index + 1]) ||
                !result.TryAdd(name[2..], args[index + 1]))
                throw new ArgumentException("A ContactResolve operator option is invalid or duplicated.");
        }
        return result;
    }

    private static void RequireExactOptions(
        IReadOnlyDictionary<string, string> values,
        IReadOnlyList<string> required,
        IReadOnlyList<string> optional)
    {
        if (required.Any(value => !values.ContainsKey(value)) ||
            values.Keys.Any(value => !required.Contains(value) && !optional.Contains(value)))
            throw new ArgumentException("The ContactResolve operator option set is incomplete or unknown.");
    }

    private static string ExistingRegularFile(string value)
    {
        var path = Path.GetFullPath(value);
        if (!File.Exists(path) || (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException("The ContactResolve request input is unavailable.");
        return path;
    }

    private static string NewRegularFile(string value)
    {
        var path = Path.GetFullPath(value);
        if (File.Exists(path) || Directory.Exists(path))
            throw new IOException("The ContactResolve output already exists.");
        var directory = Path.GetDirectoryName(path);
        if (string.IsNullOrWhiteSpace(directory) || !Directory.Exists(directory) ||
            (File.GetAttributes(directory) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException("The ContactResolve output directory is unavailable.");
        return path;
    }

    private static void WriteNew(string path, ReadOnlySpan<byte> bytes)
    {
        using var stream = new FileStream(
            path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096,
            FileOptions.WriteThrough);
        stream.Write(bytes);
        stream.Flush(true);
    }

    private static ulong U64(string value, string name) =>
        ulong.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed)
            ? parsed
            : throw new ArgumentException($"The {name} is invalid.");

    private static uint U32(string value, string name) =>
        uint.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed)
            ? parsed
            : throw new ArgumentException($"The {name} is invalid.");
}
#endif
