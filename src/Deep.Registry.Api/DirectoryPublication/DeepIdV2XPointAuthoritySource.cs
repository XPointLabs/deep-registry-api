#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Security.Cryptography;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Registry.Api.DirectoryPublication;

/// <summary>
/// Re-verifies the exact XNA1/DTS1 lineage from a separately pinned genesis.
/// DID2 admission must not obtain network authority through an ADA1/ADP1 reader.
/// </summary>
internal sealed class DeepIdV2XPointAuthoritySource
{
    private readonly byte[] networkId;
    private readonly byte[] genesisCoreHash;
    private readonly string[] authorityPaths;
    private readonly string[] timePolicyPaths;

    internal DeepIdV2XPointAuthoritySource(ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> genesisAuthorityCoreHash,
        IReadOnlyList<string> exactAuthorityPaths,
        IReadOnlyList<string> exactTimePolicyPaths)
    {
        if (networkId.Length != 16 || networkId.IndexOfAnyExcept((byte)0) < 0 ||
            genesisAuthorityCoreHash.Length != 32 ||
            genesisAuthorityCoreHash.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("DID2 network genesis pin is invalid.");
        ArgumentNullException.ThrowIfNull(exactAuthorityPaths);
        ArgumentNullException.ThrowIfNull(exactTimePolicyPaths);
        if (exactAuthorityPaths.Count is < 1 or > 64 ||
            exactTimePolicyPaths.Count is < 1 or > 64)
            throw new ArgumentException("DID2 authority lineage count is invalid.");
        authorityPaths = ValidatePaths(exactAuthorityPaths);
        timePolicyPaths = ValidatePaths(exactTimePolicyPaths);
        var comparer = OperatingSystem.IsWindows()
            ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;
        if (authorityPaths.Concat(timePolicyPaths).Distinct(comparer).Count() !=
            authorityPaths.Length + timePolicyPaths.Length)
            throw new ArgumentException("DID2 authority artifact paths must be distinct.");
        this.networkId = networkId.ToArray();
        genesisCoreHash = genesisAuthorityCoreHash.ToArray();
    }

    internal VerifiedXPointNetworkAuthority Read()
    {
        var authorities = authorityPaths.Select(ReadExact).ToArray();
        var policies = timePolicyPaths.Select(ReadExact).ToArray();
        try
        {
            var verified = XPointNetworkAuthorityVerifier.Verify(
                new XPointNetworkGenesisPin(networkId, genesisCoreHash),
                authorities.Select(static bytes => (ReadOnlyMemory<byte>)bytes).ToArray(),
                policies.Select(static bytes => (ReadOnlyMemory<byte>)bytes).ToArray());
            if (!CryptographicOperations.FixedTimeEquals(
                    verified.NetworkId.Span, networkId))
                throw new CryptographicException(
                    "DID2 authority lineage changed networks.");
            return verified;
        }
        finally
        {
            foreach (var artifact in authorities.Concat(policies))
                CryptographicOperations.ZeroMemory(artifact);
        }
    }

    private static string[] ValidatePaths(IReadOnlyList<string> paths) =>
        paths.Select(path => string.IsNullOrWhiteSpace(path)
                ? throw new ArgumentException("DID2 authority artifact path is empty.")
                : Path.GetFullPath(path))
            .ToArray();

    internal static byte[] ReadExact(string path)
    {
        var current = Path.GetPathRoot(path) ?? throw new InvalidDataException(
            "DID2 authority artifact has no filesystem root.");
        foreach (var part in Path.GetRelativePath(current, path).Split(
                     [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar],
                     StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, part);
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new CryptographicException(
                    "DID2 authority artifact path contains a reparse point.");
        }
        return DirectoryPublicationProtectedFile.ReadBounded(path, 65_535);
    }
}
#endif
