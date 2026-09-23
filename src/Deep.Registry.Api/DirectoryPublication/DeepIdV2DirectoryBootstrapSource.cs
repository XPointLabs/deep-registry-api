#if DEEP_PROTOCOL_DIRECTORY_V1
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Registry.Api.DirectoryPublication;

/// <summary>
/// Reads the operator-pinned, signed DID2 empty head independently of ADA1.
/// The expected core hash is supplied from protected deployment configuration;
/// it is never inferred from the head file being read.
/// </summary>
internal sealed class DeepIdV2DirectoryBootstrapSource
{
    private const int MaximumHeadBytes = 4096;
    private readonly string exactHeadPath;
    private readonly byte[] protectedCoreHash;

    internal DeepIdV2DirectoryBootstrapSource(string exactHeadPath,
        ReadOnlySpan<byte> protectedCoreHash)
    {
        if (string.IsNullOrWhiteSpace(exactHeadPath))
            throw new ArgumentException("A separate DID2 genesis head file is required.",
                nameof(exactHeadPath));
        if (protectedCoreHash.Length != 32 ||
            protectedCoreHash.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("A protected DID2 genesis core hash is required.",
                nameof(protectedCoreHash));
        this.exactHeadPath = Path.GetFullPath(exactHeadPath);
        this.protectedCoreHash = protectedCoreHash.ToArray();
    }

    internal AccountDirectoryProtectedLkg Read(
        VerifiedXPointNetworkAuthority authority)
    {
        ArgumentNullException.ThrowIfNull(authority);
        var exact = DirectoryPublicationProtectedFile.ReadBounded(
            exactHeadPath, MaximumHeadBytes);
        return DeepIdV2DirectoryBootstrapVerifier.RestoreGenesis(
            authority, exact, protectedCoreHash);
    }
}
#endif
