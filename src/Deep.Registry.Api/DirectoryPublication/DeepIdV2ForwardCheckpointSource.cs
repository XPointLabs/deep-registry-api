#if DEEP_PROTOCOL_DIRECTORY_V1
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Registry.Api.DirectoryPublication;

/// <summary>
/// Read-only offline-root ADF1 import. No root signing key or signing callback
/// exists in this service; the proof author later authenticates every exact
/// record with the live DTT1 before releasing a response.
/// </summary>
internal interface IDeepIdV2ForwardCheckpointSource
{
    DeepIdV2ForwardTailAuthoringInput Read(
        VerifiedXPointNetworkAuthority authority,
        DeepIdV2RestoredAuthorityState restored,
        ReadOnlySpan<byte> queriedDirectoryLeafKey,
        AccountDirectoryProtectedLkg callerProtectedLkg);
}

internal sealed class DeepIdV2FileForwardCheckpointSource :
    IDeepIdV2ForwardCheckpointSource
{
    private readonly string[] exactAdf1Paths;

    internal DeepIdV2FileForwardCheckpointSource(
        IReadOnlyList<string> exactAdf1Paths)
    {
        ArgumentNullException.ThrowIfNull(exactAdf1Paths);
        if (exactAdf1Paths.Count is < 1 or > 64 ||
            exactAdf1Paths.Any(string.IsNullOrWhiteSpace))
            throw new ArgumentException(
                "The ordered offline-root ADF1 import is invalid.",
                nameof(exactAdf1Paths));
        this.exactAdf1Paths = exactAdf1Paths.Select(Path.GetFullPath)
            .ToArray();
        var comparer = OperatingSystem.IsWindows()
            ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;
        if (this.exactAdf1Paths.Distinct(comparer).Count() !=
            this.exactAdf1Paths.Length)
            throw new ArgumentException(
                "Offline-root ADF1 import paths must be distinct.",
                nameof(exactAdf1Paths));
    }

    public DeepIdV2ForwardTailAuthoringInput Read(
        VerifiedXPointNetworkAuthority authority,
        DeepIdV2RestoredAuthorityState restored,
        ReadOnlySpan<byte> queriedDirectoryLeafKey,
        AccountDirectoryProtectedLkg callerProtectedLkg)
    {
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(restored);
        ArgumentNullException.ThrowIfNull(callerProtectedLkg);
        var exactAdf1 = new ReadOnlyMemory<byte>[exactAdf1Paths.Length];
        for (var index = 0; index < exactAdf1.Length; index++)
            exactAdf1[index] = DirectoryPublicationProtectedFile.ReadBounded(
                exactAdf1Paths[index], 16_384);
        return DeepIdV2ForwardTailMaterialAuthor.Create(authority,
            restored.Heads, restored.Transitions,
            restored.CurrentCheckpoints, queriedDirectoryLeafKey,
            callerProtectedLkg, exactAdf1);
    }
}
#endif
