#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Security.Cryptography;

namespace Deep.Registry.Api.DirectoryPublication;

// Explicit operator transition, never a runtime missing-floor initializer.
internal static class ManualToNtsFloorUpgrade
{
    internal static void Run(string manualPath, string floorPath,
        ReadOnlySpan<byte> network, ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> expectedManualHash, ulong signedPolicyLower,
        CancellationToken cancellationToken, Action? beforeActivation = null)
    {
        var pending = floorPath + ".manual-upgrade-pending";
        var fence = floorPath + ".manual-upgrade-fence";
        var paths = new[] { manualPath, floorPath, pending, fence, manualPath + ".lock", floorPath + ".lock" };
        var comparer = OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;
        if (paths.Any(path => !Path.IsPathFullyQualified(path)) ||
            paths.Select(Path.GetFullPath).Distinct(comparer).Count() != paths.Length ||
            network.Length != 16 || key.Length != 32 || expectedManualHash.Length != 32 ||
            network.IndexOfAnyExcept((byte)0) < 0 || key.IndexOfAnyExcept((byte)0) < 0 ||
            expectedManualHash.IndexOfAnyExcept((byte)0) < 0 || signedPolicyLower == 0)
            throw new ArgumentException("Manual-to-NTS upgrade custody is invalid.");
        foreach (var path in paths) RequireUnlinkedPath(path);
        using var manualLease = DirectoryPublicationProtectedFile.AcquireLease(manualPath, cancellationToken);
        using var floorLease = DirectoryPublicationProtectedFile.AcquireLease(floorPath, cancellationToken);
        if (File.Exists(floorPath)) throw new InvalidDataException("NTS floor already exists; upgrade cannot reset it.");
        var lower = ProtectedMonotonicContactResolveTrustedTimeSource.ReadRetainedLowerForUpgrade(
            manualPath, network, key, expectedManualHash);
        // Policy is a conservative acceptance constraint, not current time.
        lower = Math.Max(lower, signedPolicyLower);
        var initialFloor = AutomaticNtsTrustedTimeSource.EncodeInitialFloor(network, key, lower);
        var fencePayload = new byte[86];
        "NTU1"u8.CopyTo(fencePayload); fencePayload[5] = 1;
        network.CopyTo(fencePayload.AsSpan(6)); expectedManualHash.CopyTo(fencePayload.AsSpan(22));
        SHA256.HashData(initialFloor).CopyTo(fencePayload, 54);
        var expectedFence = DirectoryPublicationProtectedFile.Protect(fencePayload, key);
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (File.Exists(fence))
            {
                RequireExactFile(fence, expectedFence);
                // No pending file means activation already finished. A later
                // missing floor is loss, not a new provisioning opportunity.
                if (!File.Exists(pending)) throw new InvalidDataException("Activated NTS floor is missing; restore custody.");
            }
            if (File.Exists(pending)) RequireExactFile(pending, initialFloor);
            else WriteNew(pending, initialFloor);
            if (!File.Exists(fence)) WriteNew(fence, expectedFence);
            RequireExactFile(fence, expectedFence); RequireExactFile(pending, initialFloor);
            beforeActivation?.Invoke(); // Internal crash boundary; production supplies no hook.
            cancellationToken.ThrowIfCancellationRequested();
            File.Move(pending, floorPath, overwrite: false);
            RequireExactFile(floorPath, initialFloor);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(initialFloor);
            CryptographicOperations.ZeroMemory(fencePayload);
            CryptographicOperations.ZeroMemory(expectedFence);
        }
    }

    private static void RequireExactFile(string path, byte[] expected)
    {
        RequireUnlinkedPath(path);
        var actual = DirectoryPublicationProtectedFile.ReadBounded(path, expected.Length);
        try
        {
            if (actual.Length != expected.Length || !CryptographicOperations.FixedTimeEquals(actual, expected))
                throw new CryptographicException("NTS upgrade retained bytes conflict with the exact transition.");
        }
        finally { CryptographicOperations.ZeroMemory(actual); }
    }

    private static void WriteNew(string path, byte[] bytes)
    {
        RequireUnlinkedPath(path);
        using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough);
        stream.Write(bytes); stream.Flush(true);
    }

    private static void RequireUnlinkedPath(string path)
    {
        var current = Path.GetPathRoot(path)!;
        foreach (var part in Path.GetRelativePath(current, path).Split(
            [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar], StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, part);
            if ((File.Exists(current) || Directory.Exists(current)) &&
                (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new CryptographicException("Link in NTS upgrade custody path.");
        }
    }
}
#endif
