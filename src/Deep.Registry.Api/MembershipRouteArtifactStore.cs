using Microsoft.Extensions.Options;

namespace Deep.Registry.Api;

public sealed class MembershipRouteArtifactStore(IOptions<RegistryOptions> options)
{
    public const int MaximumAllowedBytes = 2 * 1024 * 1024;

    public async Task<byte[]?> ReadAsync(CancellationToken cancellationToken = default)
    {
        var path = options.Value.MembershipRouteArtifactPath;
        if (string.IsNullOrWhiteSpace(path))
            return null;
        if (options.Value.MembershipRouteArtifactMaximumBytes is <= 0 or > MaximumAllowedBytes)
            throw new InvalidOperationException("Membership artifact byte limit is invalid.");

        var info = new FileInfo(Path.GetFullPath(path));
        if (!info.Exists)
            return null;
        if (info.Length is <= 0 || info.Length > options.Value.MembershipRouteArtifactMaximumBytes)
            throw new InvalidDataException("Membership artifact is outside its configured byte limit.");

        await using var input = new FileStream(
            info.FullName,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            16 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        using var output = new MemoryStream(checked((int)info.Length));
        var buffer = new byte[16 * 1024];
        while (true)
        {
            var read = await input.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0)
                return output.ToArray();
            if (output.Length + read > options.Value.MembershipRouteArtifactMaximumBytes)
                throw new InvalidDataException("Membership artifact changed beyond its configured byte limit.");
            output.Write(buffer, 0, read);
        }
    }
}
