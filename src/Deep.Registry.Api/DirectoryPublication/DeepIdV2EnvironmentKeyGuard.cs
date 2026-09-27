#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Text;

namespace Deep.Registry.Api.DirectoryPublication;

/// <summary>
/// Linux permits duplicate raw environment names even though configuration
/// providers expose only one effective value. Reject ambiguous DID2 custody
/// paths and floor settings before DI is composed.
/// </summary>
internal static class DeepIdV2EnvironmentKeyGuard
{
    private const string Prefix = "DeepIdV2DirectoryAuthority__";
    private const int MaximumEnvironmentBytes = 4 * 1024 * 1024;
    private const int MaximumKeyBytes = 512;

    internal static void RequireUniqueProcessKeys()
    {
        if (!OperatingSystem.IsLinux()) return;
        using var raw = File.OpenRead("/proc/self/environ");
        RequireUniqueKeys(raw);
    }

    internal static void RequireUniqueKeys(Stream raw)
    {
        ArgumentNullException.ThrowIfNull(raw);
        var keys = new HashSet<string>(StringComparer.Ordinal);
        var key = new byte[MaximumKeyBytes];
        var keyLength = 0;
        var readingKey = true;
        var entryStarted = false;
        var bytesRead = 0;
        int next;
        while ((next = raw.ReadByte()) >= 0)
        {
            if (++bytesRead > MaximumEnvironmentBytes)
                throw new InvalidDataException(
                    "The raw process environment exceeds the DID2 startup bound.");
            if (next == 0)
            {
                if (entryStarted && readingKey)
                    throw new InvalidDataException(
                        "The raw process environment contains a key without a value separator.");
                keyLength = 0;
                readingKey = true;
                entryStarted = false;
                continue;
            }
            entryStarted = true;
            if (!readingKey) continue;
            if (next == '=')
            {
                var name = Encoding.UTF8.GetString(key.AsSpan(0, keyLength));
                if (name.StartsWith(Prefix, StringComparison.Ordinal) &&
                    !keys.Add(name))
                    throw new InvalidOperationException(
                        "A DID2 authority environment key is repeated.");
                readingKey = false;
                continue;
            }
            if (keyLength == key.Length)
                throw new InvalidDataException(
                    "A raw process environment key exceeds the startup bound.");
            key[keyLength++] = (byte)next;
        }
        if (entryStarted)
            throw new InvalidDataException(
                "The raw process environment ends inside a key or value.");
    }
}
#endif
