using System.Text.Json;

namespace Deep.Registry.Api;

public interface IMembershipProjectionPersistence
{
    byte[]? Read();
    void Write(ReadOnlySpan<byte> state);
    void Quarantine();
}

public sealed class FileMembershipProjectionPersistence : IMembershipProjectionPersistence
{
    private readonly string _statePath;

    public FileMembershipProjectionPersistence(string statePath)
    {
        _statePath = statePath;
    }

    public byte[]? Read() => File.Exists(_statePath) ? File.ReadAllBytes(_statePath) : null;

    public void Write(ReadOnlySpan<byte> state)
    {
        var directory = Path.GetDirectoryName(_statePath);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var temporaryPath = $"{_statePath}.tmp-{Guid.NewGuid():N}";
        try
        {
            using (var stream = new FileStream(
                       temporaryPath,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       bufferSize: 16 * 1024,
                       FileOptions.WriteThrough))
            {
                stream.Write(state);
                stream.Flush(flushToDisk: true);
            }

            if (File.Exists(_statePath))
            {
                File.Replace(temporaryPath, _statePath, null);
            }
            else
            {
                File.Move(temporaryPath, _statePath);
            }
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }

    public void Quarantine()
    {
        if (!File.Exists(_statePath))
        {
            return;
        }

        var quarantinePath =
            $"{_statePath}.corrupt-{DateTimeOffset.UtcNow:yyyyMMddHHmmssfff}.bak";
        File.Move(_statePath, quarantinePath, true);
    }
}

internal sealed record PersistedMembershipProjection
{
    public string Schema { get; init; } = MembershipProjectionService.StateSchema;
    public string ContractIdentifier { get; init; } = "";
    public string PackageVersion { get; init; } = "";
    public string NetworkIdHex { get; init; } = "";
    public string GenesisSha256 { get; init; } = "";
    public string GenesisBytesBase64 { get; init; } = "";
    public IReadOnlyList<PersistedSignature> GenesisSignatures { get; init; } = [];
    public PersistedLastKnownGood AuthorityLkg { get; init; } = new();
    public PersistedLastKnownGood AuthorityPredecessorLkg { get; init; } = new();
    public string AuthorityEnvelopeKind { get; init; } = "";
    public string AuthorityEnvelopeBase64 { get; init; } = "";
    public string ActiveDelegationBase64 { get; init; } = "";
    public IReadOnlyList<string> RevokedDelegationHashes { get; init; } = [];
    public PersistedContentDomain Bridge { get; init; } = new();
    public PersistedContentDomain Membership { get; init; } = new();
    public bool ForkDetected { get; init; }
}

internal sealed record PersistedSignature
{
    public string SignerIdHex { get; init; } = "";
    public byte Domain { get; init; }
    public string SignatureBase64 { get; init; } = "";
}

internal sealed record PersistedLastKnownGood
{
    public string NetworkIdHex { get; init; } = "";
    public uint PolicyVersion { get; init; }
    public ulong Sequence { get; init; }
    public string CanonicalHashHex { get; init; } = "";
}

internal sealed record PersistedContentDomain
{
    public PersistedLastKnownGood Lkg { get; init; } = new();
    public PersistedLastKnownGood PredecessorLkg { get; init; } = new();
    public string EnvelopeBase64 { get; init; } = "";
    public long ValidUntilUnixSeconds { get; init; }
}

internal static class MembershipProjectionJson
{
    public static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true
    };
}
