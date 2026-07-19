using System.Text.Json;

namespace Deep.Registry.Api;

public interface IMembershipProjectionPersistence
{
    byte[]? Read(int maximumBytes);
    void Write(ReadOnlySpan<byte> state);
    void Quarantine();
    IDisposable AcquireExclusiveLease();
}

public sealed class FileMembershipProjectionPersistence : IMembershipProjectionPersistence
{
    private readonly string _statePath;

    public FileMembershipProjectionPersistence(string statePath)
    {
        _statePath = statePath;
    }

    public byte[]? Read(int maximumBytes)
    {
        if (!File.Exists(_statePath))
        {
            return null;
        }

        using var stream = new FileStream(
            _statePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 16 * 1024,
            FileOptions.SequentialScan);
        if (stream.Length > maximumBytes)
        {
            throw new InvalidDataException("Persisted membership state exceeds its hard limit.");
        }

        var bytes = new byte[checked((int)stream.Length)];
        stream.ReadExactly(bytes);
        return bytes;
    }

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

    public IDisposable AcquireExclusiveLease()
    {
        var directory = Path.GetDirectoryName(_statePath);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        try
        {
            return new FileStream(
                $"{_statePath}.lock",
                FileMode.OpenOrCreate,
                FileAccess.ReadWrite,
                FileShare.None,
                bufferSize: 1,
                FileOptions.WriteThrough);
        }
        catch (IOException exception) when (IsSharingViolation(exception))
        {
            throw new MembershipProjectionLeaseBusyException(
                "The membership projection continuity lease is busy.",
                exception);
        }
    }

    private static bool IsSharingViolation(IOException exception) =>
        (exception.HResult & 0xffff) is 11 or 32 or 33;
}

public sealed class MembershipProjectionLeaseBusyException : IOException
{
    public MembershipProjectionLeaseBusyException(
        string message,
        Exception innerException)
        : base(message, innerException)
    {
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
    public long Generation { get; init; }
    public IReadOnlyList<PersistedForkRecord> ForkRecords { get; init; } = [];
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
    public PersistedLastKnownGood AcceptedAuthorityLkg { get; init; } = new();
    public string AcceptedDelegationBase64 { get; init; } = "";
}

internal sealed record PersistedForkRecord
{
    public string Domain { get; init; } = "";
    public ulong Sequence { get; init; }
    public string PreviousHashHex { get; init; } = "";
    public string FirstEnvelopeBase64 { get; init; } = "";
    public string SecondEnvelopeBase64 { get; init; } = "";
    public string FirstCanonicalStatementBase64 { get; init; } = "";
    public string SecondCanonicalStatementBase64 { get; init; } = "";
    public string FirstHashHex { get; init; } = "";
    public string SecondHashHex { get; init; } = "";
}

internal static class MembershipProjectionJson
{
    public static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true
    };
}
