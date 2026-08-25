using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Sodium;

namespace Deep.Registry.Api;

public enum CallSignalType { Offer, Answer, IceCandidate, Reconnect, Bye }

public sealed record CallParty(string Value);

public sealed record CallSignalRequest(
    string CallId,
    string ConversationId,
    CallParty Sender,
    CallParty Recipient,
    CallSignalType Type,
    string Payload,
    DateTimeOffset CreatedAt,
    string? SenderEd25519,
    string? Signature,
    string? Nonce = null);

public enum CallSignalEnqueueResult
{
    Accepted,
    Idempotent,
    Invalid,
    Unauthorized,
    Replay,
    QueueFull,
    Unavailable
}

public enum CallAuthenticatedRequestStatus { Accepted, Unauthorized, Replay, Unavailable }

public sealed record CallInboxResult(
    CallAuthenticatedRequestStatus Status,
    IReadOnlyList<CallSignalRequest> Signals);

public sealed record CallSignalStoreStatus(bool Ready, string State);

internal sealed record CallSignalReplay(
    string Sender,
    string Nonce,
    string Digest,
    DateTimeOffset ExpiresAt);

internal sealed record CallRequestReplay(
    string Purpose,
    string Recipient,
    string Nonce,
    DateTimeOffset ExpiresAt);

internal sealed record PersistedCallState(
    string Version,
    IReadOnlyList<CallSignalRequest> Signals,
    IReadOnlyList<CallSignalReplay> SignalReplays,
    IReadOnlyList<CallRequestReplay> RequestReplays);

internal interface ICallSignalPersistence
{
    PersistedCallState? Load();
    void Save(PersistedCallState state);
    void Quarantine();
}

internal sealed class FileCallSignalPersistence(string statePath) : ICallSignalPersistence
{
    private const int MaximumStateBytes = 160 * 1024 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    public PersistedCallState? Load()
    {
        if (!File.Exists(statePath))
        {
            return null;
        }

        var info = new FileInfo(statePath);
        if (info.Length <= 0 || info.Length > MaximumStateBytes)
        {
            throw new InvalidDataException("Call state has an invalid size.");
        }

        using var stream = new FileStream(
            statePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            64 * 1024,
            FileOptions.SequentialScan);
        return JsonSerializer.Deserialize<PersistedCallState>(stream, JsonOptions)
               ?? throw new InvalidDataException("Call state is empty.");
    }

    public void Save(PersistedCallState state)
    {
        var directory = Path.GetDirectoryName(statePath);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var temporaryPath = statePath + ".tmp";
        try
        {
            using (var stream = new FileStream(
                       temporaryPath,
                       FileMode.Create,
                       FileAccess.Write,
                       FileShare.None,
                       64 * 1024,
                       FileOptions.WriteThrough))
            {
                JsonSerializer.Serialize(stream, state, JsonOptions);
                stream.Flush(flushToDisk: true);
                if (stream.Length > MaximumStateBytes)
                {
                    throw new InvalidDataException("Call state exceeds its size limit.");
                }
            }

            File.Move(temporaryPath, statePath, overwrite: true);
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
        if (!File.Exists(statePath))
        {
            return;
        }

        var quarantinePath = statePath + $".corrupt-{DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}";
        File.Move(statePath, quarantinePath, overwrite: false);
    }
}

internal sealed class UnavailableCallSignalPersistence : ICallSignalPersistence
{
    public PersistedCallState? Load() =>
        throw new IOException("Call state path is unavailable.");

    public void Save(PersistedCallState state) =>
        throw new IOException("Call state path is unavailable.");

    public void Quarantine()
    {
    }
}

public sealed class CallSignalStore
{
    internal const string SignalVersion = "deep-call-signal-v2";
    internal const string InboxPurpose = "deep-call-inbox-v2";
    internal const string IcePurpose = "deep-call-ice-v2";
    internal const string NonceHeader = "X-Deep-Nonce";
    private const string StateVersion = "deep-registry-call-state-v2";
    private const int MaxQueueDepth = 256;
    private const int MaxTotalSignals = 1024;
    private const int MaxReplayEntries = 16_384;
    private const int MaxPayloadLength = 128 * 1024;
    private static readonly TimeSpan SignalTtl = TimeSpan.FromMinutes(3);
    private static readonly TimeSpan ClockSkew = TimeSpan.FromMinutes(5);
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly object gate = new();
    private readonly ICallSignalPersistence persistence;
    private PersistedCallState state;
    private CallSignalStoreStatus status;

    internal CallSignalStore(ICallSignalPersistence persistence)
    {
        this.persistence = persistence;
        try
        {
            state = persistence.Load() ?? EmptyState();
            ValidateState(state);
            status = new CallSignalStoreStatus(true, "ready");
        }
        catch (Exception exception) when (exception is JsonException or InvalidDataException)
        {
            try
            {
                persistence.Quarantine();
            }
            catch (Exception quarantineException) when (quarantineException is IOException
                                                         or UnauthorizedAccessException)
            {
                // Readiness remains failed closed even if quarantine cannot be completed.
            }

            state = EmptyState();
            status = new CallSignalStoreStatus(false, "call-state-unavailable");
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            state = EmptyState();
            status = new CallSignalStoreStatus(false, "call-state-unavailable");
        }
    }

    public CallSignalStore(
        Microsoft.Extensions.Options.IOptions<CallInfrastructureOptions> callOptions,
        Microsoft.Extensions.Options.IOptions<RegistryOptions> registryOptions)
        : this(CreatePersistence(callOptions.Value, registryOptions.Value))
    {
    }

    public CallSignalStoreStatus GetStatus()
    {
        lock (gate)
        {
            return status;
        }
    }

    public CallSignalEnqueueResult Enqueue(CallSignalRequest request, DateTimeOffset now)
    {
        if (!IsValidShape(request)
            || request.CreatedAt < now - SignalTtl
            || request.CreatedAt > now + ClockSkew)
        {
            return CallSignalEnqueueResult.Invalid;
        }

        if (!HasValidAuthenticationShape(request) || !VerifyEnvelope(request))
        {
            return CallSignalEnqueueResult.Unauthorized;
        }

        var digest = Convert.ToHexStringLower(SHA256.HashData(BuildSigningPayload(request)));
        lock (gate)
        {
            if (!status.Ready)
            {
                return CallSignalEnqueueResult.Unavailable;
            }

            var candidate = PrunedState(state, now);
            var replay = candidate.SignalReplays.FirstOrDefault(item =>
                string.Equals(item.Sender, request.Sender.Value, StringComparison.Ordinal)
                && string.Equals(item.Nonce, request.Nonce, StringComparison.Ordinal));
            if (replay is not null)
            {
                return CryptographicOperations.FixedTimeEquals(
                    Encoding.ASCII.GetBytes(replay.Digest),
                    Encoding.ASCII.GetBytes(digest))
                    ? CallSignalEnqueueResult.Idempotent
                    : CallSignalEnqueueResult.Replay;
            }

            if (candidate.SignalReplays.Count >= MaxReplayEntries)
            {
                return CallSignalEnqueueResult.QueueFull;
            }

            var recipientDepth = candidate.Signals.Count(item =>
                string.Equals(item.Recipient.Value, request.Recipient.Value, StringComparison.Ordinal));
            if (recipientDepth >= MaxQueueDepth || candidate.Signals.Count >= MaxTotalSignals)
            {
                return CallSignalEnqueueResult.QueueFull;
            }

            candidate = candidate with
            {
                Signals = candidate.Signals.Append(request).ToArray(),
                SignalReplays = candidate.SignalReplays.Append(new CallSignalReplay(
                    request.Sender.Value,
                    request.Nonce!,
                    digest,
                    request.CreatedAt.Add(SignalTtl))).ToArray()
            };
            return TryCommit(candidate)
                ? CallSignalEnqueueResult.Accepted
                : CallSignalEnqueueResult.Unavailable;
        }
    }

    public CallInboxResult DrainAuthenticated(
        string recipient,
        IHeaderDictionary headers,
        DateTimeOffset now)
    {
        var authentication = AuthenticateRequest(recipient, headers, now, InboxPurpose, "inbox");
        if (authentication is null)
        {
            return new CallInboxResult(CallAuthenticatedRequestStatus.Unauthorized, []);
        }

        lock (gate)
        {
            if (!status.Ready)
            {
                return new CallInboxResult(CallAuthenticatedRequestStatus.Unavailable, []);
            }

            var candidate = PrunedState(state, now);
            if (HasRequestReplay(candidate, authentication))
            {
                return new CallInboxResult(CallAuthenticatedRequestStatus.Replay, []);
            }

            if (candidate.RequestReplays.Count >= MaxReplayEntries)
            {
                return new CallInboxResult(CallAuthenticatedRequestStatus.Unavailable, []);
            }

            var drained = candidate.Signals
                .Where(item => string.Equals(item.Recipient.Value, recipient, StringComparison.Ordinal))
                .ToArray();
            candidate = candidate with
            {
                Signals = candidate.Signals
                    .Where(item => !string.Equals(item.Recipient.Value, recipient, StringComparison.Ordinal))
                    .ToArray(),
                RequestReplays = candidate.RequestReplays.Append(authentication).ToArray()
            };
            return TryCommit(candidate)
                ? new CallInboxResult(CallAuthenticatedRequestStatus.Accepted, drained)
                : new CallInboxResult(CallAuthenticatedRequestStatus.Unavailable, []);
        }
    }

    public CallAuthenticatedRequestStatus AuthenticateIceRequest(
        string recipient,
        IHeaderDictionary headers,
        DateTimeOffset now)
    {
        var authentication = AuthenticateRequest(recipient, headers, now, IcePurpose, "ice-servers");
        if (authentication is null)
        {
            return CallAuthenticatedRequestStatus.Unauthorized;
        }

        lock (gate)
        {
            if (!status.Ready)
            {
                return CallAuthenticatedRequestStatus.Unavailable;
            }

            var candidate = PrunedState(state, now);
            if (HasRequestReplay(candidate, authentication))
            {
                return CallAuthenticatedRequestStatus.Replay;
            }

            if (candidate.RequestReplays.Count >= MaxReplayEntries)
            {
                return CallAuthenticatedRequestStatus.Unavailable;
            }

            candidate = candidate with
            {
                RequestReplays = candidate.RequestReplays.Append(authentication).ToArray()
            };
            return TryCommit(candidate)
                ? CallAuthenticatedRequestStatus.Accepted
                : CallAuthenticatedRequestStatus.Unavailable;
        }
    }

    internal static string ResolveStatePath(
        CallInfrastructureOptions callOptions,
        RegistryOptions registryOptions)
    {
        if (!string.IsNullOrWhiteSpace(callOptions.StatePath))
        {
            return Path.GetFullPath(callOptions.StatePath);
        }

        var registryStatePath = string.IsNullOrWhiteSpace(registryOptions.StatePath)
            ? Path.Combine(AppContext.BaseDirectory, "artifacts", "registry-state.json")
            : Path.GetFullPath(registryOptions.StatePath);
        return registryStatePath + ".calls-v2.json";
    }

    private static ICallSignalPersistence CreatePersistence(
        CallInfrastructureOptions callOptions,
        RegistryOptions registryOptions)
    {
        try
        {
            return new FileCallSignalPersistence(ResolveStatePath(callOptions, registryOptions));
        }
        catch (Exception exception) when (exception is ArgumentException
                                          or NotSupportedException
                                          or IOException)
        {
            return new UnavailableCallSignalPersistence();
        }
    }

    internal static byte[] BuildSigningPayload(CallSignalRequest request) =>
        JsonSerializer.SerializeToUtf8Bytes(new
        {
            version = SignalVersion,
            request.CallId,
            request.ConversationId,
            sender = request.Sender.Value,
            recipient = request.Recipient.Value,
            type = request.Type.ToString(),
            request.Payload,
            createdAtUnixMs = request.CreatedAt.ToUnixTimeMilliseconds(),
            senderEd25519 = request.SenderEd25519,
            nonce = request.Nonce
        }, JsonOptions);

    private static CallRequestReplay? AuthenticateRequest(
        string recipient,
        IHeaderDictionary headers,
        DateTimeOffset now,
        string purpose,
        string route)
    {
        if (!IsSessionId(recipient)
            || !headers.TryGetValue("X-Deep-Ed25519", out var publicKeyRaw)
            || !headers.TryGetValue("X-Deep-Timestamp", out var timestampRaw)
            || !headers.TryGetValue(NonceHeader, out var nonceRaw)
            || !headers.TryGetValue("X-Deep-Signature", out var signatureRaw)
            || !long.TryParse(timestampRaw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var timestamp)
            || !IsNonce(nonceRaw.ToString()))
        {
            return null;
        }

        DateTimeOffset signedAt;
        try
        {
            signedAt = DateTimeOffset.FromUnixTimeSeconds(timestamp);
        }
        catch (ArgumentOutOfRangeException)
        {
            return null;
        }

        if (signedAt < now - ClockSkew || signedAt > now + ClockSkew)
        {
            return null;
        }

        try
        {
            var publicKey = Convert.FromHexString(publicKeyRaw.ToString());
            if (!PublicKeyAuth.ConvertEd25519PublicKeyToCurve25519PublicKey(publicKey)
                    .SequenceEqual(Convert.FromHexString(recipient[2..])))
            {
                return null;
            }

            var nonce = nonceRaw.ToString();
            var payload = Encoding.UTF8.GetBytes(
                $"{purpose}\nGET\n/api/calls/{route}/{recipient}\n{recipient}\n{timestamp}\n{nonce}");
            if (!PublicKeyAuth.VerifyDetached(
                    Convert.FromBase64String(signatureRaw.ToString()),
                    payload,
                    publicKey))
            {
                return null;
            }

            return new CallRequestReplay(purpose, recipient, nonce, signedAt.Add(ClockSkew));
        }
        catch (Exception exception) when (exception is ArgumentException or FormatException)
        {
            return null;
        }
    }

    private bool TryCommit(PersistedCallState candidate)
    {
        try
        {
            var normalized = Normalize(candidate);
            persistence.Save(normalized);
            state = normalized;
            return true;
        }
        catch (Exception exception) when (exception is IOException
                                          or UnauthorizedAccessException
                                          or JsonException
                                          or InvalidDataException
                                          or ArgumentException
                                          or NotSupportedException)
        {
            status = new CallSignalStoreStatus(false, "call-state-unavailable");
            return false;
        }
    }

    private static PersistedCallState PrunedState(PersistedCallState source, DateTimeOffset now) =>
        source with
        {
            Signals = source.Signals.Where(item => item.CreatedAt >= now - SignalTtl).ToArray(),
            SignalReplays = source.SignalReplays.Where(item => item.ExpiresAt >= now).ToArray(),
            RequestReplays = source.RequestReplays.Where(item => item.ExpiresAt >= now).ToArray()
        };

    private static bool HasRequestReplay(PersistedCallState source, CallRequestReplay request) =>
        source.RequestReplays.Any(item =>
            string.Equals(item.Purpose, request.Purpose, StringComparison.Ordinal)
            && string.Equals(item.Recipient, request.Recipient, StringComparison.Ordinal)
            && string.Equals(item.Nonce, request.Nonce, StringComparison.Ordinal));

    private static bool IsValidShape(CallSignalRequest request) =>
        !string.IsNullOrWhiteSpace(request.CallId)
        && request.CallId.Length <= 64
        && !string.IsNullOrWhiteSpace(request.ConversationId)
        && request.ConversationId.Length <= 256
        && IsSessionId(request.Sender.Value)
        && IsSessionId(request.Recipient.Value)
        && !string.IsNullOrWhiteSpace(request.Payload)
        && request.Payload.Length <= MaxPayloadLength
        && request.Payload.StartsWith("sealed-v1:", StringComparison.Ordinal);

    private static bool HasValidAuthenticationShape(CallSignalRequest request) =>
        request.SenderEd25519?.Length == 64
        && request.Signature is { Length: > 0 and <= 128 }
        && IsNonce(request.Nonce);

    private static bool VerifyEnvelope(CallSignalRequest request)
    {
        try
        {
            var publicKey = Convert.FromHexString(request.SenderEd25519!);
            var senderX25519 = PublicKeyAuth.ConvertEd25519PublicKeyToCurve25519PublicKey(publicKey);
            if (!senderX25519.SequenceEqual(Convert.FromHexString(request.Sender.Value[2..])))
            {
                return false;
            }

            return PublicKeyAuth.VerifyDetached(
                Convert.FromBase64String(request.Signature!),
                BuildSigningPayload(request),
                publicKey);
        }
        catch (Exception exception) when (exception is ArgumentException or FormatException)
        {
            return false;
        }
    }

    private static bool IsSessionId(string? value) =>
        value is { Length: 66 }
        && value.StartsWith("05", StringComparison.Ordinal)
        && value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static bool IsNonce(string? value) =>
        value is { Length: 32 }
        && value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static PersistedCallState EmptyState() => new(StateVersion, [], [], []);

    private static PersistedCallState Normalize(PersistedCallState source) => source with
    {
        Signals = source.Signals.ToArray(),
        SignalReplays = source.SignalReplays
            .OrderBy(static item => item.Sender, StringComparer.Ordinal)
            .ThenBy(static item => item.Nonce, StringComparer.Ordinal)
            .ToArray(),
        RequestReplays = source.RequestReplays
            .OrderBy(static item => item.Purpose, StringComparer.Ordinal)
            .ThenBy(static item => item.Recipient, StringComparer.Ordinal)
            .ThenBy(static item => item.Nonce, StringComparer.Ordinal)
            .ToArray()
    };

    private static void ValidateState(PersistedCallState value)
    {
        if (!string.Equals(value.Version, StateVersion, StringComparison.Ordinal)
            || value.Signals is null
            || value.SignalReplays is null
            || value.RequestReplays is null
            || value.Signals.Count > MaxTotalSignals
            || value.SignalReplays.Count > MaxReplayEntries
            || value.RequestReplays.Count > MaxReplayEntries
            || value.Signals.Any(item => !IsValidShape(item)
                                         || !HasValidAuthenticationShape(item)
                                         || !VerifyEnvelope(item))
            || value.SignalReplays.Any(item => !IsSessionId(item.Sender)
                                               || !IsNonce(item.Nonce)
                                               || !IsLowerHex(item.Digest, 64))
            || value.RequestReplays.Any(item => item.Purpose is not (InboxPurpose or IcePurpose)
                                                || !IsSessionId(item.Recipient)
                                                || !IsNonce(item.Nonce))
            || value.Signals.GroupBy(static item => item.Recipient.Value, StringComparer.Ordinal)
                .Any(group => group.Count() > MaxQueueDepth)
            || value.Signals.Any(signal => !value.SignalReplays.Any(replay =>
                string.Equals(replay.Sender, signal.Sender.Value, StringComparison.Ordinal)
                && string.Equals(replay.Nonce, signal.Nonce, StringComparison.Ordinal)
                && string.Equals(
                    replay.Digest,
                    Convert.ToHexStringLower(SHA256.HashData(BuildSigningPayload(signal))),
                    StringComparison.Ordinal)))
            || value.SignalReplays.GroupBy(static item => (item.Sender, item.Nonce)).Any(group => group.Count() > 1)
            || value.RequestReplays.GroupBy(static item => (item.Purpose, item.Recipient, item.Nonce))
                .Any(group => group.Count() > 1))
        {
            throw new InvalidDataException("Call state violates the v2 schema.");
        }
    }

    private static bool IsLowerHex(string? value, int length) =>
        value?.Length == length
        && value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f');
}
