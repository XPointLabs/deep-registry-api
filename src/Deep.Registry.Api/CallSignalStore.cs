using System.Collections.Concurrent;
using System.Globalization;
using System.Text;
using System.Text.Json;
using Sodium;

namespace Deep.Registry.Api;

public enum CallSignalType
{
    Offer,
    Answer,
    IceCandidate,
    Reconnect,
    Bye
}

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
    string? Signature);

public enum CallSignalEnqueueResult
{
    Accepted,
    Invalid,
    Unauthorized,
    QueueFull
}

public sealed class CallSignalStore
{
    private const int MaxQueueDepth = 256;
    private const int MaxPayloadLength = 128 * 1024;
    private static readonly TimeSpan SignalTtl = TimeSpan.FromMinutes(3);
    private static readonly TimeSpan ClockSkew = TimeSpan.FromMinutes(5);
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly ConcurrentDictionary<string, ConcurrentQueue<CallSignalRequest>> inboxes = new(StringComparer.Ordinal);

    public CallSignalEnqueueResult Enqueue(CallSignalRequest request, DateTimeOffset now)
    {
        if (!IsValidShape(request)
            || request.CreatedAt < now - SignalTtl
            || request.CreatedAt > now + ClockSkew)
        {
            return CallSignalEnqueueResult.Invalid;
        }

        if (!VerifyEnvelope(request))
        {
            return CallSignalEnqueueResult.Unauthorized;
        }

        var queue = inboxes.GetOrAdd(request.Recipient.Value, static _ => new ConcurrentQueue<CallSignalRequest>());
        Prune(queue, now);
        if (queue.Count >= MaxQueueDepth)
        {
            return CallSignalEnqueueResult.QueueFull;
        }

        queue.Enqueue(request);
        return CallSignalEnqueueResult.Accepted;
    }

    public IReadOnlyList<CallSignalRequest> Drain(string recipient, DateTimeOffset now)
    {
        if (!inboxes.TryGetValue(recipient, out var queue))
        {
            return [];
        }

        var result = new List<CallSignalRequest>();
        while (queue.TryDequeue(out var signal))
        {
            if (signal.CreatedAt >= now - SignalTtl)
            {
                result.Add(signal);
            }
        }

        if (queue.IsEmpty)
        {
            inboxes.TryRemove(recipient, out _);
        }

        return result;
    }

    public bool VerifyInboxRequest(string recipient, IHeaderDictionary headers, DateTimeOffset now)
    {
        if (!IsSessionId(recipient)
            || !headers.TryGetValue("X-Deep-Ed25519", out var publicKeyRaw)
            || !headers.TryGetValue("X-Deep-Timestamp", out var timestampRaw)
            || !headers.TryGetValue("X-Deep-Signature", out var signatureRaw)
            || !long.TryParse(timestampRaw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var timestamp))
        {
            return false;
        }

        var signedAt = DateTimeOffset.FromUnixTimeSeconds(timestamp);
        if (signedAt < now - ClockSkew || signedAt > now + ClockSkew)
        {
            return false;
        }

        try
        {
            var publicKey = Convert.FromHexString(publicKeyRaw.ToString());
            if (!PublicKeyAuth.ConvertEd25519PublicKeyToCurve25519PublicKey(publicKey)
                    .SequenceEqual(Convert.FromHexString(recipient[2..])))
            {
                return false;
            }

            return PublicKeyAuth.VerifyDetached(
                Convert.FromBase64String(signatureRaw.ToString()),
                Encoding.UTF8.GetBytes($"deep-call-inbox-v1\n{recipient}\n{timestamp}"),
                publicKey);
        }
        catch (Exception exception) when (exception is ArgumentException or FormatException)
        {
            return false;
        }
    }

    private static bool IsValidShape(CallSignalRequest request) =>
        !string.IsNullOrWhiteSpace(request.CallId)
        && request.CallId.Length <= 64
        && !string.IsNullOrWhiteSpace(request.ConversationId)
        && request.ConversationId.Length <= 256
        && IsSessionId(request.Sender.Value)
        && IsSessionId(request.Recipient.Value)
        && !string.IsNullOrWhiteSpace(request.Payload)
        && request.Payload.Length <= MaxPayloadLength
        && request.Payload.StartsWith("sealed-v1:", StringComparison.Ordinal)
        && request.SenderEd25519?.Length == 64
        && request.Signature is { Length: > 0 and <= 128 };

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

    private static byte[] BuildSigningPayload(CallSignalRequest request) =>
        JsonSerializer.SerializeToUtf8Bytes(new
        {
            version = "deep-call-signal-v1",
            request.CallId,
            request.ConversationId,
            sender = request.Sender.Value,
            recipient = request.Recipient.Value,
            type = request.Type.ToString(),
            request.Payload,
            createdAtUnixMs = request.CreatedAt.ToUnixTimeMilliseconds(),
            senderEd25519 = request.SenderEd25519
        }, JsonOptions);

    private static bool IsSessionId(string? value) =>
        value is { Length: 66 }
        && value.StartsWith("05", StringComparison.Ordinal)
        && value.All(Uri.IsHexDigit);

    private static void Prune(ConcurrentQueue<CallSignalRequest> queue, DateTimeOffset now)
    {
        while (queue.TryPeek(out var signal) && signal.CreatedAt < now - SignalTtl)
        {
            queue.TryDequeue(out _);
        }
    }
}
