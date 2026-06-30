using System.Collections.Concurrent;
using System.Text.Json;
using Rebex.Security.Cryptography;

namespace Deep.Registry.Api;

internal static class RegistryCatalogRequestAuthenticator
{
    public const string NodeIdHeader = "X-XPoint-Node-Id";
    public const string TimestampHeader = "X-XPoint-Timestamp";
    public const string NonceHeader = "X-XPoint-Nonce";
    public const string SignatureHeader = "X-XPoint-Signature";
    private const string PayloadVersion = "xpoint-registry-catalog-v1";
    private static readonly TimeSpan AllowedClockSkew = TimeSpan.FromMinutes(2);
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public static bool Verify(
        HttpRequest request,
        NodeRegistry registry,
        RegistryCatalogReplayGuard replayGuard,
        DateTimeOffset now)
    {
        var nodeId = request.Headers[NodeIdHeader].ToString();
        var nonce = request.Headers[NonceHeader].ToString();
        var signatureHex = request.Headers[SignatureHeader].ToString();
        if (!long.TryParse(request.Headers[TimestampHeader], out var timestampUnixMs)
            || string.IsNullOrWhiteSpace(nodeId)
            || string.IsNullOrWhiteSpace(nonce)
            || nonce.Length > 128)
        {
            return false;
        }

        var signedAt = DateTimeOffset.FromUnixTimeMilliseconds(timestampUnixMs);
        if ((now - signedAt).Duration() > AllowedClockSkew)
        {
            return false;
        }

        var node = registry.GetNode(nodeId);
        if (node is null
            || !string.Equals(node.NodeId, node.Ed25519PublicKey, StringComparison.OrdinalIgnoreCase)
            || node.TransportStatus is not { Enabled: true, Running: true, Degraded: false, Mocked: false })
        {
            return false;
        }

        try
        {
            var verifier = new Ed25519();
            verifier.FromPublicKey(DecodeHex(node.Ed25519PublicKey, 32));
            var payload = new CatalogRequestPayload(
                PayloadVersion,
                request.Method.ToUpperInvariant(),
                request.Path.Value ?? "/",
                nodeId.ToLowerInvariant(),
                timestampUnixMs,
                nonce);
            var bytes = JsonSerializer.SerializeToUtf8Bytes(payload, JsonOptions);
            if (!verifier.VerifyMessage(bytes, DecodeHex(signatureHex, 64)))
            {
                return false;
            }
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException)
        {
            return false;
        }

        return replayGuard.TryAccept(nodeId, nonce, now);
    }

    private static byte[] DecodeHex(string value, int expectedBytes)
    {
        var normalized = value.Trim();
        if (normalized.Length != expectedBytes * 2 || !normalized.All(Uri.IsHexDigit))
        {
            throw new ArgumentException($"Expected {expectedBytes}-byte hex value.");
        }
        return Convert.FromHexString(normalized);
    }

    private sealed record CatalogRequestPayload(
        string Version,
        string Method,
        string Path,
        string NodeId,
        long TimestampUnixMs,
        string Nonce);
}

public sealed class RegistryCatalogReplayGuard
{
    private static readonly TimeSpan Retention = TimeSpan.FromMinutes(3);
    private readonly ConcurrentDictionary<string, DateTimeOffset> seen = new(StringComparer.Ordinal);

    public bool TryAccept(string nodeId, string nonce, DateTimeOffset now)
    {
        foreach (var item in seen)
        {
            if (item.Value <= now)
            {
                seen.TryRemove(item.Key, out _);
            }
        }
        return seen.TryAdd($"{nodeId.ToLowerInvariant()}:{nonce}", now.Add(Retention));
    }
}
