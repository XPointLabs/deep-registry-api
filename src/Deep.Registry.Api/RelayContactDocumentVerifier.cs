using System.Text.Json;
using Rebex.Security.Cryptography;

namespace Deep.Registry.Api;

internal static class RelayContactDocumentVerifier
{
    private const string PayloadVersion = "deep-relay-contact-v1";
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public static bool Verify(RelayContactDocument contact, DateTimeOffset now)
    {
        if (!string.Equals(contact.SignatureAlgorithm, "ed25519", StringComparison.OrdinalIgnoreCase)
            || contact.SignedAt > now.AddMinutes(5)
            || contact.ExpiresAt <= now
            || contact.ExpiresAt <= contact.SignedAt)
        {
            return false;
        }

        try
        {
            var verifier = new Ed25519();
            verifier.FromPublicKey(DecodeHex(contact.RouterId, 32));
            return verifier.VerifyMessage(BuildPayload(contact), DecodeHex(contact.Signature, 64));
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException)
        {
            return false;
        }
    }

    private static byte[] BuildPayload(RelayContactDocument contact)
    {
        var payload = new RelayContactSigningPayload(
            PayloadVersion,
            contact.RouterId,
            contact.PublicHost,
            contact.PublicIp ?? "",
            contact.PublicPort,
            contact.X25519PublicKey,
            contact.RpcEndpoint,
            contact.SignedAt.ToUnixTimeMilliseconds(),
            contact.ExpiresAt.ToUnixTimeMilliseconds(),
            contact.RouterVersion,
            contact.IsReachable,
            contact.Capabilities
                .Where(static value => !string.IsNullOrWhiteSpace(value))
                .Select(static value => value.Trim())
                .Order(StringComparer.Ordinal)
                .ToArray());
        return JsonSerializer.SerializeToUtf8Bytes(payload, JsonOptions);
    }

    private static byte[] DecodeHex(string value, int expectedBytes)
    {
        var normalized = value.Trim();
        if (normalized.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            normalized = normalized[2..];
        }
        if (normalized.Length != expectedBytes * 2 || !normalized.All(Uri.IsHexDigit))
        {
            throw new ArgumentException($"Expected {expectedBytes}-byte hex value.");
        }
        return Convert.FromHexString(normalized);
    }

    private sealed record RelayContactSigningPayload(
        string Version,
        string RouterId,
        string PublicHost,
        string PublicIp,
        int PublicPort,
        string X25519PublicKey,
        string RpcEndpoint,
        long SignedAtUnixMs,
        long ExpiresAtUnixMs,
        string RouterVersion,
        bool IsReachable,
        IReadOnlyList<string> Capabilities);
}
