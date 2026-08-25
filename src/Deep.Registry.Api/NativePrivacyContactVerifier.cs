using System.Buffers.Binary;
using System.Text;
using Rebex.Security.Cryptography;

namespace Deep.Registry.Api;

internal static class NativePrivacyContactVerifier
{
    private const string Capability = "privacy-routing-v1";
    private static ReadOnlySpan<byte> Magic => "DPC1"u8;
    private static readonly TimeSpan AllowedClockSkew = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan MaximumLifetime = TimeSpan.FromMinutes(15);

    public static bool Verify(
        NativePrivacyContact contact,
        DateTimeOffset now,
        bool allowInsecureHttp)
    {
        if (!IsCanonicalHex(contact.RouterId, 32)
            || !IsCanonicalHex(contact.X25519PublicKey, 32)
            || !IsCanonicalHex(contact.Signature, 64)
            || contact.Capabilities is null
            || contact.Capabilities.Count != 1
            || !string.Equals(contact.Capabilities[0], Capability, StringComparison.Ordinal)
            || contact.PeerEndpoint is null
            || contact.PeerEndpoint != contact.PeerEndpoint.Trim()
            || !TryValidateEndpoint(contact.PeerEndpoint, allowInsecureHttp)
            || contact.ExpiresAtUnixSeconds <= contact.SignedAtUnixSeconds)
        {
            return false;
        }

        DateTimeOffset signedAt;
        DateTimeOffset expiresAt;
        try
        {
            signedAt = DateTimeOffset.FromUnixTimeSeconds(contact.SignedAtUnixSeconds);
            expiresAt = DateTimeOffset.FromUnixTimeSeconds(contact.ExpiresAtUnixSeconds);
        }
        catch (ArgumentOutOfRangeException)
        {
            return false;
        }

        if (signedAt > now.Add(AllowedClockSkew)
            || signedAt < now.Subtract(MaximumLifetime)
            || expiresAt <= now
            || expiresAt - signedAt > MaximumLifetime)
        {
            return false;
        }

        try
        {
            var verifier = new Ed25519();
            verifier.FromPublicKey(Convert.FromHexString(contact.RouterId));
            return verifier.VerifyMessage(
                BuildTranscript(contact),
                Convert.FromHexString(contact.Signature));
        }
        catch (Exception exception) when (
            exception is ArgumentException or InvalidOperationException or OverflowException)
        {
            return false;
        }
    }

    internal static byte[] BuildTranscript(NativePrivacyContact contact)
    {
        var endpoint = Encoding.UTF8.GetBytes(contact.PeerEndpoint);
        var capability = Encoding.ASCII.GetBytes(Capability);
        var transcript = new byte[
            4 + 32 + 32 + 8 + 8 + 2 + endpoint.Length + 1 + capability.Length];
        Magic.CopyTo(transcript);
        Convert.FromHexString(contact.RouterId).CopyTo(transcript, 4);
        Convert.FromHexString(contact.X25519PublicKey).CopyTo(transcript, 36);
        BinaryPrimitives.WriteInt64BigEndian(
            transcript.AsSpan(68, 8), contact.SignedAtUnixSeconds);
        BinaryPrimitives.WriteInt64BigEndian(
            transcript.AsSpan(76, 8), contact.ExpiresAtUnixSeconds);
        BinaryPrimitives.WriteUInt16BigEndian(
            transcript.AsSpan(84, 2), checked((ushort)endpoint.Length));
        endpoint.CopyTo(transcript, 86);
        transcript[86 + endpoint.Length] = checked((byte)capability.Length);
        capability.CopyTo(transcript, 87 + endpoint.Length);
        return transcript;
    }

    private static bool TryValidateEndpoint(string value, bool allowInsecureHttp)
    {
        if (Encoding.UTF8.GetByteCount(value) > ushort.MaxValue
            || !Uri.TryCreate(value, UriKind.Absolute, out var endpoint)
            || !string.IsNullOrEmpty(endpoint.UserInfo)
            || !string.IsNullOrEmpty(endpoint.Query)
            || !string.IsNullOrEmpty(endpoint.Fragment)
            || !string.Equals(
                endpoint.AbsolutePath,
                "/api/peer/privacy/v1/frame",
                StringComparison.Ordinal))
        {
            return false;
        }

        return string.Equals(endpoint.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal)
            || (allowInsecureHttp
                && string.Equals(endpoint.Scheme, Uri.UriSchemeHttp, StringComparison.Ordinal));
    }

    private static bool IsCanonicalHex(string? value, int expectedBytes)
    {
        return value is not null
            && value.Length == expectedBytes * 2
            && value.All(static character =>
                character is >= '0' and <= '9' or >= 'a' and <= 'f');
    }
}
