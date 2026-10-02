#if DEEP_PROTOCOL_DIRECTORY_V1
using Deep.Protocol.ContactV2;

namespace Deep.Registry.Api.DirectoryPublication;

internal sealed class ContactCoordinationIngressOptions
{
    public List<string> AllowedNodePublicKeysHex { get; set; } = [];
}

// Immutable operator-scoped transport access, never network/issuer authority.
internal sealed class ContactCoordinationIngressAuthenticator
{
    private readonly HashSet<string> allowed;
    internal ContactCoordinationIngressAuthenticator(IReadOnlyList<string> nodePublicKeysHex)
    {
        ArgumentNullException.ThrowIfNull(nodePublicKeysHex);
        if (nodePublicKeysHex.Count is < 1 or > 256 || nodePublicKeysHex.Any(value => value is null || value.Length != 64 ||
            value.AsSpan().IndexOfAnyExcept("0123456789abcdef") >= 0 || value.AsSpan().IndexOfAnyExcept('0') < 0) ||
            nodePublicKeysHex.Distinct(StringComparer.Ordinal).Count() != nodePublicKeysHex.Count)
            throw new InvalidOperationException("Private contact coordination requires 1..256 distinct canonical node public keys.");
        allowed = new(nodePublicKeysHex, StringComparer.Ordinal);
    }

    internal static ContactCoordinationIngressAuthenticator FromConfiguration(IConfiguration configuration) =>
        new((configuration.GetSection("ContactCoordinationIngress").Get<ContactCoordinationIngressOptions>() ?? new()).AllowedNodePublicKeysHex);

    internal ContactCoordinationPeerHeaders? ReadAdmittedHeaders(HttpRequest request, DateTimeOffset now)
    {
        var headers = new ContactCoordinationPeerHeaders(Single(request, ContactCoordinationPeerAuthentication.NodeHeader),
            Single(request, ContactCoordinationPeerAuthentication.TimestampHeader),
            Single(request, ContactCoordinationPeerAuthentication.NonceHeader),
            Single(request, ContactCoordinationPeerAuthentication.SignatureHeader));
        return ContactCoordinationPeerAuthentication.IsWithinAdmissionWindow(headers, now) && allowed.Contains(headers.NodePublicKeyHex)
            ? headers : null;
    }

    private static string Single(HttpRequest request, string header) =>
        request.Headers.TryGetValue(header, out var values) && values.Count == 1 ? values[0] ?? string.Empty : string.Empty;
}
#endif
