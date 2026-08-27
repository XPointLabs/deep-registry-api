using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;

namespace Deep.Registry.Api.ProductionMailbox;

public interface IProductionMailboxChallengeSourceResolver
{
    bool TryResolve(HttpContext context, out byte[] sourceKey);
}

public sealed class ProductionMailboxChallengeSourceResolver :
    IProductionMailboxChallengeSourceResolver
{
    private const int MaximumForwardedHeaderLength = 1024;
    private const int MaximumForwardedEntries = 16;
    private static readonly byte[] Domain =
        Encoding.ASCII.GetBytes("Deep/production-mailbox/challenge-source/v1\0");
    private readonly IpNetwork[] trustedProxies;

    public ProductionMailboxChallengeSourceResolver(
        IOptions<ProductionMailboxOptions> options)
    {
        var configured = options.Value.ChallengeTrustedProxyCidrs ?? [];
        if (configured.Length > 64)
            throw new InvalidOperationException(
                "Too many production mailbox challenge trusted proxies are configured.");
        trustedProxies = configured.Select(IpNetwork.Parse).ToArray();
    }

    public bool TryResolve(HttpContext context, out byte[] sourceKey)
    {
        ArgumentNullException.ThrowIfNull(context);
        var remote = Normalize(context.Connection.RemoteIpAddress);
        var source = remote;
        if (remote is not null && IsTrusted(remote))
        {
            if (!TryResolveForwarded(context.Request.Headers["X-Forwarded-For"],
                    remote, out var forwarded))
            {
                sourceKey = [];
                return false;
            }
            source = forwarded;
        }

        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(Domain);
        if (source is null)
            hash.AppendData("unknown"u8);
        else
            hash.AppendData(source.GetAddressBytes());
        sourceKey = hash.GetHashAndReset();
        return true;
    }

    private bool TryResolveForwarded(
        Microsoft.Extensions.Primitives.StringValues values,
        IPAddress immediatePeer,
        out IPAddress source)
    {
        source = immediatePeer;
        var raw = values.ToString();
        if (raw.Length is 0 or > MaximumForwardedHeaderLength)
            return false;
        var entries = raw.Split(',', StringSplitOptions.TrimEntries);
        if (entries.Length is 0 or > MaximumForwardedEntries)
            return false;

        var current = immediatePeer;
        for (var index = entries.Length - 1; index >= 0 && IsTrusted(current); index--)
        {
            if (!IPAddress.TryParse(entries[index], out var parsed))
                return false;
            current = Normalize(parsed)!;
        }
        source = current;
        return true;
    }

    private bool IsTrusted(IPAddress address) =>
        trustedProxies.Any(network => network.Contains(address));

    private static IPAddress? Normalize(IPAddress? address) =>
        address?.IsIPv4MappedToIPv6 == true ? address.MapToIPv4() : address;

    private sealed record IpNetwork(byte[] Address, int PrefixLength)
    {
        public static IpNetwork Parse(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
                throw Invalid();
            var parts = value.Split('/', StringSplitOptions.TrimEntries);
            if (parts.Length is < 1 or > 2 ||
                !IPAddress.TryParse(parts[0], out var parsed))
                throw Invalid();
            var address = Normalize(parsed)!;
            var bytes = address.GetAddressBytes();
            var maximumPrefix = bytes.Length * 8;
            var prefix = parts.Length == 1
                ? maximumPrefix
                : int.TryParse(parts[1], out var candidate) ? candidate : -1;
            if (prefix < 0 || prefix > maximumPrefix)
                throw Invalid();

            var network = bytes.ToArray();
            Mask(network, prefix);
            return new(network, prefix);

            static InvalidOperationException Invalid() => new(
                "Production mailbox challenge trusted proxy CIDR is invalid.");
        }

        public bool Contains(IPAddress candidate)
        {
            candidate = Normalize(candidate)!;
            var bytes = candidate.GetAddressBytes();
            if (bytes.Length != Address.Length)
                return false;
            Mask(bytes, PrefixLength);
            return CryptographicOperations.FixedTimeEquals(bytes, Address);
        }

        private static void Mask(byte[] bytes, int prefixLength)
        {
            var wholeBytes = prefixLength / 8;
            var remainingBits = prefixLength % 8;
            if (remainingBits != 0)
            {
                bytes[wholeBytes] &= (byte)(0xff << (8 - remainingBits));
                wholeBytes++;
            }
            bytes.AsSpan(wholeBytes).Clear();
        }
    }
}
