using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;

namespace Deep.Registry.Api;

public sealed record CallInfrastructureOptions
{
    public string? TurnSharedSecret { get; init; }

    public string? TurnSharedSecretFile { get; init; }

    public string[] IceUrls { get; init; } = [];

    public int CredentialLifetimeSeconds { get; init; } = 3600;
}

public sealed record CallIceServer(IReadOnlyList<string> Urls, string? Username = null, string? Credential = null);

public sealed record CallIceConfiguration(IReadOnlyList<CallIceServer> IceServers, DateTimeOffset ExpiresAt);

public sealed class CallIceCredentialIssuer(IOptions<CallInfrastructureOptions> options)
{
    private readonly CallInfrastructureOptions options = options.Value;

    public CallIceConfiguration? Issue(string recipient, DateTimeOffset now)
    {
        var urls = options.IceUrls
            .Where(static value => Uri.TryCreate(value, UriKind.Absolute, out var uri)
                                   && uri.Scheme is "stun" or "stuns" or "turn" or "turns")
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (urls.Length == 0)
        {
            return null;
        }

        var turnUrls = urls.Where(static value => value.StartsWith("turn:", StringComparison.OrdinalIgnoreCase)
                                                  || value.StartsWith("turns:", StringComparison.OrdinalIgnoreCase))
            .ToArray();
        var stunUrls = urls.Except(turnUrls, StringComparer.OrdinalIgnoreCase).ToArray();
        var secret = ResolveSharedSecret();
        if (turnUrls.Length > 0 && string.IsNullOrWhiteSpace(secret))
        {
            return null;
        }

        var lifetime = TimeSpan.FromSeconds(Math.Clamp(options.CredentialLifetimeSeconds, 300, 86_400));
        var expiresAt = now.Add(lifetime);
        var servers = new List<CallIceServer>();
        if (stunUrls.Length > 0)
        {
            servers.Add(new CallIceServer(stunUrls));
        }

        if (turnUrls.Length > 0)
        {
            var username = $"{expiresAt.ToUnixTimeSeconds()}:{recipient}";
            using var hmac = new HMACSHA1(Encoding.UTF8.GetBytes(secret!));
            var credential = Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(username)));
            servers.Add(new CallIceServer(turnUrls, username, credential));
        }

        return new CallIceConfiguration(servers, expiresAt);
    }

    private string? ResolveSharedSecret()
    {
        if (!string.IsNullOrWhiteSpace(options.TurnSharedSecret))
        {
            return options.TurnSharedSecret.Trim();
        }

        if (string.IsNullOrWhiteSpace(options.TurnSharedSecretFile))
        {
            return null;
        }

        try
        {
            return File.ReadAllText(options.TurnSharedSecretFile).Trim();
        }
        catch (IOException)
        {
            return null;
        }
        catch (UnauthorizedAccessException)
        {
            return null;
        }
    }
}
