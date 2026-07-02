using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;

namespace Deep.Registry.Api;

public sealed record CallInfrastructureOptions
{
    public string? TurnSharedSecret { get; init; }

    public string? TurnSharedSecretFile { get; init; }

    public string[] IceUrls { get; init; } = [];

    public int CredentialLifetimeSeconds { get; init; } = 3600;

    public string? PushNotifyUrl { get; init; }

    public string? PushNotifyBearerTokenFile { get; init; }
}

public sealed class CallPushNotifier(
    HttpClient httpClient,
    IOptions<CallInfrastructureOptions> options,
    ILogger<CallPushNotifier> logger)
{
    private readonly CallInfrastructureOptions options = options.Value;

    public async Task NotifyOfferAsync(CallSignalRequest request, CancellationToken cancellationToken)
    {
        if (request.Type != CallSignalType.Offer || string.IsNullOrWhiteSpace(options.PushNotifyUrl))
        {
            return;
        }

        try
        {
            var now = DateTimeOffset.UtcNow;
            var body = JsonSerializer.Serialize(new
            {
                pubkey = request.Recipient.Value,
                hash = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes($"{request.CallId}:{request.Signature}"))),
                @namespace = 0,
                timestamp = now.ToUnixTimeMilliseconds(),
                expiration = now.AddMinutes(3).ToUnixTimeMilliseconds(),
                data = Convert.ToBase64String(Encoding.UTF8.GetBytes(request.Payload))
            });
            using var message = new HttpRequestMessage(HttpMethod.Post, options.PushNotifyUrl)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json")
            };
            var bearerToken = ReadBearerToken();
            if (!string.IsNullOrWhiteSpace(bearerToken))
            {
                message.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", bearerToken);
            }

            using var response = await httpClient.SendAsync(message, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                logger.LogWarning("Call push notification was rejected with status {StatusCode}.", response.StatusCode);
            }
        }
        catch (Exception exception) when (exception is HttpRequestException or IOException or UnauthorizedAccessException)
        {
            logger.LogWarning(exception, "Call push notification delivery failed.");
        }
    }

    private string? ReadBearerToken()
    {
        if (string.IsNullOrWhiteSpace(options.PushNotifyBearerTokenFile))
        {
            return null;
        }

        return File.ReadAllText(options.PushNotifyBearerTokenFile).Trim();
    }
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
