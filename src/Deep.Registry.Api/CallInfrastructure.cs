using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;

namespace Deep.Registry.Api;

public sealed record CallInfrastructureOptions
{
    public bool? Enabled { get; init; }

    public bool Required { get; init; } = true;

    public string? StatePath { get; init; }

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

public sealed record CallInfrastructureStatus(bool Enabled, bool Ready, string State);

public sealed class CallIceCredentialIssuer(IOptions<CallInfrastructureOptions> options)
{
    private readonly CallInfrastructureOptions options = options.Value;

    public CallInfrastructureStatus GetStatus()
    {
        var configured = options.IceUrls.Length > 0
                         || !string.IsNullOrWhiteSpace(options.TurnSharedSecret)
                         || !string.IsNullOrWhiteSpace(options.TurnSharedSecretFile)
                         || !string.IsNullOrWhiteSpace(options.PushNotifyUrl)
                         || !string.IsNullOrWhiteSpace(options.PushNotifyBearerTokenFile);
        var enabled = options.Required || options.Enabled == true || (options.Enabled is null && configured);
        if (!enabled)
        {
            return options.Required
                ? new CallInfrastructureStatus(true, false, "call-disabled")
                : new CallInfrastructureStatus(false, true, "disabled");
        }

        if (options.Enabled == false
            || options.CredentialLifetimeSeconds is < 300 or > 3600
            || options.IceUrls.Length == 0
            || options.IceUrls.Any(static value => !IsIceUrl(value))
            || !options.IceUrls.Any(static value => IsTurnUrl(value))
            || (!string.IsNullOrWhiteSpace(options.TurnSharedSecret)
                && !string.IsNullOrWhiteSpace(options.TurnSharedSecretFile))
            || (string.IsNullOrWhiteSpace(options.PushNotifyUrl)
                && !string.IsNullOrWhiteSpace(options.PushNotifyBearerTokenFile)))
        {
            return new CallInfrastructureStatus(true, false, "call-config-invalid");
        }

        var secret = ResolveSharedSecret();
        if (string.IsNullOrWhiteSpace(secret))
        {
            return new CallInfrastructureStatus(true, false, "call-secret-unavailable");
        }

        if (!string.IsNullOrWhiteSpace(options.PushNotifyUrl)
            && (!Uri.TryCreate(options.PushNotifyUrl, UriKind.Absolute, out var pushUri)
                || pushUri.Scheme is not ("http" or "https")))
        {
            return new CallInfrastructureStatus(true, false, "call-config-invalid");
        }

        if (!string.IsNullOrWhiteSpace(options.PushNotifyBearerTokenFile)
            && string.IsNullOrWhiteSpace(ReadFile(options.PushNotifyBearerTokenFile)))
        {
            return new CallInfrastructureStatus(true, false, "call-push-token-unavailable");
        }

        return new CallInfrastructureStatus(true, true, "ready");
    }

    public CallIceConfiguration? Issue(string recipient, DateTimeOffset now)
    {
        if (!GetStatus().Ready)
        {
            return null;
        }

        var urls = options.IceUrls.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();

        var turnUrls = urls.Where(static value => IsTurnUrl(value)).ToArray();
        var stunUrls = urls.Except(turnUrls, StringComparer.OrdinalIgnoreCase).ToArray();
        var secret = ResolveSharedSecret();

        var lifetime = TimeSpan.FromSeconds(options.CredentialLifetimeSeconds);
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

        return ReadFile(options.TurnSharedSecretFile);
    }

    private static bool IsIceUrl(string value) =>
        Uri.TryCreate(value, UriKind.Absolute, out var uri)
        && uri.Scheme is "stun" or "stuns" or "turn" or "turns";

    private static bool IsTurnUrl(string value) =>
        value.StartsWith("turn:", StringComparison.OrdinalIgnoreCase)
        || value.StartsWith("turns:", StringComparison.OrdinalIgnoreCase);

    private static string? ReadFile(string path)
    {
        try
        {
            return File.ReadAllText(path).Trim();
        }
        catch (Exception exception) when (exception is IOException
                                          or UnauthorizedAccessException
                                          or ArgumentException
                                          or NotSupportedException)
        {
            return null;
        }
    }
}

public sealed record CallRuntimeStatus(bool Enabled, bool Ready, string State);

public sealed class CallRuntimeReadiness(CallIceCredentialIssuer issuer, CallSignalStore store)
{
    public CallRuntimeStatus GetStatus()
    {
        var infrastructure = issuer.GetStatus();
        if (!infrastructure.Enabled)
        {
            return new CallRuntimeStatus(false, true, infrastructure.State);
        }

        if (!infrastructure.Ready)
        {
            return new CallRuntimeStatus(true, false, infrastructure.State);
        }

        var persistence = store.GetStatus();
        return persistence.Ready
            ? new CallRuntimeStatus(true, true, "ready")
            : new CallRuntimeStatus(true, false, persistence.State);
    }
}
