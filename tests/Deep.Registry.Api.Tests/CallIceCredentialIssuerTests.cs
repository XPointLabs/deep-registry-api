using System.Security.Cryptography;
using System.Text;
using Deep.Registry.Api;
using Microsoft.Extensions.Options;

namespace Deep.Registry.Api.Tests;

public sealed class CallIceCredentialIssuerTests
{
    [Fact]
    public void IssueCreatesCoturnRestCredentialForAuthenticatedClient()
    {
        const string secret = "server-only-shared-secret";
        const string recipient = "05aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        var now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        var issuer = new CallIceCredentialIssuer(Options.Create(new CallInfrastructureOptions
        {
            TurnSharedSecret = secret,
            CredentialLifetimeSeconds = 900,
            IceUrls =
            [
                "stun:registry.xpoint.network:3478",
                "turn:registry.xpoint.network:3478?transport=udp",
                "turns:registry.xpoint.network:5349?transport=tcp"
            ]
        }));

        var result = Assert.IsType<CallIceConfiguration>(issuer.Issue(recipient, now));
        var turn = Assert.Single(result.IceServers, static server => server.Username is not null);
        var expectedUsername = $"{result.ExpiresAt.ToUnixTimeSeconds()}:{recipient}";
        using var hmac = new HMACSHA1(Encoding.UTF8.GetBytes(secret));

        Assert.Equal(expectedUsername, turn.Username);
        Assert.Equal(
            Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(expectedUsername))),
            turn.Credential);
        Assert.Contains(result.IceServers, static server => server.Username is null);
    }

    [Fact]
    public void IssueFailsClosedWhenTurnSecretIsMissing()
    {
        var issuer = new CallIceCredentialIssuer(Options.Create(new CallInfrastructureOptions
        {
            IceUrls = ["turn:registry.xpoint.network:3478"]
        }));

        Assert.Null(issuer.Issue(
            "05aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            DateTimeOffset.UtcNow));
    }

    [Fact]
    public void IssueUsesTheMinimumShortLivedCredentialWindow()
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        var issuer = new CallIceCredentialIssuer(Options.Create(new CallInfrastructureOptions
        {
            Enabled = true,
            TurnSharedSecret = "test-only-secret",
            CredentialLifetimeSeconds = 300,
            IceUrls = ["turn:registry.example:3478?transport=udp"]
        }));

        var result = Assert.IsType<CallIceConfiguration>(issuer.Issue(
            "05aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            now));

        Assert.Equal(now.AddMinutes(5), result.ExpiresAt);
    }

    [Theory]
    [InlineData(299)]
    [InlineData(3601)]
    public void IssueFailsClosedOutsideBoundedCredentialWindow(int lifetimeSeconds)
    {
        var issuer = new CallIceCredentialIssuer(Options.Create(new CallInfrastructureOptions
        {
            Enabled = true,
            TurnSharedSecret = "test-only-secret",
            CredentialLifetimeSeconds = lifetimeSeconds,
            IceUrls = ["turn:registry.example:3478"]
        }));

        Assert.Null(issuer.Issue(
            "05aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            DateTimeOffset.UtcNow));
        Assert.False(issuer.GetStatus().Ready);
    }
}
