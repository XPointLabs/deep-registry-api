using System.Net;
using System.Text.Json;
using Deep.Registry.Api;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Deep.Registry.Api.Tests;

public sealed class CallPushNotifierTests
{
    [Fact]
    public async Task OfferQueuesPrivacyPreservingInternalPush()
    {
        HttpRequestMessage? captured = null;
        string? capturedBody = null;
        var handler = new RecordingHandler(async (request, cancellationToken) =>
        {
            captured = request;
            capturedBody = await request.Content!.ReadAsStringAsync(cancellationToken);
            return new HttpResponseMessage(HttpStatusCode.Accepted);
        });
        var tokenFile = Path.GetTempFileName();
        await File.WriteAllTextAsync(tokenFile, "internal-token");
        try
        {
            var notifier = new CallPushNotifier(
                new HttpClient(handler),
                Options.Create(new CallInfrastructureOptions
                {
                    PushNotifyUrl = "http://push-service:8080/_compat/push-notify",
                    PushNotifyBearerTokenFile = tokenFile
                }),
                NullLogger<CallPushNotifier>.Instance);
            var request = new CallSignalRequest(
                "call-1",
                "conversation-1",
                new CallParty("05aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                new CallParty("05bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
                CallSignalType.Offer,
                "sealed-v1:secret-ciphertext",
                DateTimeOffset.UtcNow,
                new string('a', 64),
                "signature");

            await notifier.NotifyOfferAsync(request, CancellationToken.None);

            Assert.NotNull(captured);
            Assert.Equal("Bearer", captured!.Headers.Authorization?.Scheme);
            Assert.Equal("internal-token", captured.Headers.Authorization?.Parameter);
            using var json = JsonDocument.Parse(capturedBody!);
            Assert.Equal(request.Recipient.Value, json.RootElement.GetProperty("pubkey").GetString());
            Assert.DoesNotContain(request.ConversationId, capturedBody, StringComparison.Ordinal);
            Assert.DoesNotContain(request.Sender.Value, capturedBody, StringComparison.Ordinal);
        }
        finally
        {
            File.Delete(tokenFile);
        }
    }

    private sealed class RecordingHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> responder)
        : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            responder(request, cancellationToken);
    }
}
