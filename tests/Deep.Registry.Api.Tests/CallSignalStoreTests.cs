using System.Text;
using System.Text.Json;
using System.Security.Cryptography;
using Deep.Registry.Api;
using Microsoft.AspNetCore.Http;
using Sodium;

namespace Deep.Registry.Api.Tests;

public sealed class CallSignalStoreTests
{
    [Fact]
    public void SignedEncryptedSignalCanOnlyBeDrainedWithRecipientSignature()
    {
        var now = DateTimeOffset.UtcNow;
        var sender = CreateIdentity();
        var recipient = CreateIdentity();
        var unsigned = new CallSignalRequest(
            "call-1",
            recipient.SessionId,
            new CallParty(sender.SessionId),
            new CallParty(recipient.SessionId),
            CallSignalType.Offer,
            "sealed-v1:" + Convert.ToBase64String(RandomNumberGenerator.GetBytes(96)),
            now,
            Convert.ToHexString(sender.Keys.PublicKey).ToLowerInvariant(),
            null);
        var request = unsigned with
        {
            Signature = Convert.ToBase64String(PublicKeyAuth.SignDetached(BuildPayload(unsigned), sender.Keys.PrivateKey))
        };
        var store = new CallSignalStore();

        Assert.Equal(CallSignalEnqueueResult.Accepted, store.Enqueue(request, now));

        var headers = new HeaderDictionary();
        var timestamp = now.ToUnixTimeSeconds();
        headers["X-Deep-Ed25519"] = Convert.ToHexString(recipient.Keys.PublicKey).ToLowerInvariant();
        headers["X-Deep-Timestamp"] = timestamp.ToString(System.Globalization.CultureInfo.InvariantCulture);
        headers["X-Deep-Signature"] = Convert.ToBase64String(PublicKeyAuth.SignDetached(
            Encoding.UTF8.GetBytes($"deep-call-inbox-v1\n{recipient.SessionId}\n{timestamp}"),
            recipient.Keys.PrivateKey));

        Assert.True(store.VerifyInboxRequest(recipient.SessionId, headers, now));
        Assert.False(store.VerifyIceRequest(recipient.SessionId, headers, now));
        Assert.Single(store.Drain(recipient.SessionId, now));
        Assert.Empty(store.Drain(recipient.SessionId, now));
    }

    [Fact]
    public void TamperedSignalIsRejected()
    {
        var now = DateTimeOffset.UtcNow;
        var sender = CreateIdentity();
        var recipient = CreateIdentity();
        var unsigned = new CallSignalRequest(
            "call-2",
            recipient.SessionId,
            new CallParty(sender.SessionId),
            new CallParty(recipient.SessionId),
            CallSignalType.Offer,
            "sealed-v1:AAAA",
            now,
            Convert.ToHexString(sender.Keys.PublicKey).ToLowerInvariant(),
            null);
        var signed = unsigned with
        {
            Signature = Convert.ToBase64String(PublicKeyAuth.SignDetached(BuildPayload(unsigned), sender.Keys.PrivateKey))
        };

        var result = new CallSignalStore().Enqueue(signed with { Payload = "sealed-v1:BBBB" }, now);

        Assert.Equal(CallSignalEnqueueResult.Unauthorized, result);
    }

    private static (KeyPair Keys, string SessionId) CreateIdentity()
    {
        var keys = PublicKeyAuth.GenerateKeyPair();
        var x25519 = PublicKeyAuth.ConvertEd25519PublicKeyToCurve25519PublicKey(keys.PublicKey);
        return (keys, "05" + Convert.ToHexString(x25519).ToLowerInvariant());
    }

    private static byte[] BuildPayload(CallSignalRequest request) =>
        JsonSerializer.SerializeToUtf8Bytes(new
        {
            version = "deep-call-signal-v1",
            request.CallId,
            request.ConversationId,
            sender = request.Sender.Value,
            recipient = request.Recipient.Value,
            type = request.Type.ToString(),
            request.Payload,
            createdAtUnixMs = request.CreatedAt.ToUnixTimeMilliseconds(),
            senderEd25519 = request.SenderEd25519
        }, new JsonSerializerOptions(JsonSerializerDefaults.Web));
}
