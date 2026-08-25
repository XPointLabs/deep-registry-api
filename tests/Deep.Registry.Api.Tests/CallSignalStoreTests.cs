using System.Collections.Concurrent;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
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
        var request = SignSignal(sender, recipient, now, "call-1", Nonce(1));
        var store = CreateStore();

        Assert.Equal(CallSignalEnqueueResult.Accepted, store.Enqueue(request, now));

        var headers = SignGet(recipient, now, CallSignalStore.InboxPurpose, "inbox", Nonce(2));
        Assert.Equal(
            CallAuthenticatedRequestStatus.Unauthorized,
            store.AuthenticateIceRequest(recipient.SessionId, headers, now));

        var drained = store.DrainAuthenticated(recipient.SessionId, headers, now);
        Assert.Equal(CallAuthenticatedRequestStatus.Accepted, drained.Status);
        Assert.Single(drained.Signals);
    }

    [Fact]
    public void TamperedSignalIsRejected()
    {
        var now = DateTimeOffset.UtcNow;
        var sender = CreateIdentity();
        var recipient = CreateIdentity();
        var signed = SignSignal(sender, recipient, now, "call-2", Nonce(3));

        var result = CreateStore().Enqueue(signed with { Payload = "sealed-v1:BBBB" }, now);

        Assert.Equal(CallSignalEnqueueResult.Unauthorized, result);
    }

    [Fact]
    public void ExactSignalReplayIsIdempotentButNonceForkIsRejected()
    {
        var now = DateTimeOffset.UtcNow;
        var sender = CreateIdentity();
        var recipient = CreateIdentity();
        var request = SignSignal(sender, recipient, now, "call-3", Nonce(4));
        var fork = SignSignal(sender, recipient, now, "call-fork", Nonce(4));
        var store = CreateStore();

        Assert.Equal(CallSignalEnqueueResult.Accepted, store.Enqueue(request, now));
        Assert.Equal(CallSignalEnqueueResult.Idempotent, store.Enqueue(request, now));
        Assert.Equal(CallSignalEnqueueResult.Replay, store.Enqueue(fork, now));

        var drained = store.DrainAuthenticated(
            recipient.SessionId,
            SignGet(recipient, now, CallSignalStore.InboxPurpose, "inbox", Nonce(5)),
            now);
        Assert.Single(drained.Signals);
    }

    [Fact]
    public void ReplayedInboxRequestIsRejectedBeforeDrainMutation()
    {
        var now = DateTimeOffset.UtcNow;
        var sender = CreateIdentity();
        var recipient = CreateIdentity();
        var store = CreateStore();
        var replayedHeaders = SignGet(
            recipient,
            now,
            CallSignalStore.InboxPurpose,
            "inbox",
            Nonce(6));

        Assert.Equal(
            CallSignalEnqueueResult.Accepted,
            store.Enqueue(SignSignal(sender, recipient, now, "first", Nonce(7)), now));
        Assert.Single(store.DrainAuthenticated(recipient.SessionId, replayedHeaders, now).Signals);

        Assert.Equal(
            CallSignalEnqueueResult.Accepted,
            store.Enqueue(SignSignal(sender, recipient, now, "second", Nonce(8)), now));
        Assert.Equal(
            CallAuthenticatedRequestStatus.Replay,
            store.DrainAuthenticated(recipient.SessionId, replayedHeaders, now).Status);

        var fresh = store.DrainAuthenticated(
            recipient.SessionId,
            SignGet(recipient, now, CallSignalStore.InboxPurpose, "inbox", Nonce(9)),
            now);
        Assert.Equal("second", Assert.Single(fresh.Signals).CallId);
    }

    [Fact]
    public async Task ConcurrentEnqueueAndDrainDoesNotLoseSignals()
    {
        const int signalCount = 100;
        var now = DateTimeOffset.UtcNow;
        var sender = CreateIdentity();
        var recipient = CreateIdentity();
        var store = CreateStore();
        var drained = new ConcurrentBag<CallSignalRequest>();
        var work = new List<Task>();

        for (var index = 0; index < signalCount; index++)
        {
            var captured = index;
            work.Add(Task.Run(() => Assert.Equal(
                CallSignalEnqueueResult.Accepted,
                store.Enqueue(
                    SignSignal(sender, recipient, now, $"call-{captured}", Nonce(100 + captured)),
                    now))));
            work.Add(Task.Run(() =>
            {
                var result = store.DrainAuthenticated(
                    recipient.SessionId,
                    SignGet(
                        recipient,
                        now,
                        CallSignalStore.InboxPurpose,
                        "inbox",
                        Nonce(1000 + captured)),
                    now);
                Assert.Equal(CallAuthenticatedRequestStatus.Accepted, result.Status);
                foreach (var signal in result.Signals)
                {
                    drained.Add(signal);
                }
            }));
        }

        await Task.WhenAll(work);
        foreach (var signal in store.DrainAuthenticated(
                     recipient.SessionId,
                     SignGet(recipient, now, CallSignalStore.InboxPurpose, "inbox", Nonce(9999)),
                     now).Signals)
        {
            drained.Add(signal);
        }

        Assert.Equal(signalCount, drained.Count);
        Assert.Equal(signalCount, drained.Select(static item => item.CallId).Distinct().Count());
    }

    [Fact]
    public void InboxAndReplayStateSurviveRestart()
    {
        var statePath = Path.Combine(Path.GetTempPath(), $"deep-call-state-{Guid.NewGuid():N}.json");
        try
        {
            var now = DateTimeOffset.UtcNow;
            var sender = CreateIdentity();
            var recipient = CreateIdentity();
            var signal = SignSignal(sender, recipient, now, "restart", Nonce(10));
            var persistence = new FileCallSignalPersistence(statePath);

            Assert.Equal(
                CallSignalEnqueueResult.Accepted,
                new CallSignalStore(persistence).Enqueue(signal, now));

            var restarted = new CallSignalStore(new FileCallSignalPersistence(statePath));
            Assert.Equal(CallSignalEnqueueResult.Idempotent, restarted.Enqueue(signal, now));
            var drained = restarted.DrainAuthenticated(
                recipient.SessionId,
                SignGet(recipient, now, CallSignalStore.InboxPurpose, "inbox", Nonce(11)),
                now);
            Assert.Equal("restart", Assert.Single(drained.Signals).CallId);

            var afterDrainRestart = new CallSignalStore(new FileCallSignalPersistence(statePath));
            Assert.Empty(afterDrainRestart.DrainAuthenticated(
                recipient.SessionId,
                SignGet(recipient, now, CallSignalStore.InboxPurpose, "inbox", Nonce(12)),
                now).Signals);
        }
        finally
        {
            if (File.Exists(statePath))
            {
                File.Delete(statePath);
            }
        }
    }

    [Fact]
    public void InvalidPersistedStateIsQuarantinedAndFailsClosed()
    {
        var statePath = Path.Combine(Path.GetTempPath(), $"deep-call-corrupt-{Guid.NewGuid():N}.json");
        File.WriteAllText(statePath, "{}");
        try
        {
            var store = new CallSignalStore(new FileCallSignalPersistence(statePath));

            Assert.False(store.GetStatus().Ready);
            Assert.False(File.Exists(statePath));
            Assert.Single(Directory.GetFiles(
                Path.GetDirectoryName(statePath)!,
                Path.GetFileName(statePath) + ".corrupt-*"));
        }
        finally
        {
            foreach (var candidate in Directory.GetFiles(
                         Path.GetDirectoryName(statePath)!,
                         Path.GetFileName(statePath) + "*"))
            {
                File.Delete(candidate);
            }
        }
    }

    private static CallSignalStore CreateStore() => new(new MemoryPersistence());

    private static CallSignalRequest SignSignal(
        (KeyPair Keys, string SessionId) sender,
        (KeyPair Keys, string SessionId) recipient,
        DateTimeOffset now,
        string callId,
        string nonce)
    {
        var unsigned = new CallSignalRequest(
            callId,
            recipient.SessionId,
            new CallParty(sender.SessionId),
            new CallParty(recipient.SessionId),
            CallSignalType.Offer,
            "sealed-v1:" + Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
            now,
            Convert.ToHexStringLower(sender.Keys.PublicKey),
            null,
            nonce);
        return unsigned with
        {
            Signature = Convert.ToBase64String(PublicKeyAuth.SignDetached(
                CallSignalStore.BuildSigningPayload(unsigned),
                sender.Keys.PrivateKey))
        };
    }

    private static HeaderDictionary SignGet(
        (KeyPair Keys, string SessionId) identity,
        DateTimeOffset now,
        string purpose,
        string route,
        string nonce)
    {
        var timestamp = now.ToUnixTimeSeconds();
        var payload = Encoding.UTF8.GetBytes(
            $"{purpose}\nGET\n/api/calls/{route}/{identity.SessionId}\n{identity.SessionId}\n{timestamp}\n{nonce}");
        return new HeaderDictionary
        {
            ["X-Deep-Ed25519"] = Convert.ToHexStringLower(identity.Keys.PublicKey),
            ["X-Deep-Timestamp"] = timestamp.ToString(CultureInfo.InvariantCulture),
            [CallSignalStore.NonceHeader] = nonce,
            ["X-Deep-Signature"] = Convert.ToBase64String(
                PublicKeyAuth.SignDetached(payload, identity.Keys.PrivateKey))
        };
    }

    private static (KeyPair Keys, string SessionId) CreateIdentity()
    {
        var keys = PublicKeyAuth.GenerateKeyPair();
        var x25519 = PublicKeyAuth.ConvertEd25519PublicKeyToCurve25519PublicKey(keys.PublicKey);
        return (keys, "05" + Convert.ToHexStringLower(x25519));
    }

    private static string Nonce(int value) => value.ToString("x32", CultureInfo.InvariantCulture);

    private sealed class MemoryPersistence : ICallSignalPersistence
    {
        private PersistedCallState? state;

        public PersistedCallState? Load() => state;

        public void Save(PersistedCallState next) => state = next;

        public void Quarantine() => state = null;
    }
}
