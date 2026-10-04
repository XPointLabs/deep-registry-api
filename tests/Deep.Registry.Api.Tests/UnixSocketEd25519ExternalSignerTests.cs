using System.Buffers.Binary;
using System.Net.Sockets;
using Deep.Registry.Api.DirectoryPublication;
#if DEEP_PROTOCOL_DIRECTORY_V1
using Deep.Protocol.XPointNetworkV1;
#endif

namespace Deep.Registry.Api.Tests;

// Real Linux socket framing only. Synthetic public signature bytes are never
// crypto, grant-issuance, production-readiness or physical-device evidence.
public sealed class UnixSocketEd25519ExternalSignerTests
{
    private static readonly byte[] Payload = "synthetic-public-signing-frame"u8.ToArray();
    private static readonly byte[] Signature = Enumerable.Range(1, 64).Select(value => (byte)value).ToArray();

    [LinuxSocketFact]
    public async Task FragmentedExactSignatureAndPeerEofReturnOnlyTheExactBytes()
    {
        await using var peer = new Peer(async (socket, ct) =>
        {
            for (var offset = 0; offset < Signature.Length; offset += 7)
                await SendAll(socket, Signature.AsMemory(offset, Math.Min(7, Signature.Length - offset)), ct);
            socket.Shutdown(SocketShutdown.Send);
        });
        var signer = new UnixSocketEd25519ExternalSigner(peer.Path, TimeSpan.FromSeconds(5));
        Assert.Equal(Signature, await signer.SignAsync(Payload, default));
        await peer.Completion;
    }

    [LinuxSocketFact]
    public async Task DelayedTrailingByteRejectsInsteadOfReleasingTheFirstSignature()
    {
        await using var peer = new Peer(async (socket, ct) =>
        {
            await SendAll(socket, Signature, ct);
            await Task.Delay(150, ct);
            await SendAll(socket, new byte[] { 99 }, ct);
            socket.Shutdown(SocketShutdown.Send);
        });
        var signer = new UnixSocketEd25519ExternalSigner(peer.Path, TimeSpan.FromSeconds(5));
        await Assert.ThrowsAsync<IOException>(() => signer.SignAsync(Payload, default).AsTask());
        await peer.Completion;
    }

    [LinuxSocketFact]
    public async Task TruncatedSignatureRejectsAtPeerEof()
    {
        await using var peer = new Peer(async (socket, ct) =>
        {
            await SendAll(socket, Signature.AsMemory(0, 63), ct);
            socket.Shutdown(SocketShutdown.Send);
        });
        var signer = new UnixSocketEd25519ExternalSigner(peer.Path, TimeSpan.FromSeconds(5));
        await Assert.ThrowsAsync<IOException>(() => signer.SignAsync(Payload, default).AsTask());
        await peer.Completion;
    }

    [LinuxSocketFact]
    public async Task ExactSignatureWithoutEofCannotEscapeTheOriginalDeadline()
    {
        await using var peer = new Peer(async (socket, ct) =>
        {
            await SendAll(socket, Signature, ct);
            await Task.Delay(Timeout.Infinite, ct);
        });
        var signer = new UnixSocketEd25519ExternalSigner(peer.Path, TimeSpan.FromMilliseconds(500));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => signer.SignAsync(Payload, default).AsTask());
    }

    [LinuxSocketFact]
    public async Task CallerCancellationWhileAwaitingEofDoesNotReleaseSignature()
    {
        var written = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var peer = new Peer(async (socket, ct) =>
        {
            await SendAll(socket, Signature, ct); written.SetResult();
            await Task.Delay(Timeout.Infinite, ct);
        });
        using var cancelled = new CancellationTokenSource();
        var signer = new UnixSocketEd25519ExternalSigner(peer.Path, TimeSpan.FromSeconds(5));
        var signing = signer.SignAsync(Payload, cancelled.Token).AsTask();
        await written.Task.WaitAsync(TimeSpan.FromSeconds(5)); cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => signing);
    }

    [LinuxSocketFact]
    public async Task EmptyAndOversizedRequestsRejectBeforeOpeningAnySocket()
    {
        var path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "absent-signer-" + Guid.NewGuid().ToString("N"));
        var signer = new UnixSocketEd25519ExternalSigner(path, TimeSpan.FromSeconds(5));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => signer.SignAsync(ReadOnlyMemory<byte>.Empty, default).AsTask());
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => signer.SignAsync(new byte[UnixSocketEd25519ExternalSigner.MaximumSigningBytes + 1], default).AsTask());
        Assert.False(File.Exists(path));
    }

#if DEEP_PROTOCOL_DIRECTORY_V1
    [LinuxSocketFact]
    public async Task MaximumCanonicalMgr1SigningInputCrossesTheActualSocketWithoutTruncation()
    {
        var serials = new byte[MailboxGrantRevocationV1Codec.MaximumSerials * 16];
        for (var index = 0; index < MailboxGrantRevocationV1Codec.MaximumSerials; index++)
            BinaryPrimitives.WriteUInt32BigEndian(serials.AsSpan(index * 16 + 12), checked((uint)index + 1));
        var one = Enumerable.Repeat((byte)1, 32).ToArray();
        ReadOnlyMemory<byte>[] fields = [one.AsMemory(0, 16), new byte[] { (byte)'P', (byte)'M', (byte)'A', (byte)'2', 0, 1 }.Concat(one).ToArray(),
            new byte[] { 1 }, one, U64(1), new byte[32], U64(1), U64(1), U64(301), U32(4_096), serials];
        var payload = MailboxGrantRevocationV1Codec.CreateSignatureInput(fields);
        Assert.Equal(65_824, payload.Length);
        Assert.Equal(UnixSocketEd25519ExternalSigner.MaximumSigningBytes, payload.Length);
        // Actual canonical maximum signing input; the response is still
        // synthetic framing evidence, not an authenticated role signature.
        await using var peer = new Peer(SendResponseAsync, payload);
        var signer = new UnixSocketEd25519ExternalSigner(peer.Path, TimeSpan.FromSeconds(5));
        Assert.Equal(Signature, await signer.SignAsync(payload, default));
        await peer.Completion;
    }

    private static async Task SendResponseAsync(Socket socket, CancellationToken ct)
    {
        await SendAll(socket, Signature, ct);
        socket.Shutdown(SocketShutdown.Send);
    }
    private static byte[] U64(ulong value) { var bytes = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(bytes, value); return bytes; }
    private static byte[] U32(uint value) { var bytes = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(bytes, value); return bytes; }
#endif

    private static async Task SendAll(Socket socket, ReadOnlyMemory<byte> bytes, CancellationToken ct)
    {
        while (!bytes.IsEmpty)
        {
            var count = await socket.SendAsync(bytes, SocketFlags.None, ct);
            Assert.True(count > 0); bytes = bytes[count..];
        }
    }

    private sealed class Peer : IAsyncDisposable
    {
        private readonly Socket listener = new(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        private readonly CancellationTokenSource lifetime = new(TimeSpan.FromSeconds(10));
        internal string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "deep-sign-" + Guid.NewGuid().ToString("N"));
        internal Task Completion { get; }
        internal Peer(Func<Socket, CancellationToken, Task> response, ReadOnlyMemory<byte>? payload = null)
        {
            listener.Bind(new UnixDomainSocketEndPoint(Path)); listener.Listen(1);
            Completion = RunAsync(response, (payload ?? Payload).ToArray());
        }
        private async Task RunAsync(Func<Socket, CancellationToken, Task> response, byte[] payload)
        {
            using var accepted = await listener.AcceptAsync(lifetime.Token);
            using var stream = new NetworkStream(accepted, ownsSocket: false);
            var header = new byte[9]; await stream.ReadExactlyAsync(header, lifetime.Token);
            Assert.True(header.AsSpan(0, 4).SequenceEqual("PMES"u8)); Assert.Equal(1, header[4]);
            Assert.Equal(payload.Length, checked((int)BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(5))));
            var body = new byte[payload.Length]; await stream.ReadExactlyAsync(body, lifetime.Token);
            Assert.Equal(payload, body);
            await response(accepted, lifetime.Token);
        }
        public async ValueTask DisposeAsync()
        {
            lifetime.Cancel(); listener.Dispose();
            try { await Completion; }
            catch (OperationCanceledException) when (lifetime.IsCancellationRequested) { }
            finally { lifetime.Dispose(); File.Delete(Path); }
        }
    }

    private sealed class LinuxSocketFactAttribute : FactAttribute
    {
        public LinuxSocketFactAttribute()
        {
            if (!OperatingSystem.IsLinux()) Skip = "Requires real Linux Unix sockets; run Dockerfile target mailbox-signer-tests.";
        }
    }
}
