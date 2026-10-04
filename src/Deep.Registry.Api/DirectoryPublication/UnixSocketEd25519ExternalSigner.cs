using System.Buffers.Binary;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace Deep.Registry.Api.DirectoryPublication;

public interface IEd25519ExternalSigner
{
    ValueTask<byte[]> SignAsync(ReadOnlyMemory<byte> signingBytes, CancellationToken cancellationToken);
}

/// <summary>Protected signer transport only, not grant or identity authority.
/// PMES/v1 request framing and exact 64-byte signature followed by EOF are unchanged.</summary>
public sealed class UnixSocketEd25519ExternalSigner : IEd25519ExternalSigner
{
    // Largest current MGR1 signature input: exact record 65,863 minus
    // signature field 72, plus SIGINPUT prefix 33. This is an I/O ceiling,
    // not permission to sign an unverified role or arbitrary protocol record.
    internal const int MaximumSigningBytes = 65_824;
    private static ReadOnlySpan<byte> Magic => "PMES"u8;
    private readonly string socketPath;
    private readonly TimeSpan timeout;

    public UnixSocketEd25519ExternalSigner(string socketPath, TimeSpan timeout)
    {
        if (timeout <= TimeSpan.Zero || timeout > TimeSpan.FromSeconds(30))
            throw new ArgumentOutOfRangeException(nameof(timeout));
        this.socketPath = socketPath;
        this.timeout = timeout;
    }

    public async ValueTask<byte[]> SignAsync(ReadOnlyMemory<byte> signingBytes, CancellationToken cancellationToken)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(timeout);
        var boundedCancellation = deadline.Token;
        if (OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Production issuer signing requires a Unix domain socket.");
        if (string.IsNullOrWhiteSpace(socketPath) || !Path.IsPathFullyQualified(socketPath))
            throw new InvalidOperationException("External signer socket path is missing or relative.");
        if (signingBytes.IsEmpty || signingBytes.Length > MaximumSigningBytes)
            throw new ArgumentOutOfRangeException(nameof(signingBytes));
        using var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        await socket.ConnectAsync(new UnixDomainSocketEndPoint(socketPath), boundedCancellation);
        var header = new byte[9];
        Magic.CopyTo(header);
        header[4] = 1;
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(5), checked((uint)signingBytes.Length));
        await SendAllAsync(socket, header, boundedCancellation);
        await SendAllAsync(socket, signingBytes, boundedCancellation);
        var signature = new byte[64];
        try
        {
            var offset = 0;
            while (offset < signature.Length)
            {
                var read = await socket.ReceiveAsync(signature.AsMemory(offset), SocketFlags.None, boundedCancellation);
                if (read == 0) throw new IOException("External signer returned a truncated signature.");
                offset += read;
            }
            var trailing = new byte[1];
            if (await socket.ReceiveAsync(trailing, SocketFlags.None, boundedCancellation) != 0)
                throw new IOException("External signer returned trailing data.");
            boundedCancellation.ThrowIfCancellationRequested();
            return signature;
        }
        catch { CryptographicOperations.ZeroMemory(signature); throw; }
    }

    private static async ValueTask SendAllAsync(Socket socket, ReadOnlyMemory<byte> value, CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < value.Length)
        {
            var sent = await socket.SendAsync(value[offset..], SocketFlags.None, cancellationToken);
            if (sent == 0) throw new IOException("External signer socket closed while sending a request.");
            offset += sent;
        }
    }
}
