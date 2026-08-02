using System.Buffers.Binary;
using System.Net.Sockets;
using System.Security.Cryptography;
using Sodium;

namespace Deep.Registry.Api.ProductionMailbox;

public interface IEd25519ExternalSigner
{
    ValueTask<byte[]> SignAsync(ReadOnlyMemory<byte> signingBytes, CancellationToken cancellationToken);
}

/// <summary>
/// Production adapter for a separately protected issuer. Wire format is PMES/v1 followed by a
/// big-endian uint32 payload length and the payload; response is exactly one 64-byte detached
/// Ed25519 signature. No key material crosses the socket.
/// </summary>
public sealed class UnixSocketEd25519ExternalSigner : IEd25519ExternalSigner
{
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

    public async ValueTask<byte[]> SignAsync(
        ReadOnlyMemory<byte> signingBytes,
        CancellationToken cancellationToken)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(timeout);
        var boundedCancellation = deadline.Token;
        if (OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Production issuer signing requires a Unix domain socket.");
        if (string.IsNullOrWhiteSpace(socketPath) || !Path.IsPathFullyQualified(socketPath))
            throw new InvalidOperationException("External signer socket path is missing or relative.");
        if (signingBytes.IsEmpty || signingBytes.Length > 64 * 1024)
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
        var offset = 0;
        while (offset < signature.Length)
        {
            var read = await socket.ReceiveAsync(signature.AsMemory(offset), SocketFlags.None, boundedCancellation);
            if (read == 0) throw new IOException("External signer returned a truncated signature.");
            offset += read;
        }
        if (socket.Available != 0)
            throw new IOException("External signer returned trailing data.");
        return signature;
    }

    private static async ValueTask SendAllAsync(
        Socket socket,
        ReadOnlyMemory<byte> value,
        CancellationToken cancellationToken)
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

/// <summary>Explicit test/lab signer. Composition rejects this type outside Development.</summary>
public sealed class DevelopmentSoftwareEd25519Signer : IEd25519ExternalSigner, IDisposable
{
    private readonly byte[] privateKey;

    public DevelopmentSoftwareEd25519Signer(string seedPath)
    {
        if (string.IsNullOrWhiteSpace(seedPath)) throw new InvalidOperationException("Development signer seed path is missing.");
        var bytes = File.ReadAllBytes(Path.GetFullPath(seedPath));
        privateKey = bytes.Length switch
        {
            32 => PublicKeyAuth.GenerateKeyPair(bytes).PrivateKey,
            64 => bytes.ToArray(),
            _ => throw new InvalidDataException("Development Ed25519 key must be a 32-byte seed or 64-byte private key.")
        };
        CryptographicOperations.ZeroMemory(bytes);
    }

    public ValueTask<byte[]> SignAsync(ReadOnlyMemory<byte> signingBytes, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(PublicKeyAuth.SignDetached(signingBytes.ToArray(), privateKey));
    }

    public void Dispose() => CryptographicOperations.ZeroMemory(privateKey);
}

internal static class ProductionMailboxSignerFactory
{
    public static IEd25519ExternalSigner Create(
        ProductionMailboxOptions options,
        IHostEnvironment environment)
    {
        if (environment.IsProduction())
        {
            if (OperatingSystem.IsWindows())
                throw new PlatformNotSupportedException("Production external signing requires a Unix domain socket host.");
            if (!string.IsNullOrEmpty(options.DevelopmentSoftwareSignerSeedPath))
                throw new InvalidOperationException("Software issuer signing is forbidden in Production.");
            if (string.IsNullOrWhiteSpace(options.ExternalSignerSocketPath) ||
                !Path.IsPathFullyQualified(options.ExternalSignerSocketPath))
                throw new InvalidOperationException("Production requires an absolute external signer Unix socket path.");
            if (!File.Exists(options.ExternalSignerSocketPath))
                throw new InvalidOperationException("Production external signer Unix socket is missing.");
            var mode = File.GetUnixFileMode(options.ExternalSignerSocketPath);
            if ((mode & (UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute)) != 0)
                throw new InvalidOperationException("Production external signer Unix socket is accessible to other users.");
            return new UnixSocketEd25519ExternalSigner(options.ExternalSignerSocketPath,
                TimeSpan.FromSeconds(options.ExternalSignerTimeoutSeconds));
        }
        if (!environment.IsDevelopment() || string.IsNullOrWhiteSpace(options.DevelopmentSoftwareSignerSeedPath))
            throw new InvalidOperationException("Non-production mailbox issuance requires an explicit Development software signer.");
        if (!string.IsNullOrWhiteSpace(options.ExternalSignerSocketPath))
            return new UnixSocketEd25519ExternalSigner(options.ExternalSignerSocketPath,
                TimeSpan.FromSeconds(options.ExternalSignerTimeoutSeconds));
        return new DevelopmentSoftwareEd25519Signer(options.DevelopmentSoftwareSignerSeedPath);
    }
}
