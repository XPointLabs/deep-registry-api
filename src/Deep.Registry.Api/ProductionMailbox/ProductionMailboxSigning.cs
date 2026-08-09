using System.Buffers.Binary;
using System.Net.Sockets;
using System.Security.Cryptography;
using Sodium;
using System.Collections.Concurrent;

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

internal static class ProductionMailboxClosurePublisherSignerFactory
{
    public static IProductionMailboxClosurePublisherSigner Create(
        ProductionMailboxOptions options,
        IHostEnvironment environment)
    {
        IEd25519ExternalSigner signer;
        if (environment.IsProduction())
        {
            if (OperatingSystem.IsWindows())
                throw new PlatformNotSupportedException(
                    "Production closure publishing requires a Unix domain socket host.");
            if (!string.IsNullOrEmpty(options.DevelopmentClosurePublisherSeedPath)
                || string.IsNullOrWhiteSpace(options.ClosurePublisherSignerSocketPath)
                || !Path.IsPathFullyQualified(options.ClosurePublisherSignerSocketPath)
                || !File.Exists(options.ClosurePublisherSignerSocketPath))
                throw new InvalidOperationException(
                    "Production requires a protected closure-publisher signer socket.");
            signer = new UnixSocketEd25519ExternalSigner(
                options.ClosurePublisherSignerSocketPath,
                TimeSpan.FromSeconds(options.ClosurePublisherSignerTimeoutSeconds));
        }
        else
        {
            if (!environment.IsDevelopment()
                || string.IsNullOrWhiteSpace(options.DevelopmentClosurePublisherSeedPath))
                throw new InvalidOperationException(
                    "Development closure publishing requires an explicit software key.");
            signer = new DevelopmentSoftwareEd25519Signer(
                options.DevelopmentClosurePublisherSeedPath);
        }
        return new ProductionMailboxClosurePublisherSignerAdapter(signer);
    }
}

/// <summary>Development-only deterministic OCR key store; production uses the dedicated socket HSM.</summary>
public sealed class DevelopmentProductionMailboxOwnerControlKeyStore :
    IProductionMailboxOwnerControlKeyStore, IDisposable
{
    private readonly byte[] masterSeed;
    private readonly ConcurrentDictionary<string, byte[]> privateKeys = new(StringComparer.Ordinal);
    private volatile bool enabled = true;

    public DevelopmentProductionMailboxOwnerControlKeyStore(string seedPath)
    {
        var full = Path.GetFullPath(seedPath);
        masterSeed = ProductionMailboxProtectedFile.ReadStable(
            full, 32, 32, () =>
                ProductionMailboxArtifactProvider.EnsureNoReparseAncestors(full));
        if (masterSeed.AsSpan().IndexOfAnyExcept((byte)0) < 0)
            throw new InvalidDataException("Development OCR master seed is all-zero.");
    }

    public bool IsSigningEnabled => enabled;

    public ValueTask<ProductionMailboxOwnerControlKeyHandle> CreateOrGetAsync(
        ReadOnlyMemory<byte> idempotencyToken, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!enabled || idempotencyToken.Length != 32)
            throw new InvalidOperationException("Development OCR key store is unavailable.");
        using var hmac = new HMACSHA256(masterSeed);
        var seed = hmac.ComputeHash(idempotencyToken.ToArray());
        var pair = PublicKeyAuth.GenerateKeyPair(seed);
        CryptographicOperations.ZeroMemory(seed);
        var keyId = SHA256.HashData(pair.PublicKey);
        privateKeys.AddOrUpdate(Convert.ToHexString(keyId), pair.PrivateKey,
            (_, prior) => { CryptographicOperations.ZeroMemory(pair.PrivateKey); return prior; });
        return ValueTask.FromResult(new ProductionMailboxOwnerControlKeyHandle(
            keyId, pair.PublicKey));
    }

    public ValueTask<byte[]> SignAsync(ReadOnlyMemory<byte> keyId,
        ReadOnlyMemory<byte> signingBytes, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!enabled || keyId.Length != 32 || signingBytes.IsEmpty || signingBytes.Length > 64 * 1024
            || !privateKeys.TryGetValue(Convert.ToHexString(keyId.Span), out var privateKey))
            throw new InvalidOperationException("Development OCR key is unavailable.");
        return ValueTask.FromResult(PublicKeyAuth.SignDetached(signingBytes.ToArray(), privateKey));
    }

    public ValueTask<bool> IsHealthyAsync(ReadOnlyMemory<byte> keyId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(enabled && keyId.Length == 32
            && privateKeys.ContainsKey(Convert.ToHexString(keyId.Span)));
    }

    public ValueTask<bool> DeleteUncommittedAsync(ReadOnlyMemory<byte> idempotencyToken,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (idempotencyToken.Length != 32) return ValueTask.FromResult(false);
        using var hmac = new HMACSHA256(masterSeed);
        var seed = hmac.ComputeHash(idempotencyToken.ToArray());
        var pair = PublicKeyAuth.GenerateKeyPair(seed);
        CryptographicOperations.ZeroMemory(seed);
        var expected = SHA256.HashData(pair.PublicKey);
        CryptographicOperations.ZeroMemory(pair.PrivateKey);
        if (!privateKeys.TryRemove(Convert.ToHexString(expected), out var privateKey))
            return ValueTask.FromResult(true);
        CryptographicOperations.ZeroMemory(privateKey);
        return ValueTask.FromResult(true);
    }

    internal void Disable() => enabled = false;

    public void Dispose()
    {
        enabled = false;
        foreach (var value in privateKeys.Values) CryptographicOperations.ZeroMemory(value);
        privateKeys.Clear(); CryptographicOperations.ZeroMemory(masterSeed);
    }
}

public sealed class UnixSocketProductionMailboxOwnerControlKeyStore(
    string socketPath, TimeSpan timeout) : IProductionMailboxOwnerControlKeyStore
{
    private static ReadOnlySpan<byte> Magic => "PMOK"u8;
    public bool IsSigningEnabled => true;

    public async ValueTask<ProductionMailboxOwnerControlKeyHandle> CreateOrGetAsync(
        ReadOnlyMemory<byte> idempotencyToken, CancellationToken cancellationToken)
    {
        if (idempotencyToken.Length != 32)
            throw new InvalidDataException("OCR idempotency token is invalid.");
        var response = await ExchangeAsync(1, idempotencyToken, 64, cancellationToken);
        var keyId = response[..32]; var publicKey = response[32..];
        if (keyId.AsSpan().IndexOfAnyExcept((byte)0) < 0
            || publicKey.AsSpan().IndexOfAnyExcept((byte)0) < 0)
            throw new IOException("OCR HSM returned an invalid key identity.");
        return new(keyId, publicKey);
    }

    public ValueTask<byte[]> SignAsync(ReadOnlyMemory<byte> keyId,
        ReadOnlyMemory<byte> signingBytes, CancellationToken cancellationToken)
    {
        if (keyId.Length != 32 || signingBytes.IsEmpty || signingBytes.Length > 64 * 1024)
            throw new InvalidDataException("OCR signing request is invalid.");
        var payload = new byte[36 + signingBytes.Length];
        keyId.Span.CopyTo(payload); BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(32),
            checked((uint)signingBytes.Length)); signingBytes.Span.CopyTo(payload.AsSpan(36));
        return ExchangeAsync(2, payload, 64, cancellationToken);
    }

    public async ValueTask<bool> IsHealthyAsync(ReadOnlyMemory<byte> keyId,
        CancellationToken cancellationToken)
    {
        if (keyId.Length != 32) return false;
        var response = await ExchangeAsync(3, keyId, 1, cancellationToken);
        return response[0] == 1;
    }

    public async ValueTask<bool> DeleteUncommittedAsync(ReadOnlyMemory<byte> idempotencyToken,
        CancellationToken cancellationToken)
    {
        if (idempotencyToken.Length != 32) return false;
        var response = await ExchangeAsync(4, idempotencyToken, 1, cancellationToken);
        return response[0] == 1;
    }

    private async ValueTask<byte[]> ExchangeAsync(byte operation,
        ReadOnlyMemory<byte> payload, int responseLength, CancellationToken cancellationToken)
    {
        if (OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("OCR HSM requires a Unix domain socket.");
        if (!Path.IsPathFullyQualified(socketPath) || timeout <= TimeSpan.Zero
            || timeout > TimeSpan.FromSeconds(30))
            throw new InvalidOperationException("OCR HSM socket configuration is invalid.");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(timeout);
        using var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        await socket.ConnectAsync(new UnixDomainSocketEndPoint(socketPath), deadline.Token);
        var header = new byte[10]; Magic.CopyTo(header); header[4] = 1; header[5] = operation;
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(6), checked((uint)payload.Length));
        await SendAllAsync(socket, header, deadline.Token);
        await SendAllAsync(socket, payload, deadline.Token);
        var response = new byte[responseLength]; var offset = 0;
        while (offset < response.Length)
        {
            var read = await socket.ReceiveAsync(response.AsMemory(offset), SocketFlags.None,
                deadline.Token);
            if (read == 0) throw new IOException("OCR HSM response is truncated.");
            offset += read;
        }
        if (socket.Available != 0) throw new IOException("OCR HSM returned trailing bytes.");
        return response;
    }

    private static async ValueTask SendAllAsync(Socket socket, ReadOnlyMemory<byte> value,
        CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < value.Length)
        {
            var sent = await socket.SendAsync(value[offset..], SocketFlags.None, cancellationToken);
            if (sent == 0) throw new IOException("OCR HSM socket closed during request.");
            offset += sent;
        }
    }
}

internal static class ProductionMailboxOwnerControlKeyStoreFactory
{
    internal static IProductionMailboxOwnerControlKeyStore Create(
        ProductionMailboxOptions options, IHostEnvironment environment)
    {
        if (!options.OwnerControlSigningEnabled)
            return new DisabledProductionMailboxOwnerControlKeyStore();
        if (environment.IsProduction())
        {
            if (OperatingSystem.IsWindows())
                throw new PlatformNotSupportedException(
                    "Production OCR signing requires a Unix HSM socket.");
            if (string.IsNullOrWhiteSpace(options.OwnerControlHsmSocketPath)
                || !Path.IsPathFullyQualified(options.OwnerControlHsmSocketPath)
                || !File.Exists(options.OwnerControlHsmSocketPath)
                || string.Equals(options.OwnerControlHsmSocketPath,
                    options.ExternalSignerSocketPath, StringComparison.Ordinal)
                || string.Equals(options.OwnerControlHsmSocketPath,
                    options.ClosurePublisherSignerSocketPath, StringComparison.Ordinal))
                throw new InvalidOperationException(
                    "Production requires a dedicated protected OCR HSM socket.");
            var mode = File.GetUnixFileMode(options.OwnerControlHsmSocketPath);
            if ((mode & (UnixFileMode.OtherRead | UnixFileMode.OtherWrite |
                    UnixFileMode.OtherExecute)) != 0)
                throw new InvalidOperationException(
                    "OCR HSM socket is accessible to other users.");
            return new UnixSocketProductionMailboxOwnerControlKeyStore(
                options.OwnerControlHsmSocketPath,
                TimeSpan.FromSeconds(options.OwnerControlHsmTimeoutSeconds));
        }
        if (!environment.IsDevelopment()
            || string.IsNullOrWhiteSpace(options.DevelopmentOwnerControlSeedPath))
            return new DisabledProductionMailboxOwnerControlKeyStore();
        return new DevelopmentProductionMailboxOwnerControlKeyStore(
            options.DevelopmentOwnerControlSeedPath);
    }
}

internal sealed class DisabledProductionMailboxOwnerControlKeyStore :
    IProductionMailboxOwnerControlKeyStore
{
    public bool IsSigningEnabled => false;
    public ValueTask<ProductionMailboxOwnerControlKeyHandle> CreateOrGetAsync(
        ReadOnlyMemory<byte> idempotencyToken, CancellationToken cancellationToken) =>
        ValueTask.FromException<ProductionMailboxOwnerControlKeyHandle>(
            new InvalidOperationException("Owner-control signing is disabled."));
    public ValueTask<byte[]> SignAsync(ReadOnlyMemory<byte> keyId,
        ReadOnlyMemory<byte> signingBytes, CancellationToken cancellationToken) =>
        ValueTask.FromException<byte[]>(
            new InvalidOperationException("Owner-control signing is disabled."));
    public ValueTask<bool> IsHealthyAsync(ReadOnlyMemory<byte> keyId,
        CancellationToken cancellationToken) => ValueTask.FromResult(false);
    public ValueTask<bool> DeleteUncommittedAsync(ReadOnlyMemory<byte> idempotencyToken,
        CancellationToken cancellationToken) =>
        ValueTask.FromResult(false);
}
