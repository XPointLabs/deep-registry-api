#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Buffers.Binary;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Registry.Api.DirectoryPublication;

// Private crypto transport owner. Currentness, issuance intent and permanent
// winners remain owned by the actual issuer/journal, never this process.
internal static class MailboxRoleSigner
{
    internal sealed class Options
    {
        public string Role { get; set; } = "";
        public string NetworkIdHex { get; set; } = "";
        public string SeedPath { get; set; } = "";
        public string SocketPath { get; set; } = "";
        public uint AllowedPeerUserId { get; set; }
    }

    internal static async Task<int?> TryRunAsync(string[] args, IConfiguration config)
    {
        if (args.Length == 0 || args[0] != "mailbox-role-signer") return null;
        try {
            if (args.Length != 2 || args[1] != "run" || !OperatingSystem.IsLinux()) throw new ArgumentException("Unsupported signer command/platform.");
            var section = config.GetSection("MailboxRoleSigner");
            var allowed = new[] { "Role", "NetworkIdHex", "SeedPath", "SocketPath", "AllowedPeerUserId" };
            if (section.GetChildren().Any(child => !allowed.Contains(child.Key, StringComparer.OrdinalIgnoreCase))) throw new ArgumentException("Unknown signer configuration.");
            var options = section.Get<Options>() ?? throw new ArgumentException("Signer custody missing.");
            if (section["AllowedPeerUserId"] is null) throw new ArgumentException("Signer peer UID must be explicit.");
            using var stopping = new CancellationTokenSource();
            using var term = PosixSignalRegistration.Create(PosixSignal.SIGTERM, context => { context.Cancel = true; stopping.Cancel(); });
            using var interrupt = PosixSignalRegistration.Create(PosixSignal.SIGINT, context => { context.Cancel = true; stopping.Cancel(); });
            await RunAsync(options, stopping.Token); return 0;
        } catch (Exception error) when (error is IOException or ArgumentException or CryptographicException or InvalidOperationException or SocketException or UnauthorizedAccessException or FormatException or PlatformNotSupportedException) {
            Console.Error.WriteLine($"Mailbox role signer failed closed ({error.GetType().Name}); custody was not regenerated."); return 2;
        }
    }

    internal static void ValidateSigningInput(ReadOnlySpan<byte> input, MailboxCapabilityDomain role,
        ReadOnlySpan<byte> network, ReadOnlySpan<byte> publicKey)
    {
        if (network.Length != 16 || publicKey.Length != 32 || role is not (MailboxCapabilityDomain.Deposit or MailboxCapabilityDomain.Retrieve) ||
            input.IsEmpty || input.Length > UnixSocketEd25519ExternalSigner.MaximumSigningBytes) throw new ArgumentException("Invalid signer scope.");
        if (input.Length == 256) {
            // The ordinary public codec is the single canonical MCG3 owner.
            var exact = new byte[MailboxAuthenticatedCapabilityLimits.GrantLength];
            input[16..].CopyTo(exact); exact.AsSpan(240, 64).Fill(1);
            var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(exact);
            if (grant.Domain != role || !grant.NetworkId.Span.SequenceEqual(network) || !grant.IssuerPublicKey.Span.SequenceEqual(publicKey) ||
                !MailboxAuthenticatedCapabilityCodec.GetGrantSigningBytes(grant).AsSpan().SequenceEqual(input))
                throw new CryptographicException("Grant is outside signer purpose.");
            return;
        }
        ReadOnlySpan<byte> label = "Deep/XPoint/V1/MGR1/issuer\0"u8;
        var prefix = label.Length + 6;
        if (input.Length < prefix + MailboxGrantRevocationV1Codec.MinimumBytes - 72 || !input.StartsWith(label) ||
            BinaryPrimitives.ReadUInt16BigEndian(input[label.Length..]) != 0x0201 ||
            BinaryPrimitives.ReadUInt32BigEndian(input[(label.Length + 2)..]) != input.Length - prefix)
            throw new CryptographicException("Unknown signer purpose.");
        // Append only the known current signature field, then require a byte-
        // identical roundtrip through the public MGR1 codec. Not another parser.
        var record = new byte[input.Length - prefix + 72]; input[prefix..].CopyTo(record);
        BinaryPrimitives.WriteUInt16BigEndian(record.AsSpan(8), 12);
        var field = record.AsSpan(record.Length - 72); BinaryPrimitives.WriteUInt16BigEndian(field, 12);
        BinaryPrimitives.WriteUInt32BigEndian(field[4..], 64); field[8..].Fill(1);
        var revocation = MailboxGrantRevocationV1Codec.Decode(record);
        if (revocation.Domain != role || !revocation.Field(1).Span.SequenceEqual(network) || !revocation.Field(4).Span.SequenceEqual(publicKey) ||
            !revocation.SignatureInput.Span.SequenceEqual(input)) throw new CryptographicException("Revocation is outside signer purpose.");
    }

    internal static async Task RunAsync(Options options, CancellationToken ct)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("Signer requires Linux custody.");
        var role = options.Role switch { "deposit" => MailboxCapabilityDomain.Deposit, "retrieve" => MailboxCapabilityDomain.Retrieve,
            _ => throw new ArgumentException("Unknown signer role.") };
        var network = Convert.FromHexString(options.NetworkIdHex);
        if (network.Length != 16 || network.AsSpan().IndexOfAnyExcept((byte)0) < 0) throw new ArgumentException("Invalid signer network.");
        if (!Path.IsPathFullyQualified(options.SeedPath) || !Path.IsPathFullyQualified(options.SocketPath) ||
            System.Text.Encoding.UTF8.GetByteCount(options.SocketPath) > 100)
            throw new ArgumentException("Signer paths must be absolute and bounded.");
        var seedPath = Path.GetFullPath(options.SeedPath); var socketPath = Path.GetFullPath(options.SocketPath);
        var directory = Path.GetDirectoryName(socketPath)!; var uid = GetEffectiveUserId();
        RequirePrivateDirectory(directory, uid); RequirePrivateDirectory(Path.GetDirectoryName(seedPath)!, uid);
        _ = RequireFile(seedPath, uid, 0x8000, 0x180); // regular0600
        var leasePath = socketPath + ".lease";
        var existingLease = Stat(leasePath);
        if (existingLease is not null) _ = RequireFile(leasePath, uid, 0x8000, 0x180);
        using var lease = new FileStream(leasePath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        if (lease.Length != 0) throw new InvalidDataException("Signer lease is not an owned empty file.");
        File.SetUnixFileMode(leasePath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        var seed = DirectoryPublicationProtectedFile.ReadBounded(seedPath, 32);
        KeyPair pair;
        try {
            if (seed.Length != 32 || seed.AsSpan().IndexOfAnyExcept((byte)0) < 0) throw new InvalidDataException("Role seed must be exact nonzero raw32 custody.");
            pair = PublicKeyAuth.GenerateKeyPair(seed);
        } finally { CryptographicOperations.ZeroMemory(seed); }
        using var listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        FileIdentity? ownedSocket = null;
        try {
            if (Stat(socketPath) is { } prior) {
                _ = RequireFile(socketPath, uid, 0xc000, 0x180); // socket0600, never unlink a regular file/link.
                using var probe = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(TimeSpan.FromSeconds(1));
                try { await probe.ConnectAsync(new UnixDomainSocketEndPoint(socketPath), deadline.Token); throw new IOException("Signer endpoint is already active."); }
                catch (SocketException error) when (error.SocketErrorCode == SocketError.ConnectionRefused) {
                    if (Stat(socketPath) != prior) throw new IOException("Stale socket changed.");
                    File.Delete(socketPath); // Exact verified owned stale socket only, under the exclusive lease.
                }
            }
            listener.Bind(new UnixDomainSocketEndPoint(socketPath));
            File.SetUnixFileMode(socketPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            ownedSocket = RequireFile(socketPath, uid, 0xc000, 0x180); listener.Listen(8);
            Console.WriteLine("Protected mailbox role signer listening; not issuer readiness evidence.");
            while (!ct.IsCancellationRequested) {
                using var peer = await listener.AcceptAsync(ct);
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(TimeSpan.FromSeconds(4));
                byte[]? body = null; byte[]? signature = null;
                try {
                    var credentials = new byte[12]; uint credentialLength = 12;
                    if (GetPeerCredentials(peer.SafeHandle.DangerousGetHandle().ToInt32(), 1, 17, credentials, ref credentialLength) != 0 ||
                        credentialLength != 12 || BitConverter.ToUInt32(credentials, 4) != options.AllowedPeerUserId)
                        throw new UnauthorizedAccessException("Signer peer is not the configured local UID.");
                    using var stream = new NetworkStream(peer, ownsSocket: false);
                    var header = new byte[9]; await stream.ReadExactlyAsync(header, deadline.Token);
                    var length = BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(5));
                    if (!header.AsSpan(0, 4).SequenceEqual("PMES"u8) || header[4] != 1 || length is 0 or > UnixSocketEd25519ExternalSigner.MaximumSigningBytes)
                        throw new InvalidDataException("Invalid bounded PMES request.");
                    body = new byte[checked((int)length)]; await stream.ReadExactlyAsync(body, deadline.Token);
                    ValidateSigningInput(body, role, network, pair.PublicKey);
                    deadline.Token.ThrowIfCancellationRequested(); signature = PublicKeyAuth.SignDetached(body, pair.PrivateKey);
                    deadline.Token.ThrowIfCancellationRequested(); await stream.WriteAsync(signature, deadline.Token);
                    peer.Shutdown(SocketShutdown.Send); // Exact64 then EOF, within the original request budget.
                } catch (Exception error) when (error is IOException or SocketException or CryptographicException or ArgumentException or UnauthorizedAccessException or OperationCanceledException or FormatException or MailboxAuthenticatedCapabilityException) {
                    Console.Error.WriteLine($"Mailbox role signer rejected a request ({error.GetType().Name}).");
                } finally { if (body is not null) CryptographicOperations.ZeroMemory(body); if (signature is not null) CryptographicOperations.ZeroMemory(signature); }
            }
        } catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        finally {
            CryptographicOperations.ZeroMemory(pair.PrivateKey);
            listener.Dispose();
            if (ownedSocket is not null && Stat(socketPath) == ownedSocket) File.Delete(socketPath);
        }
    }

    internal sealed record FileIdentity(ushort Mode, uint Uid, ulong Inode, uint DeviceMajor, uint DeviceMinor);
    private static FileIdentity? Stat(string path)
    {
        var buffer = new byte[256];
        if (Statx(-100, path, 0x100, 0x10b, buffer) != 0) { // AT_FDCWD, NOFOLLOW, TYPE/MODE/UID/INO.
            var errno = Marshal.GetLastPInvokeError(); if (errno == 2) return null;
            throw new IOException("Cannot authenticate Linux custody metadata.");
        }
        if ((BitConverter.ToUInt32(buffer, 0) & 0x10b) != 0x10b) throw new IOException("Incomplete Linux custody metadata.");
        return new(BitConverter.ToUInt16(buffer, 28), BitConverter.ToUInt32(buffer, 20), BitConverter.ToUInt64(buffer, 32),
            BitConverter.ToUInt32(buffer, 136), BitConverter.ToUInt32(buffer, 140));
    }
    private static FileIdentity RequireFile(string path, uint uid, int type, int permissions)
    {
        var metadata = Stat(path) ?? throw new IOException("Required custody file missing.");
        if ((metadata.Mode & 0xf000) != type || (metadata.Mode & 0xfff) != permissions || metadata.Uid != uid)
            throw new UnauthorizedAccessException("Custody type, mode or owner is invalid.");
        return metadata;
    }
    private static void RequirePrivateDirectory(string directory, uint uid)
    {
        _ = RequireFile(directory, uid, 0x4000, 0x1c0); // directory0700
        for (string? path = Path.GetDirectoryName(directory); path is not null; path = Path.GetDirectoryName(path))
        {
            if (Stat(path) is not { } entry || (entry.Mode & 0xf000) != 0x4000) throw new IOException("Custody parent is missing or linked.");
            // A private leaf is insufficient below an untrusted renameable parent.
            // Root/user-owned sticky /tmp is allowed; other writable ancestry isn't.
            if ((entry.Mode & 0x12) != 0 && ((entry.Mode & 0x200) == 0 || entry.Uid != 0 && entry.Uid != uid))
                throw new UnauthorizedAccessException("Custody ancestor permits untrusted replacement.");
        }
    }
    [DllImport("libc", EntryPoint = "statx", SetLastError = true)]
    private static extern int Statx(int directory, [MarshalAs(UnmanagedType.LPUTF8Str)] string path, int flags, uint mask, [Out] byte[] buffer);
    [DllImport("libc", EntryPoint = "geteuid")]
    internal static extern uint GetEffectiveUserId();
    [DllImport("libc", EntryPoint = "getsockopt", SetLastError = true)]
    private static extern int GetPeerCredentials(int socket, int level, int option, [Out] byte[] buffer, ref uint length);
}
#endif
