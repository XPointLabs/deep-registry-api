using System.Buffers.Binary;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Deep.Protocol.DeepExtension.MailboxAuthority;
using Deep.Protocol.DeepExtension.MailboxTopology;
using Sodium;

namespace Deep.Registry.Api.ProductionMailbox;

public interface IProductionMailboxClosurePublisherSigner
{
    ValueTask<byte[]> SignAsync(
        ReadOnlyMemory<byte> signingBytes,
        CancellationToken cancellationToken);
}

public sealed class ProductionMailboxClosurePublisherSignerAdapter(
    IEd25519ExternalSigner inner) : IProductionMailboxClosurePublisherSigner, IDisposable
{
    public ValueTask<byte[]> SignAsync(
        ReadOnlyMemory<byte> signingBytes,
        CancellationToken cancellationToken) => inner.SignAsync(signingBytes, cancellationToken);

    public void Dispose()
    {
        if (inner is IDisposable disposable) disposable.Dispose();
    }
}

public interface IProductionMailboxClosureTransport
{
    ValueTask<bool> PrepositionAsync(
        ProductionMailboxPublicationItem item,
        ReadOnlyMemory<byte> canonicalCommand,
        CancellationToken cancellationToken);
}

public sealed class HttpsProductionMailboxClosureTransport : IProductionMailboxClosureTransport
{
    private const string Route = "/api/peer/production-mailbox/closure";
    private const string MediaType =
        "application/vnd.deep.production-mailbox-preposition-command";

    public async ValueTask<bool> PrepositionAsync(
        ProductionMailboxPublicationItem item,
        ReadOnlyMemory<byte> canonicalCommand,
        CancellationToken cancellationToken)
    {
        if (!Uri.TryCreate(item.Endpoint, UriKind.Absolute, out var origin)
            || origin.Scheme != Uri.UriSchemeHttps || origin.PathAndQuery != "/")
            return false;
        using var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = System.Net.DecompressionMethods.None,
            ConnectTimeout = TimeSpan.FromSeconds(5),
            SslOptions = new SslClientAuthenticationOptions
            {
                RemoteCertificateValidationCallback = (_, certificate, _, errors) =>
                    VerifyPinnedCertificate(certificate, errors,
                        item.CurrentSpkiSha256, item.NextSpkiSha256)
            }
        };
        using var client = new HttpClient(handler)
        {
            Timeout = TimeSpan.FromSeconds(10)
        };
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(origin, Route))
        {
            Content = new ByteArrayContent(canonicalCommand.ToArray())
        };
        request.Content.Headers.ContentType = new(MediaType);
        request.Headers.CacheControl = new() { NoStore = true };
        try
        {
            using var response = await client.SendAsync(
                request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            return response.StatusCode == System.Net.HttpStatusCode.NoContent;
        }
        catch (Exception exception) when (exception is HttpRequestException
            or IOException or TaskCanceledException)
        {
            return false;
        }
    }

    private static bool VerifyPinnedCertificate(
        X509Certificate? certificate,
        SslPolicyErrors errors,
        ReadOnlySpan<byte> currentPin,
        ReadOnlySpan<byte> nextPin)
    {
        if (certificate is null || errors != SslPolicyErrors.None
            || currentPin.Length != 32 || nextPin.Length != 32)
            return false;
        using var parsed = certificate as X509Certificate2
            ?? new X509Certificate2(certificate);
        var hash = SHA256.HashData(parsed.PublicKey.ExportSubjectPublicKeyInfo());
        return CryptographicOperations.FixedTimeEquals(hash, currentPin)
            || CryptographicOperations.FixedTimeEquals(hash, nextPin);
    }
}

internal sealed record ProductionMailboxPrepositionTarget(
    byte[] ReplicaId,
    string HttpsOrigin,
    byte[] CurrentSpkiSha256,
    byte[] NextSpkiSha256);

internal static class ProductionMailboxPublicationCodec
{
    private static ReadOnlySpan<byte> EnvelopeMagic => "PMC1"u8;
    private static ReadOnlySpan<byte> CommandMagic => "PMP1"u8;
    private static ReadOnlySpan<byte> CommandDomain => "Deep/PMP1/preposition/v1"u8;
    private const int EnvelopeHeaderLength = 28;
    private const int CommandHeaderLength = 248;
    internal const int MaximumLegacyReplicaIds = 2;

    public static byte[] EncodeEnvelope(
        ReadOnlySpan<byte> authority,
        ReadOnlySpan<byte> revocation,
        ReadOnlySpan<byte> topology,
        ReadOnlySpan<byte> selection,
        ReadOnlySpan<byte> successor)
    {
        if (authority.IsEmpty || authority.Length > ProductionMailboxAuthorityConstants.MaximumArtifactBytes
            || revocation.IsEmpty || revocation.Length > 1_048_576
            || topology.IsEmpty || topology.Length > ProductionMailboxTopologyConstants.MaximumTopologyArtifactBytes
            || selection.IsEmpty || selection.Length > ProductionMailboxTopologyConstants.MaximumSelectionArtifactBytes
            || successor.IsEmpty || successor.Length > ProductionMailboxSelectionSuccessorConstants.MaximumArtifactBytes)
            throw new InvalidDataException("Production mailbox closure field is outside bounds.");
        var total = checked(EnvelopeHeaderLength + authority.Length + revocation.Length
            + topology.Length + selection.Length + successor.Length);
        var output = new byte[total];
        EnvelopeMagic.CopyTo(output); output[4] = 1; output[5] = 1;
        WriteLength(output.AsSpan(8), authority.Length);
        WriteLength(output.AsSpan(12), revocation.Length);
        WriteLength(output.AsSpan(16), topology.Length);
        WriteLength(output.AsSpan(20), selection.Length);
        WriteLength(output.AsSpan(24), successor.Length);
        var offset = EnvelopeHeaderLength;
        Copy(authority, output, ref offset); Copy(revocation, output, ref offset);
        Copy(topology, output, ref offset); Copy(selection, output, ref offset);
        Copy(successor, output, ref offset);
        return output;
    }

    public static async ValueTask<byte[]> CreateCommandAsync(
        ulong timestampUnixSeconds,
        ProductionMailboxPrepositionTarget target,
        IReadOnlyList<byte[]> authorizedLegacyReplicaIds,
        byte[] canonicalEnvelope,
        byte[] publisherPublicKey,
        IProductionMailboxClosurePublisherSigner signer,
        CancellationToken cancellationToken)
    {
        ValidateTarget(target);
        var legacy = authorizedLegacyReplicaIds
            .Select(static value => value.ToArray())
            .OrderBy(Convert.ToHexString, StringComparer.Ordinal)
            .ToArray();
        if (legacy.Length > MaximumLegacyReplicaIds
            || legacy.Any(static value => value.Length != 32
                || value.AsSpan().IndexOfAnyExcept((byte)0) < 0)
            || legacy.Select(Convert.ToHexString).Distinct(StringComparer.Ordinal).Count()
                != legacy.Length)
            throw new InvalidDataException("Production mailbox legacy replica authorization is invalid.");
        var nonce = RandomNumberGenerator.GetBytes(32);
        var envelopeHash = SHA256.HashData(canonicalEnvelope);
        var signingBytes = SigningBytes(
            timestampUnixSeconds, nonce, envelopeHash, target.ReplicaId, legacy);
        var signature = await signer.SignAsync(signingBytes, cancellationToken);
        if (publisherPublicKey.Length != 32 || signature.Length != 64
            || signature.AsSpan().IndexOfAnyExcept((byte)0) < 0
            || !PublicKeyAuth.VerifyDetached(signature, signingBytes, publisherPublicKey))
            throw new InvalidDataException("Production mailbox publisher signature is invalid.");
        var output = new byte[checked(CommandHeaderLength + canonicalEnvelope.Length)];
        CommandMagic.CopyTo(output); output[4] = 1; output[5] = checked((byte)legacy.Length);
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(8), timestampUnixSeconds);
        nonce.CopyTo(output.AsSpan(16)); envelopeHash.CopyTo(output.AsSpan(48));
        target.ReplicaId.CopyTo(output.AsSpan(80));
        for (var index = 0; index < legacy.Length; index++)
            legacy[index].CopyTo(output.AsSpan(112 + index * 32));
        signature.CopyTo(output.AsSpan(176));
        BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(240),
            checked((uint)canonicalEnvelope.Length));
        canonicalEnvelope.CopyTo(output.AsSpan(CommandHeaderLength));
        return output;
    }

    private static byte[] SigningBytes(
        ulong timestamp, byte[] nonce, byte[] envelopeHash,
        byte[] targetReplicaId, IReadOnlyList<byte[]> legacy)
    {
        var output = new byte[CommandDomain.Length + 169];
        CommandDomain.CopyTo(output); var offset = CommandDomain.Length;
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(offset), timestamp); offset += 8;
        nonce.CopyTo(output.AsSpan(offset)); offset += 32;
        envelopeHash.CopyTo(output.AsSpan(offset)); offset += 32;
        targetReplicaId.CopyTo(output.AsSpan(offset)); offset += 32;
        output[offset++] = checked((byte)legacy.Count);
        foreach (var value in legacy)
        { value.CopyTo(output.AsSpan(offset)); offset += 32; }
        return output;
    }

    private static void ValidateTarget(ProductionMailboxPrepositionTarget target)
    {
        if (target.ReplicaId.Length != 32 || target.CurrentSpkiSha256.Length != 32
            || target.NextSpkiSha256.Length != 32
            || !Uri.TryCreate(target.HttpsOrigin, UriKind.Absolute, out var endpoint)
            || endpoint.Scheme != Uri.UriSchemeHttps || endpoint.PathAndQuery != "/")
            throw new InvalidDataException("Production mailbox publication target is invalid.");
    }

    private static void WriteLength(Span<byte> destination, int length) =>
        BinaryPrimitives.WriteUInt32BigEndian(destination, checked((uint)length));
    private static void Copy(ReadOnlySpan<byte> value, byte[] output, ref int offset)
    { value.CopyTo(output.AsSpan(offset)); offset += value.Length; }
}

public sealed class ProductionMailboxPublicationDrainer(
    IServiceScopeFactory scopeFactory,
    ILogger<ProductionMailboxPublicationDrainer> logger) : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromSeconds(15);
    private const int MaximumBatch = 64;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(Interval);
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var scope = scopeFactory.CreateScope();
                var coordinator = scope.ServiceProvider
                    .GetRequiredService<ProductionMailboxCoordinator>();
                _ = await coordinator.DrainPendingPublicationsAsync(
                    MaximumBatch, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception exception)
            {
                logger.LogWarning(exception,
                    "Production mailbox publication drain failed; durable work remains pending.");
            }
            if (!await timer.WaitForNextTickAsync(stoppingToken)) break;
        }
    }
}
