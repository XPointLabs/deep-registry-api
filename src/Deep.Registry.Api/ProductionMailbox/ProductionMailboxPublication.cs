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

    ValueTask<byte[]?> ReserveCapacityAsync(
        ProductionMailboxPrepositionTarget target,
        ReadOnlyMemory<byte> canonicalCommand,
        CancellationToken cancellationToken);

    ValueTask<byte[]?> ReconcileCapacityAsync(
        ProductionMailboxPrepositionTarget target,
        ReadOnlyMemory<byte> canonicalCommand,
        CancellationToken cancellationToken);
}

public sealed class HttpsProductionMailboxClosureTransport : IProductionMailboxClosureTransport
{
    private const string Route = "/api/peer/production-mailbox/closure";
    private const string MediaType =
        "application/vnd.deep.production-mailbox-preposition-command";
    private const string CapacityRoute =
        "/api/peer/production-mailbox/closure-capacity";
    private const string CapacityCommandMediaType =
        "application/vnd.deep.production-mailbox-capacity-command";
    private const string CapacityReceiptMediaType =
        "application/vnd.deep.production-mailbox-capacity-receipt";
    private const string CapacityReconciliationRoute =
        "/api/peer/production-mailbox/closure-capacity-reconciliation";
    private const string CapacityReconciliationCommandMediaType =
        "application/vnd.deep.production-mailbox-capacity-reconciliation-command";
    private const string CapacityReconciliationReceiptMediaType =
        "application/vnd.deep.production-mailbox-capacity-reconciliation-receipt";

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

    public async ValueTask<byte[]?> ReserveCapacityAsync(
        ProductionMailboxPrepositionTarget target,
        ReadOnlyMemory<byte> canonicalCommand,
        CancellationToken cancellationToken)
    {
        if (!Uri.TryCreate(target.HttpsOrigin, UriKind.Absolute, out var origin)
            || origin.Scheme != Uri.UriSchemeHttps || origin.PathAndQuery != "/"
            || canonicalCommand.Length != ProductionMailboxCapacityCommandCodec.EncodedLength)
            return null;
        using var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = System.Net.DecompressionMethods.None,
            ConnectTimeout = TimeSpan.FromSeconds(5),
            SslOptions = new SslClientAuthenticationOptions
            {
                RemoteCertificateValidationCallback = (_, certificate, _, errors) =>
                    VerifyPinnedCertificate(certificate, errors,
                        target.CurrentSpkiSha256, target.NextSpkiSha256)
            }
        };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
        using var request = new HttpRequestMessage(HttpMethod.Post,
            new Uri(origin, CapacityRoute))
        {
            Content = new ByteArrayContent(canonicalCommand.ToArray())
        };
        request.Content.Headers.ContentType = new(CapacityCommandMediaType);
        request.Headers.CacheControl = new() { NoStore = true };
        try
        {
            using var response = await client.SendAsync(
                request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            if (response.StatusCode != System.Net.HttpStatusCode.OK
                || response.Content.Headers.ContentLength
                    != ProductionMailboxCapacityReceiptCodec.EncodedLength
                || !string.Equals(response.Content.Headers.ContentType?.MediaType,
                    CapacityReceiptMediaType, StringComparison.OrdinalIgnoreCase))
                return null;
            var receipt = await response.Content.ReadAsByteArrayAsync(cancellationToken);
            return receipt.Length == ProductionMailboxCapacityReceiptCodec.EncodedLength
                ? receipt : null;
        }
        catch (Exception exception) when (exception is HttpRequestException
            or IOException or TaskCanceledException)
        {
            return null;
        }
    }

    public async ValueTask<byte[]?> ReconcileCapacityAsync(
        ProductionMailboxPrepositionTarget target,
        ReadOnlyMemory<byte> canonicalCommand,
        CancellationToken cancellationToken)
    {
        if (!Uri.TryCreate(target.HttpsOrigin, UriKind.Absolute, out var origin)
            || origin.Scheme != Uri.UriSchemeHttps || origin.PathAndQuery != "/"
            || canonicalCommand.Length
                != ProductionMailboxCapacityReconciliationCommandCodec.EncodedLength)
            return null;
        using var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = System.Net.DecompressionMethods.None,
            ConnectTimeout = TimeSpan.FromSeconds(5),
            SslOptions = new SslClientAuthenticationOptions
            {
                RemoteCertificateValidationCallback = (_, certificate, _, errors) =>
                    VerifyPinnedCertificate(certificate, errors,
                        target.CurrentSpkiSha256, target.NextSpkiSha256)
            }
        };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
        using var request = new HttpRequestMessage(HttpMethod.Post,
            new Uri(origin, CapacityReconciliationRoute))
        { Content = new ByteArrayContent(canonicalCommand.ToArray()) };
        request.Content.Headers.ContentType = new(CapacityReconciliationCommandMediaType);
        request.Headers.CacheControl = new() { NoStore = true };
        try
        {
            using var response = await client.SendAsync(request,
                HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            if (response.StatusCode != System.Net.HttpStatusCode.OK
                || response.Content.Headers.ContentLength
                    != ProductionMailboxCapacityReconciliationReceiptCodec.EncodedLength
                || !string.Equals(response.Content.Headers.ContentType?.MediaType,
                    CapacityReconciliationReceiptMediaType,
                    StringComparison.OrdinalIgnoreCase))
                return null;
            var receipt = await response.Content.ReadAsByteArrayAsync(cancellationToken);
            return receipt.Length
                == ProductionMailboxCapacityReconciliationReceiptCodec.EncodedLength
                ? receipt : null;
        }
        catch (Exception exception) when (exception is HttpRequestException
            or IOException or TaskCanceledException)
        { return null; }
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

public sealed record ProductionMailboxPrepositionTarget(
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
    private const int CommandHeaderLength = 280;
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
        ReadOnlyMemory<byte> reservationCohortId,
        byte[] canonicalEnvelope,
        byte[] publisherPublicKey,
        IProductionMailboxClosurePublisherSigner signer,
        CancellationToken cancellationToken)
    {
        ValidateTarget(target);
        var frozenTarget = new ProductionMailboxPrepositionTarget(
            target.ReplicaId.ToArray(), target.HttpsOrigin,
            target.CurrentSpkiSha256.ToArray(), target.NextSpkiSha256.ToArray());
        var frozenEnvelope = canonicalEnvelope.ToArray();
        var frozenPublisherPublicKey = publisherPublicKey.ToArray();
        if (frozenPublisherPublicKey.Length != 32)
            throw new InvalidDataException(
                "Production mailbox publisher public key is invalid.");
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
        var envelopeHash = SHA256.HashData(frozenEnvelope);
        var cohort = reservationCohortId.IsEmpty
            ? new byte[32] : reservationCohortId.ToArray();
        if (cohort.Length != 32)
            throw new InvalidDataException(
                "Production mailbox reservation cohort is invalid.");
        var signingBytes = SigningBytes(
            timestampUnixSeconds, nonce, envelopeHash, frozenTarget.ReplicaId, legacy,
            cohort);
        var signature = await signer.SignAsync(signingBytes, cancellationToken);
        if (signature.Length != 64
            || signature.AsSpan().IndexOfAnyExcept((byte)0) < 0
            || !PublicKeyAuth.VerifyDetached(
                signature, signingBytes, frozenPublisherPublicKey))
            throw new InvalidDataException("Production mailbox publisher signature is invalid.");
        var output = new byte[checked(CommandHeaderLength + frozenEnvelope.Length)];
        CommandMagic.CopyTo(output); output[4] = 1; output[5] = checked((byte)legacy.Length);
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(8), timestampUnixSeconds);
        nonce.CopyTo(output.AsSpan(16)); envelopeHash.CopyTo(output.AsSpan(48));
        frozenTarget.ReplicaId.CopyTo(output.AsSpan(80));
        for (var index = 0; index < legacy.Length; index++)
            legacy[index].CopyTo(output.AsSpan(112 + index * 32));
        signature.CopyTo(output.AsSpan(176));
        cohort.CopyTo(output.AsSpan(240));
        BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(272),
            checked((uint)frozenEnvelope.Length));
        frozenEnvelope.CopyTo(output.AsSpan(CommandHeaderLength));
        return output;
    }

    private static byte[] SigningBytes(
        ulong timestamp, byte[] nonce, byte[] envelopeHash,
        byte[] targetReplicaId, IReadOnlyList<byte[]> legacy, byte[] cohort)
    {
        var output = new byte[CommandDomain.Length + 201];
        CommandDomain.CopyTo(output); var offset = CommandDomain.Length;
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(offset), timestamp); offset += 8;
        nonce.CopyTo(output.AsSpan(offset)); offset += 32;
        envelopeHash.CopyTo(output.AsSpan(offset)); offset += 32;
        targetReplicaId.CopyTo(output.AsSpan(offset)); offset += 32;
        output[offset++] = checked((byte)legacy.Count);
        foreach (var value in legacy)
        { value.CopyTo(output.AsSpan(offset)); offset += 32; }
        cohort.CopyTo(output.AsSpan(CommandDomain.Length + 169));
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

public enum ProductionMailboxCapacityOperation : byte
{
    ReserveOrRenew = 1,
    Release = 2
}

internal sealed record ProductionMailboxCapacityCommand(
    ProductionMailboxCapacityOperation Operation,
    ulong TimestampUnixSeconds,
    ulong ExpiresAtUnixSeconds,
    byte[] Nonce,
    byte[] CohortId,
    byte[] TargetReplicaId,
    uint ReservedClosureCount,
    ulong ReservedBytes,
    ulong Revision,
    byte[] PublisherSignature);

internal static class ProductionMailboxCapacityCommandCodec
{
    private static ReadOnlySpan<byte> Domain => "Deep/PMB1/capacity-command/v1"u8;
    internal const int EncodedLength = 208;

    internal static ProductionMailboxCapacityCommand DecodeAndVerify(
        ReadOnlySpan<byte> encoded, ReadOnlySpan<byte> expectedPublisherPublicKey)
    {
        if (encoded.Length != EncodedLength || !encoded[..4].SequenceEqual("PMB1"u8)
            || encoded[4] != 1 || encoded.Slice(6, 2).IndexOfAnyExcept((byte)0) >= 0
            || encoded.Slice(204, 4).IndexOfAnyExcept((byte)0) >= 0)
            throw new InvalidDataException(
                "Production mailbox capacity command is invalid.");
        var value = new ProductionMailboxCapacityCommand(
            (ProductionMailboxCapacityOperation)encoded[5],
            BinaryPrimitives.ReadUInt64BigEndian(encoded[8..]),
            BinaryPrimitives.ReadUInt64BigEndian(encoded[16..]),
            encoded.Slice(24, 32).ToArray(), encoded.Slice(56, 32).ToArray(),
            encoded.Slice(88, 32).ToArray(),
            BinaryPrimitives.ReadUInt32BigEndian(encoded[120..]),
            BinaryPrimitives.ReadUInt64BigEndian(encoded[124..]),
            BinaryPrimitives.ReadUInt64BigEndian(encoded[132..]),
            encoded.Slice(140, 64).ToArray());
        Validate(value, false);
        if (expectedPublisherPublicKey.Length != 32
            || !PublicKeyAuth.VerifyDetached(value.PublisherSignature,
                SigningBytes(value), expectedPublisherPublicKey.ToArray()))
            throw new InvalidDataException(
                "Production mailbox capacity publisher signature is invalid.");
        return value;
    }

    internal static async ValueTask<byte[]> CreateAsync(
        ProductionMailboxCapacityOperation operation,
        ulong timestamp,
        ulong expires,
        ReadOnlyMemory<byte> cohortId,
        ProductionMailboxPrepositionTarget target,
        uint reservedCount,
        ulong reservedBytes,
        ulong revision,
        byte[] publisherPublicKey,
        IProductionMailboxClosurePublisherSigner signer,
        CancellationToken cancellationToken)
    {
        var frozenPublisherPublicKey = publisherPublicKey.ToArray();
        if (frozenPublisherPublicKey.Length != 32
            || target.ReplicaId.Length != 32)
            throw new InvalidDataException(
                "Production mailbox capacity target is invalid.");
        var unsigned = new ProductionMailboxCapacityCommand(
            operation, timestamp, expires, RandomNumberGenerator.GetBytes(32),
            cohortId.ToArray(), target.ReplicaId.ToArray(), reservedCount,
            reservedBytes, revision, new byte[64]);
        Validate(unsigned, true);
        var signingBytes = SigningBytes(unsigned);
        var signature = await signer.SignAsync(signingBytes, cancellationToken);
        var signed = unsigned with { PublisherSignature = signature.ToArray() };
        Validate(signed, false);
        if (!PublicKeyAuth.VerifyDetached(
                signature, signingBytes, frozenPublisherPublicKey))
            throw new InvalidDataException(
                "Production mailbox capacity publisher signature is invalid.");
        return Encode(signed);
    }

    internal static byte[] Encode(ProductionMailboxCapacityCommand value)
    {
        Validate(value, false);
        var output = new byte[EncodedLength];
        "PMB1"u8.CopyTo(output); output[4] = 1; output[5] = (byte)value.Operation;
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(8), value.TimestampUnixSeconds);
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(16), value.ExpiresAtUnixSeconds);
        value.Nonce.CopyTo(output.AsSpan(24)); value.CohortId.CopyTo(output.AsSpan(56));
        value.TargetReplicaId.CopyTo(output.AsSpan(88));
        BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(120), value.ReservedClosureCount);
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(124), value.ReservedBytes);
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(132), value.Revision);
        value.PublisherSignature.CopyTo(output.AsSpan(140));
        return output;
    }

    private static byte[] SigningBytes(ProductionMailboxCapacityCommand value)
    {
        var encoded = Encode(value with { PublisherSignature = Enumerable.Repeat((byte)1, 64).ToArray() });
        var output = new byte[Domain.Length + 140];
        Domain.CopyTo(output); encoded.AsSpan(0, 140).CopyTo(output.AsSpan(Domain.Length));
        return output;
    }

    private static void Validate(ProductionMailboxCapacityCommand value, bool allowZero)
    {
        if (value.Operation is not (ProductionMailboxCapacityOperation.ReserveOrRenew
                or ProductionMailboxCapacityOperation.Release)
            || value.TimestampUnixSeconds == 0 || value.ExpiresAtUnixSeconds <= value.TimestampUnixSeconds
            || value.Nonce.Length != 32 || value.Nonce.AsSpan().IndexOfAnyExcept((byte)0) < 0
            || value.CohortId.Length != 32 || value.CohortId.AsSpan().IndexOfAnyExcept((byte)0) < 0
            || value.TargetReplicaId.Length != 32
            || value.TargetReplicaId.AsSpan().IndexOfAnyExcept((byte)0) < 0
            || value.Revision == 0 || value.PublisherSignature.Length != 64
            || !allowZero && value.PublisherSignature.AsSpan().IndexOfAnyExcept((byte)0) < 0
            || value.Operation == ProductionMailboxCapacityOperation.ReserveOrRenew
                && (value.ReservedClosureCount == 0 || value.ReservedBytes == 0)
            || value.Operation == ProductionMailboxCapacityOperation.Release
                && (value.ReservedClosureCount != 0 || value.ReservedBytes != 0))
            throw new InvalidDataException("Production mailbox capacity command is invalid.");
    }
}

public sealed record ProductionMailboxCapacityReceipt(
    ProductionMailboxCapacityOperation Operation,
    ulong TimestampUnixSeconds,
    ulong ExpiresAtUnixSeconds,
    byte[] CohortId,
    byte[] TargetReplicaId,
    uint ReservedClosureCount,
    ulong ReservedBytes,
    uint ConsumedClosureCount,
    ulong ConsumedBytes,
    ulong Revision,
    byte[] CommandSha256,
    byte[] NodeSignature);

internal static class ProductionMailboxCapacityReceiptCodec
{
    private static ReadOnlySpan<byte> Domain => "Deep/PMB2/capacity-receipt/v1"u8;
    internal const int EncodedLength = 248;

    internal static byte[] Encode(ProductionMailboxCapacityReceipt value)
    {
        Validate(value, false);
        return EncodeCore(value);
    }

    internal static byte[] GetSigningBytes(ProductionMailboxCapacityReceipt value)
    {
        Validate(value, true);
        return SigningBytes(EncodeCore(value with { NodeSignature = new byte[64] }));
    }

    internal static ProductionMailboxCapacityReceipt DecodeAndVerify(
        ReadOnlySpan<byte> encoded, ReadOnlySpan<byte> expectedNodePublicKey)
    {
        if (encoded.Length != EncodedLength || !encoded[..4].SequenceEqual("PMB2"u8)
            || encoded[4] != 1 || encoded.Slice(6, 2).IndexOfAnyExcept((byte)0) >= 0
            || encoded.Slice(216, 32).IndexOfAnyExcept((byte)0) >= 0)
            throw new InvalidDataException("Production mailbox capacity receipt is invalid.");
        var value = new ProductionMailboxCapacityReceipt(
            (ProductionMailboxCapacityOperation)encoded[5],
            BinaryPrimitives.ReadUInt64BigEndian(encoded[8..]),
            BinaryPrimitives.ReadUInt64BigEndian(encoded[16..]),
            encoded.Slice(24, 32).ToArray(), encoded.Slice(56, 32).ToArray(),
            BinaryPrimitives.ReadUInt32BigEndian(encoded[88..]),
            BinaryPrimitives.ReadUInt64BigEndian(encoded[92..]),
            BinaryPrimitives.ReadUInt32BigEndian(encoded[100..]),
            BinaryPrimitives.ReadUInt64BigEndian(encoded[104..]),
            BinaryPrimitives.ReadUInt64BigEndian(encoded[112..]),
            encoded.Slice(120, 32).ToArray(), encoded.Slice(152, 64).ToArray());
        Validate(value, false);
        if (expectedNodePublicKey.Length != 32
            || !CryptographicOperations.FixedTimeEquals(
                value.TargetReplicaId, expectedNodePublicKey)
            || !PublicKeyAuth.VerifyDetached(value.NodeSignature,
                SigningBytes(encoded), expectedNodePublicKey.ToArray()))
            throw new InvalidDataException("Production mailbox capacity receipt is invalid.");
        return value;
    }

    private static byte[] EncodeCore(ProductionMailboxCapacityReceipt value)
    {
        var output = new byte[EncodedLength];
        "PMB2"u8.CopyTo(output); output[4] = 1; output[5] = (byte)value.Operation;
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(8), value.TimestampUnixSeconds);
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(16), value.ExpiresAtUnixSeconds);
        value.CohortId.CopyTo(output.AsSpan(24));
        value.TargetReplicaId.CopyTo(output.AsSpan(56));
        BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(88), value.ReservedClosureCount);
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(92), value.ReservedBytes);
        BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(100), value.ConsumedClosureCount);
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(104), value.ConsumedBytes);
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(112), value.Revision);
        value.CommandSha256.CopyTo(output.AsSpan(120));
        value.NodeSignature.CopyTo(output.AsSpan(152));
        return output;
    }

    private static void Validate(
        ProductionMailboxCapacityReceipt value, bool allowZeroSignature)
    {
        if (value.Operation is not (ProductionMailboxCapacityOperation.ReserveOrRenew
                or ProductionMailboxCapacityOperation.Release)
            || value.TimestampUnixSeconds == 0
            || value.ExpiresAtUnixSeconds <= value.TimestampUnixSeconds
            || value.CohortId.Length != 32
            || value.CohortId.AsSpan().IndexOfAnyExcept((byte)0) < 0
            || value.TargetReplicaId.Length != 32
            || value.TargetReplicaId.AsSpan().IndexOfAnyExcept((byte)0) < 0
            || value.CommandSha256.Length != 32
            || value.CommandSha256.AsSpan().IndexOfAnyExcept((byte)0) < 0
            || value.NodeSignature.Length != 64
            || !allowZeroSignature
                && value.NodeSignature.AsSpan().IndexOfAnyExcept((byte)0) < 0
            || value.Revision == 0
            || value.ConsumedClosureCount > value.ReservedClosureCount
            || value.ConsumedBytes > value.ReservedBytes
            || value.Operation == ProductionMailboxCapacityOperation.Release
                && (value.ReservedClosureCount != value.ConsumedClosureCount
                    || value.ReservedBytes != value.ConsumedBytes))
            throw new InvalidDataException(
                "Production mailbox capacity receipt is invalid.");
    }

    private static byte[] SigningBytes(ReadOnlySpan<byte> encoded)
    {
        var output = new byte[Domain.Length + 152];
        Domain.CopyTo(output); encoded[..152].CopyTo(output.AsSpan(Domain.Length));
        return output;
    }
}

internal sealed record ProductionMailboxCapacityReconciliationCommand(
    ulong TimestampUnixSeconds,
    ulong ExpiresAtUnixSeconds,
    byte[] Nonce,
    byte[] CohortId,
    byte[] TargetReplicaId,
    ulong LastKnownRevision,
    byte[] LastCanonicalReceipt,
    byte[] LastReceiptSha256,
    byte[] LastCommandSha256,
    byte[] PublisherSignature);

internal static class ProductionMailboxCapacityReconciliationCommandCodec
{
    private static ReadOnlySpan<byte> Domain =>
        "Deep/PMB3/capacity-reconciliation-command/v1"u8;
    internal const int EncodedLength = 504;

    internal static async ValueTask<byte[]> CreateAsync(
        ulong timestamp,
        ulong expires,
        ReadOnlyMemory<byte> cohortId,
        ProductionMailboxPrepositionTarget target,
        ulong lastKnownRevision,
        ReadOnlyMemory<byte> lastCanonicalReceipt,
        byte[] publisherPublicKey,
        IProductionMailboxClosurePublisherSigner signer,
        CancellationToken cancellationToken)
    {
        var frozenReceipt = lastCanonicalReceipt.ToArray();
        var prior = ProductionMailboxCapacityReceiptCodec.DecodeAndVerify(
            frozenReceipt, target.ReplicaId);
        if (prior.Revision != lastKnownRevision
            || !CryptographicOperations.FixedTimeEquals(prior.CohortId, cohortId.Span)
            || !CryptographicOperations.FixedTimeEquals(
                prior.TargetReplicaId, target.ReplicaId))
            throw new InvalidDataException(
                "Production mailbox capacity reconciliation predecessor is invalid.");
        var unsigned = new ProductionMailboxCapacityReconciliationCommand(
            timestamp, expires, RandomNumberGenerator.GetBytes(32), cohortId.ToArray(),
            target.ReplicaId.ToArray(), lastKnownRevision, frozenReceipt,
            SHA256.HashData(frozenReceipt), prior.CommandSha256.ToArray(), new byte[64]);
        Validate(unsigned, true);
        var signingBytes = GetSigningBytes(unsigned);
        var signature = await signer.SignAsync(signingBytes, cancellationToken);
        var signed = unsigned with { PublisherSignature = signature.ToArray() };
        Validate(signed, false);
        if (publisherPublicKey.Length != 32
            || !PublicKeyAuth.VerifyDetached(
                signed.PublisherSignature, signingBytes, publisherPublicKey.ToArray()))
            throw new InvalidDataException(
                "Production mailbox capacity reconciliation publisher signature is invalid.");
        return Encode(signed);
    }

    internal static ProductionMailboxCapacityReconciliationCommand DecodeAndVerify(
        ReadOnlySpan<byte> encoded,
        ReadOnlySpan<byte> expectedPublisherPublicKey)
    {
        var value = Decode(encoded);
        if (expectedPublisherPublicKey.Length != 32
            || !PublicKeyAuth.VerifyDetached(value.PublisherSignature,
                GetSigningBytes(value), expectedPublisherPublicKey.ToArray()))
            throw new InvalidDataException(
                "Production mailbox capacity reconciliation publisher signature is invalid.");
        return value;
    }

    internal static byte[] Encode(ProductionMailboxCapacityReconciliationCommand value)
    {
        Validate(value, false);
        var output = new byte[EncodedLength];
        "PMB3"u8.CopyTo(output); output[4] = 1;
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(8), value.TimestampUnixSeconds);
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(16), value.ExpiresAtUnixSeconds);
        value.Nonce.CopyTo(output.AsSpan(24)); value.CohortId.CopyTo(output.AsSpan(56));
        value.TargetReplicaId.CopyTo(output.AsSpan(88));
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(120), value.LastKnownRevision);
        value.LastCanonicalReceipt.CopyTo(output.AsSpan(128));
        value.LastReceiptSha256.CopyTo(output.AsSpan(376));
        value.LastCommandSha256.CopyTo(output.AsSpan(408));
        value.PublisherSignature.CopyTo(output.AsSpan(440));
        return output;
    }

    private static ProductionMailboxCapacityReconciliationCommand Decode(
        ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length != EncodedLength || !encoded[..4].SequenceEqual("PMB3"u8)
            || encoded[4] != 1 || encoded.Slice(5, 3).IndexOfAnyExcept((byte)0) >= 0)
            throw new InvalidDataException(
                "Production mailbox capacity reconciliation command is invalid.");
        var value = new ProductionMailboxCapacityReconciliationCommand(
            BinaryPrimitives.ReadUInt64BigEndian(encoded[8..]),
            BinaryPrimitives.ReadUInt64BigEndian(encoded[16..]),
            encoded.Slice(24, 32).ToArray(), encoded.Slice(56, 32).ToArray(),
            encoded.Slice(88, 32).ToArray(),
            BinaryPrimitives.ReadUInt64BigEndian(encoded[120..]),
            encoded.Slice(128, ProductionMailboxCapacityReceiptCodec.EncodedLength).ToArray(),
            encoded.Slice(376, 32).ToArray(), encoded.Slice(408, 32).ToArray(),
            encoded.Slice(440, 64).ToArray());
        Validate(value, false);
        return value;
    }

    private static byte[] GetSigningBytes(
        ProductionMailboxCapacityReconciliationCommand value)
    {
        Validate(value, true);
        var encoded = EncodeCore(value with { PublisherSignature = new byte[64] });
        var output = new byte[Domain.Length + 440];
        Domain.CopyTo(output); encoded.AsSpan(0, 440).CopyTo(output.AsSpan(Domain.Length));
        return output;
    }

    private static byte[] EncodeCore(ProductionMailboxCapacityReconciliationCommand value)
    {
        var output = new byte[EncodedLength];
        "PMB3"u8.CopyTo(output); output[4] = 1;
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(8), value.TimestampUnixSeconds);
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(16), value.ExpiresAtUnixSeconds);
        value.Nonce.CopyTo(output.AsSpan(24)); value.CohortId.CopyTo(output.AsSpan(56));
        value.TargetReplicaId.CopyTo(output.AsSpan(88));
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(120), value.LastKnownRevision);
        value.LastCanonicalReceipt.CopyTo(output.AsSpan(128));
        value.LastReceiptSha256.CopyTo(output.AsSpan(376));
        value.LastCommandSha256.CopyTo(output.AsSpan(408));
        value.PublisherSignature.CopyTo(output.AsSpan(440));
        return output;
    }

    private static void Validate(
        ProductionMailboxCapacityReconciliationCommand value,
        bool allowZeroSignature)
    {
        if (value.TimestampUnixSeconds == 0
            || value.ExpiresAtUnixSeconds <= value.TimestampUnixSeconds
            || value.Nonce.Length != 32
            || value.Nonce.AsSpan().IndexOfAnyExcept((byte)0) < 0
            || value.CohortId.Length != 32
            || value.CohortId.AsSpan().IndexOfAnyExcept((byte)0) < 0
            || value.TargetReplicaId.Length != 32
            || value.TargetReplicaId.AsSpan().IndexOfAnyExcept((byte)0) < 0
            || value.LastKnownRevision == 0
            || value.LastCanonicalReceipt.Length
                != ProductionMailboxCapacityReceiptCodec.EncodedLength
            || value.LastReceiptSha256.Length != 32
            || value.LastReceiptSha256.AsSpan().IndexOfAnyExcept((byte)0) < 0
            || value.LastCommandSha256.Length != 32
            || value.LastCommandSha256.AsSpan().IndexOfAnyExcept((byte)0) < 0
            || value.PublisherSignature.Length != 64
            || !allowZeroSignature
                && value.PublisherSignature.AsSpan().IndexOfAnyExcept((byte)0) < 0)
            throw new InvalidDataException(
                "Production mailbox capacity reconciliation command is invalid.");
        var receipt = ProductionMailboxCapacityReceiptCodec.DecodeAndVerify(
            value.LastCanonicalReceipt, value.TargetReplicaId);
        if (receipt.Revision != value.LastKnownRevision
            || !CryptographicOperations.FixedTimeEquals(receipt.CohortId, value.CohortId)
            || !CryptographicOperations.FixedTimeEquals(
                receipt.TargetReplicaId, value.TargetReplicaId)
            || !CryptographicOperations.FixedTimeEquals(
                receipt.CommandSha256, value.LastCommandSha256)
            || !CryptographicOperations.FixedTimeEquals(
                SHA256.HashData(value.LastCanonicalReceipt), value.LastReceiptSha256))
            throw new InvalidDataException(
                "Production mailbox capacity reconciliation command is invalid.");
    }
}

public enum ProductionMailboxCapacityReconciliationStatus : byte
{
    AbsentTerminal = 1
}

public sealed record ProductionMailboxCapacityReconciliationReceipt(
    ProductionMailboxCapacityReconciliationStatus Status,
    ulong TimestampUnixSeconds,
    ulong ExpiresAtUnixSeconds,
    byte[] CohortId,
    byte[] TargetReplicaId,
    ulong LastKnownRevision,
    byte[] LastReceiptSha256,
    byte[] LastCommandSha256,
    uint AccountedClosureCount,
    ulong AccountedBytes,
    byte[] AuthoritativeStateSha256,
    byte[] NodeSignature);

internal static class ProductionMailboxCapacityReconciliationReceiptCodec
{
    private static ReadOnlySpan<byte> Domain =>
        "Deep/PMB4/capacity-reconciliation-receipt/v1"u8;
    internal const int EncodedLength = 272;

    internal static ProductionMailboxCapacityReconciliationReceipt DecodeAndVerify(
        ReadOnlySpan<byte> encoded,
        ReadOnlySpan<byte> expectedNodePublicKey)
    {
        if (encoded.Length != EncodedLength || !encoded[..4].SequenceEqual("PMB4"u8)
            || encoded[4] != 1 || encoded.Slice(6, 2).IndexOfAnyExcept((byte)0) >= 0
            || encoded.Slice(164, 4).IndexOfAnyExcept((byte)0) >= 0)
            throw new InvalidDataException(
                "Production mailbox capacity reconciliation receipt is invalid.");
        var value = new ProductionMailboxCapacityReconciliationReceipt(
            (ProductionMailboxCapacityReconciliationStatus)encoded[5],
            BinaryPrimitives.ReadUInt64BigEndian(encoded[8..]),
            BinaryPrimitives.ReadUInt64BigEndian(encoded[16..]),
            encoded.Slice(24, 32).ToArray(), encoded.Slice(56, 32).ToArray(),
            BinaryPrimitives.ReadUInt64BigEndian(encoded[88..]),
            encoded.Slice(96, 32).ToArray(), encoded.Slice(128, 32).ToArray(),
            BinaryPrimitives.ReadUInt32BigEndian(encoded[160..]),
            BinaryPrimitives.ReadUInt64BigEndian(encoded[168..]),
            encoded.Slice(176, 32).ToArray(), encoded.Slice(208, 64).ToArray());
        Validate(value, false);
        if (expectedNodePublicKey.Length != 32
            || !CryptographicOperations.FixedTimeEquals(
                value.TargetReplicaId, expectedNodePublicKey)
            || !PublicKeyAuth.VerifyDetached(value.NodeSignature,
                GetSigningBytes(value), expectedNodePublicKey.ToArray()))
            throw new InvalidDataException(
                "Production mailbox capacity reconciliation receipt is invalid.");
        return value;
    }

    internal static byte[] Encode(ProductionMailboxCapacityReconciliationReceipt value)
    {
        Validate(value, false);
        var output = new byte[EncodedLength];
        "PMB4"u8.CopyTo(output); output[4] = 1; output[5] = (byte)value.Status;
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(8), value.TimestampUnixSeconds);
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(16), value.ExpiresAtUnixSeconds);
        value.CohortId.CopyTo(output.AsSpan(24));
        value.TargetReplicaId.CopyTo(output.AsSpan(56));
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(88), value.LastKnownRevision);
        value.LastReceiptSha256.CopyTo(output.AsSpan(96));
        value.LastCommandSha256.CopyTo(output.AsSpan(128));
        BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(160), value.AccountedClosureCount);
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(168), value.AccountedBytes);
        value.AuthoritativeStateSha256.CopyTo(output.AsSpan(176));
        value.NodeSignature.CopyTo(output.AsSpan(208));
        return output;
    }

    internal static byte[] GetSigningBytes(
        ProductionMailboxCapacityReconciliationReceipt value)
    {
        Validate(value, true);
        var encoded = EncodeCore(value with { NodeSignature = new byte[64] });
        var output = new byte[Domain.Length + 208];
        Domain.CopyTo(output); encoded.AsSpan(0, 208).CopyTo(output.AsSpan(Domain.Length));
        return output;
    }

    private static byte[] EncodeCore(ProductionMailboxCapacityReconciliationReceipt value)
    {
        var output = new byte[EncodedLength];
        "PMB4"u8.CopyTo(output); output[4] = 1; output[5] = (byte)value.Status;
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(8), value.TimestampUnixSeconds);
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(16), value.ExpiresAtUnixSeconds);
        value.CohortId.CopyTo(output.AsSpan(24));
        value.TargetReplicaId.CopyTo(output.AsSpan(56));
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(88), value.LastKnownRevision);
        value.LastReceiptSha256.CopyTo(output.AsSpan(96));
        value.LastCommandSha256.CopyTo(output.AsSpan(128));
        BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(160), value.AccountedClosureCount);
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(168), value.AccountedBytes);
        value.AuthoritativeStateSha256.CopyTo(output.AsSpan(176));
        value.NodeSignature.CopyTo(output.AsSpan(208));
        return output;
    }

    private static void Validate(
        ProductionMailboxCapacityReconciliationReceipt value,
        bool allowZeroSignature)
    {
        if (value.Status != ProductionMailboxCapacityReconciliationStatus.AbsentTerminal
            || value.TimestampUnixSeconds == 0
            || value.ExpiresAtUnixSeconds <= value.TimestampUnixSeconds
            || value.CohortId.Length != 32
            || value.CohortId.AsSpan().IndexOfAnyExcept((byte)0) < 0
            || value.TargetReplicaId.Length != 32
            || value.TargetReplicaId.AsSpan().IndexOfAnyExcept((byte)0) < 0
            || value.LastKnownRevision == 0
            || value.LastReceiptSha256.Length != 32
            || value.LastReceiptSha256.AsSpan().IndexOfAnyExcept((byte)0) < 0
            || value.LastCommandSha256.Length != 32
            || value.LastCommandSha256.AsSpan().IndexOfAnyExcept((byte)0) < 0
            || value.AuthoritativeStateSha256.Length != 32
            || value.AuthoritativeStateSha256.AsSpan().IndexOfAnyExcept((byte)0) < 0
            || value.NodeSignature.Length != 64
            || !allowZeroSignature
                && value.NodeSignature.AsSpan().IndexOfAnyExcept((byte)0) < 0)
            throw new InvalidDataException(
                "Production mailbox capacity reconciliation receipt is invalid.");
    }
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
