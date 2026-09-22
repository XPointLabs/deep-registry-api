using System.Collections.Concurrent;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.Registry;
using Sodium;

namespace Deep.Registry.Api.ProductionMailbox;

public sealed record ProductionMailboxContactGrantEvidence(
    string ReplicaId,
    string Signature);

public sealed record ProductionMailboxContactGrantRequest(
    string ExactXmg1,
    ushort ResultCode,
    string ExactRouteClosure,
    ushort RouteDisposition,
    ulong RouteEffectiveExpiresAtUnixSeconds,
    ulong ResultExpiresAtUnixSeconds,
    string NodeId,
    ulong IssuedAtUnixSeconds,
    string Nonce,
    string Signature,
    IReadOnlyList<ProductionMailboxContactGrantEvidence> ReplicaEvidence);

internal sealed class ProductionMailboxContactGrantReplayGuard
{
    private readonly ConcurrentDictionary<string, ulong> accepted =
        new(StringComparer.Ordinal);

    internal bool TryAccept(ReadOnlySpan<byte> nodeId, ReadOnlySpan<byte> nonce, ulong now)
    {
        foreach (var item in accepted)
            if (item.Value <= now) accepted.TryRemove(item.Key, out _);
        return accepted.TryAdd(
            $"{Convert.ToHexString(nodeId)}:{Convert.ToHexString(nonce)}",
            checked(now + 180));
    }
}

internal static class ProductionMailboxContactGrantEndpoint
{
    internal const string Route = "/internal/contact-grants";
    internal const string MediaType =
        "application/vnd.deep.mailbox-contact-grant-result.v1+octet-stream";

    internal static void Map(RouteGroupBuilder group)
    {
        group.MapPost(Route, async (
            ProductionMailboxContactGrantRequest request,
            HttpContext context,
            NodeRegistry registry,
            ProductionMailboxContactGrantReplayGuard replayGuard,
            ProductionMailboxCoordinator coordinator,
            TimeProvider timeProvider,
            CancellationToken cancellationToken) =>
        {
            try
            {
                var exactXmg1 = DecodeBase64Url(request.ExactXmg1, 435, false);
                var exactRoute = DecodeBase64Url(
                    request.ExactRouteClosure,
                    ContactRouteClosureCodec.MaximumEncodedBytes,
                    true);
                var nodeId = DecodeHex(request.NodeId, 32);
                var nonce = DecodeBase64Url(request.Nonce, 32, false);
                var signature = DecodeBase64Url(request.Signature, 64, false);
                var code = (MailboxGrantAcquisitionResultCode)request.ResultCode;
                var now = checked((ulong)timeProvider.GetUtcNow().ToUnixTimeSeconds());
                if (!Enum.IsDefined(code)
                    || request.IssuedAtUnixSeconds > checked(now + 60)
                    || now > checked(request.IssuedAtUnixSeconds + 60)
                    || !ValidDisposition(code, request.RouteDisposition)
                    || !VerifyNode(registry, nodeId, signature,
                        MailboxGrantAuthorityAuthentication.GetSigningBytes(
                            exactXmg1,
                            code,
                            exactRoute,
                            request.ResultExpiresAtUnixSeconds,
                            nodeId,
                            request.IssuedAtUnixSeconds,
                            nonce))
                    || !replayGuard.TryAccept(nodeId, nonce, now))
                    return Results.Unauthorized();

                var xmg1 = ContactCodec.Decode(
                    DeepProtocolIdentifiers.Magic.XMG1,
                    exactXmg1);
                var domain = (MailboxCapabilityDomain)xmg1.Field(6).Span[0];
                var routeHash = code == MailboxGrantAcquisitionResultCode.Success
                    ? SHA256.HashData(exactRoute)
                    : new byte[32];
                var tuple = MailboxGrantRouteEvidenceAuthentication.CreateTuple(
                    SHA256.HashData(exactXmg1),
                    xmg1.Field(3).Span,
                    MailboxGrantCapabilityDigest.Compute(xmg1.Field(4).Span, domain),
                    checked((byte)domain),
                    request.RouteDisposition,
                    routeHash,
                    request.RouteEffectiveExpiresAtUnixSeconds);
                if (!VerifyReplicaEvidence(
                    request.ReplicaEvidence,
                    registry,
                    nodeId,
                    MailboxGrantRouteEvidenceAuthentication.GetSigningBytes(tuple)))
                    return Results.Unauthorized();

                var result = await coordinator.IssueContactGrantAsync(
                    exactXmg1,
                    code,
                    exactRoute,
                    request.ResultExpiresAtUnixSeconds,
                    cancellationToken).ConfigureAwait(false);
                context.Response.Headers.CacheControl = "no-store";
                return Results.Bytes(result, MediaType);
            }
            catch (Exception exception) when (exception is ArgumentException
                or FormatException
                or OverflowException
                or CryptographicException
                or ContactFormatException
                or ProductionMailboxIssueException { Error:
                    ProductionMailboxIssueError.InvalidRequest or
                    ProductionMailboxIssueError.InvalidHolderProof })
            {
                return Results.BadRequest();
            }
            catch (ProductionMailboxIssueException exception) when (
                exception.Error is ProductionMailboxIssueError.IssuerUnavailable
                    or ProductionMailboxIssueError.Revoked)
            {
                return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
            }
        });
    }

    private static bool ValidDisposition(
        MailboxGrantAcquisitionResultCode code,
        ushort disposition) => code switch
        {
            MailboxGrantAcquisitionResultCode.Success => disposition == 1,
            MailboxGrantAcquisitionResultCode.UnknownOrExpired => disposition is 2 or 3,
            MailboxGrantAcquisitionResultCode.Conflict => disposition == 4,
            _ => false,
        };

    private static bool VerifyReplicaEvidence(
        IReadOnlyList<ProductionMailboxContactGrantEvidence>? evidence,
        NodeRegistry registry,
        ReadOnlySpan<byte> forwardingNodeId,
        byte[] signingBytes)
    {
        if (evidence is null || evidence.Count != 2) return false;
        var forwarding = forwardingNodeId.ToArray();
        var verified = new List<byte[]>(2);
        foreach (var item in evidence)
        {
            byte[] replicaId;
            byte[] signature;
            try
            {
                replicaId = DecodeHex(item.ReplicaId, 32);
                signature = DecodeBase64Url(item.Signature, 64, false);
            }
            catch (Exception exception) when (exception is ArgumentException
                or FormatException)
            {
                return false;
            }
            if (verified.Any(value => CryptographicOperations.FixedTimeEquals(
                    value, replicaId))
                || !VerifyNode(registry, replicaId, signature, signingBytes))
                return false;
            verified.Add(replicaId);
        }
        return verified.Any(value => CryptographicOperations.FixedTimeEquals(
            value, forwarding));
    }

    private static bool VerifyNode(
        NodeRegistry registry,
        ReadOnlySpan<byte> nodeId,
        ReadOnlySpan<byte> signature,
        ReadOnlySpan<byte> signingBytes)
    {
        var hex = Convert.ToHexString(nodeId).ToLowerInvariant();
        var node = registry.GetNode(hex);
        if (node is null
            || !string.Equals(node.NodeId, node.Ed25519PublicKey,
                StringComparison.OrdinalIgnoreCase)
            || !string.Equals(node.NodeId, hex, StringComparison.OrdinalIgnoreCase)
            || node.TransportStatus is not
                { Enabled: true, Running: true, Degraded: false, Mocked: false })
            return false;
        try
        {
            return PublicKeyAuth.VerifyDetached(
                signature.ToArray(),
                signingBytes.ToArray(),
                nodeId.ToArray());
        }
        catch (Exception exception) when (exception is ArgumentException
            or CryptographicException)
        {
            return false;
        }
    }

    private static byte[] DecodeHex(string value, int length)
    {
        if (value.Length != length * 2
            || value != value.ToLowerInvariant()
            || value.Any(static character => character is not (>= '0' and <= '9')
                and not (>= 'a' and <= 'f')))
            throw new FormatException("The hexadecimal value is not canonical.");
        var decoded = Convert.FromHexString(value);
        if (decoded.AsSpan().IndexOfAnyExcept((byte)0) < 0)
            throw new FormatException("The hexadecimal value is zero.");
        return decoded;
    }

    private static byte[] DecodeBase64Url(
        string value,
        int maximumLength,
        bool allowEmpty)
    {
        if (allowEmpty && value.Length == 0) return [];
        if (string.IsNullOrWhiteSpace(value) || value.Contains('='))
            throw new FormatException("The base64url value is not canonical.");
        var padded = value.Replace('-', '+').Replace('_', '/');
        padded += new string('=', (4 - padded.Length % 4) % 4);
        var decoded = Convert.FromBase64String(padded);
        if (decoded.Length == 0 || decoded.Length > maximumLength
            || Base64Url(decoded) != value)
            throw new FormatException("The base64url value has an invalid length.");
        return decoded;
    }

    private static string Base64Url(ReadOnlySpan<byte> value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
