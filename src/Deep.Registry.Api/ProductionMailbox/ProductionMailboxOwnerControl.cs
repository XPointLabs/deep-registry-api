using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxTopology;

namespace Deep.Registry.Api.ProductionMailbox;

internal static class ProductionMailboxOwnerControlHostCodec
{
    internal const int EnrollmentRequestLength = 4 + 1 + 16 +
        ProductionMailboxRouteContinuityConstants.CanonicalRouteOriginLkgLength +
        ProductionMailboxRouteAdvertisementConstants.CanonicalCertificateLength +
        ProductionMailboxRouteAuthorizationConstants.CanonicalAdvertisementV2Length +
        ProductionMailboxRouteContinuityConstants.CanonicalDelegationLength;
    internal const int EnrollmentResponseLength = 4 + 1 +
        ProductionMailboxRouteContinuityConstants.CanonicalDelegationAcceptanceLength +
        ProductionMailboxOwnerControlConstants.ResponderCertificateLength +
        ProductionMailboxRouteContinuityConstants.CanonicalRouteOriginLkgLength +
        ProductionMailboxRouteContinuityConstants.CanonicalRouteHistoryCheckpointLength;
    internal const int RevocationRequestLength = 4 + 1 + 16 +
        ProductionMailboxRouteContinuityConstants.CanonicalRevocationLength;

    internal static ProductionMailboxOwnerEnrollmentRequest DecodeEnrollment(
        ReadOnlySpan<byte> body)
    {
        if (body.Length != EnrollmentRequestLength || !body[..4].SequenceEqual("PMGE"u8)
            || body[4] != 1)
            throw new InvalidDataException("Owner enrollment frame is invalid.");
        var owned = body.ToArray();
        var offset = 5;
        return new(Take(16), Take(ProductionMailboxRouteContinuityConstants
                .CanonicalRouteOriginLkgLength),
            Take(ProductionMailboxRouteAdvertisementConstants.CanonicalCertificateLength),
            Take(ProductionMailboxRouteAuthorizationConstants.CanonicalAdvertisementV2Length),
            Take(ProductionMailboxRouteContinuityConstants.CanonicalDelegationLength));

        byte[] Take(int length)
        {
            var result = owned.AsSpan(offset, length).ToArray(); offset += length; return result;
        }
    }

    internal static byte[] EncodeEnrollmentResponse(
        ProductionMailboxRouteContinuityGenesisCommitPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        var result = new byte[EnrollmentResponseLength];
        "PMGR"u8.CopyTo(result); result[4] = 1; var offset = 5;
        Put(plan.CanonicalAcceptance.Span);
        Put(plan.CanonicalOwnerControlResponderCertificate.Span);
        Put(plan.CanonicalEnrolledRouteOriginLkg.Span);
        Put(plan.CanonicalInitialRouteHistoryCheckpoint.Span);
        return result;
        void Put(ReadOnlySpan<byte> value)
        { value.CopyTo(result.AsSpan(offset)); offset += value.Length; }
    }

    internal static void ValidateEnrollmentResponse(ReadOnlySpan<byte> body,
        ProductionMailboxRestoredGenesis restored)
    {
        ArgumentNullException.ThrowIfNull(restored);
        if (body.Length != EnrollmentResponseLength || !body[..4].SequenceEqual("PMGR"u8)
            || body[4] != 1)
            throw new InvalidDataException("Stored owner enrollment response is invalid.");
        var owned = body.ToArray();
        var f = restored.Value.Fields;
        var offset = 5;
        Check(f[14]);
        Check(f[18]);
        Check(f[16]);
        Check(f[20]);
        if (offset != body.Length)
            throw new InvalidDataException("Stored owner enrollment response is split.");
        void Check(ReadOnlySpan<byte> expected)
        {
            if (!owned.AsSpan(offset, expected.Length).SequenceEqual(expected))
                throw new InvalidDataException("Stored owner enrollment response differs from catalog.");
            offset += expected.Length;
        }
    }

    internal static ProductionMailboxOwnerRevocationRequest DecodeRevocation(
        ReadOnlySpan<byte> body)
    {
        if (body.Length != RevocationRequestLength || !body[..4].SequenceEqual("PMRV"u8)
            || body[4] != 1)
            throw new InvalidDataException("Owner revocation frame is invalid.");
        return new(body.Slice(5, 16).ToArray(), body[21..].ToArray());
    }
}

internal sealed record ProductionMailboxOwnerEnrollmentRequest(
    byte[] RequestId, byte[] CanonicalPreDelegationRouteOriginLkg,
    byte[] CanonicalRouteCertificate, byte[] CanonicalRouteAuthorization,
    byte[] CanonicalDelegation)
{
    internal byte[] CanonicalHash()
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("Deep/registry/production-mailbox/owner-enrollment-request/v1"u8);
        hash.AppendData(RequestId); hash.AppendData(CanonicalPreDelegationRouteOriginLkg);
        hash.AppendData(CanonicalRouteCertificate); hash.AppendData(CanonicalRouteAuthorization);
        hash.AppendData(CanonicalDelegation); return hash.GetHashAndReset();
    }
}

internal sealed record ProductionMailboxOwnerRevocationRequest(
    byte[] RequestId, byte[] CanonicalRevocation);

public sealed record ProductionMailboxOwnerControlKeyHandle(
    ReadOnlyMemory<byte> KeyId, ReadOnlyMemory<byte> PublicKey);

public interface IProductionMailboxOwnerControlKeyStore
{
    ValueTask<ProductionMailboxOwnerControlKeyHandle> CreateOrGetAsync(
        ReadOnlyMemory<byte> idempotencyToken, CancellationToken cancellationToken);
    ValueTask<byte[]> SignAsync(ReadOnlyMemory<byte> keyId,
        ReadOnlyMemory<byte> signingBytes, CancellationToken cancellationToken);
    ValueTask<bool> IsHealthyAsync(ReadOnlyMemory<byte> keyId,
        CancellationToken cancellationToken);
    ValueTask<bool> DeleteUncommittedAsync(ReadOnlyMemory<byte> idempotencyToken,
        CancellationToken cancellationToken);
    bool IsSigningEnabled { get; }
}

public interface IProductionMailboxOwnerChannelAuthorizer
{
    ValueTask<byte[]?> GetAuthenticatedOwnerAsync(
        HttpContext context, CancellationToken cancellationToken);
}

public sealed class CertificateProductionMailboxOwnerChannelAuthorizer
    : IProductionMailboxOwnerChannelAuthorizer
{
    public ValueTask<byte[]?> GetAuthenticatedOwnerAsync(
        HttpContext context, CancellationToken cancellationToken)
    {
        if (!context.Request.IsHttps || context.Connection.ClientCertificate is null
            || context.User.Identity?.IsAuthenticated != true)
            return ValueTask.FromResult<byte[]?>(null);
        var value = context.User.FindFirst("deep.mailbox.owner.ed25519")?.Value;
        if (string.IsNullOrWhiteSpace(value)) return ValueTask.FromResult<byte[]?>(null);
        try
        {
            var bytes = Convert.FromHexString(value);
            return ValueTask.FromResult<byte[]?>(bytes.Length == 32 &&
                bytes.AsSpan().IndexOfAnyExcept((byte)0) >= 0 ? bytes : null);
        }
        catch (FormatException) { return ValueTask.FromResult<byte[]?>(null); }
    }
}

internal sealed record ProductionMailboxOwnerEnrollmentPrepareResult(
    ProductionMailboxOwnerEnrollmentStatus Status, ulong AuthoritativeNowUnixSeconds,
    byte[]? CanonicalResponse);

internal enum ProductionMailboxOwnerEnrollmentStatus
{
    Prepared,
    ExactReplay,
    Conflict,
    Revoked,
    CapacityExceeded
}

internal sealed record ProductionMailboxOwnerRequestPrepareResult(
    ProductionMailboxOwnerRequestStatus Status, byte[]? CanonicalHeader,
    byte[]? CanonicalPayload);

internal sealed record ProductionMailboxOwnerNoChangePlanResult(
    ProductionMailboxOwnerRequestStatus Status, ulong IssuedAtUnixSeconds,
    ulong ExpiresAtUnixSeconds);

internal enum ProductionMailboxOwnerRequestStatus
{
    Prepared,
    ExactReplay,
    Conflict,
    Stale,
    Revoked,
    MissingState
}

internal sealed record ProductionMailboxAbandonedOwnerKeyClaim(
    byte[] RouteStateKey, byte[] OperationHash, byte[] KeyToken);

internal interface IProductionMailboxOwnerControlStateStore
{
    ValueTask<ProductionMailboxOwnerEnrollmentPrepareResult> PrepareOwnerEnrollmentAsync(
        ReadOnlyMemory<byte> routeStateKey, ReadOnlyMemory<byte> requestId,
        ReadOnlyMemory<byte> requestHash, ReadOnlyMemory<byte> operationHash,
        ReadOnlyMemory<byte> intentHash, ReadOnlyMemory<byte> sourceArtifactClosureHash,
        ReadOnlyMemory<byte> ownerControlKeyToken,
        ulong nowUnixSeconds,
        CancellationToken cancellationToken);
    ValueTask<ProductionMailboxOwnerEnrollmentStatus> CommitOwnerEnrollmentAsync(
        ReadOnlyMemory<byte> routeStateKey, ReadOnlyMemory<byte> requestId,
        ReadOnlyMemory<byte> requestHash, ReadOnlyMemory<byte> operationHash,
        ReadOnlyMemory<byte> sourceArtifactClosureHash,
        ProductionMailboxRouteContinuityGenesisCommitPlan plan,
        ProductionMailboxOwnerControlKeyHandle key,
        ReadOnlyMemory<byte> canonicalResponse, ulong nowUnixSeconds,
        CancellationToken cancellationToken);
    ValueTask<ProductionMailboxOwnerRequestPrepareResult> PrepareNoChangeAsync(
        ReadOnlyMemory<byte> routeStateKey, ReadOnlyMemory<byte> activeScope,
        VerifiedProductionMailboxOwnerControlRequest request,
        ulong nowUnixSeconds, CancellationToken cancellationToken);
    ValueTask<ProductionMailboxOwnerNoChangePlanResult> PlanNoChangeAsync(
        ReadOnlyMemory<byte> routeStateKey, ReadOnlyMemory<byte> activeScope,
        VerifiedProductionMailboxOwnerControlRequest request,
        ulong nowUnixSeconds, CancellationToken cancellationToken);
    ValueTask<ProductionMailboxOwnerRequestStatus> RecordNoChangeAsync(
        ReadOnlyMemory<byte> routeStateKey, ReadOnlyMemory<byte> activeScope,
        VerifiedProductionMailboxOwnerControlRequest request,
        VerifiedProductionMailboxOwnerControlResponse response,
        ulong nowUnixSeconds, CancellationToken cancellationToken);
    ValueTask<ProductionMailboxOwnerRequestPrepareResult> AuthorizeDeliveryAsync(
        ReadOnlyMemory<byte> routeStateKey, ReadOnlyMemory<byte> activeScope,
        ReadOnlyMemory<byte> requestHash, ulong nowUnixSeconds,
        CancellationToken cancellationToken);
    ValueTask<ProductionMailboxRouteContinuityCommitResult> CommitOwnerRevocationAndFenceAsync(
        ReadOnlyMemory<byte> routeStateKey, ReadOnlyMemory<byte> requestId,
        VerifiedProductionMailboxRouteContinuityRevocation revocation,
        CancellationToken cancellationToken);
    ValueTask<ProductionMailboxOwnerControlKeyHandle?> GetOwnerControlKeyAsync(
        ReadOnlyMemory<byte> routeStateKey, CancellationToken cancellationToken);
    ValueTask<ProductionMailboxAbandonedOwnerKeyClaim?> ClaimAbandonedOwnerKeyAsync(
        ulong nowUnixSeconds, ulong leaseUntilUnixSeconds,
        CancellationToken cancellationToken);
    ValueTask CompleteAbandonedOwnerKeyAsync(ReadOnlyMemory<byte> routeStateKey,
        ReadOnlyMemory<byte> operationHash,
        ReadOnlyMemory<byte> keyToken, CancellationToken cancellationToken);
}

internal sealed class ProductionMailboxOwnerControlService(
    IProductionMailboxRouteContinuityStateStore continuity,
    IProductionMailboxOwnerControlStateStore state,
    ProductionMailboxArtifactProvider artifacts,
    IEd25519ExternalSigner issuerSigner,
    IProductionMailboxOwnerControlKeyStore ownerKeys,
    TimeProvider timeProvider,
    ReadOnlyMemory<byte> routeStateHmacKey,
    uint clockSkewSeconds)
{
    private readonly byte[] routeKey = Freeze(routeStateHmacKey, 32, "route-state HMAC key");

    internal async ValueTask<byte[]> EnrollAsync(
        ReadOnlyMemory<byte> canonicalRequest, ReadOnlyMemory<byte> authenticatedOwner,
        CancellationToken cancellationToken)
    {
        var owner = Freeze(authenticatedOwner, 32, "authenticated owner");
        if (canonicalRequest.Length != ProductionMailboxOwnerControlHostCodec.EnrollmentRequestLength)
            throw new InvalidDataException("Owner enrollment request length is invalid.");
        var request = ProductionMailboxOwnerControlHostCodec.DecodeEnrollment(canonicalRequest.Span);
        var now = Now(); var current = artifacts.Current;
        var sourceArtifactClosureHash = ArtifactClosureHash(current);
        var certificate = ProductionMailboxRouteCertificateVerifier.Verify(
            request.CanonicalRouteCertificate, current.Authority, now, clockSkewSeconds,
            new SodiumProductionMailboxRouteSignatureVerifier());
        var decodedAuthorization = ProductionMailboxRouteAuthorizationCodec
            .DecodeAdvertisementV2(request.CanonicalRouteAuthorization);
        var routeDomain = ProductionMailboxRouteAdvertisementCodec.ComputeRouteDomainHash(
            decodedAuthorization.Certificate);
        var authorization = ProductionMailboxRouteAuthorizationVerifier.VerifyOwnerAuthorization(
            request.CanonicalRouteAuthorization, current.Authority,
            new ProductionMailboxOwnerRouteAuthorizationVerificationContext
            {
                ExpectedNetworkId = current.Authority.Authority.NetworkId,
                ExpectedRouteDomainHash = routeDomain,
                ExpectedPredecessorKind = decodedAuthorization.PredecessorAuthorizationKind,
                ExpectedPredecessorHash = decodedAuthorization
                    .PredecessorCanonicalRouteAuthorizationHash,
                ExpectedPredecessorSequence = decodedAuthorization
                    .PredecessorRouteAuthorizationSequence,
                NowUnixSeconds = now,
                ClockSkewSeconds = clockSkewSeconds
            });
        var intent = ProductionMailboxRouteIssuerAuthoring.VerifyGenesisIntent(
            request.CanonicalDelegation, request.CanonicalPreDelegationRouteOriginLkg,
            current.Authority, current.Revocation, certificate, authorization, now,
            clockSkewSeconds);
        if (!CryptographicOperations.FixedTimeEquals(
                intent.MailboxOwnerEd25519PublicKey.Span, owner))
            throw new UnauthorizedAccessException("Owner enrollment principal differs from RCD1.");
        var routeStateKey = Derive("route-state"u8, owner,
            intent.RouteDomainHash.ToArray());
        var requestHash = request.CanonicalHash();
        var keyToken = Derive("ocr-key"u8, intent.CanonicalDelegationHash.ToArray(),
            intent.MailboxOwnerEd25519PublicKey.ToArray());
        if (!ownerKeys.IsSigningEnabled)
            throw new InvalidOperationException("Owner-control signing is disabled.");
        var prepared = await state.PrepareOwnerEnrollmentAsync(routeStateKey, request.RequestId,
            requestHash, intent.CanonicalDelegationHash, intent.IntentHash,
            sourceArtifactClosureHash, keyToken, now,
            cancellationToken);
        if (prepared.Status == ProductionMailboxOwnerEnrollmentStatus.ExactReplay)
        {
            var replayKey = await state.GetOwnerControlKeyAsync(routeStateKey, cancellationToken)
                ?? throw new InvalidDataException("Owner-control key identity is missing.");
            if (!ownerKeys.IsSigningEnabled
                || !await ownerKeys.IsHealthyAsync(replayKey.KeyId, cancellationToken))
                throw new InvalidOperationException("Owner-control replay is disabled.");
            return prepared.CanonicalResponse!.ToArray();
        }
        if (prepared.Status != ProductionMailboxOwnerEnrollmentStatus.Prepared)
            throw new InvalidOperationException("Owner enrollment conflicts with durable state.");
        var key = await ownerKeys.CreateOrGetAsync(keyToken, cancellationToken);
        ValidateKey(key);
        var acceptedAt = prepared.AuthoritativeNowUnixSeconds;
        var ocrExpiry = Math.Min(
            ProductionMailboxRouteContinuityCodec.DecodeDelegation(
                request.CanonicalDelegation).ExpiresAtUnixSeconds,
            checked(acceptedAt + ProductionMailboxOwnerControlConstants
                .MaximumResponderCertificateLifetimeSeconds));
        var plan = await ProductionMailboxRouteIssuerAuthoring.AuthorGenesisAsync(intent,
            acceptedAt, Now(), key.PublicKey, ocrExpiry,
            async (signingRequest, destination, token) =>
                await SignIntoAsync(issuerSigner, signingRequest.SigningBytes,
                    destination, token),
            async (signingRequest, destination, token) =>
                await SignIntoAsync(issuerSigner, signingRequest.SigningBytes,
                    destination, token), cancellationToken);
        var response = ProductionMailboxOwnerControlHostCodec.EncodeEnrollmentResponse(plan);
        if (!ownerKeys.IsSigningEnabled || !await ownerKeys.IsHealthyAsync(key.KeyId,
                cancellationToken))
            throw new InvalidOperationException("Owner-control signer became unavailable.");
        var committed = await state.CommitOwnerEnrollmentAsync(routeStateKey, request.RequestId,
            requestHash, intent.CanonicalDelegationHash, sourceArtifactClosureHash,
            plan, key, response, Now(), cancellationToken);
        if (committed is not (ProductionMailboxOwnerEnrollmentStatus.Prepared or
            ProductionMailboxOwnerEnrollmentStatus.ExactReplay))
            throw new InvalidOperationException("Owner enrollment final CAS failed.");
        var restored = await continuity.GetRestoredGenesisAsync(routeStateKey, cancellationToken)
            ?? throw new InvalidDataException("Committed owner enrollment cannot be restored.");
        if (!CryptographicOperations.FixedTimeEquals(restored.Value.PlanHash, plan.PlanHash.Span))
            throw new InvalidDataException("Committed owner enrollment plan differs after reread.");
        var durable = await state.PrepareOwnerEnrollmentAsync(routeStateKey, request.RequestId,
            requestHash, intent.CanonicalDelegationHash, intent.IntentHash,
            sourceArtifactClosureHash, keyToken, Now(),
            cancellationToken);
        if (durable.Status != ProductionMailboxOwnerEnrollmentStatus.ExactReplay)
            throw new InvalidDataException("Committed owner enrollment response is unavailable.");
        if (!ownerKeys.IsSigningEnabled || !await ownerKeys.IsHealthyAsync(key.KeyId,
                cancellationToken))
            throw new InvalidOperationException("Owner-control replay is disabled.");
        return durable.CanonicalResponse!.ToArray();
    }

    internal async ValueTask<(byte[] Header, byte[] Payload)> NoChangeAsync(
        ReadOnlyMemory<byte> canonicalRequest, ReadOnlyMemory<byte> authenticatedOwner,
        CancellationToken cancellationToken)
    {
        var owner = Freeze(authenticatedOwner, 32, "authenticated owner");
        if (canonicalRequest.Length != ProductionMailboxOwnerControlConstants.RequestLength)
            throw new InvalidDataException("PMCQ1 request length is invalid.");
        var decoded = ProductionMailboxOwnerControlTransportCodec.DecodeRequest(
            canonicalRequest.Span);
        if (!CryptographicOperations.FixedTimeEquals(
                decoded.MailboxOwnerEd25519PublicKey.Span, owner))
            throw new UnauthorizedAccessException("PMCQ1 principal differs from owner.");
        var routeStateKey = Derive("route-state"u8, owner,
            decoded.RouteDomainHash.ToArray());
        var restored = await continuity.GetRestoredGenesisAsync(routeStateKey, cancellationToken)
            ?? throw new InvalidOperationException("Owner continuity enrollment is missing.");
        var verified = ProductionMailboxOwnerControlTransportCodec.VerifyRequest(
            canonicalRequest.Span, restored.Anchor, restored.Cursor, Now(), clockSkewSeconds);
        var activeScope = Derive("active-scope"u8, owner,
            decoded.RouteDomainHash.ToArray(),
            decoded.CurrentRouteHistoryCheckpointHash.ToArray(),
            [(byte)ProductionMailboxOwnerControlOperation.AdvanceOrFinalize]);
        var prepared = await state.PrepareNoChangeAsync(routeStateKey, activeScope, verified,
            Now(), cancellationToken);
        var storedKey = await state.GetOwnerControlKeyAsync(routeStateKey, cancellationToken)
            ?? throw new InvalidDataException("Owner-control key identity is missing.");
        var ocr = ProductionMailboxOwnerControlTransportCodec.DecodeResponderCertificate(
            restored.EnrollmentContext.CanonicalOwnerControlResponderCertificate.Span);
        if (!CryptographicOperations.FixedTimeEquals(
                storedKey.PublicKey.Span, ocr.ResponderEd25519PublicKey.Span))
            throw new InvalidDataException("Owner-control key identity is split.");
        var keyId = storedKey.KeyId;
        if (!ownerKeys.IsSigningEnabled || !await ownerKeys.IsHealthyAsync(keyId, cancellationToken))
            throw new InvalidOperationException("Owner-control signer is unavailable.");
        if (prepared.Status == ProductionMailboxOwnerRequestStatus.ExactReplay)
        {
            return await FinalizeNoChangeDeliveryAsync(routeStateKey, activeScope, verified,
                keyId, cancellationToken);
        }
        if (prepared.Status != ProductionMailboxOwnerRequestStatus.Prepared)
            throw new InvalidOperationException("PMCQ1 durable request conflicts.");
        var plan = await state.PlanNoChangeAsync(routeStateKey, activeScope, verified,
            Now(), cancellationToken);
        if (plan.Status != ProductionMailboxOwnerRequestStatus.Prepared)
            throw new InvalidOperationException("PMCR1 durable response plan CAS failed.");
        var response = await ProductionMailboxOwnerControlTransportCodec.AuthorNoChangeResponseAsync(
            verified, restored.Anchor, plan.IssuedAtUnixSeconds, plan.ExpiresAtUnixSeconds,
            async (signingRequest, destination, token) => await SignIntoAsync(
                ownerKeys, keyId, signingRequest.SigningBytes, destination, token),
            cancellationToken);
        var recorded = await state.RecordNoChangeAsync(routeStateKey, activeScope, verified,
            response, Now(), cancellationToken);
        if (recorded is not (ProductionMailboxOwnerRequestStatus.Prepared or
            ProductionMailboxOwnerRequestStatus.ExactReplay))
            throw new InvalidOperationException("PMCR1 durable response CAS failed.");
        return await FinalizeNoChangeDeliveryAsync(routeStateKey, activeScope, verified,
            keyId, cancellationToken);
    }

    internal async ValueTask RevokeAsync(
        ReadOnlyMemory<byte> canonicalRequest, ReadOnlyMemory<byte> authenticatedOwner,
        CancellationToken cancellationToken)
    {
        var owner = Freeze(authenticatedOwner, 32, "authenticated owner");
        var request = ProductionMailboxOwnerControlHostCodec.DecodeRevocation(
            canonicalRequest.Span);
        var decoded = ProductionMailboxRouteContinuityCodec.DecodeRevocation(
            request.CanonicalRevocation);
        var routeStateKey = Derive("route-state"u8, owner,
            decoded.RouteDomainHash.ToArray());
        var restored = await continuity.GetRestoredGenesisAsync(routeStateKey, cancellationToken)
            ?? throw new InvalidOperationException("Owner continuity enrollment is missing.");
        if (!CryptographicOperations.FixedTimeEquals(
                restored.EnrollmentContext.MailboxOwnerEd25519PublicKey.Span, owner))
            throw new UnauthorizedAccessException("RCR1 principal differs from owner.");
        var verified = ProductionMailboxRouteContinuityVerifier.VerifyOwnerRevocation(
            request.CanonicalRevocation, restored.Enrollment, Now(), clockSkewSeconds);
        var result = await state.CommitOwnerRevocationAndFenceAsync(routeStateKey,
            request.RequestId, verified, cancellationToken);
        if (result.Status is not (ProductionMailboxRouteContinuityCommitStatus.Accepted or
            ProductionMailboxRouteContinuityCommitStatus.ExactReplay))
            throw new InvalidOperationException("RCR1 durable CAS failed.");
    }

    private ulong Now() => checked((ulong)timeProvider.GetUtcNow().ToUnixTimeSeconds());

    private async ValueTask<(byte[] Header, byte[] Payload)> FinalizeNoChangeDeliveryAsync(
        ReadOnlyMemory<byte> routeStateKey, ReadOnlyMemory<byte> activeScope,
        VerifiedProductionMailboxOwnerControlRequest verified, ReadOnlyMemory<byte> keyId,
        CancellationToken cancellationToken)
    {
        var authorized = await state.AuthorizeDeliveryAsync(routeStateKey, activeScope,
            verified.CanonicalHash, Now(), cancellationToken);
        if (authorized.Status != ProductionMailboxOwnerRequestStatus.ExactReplay)
            throw new InvalidOperationException("PMCR1 delivery authorization failed.");
        var restored = await continuity.GetRestoredGenesisAsync(routeStateKey, cancellationToken)
            ?? throw new InvalidDataException("Owner continuity enrollment disappeared.");
        var durable = await state.AuthorizeDeliveryAsync(routeStateKey, activeScope,
            verified.CanonicalHash, Now(), cancellationToken);
        if (durable.Status != ProductionMailboxOwnerRequestStatus.ExactReplay)
            throw new InvalidOperationException("PMCR1 delivery authorization changed on reread.");
        var storedKey = await state.GetOwnerControlKeyAsync(routeStateKey, cancellationToken)
            ?? throw new InvalidDataException("Owner-control key identity disappeared.");
        var ocr = ProductionMailboxOwnerControlTransportCodec.DecodeResponderCertificate(
            restored.EnrollmentContext.CanonicalOwnerControlResponderCertificate.Span);
        if (!CryptographicOperations.FixedTimeEquals(storedKey.KeyId.Span, keyId.Span)
            || !CryptographicOperations.FixedTimeEquals(storedKey.PublicKey.Span,
                ocr.ResponderEd25519PublicKey.Span))
            throw new InvalidDataException("Owner-control key identity changed before delivery.");
        var reread = ProductionMailboxOwnerControlTransportCodec.VerifyResponse(
            durable.CanonicalHeader!, durable.CanonicalPayload!, verified,
            restored.Anchor, Now(), clockSkewSeconds);
        if (!ownerKeys.IsSigningEnabled || !await ownerKeys.IsHealthyAsync(keyId,
                cancellationToken))
            throw new InvalidOperationException("Owner-control delivery is disabled.");
        return (reread.CanonicalHeader.ToArray(), reread.CanonicalPayload.ToArray());
    }

    private static byte[] ArtifactClosureHash(ProductionMailboxArtifacts snapshot)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("Deep/production-mailbox/challenge-artifact-closure/v1"u8);
        hash.AppendData(snapshot.AuthoritySha256);
        hash.AppendData(snapshot.RevocationSha256);
        hash.AppendData(snapshot.TopologySha256);
        return hash.GetHashAndReset();
    }

    private byte[] Derive(ReadOnlySpan<byte> domain, params byte[][] values)
    {
        using var hmac = new HMACSHA256(routeKey);
        hmac.TransformBlock(domain.ToArray(), 0, domain.Length, null, 0);
        Span<byte> length = stackalloc byte[4];
        foreach (var value in values)
        {
            BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)value.Length));
            hmac.TransformBlock(length.ToArray(), 0, 4, null, 0);
            hmac.TransformBlock(value.ToArray(), 0, value.Length, null, 0);
        }
        hmac.TransformFinalBlock([], 0, 0);
        return hmac.Hash ?? throw new CryptographicException("Route-state derivation failed.");
    }

    private static byte[] Freeze(ReadOnlyMemory<byte> value, int length, string name)
    {
        if (value.Length != length || value.Span.IndexOfAnyExcept((byte)0) < 0)
            throw new InvalidDataException($"{name} is invalid.");
        return value.ToArray();
    }

    private static void ValidateKey(ProductionMailboxOwnerControlKeyHandle value)
    {
        ArgumentNullException.ThrowIfNull(value);
        _ = Freeze(value.KeyId, 32, "OCR key ID");
        _ = Freeze(value.PublicKey, 32, "OCR public key");
    }

    private static async ValueTask<int> SignIntoAsync(
        IEd25519ExternalSigner signer, ReadOnlyMemory<byte> signingBytes,
        Memory<byte> destination, CancellationToken cancellationToken)
    {
        var signature = await signer.SignAsync(signingBytes.ToArray(), cancellationToken);
        if (signature.Length != 64) return signature.Length;
        signature.CopyTo(destination); return signature.Length;
    }

    private static async ValueTask<int> SignIntoAsync(
        IProductionMailboxOwnerControlKeyStore signer, ReadOnlyMemory<byte> keyId,
        ReadOnlyMemory<byte> signingBytes, Memory<byte> destination,
        CancellationToken cancellationToken)
    {
        var signature = await signer.SignAsync(keyId.ToArray(), signingBytes.ToArray(),
            cancellationToken);
        if (signature.Length != 64) return signature.Length;
        signature.CopyTo(destination); return signature.Length;
    }
}

internal sealed class ProductionMailboxOwnerKeyCleanupService(
    IProductionMailboxOwnerControlStateStore state,
    IProductionMailboxOwnerControlKeyStore keys,
    TimeProvider timeProvider,
    Microsoft.Extensions.Options.IOptions<ProductionMailboxOptions> options,
    ILogger<ProductionMailboxOwnerKeyCleanupService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var limit = Math.Clamp(options.Value.MaximumOwnerControlGcBatch, 1, 4096);
                for (var index = 0; index < limit; index++)
                {
                    var now = checked((ulong)timeProvider.GetUtcNow().ToUnixTimeSeconds());
                    var claim = await state.ClaimAbandonedOwnerKeyAsync(now,
                        checked(now + 60), stoppingToken);
                    if (claim is null) break;
                    if (!await keys.DeleteUncommittedAsync(claim.KeyToken, stoppingToken))
                        throw new IOException("OCR HSM rejected abandoned-key cleanup.");
                    await state.CompleteAbandonedOwnerKeyAsync(claim.RouteStateKey,
                        claim.OperationHash, claim.KeyToken, stoppingToken);
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            { break; }
            catch (Exception exception) when (exception is IOException
                or InvalidDataException or CryptographicException or InvalidOperationException)
            {
                logger.LogWarning("Owner-control abandoned-key cleanup failed closed: {Type}",
                    exception.GetType().Name);
            }
            await Task.Delay(TimeSpan.FromSeconds(30), timeProvider, stoppingToken);
        }
    }
}

internal sealed class ProductionMailboxOwnerControlRateGate(
    TimeProvider timeProvider, ReadOnlyMemory<byte> key, int maximum, uint windowSeconds)
{
    private readonly byte[] hmacKey = key.ToArray();
    private readonly object sync = new();
    private readonly Dictionary<string, Queue<long>> windows = new(StringComparer.Ordinal);

    internal bool TryAcquire(ReadOnlySpan<byte> owner)
    {
        if (owner.Length != 32 || maximum is < 1 or > 4096 || windowSeconds is 0 or > 3600)
            return false;
        using var hmac = new HMACSHA256(hmacKey);
        var opaque = Convert.ToHexString(hmac.ComputeHash(owner.ToArray()));
        var now = timeProvider.GetUtcNow().ToUnixTimeSeconds();
        lock (sync)
        {
            if (!windows.TryGetValue(opaque, out var values))
                windows.Add(opaque, values = new Queue<long>());
            var floor = now - windowSeconds;
            while (values.TryPeek(out var value) && value <= floor) values.Dequeue();
            if (values.Count >= maximum) return false;
            values.Enqueue(now); return true;
        }
    }
}
