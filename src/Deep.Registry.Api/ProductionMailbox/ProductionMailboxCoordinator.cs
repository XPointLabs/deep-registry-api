using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Deep.Protocol.DeepExtension.MailboxAuthority;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.MailboxTopology;
using Microsoft.Extensions.Options;

namespace Deep.Registry.Api.ProductionMailbox;

public enum ProductionMailboxIssueError
{
    InvalidRequest,
    InvalidHolderProof,
    InvalidChallenge,
    RateLimited,
    Revoked,
    InvalidEntitlement,
    RouteAdvertisementRequired,
    IssuerUnavailable
}

public sealed class ProductionMailboxIssueException(
    ProductionMailboxIssueError error,
    string message) : Exception(message)
{
    public ProductionMailboxIssueError Error { get; } = error;
}

public sealed class ProductionMailboxCoordinator
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly ProductionMailboxOptions options;
    private readonly ProductionMailboxArtifacts artifacts;
    private readonly IEd25519ExternalSigner signer;
    private readonly IProductionMailboxStateStore state;
    private readonly TimeProvider timeProvider;
    private readonly ProductionMailboxMetrics metrics;

    public ProductionMailboxCoordinator(
        IOptions<ProductionMailboxOptions> options,
        ProductionMailboxArtifacts artifacts,
        IEd25519ExternalSigner signer,
        IProductionMailboxStateStore state,
        TimeProvider timeProvider,
        ProductionMailboxMetrics metrics)
    {
        this.options = options.Value;
        this.artifacts = artifacts;
        this.signer = signer;
        this.state = state;
        this.timeProvider = timeProvider;
        this.metrics = metrics;
        ValidateOptions(this.options);
    }

    public async ValueTask<ProductionMailboxChallengeResponse> CreateChallengeAsync(
        CancellationToken cancellationToken)
    {
        EnsureFresh();
        var now = Now();
        var challenge = await state.CreateChallengeAsync(
            now,
            checked(now + options.ChallengeLifetimeSeconds),
            options.MaximumChallengesPerWindow,
            now > options.ChallengeWindowSeconds ? now - options.ChallengeWindowSeconds : 0,
            cancellationToken);
        if (challenge is null)
        {
            metrics.ChallengeRejected();
            throw Error(ProductionMailboxIssueError.RateLimited, "Anonymous challenge capacity is exhausted.");
        }
        metrics.ChallengeCreated();
        return new(
            Base64Url(challenge.ChallengeId),
            Base64Url(challenge.Challenge),
            options.ProofOfWorkLeadingZeroBits,
            challenge.ExpiresAtUnixSeconds);
    }

    public async ValueTask<ProductionMailboxCredentialBundle> IssueAsync(
        ProductionMailboxIssueRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        try
        {
            var holder = Decode(request.HolderEd25519PublicKey, 32, "holder key");
            var owner = Decode(request.MailboxOwnerEd25519PublicKey, 32, "mailbox owner key");
            if (!Enum.IsDefined(request.Intent))
                throw Error(ProductionMailboxIssueError.InvalidRequest, "Issuance intent is unsupported.");
            if (request.Intent == ProductionMailboxIssuanceIntent.PeerDeposit)
                throw Error(ProductionMailboxIssueError.RouteAdvertisementRequired,
                    "Peer deposit requires a verified production mailbox route advertisement.");
            var suppliedMailboxId = DecodeOptional(request.BlindedMailboxId, 32, "blinded mailbox ID");
            var suppliedPlacementId = DecodeOptional(request.BlindedPlacementId, 32, "blinded placement ID");
            var suppliedSelection = DecodeOptional(request.SelectionInputCommitment, 32, "selection commitment");
            var signingCertificate = Decode(request.SigningCertificateSha256, 32, "signing certificate hash");
            var buildArtifact = Decode(request.BuildArtifactSha256, 32, "build artifact hash");
            var idempotencyKey = Decode(request.IdempotencyKey, 32, "idempotency key");
            var entitlementCommitment = DecodeFixedAllowZero(
                request.EntitlementCommitment, 32, "entitlement commitment");
            if (!string.IsNullOrEmpty(request.OpaqueEntitlement) || !IsZero(entitlementCommitment))
                throw Error(ProductionMailboxIssueError.InvalidEntitlement,
                    "Paid cloud limits are unavailable until node-enforced quota authorization is active.");
            EnsureFresh();
            var challengeId = Decode(request.ChallengeId, 16, "challenge ID");
            var challenge = Decode(request.Challenge, 32, "challenge");
            VerifyProofOfWork(challengeId, challenge, request.ProofOfWorkNonce);
            var proofInput = new ProductionMailboxHolderProofInput
            {
                Intent = request.Intent,
                Platform = request.Platform,
                NetworkId = artifacts.Authority.Authority.NetworkId,
                CanonicalAuthorityHash = artifacts.AuthoritySha256,
                HolderEd25519PublicKey = holder,
                MailboxOwnerEd25519PublicKey = owner,
                BlindedMailboxId = suppliedMailboxId,
                BlindedPlacementId = suppliedPlacementId,
                SelectionInputCommitment = suppliedSelection,
                SigningCertificateSha256 = signingCertificate,
                BuildArtifactSha256 = buildArtifact,
                IdempotencyKey = idempotencyKey,
                EntitlementCommitment = entitlementCommitment,
                ChallengeId = challengeId,
                Challenge = challenge,
                ProofOfWorkNonce = request.ProofOfWorkNonce
            };
            VerifyHolderProof(proofInput, request.HolderProofSignature, false);
            if (request.Intent == ProductionMailboxIssuanceIntent.LocalOwner)
                VerifyHolderProof(proofInput, request.OwnerProofSignature, true);
            else if (!string.IsNullOrEmpty(request.OwnerProofSignature))
                throw Error(ProductionMailboxIssueError.InvalidRequest, "Peer deposit must not carry owner authorization.");
            var expectedIdempotencyKey = ComputeIdempotencyKey(
                holder, owner, suppliedMailboxId, suppliedPlacementId, suppliedSelection,
                request.Intent, request.Platform, signingCertificate, buildArtifact,
                entitlementCommitment);
            RequireFixed(idempotencyKey, expectedIdempotencyKey,
                ProductionMailboxIssueError.InvalidRequest,
                "Idempotency key does not match the canonical issuance policy.");
            var holderHash = DomainHash("Deep/production-mailbox/revoked-holder/v1", holder);
            var ownerHash = DomainHash("Deep/production-mailbox/revoked-holder/v1", owner);
            if (await state.IsHolderRevokedAsync(holderHash, cancellationToken) ||
                await state.IsHolderRevokedAsync(ownerHash, cancellationToken))
                throw Error(ProductionMailboxIssueError.Revoked, "Holder or mailbox owner is revoked.");
            var route = await DeriveOwnerRouteAsync(owner, cancellationToken);
            if (request.Intent == ProductionMailboxIssuanceIntent.PeerDeposit &&
                (IsZero(suppliedMailboxId) || IsZero(suppliedPlacementId) || IsZero(suppliedSelection)))
                throw Error(ProductionMailboxIssueError.InvalidRequest, "Peer deposit requires the recipient's complete public route.");
            if (!IsZero(suppliedMailboxId)) RequireFixed(suppliedMailboxId, route.MailboxId,
                ProductionMailboxIssueError.InvalidRequest, "Blinded mailbox ID is not owned by the named mailbox owner.");
            if (!IsZero(suppliedPlacementId)) RequireFixed(suppliedPlacementId, route.PlacementId,
                ProductionMailboxIssueError.InvalidRequest, "Blinded placement ID is not owned by the named mailbox owner.");
            if (!IsZero(suppliedSelection)) RequireFixed(suppliedSelection, route.SelectionInputCommitment,
                ProductionMailboxIssueError.InvalidRequest, "Selection commitment is not owned by the named mailbox owner.");
            var limits = BaseLimits();
            var issued = await state.ConsumeChallengeAndIssueAsync(
                challengeId, challenge, Now(), artifacts.Topology.Snapshot.CurrentEpoch.NotAfterUnixSeconds,
                idempotencyKey,
                token => CreateBundleBytesAsync(holder, owner, request.Intent, route.MailboxId,
                    new BlindedPlacementId(route.PlacementId), route.SelectionInputCommitment,
                    idempotencyKey, limits, token), cancellationToken);
            if (issued is null)
                throw Error(ProductionMailboxIssueError.InvalidChallenge, "Challenge is expired, mismatched or already consumed.");
            if (issued.Replayed) metrics.BundleReplayed();
            else metrics.BundleIssued();
            return JsonSerializer.Deserialize<ProductionMailboxCredentialBundle>(issued.CanonicalResponse, JsonOptions)
                ?? throw Error(ProductionMailboxIssueError.IssuerUnavailable, "Stored issuance response is invalid.");
        }
        catch (ProductionMailboxIssueException)
        {
            metrics.RequestRejected();
            throw;
        }
        catch (Exception exception) when (exception is ArgumentException or FormatException or OverflowException)
        {
            metrics.RequestRejected();
            throw Error(ProductionMailboxIssueError.InvalidRequest, "Issuance request is malformed.");
        }
    }

    public async ValueTask RevokeHolderAsync(
        ReadOnlyMemory<byte> holderPublicKey,
        CancellationToken cancellationToken)
    {
        if (holderPublicKey.Length != 32 || holderPublicKey.Span.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("Holder key is invalid.", nameof(holderPublicKey));
        await state.RevokeHolderAsync(
            DomainHash("Deep/production-mailbox/revoked-holder/v1", holderPublicKey.ToArray()),
            Now(), cancellationToken);
        metrics.RevocationApplied();
    }

    public ProductionMailboxRuntimeCounters GetCounters() => metrics.Snapshot();

    private async ValueTask<byte[]> CreateBundleBytesAsync(
        byte[] holder,
        byte[] owner,
        ProductionMailboxIssuanceIntent intent,
        byte[] mailboxId,
        BlindedPlacementId placementId,
        byte[] selectionCommitment,
        byte[] idempotencyKey,
        ProductionMailboxServiceLimits limits,
        CancellationToken cancellationToken)
    {
        var authority = artifacts.Authority.Authority;
        var topology = artifacts.Topology.Snapshot;
        var mailboxPlacementCommitment = MailboxPlacementCommitment.Compute(placementId);
        var now = Now();
        var currentSelection = await CreateSelectionAsync(
            topology.CurrentEpoch, placementId, mailboxPlacementCommitment, selectionCommitment, now, cancellationToken);
        var nextSelection = await CreateSelectionAsync(
            topology.NextEpoch, placementId, mailboxPlacementCommitment, selectionCommitment, now, cancellationToken);
        var grants = new List<ProductionMailboxGrantEnvelope>(2);
        var domain = intent == ProductionMailboxIssuanceIntent.LocalOwner
            ? MailboxCapabilityDomain.Retrieve
            : MailboxCapabilityDomain.Deposit;
        foreach (var epoch in new[] { topology.CurrentEpoch, topology.NextEpoch })
            grants.Add(await CreateGrantAsync(epoch, domain, holder, mailboxId,
                mailboxPlacementCommitment, idempotencyKey, cancellationToken));
        var expires = topology.CurrentEpoch.NotAfterUnixSeconds;
        var bundle = new ProductionMailboxCredentialBundle(
            "production-mailbox-credential-bundle.v1",
            Base64Url(idempotencyKey),
            Base64Url(holder),
            Base64Url(owner),
            intent,
            Base64Url(mailboxId),
            Base64Url(placementId.Bytes.Span),
            Base64Url(selectionCommitment),
            Artifact("authority.pma1", ProductionMailboxMediaTypes.Authority,
                artifacts.AuthoritySha256, artifacts.AuthorityBytes),
            Artifact("revocations.pmr1", ProductionMailboxMediaTypes.Revocation,
                artifacts.RevocationSha256, artifacts.RevocationBytes),
            Artifact("topology.pmt1", ProductionMailboxMediaTypes.Topology,
                artifacts.TopologySha256, artifacts.TopologyBytes),
            [currentSelection, nextSelection],
            grants,
            limits,
            now,
            expires);
        EnsureFresh();
        return JsonSerializer.SerializeToUtf8Bytes(bundle, JsonOptions);
    }

    private async ValueTask<ProductionMailboxSelectionEnvelope> CreateSelectionAsync(
        ProductionMailboxTopologyEpoch epoch,
        BlindedPlacementId placementId,
        byte[] mailboxPlacementCommitment,
        byte[] selectionCommitment,
        ulong now,
        CancellationToken cancellationToken)
    {
        EnsureFresh();
        var authority = artifacts.Authority.Authority;
        var topology = artifacts.Topology.Snapshot;
        var selected = ProductionMailboxReplicaSelection.Select(
            topology.NetworkId.Span, topology.AuthorityGeneration, epoch, selectionCommitment);
        var issuedAt = Math.Max(now, epoch.NotBeforeUnixSeconds);
        var expiresAt = Math.Min(epoch.NotAfterUnixSeconds,
            Math.Min(topology.ExpiresAtUnixSeconds, checked(issuedAt + options.SelectionLifetimeSeconds)));
        if (issuedAt >= expiresAt)
            throw Error(ProductionMailboxIssueError.IssuerUnavailable, "Selection validity window is unavailable.");
        var draft = new ProductionMailboxSelectionProof
        {
            Algorithm = ProductionMailboxSelectionAlgorithm.RendezvousSha256V1,
            NetworkId = topology.NetworkId,
            AuthorityGeneration = topology.AuthorityGeneration,
            CanonicalAuthorityHash = artifacts.AuthoritySha256,
            TopologyGeneration = topology.TopologyGeneration,
            CanonicalTopologyHash = artifacts.TopologySha256,
            Epoch = epoch.Epoch,
            Generation = epoch.Generation,
            MembershipCommitment = epoch.MembershipCommitment,
            TopologyPlacementCommitment = epoch.TopologyPlacementCommitment,
            MailboxPlacementCommitment = mailboxPlacementCommitment,
            SelectionInputCommitment = selectionCommitment,
            IssuedAtUnixSeconds = issuedAt,
            ExpiresAtUnixSeconds = expiresAt,
            Replicas = selected.Select(id => new ProductionMailboxSelectionReplica
            {
                ReplicaId = id.ToArray(),
                CanonicalMIP1Proof = artifacts.ReadMembershipProof(epoch.Epoch, id.Span)
            }).ToArray(),
            IssuerSignature = new byte[64]
        };
        var signature = await SignAndVerifyAsync(
            ProductionMailboxTopologyCodec.GetSelectionSigningBytes(draft),
            authority.MailboxIssuerEd25519PublicKey,
            cancellationToken);
        var signed = draft with { IssuerSignature = signature };
        var canonical = ProductionMailboxTopologyCodec.EncodeSelection(signed);
        var decoded = ProductionMailboxTopologyCodec.DecodeSelection(canonical);
        if (!decoded.MailboxPlacementCommitment.Span.SequenceEqual(mailboxPlacementCommitment))
            throw Error(ProductionMailboxIssueError.IssuerUnavailable, "Canonical PMS1 lost its mailbox binding.");
        var replicas = selected.Select(id =>
        {
            var node = epoch.Nodes.Single(candidate => candidate.NodeId.Span.SequenceEqual(id.Span));
            return new ProductionMailboxReplicaEnvelope(
                Base64Url(id.Span), node.HttpsEndpoint,
                Hex(node.CurrentSpkiSha256.Span), Hex(node.NextSpkiSha256.Span));
        }).ToArray();
        var lane = epoch.Epoch == topology.CurrentEpoch.Epoch ? "current" : "next";
        return new(epoch.Epoch, epoch.Generation, $"selection-{lane}.pms1",
            ProductionMailboxMediaTypes.Selection, Hex(SHA256.HashData(canonical)),
            Base64Url(canonical), replicas);
    }

    private async ValueTask<ProductionMailboxGrantEnvelope> CreateGrantAsync(
        ProductionMailboxTopologyEpoch epoch,
        MailboxCapabilityDomain domain,
        byte[] holder,
        byte[] mailboxId,
        byte[] mailboxPlacementCommitment,
        byte[] policyHash,
        CancellationToken cancellationToken)
    {
        var authority = artifacts.Authority.Authority;
        var serial = DomainHash("Deep/production-mailbox/grant-serial/v1",
            authority.NetworkId.ToArray(), artifacts.AuthoritySha256, artifacts.TopologySha256,
            U64(epoch.Epoch), U64(epoch.Generation), [(byte)domain], holder, mailboxId,
            mailboxPlacementCommitment, policyHash)[..16];
        if (artifacts.Revocation.IsRevokedSerial(serial))
            throw Error(ProductionMailboxIssueError.Revoked, "Grant serial is revoked.");
        var draft = new MailboxAuthenticatedGrant
        {
            Domain = domain,
            Lifecycle = MailboxCapabilityLifecycle.Active,
            NetworkId = authority.NetworkId,
            Epoch = epoch.Epoch,
            Generation = epoch.Generation,
            Serial = serial,
            NotBeforeUnixSeconds = epoch.NotBeforeUnixSeconds,
            ExpiresAtUnixSeconds = epoch.NotAfterUnixSeconds,
            OverlapUntilUnixSeconds = 0,
            PlacementCommitment = mailboxPlacementCommitment,
            MembershipCommitment = epoch.MembershipCommitment,
            IssuerPublicKey = authority.MailboxIssuerEd25519PublicKey,
            HolderPublicKey = holder,
            IssuerSignature = new byte[64]
        };
        var signature = await SignAndVerifyAsync(
            MailboxAuthenticatedCapabilityCodec.GetGrantSigningBytes(draft),
            authority.MailboxIssuerEd25519PublicKey,
            cancellationToken);
        var signed = draft with { IssuerSignature = signature };
        var canonical = MailboxAuthenticatedCapabilityCodec.EncodeGrant(signed);
        var lane = epoch.Epoch == artifacts.Topology.Snapshot.CurrentEpoch.Epoch ? "current" : "next";
        var domainName = domain.ToString().ToLowerInvariant();
        return new(domainName, epoch.Epoch, epoch.Generation, $"{domainName}-{lane}.mcg2",
            ProductionMailboxMediaTypes.Grant, Hex(SHA256.HashData(canonical)), Base64Url(canonical));
    }

    private async ValueTask<byte[]> SignAndVerifyAsync(
        byte[] signingBytes,
        ReadOnlyMemory<byte> issuerPublicKey,
        CancellationToken cancellationToken)
    {
        EnsureFresh();
        byte[] signature;
        try { signature = await signer.SignAsync(signingBytes, cancellationToken); }
        catch (Exception exception) when (exception is IOException or SocketException or CryptographicException)
        { throw Error(ProductionMailboxIssueError.IssuerUnavailable, "External issuer signer is unavailable."); }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        { throw Error(ProductionMailboxIssueError.IssuerUnavailable, "External issuer signer timed out."); }
        if (signature.Length != 64 || !new SodiumMailboxCapabilityCrypto().VerifyIssuer(
                issuerPublicKey.Span, signingBytes, signature))
            throw Error(ProductionMailboxIssueError.IssuerUnavailable, "External issuer returned an invalid signature.");
        return signature;
    }

    private async ValueTask<OwnerRoute> DeriveOwnerRouteAsync(
        byte[] ownerPublicKey,
        CancellationToken cancellationToken)
    {
        var authority = artifacts.Authority.Authority;
        var transcript = DomainHash(
            "Deep/production-mailbox/owner-route-prf-input/v1",
            authority.NetworkId.ToArray(), artifacts.AuthoritySha256, ownerPublicKey);
        var issuerOutput = await SignAndVerifyAsync(
            transcript, authority.MailboxIssuerEd25519PublicKey, cancellationToken);
        var mailboxId = DomainHash(
            "Deep/production-mailbox/blinded-mailbox-id/v1",
            authority.NetworkId.ToArray(), ownerPublicKey, issuerOutput);
        var placementId = DomainHash(
            "Deep/production-mailbox/blinded-placement-id/v1",
            authority.NetworkId.ToArray(), ownerPublicKey, issuerOutput);
        var selection = ProductionMailboxReplicaSelection.ComputeSelectionInputCommitment(
            new BlindedPlacementId(placementId));
        return new OwnerRoute(mailboxId, placementId, selection);
    }

    private static void VerifyHolderProof(
        ProductionMailboxHolderProofInput input,
        string? encodedSignature,
        bool owner)
    {
        var label = owner ? "mailbox owner" : "holder";
        byte[] signature;
        try { signature = Decode(encodedSignature ?? "", 64, $"{label} proof"); }
        catch (FormatException)
        { throw Error(ProductionMailboxIssueError.InvalidHolderProof, $"{label} proof is invalid."); }
        try
        {
            var verifier = new SodiumProductionMailboxHolderProofSignatureVerifier();
            if (owner) ProductionMailboxHolderProof.VerifyOwner(input, signature, verifier);
            else ProductionMailboxHolderProof.VerifyHolder(input, signature, verifier);
        }
        catch (ProductionMailboxHolderProofException)
        {
            throw Error(ProductionMailboxIssueError.InvalidHolderProof, $"{label} proof is invalid.");
        }
    }

    private void VerifyProofOfWork(byte[] challengeId, byte[] challenge, ulong nonce)
    {
        var digest = DomainHash("Deep/production-mailbox/pow/v1", challengeId, challenge, U64(nonce));
        var remaining = options.ProofOfWorkLeadingZeroBits;
        foreach (var value in digest)
        {
            if (remaining <= 0) return;
            var required = Math.Min(remaining, 8);
            if ((value >> (8 - required)) != 0)
                throw Error(ProductionMailboxIssueError.InvalidChallenge, "Proof of work is invalid.");
            remaining -= required;
        }
    }

    private byte[] ComputeIdempotencyKey(
        byte[] holder, byte[] owner, byte[] mailboxId, byte[] placementId, byte[] selectionCommitment,
        ProductionMailboxIssuanceIntent intent, ProductionMailboxClientPlatform platform,
        byte[] certificate, byte[] buildArtifact, byte[] entitlementCommitment) => DomainHash(
            "Deep/production-mailbox/issuance-idempotency/v1", artifacts.AuthoritySha256,
            artifacts.RevocationSha256, artifacts.TopologySha256, holder, owner, mailboxId, placementId,
            selectionCommitment, [(byte)intent], [(byte)platform], certificate, buildArtifact,
            entitlementCommitment);

    private static ProductionMailboxArtifactReference Artifact(
        string fileName, string mediaType, byte[] hash, byte[] canonical)
    {
        var hex = Hex(hash);
        return new(fileName, mediaType, hex, $"\"{hex}\"",
            $"/api/production-mailbox/artifacts/{hex}/{fileName}", Base64Url(canonical));
    }

    private static ProductionMailboxServiceLimits BaseLimits() => new(
        64UL * 1024 * 1024, 10_000, 14 * 24 * 60 * 60, 1_000, false);

    private void EnsureFresh()
    {
        var now = Now();
        var skew = options.ClockSkewSeconds;
        var approval = artifacts.Authority.Authority.MrXApproval;
        var revocation = artifacts.Revocation.Snapshot;
        var topology = artifacts.Topology.Snapshot;
        var current = topology.CurrentEpoch;
        if (Outside(now, approval.RolloutNotBeforeUnixSeconds, approval.RolloutNotAfterUnixSeconds, skew) ||
            Outside(now, revocation.IssuedAtUnixSeconds, revocation.ExpiresAtUnixSeconds, skew) ||
            Outside(now, topology.IssuedAtUnixSeconds, topology.ExpiresAtUnixSeconds, skew) ||
            Outside(now, current.NotBeforeUnixSeconds, current.NotAfterUnixSeconds, skew))
            throw Error(ProductionMailboxIssueError.IssuerUnavailable,
                "Production mailbox authority artifacts are not currently valid.");
    }

    private static bool Outside(ulong now, ulong notBefore, ulong expiresAt, uint skew) =>
        now < notBefore && notBefore - now > skew || now > expiresAt && now - expiresAt > skew;

    private static byte[] Decode(string value, int length, string label)
    {
        var bytes = DecodeVariable(value, length, label);
        if (bytes.Length != length || bytes.AsSpan().IndexOfAnyExcept((byte)0) < 0)
            throw new FormatException($"{label} has invalid length or value.");
        return bytes;
    }

    private static byte[] DecodeOptional(string value, int length, string label) =>
        string.IsNullOrEmpty(value) ? new byte[length] : Decode(value, length, label);

    private static byte[] DecodeFixedAllowZero(string value, int length, string label)
    {
        var bytes = DecodeVariable(value, length, label);
        if (bytes.Length != length)
            throw new FormatException($"{label} has invalid length.");
        return bytes;
    }

    private static byte[] DecodeVariable(string value, int maximumLength, string label)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Contains('=') || value.Length > ((maximumLength + 2) / 3) * 4)
            throw new FormatException($"{label} is not canonical base64url.");
        var padded = value.Replace('-', '+').Replace('_', '/');
        padded += new string('=', (4 - padded.Length % 4) % 4);
        var bytes = Convert.FromBase64String(padded);
        if (bytes.Length > maximumLength || Base64Url(bytes) != value)
            throw new FormatException($"{label} is not canonical base64url.");
        return bytes;
    }

    private static string Base64Url(ReadOnlySpan<byte> value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    private static string Hex(ReadOnlySpan<byte> value) => Convert.ToHexStringLower(value);
    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
    private static void RequireFixed(byte[] actual, byte[] expected, ProductionMailboxIssueError error, string message)
    { if (!Fixed(actual, expected)) throw Error(error, message); }
    private static bool IsZero(ReadOnlySpan<byte> value) => value.IndexOfAnyExcept((byte)0) < 0;
    private static byte[] U64(ulong value) { var bytes = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(bytes, value); return bytes; }
    private static byte[] U32(uint value) { var bytes = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(bytes, value); return bytes; }
    private static byte[] DomainHash(string domain, params byte[][] values)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(Encoding.UTF8.GetBytes(domain));
        foreach (var value in values) hash.AppendData(value);
        return hash.GetHashAndReset();
    }
    private ulong Now() => checked((ulong)timeProvider.GetUtcNow().ToUnixTimeSeconds());
    private static ProductionMailboxIssueException Error(ProductionMailboxIssueError error, string message) => new(error, message);

    private static void ValidateOptions(ProductionMailboxOptions options)
    {
        if (!options.Enabled || options.ClockSkewSeconds > 300 ||
            options.SelectionLifetimeSeconds is 0 or > 86_400 ||
            options.ChallengeLifetimeSeconds is 0 or > 3600 ||
            options.ExternalSignerTimeoutSeconds is 0 or > 30 ||
            options.MaximumRetainedArtifactClosures is < 1 or > 64 ||
            options.ProofOfWorkLeadingZeroBits is < 8 or > 22 ||
            options.MaximumChallengesPerWindow is < 1 or > 1_000_000 ||
            options.ChallengeWindowSeconds is 0 or > 3600)
            throw new InvalidOperationException("Production mailbox coordinator options are invalid.");
    }

    private sealed record OwnerRoute(
        byte[] MailboxId,
        byte[] PlacementId,
        byte[] SelectionInputCommitment);
}
