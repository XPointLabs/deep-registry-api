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
    private readonly byte[] routeStateHmacKey;
    private readonly IProductionMailboxClosurePublisherSigner closurePublisherSigner;
    private readonly IProductionMailboxClosureTransport closureTransport;
    private readonly byte[] closurePublisherPublicKey;
    private int throwBeforeArtifactProviderCutoverOnce;
    private static Action? routeStateKeyAfterActualOpenForTests;
    internal static Action? RouteStateKeyAfterActualOpenForTests
    {
        set => Interlocked.Exchange(ref routeStateKeyAfterActualOpenForTests, value);
    }

    internal bool ThrowBeforeArtifactProviderCutoverOnce
    {
        set => Interlocked.Exchange(ref throwBeforeArtifactProviderCutoverOnce,
            value ? 1 : 0);
    }

    public ProductionMailboxCoordinator(
        IOptions<ProductionMailboxOptions> options,
        ProductionMailboxArtifacts artifacts,
        IEd25519ExternalSigner signer,
        IProductionMailboxStateStore state,
        TimeProvider timeProvider,
        ProductionMailboxMetrics metrics,
        IProductionMailboxClosurePublisherSigner closurePublisherSigner,
        IProductionMailboxClosureTransport closureTransport)
    {
        this.options = options.Value;
        this.artifacts = artifacts;
        this.signer = signer;
        this.state = state;
        this.timeProvider = timeProvider;
        this.metrics = metrics;
        this.closurePublisherSigner = closurePublisherSigner;
        this.closureTransport = closureTransport;
        ValidateOptions(this.options);
        routeStateHmacKey = ReadRouteStateHmacKey(this.options.RouteStateHmacKeyPath);
        closurePublisherPublicKey = ProductionMailboxArtifacts.Hex(
            this.options.ClosurePublisherEd25519PublicKey, 32, false);
    }

    public async ValueTask<ProductionMailboxChallengeResponse> CreateChallengeAsync(
        CancellationToken cancellationToken)
    {
        EnsureFresh();
        var now = Now();
        var challenge = await state.CreateChallengeAsync(
            now,
            checked(now + options.ChallengeLifetimeSeconds),
            ArtifactClosureHash(),
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
            challenge.ExpiresAtUnixSeconds,
            Artifact("authority.pma1", ProductionMailboxMediaTypes.Authority,
                artifacts.AuthoritySha256, artifacts.AuthorityBytes),
            Artifact("revocations.pmr1", ProductionMailboxMediaTypes.Revocation,
                artifacts.RevocationSha256, artifacts.RevocationBytes),
            Artifact("topology.pmt1", ProductionMailboxMediaTypes.Topology,
                artifacts.TopologySha256, artifacts.TopologyBytes));
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
            OwnerRoute route;
            ReadOnlyMemory<byte> enrollmentStateKey = ReadOnlyMemory<byte>.Empty;
            ProductionMailboxCanonicalEnvelope? routeCertificate = null;
            ProductionMailboxCanonicalEnvelope? routeAdvertisement = null;
            VerifiedRouteAdvertisement verifiedAdvertisement;
            if (request.Intent == ProductionMailboxIssuanceIntent.LocalOwner)
            {
                if (!IsZero(suppliedMailboxId) || !IsZero(suppliedPlacementId) ||
                    !IsZero(suppliedSelection) || string.IsNullOrEmpty(request.RouteAdvertisement)
                    || string.IsNullOrEmpty(request.EnrollmentHandle))
                    throw Error(ProductionMailboxIssueError.InvalidRequest,
                        "Local owner credentials require an enrolled PRC1 and owner-signed PRA1.");
                var local = await LoadLocalEnrollmentAsync(
                    request, holder, owner, idempotencyKey, cancellationToken);
                enrollmentStateKey = local.EnrollmentStateKey;
                route = local.Route;
                routeCertificate = local.RouteCertificate;
                routeAdvertisement = local.RouteAdvertisement;
                verifiedAdvertisement = local.VerifiedAdvertisement;
            }
            else
            {
                if (!string.IsNullOrEmpty(request.EnrollmentHandle))
                    throw Error(ProductionMailboxIssueError.InvalidRequest,
                        "Peer deposit must not carry a local enrollment handle.");
                verifiedAdvertisement = VerifyRouteAdvertisement(
                    request.RouteAdvertisement, owner, suppliedMailboxId, suppliedPlacementId,
                    suppliedSelection, ReadOnlySpan<byte>.Empty,
                    requireInitialSequence: false);
                route = verifiedAdvertisement.Route;
            }
            var routeStateKey = StateHmac(
                "Deep/production-mailbox/owner-route-state/v1", owner,
                route.MailboxId, route.PlacementId, route.SelectionInputCommitment);
            var previousOwnerBundle = request.Intent == ProductionMailboxIssuanceIntent.LocalOwner
                ? await state.GetLatestOwnerBundleAsync(routeStateKey, cancellationToken)
                : null;
            var limits = BaseLimits();
            var issued = await state.ConsumeChallengeAcceptAdvertisementAndIssueAsync(
                challengeId, challenge, Now(), artifacts.Topology.Snapshot.CurrentEpoch.NotAfterUnixSeconds,
                ArtifactClosureHash(), idempotencyKey, enrollmentStateKey,
                StateHmac("Deep/production-mailbox/route-advertisement-state/v1",
                    verifiedAdvertisement.RouteDomainHash),
                verifiedAdvertisement.Sequence,
                verifiedAdvertisement.CanonicalAdvertisementHash,
                token => CreatePreparedIssueAsync(holder, owner, request.Intent, route.MailboxId,
                    new BlindedPlacementId(route.PlacementId), route.SelectionInputCommitment,
                    idempotencyKey, limits, previousOwnerBundle, routeCertificate,
                    routeAdvertisement,
                    request.Intent == ProductionMailboxIssuanceIntent.LocalOwner
                        ? routeStateKey : [], token), cancellationToken);
            if (issued.Status == ProductionMailboxIssueCommitStatus.InvalidChallenge)
                throw Error(ProductionMailboxIssueError.InvalidChallenge,
                    "Challenge is expired, mismatched or already consumed.");
            if (issued.Status is ProductionMailboxIssueCommitStatus.EnrollmentMismatch
                or ProductionMailboxIssueCommitStatus.AdvertisementRollback
                or ProductionMailboxIssueCommitStatus.AdvertisementConflict
                or ProductionMailboxIssueCommitStatus.IssuanceConflict)
                throw Error(ProductionMailboxIssueError.InvalidRequest,
                    "Enrollment, PRA1 replay state or issuance binding conflicted.");
            if (issued.Status == ProductionMailboxIssueCommitStatus.Replayed)
                metrics.BundleReplayed();
            else metrics.BundleIssued();
            var canonicalResponse = issued.CanonicalResponse
                ?? throw Error(ProductionMailboxIssueError.IssuerUnavailable,
                    "Committed issuance response is unavailable.");
            var bundle = JsonSerializer.Deserialize<ProductionMailboxCredentialBundle>(
                    canonicalResponse, JsonOptions)
                ?? throw Error(ProductionMailboxIssueError.IssuerUnavailable, "Stored issuance response is invalid.");
            if (request.Intent == ProductionMailboxIssuanceIntent.LocalOwner
                && bundle.SelectionSuccessor is not null)
                await PublishPreparedClosureAsync(
                    idempotencyKey, canonicalResponse, cancellationToken);
            return bundle;
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

    public async ValueTask<ProductionMailboxRouteEnrollment> EnrollRouteAsync(
        ProductionMailboxIssueRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        try
        {
            var holder = Decode(request.HolderEd25519PublicKey, 32, "holder key");
            var owner = Decode(request.MailboxOwnerEd25519PublicKey, 32, "mailbox owner key");
            if (request.Intent != ProductionMailboxIssuanceIntent.LocalOwner
                || !string.IsNullOrEmpty(request.RouteAdvertisement)
                || !string.IsNullOrEmpty(request.EnrollmentHandle))
                throw Error(ProductionMailboxIssueError.InvalidRequest,
                    "Route enrollment is available only for an unbound local owner.");
            var mailbox = DecodeOptional(request.BlindedMailboxId, 32, "blinded mailbox ID");
            var placement = DecodeOptional(request.BlindedPlacementId, 32, "blinded placement ID");
            var selection = DecodeOptional(request.SelectionInputCommitment, 32,
                "selection commitment");
            if (!IsZero(mailbox) || !IsZero(placement) || !IsZero(selection))
                throw Error(ProductionMailboxIssueError.InvalidRequest,
                    "Route enrollment requires zero route inputs.");
            var signingCertificate = Decode(
                request.SigningCertificateSha256, 32, "signing certificate hash");
            var buildArtifact = Decode(
                request.BuildArtifactSha256, 32, "build artifact hash");
            var idempotencyKey = Decode(request.IdempotencyKey, 32, "idempotency key");
            var entitlementCommitment = DecodeFixedAllowZero(
                request.EntitlementCommitment, 32, "entitlement commitment");
            if (!string.IsNullOrEmpty(request.OpaqueEntitlement)
                || !IsZero(entitlementCommitment))
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
                BlindedMailboxId = mailbox,
                BlindedPlacementId = placement,
                SelectionInputCommitment = selection,
                SigningCertificateSha256 = signingCertificate,
                BuildArtifactSha256 = buildArtifact,
                IdempotencyKey = idempotencyKey,
                EntitlementCommitment = entitlementCommitment,
                ChallengeId = challengeId,
                Challenge = challenge,
                ProofOfWorkNonce = request.ProofOfWorkNonce
            };
            VerifyHolderProof(proofInput, request.HolderProofSignature, false);
            VerifyHolderProof(proofInput, request.OwnerProofSignature, true);
            RequireFixed(idempotencyKey, ComputeIdempotencyKey(
                    holder, owner, mailbox, placement, selection, request.Intent,
                    request.Platform, signingCertificate, buildArtifact,
                    entitlementCommitment),
                ProductionMailboxIssueError.InvalidRequest,
                "Idempotency key does not match the canonical enrollment policy.");
            if (await state.IsHolderRevokedAsync(
                    DomainHash("Deep/production-mailbox/revoked-holder/v1", holder),
                    cancellationToken)
                || await state.IsHolderRevokedAsync(
                    DomainHash("Deep/production-mailbox/revoked-holder/v1", owner),
                    cancellationToken))
                throw Error(ProductionMailboxIssueError.Revoked,
                    "Holder or mailbox owner is revoked.");

            var route = DeriveOwnerRoute(owner);
            var enrollmentHandle = StateHmac(
                "Deep/production-mailbox/route-enrollment-handle/v1",
                idempotencyKey, ArtifactClosureHash(), owner, route.MailboxId,
                route.PlacementId, route.SelectionInputCommitment);
            var enrollmentStateKey = StateHmac(
                "Deep/production-mailbox/route-enrollment-state/v1", enrollmentHandle);
            var expiresAt = Math.Min(
                artifacts.Topology.Snapshot.CurrentEpoch.NotAfterUnixSeconds,
                checked(Now() + ProductionMailboxRouteAdvertisementConstants.MaximumLifetimeSeconds));
            var enrolled = await state.ConsumeChallengeAndEnrollAsync(
                challengeId, challenge, Now(), expiresAt, ArtifactClosureHash(),
                enrollmentStateKey, idempotencyKey,
                token => CreateEnrollmentBytesAsync(
                    enrollmentHandle, idempotencyKey, holder, owner, route, token),
                cancellationToken);
            if (enrolled is null)
                throw Error(ProductionMailboxIssueError.InvalidChallenge,
                    "Challenge is expired, mismatched, consumed or enrollment-conflicted.");
            if (enrolled.Replayed) metrics.EnrollmentReplayed();
            else metrics.EnrollmentIssued();
            return JsonSerializer.Deserialize<ProductionMailboxRouteEnrollment>(
                       enrolled.CanonicalResponse, JsonOptions)
                   ?? throw Error(ProductionMailboxIssueError.IssuerUnavailable,
                       "Stored route enrollment response is invalid.");
        }
        catch (ProductionMailboxIssueException)
        {
            metrics.RequestRejected();
            throw;
        }
        catch (Exception exception) when (exception is ArgumentException or FormatException
            or OverflowException)
        {
            metrics.RequestRejected();
            throw Error(ProductionMailboxIssueError.InvalidRequest,
                "Route enrollment request is malformed.");
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

    private async ValueTask<byte[]> CreateEnrollmentBytesAsync(
        byte[] enrollmentHandle,
        byte[] idempotencyKey,
        byte[] holder,
        byte[] owner,
        OwnerRoute route,
        CancellationToken cancellationToken)
    {
        var now = Now();
        var certificate = await CreateRouteCertificateAsync(
            owner, route.MailboxId, route.PlacementId,
            route.SelectionInputCommitment, now, cancellationToken);
        var enrollment = new ProductionMailboxRouteEnrollment(
            "production-mailbox-route-enrollment.v1",
            Base64Url(enrollmentHandle), Base64Url(idempotencyKey), Base64Url(holder),
            Base64Url(owner), Base64Url(route.MailboxId), Base64Url(route.PlacementId),
            Base64Url(route.SelectionInputCommitment),
            Artifact("authority.pma1", ProductionMailboxMediaTypes.Authority,
                artifacts.AuthoritySha256, artifacts.AuthorityBytes),
            Artifact("revocations.pmr1", ProductionMailboxMediaTypes.Revocation,
                artifacts.RevocationSha256, artifacts.RevocationBytes),
            Artifact("topology.pmt1", ProductionMailboxMediaTypes.Topology,
                artifacts.TopologySha256, artifacts.TopologyBytes),
            certificate, now,
            ProductionMailboxRouteAdvertisementCodec.DecodeCertificate(
                Decode(certificate.CanonicalBase64Url,
                    ProductionMailboxRouteAdvertisementConstants.CanonicalCertificateLength,
                    "route certificate")).ExpiresAtUnixSeconds);
        return JsonSerializer.SerializeToUtf8Bytes(enrollment, JsonOptions);
    }

    private async ValueTask<byte[]> CreateBundleBytesAsync(
        byte[] holder,
        byte[] owner,
        ProductionMailboxIssuanceIntent intent,
        byte[] mailboxId,
        BlindedPlacementId placementId,
        byte[] selectionCommitment,
        byte[] idempotencyKey,
        ProductionMailboxServiceLimits limits,
        byte[]? previousOwnerBundleBytes,
        ProductionMailboxCanonicalEnvelope? routeCertificate,
        ProductionMailboxCanonicalEnvelope? routeAdvertisement,
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
        ProductionMailboxCredentialBundle? previousOwnerBundle = null;
        if (previousOwnerBundleBytes is not null)
            previousOwnerBundle = JsonSerializer.Deserialize<ProductionMailboxCredentialBundle>(
                previousOwnerBundleBytes, JsonOptions);
        var grants = new List<ProductionMailboxGrantEnvelope>(2);
        var domain = intent == ProductionMailboxIssuanceIntent.LocalOwner
            ? MailboxCapabilityDomain.Retrieve
            : MailboxCapabilityDomain.Deposit;
        var replayedCurrent = TryReplayPromotedGrant(
            previousOwnerBundle, holder, domain, topology.CurrentEpoch);
        if (replayedCurrent is not null)
            grants.Add(replayedCurrent with
            { FileName = $"{domain.ToString().ToLowerInvariant()}-current.mcg2" });
        else
            grants.Add(await CreateGrantAsync(topology.CurrentEpoch, domain, holder, mailboxId,
                mailboxPlacementCommitment, idempotencyKey, cancellationToken));
        grants.Add(await CreateGrantAsync(topology.NextEpoch, domain, holder, mailboxId,
            mailboxPlacementCommitment, idempotencyKey, cancellationToken));
        var expires = topology.CurrentEpoch.NotAfterUnixSeconds;
        var successor = intent == ProductionMailboxIssuanceIntent.LocalOwner
            ? await CreateSelectionSuccessorAsync(
                previousOwnerBundle, owner, mailboxId, placementId.Bytes.ToArray(),
                selectionCommitment, currentSelection, now, cancellationToken)
            : null;
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
            expires,
            routeCertificate,
            routeAdvertisement,
            successor);
        EnsureFresh();
        return JsonSerializer.SerializeToUtf8Bytes(bundle, JsonOptions);
    }

    private async ValueTask<ProductionMailboxPreparedIssue> CreatePreparedIssueAsync(
        byte[] holder,
        byte[] owner,
        ProductionMailboxIssuanceIntent intent,
        byte[] mailboxId,
        BlindedPlacementId placementId,
        byte[] selectionCommitment,
        byte[] idempotencyKey,
        ProductionMailboxServiceLimits limits,
        byte[]? previousOwnerBundleBytes,
        ProductionMailboxCanonicalEnvelope? routeCertificate,
        ProductionMailboxCanonicalEnvelope? routeAdvertisement,
        byte[] ownerRouteStateKey,
        CancellationToken cancellationToken)
    {
        var response = await CreateBundleBytesAsync(
            holder, owner, intent, mailboxId, placementId, selectionCommitment,
            idempotencyKey, limits, previousOwnerBundleBytes, routeCertificate,
            routeAdvertisement, cancellationToken);
        var publicationStateKey = StateHmac(
            "Deep/production-mailbox/publication-state/v1", idempotencyKey);
        var publicationItems = intent == ProductionMailboxIssuanceIntent.LocalOwner
            ? CreatePublicationItems(
                response, previousOwnerBundleBytes, publicationStateKey)
            : [];
        return new(response, ownerRouteStateKey, publicationStateKey, publicationItems);
    }

    private IReadOnlyList<ProductionMailboxPublicationItem> CreatePublicationItems(
            byte[] canonicalResponse,
            byte[]? previousOwnerBundleBytes,
            byte[] publicationStateKey)
    {
        if (previousOwnerBundleBytes is null) return [];
        var current = JsonSerializer.Deserialize<ProductionMailboxCredentialBundle>(
            canonicalResponse, JsonOptions)
            ?? throw Error(ProductionMailboxIssueError.IssuerUnavailable,
                "Prepared owner bundle is invalid.");
        if (current.SelectionSuccessor is null) return [];
        var previous = JsonSerializer.Deserialize<ProductionMailboxCredentialBundle>(
            previousOwnerBundleBytes, JsonOptions)
            ?? throw Error(ProductionMailboxIssueError.IssuerUnavailable,
                "Durable predecessor owner bundle is invalid.");
        var previousTopology = ProductionMailboxTopologyCodec.Decode(
            DecodeVariable(previous.Topology.CanonicalBase64Url,
                ProductionMailboxTopologyConstants.MaximumTopologyArtifactBytes,
                "previous topology"));
        var currentTopology = artifacts.Topology.Snapshot;
        var oldCurrent = previous.Selections.Single(selection =>
            selection.Epoch == previousTopology.CurrentEpoch.Epoch
            && selection.Generation == previousTopology.CurrentEpoch.Generation);
        var oldNext = previous.Selections.Single(selection =>
            selection.Epoch == previousTopology.NextEpoch.Epoch
            && selection.Generation == previousTopology.NextEpoch.Generation);
        var newCurrent = current.Selections.Single(selection =>
            selection.Epoch == currentTopology.CurrentEpoch.Epoch
            && selection.Generation == currentTopology.CurrentEpoch.Generation);
        var ordinaryIds = oldNext.Replicas.Concat(newCurrent.Replicas)
            .Select(replica => Decode(replica.ReplicaId, 32, "ordinary replica ID"))
            .ToArray();
        var legacyIds = oldCurrent.Replicas
            .Select(replica => Decode(replica.ReplicaId, 32, "old-current replica ID"))
            .Where(candidate => !ordinaryIds.Any(ordinary => Fixed(candidate, ordinary)))
            .OrderBy(Convert.ToHexString, StringComparer.Ordinal)
            .ToArray();
        if (legacyIds.Length > ProductionMailboxPublicationCodec.MaximumLegacyReplicaIds)
            throw Error(ProductionMailboxIssueError.IssuerUnavailable,
                "Old-current legacy replica set exceeds PMP1 policy.");
        var envelope = ProductionMailboxPublicationCodec.EncodeEnvelope(
            artifacts.AuthorityBytes, artifacts.RevocationBytes, artifacts.TopologyBytes,
            DecodeVariable(newCurrent.CanonicalBase64Url,
                ProductionMailboxTopologyConstants.MaximumSelectionArtifactBytes,
                "current selection"),
            DecodeVariable(current.SelectionSuccessor.CanonicalBase64Url,
                ProductionMailboxSelectionSuccessorConstants.MaximumArtifactBytes,
                "selection successor"));
        var targets = oldCurrent.Replicas.Concat(oldNext.Replicas)
            .Concat(newCurrent.Replicas)
            .GroupBy(static replica => replica.ReplicaId, StringComparer.Ordinal)
            .Select(static group => group.First())
            .OrderBy(static replica => replica.ReplicaId, StringComparer.Ordinal)
            .ToArray();
        var items = new List<ProductionMailboxPublicationItem>(targets.Length);
        foreach (var replica in targets)
        {
            var target = new ProductionMailboxPrepositionTarget(
                Decode(replica.ReplicaId, 32, "publication replica ID"),
                replica.HttpsEndpoint,
                ProductionMailboxArtifacts.Hex(replica.CurrentSpkiSha256, 32, false),
                ProductionMailboxArtifacts.Hex(replica.NextSpkiSha256, 32, false));
            items.Add(new(
                StateHmac("Deep/production-mailbox/publication-target-state/v1",
                    publicationStateKey, target.ReplicaId),
                target.ReplicaId, target.HttpsOrigin,
                target.CurrentSpkiSha256, target.NextSpkiSha256,
                legacyIds, envelope, SHA256.HashData(envelope)));
        }
        return items;
    }

    private async ValueTask PublishPreparedClosureAsync(
        byte[] idempotencyKey,
        byte[] canonicalResponse,
        CancellationToken cancellationToken)
    {
        var publicationStateKey = StateHmac(
            "Deep/production-mailbox/publication-state/v1", idempotencyKey);
        await PublishPreparedClosureCoreAsync(
            publicationStateKey, SHA256.HashData(canonicalResponse), cancellationToken);
    }

    private async ValueTask PublishPreparedClosureCoreAsync(
        byte[] publicationStateKey,
        byte[] expectedResponseSha256,
        CancellationToken cancellationToken)
    {
        var publication = await state.GetPublicationAsync(
            publicationStateKey, cancellationToken)
            ?? throw Error(ProductionMailboxIssueError.IssuerUnavailable,
                "Durable PMP1 publication outbox is missing.");
        if (!Fixed(publication.CanonicalResponseSha256,
                expectedResponseSha256))
            throw Error(ProductionMailboxIssueError.IssuerUnavailable,
                "Durable PMP1 publication response binding mismatched.");
        if (publication.Completed) return;
        var completed = false;
        foreach (var item in publication.Items.Where(static item => !item.Acknowledged))
        {
            var target = new ProductionMailboxPrepositionTarget(
                item.TargetReplicaId, item.Endpoint,
                item.CurrentSpkiSha256, item.NextSpkiSha256);
            var attemptedAt = Now();
            var command = await ProductionMailboxPublicationCodec.CreateCommandAsync(
                attemptedAt, target, item.AuthorizedLegacyReplicaIds,
                item.CanonicalEnvelope, closurePublisherPublicKey,
                closurePublisherSigner, cancellationToken);
            var attemptHash = SHA256.HashData(command);
            if (!await state.RecordPublicationAttemptAsync(
                    publicationStateKey, item.TargetStateKey, item.EnvelopeSha256,
                    attemptHash, attemptedAt, cancellationToken))
                continue;
            if (!await closureTransport.PrepositionAsync(item, command, cancellationToken))
                continue;
            completed = await state.AcknowledgePublicationAsync(
                publicationStateKey, item.TargetStateKey, item.EnvelopeSha256,
                attemptHash,
                cancellationToken);
        }
        if (!completed)
        {
            publication = await state.GetPublicationAsync(
                publicationStateKey, cancellationToken)
                ?? throw Error(ProductionMailboxIssueError.IssuerUnavailable,
                    "Durable PMP1 publication outbox disappeared.");
            if (!publication.Completed)
                throw Error(ProductionMailboxIssueError.IssuerUnavailable,
                    "PMP1 publication acknowledgement barrier is incomplete.");
        }
    }

    internal async ValueTask<int> DrainPendingPublicationsAsync(
        int maximumCount, CancellationToken cancellationToken)
    {
        var keys = await state.ListPendingPublicationKeysAsync(maximumCount, cancellationToken);
        var completed = 0;
        foreach (var key in keys)
        {
            var publication = await state.GetPublicationAsync(key, cancellationToken);
            if (publication is null || publication.Completed) continue;
            try
            {
                await PublishPreparedClosureCoreAsync(
                    key, publication.CanonicalResponseSha256, cancellationToken);
                completed++;
            }
            catch (ProductionMailboxIssueException exception)
                when (exception.Error == ProductionMailboxIssueError.IssuerUnavailable)
            {
                // The durable outbox remains pending for the next bounded drain.
            }
        }
        return completed;
    }

    internal async ValueTask<ProductionMailboxArtifacts> PromoteArtifactsAsync(
        ProductionMailboxArtifactProvider provider,
        ProductionMailboxArtifacts replacement,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentNullException.ThrowIfNull(replacement);
        var oldClosureHash = ArtifactClosureHash(provider.Current);
        var activePromotion = await state.GetActiveArtifactPromotionAsync(cancellationToken);
        if (activePromotion is not null
            && Fixed(activePromotion.NewArtifactClosureHash, oldClosureHash))
        {
            if (!activePromotion.SweepCompleted
                || !await state.MarkArtifactPromotionPublishedAsync(
                    activePromotion.PromotionStateKey, cancellationToken))
                throw Error(ProductionMailboxIssueError.IssuerUnavailable,
                    "Active artifact promotion cutover could not be reconciled.");
            return provider.Current;
        }
        if (!Fixed(oldClosureHash, ArtifactClosureHash()))
            throw Error(ProductionMailboxIssueError.IssuerUnavailable,
                "Artifact promotion coordinator snapshot is stale.");
        var replacementClosureHash = ArtifactClosureHash(replacement);
        if (Fixed(oldClosureHash, replacementClosureHash)) return provider.Current;
        if (activePromotion is not null
            && (!Fixed(activePromotion.OldArtifactClosureHash, oldClosureHash)
                || !Fixed(activePromotion.NewArtifactClosureHash,
                    replacementClosureHash)))
            throw Error(ProductionMailboxIssueError.IssuerUnavailable,
                "Active artifact promotion conflicts with the staged successor.");
        provider.StageVerifiedSuccessor(replacement);
        var successor = new ProductionMailboxCoordinator(
            Microsoft.Extensions.Options.Options.Create(options), replacement,
            signer, state, timeProvider, metrics, closurePublisherSigner,
            closureTransport);
        var newClosureHash = successor.ArtifactClosureHash();
        var promotionStateKey = activePromotion?.PromotionStateKey
            ?? StateHmac("Deep/production-mailbox/artifact-promotion-state/v1",
                oldClosureHash, newClosureHash);
        var promotion = activePromotion
            ?? await state.BeginArtifactPromotionAsync(
                promotionStateKey, oldClosureHash, newClosureHash, cancellationToken);
        if (promotion.Published)
        {
            if (!Fixed(ArtifactClosureHash(provider.Current), newClosureHash))
                throw Error(ProductionMailboxIssueError.IssuerUnavailable,
                    "Published artifact promotion is absent from the active provider.");
            return provider.Current;
        }

        while (!promotion.SweepCompleted)
        {
            var owners = await state.ListOwnerBundlesForPromotionAsync(
                promotionStateKey, 64, cancellationToken);
            if (owners.Count == 0) break;
            foreach (var ownerRecord in owners)
            {
                var previous = JsonSerializer.Deserialize<ProductionMailboxCredentialBundle>(
                    ownerRecord.CanonicalBundle, JsonOptions)
                    ?? throw Error(ProductionMailboxIssueError.IssuerUnavailable,
                        "Durable owner bundle is invalid during artifact promotion.");
                if (previous.Intent != ProductionMailboxIssuanceIntent.LocalOwner
                    || previous.RouteCertificate is null
                    || previous.RouteAdvertisement is null)
                    throw Error(ProductionMailboxIssueError.IssuerUnavailable,
                        "Artifact promotion cohort contains a non-owner or unbound route.");
                var holder = Decode(previous.HolderEd25519PublicKey, 32,
                    "promoted holder key");
                var owner = Decode(previous.MailboxOwnerEd25519PublicKey, 32,
                    "promoted owner key");
                var mailbox = Decode(previous.BlindedMailboxId, 32,
                    "promoted mailbox ID");
                var placement = Decode(previous.BlindedPlacementId, 32,
                    "promoted placement ID");
                var selection = Decode(previous.SelectionInputCommitment, 32,
                    "promoted selection commitment");
                var routeStateKey = StateHmac(
                    "Deep/production-mailbox/owner-route-state/v1", owner,
                    mailbox, placement, selection);
                RequireFixed(routeStateKey, ownerRecord.RouteStateKey,
                    ProductionMailboxIssueError.IssuerUnavailable,
                    "Artifact promotion owner route state binding mismatched.");
                var promotionIdempotencyKey = StateHmac(
                    "Deep/production-mailbox/artifact-promotion-issuance/v1",
                    promotionStateKey, ownerRecord.RouteStateKey,
                    SHA256.HashData(ownerRecord.CanonicalBundle));
                var prepared = await successor.CreatePreparedIssueAsync(
                    holder, owner, ProductionMailboxIssuanceIntent.LocalOwner,
                    mailbox, new BlindedPlacementId(placement), selection,
                    promotionIdempotencyKey, BaseLimits(),
                    ownerRecord.CanonicalBundle, previous.RouteCertificate,
                    previous.RouteAdvertisement, ownerRecord.RouteStateKey,
                    cancellationToken);
                if (!await state.CommitPromotedOwnerAsync(
                        promotionStateKey, ownerRecord, prepared, successor.Now(),
                        cancellationToken))
                    throw Error(ProductionMailboxIssueError.IssuerUnavailable,
                        "Artifact promotion owner transaction conflicted.");
                await successor.PublishPreparedClosureCoreAsync(
                    prepared.PublicationStateKey,
                    SHA256.HashData(prepared.CanonicalResponse), cancellationToken);
            }
            promotion = await state.GetArtifactPromotionAsync(
                    promotionStateKey, cancellationToken)
                ?? throw Error(ProductionMailboxIssueError.IssuerUnavailable,
                    "Artifact promotion state disappeared.");
        }

        if (!await state.CompleteArtifactPromotionSweepAsync(
                promotionStateKey, cancellationToken))
        {
            _ = await successor.DrainPendingPublicationsAsync(256, cancellationToken);
            if (!await state.CompleteArtifactPromotionSweepAsync(
                    promotionStateKey, cancellationToken))
                throw Error(ProductionMailboxIssueError.IssuerUnavailable,
                    "Artifact promotion publication acknowledgement barrier is incomplete.");
        }
        if (Interlocked.Exchange(ref throwBeforeArtifactProviderCutoverOnce, 0) == 1)
            throw new IOException(
                "Injected failure after promotion sweep and before artifact provider cutover.");
        provider.PublishVerified(replacement, successor.Now());
        if (!await state.MarkArtifactPromotionPublishedAsync(
                promotionStateKey, cancellationToken))
            throw Error(ProductionMailboxIssueError.IssuerUnavailable,
                "Artifact promotion publication marker was not committed.");
        return replacement;
    }

    internal async ValueTask<ProductionMailboxArtifacts> PromoteConfiguredArtifactsAsync(
        ProductionMailboxArtifactProvider provider,
        TimeProvider reloadTimeProvider,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentNullException.ThrowIfNull(reloadTimeProvider);
        var activePromotion = await state.GetActiveArtifactPromotionAsync(cancellationToken);
        ProductionMailboxArtifacts replacement;
        if (activePromotion is null)
        {
            replacement = provider.LoadVerifiedSuccessor(reloadTimeProvider);
        }
        else if (Fixed(activePromotion.NewArtifactClosureHash,
                     ArtifactClosureHash(provider.Current)))
        {
            replacement = provider.Current;
        }
        else
        {
            replacement = provider.LoadStagedByArtifactClosureHash(
                activePromotion.NewArtifactClosureHash);
        }
        return await PromoteArtifactsAsync(provider, replacement, cancellationToken);
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
            topology.NetworkId.Span, epoch, selectionCommitment);
        var issuedAt = Math.Max(now, epoch.NotBeforeUnixSeconds);
        var expiresAt = Math.Min(epoch.NotAfterUnixSeconds,
            Math.Min(topology.ExpiresAtUnixSeconds, checked(issuedAt + options.SelectionLifetimeSeconds)));
        if (issuedAt >= expiresAt)
            throw Error(ProductionMailboxIssueError.IssuerUnavailable, "Selection validity window is unavailable.");
        var draft = new ProductionMailboxSelectionProof
        {
            Algorithm = ProductionMailboxSelectionAlgorithm.RendezvousSha256V2,
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

    private static ProductionMailboxGrantEnvelope? TryReplayPromotedGrant(
        ProductionMailboxCredentialBundle? previous,
        byte[] holder,
        MailboxCapabilityDomain domain,
        ProductionMailboxTopologyEpoch currentEpoch)
    {
        if (previous is null || previous.HolderEd25519PublicKey != Base64Url(holder))
            return null;
        var domainName = domain.ToString().ToLowerInvariant();
        return previous.Grants.SingleOrDefault(grant =>
            grant.Domain == domainName && grant.Epoch == currentEpoch.Epoch &&
            grant.Generation == currentEpoch.Generation);
    }

    private async ValueTask<ProductionMailboxCanonicalEnvelope?> CreateSelectionSuccessorAsync(
        ProductionMailboxCredentialBundle? previous,
        byte[] owner,
        byte[] mailboxId,
        byte[] placementId,
        byte[] selectionCommitment,
        ProductionMailboxSelectionEnvelope currentSelectionEnvelope,
        ulong now,
        CancellationToken cancellationToken)
    {
        if (previous is null || previous.Authority.Sha256 == Hex(artifacts.AuthoritySha256) &&
            previous.Topology.Sha256 == Hex(artifacts.TopologySha256))
            return null;
        try
        {
            var oldAuthorityBytes = DecodeVariable(previous.Authority.CanonicalBase64Url,
                ProductionMailboxAuthorityConstants.MaximumArtifactBytes, "previous authority");
            var oldAuthority = ProductionMailboxAuthorityCodec.Decode(oldAuthorityBytes);
            var oldTopologyBytes = DecodeVariable(previous.Topology.CanonicalBase64Url,
                ProductionMailboxTopologyConstants.MaximumTopologyArtifactBytes, "previous topology");
            var oldTopology = ProductionMailboxTopologyCodec.Decode(oldTopologyBytes);
            var newAuthority = artifacts.Authority.Authority;
            var newTopology = artifacts.Topology.Snapshot;
            if (oldAuthority.AuthorityGeneration >= newAuthority.AuthorityGeneration ||
                oldTopology.TopologyGeneration >= newTopology.TopologyGeneration)
                throw Error(ProductionMailboxIssueError.IssuerUnavailable,
                    "Stored mailbox route closure is not a forward predecessor.");
            var direct = newAuthority.AuthorityGeneration == oldAuthority.AuthorityGeneration + 1 &&
                newTopology.TopologyGeneration == oldTopology.TopologyGeneration + 1;
            var mode = direct
                ? ProductionMailboxSelectionSuccessorMode.DirectPromotion
                : ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint;
            var oldSelectionEnvelope = previous.Selections.Single(selection =>
                selection.Epoch == oldTopology.NextEpoch.Epoch &&
                selection.Generation == oldTopology.NextEpoch.Generation);
            var oldSelectionBytes = DecodeVariable(oldSelectionEnvelope.CanonicalBase64Url,
                ProductionMailboxTopologyConstants.MaximumSelectionArtifactBytes,
                "previous next selection");
            var oldSelection = ProductionMailboxTopologyCodec.DecodeSelection(oldSelectionBytes);
            var newSelectionBytes = DecodeVariable(currentSelectionEnvelope.CanonicalBase64Url,
                ProductionMailboxTopologyConstants.MaximumSelectionArtifactBytes,
                "current selection");
            var newSelection = ProductionMailboxTopologyCodec.DecodeSelection(newSelectionBytes);
            var expires = Math.Min(newSelection.ExpiresAtUnixSeconds,
                checked(now + ProductionMailboxSelectionSuccessorConstants.MaximumLifetimeSeconds));
            var draft = new ProductionMailboxSelectionSuccessorProof
            {
                Mode = mode,
                NetworkId = newAuthority.NetworkId,
                OldEpoch = oldSelection.Epoch,
                OldEpochGeneration = oldSelection.Generation,
                NewEpoch = newSelection.Epoch,
                NewEpochGeneration = newSelection.Generation,
                MailboxOwnerEd25519PublicKey = owner,
                BlindedMailboxId = mailboxId,
                BlindedPlacementId = placementId,
                SelectionInputCommitment = selectionCommitment,
                OldCanonicalAuthorityHash = SHA256.HashData(oldAuthorityBytes),
                NewCanonicalAuthorityHash = artifacts.AuthoritySha256,
                OldTopologyGeneration = oldTopology.TopologyGeneration,
                OldCanonicalTopologyHash = SHA256.HashData(oldTopologyBytes),
                NewTopologyGeneration = newTopology.TopologyGeneration,
                NewCanonicalTopologyHash = artifacts.TopologySha256,
                OldCanonicalSelectionHash = SHA256.HashData(oldSelectionBytes),
                NewCanonicalSelectionHash = SHA256.HashData(newSelectionBytes),
                IssuedAtUnixSeconds = now,
                ExpiresAtUnixSeconds = expires,
                CanonicalNewAuthority = artifacts.AuthorityBytes,
                OldCanonicalSelection = oldSelectionBytes,
                NewCanonicalSelection = newSelectionBytes,
                OldIssuerSignature = new byte[64],
                NewIssuerSignature = new byte[64]
            };
            if (direct && !oldAuthority.MailboxIssuerEd25519PublicKey.Span.SequenceEqual(
                    newAuthority.MailboxIssuerEd25519PublicKey.Span))
                throw Error(ProductionMailboxIssueError.IssuerUnavailable,
                    "Direct PSS1 across issuer-key rotation must be pre-issued during rollout.");
            var oldSignature = direct
                ? await SignAndVerifyAsync(
                    ProductionMailboxSelectionSuccessorCodec.GetOldIssuerSigningBytes(draft),
                    oldAuthority.MailboxIssuerEd25519PublicKey, cancellationToken)
                : new byte[64];
            var withOldSignature = draft with { OldIssuerSignature = oldSignature };
            var newSignature = await SignAndVerifyAsync(
                ProductionMailboxSelectionSuccessorCodec.GetNewIssuerSigningBytes(withOldSignature),
                newAuthority.MailboxIssuerEd25519PublicKey, cancellationToken);
            var canonical = ProductionMailboxSelectionSuccessorCodec.Encode(
                withOldSignature with { NewIssuerSignature = newSignature });
            return new("selection-successor.pss1",
                ProductionMailboxMediaTypes.SelectionSuccessor,
                Hex(SHA256.HashData(canonical)), Base64Url(canonical));
        }
        catch (InvalidOperationException exception)
        {
            throw Error(ProductionMailboxIssueError.IssuerUnavailable,
                $"Stored mailbox successor state is invalid: {exception.Message}");
        }
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

    private OwnerRoute DeriveOwnerRoute(byte[] ownerPublicKey)
    {
        var authority = artifacts.Authority.Authority;
        var routeInput = DomainHash(
            "Deep/production-mailbox/owner-route-input/v2",
            authority.NetworkId.ToArray(), ownerPublicKey);
        var mailboxId = DomainHash(
            "Deep/production-mailbox/blinded-mailbox-id/v2",
            authority.NetworkId.ToArray(), ownerPublicKey, routeInput);
        var placementId = DomainHash(
            "Deep/production-mailbox/blinded-placement-id/v2",
            authority.NetworkId.ToArray(), ownerPublicKey, routeInput);
        var selection = ProductionMailboxReplicaSelection.ComputeSelectionInputCommitment(
            new BlindedPlacementId(placementId));
        return new OwnerRoute(mailboxId, placementId, selection);
    }

    private VerifiedRouteAdvertisement VerifyRouteAdvertisement(
        string? encodedAdvertisement, byte[] expectedOwner, byte[] mailboxId,
        byte[] placementId, byte[] selectionCommitment,
        ReadOnlySpan<byte> expectedCertificate,
        bool requireInitialSequence)
    {
        if (string.IsNullOrEmpty(encodedAdvertisement))
            throw Error(ProductionMailboxIssueError.RouteAdvertisementRequired,
                "Peer deposit requires the recipient's owner-signed PRA1.");
        if (IsZero(mailboxId) || IsZero(placementId) || IsZero(selectionCommitment))
            throw Error(ProductionMailboxIssueError.InvalidRequest,
                "Peer deposit requires the recipient's complete public route.");
        try
        {
            var canonical = Decode(encodedAdvertisement,
                ProductionMailboxRouteAdvertisementConstants.CanonicalAdvertisementLength,
                "route advertisement");
            var decoded = ProductionMailboxRouteAdvertisementCodec.DecodeAdvertisement(canonical);
            var canonicalCertificate = ProductionMailboxRouteAdvertisementCodec.EncodeCertificate(
                decoded.Certificate);
            if (!expectedCertificate.IsEmpty
                && !Fixed(canonicalCertificate, expectedCertificate))
                throw Error(ProductionMailboxIssueError.InvalidRequest,
                    "PRA1 does not embed the exact enrolled PRC1.");
            RequireFixed(decoded.Certificate.MailboxOwnerEd25519PublicKey.ToArray(), expectedOwner,
                ProductionMailboxIssueError.InvalidRequest, "PRA1 mailbox owner mismatch.");
            RequireFixed(decoded.Certificate.BlindedMailboxId.ToArray(), mailboxId,
                ProductionMailboxIssueError.InvalidRequest, "PRA1 mailbox ID mismatch.");
            RequireFixed(decoded.Certificate.BlindedPlacementId.ToArray(), placementId,
                ProductionMailboxIssueError.InvalidRequest, "PRA1 placement ID mismatch.");
            RequireFixed(decoded.Certificate.SelectionInputCommitment.ToArray(), selectionCommitment,
                ProductionMailboxIssueError.InvalidRequest, "PRA1 selection input mismatch.");
            var routeDomainHash = ProductionMailboxRouteAdvertisementCodec.ComputeRouteDomainHash(
                decoded.Certificate);
            var verified = ProductionMailboxRouteAdvertisementVerifier.Verify(
                canonical, artifacts.Authority,
                new ProductionMailboxRouteAdvertisementVerificationContext
                {
                    NowUnixSeconds = Now(),
                    ClockSkewSeconds = options.ClockSkewSeconds,
                    ExpectedRouteDomainHash = routeDomainHash,
                    LastAcceptedSequence = 0,
                    LastAcceptedAdvertisementHash = new byte[32]
                }, new SodiumProductionMailboxRouteSignatureVerifier());
            if (requireInitialSequence && verified.NextAcceptedSequence != 1)
                throw Error(ProductionMailboxIssueError.InvalidRequest,
                    "The first enrolled PRA1 must use sequence 1.");
            return new(
                new OwnerRoute(mailboxId, placementId, selectionCommitment),
                canonical, canonicalCertificate, verified.RouteDomainHash.ToArray(),
                verified.NextAcceptedSequence,
                verified.CanonicalAdvertisementHash.ToArray());
        }
        catch (ProductionMailboxRouteAdvertisementException exception)
        {
            throw Error(ProductionMailboxIssueError.RouteAdvertisementRequired,
                $"Peer route advertisement is invalid: {exception.Message}");
        }
    }

    private async ValueTask<LocalEnrollmentBinding> LoadLocalEnrollmentAsync(
        ProductionMailboxIssueRequest request,
        byte[] holder,
        byte[] owner,
        byte[] idempotencyKey,
        CancellationToken cancellationToken)
    {
        var handle = Decode(request.EnrollmentHandle ?? "", 32, "enrollment handle");
        var stateKey = StateHmac(
            "Deep/production-mailbox/route-enrollment-state/v1", handle);
        var canonicalEnrollment = await state.GetRouteEnrollmentAsync(
            stateKey, cancellationToken)
            ?? throw Error(ProductionMailboxIssueError.InvalidRequest,
                "Route enrollment handle is unknown or expired.");
        ProductionMailboxRouteEnrollment enrollment;
        try
        {
            enrollment = JsonSerializer.Deserialize<ProductionMailboxRouteEnrollment>(
                canonicalEnrollment, JsonOptions)
                ?? throw new JsonException();
        }
        catch (JsonException)
        {
            throw Error(ProductionMailboxIssueError.IssuerUnavailable,
                "Stored route enrollment is malformed.");
        }
        if (enrollment.Schema != "production-mailbox-route-enrollment.v1"
            || enrollment.ExpiresAtUnixSeconds < Now())
            throw Error(ProductionMailboxIssueError.InvalidRequest,
                "Route enrollment is expired or unsupported.");
        RequireFixed(Decode(enrollment.EnrollmentHandle, 32, "stored enrollment handle"),
            handle, ProductionMailboxIssueError.InvalidRequest,
            "Route enrollment handle mismatch.");
        RequireFixed(Decode(enrollment.IdempotencyKey, 32, "stored idempotency key"),
            idempotencyKey, ProductionMailboxIssueError.InvalidRequest,
            "Route enrollment idempotency mismatch.");
        RequireFixed(Decode(enrollment.HolderEd25519PublicKey, 32, "stored holder key"),
            holder, ProductionMailboxIssueError.InvalidRequest,
            "Route enrollment holder mismatch.");
        RequireFixed(Decode(enrollment.MailboxOwnerEd25519PublicKey, 32, "stored owner key"),
            owner, ProductionMailboxIssueError.InvalidRequest,
            "Route enrollment owner mismatch.");
        if (enrollment.Authority.Sha256 != Hex(artifacts.AuthoritySha256)
            || enrollment.Revocation.Sha256 != Hex(artifacts.RevocationSha256)
            || enrollment.Topology.Sha256 != Hex(artifacts.TopologySha256))
            throw Error(ProductionMailboxIssueError.InvalidRequest,
                "Route enrollment artifact closure is not current.");
        var route = new OwnerRoute(
            Decode(enrollment.BlindedMailboxId, 32, "enrolled mailbox ID"),
            Decode(enrollment.BlindedPlacementId, 32, "enrolled placement ID"),
            Decode(enrollment.SelectionInputCommitment, 32, "enrolled selection input"));
        var expectedRoute = DeriveOwnerRoute(owner);
        RequireFixed(route.MailboxId, expectedRoute.MailboxId,
            ProductionMailboxIssueError.InvalidRequest, "Enrolled mailbox route mismatch.");
        RequireFixed(route.PlacementId, expectedRoute.PlacementId,
            ProductionMailboxIssueError.InvalidRequest, "Enrolled placement route mismatch.");
        RequireFixed(route.SelectionInputCommitment, expectedRoute.SelectionInputCommitment,
            ProductionMailboxIssueError.InvalidRequest, "Enrolled selection route mismatch.");
        var certificate = Decode(enrollment.RouteCertificate.CanonicalBase64Url,
            ProductionMailboxRouteAdvertisementConstants.CanonicalCertificateLength,
            "enrolled route certificate");
        if (enrollment.RouteCertificate.Sha256 != Hex(SHA256.HashData(certificate)))
            throw Error(ProductionMailboxIssueError.InvalidRequest,
                "Enrolled route certificate hash mismatch.");
        _ = ProductionMailboxRouteCertificateVerifier.Verify(
            certificate, artifacts.Authority, Now(), options.ClockSkewSeconds,
            new SodiumProductionMailboxRouteSignatureVerifier());
        var advertisement = VerifyRouteAdvertisement(
            request.RouteAdvertisement, owner, route.MailboxId, route.PlacementId,
            route.SelectionInputCommitment, certificate, requireInitialSequence: false);
        var advertisementEnvelope = new ProductionMailboxCanonicalEnvelope(
            "route-advertisement.pra1", ProductionMailboxMediaTypes.RouteAdvertisement,
            Hex(advertisement.CanonicalAdvertisementHash),
            Base64Url(advertisement.CanonicalAdvertisement));
        return new(stateKey, route, enrollment.RouteCertificate,
            advertisementEnvelope, advertisement);
    }

    private async ValueTask<ProductionMailboxCanonicalEnvelope> CreateRouteCertificateAsync(
        byte[] owner, byte[] mailboxId, byte[] placementId, byte[] selectionCommitment,
        ulong now, CancellationToken cancellationToken)
    {
        var authority = artifacts.Authority.Authority;
        var expires = Math.Min(authority.CurrentEpoch.NotAfterUnixSeconds,
            Math.Min(authority.MrXApproval.RolloutNotAfterUnixSeconds,
                Math.Min(authority.Revocation.ExpiresAtUnixSeconds,
                    checked(now + ProductionMailboxRouteAdvertisementConstants.MaximumLifetimeSeconds))));
        var draft = new ProductionMailboxRouteCertificate
        {
            NetworkId = authority.NetworkId,
            AuthorityGeneration = authority.AuthorityGeneration,
            CanonicalAuthorityHash = artifacts.AuthoritySha256,
            IssuerEd25519PublicKey = authority.MailboxIssuerEd25519PublicKey,
            MailboxOwnerEd25519PublicKey = owner,
            BlindedMailboxId = mailboxId,
            BlindedPlacementId = placementId,
            SelectionInputCommitment = selectionCommitment,
            IssuedAtUnixSeconds = now,
            ExpiresAtUnixSeconds = expires,
            IssuerSignature = new byte[64]
        };
        var signature = await SignAndVerifyAsync(
            ProductionMailboxRouteAdvertisementCodec.GetCertificateSigningBytes(draft),
            authority.MailboxIssuerEd25519PublicKey, cancellationToken);
        var canonical = ProductionMailboxRouteAdvertisementCodec.EncodeCertificate(
            draft with { IssuerSignature = signature });
        return new("route-certificate.prc1", ProductionMailboxMediaTypes.RouteCertificate,
            Hex(SHA256.HashData(canonical)), Base64Url(canonical));
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

    private byte[] ArtifactClosureHash() => ArtifactClosureHash(artifacts);

    private static byte[] ArtifactClosureHash(ProductionMailboxArtifacts snapshot) => DomainHash(
        "Deep/production-mailbox/challenge-artifact-closure/v1",
        snapshot.AuthoritySha256, snapshot.RevocationSha256, snapshot.TopologySha256);

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
    private byte[] StateHmac(string domain, params byte[][] values)
    {
        using var hmac = IncrementalHash.CreateHMAC(
            HashAlgorithmName.SHA256, routeStateHmacKey);
        hmac.AppendData(Encoding.UTF8.GetBytes(domain));
        foreach (var value in values)
            hmac.AppendData(value);
        return hmac.GetHashAndReset();
    }
    private static byte[] ReadRouteStateHmacKey(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            throw new InvalidOperationException("Production mailbox route-state HMAC key path is missing.");
        var fullPath = Path.GetFullPath(path);
        var callback = Interlocked.Exchange(
            ref routeStateKeyAfterActualOpenForTests, null);
        var value = ProductionMailboxProtectedFile.ReadStable(
            fullPath, 32, 32,
            () => ProductionMailboxArtifactProvider.EnsureNoReparseAncestors(fullPath),
            callback);
        if (value.AsSpan().IndexOfAnyExcept((byte)0) < 0)
            throw new InvalidOperationException("Production mailbox route-state HMAC key is invalid.");
        return value;
    }
    private ulong Now() => checked((ulong)timeProvider.GetUtcNow().ToUnixTimeSeconds());
    private static ProductionMailboxIssueException Error(ProductionMailboxIssueError error, string message) => new(error, message);

    private static void ValidateOptions(ProductionMailboxOptions options)
    {
        if (!options.Enabled || options.ClockSkewSeconds > 300 ||
            options.SelectionLifetimeSeconds is 0 or > 86_400 ||
            options.ChallengeLifetimeSeconds is 0 or > 3600 ||
            options.ExternalSignerTimeoutSeconds is 0 or > 30 ||
            options.ClosurePublisherSignerTimeoutSeconds is 0 or > 30 ||
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

    private sealed record VerifiedRouteAdvertisement(
        OwnerRoute Route,
        byte[] CanonicalAdvertisement,
        byte[] CanonicalCertificate,
        byte[] RouteDomainHash,
        ulong Sequence,
        byte[] CanonicalAdvertisementHash);

    private sealed record LocalEnrollmentBinding(
        byte[] EnrollmentStateKey,
        OwnerRoute Route,
        ProductionMailboxCanonicalEnvelope RouteCertificate,
        ProductionMailboxCanonicalEnvelope RouteAdvertisement,
        VerifiedRouteAdvertisement VerifiedAdvertisement);
}
