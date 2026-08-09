extern alias xnode;

using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Deep.Protocol.DeepExtension.MailboxAuthority;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.MailboxTopology;
using Deep.Protocol.DeepExtension.MembershipRoutes;
using Deep.Registry.Api.ProductionMailbox;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Hosting;
using Npgsql;
using Sodium;

namespace Deep.Registry.Api.Tests;

public sealed class ProductionMailboxCoordinatorTests
{
    [Fact]
    public async Task ChallengePublishesAndBindsExactArtifactClosure()
    {
        using var fixture = Fixture.Create();
        var state = new InMemoryProductionMailboxStateStore();
        using var signer = new DevelopmentSoftwareEd25519Signer(fixture.IssuerSeedPath);
        var coordinator = fixture.Coordinator(state, signer);

        var challenge = await coordinator.CreateChallengeAsync(CancellationToken.None);
        foreach (var pair in new[]
                 {
                     (challenge.Authority, fixture.Artifacts.AuthorityBytes),
                     (challenge.Revocation, fixture.Artifacts.RevocationBytes),
                     (challenge.Topology, fixture.Artifacts.TopologyBytes)
                 })
        {
            Assert.Equal(pair.Item2, Decode(pair.Item1.CanonicalBase64Url));
            Assert.Equal(pair.Item1.Sha256,
                Convert.ToHexStringLower(SHA256.HashData(pair.Item2)));
        }

        var directState = new InMemoryProductionMailboxStateStore();
        var closure = Fixture.Bytes(200, 32);
        var created = await directState.CreateChallengeAsync(
            Fixture.Now, Fixture.Now + 60, closure, 1, Fixture.Now - 60,
            CancellationToken.None);
        Assert.NotNull(created);
        var wrongClosure = Fixture.Bytes(201, 32);
        Assert.Null(await directState.ConsumeChallengeAndIssueAsync(
            created.ChallengeId, created.Challenge, Fixture.Now, Fixture.Now + 60,
            wrongClosure, Fixture.Bytes(202, 32),
            _ => ValueTask.FromResult(Fixture.Bytes(203, 32)), CancellationToken.None));
        Assert.NotNull(await directState.ConsumeChallengeAndIssueAsync(
            created.ChallengeId, created.Challenge, Fixture.Now, Fixture.Now + 60,
            closure, Fixture.Bytes(202, 32),
            _ => ValueTask.FromResult(Fixture.Bytes(203, 32)), CancellationToken.None));
    }

    [Fact]
    public async Task AnonymousBaseIssuance_IsCanonicalIdempotentAndBindsCurrentNext()
    {
        using var fixture = Fixture.Create();
        var state = new InMemoryProductionMailboxStateStore();
        using var signer = new DevelopmentSoftwareEd25519Signer(fixture.IssuerSeedPath);
        var coordinator = fixture.Coordinator(state, signer);
        var request = await fixture.RequestAsync(coordinator);
        var first = await coordinator.IssueAsync(request, CancellationToken.None);
        var secondRequest = await fixture.RequestAsync(coordinator);
        var second = await coordinator.IssueAsync(secondRequest, CancellationToken.None);

        Assert.Equal("production-mailbox-credential-bundle.v1", first.Schema);
        Assert.False(first.Limits.Entitled);
        Assert.Equal(64UL * 1024 * 1024, first.Limits.StoredBytes);
        Assert.Equal(first.IdempotencyKey, second.IdempotencyKey);
        Assert.Equal(first.Selections.Select(x => x.CanonicalBase64Url),
            second.Selections.Select(x => x.CanonicalBase64Url));
        Assert.Equal(first.Grants.Select(x => x.CanonicalBase64Url),
            second.Grants.Select(x => x.CanonicalBase64Url));
        Assert.Equal(2, first.Selections.Count);
        Assert.Equal(2, first.Grants.Count);
        Assert.Equal(ProductionMailboxIssuanceIntent.LocalOwner, first.Intent);
        Assert.NotNull(first.RouteCertificate);
        var verifiedRouteCertificate = ProductionMailboxRouteCertificateVerifier.Verify(
            Decode(first.RouteCertificate.CanonicalBase64Url), fixture.Artifacts.Authority,
            Fixture.Now, 0, new SodiumProductionMailboxRouteSignatureVerifier());
        Assert.Equal(fixture.OwnerPublicKey,
            verifiedRouteCertificate.Certificate.MailboxOwnerEd25519PublicKey.ToArray());
        Assert.All(first.Grants, grant => Assert.Equal("retrieve", grant.Domain));
        foreach (var artifact in new[] { first.Authority, first.Revocation, first.Topology })
        {
            var canonical = Decode(artifact.CanonicalBase64Url);
            Assert.Equal(artifact.Sha256, Convert.ToHexStringLower(SHA256.HashData(canonical)));
            Assert.Equal($"/api/production-mailbox/artifacts/{artifact.Sha256}/{artifact.FileName}",
                artifact.ContentPath);
        }

        foreach (var selection in first.Selections)
        {
            Assert.Equal(2, selection.Replicas.Count);
            Assert.All(selection.Replicas, replica => Assert.NotEqual(
                replica.CurrentSpkiSha256, replica.NextSpkiSha256));
            var canonical = Decode(selection.CanonicalBase64Url);
            var verified = ProductionMailboxSelectionVerifier.Verify(
                canonical, fixture.Artifacts.Authority, fixture.Artifacts.Topology,
                new BlindedPlacementId(Decode(first.BlindedPlacementId)), Fixture.Now, 0,
                new SodiumProductionMailboxTopologySignatureVerifier());
            Assert.Equal(2, verified.Replicas.Count);
        }
        foreach (var grantEnvelope in first.Grants)
        {
            var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(
                Decode(grantEnvelope.CanonicalBase64Url));
            Assert.Equal(fixture.HolderPublicKey, grant.HolderPublicKey.ToArray());
            Assert.Equal(MailboxPlacementCommitment.Compute(
                new BlindedPlacementId(Decode(first.BlindedPlacementId))), grant.PlacementCommitment.ToArray());
            Assert.True(new SodiumMailboxCapabilityCrypto().VerifyIssuer(
                fixture.IssuerPublicKey,
                MailboxAuthenticatedCapabilityCodec.GetGrantSigningBytes(grant),
                grant.IssuerSignature.Span));
        }
        var counters = coordinator.GetCounters();
        Assert.Equal(1, counters.BundlesIssued);
        Assert.Equal(1, counters.BundlesReplayed);
        var responseJson = System.Text.Json.JsonSerializer.Serialize(first);
        Assert.DoesNotContain(request.Challenge, responseJson, StringComparison.Ordinal);
        Assert.DoesNotContain(request.HolderProofSignature, responseJson, StringComparison.Ordinal);
        Assert.DoesNotContain(request.SigningCertificateSha256, responseJson, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TwoPhaseEnrollment_ReplaysExactPrcAndRejectsCrossEnrollmentSubstitution()
    {
        using var fixture = Fixture.Create(maximumChallenges: 32);
        var state = new InMemoryProductionMailboxStateStore();
        using var signer = new DevelopmentSoftwareEd25519Signer(fixture.IssuerSeedPath);
        var coordinator = fixture.Coordinator(state, signer);

        var firstCredentialRequest = await fixture.RequestAsync(coordinator);
        var enrollmentReplayRequest = fixture.Resign(firstCredentialRequest with
        {
            EnrollmentHandle = null,
            RouteAdvertisement = null
        });
        var replayedEnrollment = await coordinator.EnrollRouteAsync(
            enrollmentReplayRequest, CancellationToken.None);
        Assert.Equal(firstCredentialRequest.EnrollmentHandle,
            replayedEnrollment.EnrollmentHandle);
        var firstAdvertisement = ProductionMailboxRouteAdvertisementCodec.DecodeAdvertisement(
            Decode(firstCredentialRequest.RouteAdvertisement!));
        Assert.Equal(
            Decode(replayedEnrollment.RouteCertificate.CanonicalBase64Url),
            ProductionMailboxRouteAdvertisementCodec.EncodeCertificate(
                firstAdvertisement.Certificate));
        var enrollmentJson = System.Text.Json.JsonSerializer.Serialize(replayedEnrollment);
        Assert.DoesNotContain("grants", enrollmentJson, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("selections", enrollmentJson, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(1, coordinator.GetCounters().EnrollmentsIssued);
        Assert.Equal(1, coordinator.GetCounters().EnrollmentsReplayed);

        var credentialRequest = await fixture.RequestAsync(coordinator);
        var bundle = await coordinator.IssueAsync(credentialRequest, CancellationToken.None);
        Assert.Equal(replayedEnrollment.RouteCertificate.CanonicalBase64Url,
            bundle.RouteCertificate!.CanonicalBase64Url);
        Assert.Equal(credentialRequest.RouteAdvertisement,
            bundle.RouteAdvertisement!.CanonicalBase64Url);

        var attackerHolder = PublicKeyAuth.GenerateKeyPair(Fixture.Bytes(181, 32));
        var attackerOwner = PublicKeyAuth.GenerateKeyPair(Fixture.Bytes(182, 32));
        var attacker = await fixture.RequestAsync(
            coordinator, ProductionMailboxIssuanceIntent.LocalOwner,
            attackerHolder.PublicKey, attackerHolder.PrivateKey,
            attackerOwner.PublicKey, attackerOwner.PrivateKey);
        var victim = await fixture.RequestAsync(coordinator);
        var crossEnrollment = fixture.Resign(victim with
        {
            EnrollmentHandle = attacker.EnrollmentHandle,
            RouteAdvertisement = attacker.RouteAdvertisement
        });
        Assert.Equal(ProductionMailboxIssueError.InvalidRequest,
            (await Assert.ThrowsAsync<ProductionMailboxIssueException>(() =>
                coordinator.IssueAsync(crossEnrollment, CancellationToken.None).AsTask())).Error);

        var victimAdvertisement = ProductionMailboxRouteAdvertisementCodec.DecodeAdvertisement(
            Decode(victim.RouteAdvertisement!));
        var substitutedCertificateDraft = victimAdvertisement with
        {
            Certificate = victimAdvertisement.Certificate with
            {
                ExpiresAtUnixSeconds = victimAdvertisement.Certificate.ExpiresAtUnixSeconds - 1
            },
            ExpiresAtUnixSeconds = victimAdvertisement.ExpiresAtUnixSeconds - 1,
            OwnerSignature = new byte[64]
        };
        var substitutedCertificate = substitutedCertificateDraft with
        {
            OwnerSignature = PublicKeyAuth.SignDetached(
                ProductionMailboxRouteAdvertisementCodec.GetAdvertisementSigningBytes(
                    substitutedCertificateDraft), fixture.OwnerPrivateKey)
        };
        var exactEnrollmentSubstitution = fixture.Resign(victim with
        {
            RouteAdvertisement = B64(
                ProductionMailboxRouteAdvertisementCodec.EncodeAdvertisement(
                    substitutedCertificate))
        });
        Assert.Equal(ProductionMailboxIssueError.InvalidRequest,
            (await Assert.ThrowsAsync<ProductionMailboxIssueException>(() =>
                coordinator.IssueAsync(exactEnrollmentSubstitution,
                    CancellationToken.None).AsTask())).Error);
    }

    [Fact]
    public async Task ConcurrentIssuance_ReturnsOneDeterministicOutcome()
    {
        using var fixture = Fixture.Create(maximumChallenges: 32);
        var state = new InMemoryProductionMailboxStateStore();
        using var signer = new DevelopmentSoftwareEd25519Signer(fixture.IssuerSeedPath);
        var coordinator = fixture.Coordinator(state, signer);
        var requests = new List<ProductionMailboxIssueRequest>();
        for (var index = 0; index < 12; index++) requests.Add(await fixture.RequestAsync(coordinator));
        var bundles = await Task.WhenAll(requests.Select(request =>
            coordinator.IssueAsync(request, CancellationToken.None).AsTask()));
        Assert.Single(bundles.Select(bundle => bundle.IdempotencyKey).Distinct(StringComparer.Ordinal));
        Assert.Single(bundles.Select(bundle => bundle.Grants[0].CanonicalBase64Url).Distinct(StringComparer.Ordinal));
        Assert.Equal(1, coordinator.GetCounters().BundlesIssued);
        Assert.Equal(11, coordinator.GetCounters().BundlesReplayed);
    }

    [Fact]
    public async Task SelectionAttestationChallengeRevocationAndSignerFailures_FailClosed()
    {
        using var fixture = Fixture.Create();
        var state = new InMemoryProductionMailboxStateStore();
        using var signer = new DevelopmentSoftwareEd25519Signer(fixture.IssuerSeedPath);
        var coordinator = fixture.Coordinator(state, signer);

        var mismatch = await fixture.RequestAsync(coordinator);
        mismatch = mismatch with { SelectionInputCommitment = B64(Fixture.Bytes(220, 32)) };
        Assert.Equal(ProductionMailboxIssueError.InvalidHolderProof,
            (await Assert.ThrowsAsync<ProductionMailboxIssueException>(() =>
                coordinator.IssueAsync(mismatch, CancellationToken.None).AsTask())).Error);

        var badAttestation = await fixture.RequestAsync(
            coordinator, ProductionMailboxIssuanceIntent.LocalOwner,
            fixture.HolderPublicKey, fixture.HolderPrivateKey,
            fixture.OwnerPublicKey, fixture.OwnerPrivateKey,
            buildArtifact: Fixture.Bytes(221, 32));
        var metadataOnly = await coordinator.IssueAsync(badAttestation, CancellationToken.None);
        Assert.Equal(badAttestation.HolderEd25519PublicKey, metadataOnly.HolderEd25519PublicKey);

        var consumed = await fixture.RequestAsync(coordinator);
        _ = await coordinator.IssueAsync(consumed, CancellationToken.None);
        Assert.Equal(ProductionMailboxIssueError.InvalidChallenge,
            (await Assert.ThrowsAsync<ProductionMailboxIssueException>(() =>
                coordinator.IssueAsync(consumed, CancellationToken.None).AsTask())).Error);

        var revoked = await fixture.RequestAsync(coordinator);
        await coordinator.RevokeHolderAsync(fixture.HolderPublicKey, CancellationToken.None);
        Assert.Equal(ProductionMailboxIssueError.Revoked,
            (await Assert.ThrowsAsync<ProductionMailboxIssueException>(() =>
                coordinator.IssueAsync(revoked, CancellationToken.None).AsTask())).Error);

        var badSignatureState = new InMemoryProductionMailboxStateStore();
        var enrollmentCoordinator = fixture.Coordinator(badSignatureState, signer);
        var badSignature = await fixture.RequestAsync(enrollmentCoordinator);
        var badSignatureCoordinator = fixture.Coordinator(
            badSignatureState, new InvalidSigner());
        Assert.Equal(ProductionMailboxIssueError.IssuerUnavailable,
            (await Assert.ThrowsAsync<ProductionMailboxIssueException>(() =>
                badSignatureCoordinator.IssueAsync(badSignature, CancellationToken.None).AsTask())).Error);
    }

    [Fact]
    public async Task PaidEntitlement_IsRejectedUntilNodeEnforcedQuotaExists()
    {
        using var fixture = Fixture.Create();
        using var signer = new DevelopmentSoftwareEd25519Signer(fixture.IssuerSeedPath);
        var coordinator = fixture.Coordinator(new InMemoryProductionMailboxStateStore(), signer);
        var request = await fixture.RequestAsync(coordinator);
        request = fixture.Resign(request with
        { OpaqueEntitlement = B64(Encoding.ASCII.GetBytes("opaque-paid-proof")) });
        Assert.Equal(ProductionMailboxIssueError.InvalidEntitlement,
            (await Assert.ThrowsAsync<ProductionMailboxIssueException>(() =>
                coordinator.IssueAsync(request, CancellationToken.None).AsTask())).Error);
    }

    [Fact]
    public async Task HolderProof_BindsCanonicalIdempotencyAndOpaqueEntitlement()
    {
        using var fixture = Fixture.Create(maximumChallenges: 8);
        using var signer = new DevelopmentSoftwareEd25519Signer(fixture.IssuerSeedPath);
        var coordinator = fixture.Coordinator(new InMemoryProductionMailboxStateStore(), signer);

        var wrongIdempotency = await fixture.RequestAsync(coordinator);
        wrongIdempotency = fixture.SignExact(wrongIdempotency with
        { IdempotencyKey = B64(Fixture.Bytes(201, 32)) });
        Assert.Equal(ProductionMailboxIssueError.InvalidRequest,
            (await Assert.ThrowsAsync<ProductionMailboxIssueException>(() =>
                coordinator.IssueAsync(wrongIdempotency, CancellationToken.None).AsTask())).Error);

        var substituted = await fixture.RequestAsync(coordinator);
        substituted = fixture.Resign(substituted with
        { OpaqueEntitlement = B64(Encoding.ASCII.GetBytes("opaque-paid-proof")) });
        substituted = substituted with
        { OpaqueEntitlement = B64(Encoding.ASCII.GetBytes("substituted-proof")) };
        Assert.Equal(ProductionMailboxIssueError.InvalidEntitlement,
            (await Assert.ThrowsAsync<ProductionMailboxIssueException>(() =>
                coordinator.IssueAsync(substituted, CancellationToken.None).AsTask())).Error);
    }

    [Fact]
    public async Task OwnerBinding_PreventsFirstClaim_AllowsRotation_AndPeerGetsDepositOnly()
    {
        using var fixture = Fixture.Create(maximumChallenges: 32);
        var state = new InMemoryProductionMailboxStateStore();
        using var signer = new DevelopmentSoftwareEd25519Signer(fixture.IssuerSeedPath);
        var coordinator = fixture.Coordinator(state, signer);
        var original = await coordinator.IssueAsync(
            await fixture.RequestAsync(coordinator), CancellationToken.None);
        var ownerStateKey = Assert.Single(state.SnapshotOwnerRouteStateKeys());
        Assert.False(ownerStateKey.AsSpan().SequenceEqual(fixture.OwnerPublicKey));
        Assert.False(ownerStateKey.AsSpan().SequenceEqual(Decode(original.BlindedMailboxId)));
        Assert.False(ownerStateKey.AsSpan().SequenceEqual(Decode(original.BlindedPlacementId)));

        var rotatedHolder = PublicKeyAuth.GenerateKeyPair(Fixture.Bytes(140, 32));
        var rotation = await fixture.RequestAsync(
            coordinator, ProductionMailboxIssuanceIntent.LocalOwner,
            rotatedHolder.PublicKey, rotatedHolder.PrivateKey,
            fixture.OwnerPublicKey, fixture.OwnerPrivateKey);
        var rotated = await coordinator.IssueAsync(rotation, CancellationToken.None);
        Assert.Equal(original.BlindedMailboxId, rotated.BlindedMailboxId);
        Assert.Equal(original.BlindedPlacementId, rotated.BlindedPlacementId);
        Assert.All(rotated.Grants, grant => Assert.Equal(
            rotatedHolder.PublicKey,
            MailboxAuthenticatedCapabilityCodec.DecodeGrant(Decode(grant.CanonicalBase64Url))
                .HolderPublicKey.ToArray()));

        var attackerHolder = PublicKeyAuth.GenerateKeyPair(Fixture.Bytes(150, 32));
        var attackerOwner = PublicKeyAuth.GenerateKeyPair(Fixture.Bytes(160, 32));
        var attackerRequest = await fixture.RequestAsync(
            coordinator, ProductionMailboxIssuanceIntent.LocalOwner,
            attackerHolder.PublicKey, attackerHolder.PrivateKey,
            attackerOwner.PublicKey, attackerOwner.PrivateKey);
        var attackerBundle = await coordinator.IssueAsync(attackerRequest, CancellationToken.None);
        Assert.NotEqual(original.BlindedMailboxId, attackerBundle.BlindedMailboxId);
        Assert.NotEqual(original.BlindedPlacementId, attackerBundle.BlindedPlacementId);

        var peer = await fixture.RequestAsync(
            coordinator, ProductionMailboxIssuanceIntent.PeerDeposit,
            attackerHolder.PublicKey, attackerHolder.PrivateKey,
            fixture.OwnerPublicKey, null);
        Assert.Equal(ProductionMailboxIssueError.RouteAdvertisementRequired,
            (await Assert.ThrowsAsync<ProductionMailboxIssueException>(() =>
                coordinator.IssueAsync(peer, CancellationToken.None).AsTask())).Error);

        var certificate = ProductionMailboxRouteAdvertisementCodec.DecodeCertificate(
            Decode(original.RouteCertificate!.CanonicalBase64Url));
        var advertisementDraft = new ProductionMailboxRouteAdvertisement
        {
            Certificate = certificate,
            Sequence = 1,
            PublishedAtUnixSeconds = Fixture.Now,
            ExpiresAtUnixSeconds = certificate.ExpiresAtUnixSeconds,
            OwnerSignature = new byte[64]
        };
        var advertisement = advertisementDraft with
        {
            OwnerSignature = PublicKeyAuth.SignDetached(
                ProductionMailboxRouteAdvertisementCodec.GetAdvertisementSigningBytes(
                    advertisementDraft), fixture.OwnerPrivateKey)
        };
        var advertisedPeer = fixture.Resign(peer with
        {
            RouteAdvertisement = B64(
                ProductionMailboxRouteAdvertisementCodec.EncodeAdvertisement(advertisement))
        }, attackerHolder.PrivateKey, null);
        var peerBundle = await coordinator.IssueAsync(advertisedPeer, CancellationToken.None);
        Assert.Equal(ProductionMailboxIssuanceIntent.PeerDeposit, peerBundle.Intent);
        Assert.Null(peerBundle.RouteCertificate);
        Assert.All(peerBundle.Grants, grant => Assert.Equal("deposit", grant.Domain));
        var advertisementStateKeys = state.SnapshotAdvertisementStateKeys();
        Assert.Equal(2, advertisementStateKeys.Count);
        Assert.All(advertisementStateKeys, advertisementStateKey =>
            Assert.False(advertisementStateKey.AsSpan().SequenceEqual(
                ProductionMailboxRouteAdvertisementCodec.ComputeRouteDomainHash(certificate))));

        var tamperedPeer = await fixture.RequestAsync(
            coordinator, ProductionMailboxIssuanceIntent.PeerDeposit,
            attackerHolder.PublicKey, attackerHolder.PrivateKey,
            fixture.OwnerPublicKey, null);
        var tamperedSignature = advertisement.OwnerSignature.ToArray();
        tamperedSignature[0] ^= 0x01;
        tamperedPeer = fixture.Resign(tamperedPeer with
        {
            RouteAdvertisement = B64(ProductionMailboxRouteAdvertisementCodec
                .EncodeAdvertisement(advertisement with
                {
                    OwnerSignature = tamperedSignature
                }))
        }, attackerHolder.PrivateKey, null);
        Assert.Equal(ProductionMailboxIssueError.RouteAdvertisementRequired,
            (await Assert.ThrowsAsync<ProductionMailboxIssueException>(() =>
                coordinator.IssueAsync(tamperedPeer, CancellationToken.None).AsTask())).Error);

        var crossOwnerPeer = await fixture.RequestAsync(
            coordinator, ProductionMailboxIssuanceIntent.PeerDeposit,
            attackerHolder.PublicKey, attackerHolder.PrivateKey,
            attackerOwner.PublicKey, null);
        crossOwnerPeer = fixture.Resign(crossOwnerPeer with
        {
            BlindedMailboxId = original.BlindedMailboxId,
            BlindedPlacementId = original.BlindedPlacementId,
            SelectionInputCommitment = original.SelectionInputCommitment,
            RouteAdvertisement = B64(ProductionMailboxRouteAdvertisementCodec
                .EncodeAdvertisement(advertisement))
        }, attackerHolder.PrivateKey, null);
        Assert.Equal(ProductionMailboxIssueError.InvalidRequest,
            (await Assert.ThrowsAsync<ProductionMailboxIssueException>(() =>
                coordinator.IssueAsync(crossOwnerPeer, CancellationToken.None).AsTask())).Error);

        var intentReplay = peer with { Intent = ProductionMailboxIssuanceIntent.LocalOwner };
        Assert.Equal(ProductionMailboxIssueError.InvalidHolderProof,
            (await Assert.ThrowsAsync<ProductionMailboxIssueException>(() =>
                coordinator.IssueAsync(intentReplay, CancellationToken.None).AsTask())).Error);

        await coordinator.RevokeHolderAsync(fixture.HolderPublicKey, CancellationToken.None);
        var afterRevocation = await fixture.RequestAsync(
            coordinator, ProductionMailboxIssuanceIntent.LocalOwner,
            rotatedHolder.PublicKey, rotatedHolder.PrivateKey,
            fixture.OwnerPublicKey, fixture.OwnerPrivateKey);
        _ = await coordinator.IssueAsync(afterRevocation, CancellationToken.None);
    }

    [Fact]
    public async Task RouteAdvertisementState_IsMonotonicIdempotentAndRejectsForks()
    {
        var state = new InMemoryProductionMailboxStateStore();
        var key = Fixture.Bytes(0x31, 32);
        var first = Fixture.Bytes(0x32, 32);
        var second = Fixture.Bytes(0x33, 32);

        Assert.Equal(ProductionMailboxRouteAdvertisementAcceptance.Accepted,
            await state.AcceptRouteAdvertisementAsync(key, 2, first, CancellationToken.None));
        Assert.Equal(ProductionMailboxRouteAdvertisementAcceptance.ExactReplay,
            await state.AcceptRouteAdvertisementAsync(key, 2, first, CancellationToken.None));
        Assert.Equal(ProductionMailboxRouteAdvertisementAcceptance.Conflict,
            await state.AcceptRouteAdvertisementAsync(key, 2, second, CancellationToken.None));
        Assert.Equal(ProductionMailboxRouteAdvertisementAcceptance.Accepted,
            await state.AcceptRouteAdvertisementAsync(key, 3, second, CancellationToken.None));
        Assert.Equal(ProductionMailboxRouteAdvertisementAcceptance.Rollback,
            await state.AcceptRouteAdvertisementAsync(key, 2, first, CancellationToken.None));
    }

    [Fact]
    public async Task TwoPhaseState_CallbackFailureRollsBackAndExactRetryReplays()
    {
        var state = new InMemoryProductionMailboxStateStore();
        var closure = Fixture.Bytes(190, 32);
        var enrollmentKey = Fixture.Bytes(191, 32);
        var idempotency = Fixture.Bytes(192, 32);
        var enrollmentResponse = Fixture.Bytes(193, 64);
        var challenge = await state.CreateChallengeAsync(
            Fixture.Now, Fixture.Now + 60, closure, 8, Fixture.Now - 60,
            CancellationToken.None);
        Assert.NotNull(challenge);
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await state.ConsumeChallengeAndEnrollAsync(
                challenge.ChallengeId, challenge.Challenge, Fixture.Now,
                Fixture.Now + 60, closure, enrollmentKey, idempotency,
                _ => throw new InvalidOperationException("injected before commit"),
                CancellationToken.None));
        var enrolled = await state.ConsumeChallengeAndEnrollAsync(
            challenge.ChallengeId, challenge.Challenge, Fixture.Now,
            Fixture.Now + 60, closure, enrollmentKey, idempotency,
            _ => ValueTask.FromResult(enrollmentResponse), CancellationToken.None);
        Assert.NotNull(enrolled);
        Assert.False(enrolled.Replayed);
        Assert.Equal(enrollmentResponse, enrolled.CanonicalResponse);

        var routeState = Fixture.Bytes(194, 32);
        var advertisementHash = Fixture.Bytes(195, 32);
        var credentialResponse = Fixture.Bytes(196, 80);
        var credentialChallenge = await state.CreateChallengeAsync(
            Fixture.Now, Fixture.Now + 60, closure, 8, Fixture.Now - 60,
            CancellationToken.None);
        Assert.NotNull(credentialChallenge);
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await state.ConsumeChallengeAcceptAdvertisementAndIssueAsync(
                credentialChallenge.ChallengeId, credentialChallenge.Challenge,
                Fixture.Now, Fixture.Now + 60, closure, idempotency, enrollmentKey,
                routeState, 1, advertisementHash,
                _ => throw new InvalidOperationException("injected before commit"),
                CancellationToken.None));
        var issued = await state.ConsumeChallengeAcceptAdvertisementAndIssueAsync(
            credentialChallenge.ChallengeId, credentialChallenge.Challenge,
            Fixture.Now, Fixture.Now + 60, closure, idempotency, enrollmentKey,
            routeState, 1, advertisementHash,
            _ => ValueTask.FromResult(new ProductionMailboxPreparedIssue(
                credentialResponse, [], [], [])), CancellationToken.None);
        Assert.Equal(ProductionMailboxIssueCommitStatus.Accepted, issued.Status);
        Assert.Equal(credentialResponse, issued.CanonicalResponse);

        var replayChallenge = await state.CreateChallengeAsync(
            Fixture.Now, Fixture.Now + 60, closure, 8, Fixture.Now - 60,
            CancellationToken.None);
        Assert.NotNull(replayChallenge);
        var replayed = await state.ConsumeChallengeAcceptAdvertisementAndIssueAsync(
            replayChallenge.ChallengeId, replayChallenge.Challenge,
            Fixture.Now, Fixture.Now + 60, closure, idempotency, enrollmentKey,
            routeState, 1, advertisementHash,
            _ => throw new InvalidOperationException("replay must not invoke callback"),
            CancellationToken.None);
        Assert.Equal(ProductionMailboxIssueCommitStatus.Replayed, replayed.Status);
        Assert.Equal(credentialResponse, replayed.CanonicalResponse);
    }

    [Fact]
    public async Task PostgreSqlTwoPhaseState_ExpiredDeterministicKeysRenewConcurrently()
    {
        var connectionString = Environment.GetEnvironmentVariable("DEEP_TEST_POSTGRES");
        if (string.IsNullOrWhiteSpace(connectionString)) return;

        await using var database = await PostgresTestDatabase.CreateAsync(connectionString);
        var state = new PostgreSqlProductionMailboxStateStore(database.ConnectionString);
        var prefix = RandomNumberGenerator.GetBytes(16);
        byte[] Key(byte suffix) => SHA256.HashData([.. prefix, suffix]);
        const ulong firstNow = 1_000_000;
        var closure = Key(1);
        var enrollmentStateKey = Key(2);
        var enrollmentIdempotencyKey = Key(3);

        var firstEnrollmentChallenge = await state.CreateChallengeAsync(
            firstNow, firstNow + 60, closure, 100, firstNow - 60,
            CancellationToken.None);
        Assert.NotNull(firstEnrollmentChallenge);
        var firstEnrollment = await state.ConsumeChallengeAndEnrollAsync(
            firstEnrollmentChallenge.ChallengeId,
            firstEnrollmentChallenge.Challenge,
            firstNow, firstNow + 10, closure, enrollmentStateKey,
            enrollmentIdempotencyKey,
            _ => ValueTask.FromResult(Key(4)), CancellationToken.None);
        Assert.NotNull(firstEnrollment);
        Assert.False(firstEnrollment.Replayed);

        const ulong renewalNow = firstNow + 11;
        var enrollmentChallenges = new[]
        {
            await state.CreateChallengeAsync(
                renewalNow, renewalNow + 120, closure, 100, renewalNow - 60,
                CancellationToken.None),
            await state.CreateChallengeAsync(
                renewalNow, renewalNow + 120, closure, 100, renewalNow - 60,
                CancellationToken.None)
        };
        Assert.All(enrollmentChallenges, Assert.NotNull);
        var enrollmentCallbacks = 0;
        var renewedEnrollmentResponse = Key(5);
        var enrollmentRenewals = await Task.WhenAll(enrollmentChallenges.Select(
            challenge => state.ConsumeChallengeAndEnrollAsync(
                challenge!.ChallengeId, challenge.Challenge,
                renewalNow, renewalNow + 120, closure, enrollmentStateKey,
                enrollmentIdempotencyKey,
                _ =>
                {
                    Interlocked.Increment(ref enrollmentCallbacks);
                    return ValueTask.FromResult(renewedEnrollmentResponse);
                }, CancellationToken.None).AsTask()));
        Assert.Equal(1, enrollmentCallbacks);
        Assert.All(enrollmentRenewals, Assert.NotNull);
        Assert.Equal(1, enrollmentRenewals.Count(static result => result!.Replayed));
        Assert.All(enrollmentRenewals, result =>
            Assert.Equal(renewedEnrollmentResponse, result!.CanonicalResponse));

        var issuanceIdempotencyKey = Key(6);
        var routeDomainHash = Key(7);
        var advertisementHash = Key(8);
        var firstIssueChallenge = await state.CreateChallengeAsync(
            renewalNow, renewalNow + 60, closure, 100, renewalNow - 60,
            CancellationToken.None);
        Assert.NotNull(firstIssueChallenge);
        var firstIssue = await state.ConsumeChallengeAcceptAdvertisementAndIssueAsync(
            firstIssueChallenge.ChallengeId, firstIssueChallenge.Challenge,
            renewalNow, renewalNow + 10, closure, issuanceIdempotencyKey,
            enrollmentStateKey, routeDomainHash, 1, advertisementHash,
            _ => ValueTask.FromResult(new ProductionMailboxPreparedIssue(
                Key(9), [], [], [])), CancellationToken.None);
        Assert.Equal(ProductionMailboxIssueCommitStatus.Accepted, firstIssue.Status);

        const ulong issueRenewalNow = renewalNow + 11;
        var renewedAdvertisementHash = Key(11);
        var issueChallenges = new[]
        {
            await state.CreateChallengeAsync(
                issueRenewalNow, issueRenewalNow + 60, closure, 100,
                issueRenewalNow - 60, CancellationToken.None),
            await state.CreateChallengeAsync(
                issueRenewalNow, issueRenewalNow + 60, closure, 100,
                issueRenewalNow - 60, CancellationToken.None)
        };
        Assert.All(issueChallenges, Assert.NotNull);
        var issueCallbacks = 0;
        var renewedIssueResponse = Key(10);
        var issueRenewals = await Task.WhenAll(issueChallenges.Select(
            challenge => state.ConsumeChallengeAcceptAdvertisementAndIssueAsync(
                challenge!.ChallengeId, challenge.Challenge,
                issueRenewalNow, issueRenewalNow + 60, closure,
                issuanceIdempotencyKey, enrollmentStateKey, routeDomainHash,
                2, renewedAdvertisementHash,
                _ =>
                {
                    Interlocked.Increment(ref issueCallbacks);
                    return ValueTask.FromResult(new ProductionMailboxPreparedIssue(
                        renewedIssueResponse, [], [], []));
                }, CancellationToken.None).AsTask()));
        Assert.Equal(1, issueCallbacks);
        Assert.Equal(1, issueRenewals.Count(static result =>
            result.Status == ProductionMailboxIssueCommitStatus.Replayed));
        Assert.Equal(1, issueRenewals.Count(static result =>
            result.Status == ProductionMailboxIssueCommitStatus.Accepted));
        Assert.All(issueRenewals, result =>
            Assert.Equal(renewedIssueResponse, result.CanonicalResponse));

        var liveForkChallenge = await state.CreateChallengeAsync(
            issueRenewalNow, issueRenewalNow + 60, closure, 100,
            issueRenewalNow - 60, CancellationToken.None);
        Assert.NotNull(liveForkChallenge);
        var liveFork = await state.ConsumeChallengeAcceptAdvertisementAndIssueAsync(
            liveForkChallenge.ChallengeId, liveForkChallenge.Challenge,
            issueRenewalNow, issueRenewalNow + 60, closure,
            issuanceIdempotencyKey, enrollmentStateKey, routeDomainHash,
            3, Key(12), _ => throw new InvalidOperationException(
                "live issuance fork must not invoke callback"), CancellationToken.None);
        Assert.Equal(ProductionMailboxIssueCommitStatus.IssuanceConflict,
            liveFork.Status);

        var rollbackChallenge = await state.CreateChallengeAsync(
            issueRenewalNow, issueRenewalNow + 60, closure, 100,
            issueRenewalNow - 60, CancellationToken.None);
        Assert.NotNull(rollbackChallenge);
        var rollback = await state.ConsumeChallengeAcceptAdvertisementAndIssueAsync(
            rollbackChallenge.ChallengeId, rollbackChallenge.Challenge,
            issueRenewalNow, issueRenewalNow + 60, closure, Key(13),
            enrollmentStateKey, routeDomainHash, 1, advertisementHash,
            _ => throw new InvalidOperationException(
                "advertisement rollback must not invoke callback"),
            CancellationToken.None);
        Assert.Equal(ProductionMailboxIssueCommitStatus.AdvertisementRollback,
            rollback.Status);

        var routeForkChallenge = await state.CreateChallengeAsync(
            issueRenewalNow, issueRenewalNow + 60, closure, 100,
            issueRenewalNow - 60, CancellationToken.None);
        Assert.NotNull(routeForkChallenge);
        var routeFork = await state.ConsumeChallengeAcceptAdvertisementAndIssueAsync(
            routeForkChallenge.ChallengeId, routeForkChallenge.Challenge,
            issueRenewalNow, issueRenewalNow + 60, closure, Key(14),
            enrollmentStateKey, routeDomainHash, 2, Key(15),
            _ => throw new InvalidOperationException(
                "advertisement fork must not invoke callback"),
            CancellationToken.None);
        Assert.Equal(ProductionMailboxIssueCommitStatus.AdvertisementConflict,
            routeFork.Status);
    }

    [Fact]
    public async Task PostgreSqlCapacityPlan_PersistsExactAttemptReceiptAndAtomicBarrier()
    {
        var connectionString = Environment.GetEnvironmentVariable("DEEP_TEST_POSTGRES");
        if (string.IsNullOrWhiteSpace(connectionString)) return;
        await using var database = await PostgresTestDatabase.CreateAsync(connectionString);
        var state = new PostgreSqlProductionMailboxStateStore(database.ConnectionString);
        var prefix = RandomNumberGenerator.GetBytes(16);
        byte[] Key(byte suffix) => SHA256.HashData([.. prefix, suffix]);
        var now = checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        var routeKey = Key(1);
        await state.StoreLatestOwnerBundleAsync(
            routeKey, Key(2), now, CancellationToken.None);
        var promotionKey = Key(3);
        _ = await state.BeginArtifactPromotionAsync(
            promotionKey, Key(4), Key(5), CancellationToken.None);
        var owner = Assert.Single(await state.ListOwnerBundlesForCapacityPlanningAsync(
            promotionKey, 8, CancellationToken.None));
        var node = PublicKeyAuth.GenerateKeyPair(Key(6));
        var envelope = Fixture.Bytes(0xA7, 80);
        var item = new ProductionMailboxPublicationItem(
            Key(7), node.PublicKey, "https://pg-capacity.example/", Key(8), Key(9),
            [], envelope, SHA256.HashData(envelope), promotionKey);
        Assert.True(await state.CommitCapacityPlannedOwnerAsync(
            promotionKey, owner, [item], 1024, CancellationToken.None));
        Assert.True(await state.CompleteCapacityPlanAsync(
            promotionKey, CancellationToken.None));
        var target = Assert.Single((await state.GetCapacityPlanAsync(
            promotionKey, CancellationToken.None))!.Targets);
        var command = Fixture.Bytes(0xAA,
            ProductionMailboxCapacityCommandCodec.EncodedLength);
        Assert.Equal(command, await state.GetOrRecordCapacityAttemptAsync(
            promotionKey, target.TargetReplicaId, 0, 1, command,
            CancellationToken.None));
        Assert.Equal(command, await state.GetOrRecordCapacityAttemptAsync(
            promotionKey, target.TargetReplicaId, 0, 1,
            Fixture.Bytes(0xAB, command.Length), CancellationToken.None));
        var unsigned = new ProductionMailboxCapacityReceipt(
            ProductionMailboxCapacityOperation.ReserveOrRenew,
            now, now + 1_000, promotionKey, target.TargetReplicaId,
            target.ReservedClosureCount, target.ReservedBytes, 0, 0, 1,
            SHA256.HashData(command), new byte[64]);
        var receipt = unsigned with
        {
            NodeSignature = PublicKeyAuth.SignDetached(
                ProductionMailboxCapacityReceiptCodec.GetSigningBytes(unsigned),
                node.PrivateKey)
        };
        Assert.True(await state.RecordCapacityReceiptAsync(
            promotionKey, target.TargetReplicaId, 0, receipt,
            ProductionMailboxCapacityReceiptCodec.Encode(receipt),
            CancellationToken.None));
        var prepared = new ProductionMailboxPreparedIssue(
            Key(10), routeKey, Key(11), [item]);
        Assert.True(await state.CommitPromotedOwnerAsync(
            promotionKey, owner, prepared, now, 300, CancellationToken.None));
        var durable = await state.GetCapacityPlanAsync(
            promotionKey, CancellationToken.None);
        Assert.Equal(1UL, Assert.Single(durable!.Targets).Revision);
        Assert.Null(Assert.Single(durable.Targets).PendingCanonicalCommand);

        var attemptHash = Key(12);
        Assert.True(await state.RecordPublicationAttemptAsync(
            prepared.PublicationStateKey, item.TargetStateKey,
            item.EnvelopeSha256, attemptHash, now, CancellationToken.None));
        Assert.True(await state.AcknowledgePublicationAsync(
            prepared.PublicationStateKey, item.TargetStateKey,
            item.EnvelopeSha256, attemptHash, CancellationToken.None));
        Assert.True(await state.CompleteArtifactPromotionSweepAsync(
            promotionKey, CancellationToken.None));
        Assert.True(await state.MarkArtifactPromotionPublishedAsync(
            promotionKey, CancellationToken.None));
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            state.BeginArtifactPromotionAsync(
                Key(13), Key(5), Key(14), CancellationToken.None).AsTask());

        var releaseCommand = Fixture.Bytes(0xAC,
            ProductionMailboxCapacityCommandCodec.EncodedLength);
        Assert.Equal(releaseCommand, await state.GetOrRecordCapacityAttemptAsync(
            promotionKey, target.TargetReplicaId, 1, 2, releaseCommand,
            CancellationToken.None));
        var unsignedRelease = new ProductionMailboxCapacityReceipt(
            ProductionMailboxCapacityOperation.Release,
            now, now + 1_000, promotionKey, target.TargetReplicaId,
            0, 0, 0, 0, 2, SHA256.HashData(releaseCommand), new byte[64]);
        var release = unsignedRelease with
        {
            NodeSignature = PublicKeyAuth.SignDetached(
                ProductionMailboxCapacityReceiptCodec.GetSigningBytes(unsignedRelease),
                node.PrivateKey)
        };
        Assert.True(await state.RecordCapacityReceiptAsync(
            promotionKey, target.TargetReplicaId, 1, release,
            ProductionMailboxCapacityReceiptCodec.Encode(release),
            CancellationToken.None));
        Assert.True(await state.MarkArtifactPromotionCapacityReleasedAsync(
            promotionKey, CancellationToken.None));
        var nextPromotion = await state.BeginArtifactPromotionAsync(
            Key(13), Key(5), Key(14), CancellationToken.None);
        Assert.False(nextPromotion.Published);
    }

    [Fact]
    public async Task PostgreSqlPromotionCommit_RechecksCapacityAtFinalCursorBoundary()
    {
        var connectionString = Environment.GetEnvironmentVariable("DEEP_TEST_POSTGRES");
        if (string.IsNullOrWhiteSpace(connectionString)) return;
        await using var database = await PostgresTestDatabase.CreateAsync(connectionString);
        var state = new PostgreSqlProductionMailboxStateStore(database.ConnectionString)
        {
            CommitPromotedOwnerDelayBeforeFinalCapacityCheck =
                TimeSpan.FromMilliseconds(2_100)
        };
        var prefix = RandomNumberGenerator.GetBytes(16);
        byte[] Key(byte suffix) => SHA256.HashData([.. prefix, suffix]);
        var now = checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        var routeKey = Key(1);
        var originalBundle = Key(2);
        await state.StoreLatestOwnerBundleAsync(
            routeKey, originalBundle, now, CancellationToken.None);
        var promotionKey = Key(3);
        _ = await state.BeginArtifactPromotionAsync(
            promotionKey, Key(4), Key(5), CancellationToken.None);
        var owner = Assert.Single(await state.ListOwnerBundlesForCapacityPlanningAsync(
            promotionKey, 8, CancellationToken.None));
        var node = PublicKeyAuth.GenerateKeyPair(Key(6));
        var envelope = Fixture.Bytes(0xB7, 80);
        var item = new ProductionMailboxPublicationItem(
            Key(7), node.PublicKey, "https://pg-capacity-delay.example/",
            Key(8), Key(9), [], envelope, SHA256.HashData(envelope), promotionKey);
        Assert.True(await state.CommitCapacityPlannedOwnerAsync(
            promotionKey, owner, [item], 1024, CancellationToken.None));
        Assert.True(await state.CompleteCapacityPlanAsync(
            promotionKey, CancellationToken.None));
        var target = Assert.Single((await state.GetCapacityPlanAsync(
            promotionKey, CancellationToken.None))!.Targets);
        var command = Fixture.Bytes(0xBA,
            ProductionMailboxCapacityCommandCodec.EncodedLength);
        Assert.Equal(command, await state.GetOrRecordCapacityAttemptAsync(
            promotionKey, target.TargetReplicaId, 0, 1, command,
            CancellationToken.None));
        var unsigned = new ProductionMailboxCapacityReceipt(
            ProductionMailboxCapacityOperation.ReserveOrRenew,
            now, now + 5, promotionKey, target.TargetReplicaId,
            target.ReservedClosureCount, target.ReservedBytes, 0, 0, 1,
            SHA256.HashData(command), new byte[64]);
        var receipt = unsigned with
        {
            NodeSignature = PublicKeyAuth.SignDetached(
                ProductionMailboxCapacityReceiptCodec.GetSigningBytes(unsigned),
                node.PrivateKey)
        };
        Assert.True(await state.RecordCapacityReceiptAsync(
            promotionKey, target.TargetReplicaId, 0, receipt,
            ProductionMailboxCapacityReceiptCodec.Encode(receipt),
            CancellationToken.None));
        var prepared = new ProductionMailboxPreparedIssue(
            Key(10), routeKey, Key(11), [item]);

        Assert.False(await state.CommitPromotedOwnerAsync(
            promotionKey, owner, prepared, now, 4, CancellationToken.None));

        var pendingOwner = Assert.Single(await state.ListOwnerBundlesForPromotionAsync(
            promotionKey, 8, CancellationToken.None));
        Assert.Equal(originalBundle, pendingOwner.CanonicalBundle);
        Assert.Null(await state.GetPublicationAsync(
            prepared.PublicationStateKey, CancellationToken.None));
    }

    [Fact]
    public async Task PostgreSqlCapacityRevisionCap_LeavesExactTerminalReleaseSlot()
    {
        var connectionString = Environment.GetEnvironmentVariable("DEEP_TEST_POSTGRES");
        if (string.IsNullOrWhiteSpace(connectionString)) return;
        await using var database = await PostgresTestDatabase.CreateAsync(connectionString);
        var state = new PostgreSqlProductionMailboxStateStore(database.ConnectionString);
        var prefix = RandomNumberGenerator.GetBytes(16);
        byte[] Key(byte suffix) => SHA256.HashData([.. prefix, suffix]);
        var now = checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        var routeKey = Key(1);
        await state.StoreLatestOwnerBundleAsync(
            routeKey, Key(2), now, CancellationToken.None);
        var promotionKey = Key(3);
        _ = await state.BeginArtifactPromotionAsync(
            promotionKey, Key(4), Key(5), CancellationToken.None);
        var owner = Assert.Single(await state.ListOwnerBundlesForCapacityPlanningAsync(
            promotionKey, 8, CancellationToken.None));
        var node = PublicKeyAuth.GenerateKeyPair(Key(6));
        var envelope = Fixture.Bytes(0xC1, 80);
        var item = new ProductionMailboxPublicationItem(
            Key(7), node.PublicKey, "https://pg-capacity-max.example/",
            Key(8), Key(9), [], envelope, SHA256.HashData(envelope), promotionKey);
        Assert.True(await state.CommitCapacityPlannedOwnerAsync(
            promotionKey, owner, [item], 1024, CancellationToken.None));
        Assert.True(await state.CompleteCapacityPlanAsync(
            promotionKey, CancellationToken.None));
        await using (var connection = new NpgsqlConnection(database.ConnectionString))
        {
            await connection.OpenAsync();
            await using var command = new NpgsqlCommand(
                "UPDATE production_mailbox_capacity_targets SET revision=@revision WHERE promotion_state_key=@key",
                connection);
            command.Parameters.AddWithValue("revision", long.MaxValue - 1);
            command.Parameters.AddWithValue("key", promotionKey);
            Assert.Equal(1, await command.ExecuteNonQueryAsync());
        }
        var target = Assert.Single((await state.GetCapacityPlanAsync(
            promotionKey, CancellationToken.None))!.Targets);
        var terminalRevision = (ulong)long.MaxValue;
        var releaseCommand = Fixture.Bytes(0xC2,
            ProductionMailboxCapacityCommandCodec.EncodedLength);
        Assert.Equal(releaseCommand, await state.GetOrRecordCapacityAttemptAsync(
            promotionKey, target.TargetReplicaId, terminalRevision - 1,
            terminalRevision, releaseCommand, CancellationToken.None));

        ProductionMailboxCapacityReceipt Receipt(
            ProductionMailboxCapacityOperation operation)
        {
            var unsigned = new ProductionMailboxCapacityReceipt(
                operation, now, now + 1_000, promotionKey,
                target.TargetReplicaId,
                operation == ProductionMailboxCapacityOperation.Release
                    ? 0 : target.ReservedClosureCount,
                operation == ProductionMailboxCapacityOperation.Release
                    ? 0 : target.ReservedBytes,
                0, 0, terminalRevision, SHA256.HashData(releaseCommand),
                new byte[64]);
            return unsigned with
            {
                NodeSignature = PublicKeyAuth.SignDetached(
                    ProductionMailboxCapacityReceiptCodec.GetSigningBytes(unsigned),
                    node.PrivateKey)
            };
        }

        var nonterminal = Receipt(ProductionMailboxCapacityOperation.ReserveOrRenew);
        Assert.False(await state.RecordCapacityReceiptAsync(
            promotionKey, target.TargetReplicaId, terminalRevision - 1,
            nonterminal, ProductionMailboxCapacityReceiptCodec.Encode(nonterminal),
            CancellationToken.None));
        var release = Receipt(ProductionMailboxCapacityOperation.Release);
        Assert.True(await state.RecordCapacityReceiptAsync(
            promotionKey, target.TargetReplicaId, terminalRevision - 1,
            release, ProductionMailboxCapacityReceiptCodec.Encode(release),
            CancellationToken.None));
        Assert.Null(await state.GetOrRecordCapacityAttemptAsync(
            promotionKey, target.TargetReplicaId, terminalRevision,
            terminalRevision + 1, Fixture.Bytes(0xC3,
                ProductionMailboxCapacityCommandCodec.EncodedLength),
            CancellationToken.None));
    }

    [Fact]
    public void CapacityRevisionPolicy_ReservesTerminalSlotForRelease()
    {
        var maximum = ProductionMailboxCapacityRevisionPolicy.MaximumStoredRevision;
        Assert.True(ProductionMailboxCapacityRevisionPolicy.CanIssueSuccessor(
            maximum - 2, ProductionMailboxCapacityOperation.ReserveOrRenew));
        Assert.False(ProductionMailboxCapacityRevisionPolicy.CanIssueSuccessor(
            maximum - 1, ProductionMailboxCapacityOperation.ReserveOrRenew));
        Assert.True(ProductionMailboxCapacityRevisionPolicy.CanIssueSuccessor(
            maximum - 1, ProductionMailboxCapacityOperation.Release));
        Assert.False(ProductionMailboxCapacityRevisionPolicy.CanIssueSuccessor(
            maximum, ProductionMailboxCapacityOperation.Release));

        ProductionMailboxCapacityReceipt Receipt(
            ProductionMailboxCapacityOperation operation, ulong revision) => new(
                operation, 1, 2, Fixture.Bytes(1, 32), Fixture.Bytes(2, 32),
                0, 0, 0, 0, revision, Fixture.Bytes(3, 32), new byte[64]);
        Assert.True(ProductionMailboxCapacityRevisionPolicy.IsStorableReceipt(
            Receipt(ProductionMailboxCapacityOperation.ReserveOrRenew, maximum - 1)));
        Assert.False(ProductionMailboxCapacityRevisionPolicy.IsStorableReceipt(
            Receipt(ProductionMailboxCapacityOperation.ReserveOrRenew, maximum)));
        Assert.True(ProductionMailboxCapacityRevisionPolicy.IsStorableReceipt(
            Receipt(ProductionMailboxCapacityOperation.Release, maximum)));
        Assert.False(ProductionMailboxCapacityRevisionPolicy.IsStorableReceipt(
            Receipt(ProductionMailboxCapacityOperation.Release, maximum + 1)));
    }

    [Fact]
    public void ProductionComposition_RejectsSoftwareSignerAndMissingSocket()
    {
        using var fixture = Fixture.Create();
        var software = fixture.OptionsDictionary();
        software["ProductionMailbox:DevelopmentSoftwareSignerSeedPath"] = fixture.IssuerSeedPath;
        software["ProductionMailbox:ExternalSignerSocketPath"] = "";
        Assert.True(Assert.ThrowsAny<Exception>(() => ResolveSigner(software))
            is InvalidOperationException or PlatformNotSupportedException);

        var missing = fixture.OptionsDictionary();
        missing["ProductionMailbox:DevelopmentSoftwareSignerSeedPath"] = "";
        missing["ProductionMailbox:ExternalSignerSocketPath"] = "";
        Assert.True(Assert.ThrowsAny<Exception>(() => ResolveSigner(missing))
            is InvalidOperationException or PlatformNotSupportedException);
    }

    [Fact]
    public void CoordinatorConstruction_RejectsLinkedAndSwappedRouteStateKey()
    {
        using var fixture = Fixture.Create();
        using var signer = new DevelopmentSoftwareEd25519Signer(
            fixture.IssuerSeedPath);
        var root = Path.Combine(Path.GetTempPath(), "deep-route-key-tests",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var key = File.ReadAllBytes(fixture.Options.RouteStateHmacKeyPath);
            var target = Path.Combine(root, "target.key");
            File.WriteAllBytes(target, key);
            var leafLink = Path.Combine(root, "leaf-link.key");
            File.CreateSymbolicLink(leafLink, target);
            fixture.Options.RouteStateHmacKeyPath = leafLink;
            Assert.ThrowsAny<Exception>(() => fixture.Coordinator(
                new InMemoryProductionMailboxStateStore(), signer));

            var targetDirectory = Path.Combine(root, "target-directory");
            Directory.CreateDirectory(targetDirectory);
            File.WriteAllBytes(Path.Combine(targetDirectory, "state.key"), key);
            var ancestorLink = Path.Combine(root, "ancestor-link");
            Directory.CreateSymbolicLink(ancestorLink, targetDirectory);
            fixture.Options.RouteStateHmacKeyPath = Path.Combine(
                ancestorLink, "state.key");
            Assert.ThrowsAny<Exception>(() => fixture.Coordinator(
                new InMemoryProductionMailboxStateStore(), signer));

            var swap = Path.Combine(root, "swap.key");
            var replacement = Path.Combine(root, "replacement.key");
            var backup = Path.Combine(root, "backup.key");
            File.WriteAllBytes(swap, key);
            File.WriteAllBytes(replacement, Fixture.Bytes(0xAC, 32));
            fixture.Options.RouteStateHmacKeyPath = swap;
            ProductionMailboxCoordinator.RouteStateKeyAfterActualOpenForTests = () =>
            {
                File.Move(swap, backup);
                File.Move(replacement, swap);
            };
            Assert.Throws<InvalidDataException>(() => fixture.Coordinator(
                new InMemoryProductionMailboxStateStore(), signer));
        }
        finally
        {
            ProductionMailboxCoordinator.RouteStateKeyAfterActualOpenForTests = null;
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void ArtifactLoad_RejectsStaleOrTamperedClosure()
    {
        using var fixture = Fixture.Create();
        var stale = new FixedTimeProvider(DateTimeOffset.FromUnixTimeSeconds(
            checked((long)Fixture.Now + 10_000)));
        Assert.ThrowsAny<Exception>(() => ProductionMailboxArtifacts.Load(fixture.Options, stale));
        var bytes = File.ReadAllBytes(fixture.Options.TopologyPath);
        bytes[^1] ^= 1;
        File.WriteAllBytes(fixture.Options.TopologyPath, bytes);
        Assert.Throws<ProductionMailboxTopologyException>(() =>
            ProductionMailboxArtifacts.Load(fixture.Options, fixture.TimeProvider));
    }

    [Fact]
    public async Task ArtifactFreshness_IsCheckedPerRequestBeforeIssuerUse()
    {
        using var fixture = Fixture.Create();
        var state = new InMemoryProductionMailboxStateStore();
        using var enrollmentSigner = new DevelopmentSoftwareEd25519Signer(
            fixture.IssuerSeedPath);
        var enrollmentCoordinator = fixture.Coordinator(state, enrollmentSigner);
        var request = await fixture.RequestAsync(enrollmentCoordinator);
        var signer = new CountingSigner();
        var coordinator = fixture.Coordinator(state, signer);
        fixture.TimeProvider.Set(Fixture.Now + 2_000);

        Assert.Equal(ProductionMailboxIssueError.IssuerUnavailable,
            (await Assert.ThrowsAsync<ProductionMailboxIssueException>(() =>
                coordinator.IssueAsync(request, CancellationToken.None).AsTask())).Error);
        Assert.Equal(0, signer.Calls);
        Assert.Equal(ProductionMailboxIssueError.IssuerUnavailable,
            (await Assert.ThrowsAsync<ProductionMailboxIssueException>(() =>
                coordinator.CreateChallengeAsync(CancellationToken.None).AsTask())).Error);
    }

    [Fact]
    public async Task IssueReloadInterleaving_RetainsExactContentAddressedClosure()
    {
        using var first = Fixture.Create();
        using var second = Fixture.Create(artifactSeedOffset: 1);
        var provider = new ProductionMailboxArtifactProvider(first.Options, first.TimeProvider);
        using var signer = new DevelopmentSoftwareEd25519Signer(first.IssuerSeedPath);
        var coordinator = new ProductionMailboxCoordinator(
            Microsoft.Extensions.Options.Options.Create(first.Options), provider.Current, signer,
            new InMemoryProductionMailboxStateStore(), first.TimeProvider,
            new ProductionMailboxMetrics(),
            new ProductionMailboxClosurePublisherSignerAdapter(signer),
            new AcceptingClosureTransport());
        var request = await first.RequestAsync(coordinator);
        var oldAuthorityHash = Convert.ToHexStringLower(first.Artifacts.AuthoritySha256);

        provider.PublishVerified(second.Artifacts, Fixture.Now);
        var bundle = await coordinator.IssueAsync(request, CancellationToken.None);

        Assert.Equal(oldAuthorityHash, bundle.Authority.Sha256);
        Assert.Equal(first.Artifacts.AuthorityBytes, Decode(bundle.Authority.CanonicalBase64Url));
        Assert.True(provider.TryGetArtifact(oldAuthorityHash, "authority.pma1",
            out var retained, out var mediaType));
        Assert.Equal(first.Artifacts.AuthorityBytes, retained);
        Assert.Equal(ProductionMailboxMediaTypes.Authority, mediaType);
        Assert.NotEqual(oldAuthorityHash,
            Convert.ToHexStringLower(provider.Current.AuthoritySha256));
    }

    [Fact]
    public async Task RotationIssuesVerifiableDirectPssAndReplaysExactPromotedGrant()
    {
        using var first = Fixture.Create();
        var state = new InMemoryProductionMailboxStateStore();
        using var firstSigner = new DevelopmentSoftwareEd25519Signer(first.IssuerSeedPath);
        var firstCoordinator = first.Coordinator(state, firstSigner);
        var oldBundle = await firstCoordinator.IssueAsync(
            await first.RequestAsync(firstCoordinator), CancellationToken.None);
        using var second = Fixture.CreateRotation(first);
        using var secondSigner = new DevelopmentSoftwareEd25519Signer(second.IssuerSeedPath);
        var secondCoordinator = second.Coordinator(state, secondSigner);
        var candidate = await second.RequestAsync(secondCoordinator);
        var candidateAdvertisement = ProductionMailboxRouteAdvertisementCodec.DecodeAdvertisement(
            Decode(candidate.RouteAdvertisement!));
        var rollbackDraft = candidateAdvertisement with
        {
            Sequence = 1,
            OwnerSignature = new byte[64]
        };
        var rollback = rollbackDraft with
        {
            OwnerSignature = PublicKeyAuth.SignDetached(
                ProductionMailboxRouteAdvertisementCodec.GetAdvertisementSigningBytes(
                    rollbackDraft), second.OwnerPrivateKey)
        };
        var rollbackRequest = second.Resign(candidate with
        {
            RouteAdvertisement = B64(
                ProductionMailboxRouteAdvertisementCodec.EncodeAdvertisement(rollback))
        });
        Assert.Equal(ProductionMailboxIssueError.InvalidRequest,
            (await Assert.ThrowsAsync<ProductionMailboxIssueException>(() =>
                secondCoordinator.IssueAsync(
                    rollbackRequest, CancellationToken.None).AsTask())).Error);
        var newBundle = await secondCoordinator.IssueAsync(
            await second.RequestAsync(secondCoordinator), CancellationToken.None);

        Assert.NotNull(newBundle.SelectionSuccessor);
        var oldTopology = first.Artifacts.Topology.Snapshot;
        var oldNextSelection = oldBundle.Selections.Single(value =>
            value.Epoch == oldTopology.NextEpoch.Epoch &&
            value.Generation == oldTopology.NextEpoch.Generation);
        var verified = ProductionMailboxSelectionSuccessorVerifier.VerifyDirectPromotion(
            Decode(newBundle.SelectionSuccessor.CanonicalBase64Url),
            first.Artifacts.Authority, first.Artifacts.Topology,
            second.Artifacts.Authority, second.Artifacts.Topology,
            new ProductionMailboxSelectionSuccessorVerificationContext
            {
                ExpectedNetworkId = second.Artifacts.Authority.Authority.NetworkId,
                ExpectedMailboxOwnerEd25519PublicKey = second.OwnerPublicKey,
                ExpectedBlindedMailboxId = Decode(newBundle.BlindedMailboxId),
                ExpectedBlindedPlacementId = Decode(newBundle.BlindedPlacementId),
                PinnedMrXPublicKeySha256 = Convert.FromHexString(
                    second.Options.PinnedMrXPublicKeySha256),
                ExpectedOldCanonicalSelectionHash = SHA256.HashData(
                    Decode(oldNextSelection.CanonicalBase64Url)),
                NowUnixSeconds = Fixture.Now,
                ClockSkewSeconds = 0
            }, new SodiumProductionMailboxAuthoritySignatureVerifier(),
            new SodiumProductionMailboxTopologySignatureVerifier(),
            new SodiumProductionMailboxSelectionSuccessorSignatureVerifier());
        Assert.Equal(ProductionMailboxSelectionSuccessorMode.DirectPromotion,
            verified.Proof.Mode);

        var oldNextGrant = oldBundle.Grants.Single(value =>
            value.Epoch == oldTopology.NextEpoch.Epoch &&
            value.Generation == oldTopology.NextEpoch.Generation);
        var promotedCurrentGrant = newBundle.Grants.Single(value =>
            value.Epoch == second.Artifacts.Topology.Snapshot.CurrentEpoch.Epoch &&
            value.Generation == second.Artifacts.Topology.Snapshot.CurrentEpoch.Generation);
        Assert.Equal(oldNextGrant.CanonicalBase64Url, promotedCurrentGrant.CanonicalBase64Url);
    }

    [Fact]
    public async Task PublicationRetryRenewsFreshPmpAttemptAfterOriginalAttemptExpires()
    {
        using var first = Fixture.Create();
        var state = new InMemoryProductionMailboxStateStore();
        using var firstSigner = new DevelopmentSoftwareEd25519Signer(first.IssuerSeedPath);
        var firstCoordinator = first.Coordinator(state, firstSigner);
        _ = await firstCoordinator.IssueAsync(
            await first.RequestAsync(firstCoordinator), CancellationToken.None);

        using var second = Fixture.CreateRotation(first);
        using var secondSigner = new DevelopmentSoftwareEd25519Signer(second.IssuerSeedPath);
        var transport = new SwitchableClosureTransport { Accept = false };
        var coordinator = second.Coordinator(state, secondSigner, transport);
        var request = await second.RequestAsync(coordinator);
        Assert.Equal(ProductionMailboxIssueError.IssuerUnavailable,
            (await Assert.ThrowsAsync<ProductionMailboxIssueException>(() =>
                coordinator.IssueAsync(request, CancellationToken.None).AsTask())).Error);
        var firstAttemptHashes = transport.CommandHashes.ToArray();
        Assert.NotEmpty(firstAttemptHashes);
        Assert.NotEmpty(await state.ListPendingPublicationKeysAsync(8, CancellationToken.None));

        second.TimeProvider.Set(Fixture.Now + 301);
        transport.Accept = true;
        var replay = await second.RequestAsync(coordinator);
        _ = await coordinator.IssueAsync(replay, CancellationToken.None);

        var renewed = transport.CommandHashes.Skip(firstAttemptHashes.Length).ToArray();
        Assert.Equal(firstAttemptHashes.Length, renewed.Length);
        Assert.All(firstAttemptHashes.Zip(renewed), pair => Assert.NotEqual(pair.First, pair.Second));
        Assert.Empty(await state.ListPendingPublicationKeysAsync(8, CancellationToken.None));
    }

    [Fact]
    public async Task ProactivePromotion_FencesLateOwnersAndResumesAfterAtomicCommitCrash()
    {
        using var first = Fixture.Create(maximumChallenges: 32);
        var state = new InMemoryProductionMailboxStateStore();
        using var firstSigner = new DevelopmentSoftwareEd25519Signer(first.IssuerSeedPath);
        var firstCoordinator = first.Coordinator(state, firstSigner);
        var oldBundle = await firstCoordinator.IssueAsync(
            await first.RequestAsync(firstCoordinator), CancellationToken.None);
        var secondHolder = PublicKeyAuth.GenerateKeyPair(Fixture.Bytes(0xB7, 32));
        var secondOwner = PublicKeyAuth.GenerateKeyPair(Fixture.Bytes(0xB8, 32));
        _ = await firstCoordinator.IssueAsync(
            await first.RequestAsync(firstCoordinator,
                ProductionMailboxIssuanceIntent.LocalOwner,
                secondHolder.PublicKey, secondHolder.PrivateKey,
                secondOwner.PublicKey, secondOwner.PrivateKey),
            CancellationToken.None);
        var provider = new ProductionMailboxArtifactProvider(
            first.Options, first.TimeProvider);

        using var second = Fixture.CreateRotation(first);
        using var secondSigner = new DevelopmentSoftwareEd25519Signer(second.IssuerSeedPath);
        var transport = new SwitchableClosureTransport { Accept = true };
        var promotionCoordinator = first.Coordinator(state, secondSigner, transport);
        state.ThrowAfterPromotedOwnerCommitOnce = true;
        await Assert.ThrowsAsync<IOException>(() =>
            promotionCoordinator.PromoteArtifactsAsync(
                provider, second.Artifacts, CancellationToken.None).AsTask());

        Assert.Equal(first.Artifacts.AuthoritySha256, provider.Current.AuthoritySha256);
        Assert.NotEmpty(await state.ListPendingPublicationKeysAsync(
            8, CancellationToken.None));
        var blocked = await Assert.ThrowsAsync<ProductionMailboxIssueException>(() =>
            first.RequestAsync(promotionCoordinator));
        Assert.Contains(blocked.Error,
            new[] { ProductionMailboxIssueError.InvalidChallenge,
                ProductionMailboxIssueError.IssuerUnavailable });

        File.Copy(second.Options.AuthorityPath, first.Options.AuthorityPath, true);
        File.Copy(second.Options.RevocationPath, first.Options.RevocationPath, true);
        File.Copy(second.Options.TopologyPath, first.Options.TopologyPath, true);
        Directory.Delete(first.Options.MembershipProofDirectory, recursive: true);
        var restartedProvider = new ProductionMailboxArtifactProvider(
            first.Options, first.TimeProvider);
        Assert.Equal(first.Artifacts.AuthoritySha256,
            restartedProvider.Current.AuthoritySha256);
        File.Delete(first.Options.AuthorityPath);
        File.Delete(first.Options.RevocationPath);
        File.Delete(first.Options.TopologyPath);
        var restartedCoordinator = first.Coordinator(state, secondSigner, transport);
        var promoted = await restartedCoordinator.PromoteConfiguredArtifactsAsync(
            restartedProvider, first.TimeProvider, CancellationToken.None);
        Assert.Equal(second.Artifacts.AuthoritySha256, promoted.AuthoritySha256);
        Assert.Equal(second.Artifacts.AuthoritySha256,
            restartedProvider.Current.AuthoritySha256);
        Assert.Empty(await state.ListPendingPublicationKeysAsync(8, CancellationToken.None));
        Assert.NotEmpty(transport.CommandHashes);
        Assert.Equal(2, state.SnapshotOwnerRouteStateKeys().Count);
        foreach (var ownerStateKey in state.SnapshotOwnerRouteStateKeys())
        {
            var promotedBytes = await state.GetLatestOwnerBundleAsync(
                ownerStateKey, CancellationToken.None);
            var promotedBundle = System.Text.Json.JsonSerializer.Deserialize<
                ProductionMailboxCredentialBundle>(promotedBytes!,
                    new System.Text.Json.JsonSerializerOptions(
                        System.Text.Json.JsonSerializerDefaults.Web));
            Assert.NotNull(promotedBundle);
            Assert.Equal(Convert.ToHexStringLower(second.Artifacts.AuthoritySha256),
                promotedBundle.Authority.Sha256);
            Assert.NotEqual(oldBundle.Authority.Sha256, promotedBundle.Authority.Sha256);
            Assert.NotNull(promotedBundle.SelectionSuccessor);
        }
    }

    [Fact]
    public async Task Promotion_ReservesEveryTargetBeforeFirstOwnerAndReleasesUnusedCapacity()
    {
        using var first = Fixture.Create();
        first.Options.ClockSkewSeconds = 60;
        var state = new InMemoryProductionMailboxStateStore(first.TimeProvider);
        using var firstSigner = new DevelopmentSoftwareEd25519Signer(first.IssuerSeedPath);
        var firstCoordinator = first.Coordinator(state, firstSigner);
        _ = await firstCoordinator.IssueAsync(
            await first.RequestAsync(firstCoordinator), CancellationToken.None);
        var provider = new ProductionMailboxArtifactProvider(
            first.Options, first.TimeProvider);
        using var second = Fixture.CreateRotation(first);
        using var secondSigner = new DevelopmentSoftwareEd25519Signer(second.IssuerSeedPath);
        var transport = new AcceptingClosureTransport
        {
            ReceiptTimestampOffsetSeconds = 1
        };
        var coordinator = first.Coordinator(state, secondSigner, transport);

        _ = await coordinator.PromoteArtifactsAsync(
            provider, second.Artifacts, CancellationToken.None);

        var firstPmp = transport.Events.IndexOf("PMP");
        Assert.True(firstPmp > 0);
        Assert.All(transport.Events.Take(firstPmp),
            static value => Assert.Equal("RESERVE", value));
        var reserves = transport.CapacityCommands.Where(command =>
            command[5] == (byte)ProductionMailboxCapacityOperation.ReserveOrRenew)
            .ToArray();
        var releases = transport.CapacityCommands.Where(command =>
            command[5] == (byte)ProductionMailboxCapacityOperation.Release)
            .ToArray();
        Assert.Equal(firstPmp, reserves.Length);
        Assert.Equal(reserves.Length, releases.Length);
        var cohort = reserves[0].AsSpan(56, 32).ToArray();
        Assert.True(cohort.AsSpan().IndexOfAnyExcept((byte)0) >= 0);
        Assert.All(reserves, command =>
        {
            Assert.Equal(cohort, command.AsSpan(56, 32).ToArray());
            Assert.Equal(1UL, BinaryPrimitives.ReadUInt64BigEndian(command.AsSpan(132)));
        });
        Assert.All(releases, command =>
        {
            Assert.Equal(cohort, command.AsSpan(56, 32).ToArray());
            Assert.Equal(2UL, BinaryPrimitives.ReadUInt64BigEndian(command.AsSpan(132)));
        });
        var plan = await state.GetCapacityPlanAsync(
            cohort, CancellationToken.None);
        Assert.NotNull(plan);
        Assert.True(plan.Completed);
        Assert.All(plan.Targets, static target => Assert.True(target.Released));
        var commandCount = transport.CapacityCommands.Count;

        var replay = await coordinator.PromoteArtifactsAsync(
            provider, second.Artifacts, CancellationToken.None);

        Assert.Equal(second.Artifacts.AuthoritySha256, replay.AuthoritySha256);
        Assert.Equal(commandCount, transport.CapacityCommands.Count);
    }

    [Fact]
    public async Task Promotion_CompletesNodeSignedReleaseAfterReservationAutoExpiry()
    {
        using var first = Fixture.Create();
        first.Options.CapacityReservationLifetimeSeconds = 600;
        first.Options.CapacityReservationRenewalMarginSeconds = 30;
        var state = new InMemoryProductionMailboxStateStore(first.TimeProvider)
        {
            AfterPromotionPublishedForTests = () =>
                first.TimeProvider.Set(Fixture.Now + 601)
        };
        using var firstSigner = new DevelopmentSoftwareEd25519Signer(first.IssuerSeedPath);
        var firstCoordinator = first.Coordinator(state, firstSigner);
        _ = await firstCoordinator.IssueAsync(
            await first.RequestAsync(firstCoordinator), CancellationToken.None);
        var provider = new ProductionMailboxArtifactProvider(
            first.Options, first.TimeProvider);
        using var second = Fixture.CreateRotation(first);
        using var secondSigner = new DevelopmentSoftwareEd25519Signer(second.IssuerSeedPath);
        var transport = new AcceptingClosureTransport();
        transport.ForceReconciliationForRelease = true;
        var coordinator = first.Coordinator(state, secondSigner, transport);

        _ = await coordinator.PromoteArtifactsAsync(
            provider, second.Artifacts, CancellationToken.None);

        var reserves = transport.CapacityCommands.Where(command =>
            command[5] == (byte)ProductionMailboxCapacityOperation.ReserveOrRenew)
            .ToArray();
        var releases = transport.CapacityCommands.Where(command =>
            command[5] == (byte)ProductionMailboxCapacityOperation.Release)
            .ToArray();
        Assert.Equal(3, reserves.Length);
        Assert.Equal(3, releases.Length);
        Assert.Equal(3, transport.ReconciliationCommands.Count);
        var reserveExpiry = reserves.Max(command =>
            BinaryPrimitives.ReadUInt64BigEndian(command.AsSpan(16)));
        Assert.All(releases, command => Assert.True(
            BinaryPrimitives.ReadUInt64BigEndian(command.AsSpan(8))
                > reserveExpiry));
        Assert.Null(await state.GetActiveArtifactPromotionAsync(CancellationToken.None));
    }

    [Fact]
    public async Task PostgreSqlPromotion_ReconcilesRealXNodeAfterRetentionAndBothRestart()
    {
        var connectionString = Environment.GetEnvironmentVariable("DEEP_TEST_POSTGRES");
        if (string.IsNullOrWhiteSpace(connectionString)) return;
        await using var database = await PostgresTestDatabase.CreateAsync(connectionString);
        using var first = Fixture.Create();
        first.Options.ClockSkewSeconds = 0;
        first.Options.CapacityReservationLifetimeSeconds = 600;
        first.Options.CapacityReservationRenewalMarginSeconds = 30;
        var state = new PostgreSqlProductionMailboxStateStore(database.ConnectionString);
        using var firstSigner = new DevelopmentSoftwareEd25519Signer(first.IssuerSeedPath);
        var firstCoordinator = first.Coordinator(state, firstSigner);
        _ = await firstCoordinator.IssueAsync(
            await first.RequestAsync(firstCoordinator), CancellationToken.None);
        var provider = new ProductionMailboxArtifactProvider(
            first.Options, first.TimeProvider);
        using var second = Fixture.CreateRotation(first);
        using var secondSigner = new DevelopmentSoftwareEd25519Signer(second.IssuerSeedPath);
        using var transport = new RealXNodeClosureTransport(
            first.Options.ClosurePublisherEd25519PublicKey,
            first.Options.ExpectedNetworkId,
            first.Options.PinnedMrXPublicKeySha256,
            first.TimeProvider,
            maximumReservationLifetimeSeconds: 600)
        {
            DropReleaseAndReconciliation = true
        };
        var coordinator = first.Coordinator(state, secondSigner, transport);

        var interrupted = await Assert.ThrowsAsync<ProductionMailboxIssueException>(async () =>
            await coordinator.PromoteArtifactsAsync(
                provider, second.Artifacts, CancellationToken.None));
        var active = await state.GetActiveArtifactPromotionAsync(CancellationToken.None);
        Assert.NotNull(active);
        Assert.True(active.Published,
            interrupted.Message + Environment.NewLine + transport.LastFailure);
        Assert.False(active.CapacityReleaseCompleted);

        first.TimeProvider.Set(Fixture.Now + 1_261);
        transport.DropReleaseAndReconciliation = false;
        transport.Restart();
        var restartedState = new PostgreSqlProductionMailboxStateStore(
            database.ConnectionString);
        var restartedCoordinator = first.Coordinator(
            restartedState, secondSigner, transport);

        var resumeError = await Record.ExceptionAsync(async () =>
            _ = await restartedCoordinator.PromoteArtifactsAsync(
                provider, second.Artifacts, CancellationToken.None));
        if (resumeError is not null)
            throw new Xunit.Sdk.XunitException(
                resumeError + Environment.NewLine + transport.LastFailure);

        Assert.True(transport.ReconciliationCount > 0);
        Assert.Null(await restartedState.GetActiveArtifactPromotionAsync(
            CancellationToken.None));
        var publishedClosure = await restartedState
            .GetOrInitializePublishedArtifactClosureAsync(
                Fixture.Bytes(243, 32), CancellationToken.None);
        var next = await restartedState.BeginArtifactPromotionAsync(
            Fixture.Bytes(242, 32), publishedClosure, Fixture.Bytes(244, 32),
            CancellationToken.None);
        Assert.False(next.Published);
    }

    [Theory]
    [InlineData(-61)]
    [InlineData(61)]
    public async Task Promotion_RejectsCapacityReceiptTimestampOutsideClockWindow(
        long receiptTimestampOffsetSeconds)
    {
        using var first = Fixture.Create();
        first.Options.ClockSkewSeconds = 60;
        var state = new InMemoryProductionMailboxStateStore(first.TimeProvider);
        using var firstSigner = new DevelopmentSoftwareEd25519Signer(first.IssuerSeedPath);
        var firstCoordinator = first.Coordinator(state, firstSigner);
        _ = await firstCoordinator.IssueAsync(
            await first.RequestAsync(firstCoordinator), CancellationToken.None);
        var provider = new ProductionMailboxArtifactProvider(
            first.Options, first.TimeProvider);
        using var second = Fixture.CreateRotation(first);
        using var secondSigner = new DevelopmentSoftwareEd25519Signer(second.IssuerSeedPath);
        var transport = new AcceptingClosureTransport
        {
            ReceiptTimestampOffsetSeconds = receiptTimestampOffsetSeconds
        };
        var coordinator = first.Coordinator(state, secondSigner, transport);

        var error = await Assert.ThrowsAsync<ProductionMailboxIssueException>(() =>
            coordinator.PromoteArtifactsAsync(provider, second.Artifacts,
                CancellationToken.None).AsTask());

        Assert.Equal(ProductionMailboxIssueError.IssuerUnavailable, error.Error);
        Assert.Empty(transport.Received);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public async Task Promotion_ResumesTerminalReleaseAfterLostResponseWithoutReserve(
        int failReleaseOrdinal)
    {
        using var first = Fixture.Create();
        var state = new InMemoryProductionMailboxStateStore(first.TimeProvider);
        using var firstSigner = new DevelopmentSoftwareEd25519Signer(first.IssuerSeedPath);
        var firstCoordinator = first.Coordinator(state, firstSigner);
        _ = await firstCoordinator.IssueAsync(
            await first.RequestAsync(firstCoordinator), CancellationToken.None);
        var provider = new ProductionMailboxArtifactProvider(
            first.Options, first.TimeProvider);
        using var second = Fixture.CreateRotation(first);
        using var secondSigner = new DevelopmentSoftwareEd25519Signer(second.IssuerSeedPath);
        var transport = new AcceptingClosureTransport
        {
            FailReleaseOrdinalOnce = failReleaseOrdinal
        };
        var coordinator = first.Coordinator(state, secondSigner, transport);

        await Assert.ThrowsAsync<ProductionMailboxIssueException>(() =>
            coordinator.PromoteArtifactsAsync(provider, second.Artifacts,
                CancellationToken.None).AsTask());

        Assert.Equal(second.Artifacts.AuthoritySha256,
            provider.Current.AuthoritySha256);
        var active = await state.GetActiveArtifactPromotionAsync(CancellationToken.None);
        Assert.NotNull(active);
        Assert.True(active.Published);
        Assert.False(active.CapacityReleaseCompleted);
        var firstReleaseEvent = transport.Events.IndexOf("RELEASE");
        Assert.True(firstReleaseEvent >= 0);
        var failedCommand = transport.CapacityCommands.Last().ToArray();

        var restartedProvider = new ProductionMailboxArtifactProvider(
            first.Options, first.TimeProvider);
        var restartedCoordinator = first.Coordinator(
            state, secondSigner, transport);
        _ = await restartedCoordinator.PromoteArtifactsAsync(
            restartedProvider, second.Artifacts, CancellationToken.None);

        Assert.Equal(second.Artifacts.AuthoritySha256,
            restartedProvider.Current.AuthoritySha256);
        Assert.DoesNotContain("RESERVE", transport.Events.Skip(firstReleaseEvent));
        Assert.Contains(transport.CapacityCommands.Skip(failReleaseOrdinal),
            command => command.AsSpan().SequenceEqual(failedCommand));
        Assert.Null(await state.GetActiveArtifactPromotionAsync(CancellationToken.None));
    }

    [Fact]
    public async Task Promotion_ResumesAfterAllTerminalReleasesBeforeCleanupMarker()
    {
        using var first = Fixture.Create();
        var state = new InMemoryProductionMailboxStateStore(first.TimeProvider)
        {
            ThrowBeforeCapacityReleasedOnce = true
        };
        using var firstSigner = new DevelopmentSoftwareEd25519Signer(first.IssuerSeedPath);
        var firstCoordinator = first.Coordinator(state, firstSigner);
        _ = await firstCoordinator.IssueAsync(
            await first.RequestAsync(firstCoordinator), CancellationToken.None);
        var provider = new ProductionMailboxArtifactProvider(
            first.Options, first.TimeProvider);
        using var second = Fixture.CreateRotation(first);
        using var secondSigner = new DevelopmentSoftwareEd25519Signer(second.IssuerSeedPath);
        var transport = new AcceptingClosureTransport();
        var coordinator = first.Coordinator(state, secondSigner, transport);

        await Assert.ThrowsAsync<IOException>(() => coordinator.PromoteArtifactsAsync(
            provider, second.Artifacts, CancellationToken.None).AsTask());
        var commandCount = transport.CapacityCommands.Count;
        var active = await state.GetActiveArtifactPromotionAsync(CancellationToken.None);
        Assert.NotNull(active);
        Assert.True(active.Published);
        Assert.False(active.CapacityReleaseCompleted);
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            state.BeginArtifactPromotionAsync(
                Fixture.Bytes(0xE1, 32), active.NewArtifactClosureHash,
                Fixture.Bytes(0xE2, 32), CancellationToken.None).AsTask());

        var restartedProvider = new ProductionMailboxArtifactProvider(
            first.Options, first.TimeProvider);
        var restartedCoordinator = first.Coordinator(
            state, secondSigner, transport);
        _ = await restartedCoordinator.PromoteArtifactsAsync(
            restartedProvider, second.Artifacts, CancellationToken.None);

        Assert.Equal(commandCount, transport.CapacityCommands.Count);
        Assert.Null(await state.GetActiveArtifactPromotionAsync(CancellationToken.None));
        var nextPromotion = await state.BeginArtifactPromotionAsync(
            Fixture.Bytes(0xE1, 32), active.NewArtifactClosureHash,
            Fixture.Bytes(0xE2, 32), CancellationToken.None);
        Assert.False(nextPromotion.Published);
    }

    [Fact]
    public async Task Promotion_CapacityFailureFreezesBeforeOwnerCommitAndRetryResumes()
    {
        using var first = Fixture.Create();
        var state = new InMemoryProductionMailboxStateStore(first.TimeProvider);
        using var firstSigner = new DevelopmentSoftwareEd25519Signer(first.IssuerSeedPath);
        var firstCoordinator = first.Coordinator(state, firstSigner);
        var oldBundle = await firstCoordinator.IssueAsync(
            await first.RequestAsync(firstCoordinator), CancellationToken.None);
        var ownerStateKey = Assert.Single(state.SnapshotOwnerRouteStateKeys());
        var provider = new ProductionMailboxArtifactProvider(
            first.Options, first.TimeProvider);
        using var second = Fixture.CreateRotation(first);
        using var secondSigner = new DevelopmentSoftwareEd25519Signer(second.IssuerSeedPath);
        var transport = new AcceptingClosureTransport
        {
            AcceptCapacity = static (_, _) => false
        };
        var coordinator = first.Coordinator(state, secondSigner, transport);

        var failure = await Assert.ThrowsAsync<ProductionMailboxIssueException>(() =>
            coordinator.PromoteArtifactsAsync(
                provider, second.Artifacts, CancellationToken.None).AsTask());
        Assert.Equal(ProductionMailboxIssueError.IssuerUnavailable, failure.Error);
        Assert.Equal(first.Artifacts.AuthoritySha256, provider.Current.AuthoritySha256);
        Assert.Empty(await state.ListPendingPublicationKeysAsync(
            8, CancellationToken.None));
        var stillOld = await state.GetLatestOwnerBundleAsync(
            ownerStateKey, CancellationToken.None);
        Assert.Equal(oldBundle.Authority.Sha256,
            System.Text.Json.JsonSerializer.Deserialize<ProductionMailboxCredentialBundle>(
                stillOld!, new System.Text.Json.JsonSerializerOptions(
                    System.Text.Json.JsonSerializerDefaults.Web))!
                .Authority.Sha256);

        transport.AcceptCapacity = static (_, _) => true;
        _ = await coordinator.PromoteArtifactsAsync(
            provider, second.Artifacts, CancellationToken.None);
        Assert.True(transport.CapacityCommands.Count >= 2);
        Assert.Equal(transport.CapacityCommands[0], transport.CapacityCommands[1]);
        Assert.Equal(second.Artifacts.AuthoritySha256, provider.Current.AuthoritySha256);
        Assert.Contains("PMP", transport.Events);
        Assert.Contains("RELEASE", transport.Events);
    }

    [Fact]
    public async Task PromotionState_PaginatesImmutableWatermarkAndRequiresEveryAck()
    {
        var state = new InMemoryProductionMailboxStateStore();
        for (var index = 1; index <= 70; index++)
            await state.StoreLatestOwnerBundleAsync(
                Fixture.Bytes((byte)index, 32), Fixture.Bytes((byte)(index + 70), 48),
                Fixture.Now, CancellationToken.None);
        var promotionKey = Fixture.Bytes(0xD0, 32);
        var promotion = await state.BeginArtifactPromotionAsync(
            promotionKey, Fixture.Bytes(0xD1, 32), Fixture.Bytes(0xD2, 32),
            CancellationToken.None);
        Assert.Equal(70, promotion.OwnerWatermark);
        await state.StoreLatestOwnerBundleAsync(
            Fixture.Bytes(0xD3, 32), Fixture.Bytes(0xD4, 48), Fixture.Now,
            CancellationToken.None);

        static (ProductionMailboxPublicationItem Item,
            ProductionMailboxPreparedIssue Prepared) Work(
                ProductionMailboxOwnerBundleRecord owner, byte[] promotionStateKey)
        {
            var marker = checked((byte)owner.Sequence);
            var envelope = Fixture.Bytes(marker, 64);
            var publicationKey = SHA256.HashData(
                Encoding.UTF8.GetBytes($"promotion-{owner.Sequence}"));
            var targetKey = SHA256.HashData(
                Encoding.UTF8.GetBytes($"target-{owner.Sequence}"));
            var capacityNode = PublicKeyAuth.GenerateKeyPair(Fixture.Bytes(0xE1, 32));
            var item = new ProductionMailboxPublicationItem(
                targetKey, capacityNode.PublicKey, "https://node.example/",
                Fixture.Bytes(0xE2, 32), Fixture.Bytes(0xE3, 32), [],
                envelope, SHA256.HashData(envelope), promotionStateKey);
            return (item, new ProductionMailboxPreparedIssue(
                Fixture.Bytes((byte)(marker + 1), 96), owner.RouteStateKey,
                publicationKey, [item]));
        }

        while (true)
        {
            var owners = await state.ListOwnerBundlesForCapacityPlanningAsync(
                promotionKey, 64, CancellationToken.None);
            if (owners.Count == 0) break;
            foreach (var owner in owners)
            {
                var work = Work(owner, promotionKey);
                Assert.True(await state.CommitCapacityPlannedOwnerAsync(
                    promotionKey, owner, [work.Item], 1024,
                    CancellationToken.None));
            }
        }
        Assert.True(await state.CompleteCapacityPlanAsync(
            promotionKey, CancellationToken.None));
        var capacityPlan = await state.GetCapacityPlanAsync(
            promotionKey, CancellationToken.None);
        var capacityTarget = Assert.Single(capacityPlan!.Targets);
        Assert.Equal(70U, capacityTarget.ReservedClosureCount);
        var capacityCommand = Fixture.Bytes(0xEA,
            ProductionMailboxCapacityCommandCodec.EncodedLength);
        var unsignedCapacityReceipt = new ProductionMailboxCapacityReceipt(
            ProductionMailboxCapacityOperation.ReserveOrRenew,
            Fixture.Now, Fixture.Now + 1_000, promotionKey,
            capacityTarget.TargetReplicaId, capacityTarget.ReservedClosureCount,
            capacityTarget.ReservedBytes, 0, 0, 1,
            SHA256.HashData(capacityCommand), new byte[64]);
        var capacityNode = PublicKeyAuth.GenerateKeyPair(Fixture.Bytes(0xE1, 32));
        var capacityReceipt = unsignedCapacityReceipt with
        {
            NodeSignature = PublicKeyAuth.SignDetached(
                ProductionMailboxCapacityReceiptCodec.GetSigningBytes(
                    unsignedCapacityReceipt), capacityNode.PrivateKey)
        };
        Assert.Equal(capacityCommand, await state.GetOrRecordCapacityAttemptAsync(
            promotionKey, capacityTarget.TargetReplicaId, 0, 1,
            capacityCommand, CancellationToken.None));
        Assert.True(await state.RecordCapacityReceiptAsync(
            promotionKey, capacityTarget.TargetReplicaId, 0, capacityReceipt,
            ProductionMailboxCapacityReceiptCodec.Encode(capacityReceipt),
            CancellationToken.None));

        var processed = 0;
        while (true)
        {
            var owners = await state.ListOwnerBundlesForPromotionAsync(
                promotionKey, 64, CancellationToken.None);
            if (owners.Count == 0) break;
            Assert.InRange(owners.Count, 1, 64);
            foreach (var owner in owners)
            {
                var work = Work(owner, promotionKey);
                Assert.True(await state.CommitPromotedOwnerAsync(
                    promotionKey, owner, work.Prepared, Fixture.Now,
                    300,
                    CancellationToken.None));
                var attempt = Fixture.Bytes(0xE4, 32);
                Assert.True(await state.RecordPublicationAttemptAsync(
                    work.Prepared.PublicationStateKey, work.Item.TargetStateKey,
                    work.Item.EnvelopeSha256, attempt,
                    Fixture.Now, CancellationToken.None));
                Assert.True(await state.AcknowledgePublicationAsync(
                    work.Prepared.PublicationStateKey, work.Item.TargetStateKey,
                    work.Item.EnvelopeSha256, attempt,
                    CancellationToken.None));
                processed++;
            }
        }
        Assert.Equal(70, processed);
        Assert.True(await state.CompleteArtifactPromotionSweepAsync(
            promotionKey, CancellationToken.None));
        Assert.True(await state.MarkArtifactPromotionPublishedAsync(
            promotionKey, CancellationToken.None));
        Assert.Equal(Fixture.Bytes(0xD4, 48),
            await state.GetLatestOwnerBundleAsync(
                Fixture.Bytes(0xD3, 32), CancellationToken.None));
    }

    [Fact]
    public async Task PromotionCommit_UsesLockedAuthoritativeTimeAndRejectsReleasedReceipt()
    {
        var time = new FixedTimeProvider(
            DateTimeOffset.FromUnixTimeSeconds(checked((long)Fixture.Now)));
        var state = new InMemoryProductionMailboxStateStore(time);
        var routeKey = Fixture.Bytes(0xC0, 32);
        await state.StoreLatestOwnerBundleAsync(
            routeKey, Fixture.Bytes(0xC1, 64), Fixture.Now,
            CancellationToken.None);
        var promotionKey = Fixture.Bytes(0xC2, 32);
        _ = await state.BeginArtifactPromotionAsync(
            promotionKey, Fixture.Bytes(0xC3, 32), Fixture.Bytes(0xC4, 32),
            CancellationToken.None);
        var owner = Assert.Single(await state.ListOwnerBundlesForCapacityPlanningAsync(
            promotionKey, 8, CancellationToken.None));
        var envelope = Fixture.Bytes(0xC5, 64);
        var capacityNode = PublicKeyAuth.GenerateKeyPair(Fixture.Bytes(0xC7, 32));
        var item = new ProductionMailboxPublicationItem(
            Fixture.Bytes(0xC6, 32), capacityNode.PublicKey,
            "https://capacity.example/", Fixture.Bytes(0xC8, 32),
            Fixture.Bytes(0xC9, 32), [], envelope, SHA256.HashData(envelope),
            promotionKey);
        Assert.True(await state.CommitCapacityPlannedOwnerAsync(
            promotionKey, owner, [item], 1024, CancellationToken.None));
        Assert.True(await state.CompleteCapacityPlanAsync(
            promotionKey, CancellationToken.None));
        var target = Assert.Single((await state.GetCapacityPlanAsync(
            promotionKey, CancellationToken.None))!.Targets);
        var prepared = new ProductionMailboxPreparedIssue(
            Fixture.Bytes(0xCA, 96), routeKey, Fixture.Bytes(0xCB, 32), [item]);

        ProductionMailboxCapacityReceipt Receipt(
            ProductionMailboxCapacityOperation operation,
            ulong revision, ulong expires)
        {
            var release = operation == ProductionMailboxCapacityOperation.Release;
            var unsigned = new ProductionMailboxCapacityReceipt(
                operation, Fixture.Now, expires, promotionKey,
                target.TargetReplicaId,
                release ? 0 : target.ReservedClosureCount,
                release ? 0 : target.ReservedBytes, 0, 0, revision,
                SHA256.HashData(Fixture.Bytes(
                    checked((byte)(0xD0 + revision)),
                    ProductionMailboxCapacityCommandCodec.EncodedLength)),
                new byte[64]);
            return unsigned with
            {
                NodeSignature = PublicKeyAuth.SignDetached(
                    ProductionMailboxCapacityReceiptCodec.GetSigningBytes(unsigned),
                    capacityNode.PrivateKey)
            };
        }

        var expiring = Receipt(
            ProductionMailboxCapacityOperation.ReserveOrRenew, 1,
            Fixture.Now + 300);
        _ = await state.GetOrRecordCapacityAttemptAsync(
            promotionKey, target.TargetReplicaId, 0, 1,
            Fixture.Bytes(0xD1, ProductionMailboxCapacityCommandCodec.EncodedLength),
            CancellationToken.None);
        Assert.True(await state.RecordCapacityReceiptAsync(
            promotionKey, target.TargetReplicaId, 0, expiring,
            ProductionMailboxCapacityReceiptCodec.Encode(expiring),
            CancellationToken.None));
        time.Set(Fixture.Now + 1);
        Assert.False(await state.CommitPromotedOwnerAsync(
            promotionKey, owner, prepared, Fixture.Now + 1, 300,
            CancellationToken.None));

        var renewed = Receipt(
            ProductionMailboxCapacityOperation.ReserveOrRenew, 2,
            Fixture.Now + 1_000);
        _ = await state.GetOrRecordCapacityAttemptAsync(
            promotionKey, target.TargetReplicaId, 1, 2,
            Fixture.Bytes(0xD2, ProductionMailboxCapacityCommandCodec.EncodedLength),
            CancellationToken.None);
        Assert.True(await state.RecordCapacityReceiptAsync(
            promotionKey, target.TargetReplicaId, 1, renewed,
            ProductionMailboxCapacityReceiptCodec.Encode(renewed),
            CancellationToken.None));
        var released = Receipt(
            ProductionMailboxCapacityOperation.Release, 3,
            Fixture.Now + 1_000);
        _ = await state.GetOrRecordCapacityAttemptAsync(
            promotionKey, target.TargetReplicaId, 2, 3,
            Fixture.Bytes(0xD3, ProductionMailboxCapacityCommandCodec.EncodedLength),
            CancellationToken.None);
        Assert.True(await state.RecordCapacityReceiptAsync(
            promotionKey, target.TargetReplicaId, 2, released,
            ProductionMailboxCapacityReceiptCodec.Encode(released),
            CancellationToken.None));
        Assert.False(await state.CommitPromotedOwnerAsync(
            promotionKey, owner, prepared, Fixture.Now + 1, 300,
            CancellationToken.None));

        var resumed = Receipt(
            ProductionMailboxCapacityOperation.ReserveOrRenew, 4,
            Fixture.Now + 1_000);
        Assert.Null(await state.GetOrRecordCapacityAttemptAsync(
            promotionKey, target.TargetReplicaId, 3, 4,
            Fixture.Bytes(0xD4, ProductionMailboxCapacityCommandCodec.EncodedLength),
            CancellationToken.None));
        Assert.False(await state.RecordCapacityReceiptAsync(
            promotionKey, target.TargetReplicaId, 3, resumed,
            ProductionMailboxCapacityReceiptCodec.Encode(resumed),
            CancellationToken.None));
        Assert.False(await state.CommitPromotedOwnerAsync(
            promotionKey, owner, prepared, Fixture.Now + 1, 300,
            CancellationToken.None));
    }

    [Fact]
    public async Task Promotion_ReconcilesCrashAfterProviderCutoverBeforePublishedMarker()
    {
        using var first = Fixture.Create();
        var state = new InMemoryProductionMailboxStateStore();
        using var firstSigner = new DevelopmentSoftwareEd25519Signer(first.IssuerSeedPath);
        var firstCoordinator = first.Coordinator(state, firstSigner);
        _ = await firstCoordinator.IssueAsync(
            await first.RequestAsync(firstCoordinator), CancellationToken.None);
        var provider = new ProductionMailboxArtifactProvider(
            first.Options, first.TimeProvider);
        using var second = Fixture.CreateRotation(first);
        using var secondSigner = new DevelopmentSoftwareEd25519Signer(second.IssuerSeedPath);
        var promotionCoordinator = first.Coordinator(
            state, secondSigner, new AcceptingClosureTransport());
        state.ThrowBeforePromotionPublishedOnce = true;

        await Assert.ThrowsAsync<IOException>(() =>
            promotionCoordinator.PromoteArtifactsAsync(
                provider, second.Artifacts, CancellationToken.None).AsTask());
        Assert.Equal(second.Artifacts.AuthoritySha256,
            provider.Current.AuthoritySha256);
        var active = await state.GetActiveArtifactPromotionAsync(CancellationToken.None);
        Assert.NotNull(active);
        Assert.True(active.SweepCompleted);

        var restartedProvider = new ProductionMailboxArtifactProvider(
            first.Options, first.TimeProvider);
        Assert.Equal(second.Artifacts.AuthoritySha256,
            restartedProvider.Current.AuthoritySha256);
        var restartedCoordinator = first.Coordinator(
            state, secondSigner, new AcceptingClosureTransport());
        var reconciled = await restartedCoordinator.PromoteConfiguredArtifactsAsync(
            restartedProvider, first.TimeProvider, CancellationToken.None);
        Assert.Equal(second.Artifacts.AuthoritySha256, reconciled.AuthoritySha256);
        Assert.Null(await state.GetActiveArtifactPromotionAsync(CancellationToken.None));
    }

    [Fact]
    public async Task Promotion_FreshProviderKeepsOldActiveAfterCompletedSweepBeforeCutover()
    {
        using var first = Fixture.Create();
        var state = new InMemoryProductionMailboxStateStore();
        using var firstSigner = new DevelopmentSoftwareEd25519Signer(first.IssuerSeedPath);
        var firstCoordinator = first.Coordinator(state, firstSigner);
        _ = await firstCoordinator.IssueAsync(
            await first.RequestAsync(firstCoordinator), CancellationToken.None);
        var provider = new ProductionMailboxArtifactProvider(
            first.Options, first.TimeProvider);
        using var second = Fixture.CreateRotation(first);
        using var secondSigner = new DevelopmentSoftwareEd25519Signer(second.IssuerSeedPath);
        var promotionCoordinator = first.Coordinator(
            state, secondSigner, new AcceptingClosureTransport());
        promotionCoordinator.ThrowBeforeArtifactProviderCutoverOnce = true;

        await Assert.ThrowsAsync<IOException>(() =>
            promotionCoordinator.PromoteArtifactsAsync(
                provider, second.Artifacts, CancellationToken.None).AsTask());
        var active = await state.GetActiveArtifactPromotionAsync(CancellationToken.None);
        Assert.NotNull(active);
        Assert.True(active.SweepCompleted);
        Assert.Equal(first.Artifacts.AuthoritySha256, provider.Current.AuthoritySha256);

        var restartedProvider = new ProductionMailboxArtifactProvider(
            first.Options, first.TimeProvider);
        Assert.Equal(first.Artifacts.AuthoritySha256,
            restartedProvider.Current.AuthoritySha256);
        var restartedCoordinator = first.Coordinator(
            state, secondSigner, new AcceptingClosureTransport());
        var promoted = await restartedCoordinator.PromoteConfiguredArtifactsAsync(
            restartedProvider, first.TimeProvider, CancellationToken.None);
        Assert.Equal(second.Artifacts.AuthoritySha256, promoted.AuthoritySha256);
        Assert.Null(await state.GetActiveArtifactPromotionAsync(CancellationToken.None));
    }

    [Fact]
    public async Task AtomicOwnerStateCommit_SurvivesLostIssueResponseBeforeNextRotation()
    {
        using var first = Fixture.Create();
        var state = new InMemoryProductionMailboxStateStore();
        using var firstSigner = new DevelopmentSoftwareEd25519Signer(first.IssuerSeedPath);
        var firstCoordinator = first.Coordinator(state, firstSigner);
        var lostRequest = await first.RequestAsync(firstCoordinator);
        state.ThrowAfterIssueCommitOnce = true;
        await Assert.ThrowsAsync<IOException>(() => firstCoordinator.IssueAsync(
            lostRequest, CancellationToken.None).AsTask());

        using var second = Fixture.CreateRotation(first);
        using var secondSigner = new DevelopmentSoftwareEd25519Signer(second.IssuerSeedPath);
        var secondCoordinator = second.Coordinator(state, secondSigner);
        var next = await secondCoordinator.IssueAsync(
            await second.RequestAsync(secondCoordinator), CancellationToken.None);

        Assert.NotNull(next.SelectionSuccessor);
        var successor = ProductionMailboxSelectionSuccessorCodec.Decode(
            Decode(next.SelectionSuccessor.CanonicalBase64Url));
        Assert.Equal(ProductionMailboxSelectionSuccessorMode.DirectPromotion,
            successor.Mode);
    }

    [Fact]
    public async Task TwoMissedRotationsIssueVerifiableOfflineCheckpoint()
    {
        using var first = Fixture.Create();
        var state = new InMemoryProductionMailboxStateStore();
        using var firstSigner = new DevelopmentSoftwareEd25519Signer(first.IssuerSeedPath);
        var firstCoordinator = first.Coordinator(state, firstSigner);
        var oldBundle = await firstCoordinator.IssueAsync(
            await first.RequestAsync(firstCoordinator), CancellationToken.None);

        using var second = Fixture.CreateRotation(first);
        using var third = Fixture.CreateRotation(second);
        using var thirdSigner = new DevelopmentSoftwareEd25519Signer(third.IssuerSeedPath);
        var thirdCoordinator = third.Coordinator(state, thirdSigner);
        var currentBundle = await thirdCoordinator.IssueAsync(
            await third.RequestAsync(thirdCoordinator), CancellationToken.None);

        Assert.NotNull(currentBundle.SelectionSuccessor);
        var oldNext = oldBundle.Selections.Single(value =>
            value.Epoch == first.Artifacts.Topology.Snapshot.NextEpoch.Epoch);
        var current = currentBundle.Selections.Single(value =>
            value.Epoch == third.Artifacts.Topology.Snapshot.CurrentEpoch.Epoch);
        var next = currentBundle.Selections.Single(value =>
            value.Epoch == third.Artifacts.Topology.Snapshot.NextEpoch.Epoch);
        var oldSelectionBytes = Decode(oldNext.CanonicalBase64Url);
        var oldSelection = ProductionMailboxTopologyCodec.DecodeSelection(
            oldSelectionBytes);
        var verified = ProductionMailboxSelectionSuccessorVerifier
            .VerifyOfflineCheckpointClosure(
            Decode(currentBundle.SelectionSuccessor.CanonicalBase64Url),
            third.Artifacts.AuthorityBytes,
            third.Artifacts.RevocationBytes,
            third.Artifacts.TopologyBytes,
            oldSelectionBytes,
            Decode(current.CanonicalBase64Url),
            Decode(next.CanonicalBase64Url),
            first.Artifacts.Authority,
            first.Artifacts.Topology,
            new ProductionMailboxOfflineCheckpointClosureVerificationContext
            {
                ExpectedNetworkId = third.Artifacts.Authority.Authority.NetworkId,
                ExpectedMailboxOwnerEd25519PublicKey = third.OwnerPublicKey,
                ExpectedBlindedMailboxId = Decode(currentBundle.BlindedMailboxId),
                ExpectedBlindedPlacementId = Decode(currentBundle.BlindedPlacementId),
                ExpectedSelectionInputCommitment = oldSelection.SelectionInputCommitment,
                PinnedMrXPublicKeySha256 = Convert.FromHexString(
                    third.Options.PinnedMrXPublicKeySha256),
                ExpectedOldAuthorityGeneration =
                    first.Artifacts.Authority.Authority.AuthorityGeneration,
                ExpectedOldCanonicalAuthorityHash =
                    first.Artifacts.Authority.CanonicalAuthorityHash,
                ExpectedOldRevocationGeneration =
                    first.Artifacts.Revocation.Snapshot.RevocationGeneration,
                ExpectedOldRevocationHeadHash =
                    first.Artifacts.Revocation.Snapshot.RevocationHeadHash,
                ExpectedOldRevocationSnapshotHash =
                    first.Artifacts.Revocation.CanonicalSnapshotHash,
                ExpectedOldTopologyGeneration =
                    first.Artifacts.Topology.Snapshot.TopologyGeneration,
                ExpectedOldCanonicalTopologyHash =
                    first.Artifacts.Topology.CanonicalTopologyHash,
                ExpectedOldCanonicalSelectionHash = SHA256.HashData(
                    oldSelectionBytes),
                VerifiedAtUnixSeconds = Fixture.Now,
                ClockSkewSeconds = 0
            });
        Assert.Equal(ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint,
            verified.Successor.Proof.Mode);
        Assert.All(verified.Successor.Proof.OldIssuerSignature.ToArray(),
            value => Assert.Equal(0, value));
    }

    [Fact]
    public void ArtifactCatalog_RejectsReloadBeforeEvictingAnUnexpiredClosure()
    {
        using var first = Fixture.Create();
        using var second = Fixture.Create(artifactSeedOffset: 1);
        first.Options.MaximumRetainedArtifactClosures = 1;
        var provider = new ProductionMailboxArtifactProvider(first.Options, first.TimeProvider);

        Assert.Throws<InvalidOperationException>(() =>
            provider.PublishVerified(second.Artifacts, Fixture.Now));
        Assert.Equal(first.Artifacts.AuthoritySha256, provider.Current.AuthoritySha256);
    }

    [Fact]
    public void ArtifactCatalog_PrunesExpiredStagedClosureAcrossRestart()
    {
        using var first = Fixture.Create();
        first.Options.MaximumRetainedArtifactClosures = 2;
        var provider = new ProductionMailboxArtifactProvider(
            first.Options, first.TimeProvider);
        using var expiredCandidate = Fixture.CreateRotation(first);
        provider.StageVerifiedSuccessor(expiredCandidate.Artifacts);

        var catalogRoot = Path.Combine(Path.GetDirectoryName(
            first.Options.RouteStateHmacKeyPath)!,
            "production-mailbox-artifact-catalog");
        var activeId = Convert.ToHexStringLower(File.ReadAllBytes(
            Path.Combine(catalogRoot, "active.pmac1"))[..32]);
        var stagedManifest = Directory.EnumerateFiles(
                catalogRoot, "*.pmac1.json")
            .Single(path => !Path.GetFileName(path).StartsWith(
                activeId, StringComparison.Ordinal));
        ExpireCatalogManifest(
            stagedManifest, first.Options.RouteStateHmacKeyPath);

        var restarted = new ProductionMailboxArtifactProvider(
            first.Options, first.TimeProvider);
        Assert.Single(Directory.EnumerateFiles(catalogRoot, "*.pmac1.json"));
        using var replacement = Fixture.CreateRotation(first, routeVariant: 1);
        restarted.StageVerifiedSuccessor(replacement.Artifacts);
        Assert.Equal(2, Directory.EnumerateFiles(
            catalogRoot, "*.pmac1.json").Count());
    }

    [Fact]
    public void ArtifactCatalog_RejectsWrongMembershipProofBeforeStaging()
    {
        using var first = Fixture.Create();
        using var second = Fixture.CreateRotation(first);
        var provider = new ProductionMailboxArtifactProvider(
            first.Options, first.TimeProvider);
        var currentEpochPrefix = second.Artifacts.Topology.Snapshot.CurrentEpoch.Epoch + "-";
        var proofs = Directory.EnumerateFiles(second.Options.MembershipProofDirectory)
            .Where(path => Path.GetFileName(path).StartsWith(
                currentEpochPrefix, StringComparison.Ordinal))
            .Take(2).ToArray();
        Assert.Equal(2, proofs.Length);
        File.Copy(proofs[1], proofs[0], overwrite: true);

        Assert.Throws<InvalidDataException>(() =>
            provider.StageVerifiedSuccessor(second.Artifacts));
        Assert.Equal(first.Artifacts.AuthoritySha256,
            provider.Current.AuthoritySha256);
    }

    [Fact]
    public void ArtifactProvider_PublicSurfaceCannotMutateActiveClosure()
    {
        var publicMethods = typeof(ProductionMailboxArtifactProvider)
            .GetMethods(System.Reflection.BindingFlags.Instance
                | System.Reflection.BindingFlags.Public)
            .Select(static method => method.Name)
            .ToHashSet(StringComparer.Ordinal);
        Assert.DoesNotContain("Reload", publicMethods);
        Assert.DoesNotContain("PublishVerified", publicMethods);
        Assert.DoesNotContain("StageVerifiedSuccessor", publicMethods);
    }

    [Fact]
    public void ArtifactCatalog_CorruptStagedClosureCannotBecomeActiveOrBlockOldRestart()
    {
        using var first = Fixture.Create();
        using var second = Fixture.CreateRotation(first);
        var provider = new ProductionMailboxArtifactProvider(
            first.Options, first.TimeProvider);
        provider.StageVerifiedSuccessor(second.Artifacts);
        var catalogRoot = Path.Combine(Path.GetDirectoryName(
            first.Options.RouteStateHmacKeyPath)!,
            "production-mailbox-artifact-catalog");
        var stagedAuthority = Directory.EnumerateFiles(catalogRoot, "*.pma1")
            .Single(path => !File.ReadAllBytes(path).AsSpan().SequenceEqual(
                first.Artifacts.AuthorityBytes));
        var corrupted = File.ReadAllBytes(stagedAuthority);
        corrupted[^1] ^= 1;
        File.WriteAllBytes(stagedAuthority, corrupted);

        Assert.ThrowsAny<Exception>(() =>
            provider.StageVerifiedSuccessor(second.Artifacts));
        Assert.ThrowsAny<Exception>(() =>
            provider.PublishVerified(second.Artifacts, Fixture.Now));
        Assert.Equal(first.Artifacts.AuthoritySha256,
            provider.Current.AuthoritySha256);

        var restarted = new ProductionMailboxArtifactProvider(
            first.Options, first.TimeProvider);
        Assert.Equal(first.Artifacts.AuthoritySha256,
            restarted.Current.AuthoritySha256);
    }

    [Fact]
    public void ArtifactCatalog_StableReadRejectsLeafLinkAndSameLengthPathSwap()
    {
        var root = Path.Combine(Path.GetTempPath(), "deep-pma-stable-read",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var first = Path.Combine(root, "first.bin");
            var second = Path.Combine(root, "second.bin");
            var backup = Path.Combine(root, "backup.bin");
            File.WriteAllBytes(first, Fixture.Bytes(0x11, 32));
            File.WriteAllBytes(second, Fixture.Bytes(0x22, 32));
            Assert.Throws<InvalidDataException>(() =>
                ProductionMailboxProtectedFile.ReadStable(
                    first, 32, 32, () =>
                        ProductionMailboxArtifactProvider.EnsureNoReparseAncestors(first),
                    () =>
                    {
                        File.Move(first, backup);
                        File.Move(second, first);
                    }));

            var link = Path.Combine(root, "linked.bin");
            File.CreateSymbolicLink(link, first);
            Assert.ThrowsAny<Exception>(() =>
                ProductionMailboxProtectedFile.ReadStable(
                    link, 32, 32, () =>
                        ProductionMailboxArtifactProvider.EnsureNoReparseAncestors(link)));
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void ArtifactCatalog_TombstoneCrashIsReconciledWithoutEvictingActive()
    {
        using var first = Fixture.Create();
        first.Options.MaximumRetainedArtifactClosures = 2;
        using var second = Fixture.CreateRotation(first);
        var provider = new ProductionMailboxArtifactProvider(
            first.Options, first.TimeProvider);
        provider.StageVerifiedSuccessor(second.Artifacts);
        var catalogRoot = Path.Combine(Path.GetDirectoryName(
            first.Options.RouteStateHmacKeyPath)!,
            "production-mailbox-artifact-catalog");
        var activeId = Convert.ToHexStringLower(File.ReadAllBytes(
            Path.Combine(catalogRoot, "active.pmac1"))[..32]);
        var stagedManifest = Directory.EnumerateFiles(
                catalogRoot, "*.pmac1.json")
            .Single(path => !Path.GetFileName(path).StartsWith(
                activeId, StringComparison.Ordinal));
        ExpireCatalogManifest(
            stagedManifest, first.Options.RouteStateHmacKeyPath);
        var injected = 0;
        provider.CatalogMutationFaultForTests = point =>
        {
            if (point == "after-manifest-tombstone"
                && Interlocked.Exchange(ref injected, 1) == 0)
                throw new IOException("injected catalog deletion crash");
        };
        Assert.Throws<IOException>(() =>
            provider.PruneExpiredForTests(Fixture.Now));
        Assert.True(Directory.EnumerateFiles(
            catalogRoot, "*.pmac1.json.gc").Any());

        var restarted = new ProductionMailboxArtifactProvider(
            first.Options, first.TimeProvider);
        Assert.Equal(first.Artifacts.AuthoritySha256,
            restarted.Current.AuthoritySha256);
        Assert.DoesNotContain(Directory.EnumerateFileSystemEntries(catalogRoot),
            path => path.EndsWith(".gc", StringComparison.Ordinal));
        Assert.Single(Directory.EnumerateFiles(catalogRoot, "*.pmac1.json"));
    }

    [Fact]
    public async Task ArtifactCatalog_DurablePublishedStateRejectsSignedPointerRollback()
    {
        using var first = Fixture.Create();
        using var second = Fixture.CreateRotation(first);
        var state = new InMemoryProductionMailboxStateStore();
        var provider = new ProductionMailboxArtifactProvider(
            first.Options, first.TimeProvider);
        var oldClosureHash = ProductionMailboxArtifactProvider
            .ComputeArtifactClosureHash(provider.Current);
        _ = await state.GetOrInitializePublishedArtifactClosureAsync(
            oldClosureHash, CancellationToken.None);
        var catalogRoot = Path.Combine(Path.GetDirectoryName(
            first.Options.RouteStateHmacKeyPath)!,
            "production-mailbox-artifact-catalog");
        var pointerPath = Path.Combine(catalogRoot, "active.pmac1");
        var oldSignedPointer = File.ReadAllBytes(pointerPath);
        var newClosureHash = ProductionMailboxArtifactProvider
            .ComputeArtifactClosureHash(second.Artifacts);
        var promotion = await state.BeginArtifactPromotionAsync(
            Fixture.Bytes(0xF1, 32), oldClosureHash, newClosureHash,
            CancellationToken.None);
        Assert.True(await state.CompleteArtifactPromotionSweepAsync(
            promotion.PromotionStateKey, CancellationToken.None));
        provider.PublishVerified(second.Artifacts, Fixture.Now);
        Assert.True(await state.MarkArtifactPromotionPublishedAsync(
            promotion.PromotionStateKey, CancellationToken.None));

        File.WriteAllBytes(pointerPath, oldSignedPointer);
        var rolledBack = new ProductionMailboxArtifactProvider(
            first.Options, first.TimeProvider);
        Assert.Equal(first.Artifacts.AuthoritySha256,
            rolledBack.Current.AuthoritySha256);
        var validator = new ProductionMailboxArtifactsStartupValidator(
            rolledBack, state);
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            validator.StartAsync(CancellationToken.None));
    }

    [Fact]
    public void ArtifactSnapshot_ReturnedArraysCannotMutateVerifiedOwnedState()
    {
        using var first = Fixture.Create();
        var provider = new ProductionMailboxArtifactProvider(
            first.Options, first.TimeProvider);
        var expectedAuthority = first.Artifacts.AuthorityBytes;
        var expectedAuthorityHash = first.Artifacts.AuthoritySha256;
        var expectedClosureHash = ProductionMailboxArtifactProvider
            .ComputeArtifactClosureHash(provider.Current);
        foreach (var value in new[]
                 {
                     provider.Current.AuthorityBytes,
                     provider.Current.RevocationBytes,
                     provider.Current.TopologyBytes,
                     provider.Current.AuthoritySha256,
                     provider.Current.RevocationSha256,
                     provider.Current.TopologySha256
                 })
            value.AsSpan().Fill(0xFF);

        Assert.Equal(expectedAuthority, provider.Current.AuthorityBytes);
        Assert.Equal(expectedAuthorityHash, provider.Current.AuthoritySha256);
        Assert.Equal(expectedClosureHash,
            ProductionMailboxArtifactProvider.ComputeArtifactClosureHash(
                provider.Current));
        Assert.True(provider.TryGetArtifact(
            Convert.ToHexStringLower(expectedAuthorityHash), "authority.pma1",
            out var served, out _));
        served.AsSpan().Fill(0xEE);
        Assert.True(provider.TryGetArtifact(
            Convert.ToHexStringLower(expectedAuthorityHash), "authority.pma1",
            out var servedAgain, out _));
        Assert.Equal(expectedAuthority, servedAgain);
        var publicProperties = typeof(ProductionMailboxArtifacts).GetProperties()
            .Select(static property => property.Name).ToArray();
        Assert.DoesNotContain("Authority", publicProperties);
        Assert.DoesNotContain("Revocation", publicProperties);
        Assert.DoesNotContain("Topology", publicProperties);
    }

    [Fact]
    public void ArtifactCatalog_RejectsManifestPredecessorContextTamper()
    {
        using var fixture = Fixture.Create();
        _ = new ProductionMailboxArtifactProvider(
            fixture.Options, fixture.TimeProvider);
        var catalogRoot = Path.Combine(Path.GetDirectoryName(
            fixture.Options.RouteStateHmacKeyPath)!,
            "production-mailbox-artifact-catalog");
        var manifestPath = Directory.EnumerateFiles(
            catalogRoot, "*.pmac1.json").Single();
        var manifest = JsonNode.Parse(File.ReadAllBytes(manifestPath))!.AsObject();
        manifest["previousTopologyGeneration"] = 123456UL;
        File.WriteAllBytes(manifestPath,
            System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(manifest,
                new System.Text.Json.JsonSerializerOptions(
                    System.Text.Json.JsonSerializerDefaults.Web)));

        Assert.Throws<InvalidDataException>(() =>
            new ProductionMailboxArtifactProvider(
                fixture.Options, fixture.TimeProvider));
    }

    [Fact]
    public async Task HttpArtifacts_UseExactMediaTypeAndEtag_WhileAdminIsPrivate()
    {
        using var fixture = Fixture.Create();
        using var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment(Environments.Development);
            builder.UseSetting("ProductionMailbox:Enabled", "true");
            builder.ConfigureAppConfiguration((_, configuration) =>
                configuration.AddInMemoryCollection(fixture.OptionsDictionary()));
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<TimeProvider>();
                services.AddSingleton<TimeProvider>(fixture.TimeProvider);
            });
        });
        using var client = factory.CreateClient();
        var authorityHash = Convert.ToHexStringLower(fixture.Artifacts.AuthoritySha256);
        var authorityPath = $"/api/production-mailbox/artifacts/{authorityHash}/authority.pma1";
        using var first = await client.GetAsync(authorityPath);
        Assert.Equal(System.Net.HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(ProductionMailboxMediaTypes.Authority, first.Content.Headers.ContentType?.MediaType);
        Assert.NotNull(first.Headers.ETag);
        using var cached = new HttpRequestMessage(HttpMethod.Get,
            authorityPath);
        cached.Headers.IfNoneMatch.Add(first.Headers.ETag!);
        using var notModified = await client.SendAsync(cached);
        Assert.Equal(System.Net.HttpStatusCode.NotModified, notModified.StatusCode);
        using var mutableAlias = await client.GetAsync(
            "/api/production-mailbox/artifacts/authority.pma1");
        Assert.Equal(System.Net.HttpStatusCode.NotFound, mutableAlias.StatusCode);
        using var admin = await client.GetAsync("/api/internal/production-mailbox/runtime");
        Assert.Equal(System.Net.HttpStatusCode.Unauthorized, admin.StatusCode);
        fixture.TimeProvider.Set(Fixture.Now + 2_000);
        using var unavailable = await client.PostAsync(
            "/api/production-mailbox/challenges", content: null);
        Assert.Equal(System.Net.HttpStatusCode.ServiceUnavailable, unavailable.StatusCode);
    }

    private static IEd25519ExternalSigner ResolveSigner(Dictionary<string, string?> values)
    {
        var configuration = new Microsoft.Extensions.Configuration.ConfigurationBuilder()
            .AddInMemoryCollection(values).Build();
        var services = new Microsoft.Extensions.DependencyInjection.ServiceCollection();
        services.AddSingleton<TimeProvider>(TimeProvider.System);
        _ = services.AddProductionMailbox(configuration, new FakeEnvironment("Production"));
        using var provider = services.BuildServiceProvider();
        return provider.GetRequiredService<IEd25519ExternalSigner>();
    }

    private sealed class FakeEnvironment(string name) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = name;
        public string ApplicationName { get; set; } = "tests";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }

    private sealed class InvalidSigner : IEd25519ExternalSigner
    {
        public ValueTask<byte[]> SignAsync(ReadOnlyMemory<byte> signingBytes, CancellationToken cancellationToken) =>
            ValueTask.FromResult(Fixture.Bytes(230, 64));
    }

    private sealed class CountingSigner : IEd25519ExternalSigner
    {
        private int calls;
        public int Calls => Volatile.Read(ref calls);
        public ValueTask<byte[]> SignAsync(
            ReadOnlyMemory<byte> signingBytes,
            CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref calls);
            return ValueTask.FromResult(Fixture.Bytes(230, 64));
        }
    }

    private sealed class AcceptingClosureTransport : IProductionMailboxClosureTransport
    {
        public List<ProductionMailboxPublicationItem> Received { get; } = [];
        public List<byte[]> CapacityCommands { get; } = [];
        public List<byte[]> ReconciliationCommands { get; } = [];
        public List<string> Events { get; } = [];
        public Func<ProductionMailboxPrepositionTarget, int, bool> AcceptCapacity { get; set; }
            = static (_, _) => true;
        public long ReceiptTimestampOffsetSeconds { get; set; }
        public int FailReleaseOrdinalOnce { get; set; }
        public bool ForceReconciliationForRelease { get; set; }
        private int releaseCalls;

        public ValueTask<bool> PrepositionAsync(
            ProductionMailboxPublicationItem item,
            ReadOnlyMemory<byte> canonicalCommand,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Events.Add("PMP");
            Received.Add(item with
            {
                LastAttemptSha256 = SHA256.HashData(canonicalCommand.Span)
            });
            return ValueTask.FromResult(true);
        }

        public ValueTask<byte[]?> ReserveCapacityAsync(
            ProductionMailboxPrepositionTarget target,
            ReadOnlyMemory<byte> canonicalCommand,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var command = canonicalCommand.ToArray();
            CapacityCommands.Add(command);
            var isRelease = command[5]
                == (byte)ProductionMailboxCapacityOperation.Release;
            Events.Add(isRelease ? "RELEASE" : "RESERVE");
            var releaseOrdinal = isRelease
                ? Interlocked.Increment(ref releaseCalls) : 0;
            var dropResponse = isRelease && (ForceReconciliationForRelease
                || FailReleaseOrdinalOnce != 0
                    && releaseOrdinal == FailReleaseOrdinalOnce);
            return ValueTask.FromResult<byte[]?>(
                !dropResponse && AcceptCapacity(target, CapacityCommands.Count)
                    ? CreateCapacityReceipt(command, ReceiptTimestampOffsetSeconds) : null);
        }

        public ValueTask<byte[]?> ReconcileCapacityAsync(
            ProductionMailboxPrepositionTarget target,
            ReadOnlyMemory<byte> canonicalCommand,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Events.Add("RECONCILE");
            var command = canonicalCommand.ToArray();
            ReconciliationCommands.Add(command);
            return ValueTask.FromResult<byte[]?>(
                ForceReconciliationForRelease
                    ? CreateCapacityReconciliationReceipt(command) : null);
        }
    }

    private sealed class SwitchableClosureTransport : IProductionMailboxClosureTransport
    {
        public bool Accept { get; set; }
        public List<string> CommandHashes { get; } = [];

        public ValueTask<bool> PrepositionAsync(
            ProductionMailboxPublicationItem item,
            ReadOnlyMemory<byte> canonicalCommand,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            CommandHashes.Add(Convert.ToHexString(SHA256.HashData(canonicalCommand.Span)));
            return ValueTask.FromResult(Accept);
        }

        public ValueTask<byte[]?> ReserveCapacityAsync(
            ProductionMailboxPrepositionTarget target,
            ReadOnlyMemory<byte> canonicalCommand,
            CancellationToken cancellationToken) => ValueTask.FromResult<byte[]?>(
                Accept ? CreateCapacityReceipt(canonicalCommand.Span) : null);

        public ValueTask<byte[]?> ReconcileCapacityAsync(
            ProductionMailboxPrepositionTarget target,
            ReadOnlyMemory<byte> canonicalCommand,
            CancellationToken cancellationToken) => ValueTask.FromResult<byte[]?>(null);
    }

    private sealed class RealXNodeClosureTransport :
        IProductionMailboxClosureTransport, IDisposable
    {
        private readonly string root = Path.Combine(
            Path.GetTempPath(), "deep-registry-real-xnode", Guid.NewGuid().ToString("N"));
        private readonly string publisherPublicKey;
        private readonly string expectedNetworkId;
        private readonly string pinnedMrXPublicKeySha256;
        private readonly FixedTimeProvider timeProvider;
        private readonly uint maximumReservationLifetimeSeconds;
        private readonly Dictionary<string, NodeConfiguration> configurations =
            new(StringComparer.Ordinal);
        private readonly Dictionary<string,
            xnode::XNode.ProductionMailboxClosureStore> stores =
            new(StringComparer.Ordinal);

        internal RealXNodeClosureTransport(
            string publisherPublicKey,
            string expectedNetworkId,
            string pinnedMrXPublicKeySha256,
            FixedTimeProvider timeProvider,
            uint maximumReservationLifetimeSeconds)
        {
            this.publisherPublicKey = publisherPublicKey;
            this.expectedNetworkId = expectedNetworkId;
            this.pinnedMrXPublicKeySha256 = pinnedMrXPublicKeySha256;
            this.timeProvider = timeProvider;
            this.maximumReservationLifetimeSeconds = maximumReservationLifetimeSeconds;
            Directory.CreateDirectory(root);
        }

        internal bool DropReleaseAndReconciliation { get; set; }
        internal int ReconciliationCount { get; private set; }
        internal string? LastFailure { get; private set; }

        public async ValueTask<bool> PrepositionAsync(
            ProductionMailboxPublicationItem item,
            ReadOnlyMemory<byte> canonicalCommand,
            CancellationToken cancellationToken)
        {
            try
            {
                await Store(item.TargetReplicaId).PrepositionAsync(
                    canonicalCommand, cancellationToken);
                return true;
            }
            catch (Exception exception) when (exception is InvalidDataException
                or InvalidOperationException or IOException)
            {
                LastFailure = exception.ToString();
                return false;
            }
        }

        public async ValueTask<byte[]?> ReserveCapacityAsync(
            ProductionMailboxPrepositionTarget target,
            ReadOnlyMemory<byte> canonicalCommand,
            CancellationToken cancellationToken)
        {
            if (DropReleaseAndReconciliation
                && canonicalCommand.Span[5]
                    == (byte)ProductionMailboxCapacityOperation.Release)
                return null;
            try
            {
                return await Store(target.ReplicaId).ReserveCapacityAsync(
                    canonicalCommand, cancellationToken);
            }
            catch (Exception exception) when (exception is InvalidDataException
                or InvalidOperationException or IOException)
            {
                LastFailure = exception.ToString();
                return null;
            }
        }

        public async ValueTask<byte[]?> ReconcileCapacityAsync(
            ProductionMailboxPrepositionTarget target,
            ReadOnlyMemory<byte> canonicalCommand,
            CancellationToken cancellationToken)
        {
            if (DropReleaseAndReconciliation) return null;
            try
            {
                var receipt = await Store(target.ReplicaId).ReconcileAbsentCapacityAsync(
                    canonicalCommand, cancellationToken);
                ReconciliationCount++;
                return receipt;
            }
            catch (Exception exception) when (exception is InvalidDataException
                or InvalidOperationException or IOException)
            {
                LastFailure = exception.ToString();
                return null;
            }
        }

        internal void Restart() => stores.Clear();

        private xnode::XNode.ProductionMailboxClosureStore Store(byte[] targetReplicaId)
        {
            var key = Convert.ToHexString(targetReplicaId);
            if (stores.TryGetValue(key, out var existing)) return existing;
            if (!configurations.TryGetValue(key, out var configuration))
            {
                byte[]? seed = null;
                for (var value = 0; value <= byte.MaxValue; value++)
                {
                    var candidate = Fixture.Bytes((byte)value, 32);
                    if (!PublicKeyAuth.GenerateKeyPair(candidate).PublicKey.AsSpan()
                            .SequenceEqual(targetReplicaId))
                        continue;
                    seed = candidate;
                    break;
                }
                if (seed is null)
                    throw new InvalidOperationException(
                        "The integration fixture does not own the selected XNode key.");
                var dataRoot = Path.Combine(root, key);
                Directory.CreateDirectory(dataRoot);
                var hmacKeyPath = Path.Combine(dataRoot, "closure-hmac.key");
                File.WriteAllBytes(hmacKeyPath, Fixture.Bytes(245, 32));
                var node = new XNode.Core.RouterNodeOptions
                {
                    DataDirectory = dataRoot,
                    RouterId = key,
                    Ed25519PrivateKey = Convert.ToHexString(seed)
                };
                var options = new xnode::XNode.ProductionMailboxAuthorityOptions
                {
                    ClosureDirectory = Path.Combine(dataRoot, "closures"),
                    ClosureStateHmacKeyPath = hmacKeyPath,
                    ClosurePublisherEd25519PublicKey = publisherPublicKey,
                    ExpectedNetworkId = expectedNetworkId,
                    PinnedMrXPublicKeySha256 = pinnedMrXPublicKeySha256,
                    ClockSkewSeconds = 0,
                    MaximumStoredClosures = 1_000,
                    MaximumClosureStoreBytes = 1_073_741_824,
                    MaximumClosureLineagesPerSelection = 4,
                    MaximumClosureReservations = 32,
                    MinimumClosureReservationLifetimeSeconds = 60,
                    MaximumClosureReservationLifetimeSeconds =
                        maximumReservationLifetimeSeconds,
                    ClosureAccountingOverheadBytes = 1_024
                };
                configuration = new(options, node);
                configurations.Add(key, configuration);
            }
            var store = new xnode::XNode.ProductionMailboxClosureStore(
                configuration.Options, configuration.Node,
                new XNodeTimeProviderClock(timeProvider),
                new XNode.Core.Mailbox.MailboxStorageSecurity(),
                new XNode.Core.Mailbox.MailboxDurabilityBarrier());
            stores.Add(key, store);
            return store;
        }

        public void Dispose()
        {
            stores.Clear();
            configurations.Clear();
            if (Directory.Exists(root)) Directory.Delete(root, true);
        }

        private sealed record NodeConfiguration(
            xnode::XNode.ProductionMailboxAuthorityOptions Options,
            XNode.Core.RouterNodeOptions Node);
    }

    private sealed class XNodeTimeProviderClock(FixedTimeProvider timeProvider) :
        XNode.Core.IClock
    {
        public DateTimeOffset UtcNow => timeProvider.GetUtcNow();
    }

    private static byte[] CreateCapacityReceipt(
        ReadOnlySpan<byte> command,
        long receiptTimestampOffsetSeconds = 0)
    {
        Assert.Equal(ProductionMailboxCapacityCommandCodec.EncodedLength,
            command.Length);
        var operation = (ProductionMailboxCapacityOperation)command[5];
        var target = command.Slice(88, 32).ToArray();
        byte[]? privateKey = null;
        for (var seed = 0; seed <= byte.MaxValue; seed++)
        {
            var pair = PublicKeyAuth.GenerateKeyPair(Fixture.Bytes((byte)seed, 32));
            if (!pair.PublicKey.AsSpan().SequenceEqual(target)) continue;
            privateKey = pair.PrivateKey;
            break;
        }
        Assert.NotNull(privateKey);
        var reservedCount = operation == ProductionMailboxCapacityOperation.Release
            ? 0U : BinaryPrimitives.ReadUInt32BigEndian(command[120..]);
        var reservedBytes = operation == ProductionMailboxCapacityOperation.Release
            ? 0UL : BinaryPrimitives.ReadUInt64BigEndian(command[124..]);
        var commandTimestamp = BinaryPrimitives.ReadUInt64BigEndian(command[8..]);
        var receiptTimestamp = receiptTimestampOffsetSeconds >= 0
            ? checked(commandTimestamp + (ulong)receiptTimestampOffsetSeconds)
            : checked(commandTimestamp - (ulong)-receiptTimestampOffsetSeconds);
        var unsigned = new ProductionMailboxCapacityReceipt(
            operation,
            receiptTimestamp,
            BinaryPrimitives.ReadUInt64BigEndian(command[16..]),
            command.Slice(56, 32).ToArray(), target,
            reservedCount, reservedBytes, 0, 0,
            BinaryPrimitives.ReadUInt64BigEndian(command[132..]),
            SHA256.HashData(command), new byte[64]);
        var signature = PublicKeyAuth.SignDetached(
            ProductionMailboxCapacityReceiptCodec.GetSigningBytes(unsigned),
            privateKey);
        return ProductionMailboxCapacityReceiptCodec.Encode(
            unsigned with { NodeSignature = signature });
    }

    private static byte[] CreateCapacityReconciliationReceipt(
        ReadOnlySpan<byte> command)
    {
        Assert.Equal(ProductionMailboxCapacityReconciliationCommandCodec.EncodedLength,
            command.Length);
        var target = command.Slice(88, 32).ToArray();
        byte[]? privateKey = null;
        for (var seed = 0; seed <= byte.MaxValue; seed++)
        {
            var pair = PublicKeyAuth.GenerateKeyPair(Fixture.Bytes((byte)seed, 32));
            if (!pair.PublicKey.AsSpan().SequenceEqual(target)) continue;
            privateKey = pair.PrivateKey;
            break;
        }
        Assert.NotNull(privateKey);
        var unsigned = new ProductionMailboxCapacityReconciliationReceipt(
            ProductionMailboxCapacityReconciliationStatus.AbsentTerminal,
            BinaryPrimitives.ReadUInt64BigEndian(command[8..]),
            BinaryPrimitives.ReadUInt64BigEndian(command[16..]),
            command.Slice(56, 32).ToArray(), target,
            BinaryPrimitives.ReadUInt64BigEndian(command[120..]),
            command.Slice(376, 32).ToArray(), command.Slice(408, 32).ToArray(),
            0, 0, Fixture.Bytes(241, 32), new byte[64]);
        var signature = PublicKeyAuth.SignDetached(
            ProductionMailboxCapacityReconciliationReceiptCodec.GetSigningBytes(unsigned),
            privateKey);
        return ProductionMailboxCapacityReconciliationReceiptCodec.Encode(
            unsigned with { NodeSignature = signature });
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        private long unixSeconds = now.ToUnixTimeSeconds();
        public override DateTimeOffset GetUtcNow() =>
            DateTimeOffset.FromUnixTimeSeconds(Interlocked.Read(ref unixSeconds));
        public void Set(ulong value) => Interlocked.Exchange(ref unixSeconds, checked((long)value));
    }

    private sealed class PostgresTestDatabase : IAsyncDisposable
    {
        private readonly string administrativeConnectionString;
        private readonly string schema;

        private PostgresTestDatabase(
            string administrativeConnectionString,
            string schema,
            string connectionString)
        {
            this.administrativeConnectionString = administrativeConnectionString;
            this.schema = schema;
            ConnectionString = connectionString;
        }

        public string ConnectionString { get; }

        public static async ValueTask<PostgresTestDatabase> CreateAsync(
            string connectionString)
        {
            var schema = "deep_registry_test_"
                + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(8));
            var quotedSchema = new NpgsqlCommandBuilder().QuoteIdentifier(schema);
            await using (var connection = new NpgsqlConnection(connectionString))
            {
                await connection.OpenAsync();
                await using var command = new NpgsqlCommand(
                    $"CREATE SCHEMA {quotedSchema}", connection);
                await command.ExecuteNonQueryAsync();
            }
            var isolated = new NpgsqlConnectionStringBuilder(connectionString)
            {
                SearchPath = schema,
                Pooling = false
            };
            return new PostgresTestDatabase(
                connectionString, schema, isolated.ConnectionString);
        }

        public async ValueTask DisposeAsync()
        {
            var quotedSchema = new NpgsqlCommandBuilder().QuoteIdentifier(schema);
            await using var connection = new NpgsqlConnection(
                administrativeConnectionString);
            await connection.OpenAsync();
            await using var command = new NpgsqlCommand(
                $"DROP SCHEMA IF EXISTS {quotedSchema} CASCADE", connection);
            await command.ExecuteNonQueryAsync();
        }
    }

    private sealed class Fixture : IDisposable
    {
        public const ulong Now = 2_100_000_000;
        private readonly string root;
        private Fixture(string root, ProductionMailboxOptions options, FixedTimeProvider timeProvider,
            ProductionMailboxArtifacts artifacts, byte[] issuerPublicKey, byte[] holderPublicKey,
            byte[] holderPrivateKey, byte[] ownerPublicKey, byte[] ownerPrivateKey,
            int maximumChallenges, byte[] issuerSeed, byte[] mrXPrivateKey,
            MembershipRouteDescriptor[] nextDescriptors,
            ulong routeAdvertisementSequence)
        {
            this.root = root; Options = options; TimeProvider = timeProvider; Artifacts = artifacts;
            IssuerPublicKey = issuerPublicKey; HolderPublicKey = holderPublicKey;
            HolderPrivateKey = holderPrivateKey; OwnerPublicKey = ownerPublicKey;
            OwnerPrivateKey = ownerPrivateKey; MaximumChallenges = maximumChallenges;
            IssuerSeed = issuerSeed; MrXPrivateKey = mrXPrivateKey;
            NextDescriptors = nextDescriptors;
            RouteAdvertisementSequence = routeAdvertisementSequence;
            IssuerSeedPath = Path.Combine(root, "issuer.seed");
        }

        public ProductionMailboxOptions Options { get; }
        public FixedTimeProvider TimeProvider { get; }
        public ProductionMailboxArtifacts Artifacts { get; }
        public byte[] IssuerPublicKey { get; }
        public byte[] HolderPublicKey { get; }
        public byte[] HolderPrivateKey { get; }
        public byte[] OwnerPublicKey { get; }
        public byte[] OwnerPrivateKey { get; }
        public string IssuerSeedPath { get; }
        public int MaximumChallenges { get; }
        public byte[] IssuerSeed { get; }
        public byte[] MrXPrivateKey { get; }
        public MembershipRouteDescriptor[] NextDescriptors { get; }
        public ulong RouteAdvertisementSequence { get; }

        public static Fixture Create(int maximumChallenges = 16, byte artifactSeedOffset = 0)
        {
            var root = Path.Combine(Path.GetTempPath(), "deep-pma-tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(root);
            var proofRoot = Path.Combine(root, "proofs"); Directory.CreateDirectory(proofRoot);
            var issuerSeed = Bytes(unchecked((byte)(30 + artifactSeedOffset)), 32);
            var issuer = PublicKeyAuth.GenerateKeyPair(issuerSeed);
            var mrX = PublicKeyAuth.GenerateKeyPair(Bytes(unchecked((byte)(60 + artifactSeedOffset)), 32));
            var holder = PublicKeyAuth.GenerateKeyPair(Bytes(unchecked((byte)(90 + artifactSeedOffset)), 32));
            var owner = PublicKeyAuth.GenerateKeyPair(Bytes(unchecked((byte)(100 + artifactSeedOffset)), 32));
            File.WriteAllBytes(Path.Combine(root, "issuer.seed"), issuerSeed);
            var routeStateHmacKeyPath = Path.Combine(root, "route-state-hmac.key");
            File.WriteAllBytes(routeStateHmacKeyPath,
                Bytes(unchecked((byte)(110 + artifactSeedOffset)), 32));
            var current = Descriptors(9, Now - 200, Now + 1_000);
            var next = Descriptors(10, Now - 10, Now + 1_200);
            var draft = Authority(issuer.PublicKey, mrX.PublicKey,
                MembershipRouteDescriptorCodec.ComputeRoot(current),
                MembershipRouteDescriptorCodec.ComputeRoot(next));
            var unsignedRevocation = new ProductionMailboxRevocationSnapshot
            {
                NetworkId = draft.NetworkId,
                AuthorityGeneration = draft.AuthorityGeneration,
                AuthorityBindingHash = ProductionMailboxRevocationSnapshotCodec.ComputeAuthorityBindingHash(draft),
                RevocationGeneration = draft.Revocation.Generation,
                RevocationHeadHash = draft.Revocation.HeadHash,
                PreviousRevocationHeadHash = draft.Revocation.PreviousHeadHash,
                IssuedAtUnixSeconds = draft.Revocation.IssuedAtUnixSeconds,
                ExpiresAtUnixSeconds = draft.Revocation.ExpiresAtUnixSeconds,
                RevokedGrantSerials = [],
                IssuerSignature = new byte[64]
            };
            var revocation = unsignedRevocation with
            {
                IssuerSignature = PublicKeyAuth.SignDetached(
                    ProductionMailboxRevocationSnapshotCodec.GetSigningBytes(unsignedRevocation), issuer.PrivateKey)
            };
            var revocationBytes = ProductionMailboxRevocationSnapshotCodec.Encode(revocation);
            var authority = SignAuthority(draft with
            {
                Revocation = draft.Revocation with { SnapshotHash = SHA256.HashData(revocationBytes) }
            }, mrX.PrivateKey);
            var authorityBytes = ProductionMailboxAuthorityCodec.Encode(authority);
            var verifiedAuthority = ProductionMailboxAuthorityVerifier.Verify(authority,
                AuthorityContext(authority, mrX.PublicKey), new SodiumProductionMailboxAuthoritySignatureVerifier());
            var topology = new ProductionMailboxTopologySnapshot
            {
                NetworkId = authority.NetworkId,
                AuthorityGeneration = authority.AuthorityGeneration,
                CanonicalAuthorityHash = verifiedAuthority.CanonicalAuthorityHash,
                TopologyGeneration = 3,
                PreviousTopologyHash = Bytes(120, 32),
                IssuedAtUnixSeconds = Now - 5,
                ExpiresAtUnixSeconds = Now + 500,
                CurrentEpoch = TopologyEpoch(authority.CurrentEpoch, current),
                NextEpoch = TopologyEpoch(authority.NextEpoch, next),
                IssuerSignature = new byte[64]
            };
            topology = SignTopology(topology, issuer.PrivateKey);
            var topologyBytes = ProductionMailboxTopologyCodec.Encode(topology);
            WriteProofs(proofRoot, current); WriteProofs(proofRoot, next);
            var authorityPath = Path.Combine(root, "authority.pma1"); File.WriteAllBytes(authorityPath, authorityBytes);
            var revocationPath = Path.Combine(root, "revocations.pmr1"); File.WriteAllBytes(revocationPath, revocationBytes);
            var topologyPath = Path.Combine(root, "topology.pmt1"); File.WriteAllBytes(topologyPath, topologyBytes);
            var options = new ProductionMailboxOptions
            {
                Enabled = true,
                AuthorityPath = authorityPath,
                RevocationPath = revocationPath,
                TopologyPath = topologyPath,
                MembershipProofDirectory = proofRoot,
                PinnedMrXPublicKeySha256 = Hex(SHA256.HashData(mrX.PublicKey)),
                ExpectedNetworkId = Hex(authority.NetworkId.Span),
                PreviousAuthorityGeneration = 6,
                PreviousAuthorityHash = Hex(authority.PreviousAuthorityHash.Span),
                PreviousRevocationGeneration = 5,
                PreviousRevocationHeadHash = Hex(authority.Revocation.PreviousHeadHash.Span),
                PreviousRevocationSnapshotHash = Hex(Bytes(23, 32)),
                PreviousTopologyGeneration = 2,
                PreviousTopologyHash = Hex(topology.PreviousTopologyHash.Span),
                ClockSkewSeconds = 0,
                SelectionLifetimeSeconds = 300,
                ChallengeLifetimeSeconds = 300,
                ProofOfWorkLeadingZeroBits = 8,
                MaximumChallengesPerWindow = maximumChallenges,
                ChallengeWindowSeconds = 60,
                UseDevelopmentInMemoryState = true,
                DevelopmentSoftwareSignerSeedPath = Path.Combine(root, "issuer.seed"),
                DevelopmentClosurePublisherSeedPath = Path.Combine(root, "issuer.seed"),
                ClosurePublisherEd25519PublicKey = Hex(issuer.PublicKey),
                RouteStateHmacKeyPath = routeStateHmacKeyPath
            };
            var time = new FixedTimeProvider(DateTimeOffset.FromUnixTimeSeconds(checked((long)Now)));
            var artifacts = ProductionMailboxArtifacts.Load(options, time);
            return new Fixture(root, options, time, artifacts, issuer.PublicKey,
                holder.PublicKey, holder.PrivateKey, owner.PublicKey, owner.PrivateKey,
                maximumChallenges, issuerSeed, mrX.PrivateKey, next, 1);
        }

        public static Fixture CreateRotation(Fixture previous, int routeVariant = 0)
        {
            var root = Path.Combine(Path.GetTempPath(), "deep-pma-tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(root);
            var proofRoot = Path.Combine(root, "proofs"); Directory.CreateDirectory(proofRoot);
            File.WriteAllBytes(Path.Combine(root, "issuer.seed"), previous.IssuerSeed);
            var routeStateHmacKeyPath = Path.Combine(root, "route-state-hmac.key");
            File.Copy(previous.Options.RouteStateHmacKeyPath, routeStateHmacKeyPath);
            var issuer = PublicKeyAuth.GenerateKeyPair(previous.IssuerSeed);
            var oldAuthority = previous.Artifacts.Authority.Authority;
            var current = previous.NextDescriptors;
            var nextEpochNumber = oldAuthority.NextEpoch.Epoch + 1;
            var next = Descriptors(nextEpochNumber, Now - 10, Now + 1_800,
                routeVariant);
            var nextEpoch = Epoch(nextEpochNumber, oldAuthority.NextEpoch.Generation + 1,
                MembershipRouteDescriptorCodec.ComputeRoot(next),
                Bytes(unchecked((byte)(12 + nextEpochNumber)), 32),
                Now - 10, Now + 1_800);
            var draft = oldAuthority with
            {
                AuthorityGeneration = oldAuthority.AuthorityGeneration + 1,
                PreviousAuthorityHash = previous.Artifacts.AuthoritySha256,
                CurrentEpoch = oldAuthority.NextEpoch,
                NextEpoch = nextEpoch,
                Revocation = oldAuthority.Revocation with
                {
                    Generation = oldAuthority.Revocation.Generation + 1,
                    PreviousHeadHash = oldAuthority.Revocation.HeadHash,
                    HeadHash = Bytes(unchecked((byte)(25 + oldAuthority.Revocation.Generation)), 32),
                    IssuedAtUnixSeconds = Now - 10,
                    ExpiresAtUnixSeconds = Now + 800
                },
                MrXApproval = oldAuthority.MrXApproval with
                {
                    RolloutNotBeforeUnixSeconds = Now - 10,
                    RolloutNotAfterUnixSeconds = Now + 800
                },
                Signature = new byte[64]
            };
            var unsignedRevocation = new ProductionMailboxRevocationSnapshot
            {
                NetworkId = draft.NetworkId,
                AuthorityGeneration = draft.AuthorityGeneration,
                AuthorityBindingHash = ProductionMailboxRevocationSnapshotCodec.ComputeAuthorityBindingHash(draft),
                RevocationGeneration = draft.Revocation.Generation,
                RevocationHeadHash = draft.Revocation.HeadHash,
                PreviousRevocationHeadHash = draft.Revocation.PreviousHeadHash,
                IssuedAtUnixSeconds = draft.Revocation.IssuedAtUnixSeconds,
                ExpiresAtUnixSeconds = draft.Revocation.ExpiresAtUnixSeconds,
                RevokedGrantSerials = [],
                IssuerSignature = new byte[64]
            };
            var revocation = unsignedRevocation with
            {
                IssuerSignature = PublicKeyAuth.SignDetached(
                    ProductionMailboxRevocationSnapshotCodec.GetSigningBytes(unsignedRevocation),
                    issuer.PrivateKey)
            };
            var revocationBytes = ProductionMailboxRevocationSnapshotCodec.Encode(revocation);
            var authority = SignAuthority(draft with
            {
                Revocation = draft.Revocation with { SnapshotHash = SHA256.HashData(revocationBytes) }
            }, previous.MrXPrivateKey);
            var authorityBytes = ProductionMailboxAuthorityCodec.Encode(authority);
            var verifiedAuthority = ProductionMailboxAuthorityVerifier.Verify(authority,
                new ProductionMailboxAuthorityVerificationContext
                {
                    PinnedMrXPublicKeySha256 = SHA256.HashData(authority.MrXApprovalEd25519PublicKey.Span),
                    ExpectedNetworkId = authority.NetworkId,
                    LastCommittedGeneration = oldAuthority.AuthorityGeneration,
                    LastCommittedAuthorityHash = previous.Artifacts.AuthoritySha256,
                    LastCommittedRevocationGeneration = oldAuthority.Revocation.Generation,
                    LastCommittedRevocationHeadHash = oldAuthority.Revocation.HeadHash,
                    LastCommittedRevocationSnapshotHash = previous.Artifacts.RevocationSha256,
                    NowUnixSeconds = Now,
                    ClockSkewSeconds = 0
                }, new SodiumProductionMailboxAuthoritySignatureVerifier());
            var topology = SignTopology(new ProductionMailboxTopologySnapshot
            {
                NetworkId = authority.NetworkId,
                AuthorityGeneration = authority.AuthorityGeneration,
                CanonicalAuthorityHash = verifiedAuthority.CanonicalAuthorityHash,
                TopologyGeneration = previous.Artifacts.Topology.Snapshot.TopologyGeneration + 1,
                PreviousTopologyHash = previous.Artifacts.TopologySha256,
                IssuedAtUnixSeconds = Now - 2,
                ExpiresAtUnixSeconds = Now + 500,
                CurrentEpoch = TopologyEpoch(authority.CurrentEpoch, current),
                NextEpoch = TopologyEpoch(authority.NextEpoch, next),
                IssuerSignature = new byte[64]
            }, issuer.PrivateKey);
            var topologyBytes = ProductionMailboxTopologyCodec.Encode(topology);
            WriteProofs(proofRoot, current); WriteProofs(proofRoot, next);
            var authorityPath = Path.Combine(root, "authority.pma1"); File.WriteAllBytes(authorityPath, authorityBytes);
            var revocationPath = Path.Combine(root, "revocations.pmr1"); File.WriteAllBytes(revocationPath, revocationBytes);
            var topologyPath = Path.Combine(root, "topology.pmt1"); File.WriteAllBytes(topologyPath, topologyBytes);
            var options = new ProductionMailboxOptions
            {
                Enabled = true,
                AuthorityPath = authorityPath,
                RevocationPath = revocationPath,
                TopologyPath = topologyPath,
                MembershipProofDirectory = proofRoot,
                PinnedMrXPublicKeySha256 = Hex(SHA256.HashData(authority.MrXApprovalEd25519PublicKey.Span)),
                ExpectedNetworkId = Hex(authority.NetworkId.Span),
                PreviousAuthorityGeneration = oldAuthority.AuthorityGeneration,
                PreviousAuthorityHash = Hex(previous.Artifacts.AuthoritySha256),
                PreviousRevocationGeneration = oldAuthority.Revocation.Generation,
                PreviousRevocationHeadHash = Hex(oldAuthority.Revocation.HeadHash.Span),
                PreviousRevocationSnapshotHash = Hex(previous.Artifacts.RevocationSha256),
                PreviousTopologyGeneration = previous.Artifacts.Topology.Snapshot.TopologyGeneration,
                PreviousTopologyHash = Hex(previous.Artifacts.TopologySha256),
                ClockSkewSeconds = 0,
                SelectionLifetimeSeconds = 300,
                ChallengeLifetimeSeconds = 300,
                ProofOfWorkLeadingZeroBits = 8,
                MaximumChallengesPerWindow = previous.MaximumChallenges,
                ChallengeWindowSeconds = 60,
                UseDevelopmentInMemoryState = true,
                DevelopmentSoftwareSignerSeedPath = Path.Combine(root, "issuer.seed"),
                DevelopmentClosurePublisherSeedPath = Path.Combine(root, "issuer.seed"),
                ClosurePublisherEd25519PublicKey = Hex(issuer.PublicKey),
                RouteStateHmacKeyPath = routeStateHmacKeyPath
            };
            var time = new FixedTimeProvider(DateTimeOffset.FromUnixTimeSeconds(checked((long)Now)));
            var artifacts = ProductionMailboxArtifacts.Load(options, time);
            return new Fixture(root, options, time, artifacts, issuer.PublicKey,
                previous.HolderPublicKey, previous.HolderPrivateKey,
                previous.OwnerPublicKey, previous.OwnerPrivateKey, previous.MaximumChallenges,
                previous.IssuerSeed, previous.MrXPrivateKey, next,
                checked(previous.RouteAdvertisementSequence + 1));
        }

        public ProductionMailboxCoordinator Coordinator(
            IProductionMailboxStateStore state,
            IEd25519ExternalSigner signer,
            IProductionMailboxClosureTransport? closureTransport = null) => new(
                Microsoft.Extensions.Options.Options.Create(Options), Artifacts, signer, state,
                TimeProvider, new ProductionMailboxMetrics(),
                new ProductionMailboxClosurePublisherSignerAdapter(signer),
                closureTransport ?? new AcceptingClosureTransport());

        public Task<ProductionMailboxIssueRequest> RequestAsync(ProductionMailboxCoordinator coordinator) =>
            RequestAsync(coordinator, ProductionMailboxIssuanceIntent.LocalOwner,
                HolderPublicKey, HolderPrivateKey, OwnerPublicKey, OwnerPrivateKey);

        public async Task<ProductionMailboxIssueRequest> RequestAsync(
            ProductionMailboxCoordinator coordinator,
            ProductionMailboxIssuanceIntent intent,
            byte[] holderPublicKey,
            byte[] holderPrivateKey,
            byte[] ownerPublicKey,
            byte[]? ownerPrivateKey,
            byte[]? signingCertificate = null,
            byte[]? buildArtifact = null)
        {
            var request = await RawRequestAsync(
                coordinator, intent, holderPublicKey, holderPrivateKey,
                ownerPublicKey, ownerPrivateKey, signingCertificate, buildArtifact);
            if (intent != ProductionMailboxIssuanceIntent.LocalOwner)
                return request;
            if (ownerPrivateKey is null)
                throw new InvalidOperationException(
                    "Local owner enrollment requires the owner private key in tests.");
            var enrollment = await coordinator.EnrollRouteAsync(
                request, CancellationToken.None);
            var certificate = ProductionMailboxRouteAdvertisementCodec.DecodeCertificate(
                Decode(enrollment.RouteCertificate.CanonicalBase64Url));
            var advertisementDraft = new ProductionMailboxRouteAdvertisement
            {
                Certificate = certificate,
                Sequence = RouteAdvertisementSequence,
                PublishedAtUnixSeconds = Now,
                ExpiresAtUnixSeconds = certificate.ExpiresAtUnixSeconds,
                OwnerSignature = new byte[64]
            };
            var advertisement = advertisementDraft with
            {
                OwnerSignature = PublicKeyAuth.SignDetached(
                    ProductionMailboxRouteAdvertisementCodec.GetAdvertisementSigningBytes(
                        advertisementDraft), ownerPrivateKey)
            };
            var credentialRequest = await RawRequestAsync(
                coordinator, intent, holderPublicKey, holderPrivateKey,
                ownerPublicKey, ownerPrivateKey, signingCertificate, buildArtifact);
            return Resign(credentialRequest with
            {
                EnrollmentHandle = enrollment.EnrollmentHandle,
                RouteAdvertisement = B64(
                    ProductionMailboxRouteAdvertisementCodec.EncodeAdvertisement(advertisement))
            }, holderPrivateKey, ownerPrivateKey);
        }

        private async Task<ProductionMailboxIssueRequest> RawRequestAsync(
            ProductionMailboxCoordinator coordinator,
            ProductionMailboxIssuanceIntent intent,
            byte[] holderPublicKey,
            byte[] holderPrivateKey,
            byte[] ownerPublicKey,
            byte[]? ownerPrivateKey,
            byte[]? signingCertificate,
            byte[]? buildArtifact)
        {
            var challenge = await coordinator.CreateChallengeAsync(CancellationToken.None);
            var id = Decode(challenge.ChallengeId); var value = Decode(challenge.Challenge);
            var nonce = Solve(id, value, challenge.LeadingZeroBits);
            var route = DeriveOwnerRoute(ownerPublicKey);
            var mailbox = intent == ProductionMailboxIssuanceIntent.LocalOwner ? "" : B64(route.MailboxId);
            var placement = intent == ProductionMailboxIssuanceIntent.LocalOwner ? "" : B64(route.PlacementId);
            var selection = intent == ProductionMailboxIssuanceIntent.LocalOwner ? "" : B64(route.SelectionCommitment);
            var certificate = signingCertificate ?? Bytes(15, 32);
            var artifact = buildArtifact ?? Bytes(17, 32);
            var request = new ProductionMailboxIssueRequest(
                B64(holderPublicKey), B64(ownerPublicKey), intent,
                ProductionMailboxClientPlatform.Android,
                B64(certificate), B64(artifact), "", B64(new byte[32]), mailbox, placement, selection,
                challenge.ChallengeId, challenge.Challenge, nonce,
                "", null, null);
            return Resign(request, holderPrivateKey, ownerPrivateKey);
        }

        public ProductionMailboxIssueRequest Resign(
            ProductionMailboxIssueRequest request,
            byte[]? holderPrivateKey = null,
            byte[]? ownerPrivateKey = null)
        {
            var entitlement = string.IsNullOrEmpty(request.OpaqueEntitlement)
                ? Array.Empty<byte>() : Decode(request.OpaqueEntitlement);
            var entitlementCommitment = entitlement.Length == 0
                ? new byte[32] : SHA256.HashData(entitlement);
            var canonical = request with { EntitlementCommitment = B64(entitlementCommitment) };
            canonical = canonical with { IdempotencyKey = B64(ComputeIdempotencyKey(canonical)) };
            return SignExact(canonical, holderPrivateKey, ownerPrivateKey);
        }

        public ProductionMailboxIssueRequest SignExact(
            ProductionMailboxIssueRequest request,
            byte[]? holderPrivateKey = null,
            byte[]? ownerPrivateKey = null)
        {
            var proof = ProductionMailboxHolderProof.GetSigningBytes(ProofInput(request));
            return request with
            {
                HolderProofSignature = B64(PublicKeyAuth.SignDetached(proof, holderPrivateKey ?? HolderPrivateKey)),
                OwnerProofSignature = request.Intent == ProductionMailboxIssuanceIntent.LocalOwner
                    ? B64(PublicKeyAuth.SignDetached(proof, ownerPrivateKey ?? OwnerPrivateKey)) : null
            };
        }

        private ProductionMailboxHolderProofInput ProofInput(ProductionMailboxIssueRequest request) => new()
        {
            Intent = request.Intent,
            Platform = request.Platform,
            NetworkId = Artifacts.Authority.Authority.NetworkId,
            CanonicalAuthorityHash = Artifacts.AuthoritySha256,
            HolderEd25519PublicKey = Decode(request.HolderEd25519PublicKey),
            MailboxOwnerEd25519PublicKey = Decode(request.MailboxOwnerEd25519PublicKey),
            BlindedMailboxId = string.IsNullOrEmpty(request.BlindedMailboxId) ? new byte[32] : Decode(request.BlindedMailboxId),
            BlindedPlacementId = string.IsNullOrEmpty(request.BlindedPlacementId) ? new byte[32] : Decode(request.BlindedPlacementId),
            SelectionInputCommitment = string.IsNullOrEmpty(request.SelectionInputCommitment) ? new byte[32] : Decode(request.SelectionInputCommitment),
            SigningCertificateSha256 = Decode(request.SigningCertificateSha256),
            BuildArtifactSha256 = Decode(request.BuildArtifactSha256),
            IdempotencyKey = Decode(request.IdempotencyKey),
            EntitlementCommitment = Decode(request.EntitlementCommitment),
            ChallengeId = Decode(request.ChallengeId),
            Challenge = Decode(request.Challenge),
            ProofOfWorkNonce = request.ProofOfWorkNonce
        };

        private byte[] ComputeIdempotencyKey(ProductionMailboxIssueRequest request) => DomainHash(
            "Deep/production-mailbox/issuance-idempotency/v1",
            Artifacts.AuthoritySha256, Artifacts.RevocationSha256, Artifacts.TopologySha256,
            Decode(request.HolderEd25519PublicKey), Decode(request.MailboxOwnerEd25519PublicKey),
            string.IsNullOrEmpty(request.BlindedMailboxId) ? new byte[32] : Decode(request.BlindedMailboxId),
            string.IsNullOrEmpty(request.BlindedPlacementId) ? new byte[32] : Decode(request.BlindedPlacementId),
            string.IsNullOrEmpty(request.SelectionInputCommitment) ? new byte[32] : Decode(request.SelectionInputCommitment),
            [(byte)request.Intent], [(byte)request.Platform], Decode(request.SigningCertificateSha256),
            Decode(request.BuildArtifactSha256), Decode(request.EntitlementCommitment));

        public OwnerRoute DeriveOwnerRoute(byte[] ownerPublicKey)
        {
            var routeInput = DomainHash("Deep/production-mailbox/owner-route-input/v2",
                Artifacts.Authority.Authority.NetworkId.ToArray(), ownerPublicKey);
            var mailbox = DomainHash("Deep/production-mailbox/blinded-mailbox-id/v2",
                Artifacts.Authority.Authority.NetworkId.ToArray(), ownerPublicKey, routeInput);
            var placement = DomainHash("Deep/production-mailbox/blinded-placement-id/v2",
                Artifacts.Authority.Authority.NetworkId.ToArray(), ownerPublicKey, routeInput);
            return new OwnerRoute(mailbox, placement,
                ProductionMailboxReplicaSelection.ComputeSelectionInputCommitment(new BlindedPlacementId(placement)));
        }

        public Dictionary<string, string?> OptionsDictionary() => new()
        {
            ["ProductionMailbox:Enabled"] = "true",
            ["ProductionMailbox:UseDevelopmentInMemoryState"] = "true",
            ["ProductionMailbox:AuthorityPath"] = Options.AuthorityPath,
            ["ProductionMailbox:RevocationPath"] = Options.RevocationPath,
            ["ProductionMailbox:TopologyPath"] = Options.TopologyPath,
            ["ProductionMailbox:MembershipProofDirectory"] = Options.MembershipProofDirectory,
            ["ProductionMailbox:PinnedMrXPublicKeySha256"] = Options.PinnedMrXPublicKeySha256,
            ["ProductionMailbox:ExpectedNetworkId"] = Options.ExpectedNetworkId,
            ["ProductionMailbox:PreviousAuthorityGeneration"] = Options.PreviousAuthorityGeneration.ToString(),
            ["ProductionMailbox:PreviousAuthorityHash"] = Options.PreviousAuthorityHash,
            ["ProductionMailbox:PreviousRevocationGeneration"] = Options.PreviousRevocationGeneration.ToString(),
            ["ProductionMailbox:PreviousRevocationHeadHash"] = Options.PreviousRevocationHeadHash,
            ["ProductionMailbox:PreviousRevocationSnapshotHash"] = Options.PreviousRevocationSnapshotHash,
            ["ProductionMailbox:PreviousTopologyGeneration"] = Options.PreviousTopologyGeneration.ToString(),
            ["ProductionMailbox:PreviousTopologyHash"] = Options.PreviousTopologyHash,
            ["ProductionMailbox:ClockSkewSeconds"] = "0",
            ["ProductionMailbox:SelectionLifetimeSeconds"] = Options.SelectionLifetimeSeconds.ToString(),
            ["ProductionMailbox:ChallengeLifetimeSeconds"] = Options.ChallengeLifetimeSeconds.ToString(),
            ["ProductionMailbox:ProofOfWorkLeadingZeroBits"] = Options.ProofOfWorkLeadingZeroBits.ToString(),
            ["ProductionMailbox:MaximumChallengesPerWindow"] = Options.MaximumChallengesPerWindow.ToString(),
            ["ProductionMailbox:ChallengeWindowSeconds"] = Options.ChallengeWindowSeconds.ToString(),
            ["ProductionMailbox:DevelopmentSoftwareSignerSeedPath"] = Options.DevelopmentSoftwareSignerSeedPath,
            ["ProductionMailbox:DevelopmentClosurePublisherSeedPath"] = Options.DevelopmentClosurePublisherSeedPath,
            ["ProductionMailbox:ClosurePublisherEd25519PublicKey"] = Options.ClosurePublisherEd25519PublicKey,
            ["ProductionMailbox:RouteStateHmacKeyPath"] = Options.RouteStateHmacKeyPath
        };

        public void Dispose()
        {
            if (Directory.Exists(root)) Directory.Delete(root, true);
        }

        private static ProductionMailboxAuthority Authority(byte[] issuer, byte[] mrX, byte[] currentRoot, byte[] nextRoot) => new()
        {
            DevelopmentOnly = false,
            Environment = ProductionMailboxAuthorityEnvironment.Production,
            Transport = ProductionMailboxAuthorityTransport.AuthenticatedMau2,
            Ownership = ProductionMailboxAuthorityOwnership.OfficialManaged,
            EndpointPolicy = ProductionMailboxAuthorityEndpointPolicy.PublicHttpsOnly,
            NetworkId = Bytes(1, 16),
            AuthorityGeneration = 7,
            PreviousAuthorityHash = Bytes(2, 32),
            MailboxIssuerEd25519PublicKey = issuer,
            MrXApprovalEd25519PublicKey = mrX,
            Coordinator = Endpoint("https://coord.example.net/", 4),
            NodeIngress = Endpoint("https://ingress.example.net/mau2/", 6),
            CurrentEpoch = Epoch(9, 70, currentRoot, Bytes(8, 32), Now - 200, Now + 1_000),
            NextEpoch = Epoch(10, 71, nextRoot, Bytes(10, 32), Now - 10, Now + 1_200),
            Revocation = new ProductionMailboxAuthorityRevocation
            {
                SnapshotHash = Bytes(12, 32),
                HeadHash = Bytes(13, 32),
                PreviousHeadHash = Bytes(22, 32),
                Generation = 6,
                IssuedAtUnixSeconds = Now - 20,
                ExpiresAtUnixSeconds = Now + 800
            },
            MrXApproval = new ProductionMailboxAuthorityApproval
            {
                AuthorityPayloadHash = Bytes(14, 32),
                AllowedAndroidSigningCertificateSha256 = [Bytes(15, 32)],
                AllowedWindowsSigningCertificateSha256 = [Bytes(16, 32)],
                AndroidReleaseBuildArtifactSha256 = [Bytes(17, 32)],
                WindowsReleaseBuildArtifactSha256 = [Bytes(18, 32)],
                RolloutNotBeforeUnixSeconds = Now - 30,
                RolloutNotAfterUnixSeconds = Now + 800
            },
            Signature = new byte[64]
        };

        private static ProductionMailboxAuthorityVerificationContext AuthorityContext(ProductionMailboxAuthority authority, byte[] mrX) => new()
        {
            PinnedMrXPublicKeySha256 = SHA256.HashData(mrX),
            ExpectedNetworkId = authority.NetworkId,
            LastCommittedGeneration = 6,
            LastCommittedAuthorityHash = authority.PreviousAuthorityHash,
            LastCommittedRevocationGeneration = 5,
            LastCommittedRevocationHeadHash = authority.Revocation.PreviousHeadHash,
            LastCommittedRevocationSnapshotHash = Bytes(23, 32),
            NowUnixSeconds = Now,
            ClockSkewSeconds = 0
        };

        private static ProductionMailboxAuthority SignAuthority(ProductionMailboxAuthority value, byte[] key)
        {
            var bound = value with
            {
                MrXApproval = value.MrXApproval with
                { AuthorityPayloadHash = ProductionMailboxAuthorityCodec.ComputePayloadHash(value) },
                Signature = new byte[64]
            };
            return bound with { Signature = PublicKeyAuth.SignDetached(ProductionMailboxAuthorityCodec.GetSigningBytes(bound), key) };
        }
        private static ProductionMailboxTopologySnapshot SignTopology(ProductionMailboxTopologySnapshot value, byte[] key)
        {
            var unsigned = value with { IssuerSignature = new byte[64] };
            return unsigned with { IssuerSignature = PublicKeyAuth.SignDetached(ProductionMailboxTopologyCodec.GetSigningBytes(unsigned), key) };
        }
        private static ProductionMailboxAuthorityEndpoint Endpoint(string uri, byte seed) => new()
        { Uri = uri, CurrentSpkiSha256 = Bytes(seed, 32), NextSpkiSha256 = Bytes((byte)(seed + 1), 32) };
        private static ProductionMailboxAuthorityEpoch Epoch(ulong epoch, ulong generation, byte[] membership, byte[] topologyPlacement, ulong from, ulong until) => new()
        {
            Epoch = epoch,
            Generation = generation,
            MembershipCommitment = membership,
            TopologyPlacementCommitment = topologyPlacement,
            NotBeforeUnixSeconds = from,
            NotAfterUnixSeconds = until
        };
        private static ProductionMailboxTopologyEpoch TopologyEpoch(ProductionMailboxAuthorityEpoch epoch, MembershipRouteDescriptor[] descriptors) => new()
        {
            Epoch = epoch.Epoch,
            Generation = epoch.Generation,
            MembershipCommitment = epoch.MembershipCommitment,
            TopologyPlacementCommitment = epoch.TopologyPlacementCommitment,
            NotBeforeUnixSeconds = epoch.NotBeforeUnixSeconds,
            NotAfterUnixSeconds = epoch.NotAfterUnixSeconds,
            Nodes = descriptors.Select((descriptor, index) => new ProductionMailboxTopologyNode
            {
                NodeId = descriptor.RouterId,
                HttpsEndpoint = $"https://node-{index + 1}.example.net/",
                CurrentSpkiSha256 = Bytes((byte)(130 + index * 2), 32),
                NextSpkiSha256 = Bytes((byte)(131 + index * 2), 32)
            }).ToArray()
        };
        private static MembershipRouteDescriptor[] Descriptors(
            ulong epoch, ulong from, ulong until, int variant = 0) =>
            new[]
            {
                Descriptor(0x10 + variant, epoch, from, until),
                Descriptor(0x40 + variant, epoch, from, until),
                Descriptor(0x70 + variant, epoch, from, until)
            }.OrderBy(static descriptor => Convert.ToHexString(
                    descriptor.RouterId.ToArray()),
                StringComparer.Ordinal).ToArray();
        private static MembershipRouteDescriptor Descriptor(int start, ulong epoch, ulong from, ulong until) => new()
        {
            RouterId = PublicKeyAuth.GenerateKeyPair(Bytes((byte)start, 32)).PublicKey,
            Ed25519PublicKey = Range(start + 32, 32),
            X25519PublicKey = Range(start + 64, 32),
            RpcEndpoint = $"https://route-{start}.example.net/",
            Roles = MembershipRouteRole.Storage,
            Capabilities = MembershipRouteCapability.Storage,
            Epoch = epoch,
            ValidFromUnixSeconds = from,
            ValidUntilUnixSeconds = until
        };
        private static void WriteProofs(string root, MembershipRouteDescriptor[] descriptors)
        {
            var proofs = MembershipRouteDescriptorCodec.BuildProofs(descriptors);
            for (var index = 0; index < descriptors.Length; index++)
            {
                var descriptor = descriptors[index];
                var mip = new MailboxReplicaMembershipProof
                {
                    ReplicaId = descriptor.RouterId,
                    SigningPublicKey = descriptor.Ed25519PublicKey,
                    Epoch = descriptor.Epoch,
                    MembershipCommitment = MembershipRouteDescriptorCodec.ComputeRoot(descriptors),
                    CanonicalInclusionProof = MailboxReplicaRouteProofCodec.Encode(descriptor, proofs[index])
                };
                File.WriteAllBytes(Path.Combine(root,
                    $"{descriptor.Epoch}-{Convert.ToHexStringLower(descriptor.RouterId.Span)}.mip1"),
                    MailboxPeerReplicationCodec.EncodeMembershipProof(mip));
            }
        }
        private static ulong Solve(byte[] id, byte[] challenge, int bits)
        {
            var encoded = new byte[8];
            for (ulong nonce = 0; nonce < ulong.MaxValue; nonce++)
            {
                using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                hash.AppendData(Encoding.UTF8.GetBytes("Deep/production-mailbox/pow/v1"));
                hash.AppendData(id); hash.AppendData(challenge);
                BinaryPrimitives.WriteUInt64BigEndian(encoded, nonce); hash.AppendData(encoded);
                var digest = hash.GetHashAndReset();
                var remaining = bits; var valid = true;
                foreach (var value in digest)
                {
                    if (remaining <= 0) break;
                    var required = Math.Min(remaining, 8);
                    if ((value >> (8 - required)) != 0) { valid = false; break; }
                    remaining -= required;
                }
                if (valid) return nonce;
            }
            throw new InvalidOperationException();
        }
        public static byte[] Bytes(byte seed, int length) => Enumerable.Range(0, length).Select(i => unchecked((byte)(seed + i))).ToArray();
        private static byte[] Range(int start, int length) => Enumerable.Range(start, length).Select(i => unchecked((byte)i)).ToArray();
        private static string Hex(ReadOnlySpan<byte> bytes) => Convert.ToHexStringLower(bytes);
        private static byte[] DomainHash(string domain, params byte[][] values)
        {
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            hash.AppendData(Encoding.UTF8.GetBytes(domain));
            foreach (var value in values) hash.AppendData(value);
            return hash.GetHashAndReset();
        }
        public sealed record OwnerRoute(byte[] MailboxId, byte[] PlacementId, byte[] SelectionCommitment);
    }

    private static string B64(ReadOnlySpan<byte> value) => Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    private static void ExpireCatalogManifest(string manifestPath, string keyPath)
    {
        var json = new System.Text.Json.JsonSerializerOptions(
            System.Text.Json.JsonSerializerDefaults.Web);
        var manifest = JsonNode.Parse(File.ReadAllBytes(manifestPath))!.AsObject();
        manifest["retainUntilUnixSeconds"] = Fixture.Now - 1;
        manifest["integrityTag"] = "";
        var unsignedManifest = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(
            manifest, json);
        using var hmac = IncrementalHash.CreateHMAC(
            HashAlgorithmName.SHA256, File.ReadAllBytes(keyPath));
        hmac.AppendData(Encoding.UTF8.GetBytes(
            "Deep/production-mailbox/artifact-catalog-manifest/v1"));
        hmac.AppendData(unsignedManifest);
        manifest["integrityTag"] = Convert.ToHexStringLower(hmac.GetHashAndReset());
        File.WriteAllBytes(manifestPath,
            System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(manifest, json));
    }

    private static byte[] Decode(string value)
    {
        var padded = value.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(padded + new string('=', (4 - padded.Length % 4) % 4));
    }
}
