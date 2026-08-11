using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxAuthority;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.MailboxTopology;
using Deep.Registry.Api.ProductionMailbox;

namespace Deep.Registry.Api.Tests;

public sealed class ProductionMailboxRouteContinuityStateTests
{
    [Fact]
    public void StateSurface_HasNoPartialGenesisMutationPath()
    {
        var routeMethods = typeof(IProductionMailboxRouteContinuityStateStore)
            .GetMethods(BindingFlags.Instance | BindingFlags.Public);
        Assert.DoesNotContain(routeMethods, method =>
            method.Name.Contains("Genesis", StringComparison.Ordinal)
            && method.Name.StartsWith("Commit", StringComparison.Ordinal));
        Assert.DoesNotContain(routeMethods, method => method.GetParameters().Any(parameter =>
            parameter.ParameterType ==
            typeof(ProductionMailboxRouteContinuityGenesisCommitPlan)));
        var ownerMethods = typeof(IProductionMailboxOwnerControlStateStore)
            .GetMethods(BindingFlags.Instance | BindingFlags.Public);
        var enrollment = Assert.Single(ownerMethods, method =>
            method.Name == "CommitOwnerEnrollmentAsync");
        Assert.Contains(enrollment.GetParameters(), parameter => parameter.ParameterType ==
            typeof(ProductionMailboxRouteContinuityGenesisCommitPlan));
        Assert.DoesNotContain(typeof(InMemoryProductionMailboxStateStore)
            .GetMethods(BindingFlags.Instance | BindingFlags.Public), method =>
                method.Name.Contains("RouteContinuity", StringComparison.Ordinal));
        Assert.DoesNotContain(typeof(PostgreSqlProductionMailboxStateStore)
            .GetMethods(BindingFlags.Instance | BindingFlags.Public), method =>
                method.Name.Contains("RouteContinuity", StringComparison.Ordinal));
    }

    internal static VerifiedProductionMailboxRouteSelectionTransition Transition(
        byte[] oldRol, ulong oldLocalGeneration, byte[] predecessorHash,
        ulong predecessorSequence, byte seed, bool delegated = false,
        ProductionMailboxRouteAuthorizationKind predecessorKind =
            ProductionMailboxRouteAuthorizationKind.OwnerPRA2)
    {
        const ulong now = 10_000;
        var network = Bytes(seed, 16);
        var issuer = Bytes((byte)(seed + 1), 32);
        var authority = Authority(network, issuer, seed, now);
        var canonicalAuthority = ProductionMailboxAuthorityCodec.Encode(authority);
        var authorityHash = SHA256.HashData(canonicalAuthority);
        var owner = Bytes((byte)(seed + 2), 32);
        var mailbox = Bytes((byte)(seed + 3), 32);
        var placement = Bytes((byte)(seed + 4), 32);
        var selection = Bytes((byte)(seed + 5), 32);
        var certificate = new ProductionMailboxRouteCertificate
        {
            NetworkId = network,
            AuthorityGeneration = authority.AuthorityGeneration,
            CanonicalAuthorityHash = authorityHash,
            IssuerEd25519PublicKey = issuer,
            MailboxOwnerEd25519PublicKey = owner,
            BlindedMailboxId = mailbox,
            BlindedPlacementId = placement,
            SelectionInputCommitment = selection,
            IssuedAtUnixSeconds = now,
            ExpiresAtUnixSeconds = now + 500,
            IssuerSignature = Bytes((byte)(seed + 6), 64)
        };
        var certificateBytes = ProductionMailboxRouteAdvertisementCodec.EncodeCertificate(certificate);
        var certificateHash = SHA256.HashData(certificateBytes);
        var routeDomain = ProductionMailboxRouteAdvertisementCodec.ComputeRouteDomainHash(certificate);
        var newKind = delegated
            ? ProductionMailboxRouteAuthorizationKind.DelegatedRCA1
            : ProductionMailboxRouteAuthorizationKind.OwnerPRA2;
        var salt = delegated ? Bytes((byte)(seed + 7), 32) : new byte[32];
        var commitment = delegated ? Bytes((byte)(seed + 8), 32) : new byte[32];
        byte[] checkpointBytes;
        byte[] checkpointHash;
        if (delegated)
        {
            checkpointBytes = ProductionMailboxRouteContinuityCodec.EncodeRevocationCheckpoint(
                new ProductionMailboxRouteRevocationCheckpoint
                {
                    NetworkId = network,
                    RouteDomainHash = routeDomain,
                    CurrentAuthorityGeneration = authority.AuthorityGeneration,
                    CurrentCanonicalAuthorityHash = authorityHash,
                    CurrentIssuerEd25519PublicKey = issuer,
                    CurrentOwnerRevocationGeneration = 0,
                    CurrentOwnerRevocationHeadHash = new byte[32],
                    TransitionSalt = salt,
                    ContinuityTransitionCommitment = commitment,
                    Status = ProductionMailboxRouteRevocationStatus.Active,
                    IssuedAtUnixSeconds = now,
                    ExpiresAtUnixSeconds = now + 300,
                    CurrentIssuerSignature = Bytes((byte)(seed + 9), 64)
                });
            checkpointHash = SHA256.HashData(checkpointBytes);
        }
        else
        {
            checkpointBytes = [];
            checkpointHash = new byte[32];
        }
        var oldSelectionHash = Bytes((byte)(seed + 10), 32);
        var newSelectionHash = Bytes((byte)(seed + 11), 32);
        var context = new ProductionMailboxRouteTransitionContext
        {
            Mode = ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint,
            PredecessorAuthorizationKind = predecessorKind,
            NewAuthorizationKind = newKind,
            NetworkId = network,
            RouteDomainHash = routeDomain,
            OldCanonicalSelectionHash = oldSelectionHash,
            NewCanonicalSelectionHash = newSelectionHash,
            PredecessorCanonicalRouteAuthorizationHash = predecessorHash,
            PredecessorRouteAuthorizationSequence = predecessorSequence,
            FreshCanonicalRouteCertificateHash = certificateHash,
            NewRouteAuthorizationSequence = predecessorSequence + 1,
            TransitionSalt = salt,
            ContinuityTransitionCommitment = commitment,
            CanonicalRevocationCheckpointHash = checkpointHash,
            CurrentCanonicalAuthorityHash = authorityHash,
            CurrentAuthorityGeneration = authority.AuthorityGeneration,
            SealedOldRouteOriginLkgHash = ProductionMailboxRouteContinuityStateGuard
                .ComputeRouteOriginLkgHash(oldRol),
            OldRouteVerifiedAtUnixSeconds = now - 100,
            OldLocalRouteCommitGeneration = oldLocalGeneration,
            NotBeforeUnixSeconds = now,
            ExpiresAtUnixSeconds = now + 300
        };
        var contextBytes = ProductionMailboxRouteAuthorizationCodec.EncodeTransitionContext(context);
        byte[] authorizationBytes;
        if (delegated)
        {
            authorizationBytes = ProductionMailboxRouteAuthorizationCodec.EncodeContinuityActivation(
                new ProductionMailboxRouteContinuityActivation
                {
                    NetworkId = network,
                    RouteDomainHash = routeDomain,
                    CurrentAuthorityGeneration = authority.AuthorityGeneration,
                    CurrentCanonicalAuthorityHash = authorityHash,
                    CurrentIssuerEd25519PublicKey = issuer,
                    CurrentRevocationGeneration = authority.Revocation.Generation,
                    CurrentRevocationHeadHash = authority.Revocation.HeadHash,
                    CurrentRevocationSnapshotHash = authority.Revocation.SnapshotHash,
                    TransitionSalt = salt,
                    ContinuityTransitionCommitment = commitment,
                    CanonicalRevocationCheckpointHash = checkpointHash,
                    FreshCanonicalRouteCertificateHash = certificateHash,
                    CanonicalTransitionContextHash = SHA256.HashData(contextBytes),
                    PredecessorAuthorizationKind =
                        predecessorKind,
                    PredecessorCanonicalRouteAuthorizationHash = predecessorHash,
                    PredecessorRouteAuthorizationSequence = predecessorSequence,
                    ActivationSequence = predecessorSequence + 1,
                    IssuedAtUnixSeconds = now,
                    ExpiresAtUnixSeconds = now + 300,
                    CurrentIssuerSignature = Bytes((byte)(seed + 12), 64)
                });
        }
        else
        {
            authorizationBytes = ProductionMailboxRouteAuthorizationCodec.EncodeAdvertisementV2(
                new ProductionMailboxRouteAdvertisementV2
                {
                    Certificate = certificate,
                    PredecessorAuthorizationKind = predecessorKind,
                    PredecessorCanonicalRouteAuthorizationHash = predecessorHash,
                    PredecessorRouteAuthorizationSequence = predecessorSequence,
                    Sequence = predecessorSequence + 1,
                    PublishedAtUnixSeconds = now,
                    ExpiresAtUnixSeconds = now + 300,
                    OwnerSignature = Bytes((byte)(seed + 12), 64)
                });
        }
        var authorizationHash = SHA256.HashData(authorizationBytes);
        var selectionProof = new ProductionMailboxSelectionSuccessorProof
        {
            Mode = ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint,
            NetworkId = network,
            OldEpoch = 9,
            OldEpochGeneration = 20,
            NewEpoch = 10,
            NewEpochGeneration = 21,
            MailboxOwnerEd25519PublicKey = owner,
            BlindedMailboxId = mailbox,
            BlindedPlacementId = placement,
            SelectionInputCommitment = selection,
            OldCanonicalAuthorityHash = Bytes((byte)(seed + 13), 32),
            NewCanonicalAuthorityHash = authorityHash,
            OldTopologyGeneration = 30,
            OldCanonicalTopologyHash = Bytes((byte)(seed + 14), 32),
            NewTopologyGeneration = 31,
            NewCanonicalTopologyHash = Bytes((byte)(seed + 15), 32),
            OldCanonicalSelectionHash = oldSelectionHash,
            NewCanonicalSelectionHash = newSelectionHash,
            IssuedAtUnixSeconds = now,
            ExpiresAtUnixSeconds = now + 300,
            CanonicalNewAuthority = canonicalAuthority,
            OldCanonicalSelection = new byte[] { (byte)(seed + 16) },
            NewCanonicalSelection = new byte[] { (byte)(seed + 17) },
            OldIssuerSignature = new byte[64],
            NewIssuerSignature = Bytes((byte)(seed + 18), 64)
        };
        var pss = new ProductionMailboxSelectionSuccessorV2Proof
        {
            Selection = selectionProof,
            CanonicalTransitionContextHash = SHA256.HashData(contextBytes),
            PredecessorAuthorizationKind = predecessorKind,
            NewAuthorizationKind = newKind,
            PredecessorCanonicalRouteAuthorizationHash = predecessorHash,
            PredecessorRouteAuthorizationSequence = predecessorSequence,
            FreshCanonicalRouteCertificateHash = certificateHash,
            NewCanonicalRouteAuthorizationHash = authorizationHash,
            NewRouteAuthorizationSequence = predecessorSequence + 1,
            CanonicalRevocationCheckpointHash = checkpointHash
        };
        var canonicalPss = ProductionMailboxSelectionSuccessorV2Codec.Encode(pss);
        var nextRol = Bytes((byte)(seed + 19),
            ProductionMailboxRouteContinuityConstants.CanonicalRouteOriginLkgLength);
        var transcript = Bytes((byte)(seed + 20), 256);
        var verifiedSelection = (VerifiedProductionMailboxSelectionSuccessor)
            RuntimeHelpers.GetUninitializedObject(typeof(VerifiedProductionMailboxSelectionSuccessor));
        return CreateTransition(verifiedSelection, null,
            newKind,
            predecessorSequence + 1, canonicalPss, certificateBytes, contextBytes,
            authorizationBytes, checkpointBytes, nextRol,
            ProductionMailboxRouteContinuityStateGuard.ComputeRouteOriginLkgHash(nextRol),
            transcript, SHA256.HashData(transcript));
    }

    private static ProductionMailboxAuthority Authority(
        byte[] network, byte[] issuer, byte seed, ulong now)
    {
        var value = new ProductionMailboxAuthority
        {
            DevelopmentOnly = false,
            Environment = ProductionMailboxAuthorityEnvironment.Production,
            Transport = ProductionMailboxAuthorityTransport.AuthenticatedMau2,
            Ownership = ProductionMailboxAuthorityOwnership.OfficialManaged,
            EndpointPolicy = ProductionMailboxAuthorityEndpointPolicy.PublicHttpsOnly,
            NetworkId = network,
            AuthorityGeneration = 7,
            PreviousAuthorityHash = Bytes((byte)(seed + 20), 32),
            MailboxIssuerEd25519PublicKey = issuer,
            MrXApprovalEd25519PublicKey = Bytes((byte)(seed + 21), 32),
            Coordinator = Endpoint("https://coord.example.net/", (byte)(seed + 22)),
            NodeIngress = Endpoint("https://ingress.example.net/mau2/", (byte)(seed + 24)),
            CurrentEpoch = Epoch(9, 70, seed, now - 200, now + 1_000),
            NextEpoch = Epoch(10, 71, (byte)(seed + 2), now - 10, now + 1_200),
            Revocation = new ProductionMailboxAuthorityRevocation
            {
                SnapshotHash = Bytes((byte)(seed + 26), 32),
                HeadHash = Bytes((byte)(seed + 27), 32),
                PreviousHeadHash = Bytes((byte)(seed + 28), 32),
                Generation = 6,
                IssuedAtUnixSeconds = now - 20,
                ExpiresAtUnixSeconds = now + 800
            },
            MrXApproval = new ProductionMailboxAuthorityApproval
            {
                AuthorityPayloadHash = Bytes((byte)(seed + 29), 32),
                AllowedAndroidSigningCertificateSha256 = [Bytes((byte)(seed + 30), 32)],
                AllowedWindowsSigningCertificateSha256 = [Bytes((byte)(seed + 31), 32)],
                AndroidReleaseBuildArtifactSha256 = [Bytes((byte)(seed + 32), 32)],
                WindowsReleaseBuildArtifactSha256 = [Bytes((byte)(seed + 33), 32)],
                RolloutNotBeforeUnixSeconds = now - 30,
                RolloutNotAfterUnixSeconds = now + 800
            },
            Signature = Bytes((byte)(seed + 34), 64)
        };
        return value with
        {
            MrXApproval = value.MrXApproval with
            { AuthorityPayloadHash = ProductionMailboxAuthorityCodec.ComputePayloadHash(value) }
        };
    }

    private static ProductionMailboxAuthorityEndpoint Endpoint(string uri, byte seed) => new()
    {
        Uri = uri,
        CurrentSpkiSha256 = Bytes(seed, 32),
        NextSpkiSha256 = Bytes((byte)(seed + 1), 32)
    };

    private static ProductionMailboxAuthorityEpoch Epoch(
        ulong epoch, ulong generation, byte seed, ulong from, ulong until) => new()
        {
            Epoch = epoch,
            Generation = generation,
            MembershipCommitment = Bytes(seed, 32),
            TopologyPlacementCommitment = Bytes((byte)(seed + 1), 32),
            NotBeforeUnixSeconds = from,
            NotAfterUnixSeconds = until
        };

    [UnsafeAccessor(UnsafeAccessorKind.Constructor)]
    private static extern VerifiedProductionMailboxRouteSelectionTransition CreateTransition(
        VerifiedProductionMailboxSelectionSuccessor selectionSuccessor,
        VerifiedProductionMailboxOfflineCheckpointClosure? offlineClosure,
        ProductionMailboxRouteAuthorizationKind authorizationKind,
        ulong authorizationSequence,
        ReadOnlySpan<byte> canonicalSuccessor,
        ReadOnlySpan<byte> canonicalRouteCertificate,
        ReadOnlySpan<byte> canonicalTransitionContext,
        ReadOnlySpan<byte> canonicalRouteAuthorization,
        ReadOnlySpan<byte> canonicalRevocationCheckpoint,
        ReadOnlySpan<byte> canonicalNextRouteOriginLkg,
        ReadOnlySpan<byte> nextRouteOriginLkgHash,
        ReadOnlySpan<byte> canonicalTranscript,
        ReadOnlySpan<byte> transcriptHash);

    private static byte[] Bytes(byte seed, int length) => Enumerable.Range(0, length)
        .Select(index => unchecked((byte)(seed + index))).ToArray();

}
