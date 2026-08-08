using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxAuthority;
using Deep.Protocol.DeepExtension.MailboxTopology;
using Deep.Registry.Api.ProductionMailbox;
using Npgsql;

namespace Deep.Registry.Api.Tests;

public sealed class ProductionMailboxRouteContinuityStateTests
{
    [Fact]
    public async Task InMemoryEnrollmentCas_IsExactDefensiveAndRejectsForks()
    {
        var store = (IProductionMailboxRouteContinuityStateStore)
            new InMemoryProductionMailboxStateStore();
        await RunEnrollmentContractAsync(store);
        await RunTransitionParityAsync(store, 120);
    }

    [Fact]
    public async Task PostgreSqlEnrollmentCas_MatchesInMemoryAcrossRestartAndConcurrency()
    {
        var connectionString = Environment.GetEnvironmentVariable("DEEP_TEST_POSTGRES");
        if (string.IsNullOrWhiteSpace(connectionString)) return;
        await using var database = await PostgresTestDatabase.CreateAsync(connectionString);
        var store = (IProductionMailboxRouteContinuityStateStore)
            new PostgreSqlProductionMailboxStateStore(database.ConnectionString);
        await RunEnrollmentContractAsync(store);
        var pgTransition = await RunTransitionParityAsync(store, 130);
        var transitionRestart = (IProductionMailboxRouteContinuityStateStore)
            new PostgreSqlProductionMailboxStateStore(database.ConnectionString);
        var replay = await transitionRestart.CommitVerifiedTransitionAsync(
            pgTransition.Key, pgTransition.OldRol, pgTransition.Transition,
            CancellationToken.None);
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.ExactReplay, replay.Status);
        var delegatedAfterRestart = await transitionRestart.GetRouteContinuityStateAsync(
            pgTransition.DelegatedKey, CancellationToken.None);
        Assert.NotNull(delegatedAfterRestart);
        Assert.Equal(ProductionMailboxRouteAuthorizationKind.DelegatedRCA1,
            delegatedAfterRestart.CurrentAuthorizationKind);
        var delegatedReplay = await transitionRestart.CommitVerifiedTransitionAsync(
            pgTransition.DelegatedKey, pgTransition.DelegatedOldRol,
            pgTransition.DelegatedTransition, CancellationToken.None);
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.ExactReplay,
            delegatedReplay.Status);

        var delegatedForkA = Transition(delegatedAfterRestart.CanonicalRouteOriginLkg.ToArray(),
            delegatedAfterRestart.LocalCommitGeneration,
            delegatedAfterRestart.CurrentAuthorizationHash.ToArray(),
            delegatedAfterRestart.CurrentAuthorizationSequence, 201, delegated: true,
            predecessorKind: ProductionMailboxRouteAuthorizationKind.DelegatedRCA1);
        var delegatedForkB = Transition(delegatedAfterRestart.CanonicalRouteOriginLkg.ToArray(),
            delegatedAfterRestart.LocalCommitGeneration,
            delegatedAfterRestart.CurrentAuthorizationHash.ToArray(),
            delegatedAfterRestart.CurrentAuthorizationSequence, 202, delegated: true,
            predecessorKind: ProductionMailboxRouteAuthorizationKind.DelegatedRCA1);
        var forkStore = (IProductionMailboxRouteContinuityStateStore)
            new PostgreSqlProductionMailboxStateStore(database.ConnectionString);
        var forkResults = await Task.WhenAll(
            transitionRestart.CommitVerifiedTransitionAsync(pgTransition.DelegatedKey,
                delegatedAfterRestart.CanonicalRouteOriginLkg, delegatedForkA,
                CancellationToken.None).AsTask(),
            forkStore.CommitVerifiedTransitionAsync(pgTransition.DelegatedKey,
                delegatedAfterRestart.CanonicalRouteOriginLkg, delegatedForkB,
                CancellationToken.None).AsTask());
        Assert.Single(forkResults, result =>
            result.Status == ProductionMailboxRouteContinuityCommitStatus.Accepted);
        Assert.Single(forkResults, result => result.Status is
            ProductionMailboxRouteContinuityCommitStatus.Rollback or
            ProductionMailboxRouteContinuityCommitStatus.Conflict);
        await using (var connection = new NpgsqlConnection(database.ConnectionString))
        {
            await connection.OpenAsync();
            await using var command = new NpgsqlCommand(
                "UPDATE production_mailbox_route_continuity_v2 SET delegation_sequence=@zeroSequence,canonical_delegation=@empty,canonical_delegation_hash=@zeroHash,canonical_delegation_acceptance=@empty,canonical_delegation_acceptance_hash=@zeroHash WHERE route_state_key=@key",
                connection);
            command.Parameters.AddWithValue("zeroSequence", new byte[8]);
            command.Parameters.AddWithValue("empty", Array.Empty<byte>());
            command.Parameters.AddWithValue("zeroHash", new byte[32]);
            command.Parameters.AddWithValue("key", pgTransition.DelegatedKey);
            Assert.Equal(1, await command.ExecuteNonQueryAsync());
        }
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            transitionRestart.GetRouteContinuityStateAsync(pgTransition.DelegatedKey,
                CancellationToken.None).AsTask());

        var routeKey = Bytes(170, 32);
        var oldRol = Bytes(171, ProductionMailboxRouteContinuityConstants.CanonicalRouteOriginLkgLength);
        var first = Plan(oldRol, delegationSeed: 172, acceptanceSeed: 173);
        var competing = Plan(oldRol, delegationSeed: 174, acceptanceSeed: 175);
        var restartedA = (IProductionMailboxRouteContinuityStateStore)
            new PostgreSqlProductionMailboxStateStore(database.ConnectionString);
        var restartedB = (IProductionMailboxRouteContinuityStateStore)
            new PostgreSqlProductionMailboxStateStore(database.ConnectionString);
        var results = await Task.WhenAll(
            restartedA.CommitEnrollmentAsync(routeKey, first, CancellationToken.None).AsTask(),
            restartedB.CommitEnrollmentAsync(routeKey, competing, CancellationToken.None).AsTask());
        Assert.Single(results, result =>
            result.Status == ProductionMailboxRouteContinuityCommitStatus.Accepted);
        Assert.Single(results, result => result.Status is
            ProductionMailboxRouteContinuityCommitStatus.Rollback or
            ProductionMailboxRouteContinuityCommitStatus.Conflict or
            ProductionMailboxRouteContinuityCommitStatus.PredecessorMismatch);

        var winner = results.Single(result =>
            result.Status == ProductionMailboxRouteContinuityCommitStatus.Accepted).State!;
        var restarted = (IProductionMailboxRouteContinuityStateStore)
            new PostgreSqlProductionMailboxStateStore(database.ConnectionString);
        var durable = await restarted.GetRouteContinuityStateAsync(routeKey,
            CancellationToken.None);
        Assert.NotNull(durable);
        Assert.Equal(winner.CanonicalDelegationHash.ToArray(),
            durable.CanonicalDelegationHash.ToArray());

        await using (var connection = new NpgsqlConnection(database.ConnectionString))
        {
            await connection.OpenAsync();
            var corrupted = durable.CanonicalDelegation.ToArray();
            corrupted[40] ^= 1;
            await using var command = new NpgsqlCommand(
                "UPDATE production_mailbox_route_continuity_v2 SET canonical_delegation=@value WHERE route_state_key=@key",
                connection);
            command.Parameters.AddWithValue("value", corrupted);
            command.Parameters.AddWithValue("key", routeKey);
            Assert.Equal(1, await command.ExecuteNonQueryAsync());
        }
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            restarted.GetRouteContinuityStateAsync(routeKey, CancellationToken.None).AsTask());
    }

    [Fact]
    public void StateSurface_RequiresSealedProtocolCapabilitiesForEveryMutation()
    {
        var methods = typeof(IProductionMailboxRouteContinuityStateStore)
            .GetMethods(BindingFlags.Instance | BindingFlags.Public);
        Assert.Collection(methods.OrderBy(static method => method.Name, StringComparer.Ordinal),
            method =>
            {
                Assert.Equal("CommitEnrollmentAsync", method.Name);
                Assert.Contains(method.GetParameters(), parameter =>
                    parameter.ParameterType ==
                    typeof(ProductionMailboxRouteContinuityEnrollmentCommitPlan));
            },
            method =>
            {
                Assert.Equal("CommitVerifiedTransitionAsync", method.Name);
                Assert.Contains(method.GetParameters(), parameter =>
                    parameter.ParameterType ==
                    typeof(VerifiedProductionMailboxRouteSelectionTransition));
            },
            method => Assert.Equal("GetRouteContinuityStateAsync", method.Name));
        Assert.DoesNotContain(methods, method => method.Name.Contains("Revocation",
            StringComparison.Ordinal) || method.Name.Contains("History", StringComparison.Ordinal));
        Assert.DoesNotContain(typeof(InMemoryProductionMailboxStateStore)
            .GetMethods(BindingFlags.Instance | BindingFlags.Public), method =>
                method.Name.Contains("RouteContinuity", StringComparison.Ordinal));
    }

    [Fact]
    public async Task InMemoryEnrollmentCas_FreezesRouteKeyBeforeWaiting()
    {
        var concrete = new InMemoryProductionMailboxStateStore();
        var store = (IProductionMailboxRouteContinuityStateStore)concrete;
        var gate = (SemaphoreSlim)typeof(InMemoryProductionMailboxStateStore)
            .GetField("gate", BindingFlags.Instance | BindingFlags.NonPublic)!
            .GetValue(concrete)!;
        await gate.WaitAsync();
        var key = Bytes(80, 32);
        var originalKey = key.ToArray();
        var oldRol = Bytes(81,
            ProductionMailboxRouteContinuityConstants.CanonicalRouteOriginLkgLength);
        var pending = store.CommitEnrollmentAsync(key,
            Plan(oldRol, delegationSeed: 82, acceptanceSeed: 83),
            CancellationToken.None).AsTask();
        key[0] ^= 1;
        gate.Release();
        var result = await pending;
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.Accepted, result.Status);
        Assert.NotNull(await store.GetRouteContinuityStateAsync(originalKey,
            CancellationToken.None));
        Assert.Null(await store.GetRouteContinuityStateAsync(key, CancellationToken.None));
    }

    [Fact]
    public async Task InMemoryVerifiedTransition_AdvancesTaggedAuthorizationAndReplaysExactly()
    {
        var store = (IProductionMailboxRouteContinuityStateStore)
            new InMemoryProductionMailboxStateStore();
        var key = Bytes(90, 32);
        var preEnrollmentRol = Bytes(91,
            ProductionMailboxRouteContinuityConstants.CanonicalRouteOriginLkgLength);
        var enrollment = Plan(preEnrollmentRol, delegationSeed: 92, acceptanceSeed: 93);
        var enrolled = await store.CommitEnrollmentAsync(key, enrollment, CancellationToken.None);
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.Accepted, enrolled.Status);
        var oldRol = enrolled.State!.CanonicalRouteOriginLkg.ToArray();
        var transition = Transition(oldRol, 4,
            enrolled.State.CurrentAuthorizationHash.ToArray(),
            enrolled.State.CurrentAuthorizationSequence, 94);
        var accepted = await store.CommitVerifiedTransitionAsync(key, oldRol, transition,
            CancellationToken.None);
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.Accepted, accepted.Status);
        Assert.Equal(ProductionMailboxRouteAuthorizationKind.OwnerPRA2,
            accepted.State!.CurrentAuthorizationKind);
        Assert.Equal(8UL, accepted.State.CurrentAuthorizationSequence);
        Assert.Equal(5UL, accepted.State.LocalCommitGeneration);
        Assert.NotEmpty(accepted.State.CanonicalTransitionTranscript.ToArray());

        var replay = await store.CommitVerifiedTransitionAsync(key, oldRol, transition,
            CancellationToken.None);
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.ExactReplay, replay.Status);
        Assert.Equal(accepted.State.TransitionTranscriptHash.ToArray(),
            replay.State!.TransitionTranscriptHash.ToArray());
    }

    private static async Task RunEnrollmentContractAsync(
        IProductionMailboxRouteContinuityStateStore store)
    {
        var routeKey = Bytes(11, 32);
        var oldRol = Bytes(12, ProductionMailboxRouteContinuityConstants.CanonicalRouteOriginLkgLength);
        var plan = Plan(oldRol, delegationSeed: 13, acceptanceSeed: 14);
        var accepted = await store.CommitEnrollmentAsync(routeKey, plan, CancellationToken.None);
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.Accepted, accepted.Status);
        Assert.NotNull(accepted.State);
        Assert.Equal(1UL, accepted.State.DelegationSequence);
        Assert.Equal(ProductionMailboxRouteAuthorizationKind.OwnerPRA2,
            accepted.State.CurrentAuthorizationKind);

        var exposed = accepted.State.CanonicalDelegation.ToArray();
        exposed[0] ^= 1;
        routeKey[0] ^= 1;
        oldRol[0] ^= 1;
        Assert.NotEqual(exposed, accepted.State.CanonicalDelegation.ToArray());

        var replayKey = Bytes(11, 32);
        var replayOldRol = Bytes(12,
            ProductionMailboxRouteContinuityConstants.CanonicalRouteOriginLkgLength);
        var replay = await store.CommitEnrollmentAsync(replayKey,
            Plan(replayOldRol, delegationSeed: 13, acceptanceSeed: 14),
            CancellationToken.None);
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.ExactReplay, replay.Status);

        var sameDelegationDifferentAcceptance = await store.CommitEnrollmentAsync(replayKey,
            Plan(replayOldRol, delegationSeed: 13, acceptanceSeed: 15),
            CancellationToken.None);
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.Conflict,
            sameDelegationDifferentAcceptance.Status);

        var rollback = await store.CommitEnrollmentAsync(replayKey,
            Plan(replayOldRol, delegationSeed: 16, acceptanceSeed: 17),
            CancellationToken.None);
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.Rollback, rollback.Status);
        var durable = await store.GetRouteContinuityStateAsync(replayKey,
            CancellationToken.None);
        Assert.NotNull(durable);
        Assert.Equal(accepted.State.CanonicalDelegationHash.ToArray(),
            durable.CanonicalDelegationHash.ToArray());
    }

    private static async Task<TransitionReplay> RunTransitionParityAsync(
        IProductionMailboxRouteContinuityStateStore store, byte seed)
    {
        var ownerKey = Bytes(seed, 32);
        var ownerOldRol = Bytes((byte)(seed + 1),
            ProductionMailboxRouteContinuityConstants.CanonicalRouteOriginLkgLength);
        const ulong highSequence = 0x8000_0000_0000_0010;
        const ulong highLocalGeneration = 0x8000_0000_0000_0020;
        var ownerTransition = Transition(ownerOldRol, highLocalGeneration,
            Bytes((byte)(seed + 2), 32), highSequence, (byte)(seed + 3));
        var ownerAccepted = await store.CommitVerifiedTransitionAsync(ownerKey, ownerOldRol,
            ownerTransition, CancellationToken.None);
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.Accepted,
            ownerAccepted.Status);
        Assert.Equal(highSequence + 1, ownerAccepted.State!.CurrentAuthorizationSequence);
        Assert.Equal(highLocalGeneration + 1, ownerAccepted.State.LocalCommitGeneration);

        var missingDelegatedKey = Bytes((byte)(seed + 40), 32);
        var missingOldRol = Bytes((byte)(seed + 41),
            ProductionMailboxRouteContinuityConstants.CanonicalRouteOriginLkgLength);
        var missingDelegated = Transition(missingOldRol, 3, Bytes((byte)(seed + 42), 32),
            7, (byte)(seed + 43), delegated: true);
        var missing = await store.CommitVerifiedTransitionAsync(missingDelegatedKey,
            missingOldRol, missingDelegated, CancellationToken.None);
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.MissingState, missing.Status);
        Assert.Null(await store.GetRouteContinuityStateAsync(missingDelegatedKey,
            CancellationToken.None));

        var delegatedKey = Bytes((byte)(seed + 60), 32);
        var preEnrollmentRol = Bytes((byte)(seed + 61),
            ProductionMailboxRouteContinuityConstants.CanonicalRouteOriginLkgLength);
        var enrolled = await store.CommitEnrollmentAsync(delegatedKey,
            Plan(preEnrollmentRol, (byte)(seed + 62), (byte)(seed + 63)),
            CancellationToken.None);
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.Accepted, enrolled.Status);
        var delegatedOldRol = enrolled.State!.CanonicalRouteOriginLkg.ToArray();
        var delegatedTransition = Transition(delegatedOldRol, 4,
            enrolled.State.CurrentAuthorizationHash.ToArray(),
            enrolled.State.CurrentAuthorizationSequence, (byte)(seed + 64), delegated: true);
        var delegatedAccepted = await store.CommitVerifiedTransitionAsync(delegatedKey,
            delegatedOldRol, delegatedTransition, CancellationToken.None);
        Assert.Equal(ProductionMailboxRouteContinuityCommitStatus.Accepted,
            delegatedAccepted.Status);
        Assert.Equal(ProductionMailboxRouteAuthorizationKind.DelegatedRCA1,
            delegatedAccepted.State!.CurrentAuthorizationKind);
        Assert.Equal(1UL, delegatedAccepted.State.DelegationSequence);
        Assert.Equal(ProductionMailboxRouteContinuityConstants.CanonicalDelegationLength,
            delegatedAccepted.State.CanonicalDelegation.Length);

        return new(ownerKey, ownerOldRol, ownerTransition, delegatedKey,
            delegatedOldRol, delegatedTransition);
    }

    private static ProductionMailboxRouteContinuityEnrollmentCommitPlan Plan(
        byte[] oldRol, byte delegationSeed, byte acceptanceSeed)
    {
        var oldRolHash = SHA256.HashData(oldRol);
        var delegation = new ProductionMailboxRouteContinuityDelegation
        {
            NetworkId = Bytes(delegationSeed, 16),
            PinnedMrXPublicKeySha256 = Bytes((byte)(delegationSeed + 1), 32),
            RouteDomainHash = Bytes((byte)(delegationSeed + 2), 32),
            MailboxOwnerEd25519PublicKey = Bytes((byte)(delegationSeed + 3), 32),
            BlindedMailboxId = Bytes((byte)(delegationSeed + 4), 32),
            BlindedPlacementId = Bytes((byte)(delegationSeed + 5), 32),
            SelectionInputCommitment = Bytes((byte)(delegationSeed + 6), 32),
            AnchorAuthorityGeneration = 10,
            AnchorCanonicalAuthorityHash = Bytes((byte)(delegationSeed + 7), 32),
            AnchorCanonicalRouteCertificateHash = Bytes((byte)(delegationSeed + 8), 32),
            AnchorAuthorizationKind = ProductionMailboxRouteAuthorizationKind.OwnerPRA2,
            AnchorCanonicalRouteAuthorizationHash = Bytes((byte)(delegationSeed + 9), 32),
            AnchorRouteAuthorizationSequence = 7,
            PreDelegationRouteOriginLkgHash = oldRolHash,
            RouteVerifiedAtUnixSeconds = 1_000,
            Capability = ProductionMailboxRouteContinuityCapability.RouteContinuityOnly,
            DelegationSerial = Bytes((byte)(delegationSeed + 10), 16),
            DelegationSequence = 1,
            PreviousCanonicalDelegationHash = new byte[32],
            MaximumAuthorityGeneration = 20,
            FirstActivationSequence = 8,
            LastActivationSequence = 16,
            IssuedAtUnixSeconds = 1_010,
            NotBeforeUnixSeconds = 1_010,
            ExpiresAtUnixSeconds = 2_000,
            OwnerSignature = Bytes((byte)(delegationSeed + 11), 64)
        };
        var canonicalDelegation = ProductionMailboxRouteContinuityCodec.EncodeDelegation(delegation);
        var delegationHash = SHA256.HashData(canonicalDelegation);
        var acceptance = new ProductionMailboxRouteDelegationAcceptance
        {
            NetworkId = delegation.NetworkId,
            RouteDomainHash = delegation.RouteDomainHash,
            CanonicalDelegationHash = delegationHash,
            AnchorAuthorityGeneration = delegation.AnchorAuthorityGeneration,
            AnchorCanonicalAuthorityHash = delegation.AnchorCanonicalAuthorityHash,
            AnchorCanonicalRouteCertificateHash = delegation.AnchorCanonicalRouteCertificateHash,
            AnchorAuthorizationKind = delegation.AnchorAuthorizationKind,
            AnchorCanonicalRouteAuthorizationHash = delegation.AnchorCanonicalRouteAuthorizationHash,
            AnchorRouteAuthorizationSequence = delegation.AnchorRouteAuthorizationSequence,
            PreDelegationRouteOriginLkgHash = oldRolHash,
            RouteVerifiedAtUnixSeconds = delegation.RouteVerifiedAtUnixSeconds,
            AcceptedAtUnixSeconds = 1_020,
            AnchorIssuerSignature = Bytes(acceptanceSeed, 64)
        };
        var canonicalAcceptance = ProductionMailboxRouteContinuityCodec
            .EncodeDelegationAcceptance(acceptance);
        var enrolledRol = Bytes((byte)(delegationSeed + 20),
            ProductionMailboxRouteContinuityConstants.CanonicalRouteOriginLkgLength);
        return CreatePlan(oldRol, oldRolHash, 3, 0, new byte[32], canonicalDelegation,
            delegationHash, canonicalAcceptance, SHA256.HashData(canonicalAcceptance),
            enrolledRol, SHA256.HashData(enrolledRol));
    }

    private static VerifiedProductionMailboxRouteSelectionTransition Transition(
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
            SealedOldRouteOriginLkgHash = SHA256.HashData(oldRol),
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
            authorizationBytes, checkpointBytes, nextRol, SHA256.HashData(nextRol),
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
    private static extern ProductionMailboxRouteContinuityEnrollmentCommitPlan CreatePlan(
        ReadOnlySpan<byte> expectedOldRouteOriginLkg,
        ReadOnlySpan<byte> expectedOldRouteOriginLkgHash,
        ulong expectedOldLocalCommitGeneration,
        ulong expectedPreviousDelegationSequence,
        ReadOnlySpan<byte> expectedPreviousDelegationHash,
        ReadOnlySpan<byte> canonicalDelegation,
        ReadOnlySpan<byte> canonicalDelegationHash,
        ReadOnlySpan<byte> canonicalAcceptance,
        ReadOnlySpan<byte> canonicalAcceptanceHash,
        ReadOnlySpan<byte> canonicalEnrolledRouteOriginLkg,
        ReadOnlySpan<byte> enrolledRouteOriginLkgHash);

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

    private sealed record TransitionReplay(
        byte[] Key,
        byte[] OldRol,
        VerifiedProductionMailboxRouteSelectionTransition Transition,
        byte[] DelegatedKey,
        byte[] DelegatedOldRol,
        VerifiedProductionMailboxRouteSelectionTransition DelegatedTransition);

    private sealed class PostgresTestDatabase : IAsyncDisposable
    {
        private readonly string administrativeConnectionString;
        private readonly string schema;

        private PostgresTestDatabase(string administrativeConnectionString,
            string schema, string connectionString)
        {
            this.administrativeConnectionString = administrativeConnectionString;
            this.schema = schema;
            ConnectionString = connectionString;
        }

        internal string ConnectionString { get; }

        internal static async ValueTask<PostgresTestDatabase> CreateAsync(string connectionString)
        {
            var schema = "deep_registry_route_v2_" +
                Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(8));
            var quoted = new NpgsqlCommandBuilder().QuoteIdentifier(schema);
            await using (var connection = new NpgsqlConnection(connectionString))
            {
                await connection.OpenAsync();
                await new NpgsqlCommand($"CREATE SCHEMA {quoted}", connection)
                    .ExecuteNonQueryAsync();
            }
            var isolated = new NpgsqlConnectionStringBuilder(connectionString)
            {
                SearchPath = schema,
                Pooling = false
            };
            return new(connectionString, schema, isolated.ConnectionString);
        }

        public async ValueTask DisposeAsync()
        {
            var quoted = new NpgsqlCommandBuilder().QuoteIdentifier(schema);
            await using var connection = new NpgsqlConnection(administrativeConnectionString);
            await connection.OpenAsync();
            await new NpgsqlCommand($"DROP SCHEMA IF EXISTS {quoted} CASCADE", connection)
                .ExecuteNonQueryAsync();
        }
    }
}
