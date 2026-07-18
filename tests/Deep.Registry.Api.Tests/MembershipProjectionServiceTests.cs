using Deep.Protocol.DeepExtension.Membership;
using Deep.Registry.Api.Tests.Fixtures;

namespace Deep.Registry.Api.Tests;

public sealed class MembershipProjectionServiceTests
{
    [Fact]
    public void ValidBridgeAndMembership_AdvanceSeparateDomainLkgs()
    {
        var fixture = new P04ProjectionFixture();
        var persistence = new MemoryProjectionPersistence();
        var service = fixture.CreateService(persistence);
        fixture.SeedAuthority(service);
        var bridge = fixture.Bridge();
        var membership = fixture.Membership();

        Assert.Equal(MembershipProjectionCode.Accepted, service.ApplyBridge(bridge).Code);
        Assert.Equal(MembershipProjectionCode.Accepted, service.ApplyMembership(membership).Code);
        Assert.Equal(MembershipProjectionCode.Idempotent, service.ApplyBridge(bridge).Code);

        var status = service.GetStatus();
        Assert.True(status.Ready);
        Assert.Equal(2UL, status.BridgeSequence);
        Assert.Equal(2UL, status.MembershipSequence);
        Assert.Equal(4, status.Counters.Accepted);
        Assert.Equal(1, status.Counters.Idempotent);
    }

    [Fact]
    public void OneSignerAndSequenceGap_FailWithoutReplacingLkg()
    {
        var fixture = new P04ProjectionFixture();
        var service = fixture.CreateService(new MemoryProjectionPersistence());
        fixture.SeedAuthority(service);

        var oneSigner = service.ApplyBridge(fixture.Bridge(signerCount: 1));
        var gap = service.ApplyBridge(fixture.Bridge(sequence: 3));

        Assert.False(oneSigner.Success);
        Assert.Equal(MembershipProjectionCode.InvalidSigner, oneSigner.Code);
        Assert.False(gap.Success);
        Assert.Equal(MembershipProjectionCode.SequenceGap, gap.Code);
        Assert.Null(service.GetStatus().BridgeSequence);
    }

    [Fact]
    public void RollbackAndCrossDomainPreviousHash_DoNotAdvance()
    {
        var fixture = new P04ProjectionFixture();
        var service = fixture.CreateService(new MemoryProjectionPersistence());
        fixture.SeedAuthority(service);
        var bridge = fixture.Bridge();
        var membership = fixture.Membership();
        Assert.True(service.ApplyBridge(bridge).Success);
        Assert.True(service.ApplyMembership(membership).Success);
        var membershipHash = MembershipContractHash.Sha256(
            MembershipContractCodec.GetMembershipSigningBytes(
                MembershipContractCodec.DecodeSignedMembership(membership).Statement));

        var crossDomain = fixture.Bridge(sequence: 3, previousHash: membershipHash);
        var rollback = fixture.Bridge(sequence: 1);

        Assert.Equal(MembershipProjectionCode.Rollback, service.ApplyBridge(crossDomain).Code);
        Assert.Equal(MembershipProjectionCode.Rollback, service.ApplyBridge(rollback).Code);
        Assert.Equal(2UL, service.GetStatus().BridgeSequence);
    }

    [Fact]
    public void CompetingValidSuccessor_RecordsForkAndFailsReadiness()
    {
        var fixture = new P04ProjectionFixture();
        var service = fixture.CreateService(new MemoryProjectionPersistence());
        fixture.SeedAuthority(service);
        Assert.True(service.ApplyBridge(fixture.Bridge()).Success);

        var fork = service.ApplyBridge(
            fixture.Bridge(contact: "https://other.example.invalid/v1"));

        Assert.False(fork.Success);
        Assert.Equal(MembershipProjectionCode.ForkDetected, fork.Code);
        Assert.False(service.GetStatus().Ready);
        Assert.Equal("fork-detected", service.GetStatus().State);
        Assert.False(service.TryGetBridge(out _));
    }

    [Fact]
    public void ExpiredCandidateAndOversizedRawArtifact_FailClosed()
    {
        var fixture = new P04ProjectionFixture();
        var service = fixture.CreateService(new MemoryProjectionPersistence());
        fixture.SeedAuthority(service);

        var expired = service.ApplyBridge(
            fixture.Bridge(
                validFrom: (ulong)P04ProjectionFixture.NowUnixSeconds - 1000,
                validUntil: (ulong)P04ProjectionFixture.NowUnixSeconds - 100));
        var oversized = service.ApplyBridge(new byte[129 * 1024]);

        Assert.Equal(MembershipProjectionCode.Expired, expired.Code);
        Assert.Equal(MembershipProjectionCode.InvalidLength, oversized.Code);
        Assert.False(service.GetStatus().Ready);
    }

    [Fact]
    public void PersistenceFailure_DoesNotPublishMemoryState()
    {
        var fixture = new P04ProjectionFixture();
        var persistence = new MemoryProjectionPersistence();
        var service = fixture.CreateService(persistence);
        fixture.SeedAuthority(service);
        persistence.ThrowOnWrite = true;

        var result = service.ApplyBridge(fixture.Bridge());

        Assert.Equal(MembershipProjectionCode.PersistenceFailure, result.Code);
        Assert.Null(service.GetStatus().BridgeSequence);
        Assert.False(service.TryGetBridge(out _));
    }

    [Fact]
    public void CachedValidStateSurvivesRestartAndSourceFailure()
    {
        var fixture = new P04ProjectionFixture();
        var persistence = new MemoryProjectionPersistence();
        var first = fixture.CreateService(persistence);
        fixture.SeedAuthority(first);
        var bridge = fixture.Bridge();
        Assert.True(first.ApplyBridge(bridge).Success);

        var restarted = fixture.CreateService(persistence);
        restarted.RecordSourceFailure();

        Assert.True(restarted.GetStatus().Ready);
        Assert.True(restarted.TryGetBridge(out var cached));
        Assert.Equal(bridge, cached!.Bytes);
        Assert.Equal(1, restarted.GetStatus().Counters.SourceFailures);
    }

    [Fact]
    public void CorruptPersistedState_IsQuarantinedAndNeverReady()
    {
        var fixture = new P04ProjectionFixture();
        var persistence = new MemoryProjectionPersistence
        {
            State = "{not-json"u8.ToArray()
        };

        var service = fixture.CreateService(persistence);

        Assert.True(persistence.Quarantined);
        Assert.False(service.GetStatus().Ready);
        Assert.Equal("corrupt-state", service.GetStatus().State);
        Assert.Equal(1, service.GetStatus().Counters.CorruptStateRecoveries);
    }

    [Fact]
    public void CachedExpiredState_IsRetainedButNotServed()
    {
        var fixture = new P04ProjectionFixture();
        var persistence = new MemoryProjectionPersistence();
        var first = fixture.CreateService(persistence);
        fixture.SeedAuthority(first);
        Assert.True(first.ApplyBridge(fixture.Bridge()).Success);
        fixture.Time.Value = DateTimeOffset.FromUnixTimeSeconds(
            P04ProjectionFixture.NowUnixSeconds + 3000);

        var restarted = fixture.CreateService(persistence);

        Assert.False(restarted.GetStatus().Ready);
        Assert.Equal("stale", restarted.GetStatus().State);
        Assert.False(restarted.TryGetBridge(out _));
        Assert.NotNull(persistence.State);
        Assert.False(persistence.Quarantined);
    }

    [Fact]
    public void WrongNetworkProtocolAndNotYetValid_AreRejectedWithBoundedCodes()
    {
        var fixture = new P04ProjectionFixture();
        var service = fixture.CreateService(new MemoryProjectionPersistence());
        fixture.SeedAuthority(service);

        var wrongNetwork = service.ApplyBridge(
            fixture.Bridge(networkId: new byte[MembershipLimits.NetworkIdLength]));
        var wrongProtocol = service.ApplyBridge(
            fixture.Bridge(minimumProtocol: 3, maximumProtocol: 4));
        var future = service.ApplyBridge(
            fixture.Bridge(
                validFrom: (ulong)P04ProjectionFixture.NowUnixSeconds + 100,
                validUntil: (ulong)P04ProjectionFixture.NowUnixSeconds + 1000));

        Assert.Equal(MembershipProjectionCode.WrongNetwork, wrongNetwork.Code);
        Assert.Equal(MembershipProjectionCode.WrongProtocol, wrongProtocol.Code);
        Assert.Equal(MembershipProjectionCode.NotYetValid, future.Code);
        Assert.Null(service.GetStatus().BridgeSequence);
    }

    [Fact]
    public void RevocationClearsActiveDelegationUntilAForwardDelegationExists()
    {
        var fixture = new P04ProjectionFixture();
        var service = fixture.CreateService(new MemoryProjectionPersistence());
        fixture.SeedAuthority(service);

        Assert.Equal(
            MembershipProjectionCode.Accepted,
            service.ApplyRevocation(fixture.Revocation()).Code);
        var bridge = service.ApplyBridge(fixture.Bridge());

        Assert.Equal(MembershipProjectionCode.StateUnavailable, bridge.Code);
        Assert.False(service.GetStatus().Ready);
    }

    [Fact]
    public void ConcurrentCompetingCandidates_EndInFailClosedForkState()
    {
        var fixture = new P04ProjectionFixture();
        var service = fixture.CreateService(new MemoryProjectionPersistence());
        fixture.SeedAuthority(service);
        var first = fixture.Bridge(contact: "https://first.example.invalid/v1");
        var second = fixture.Bridge(contact: "https://second.example.invalid/v1");
        MembershipProjectionApplyResult? firstResult = null;
        MembershipProjectionApplyResult? secondResult = null;

        Parallel.Invoke(
            () => firstResult = service.ApplyBridge(first),
            () => secondResult = service.ApplyBridge(second));

        Assert.Contains(
            new[] { firstResult!.Code, secondResult!.Code },
            code => code == MembershipProjectionCode.Accepted);
        Assert.Contains(
            new[] { firstResult.Code, secondResult.Code },
            code => code == MembershipProjectionCode.ForkDetected);
        Assert.False(service.GetStatus().Ready);
        Assert.False(service.TryGetBridge(out _));
    }

    [Fact]
    public void CryptographicallyInvalidSignature_IsRejected()
    {
        var fixture = new P04ProjectionFixture();
        var service = fixture.CreateService(new MemoryProjectionPersistence());
        fixture.SeedAuthority(service);
        var bridge = MembershipContractCodec.DecodeSignedBridge(fixture.Bridge());
        var signatures = bridge.Signatures.ToArray();
        var corrupted = signatures[0].Signature.ToArray();
        corrupted[^1] ^= 0x01;
        signatures[0] = signatures[0] with { Signature = corrupted };
        var invalid = MembershipContractCodec.EncodeSignedBridge(
            bridge with { Signatures = signatures });

        var result = service.ApplyBridge(invalid);

        Assert.Equal(MembershipProjectionCode.InvalidSignature, result.Code);
        Assert.Null(service.GetStatus().BridgeSequence);
    }

    [Fact]
    public void ProjectionService_HasNoNodeRegistryAuthorityDependency()
    {
        var fields = typeof(MembershipProjectionService)
            .GetFields(
                System.Reflection.BindingFlags.Instance |
                System.Reflection.BindingFlags.NonPublic |
                System.Reflection.BindingFlags.Public);

        Assert.DoesNotContain(fields, field => field.FieldType == typeof(NodeRegistry));
        Assert.DoesNotContain(
            typeof(MembershipProjectionService).GetConstructors()
                .SelectMany(constructor => constructor.GetParameters()),
            parameter => parameter.ParameterType == typeof(NodeRegistry));
    }
}
