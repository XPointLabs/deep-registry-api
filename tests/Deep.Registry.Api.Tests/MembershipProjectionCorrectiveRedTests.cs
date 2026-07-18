using System.Text;
using System.Text.Json.Nodes;
using Deep.Registry.Api.Tests.Fixtures;

namespace Deep.Registry.Api.Tests;

public sealed class MembershipProjectionCorrectiveRedTests
{
    [Fact]
    public void EnabledProjectionWithoutExternalAnchor_FailsClosed()
    {
        var fixture = new P04ProjectionFixture();
        var persistence = new MemoryProjectionPersistence();
        var service = new MembershipProjectionService(
            Microsoft.Extensions.Options.Options.Create(fixture.Options()),
            fixture.Time,
            P04MembershipArtifactVerifier.Create([fixture.Verifier]),
            persistence,
            MembershipProjectionMonotonicBoundary.Create([]));

        var result = service.ApplyGenesis(fixture.GenesisBytes, fixture.GenesisSignatures);

        Assert.Equal(MembershipProjectionCode.MonotonicAnchorUnavailable, result.Code);
        Assert.Equal("monotonic-anchor-unavailable", service.GetStatus().State);
        Assert.False(service.GetStatus().Ready);
    }

    [Fact]
    public void AuthorityRevocationImmediatelyStopsOldBridge_AndRestartPreservesState()
    {
        var fixture = new P04ProjectionFixture();
        var persistence = new MemoryProjectionPersistence();
        var anchor = new MemoryMonotonicAnchor();
        var service = fixture.CreateService(persistence, anchor);
        fixture.SeedAuthority(service);
        Assert.True(service.ApplyBridge(fixture.Bridge()).Success);

        Assert.True(service.ApplyRevocation(fixture.Revocation()).Success);
        Assert.False(service.TryGetBridge(out _));
        var restarted = fixture.CreateService(persistence, anchor);

        Assert.False(restarted.TryGetBridge(out _));
        Assert.False(restarted.GetStatus().Ready);
        Assert.Equal("authority-transition", restarted.GetStatus().State);
        Assert.Equal(0, restarted.GetStatus().Counters.CorruptStateRecoveries);
        Assert.False(persistence.Quarantined);
    }

    [Fact]
    public void ForkLatchSurvivesFailedPersistence()
    {
        var fixture = new P04ProjectionFixture();
        var persistence = new MemoryProjectionPersistence();
        var anchor = new MemoryMonotonicAnchor();
        var service = fixture.CreateService(persistence, anchor);
        fixture.SeedAuthority(service);
        Assert.True(service.ApplyBridge(fixture.Bridge()).Success);
        persistence.ThrowOnWrite = true;

        var fork = service.ApplyBridge(
            fixture.Bridge(contact: "https://fork.example.invalid/v1"));

        Assert.Equal(MembershipProjectionCode.PersistenceFailure, fork.Code);
        Assert.False(service.TryGetBridge(out _));
        Assert.Equal("fork-detected", service.GetStatus().State);
    }

    [Fact]
    public void PersistedForkCandidatesPreventBooleanClearRecovery()
    {
        var fixture = new P04ProjectionFixture();
        var persistence = new MemoryProjectionPersistence();
        var anchor = new MemoryMonotonicAnchor();
        var service = fixture.CreateService(persistence, anchor);
        fixture.SeedAuthority(service);
        var first = fixture.Bridge();
        var second = fixture.Bridge(contact: "https://fork.example.invalid/v1");
        Assert.True(service.ApplyBridge(first).Success);
        Assert.Equal(MembershipProjectionCode.ForkDetected, service.ApplyBridge(second).Code);
        var document = JsonNode.Parse(persistence.State!)!.AsObject();
        document["forkDetected"] = false;
        persistence.State = Encoding.UTF8.GetBytes(document.ToJsonString());
        anchor.RebindCurrentState(persistence.State);

        var restarted = fixture.CreateService(persistence, anchor);

        Assert.Equal("fork-detected", restarted.GetStatus().State);
        Assert.False(restarted.TryGetBridge(out _));
        Assert.Contains(Convert.ToBase64String(first), Encoding.UTF8.GetString(persistence.State!));
        Assert.Contains(Convert.ToBase64String(second), Encoding.UTF8.GetString(persistence.State!));
    }

    [Fact]
    public void WholeFileRollbackBehindAnchor_FailsClosed()
    {
        var fixture = new P04ProjectionFixture();
        var persistence = new MemoryProjectionPersistence();
        var anchor = new MemoryMonotonicAnchor();
        var service = fixture.CreateService(persistence, anchor);
        fixture.SeedAuthority(service);
        Assert.True(service.ApplyBridge(fixture.Bridge()).Success);
        var oldState = persistence.State!.ToArray();
        Assert.True(service.ApplyMembership(fixture.Membership()).Success);
        persistence.State = oldState;

        var restarted = fixture.CreateService(persistence, anchor);

        Assert.False(restarted.GetStatus().Ready);
        Assert.Equal("monotonic-conflict", restarted.GetStatus().State);
        Assert.False(restarted.TryGetBridge(out _));
    }

    [Fact]
    public void ConfiguredArtifactLimit_IsNotSilentlyWidened()
    {
        var fixture = new P04ProjectionFixture();
        var options = fixture.Options() with { MaximumArtifactBytes = 8 };
        var service = new MembershipProjectionService(
            Microsoft.Extensions.Options.Options.Create(options),
            fixture.Time,
            P04MembershipArtifactVerifier.Create([fixture.Verifier]),
            new MemoryProjectionPersistence(),
            MembershipProjectionMonotonicBoundary.Create([new MemoryMonotonicAnchor()]));

        var result = service.ApplyGenesis(new byte[9], fixture.GenesisSignatures);

        Assert.Equal(MembershipProjectionCode.InvalidLength, result.Code);
    }

    [Fact]
    public void OversizedPersistedFile_IsRejectedBeforeDeserialization()
    {
        var fixture = new P04ProjectionFixture();
        var persistence = new MemoryProjectionPersistence
        {
            State = new byte[2049]
        };
        var options = fixture.Options() with { MaximumStateBytes = 2048 };

        var service = new MembershipProjectionService(
            Microsoft.Extensions.Options.Options.Create(options),
            fixture.Time,
            P04MembershipArtifactVerifier.Create([fixture.Verifier]),
            persistence,
            MembershipProjectionMonotonicBoundary.Create([new MemoryMonotonicAnchor()]));

        Assert.Equal("corrupt-state", service.GetStatus().State);
        Assert.True(persistence.Quarantined);
        Assert.Equal(2048, persistence.LastReadMaximumBytes);
    }

    [Fact]
    public void FilePersistence_UsesExclusiveInterprocessLease()
    {
        var path = Path.Combine(Path.GetTempPath(), $"p06-lease-{Guid.NewGuid():N}.json");
        try
        {
            var first = new FileMembershipProjectionPersistence(path);
            var second = new FileMembershipProjectionPersistence(path);
            using var lease = first.AcquireExclusiveLease();

            Assert.Throws<IOException>(() => second.AcquireExclusiveLease());
        }
        finally
        {
            foreach (var file in Directory.GetFiles(
                         Path.GetDirectoryName(path)!,
                         $"{Path.GetFileName(path)}*"))
            {
                File.Delete(file);
            }
        }
    }
}
