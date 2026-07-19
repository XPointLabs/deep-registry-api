using System.Text;
using System.Text.Json;
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
        var persisted = JsonNode.Parse(persistence.State!)!.AsObject();
        var record = persisted["forkRecords"]!.AsArray().Single()!.AsObject();
        Assert.Equal(
            Convert.ToBase64String(first),
            record["firstEnvelopeBase64"]!.GetValue<string>());
        Assert.Equal(
            Convert.ToBase64String(second),
            record["secondEnvelopeBase64"]!.GetValue<string>());
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
    public void WholeFileRollbackWhileRunning_IsDetectedBeforeServing()
    {
        var fixture = new P04ProjectionFixture();
        var persistence = new MemoryProjectionPersistence();
        var service = fixture.CreateService(persistence);
        fixture.SeedAuthority(service);
        Assert.True(service.ApplyBridge(fixture.Bridge()).Success);
        var oldState = persistence.State!.ToArray();
        Assert.True(service.ApplyMembership(fixture.Membership()).Success);
        persistence.State = oldState;

        Assert.False(service.TryGetBridge(out _));
        Assert.Equal("monotonic-conflict", service.GetStatus().State);
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

            Assert.Throws<MembershipProjectionLeaseBusyException>(
                () => second.AcquireExclusiveLease());
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

    [Fact]
    public void TimestampOutsideDateTimeOffsetRange_IsRejectedWithBoundedCode()
    {
        var fixture = new P04ProjectionFixture();
        var service = fixture.CreateService(new MemoryProjectionPersistence());
        fixture.SeedAuthority(service);

        var result = service.ApplyBridge(
            fixture.Bridge(validUntil: ulong.MaxValue));

        Assert.Equal(MembershipProjectionCode.TimestampOutOfRange, result.Code);
        Assert.False(result.Success);
    }

    [Fact]
    public void AuthorityForkPersistsBothCandidatesAndCannotBeClearedByBoolean()
    {
        var fixture = new P04ProjectionFixture();
        var persistence = new MemoryProjectionPersistence();
        var service = fixture.CreateService(persistence);
        Assert.True(
            service.ApplyGenesis(fixture.GenesisBytes, fixture.GenesisSignatures).Success);
        Assert.True(service.ApplyDelegation(fixture.DelegationBytes).Success);
        var competing = fixture.CompetingDelegation();

        Assert.Equal(
            MembershipProjectionCode.ForkDetected,
            service.ApplyDelegation(competing).Code);
        var document = JsonNode.Parse(persistence.State!)!.AsObject();
        document["forkDetected"] = false;
        persistence.State = Encoding.UTF8.GetBytes(document.ToJsonString());
        persistence.Anchor.RebindCurrentState(persistence.State);

        var restarted = fixture.CreateService(persistence);
        var record = JsonNode.Parse(persistence.State!)!["forkRecords"]!
            .AsArray()
            .Single()!
            .AsObject();

        Assert.Equal("fork-detected", restarted.GetStatus().State);
        Assert.Equal(
            Convert.ToBase64String(fixture.DelegationBytes),
            record["firstEnvelopeBase64"]!.GetValue<string>());
        Assert.Equal(
            Convert.ToBase64String(competing),
            record["secondEnvelopeBase64"]!.GetValue<string>());
    }

    [Fact]
    public void RevocationStateWithActiveDelegation_IsQuarantined()
    {
        var fixture = new P04ProjectionFixture();
        var persistence = new MemoryProjectionPersistence();
        var service = fixture.CreateService(persistence);
        fixture.SeedAuthority(service);
        Assert.True(service.ApplyRevocation(fixture.Revocation()).Success);
        var document = JsonNode.Parse(persistence.State!)!.AsObject();
        document["activeDelegationBase64"] =
            Convert.ToBase64String(fixture.DelegationBytes);
        persistence.State = Encoding.UTF8.GetBytes(document.ToJsonString());
        persistence.Anchor.RebindCurrentState(persistence.State);

        var restarted = fixture.CreateService(persistence);

        Assert.Equal("corrupt-state", restarted.GetStatus().State);
        Assert.True(persistence.Quarantined);
    }

    [Fact]
    public void ForkPoisonSurvivesMainStateWriteFailureAndRestart()
    {
        var fixture = new P04ProjectionFixture();
        var persistence = new MemoryProjectionPersistence();
        var service = fixture.CreateService(persistence);
        fixture.SeedAuthority(service);
        Assert.True(service.ApplyBridge(fixture.Bridge()).Success);
        persistence.ThrowOnWrite = true;

        var fork = service.ApplyBridge(
            fixture.Bridge(contact: "https://poison.example.invalid/v1"));

        Assert.Equal(MembershipProjectionCode.PersistenceFailure, fork.Code);
        Assert.True(persistence.Anchor.Read().TerminalUnsafe);
        persistence.ThrowOnWrite = false;
        var restarted = fixture.CreateService(persistence);
        Assert.Equal("fork-detected", restarted.GetStatus().State);
        Assert.False(restarted.TryGetBridge(out _));
    }

    [Fact]
    public void RealFileLeaseContentionIsTransientAndRecovers()
    {
        var fixture = new P04ProjectionFixture();
        var statePath = Path.Combine(
            Path.GetTempPath(),
            $"p06-contention-{Guid.NewGuid():N}.json");
        var firstPersistence = new FileMembershipProjectionPersistence(statePath);
        var secondPersistence = new FileMembershipProjectionPersistence(statePath);
        var anchor = new MemoryMonotonicAnchor();
        MembershipProjectionService? contending = null;
        try
        {
            var first = fixture.CreateService(firstPersistence, anchor);
            fixture.SeedAuthority(first);
            Assert.True(first.ApplyBridge(fixture.Bridge()).Success);
            using (firstPersistence.AcquireExclusiveLease())
            {
                contending = fixture.CreateService(secondPersistence, anchor);
                Assert.Equal("continuity-busy", contending.GetStatus().State);
                Assert.False(contending.TryGetBridge(out _));
            }

            Assert.Equal("current", contending.GetStatus().State);
            Assert.True(contending.TryGetBridge(out _));
        }
        finally
        {
            foreach (var file in Directory.GetFiles(
                         Path.GetDirectoryName(statePath)!,
                         $"{Path.GetFileName(statePath)}*"))
            {
                File.Delete(file);
            }
        }
    }

    [Theory]
    [InlineData("bridge")]
    [InlineData("authorityLkg")]
    [InlineData("forkRecords")]
    public void ParseableJsonWithNullNestedStateIsQuarantined(string property)
    {
        var fixture = new P04ProjectionFixture();
        var persistence = new MemoryProjectionPersistence();
        var service = fixture.CreateService(persistence);
        fixture.SeedAuthority(service);
        var document = JsonNode.Parse(persistence.State!)!.AsObject();
        document[property] = null;
        persistence.State = Encoding.UTF8.GetBytes(document.ToJsonString());
        persistence.Anchor.RebindCurrentState(persistence.State);

        var exception = Record.Exception(() => fixture.CreateService(persistence));

        Assert.Null(exception);
        Assert.True(persistence.Quarantined);
    }

    [Fact]
    public void InvalidConfiguredStateLimitIsRejectedBeforePersistedRead()
    {
        var fixture = new P04ProjectionFixture();
        var persistence = new MemoryProjectionPersistence
        {
            State = new byte[32]
        };
        var options = fixture.Options() with
        {
            MaximumStateBytes = (1024 * 1024) + 1
        };

        var service = new MembershipProjectionService(
            Microsoft.Extensions.Options.Options.Create(options),
            fixture.Time,
            P04MembershipArtifactVerifier.Create([fixture.Verifier]),
            persistence,
            MembershipProjectionMonotonicBoundary.Create([persistence.Anchor]));

        Assert.Equal(0, persistence.ReadCount);
        Assert.Equal("invalid-configuration", service.GetStatus().State);
    }

    [Fact]
    public void TransientAnchorReadIsNonReadyThenRecovers()
    {
        var fixture = new P04ProjectionFixture();
        var persistence = new MemoryProjectionPersistence();
        var first = fixture.CreateService(persistence);
        fixture.SeedAuthority(first);
        Assert.True(first.ApplyBridge(fixture.Bridge()).Success);
        persistence.Anchor.TransientReadFailuresRemaining = 9;
        var service = fixture.CreateService(persistence);

        Assert.Equal("monotonic-anchor-transient", service.GetStatus().State);
        Assert.False(service.TryGetBridge(out _));
        Assert.Equal("current", service.GetStatus().State);
        Assert.True(service.TryGetBridge(out _));
    }

    [Fact]
    public void TransientAnchorCasRetriesWithinBound()
    {
        var fixture = new P04ProjectionFixture();
        var persistence = new MemoryProjectionPersistence();
        var service = fixture.CreateService(persistence);
        fixture.SeedAuthority(service);
        persistence.Anchor.TransientCompareExchangeFailuresRemaining = 2;

        var result = service.ApplyBridge(fixture.Bridge());

        Assert.Equal(MembershipProjectionCode.Accepted, result.Code);
        Assert.True(service.TryGetBridge(out _));
    }

    [Fact]
    public void ExhaustedTransientAnchorCasReturnsTypedNonReadyResult()
    {
        var fixture = new P04ProjectionFixture();
        var persistence = new MemoryProjectionPersistence();
        var service = fixture.CreateService(persistence);
        fixture.SeedAuthority(service);
        persistence.Anchor.TransientCompareExchangeFailuresRemaining = 3;

        var result = service.ApplyBridge(fixture.Bridge());

        Assert.Equal(MembershipProjectionCode.MonotonicAnchorTransient, result.Code);
        Assert.False(result.Success);
        Assert.True(service.TryGetBridge(out _));
        Assert.Equal("current", service.GetStatus().State);
    }

    [Fact]
    public void CorruptRecoveryCounterDoesNotPreventReseedContinuity()
    {
        var fixture = new P04ProjectionFixture();
        var persistence = new MemoryProjectionPersistence
        {
            State = "{bad-json"u8.ToArray()
        };
        persistence.Anchor.RebindAsGeneration(1, persistence.State);
        var service = fixture.CreateService(persistence);
        Assert.Equal("corrupt-state", service.GetStatus().State);
        Assert.Equal(1, service.GetStatus().Counters.CorruptStateRecoveries);
        persistence.Anchor.Reset();

        fixture.SeedAuthority(service);
        Assert.True(service.ApplyBridge(fixture.Bridge()).Success);

        Assert.Equal("current", service.GetStatus().State);
        Assert.Equal(1, service.GetStatus().Counters.CorruptStateRecoveries);
    }

    [Fact]
    public void ForkTerminalJournalSurvivesAllAnchorPoisonCasFailures()
    {
        var fixture = new P04ProjectionFixture();
        var persistence = new MemoryProjectionPersistence();
        var service = fixture.CreateService(persistence);
        fixture.SeedAuthority(service);
        Assert.True(service.ApplyBridge(fixture.Bridge()).Success);
        persistence.Anchor.TransientCompareExchangeFailuresRemaining = 3;

        var result = service.ApplyBridge(
            fixture.Bridge(contact: "https://journal.example.invalid/v1"));

        Assert.Equal(MembershipProjectionCode.MonotonicAnchorTransient, result.Code);
        Assert.NotNull(persistence.TerminalJournal);
        persistence.Anchor.TransientCompareExchangeFailuresRemaining = 0;
        var restarted = fixture.CreateService(persistence);
        Assert.Equal("fork-detected", restarted.GetStatus().State);
        Assert.False(restarted.TryGetBridge(out _));
    }

    [Fact]
    public void PreparedGenerationRecoversOnDirectStatefulApplyAfterPrecommitCasFailures()
    {
        var fixture = new P04ProjectionFixture();
        var persistence = new MemoryProjectionPersistence();
        var service = fixture.CreateService(persistence);
        fixture.SeedAuthority(service);
        var bridge = fixture.Bridge();
        persistence.Anchor.TransientCompareExchangeFailuresRemaining = 3;

        var interrupted = service.ApplyBridge(bridge);
        Assert.Equal(MembershipProjectionCode.MonotonicAnchorTransient, interrupted.Code);
        Assert.NotNull(persistence.PreparedTransition);
        persistence.Anchor.TransientCompareExchangeFailuresRemaining = 0;

        var retried = service.ApplyBridge(bridge);

        Assert.Equal(MembershipProjectionCode.Idempotent, retried.Code);
        Assert.Null(persistence.PreparedTransition);
        Assert.True(service.TryGetBridge(out _));
    }

    [Fact]
    public void PreparedGenerationRecoversAfterRestartWhenAnchorStillExpected()
    {
        var fixture = new P04ProjectionFixture();
        var persistence = new MemoryProjectionPersistence();
        var service = fixture.CreateService(persistence);
        fixture.SeedAuthority(service);
        var bridge = fixture.Bridge();
        persistence.Anchor.TransientCompareExchangeFailuresRemaining = 3;
        Assert.Equal(
            MembershipProjectionCode.MonotonicAnchorTransient,
            service.ApplyBridge(bridge).Code);
        persistence.Anchor.TransientCompareExchangeFailuresRemaining = 0;

        var restarted = fixture.CreateService(persistence);

        Assert.Equal("current", restarted.GetStatus().State);
        Assert.True(restarted.TryGetBridge(out var recovered));
        Assert.Equal(bridge, recovered!.Bytes);
        Assert.Null(persistence.PreparedTransition);
    }

    [Fact]
    public void CommitThenThrowCasIsAcceptedAsExactIntendedNextGeneration()
    {
        var fixture = new P04ProjectionFixture();
        var persistence = new MemoryProjectionPersistence();
        var service = fixture.CreateService(persistence);
        fixture.SeedAuthority(service);
        persistence.Anchor.CommitThenThrowCompareExchangeFailuresRemaining = 1;
        var bridge = fixture.Bridge();

        var result = service.ApplyBridge(bridge);
        var restarted = fixture.CreateService(persistence);

        Assert.Equal(MembershipProjectionCode.Accepted, result.Code);
        Assert.Null(persistence.PreparedTransition);
        Assert.True(restarted.TryGetBridge(out var recovered));
        Assert.Equal(bridge, recovered!.Bytes);
    }

    [Fact]
    public void StatefulApplyDirectlyRecoversLeaseBusyWithoutStatusProbe()
    {
        var fixture = new P04ProjectionFixture();
        var statePath = Path.Combine(
            Path.GetTempPath(),
            $"p06-apply-contention-{Guid.NewGuid():N}.json");
        var firstPersistence = new FileMembershipProjectionPersistence(statePath);
        var secondPersistence = new FileMembershipProjectionPersistence(statePath);
        var anchor = new MemoryMonotonicAnchor();
        try
        {
            var first = fixture.CreateService(firstPersistence, anchor);
            fixture.SeedAuthority(first);
            var bridge = fixture.Bridge();
            Assert.True(first.ApplyBridge(bridge).Success);
            MembershipProjectionService contending;
            using (firstPersistence.AcquireExclusiveLease())
            {
                contending = fixture.CreateService(secondPersistence, anchor);
            }

            var retried = contending.ApplyBridge(bridge);

            Assert.Equal(MembershipProjectionCode.Idempotent, retried.Code);
            Assert.True(contending.TryGetBridge(out _));
        }
        finally
        {
            foreach (var file in Directory.GetFiles(
                         Path.GetDirectoryName(statePath)!,
                         $"{Path.GetFileName(statePath)}*"))
            {
                File.Delete(file);
            }
        }
    }

    [Fact]
    public void StatefulApplyDirectlyRecoversStartupAnchorTransient()
    {
        var fixture = new P04ProjectionFixture();
        var persistence = new MemoryProjectionPersistence();
        var first = fixture.CreateService(persistence);
        fixture.SeedAuthority(first);
        var bridge = fixture.Bridge();
        Assert.True(first.ApplyBridge(bridge).Success);
        persistence.Anchor.TransientReadFailuresRemaining = 3;
        var restarted = fixture.CreateService(persistence);
        persistence.Anchor.TransientReadFailuresRemaining = 0;

        var result = restarted.ApplyBridge(bridge);

        Assert.Equal(MembershipProjectionCode.Idempotent, result.Code);
        Assert.True(restarted.TryGetBridge(out _));
    }

    [Fact]
    public void ValidTerminalJournalDominatesOversizedPreparedTransitionAtStartup()
    {
        var fixture = new P04ProjectionFixture();
        var persistence = new MemoryProjectionPersistence();
        var service = fixture.CreateService(persistence);
        fixture.SeedAuthority(service);
        Assert.True(service.ApplyBridge(fixture.Bridge()).Success);
        persistence.Anchor.TransientCompareExchangeFailuresRemaining = 3;
        Assert.Equal(
            MembershipProjectionCode.MonotonicAnchorTransient,
            service.ApplyBridge(
                fixture.Bridge(contact: "https://terminal-first.example.invalid/v1")).Code);
        Assert.NotNull(persistence.TerminalJournal);
        persistence.Anchor.TransientCompareExchangeFailuresRemaining = 0;
        persistence.PreparedTransition = new byte[(512 * 1024) + 1];

        MembershipProjectionService? restarted = null;
        var exception = Record.Exception(
            () => restarted = fixture.CreateService(persistence));

        Assert.Null(exception);
        Assert.NotNull(restarted);
        Assert.False(restarted.GetStatus().Ready);
        Assert.Equal("fork-detected", restarted.GetStatus().State);
        Assert.False(restarted.TryGetBridge(out _));
    }

    [Fact]
    public void OversizedDetailedForkJournalFallsBackToCompactTerminalMarker()
    {
        var fixture = new P04ProjectionFixture();
        var persistence = new MemoryProjectionPersistence
        {
            TerminalJournalMaximumBytes = 512
        };
        var service = fixture.CreateService(persistence);
        fixture.SeedAuthority(service);
        Assert.True(service.ApplyBridge(fixture.Bridge()).Success);

        var result = service.ApplyBridge(
            fixture.Bridge(contact: "https://compact-marker.example.invalid/v1"));

        Assert.Equal(MembershipProjectionCode.ForkDetected, result.Code);
        Assert.NotNull(persistence.TerminalJournal);
        Assert.True(persistence.TerminalJournal.Length <= 512);
        Assert.NotNull(persistence.TerminalEvidence);
        var restarted = fixture.CreateService(persistence);
        Assert.Equal("fork-detected", restarted.GetStatus().State);
        Assert.False(restarted.TryGetBridge(out _));
    }

    [Fact]
    public void TerminalJournalPrecommitIoFailureStillPoisonsExternalAnchor()
    {
        var fixture = new P04ProjectionFixture();
        var persistence = new MemoryProjectionPersistence
        {
            ThrowOnTerminalJournalWrite = true
        };
        var service = fixture.CreateService(persistence);
        fixture.SeedAuthority(service);
        Assert.True(service.ApplyBridge(fixture.Bridge()).Success);

        var result = service.ApplyBridge(
            fixture.Bridge(contact: "https://anchor-fallback.example.invalid/v1"));

        Assert.Equal(MembershipProjectionCode.ForkDetected, result.Code);
        Assert.Null(persistence.TerminalJournal);
        Assert.True(persistence.Anchor.Read().TerminalUnsafe);
        var restarted = fixture.CreateService(persistence);
        Assert.Equal("fork-detected", restarted.GetStatus().State);
        Assert.False(restarted.TryGetBridge(out _));
    }

    [Fact]
    public void UndeclaredTerminalPersistenceFailureCannotSuppressExternalPoison()
    {
        var fixture = new P04ProjectionFixture();
        var persistence = new MemoryProjectionPersistence
        {
            TerminalJournalWriteException = new NotSupportedException(
                "terminal persistence canary")
        };
        var service = fixture.CreateService(persistence);
        fixture.SeedAuthority(service);
        Assert.True(service.ApplyBridge(fixture.Bridge()).Success);

        var result = service.ApplyBridge(
            fixture.Bridge(contact: "https://unexpected-local.example.invalid/v1"));

        Assert.Equal(MembershipProjectionCode.ForkDetected, result.Code);
        Assert.Null(persistence.TerminalJournal);
        Assert.True(persistence.Anchor.Read().TerminalUnsafe);
        var restarted = fixture.CreateService(persistence);
        Assert.Equal("fork-detected", restarted.GetStatus().State);
        Assert.False(restarted.TryGetBridge(out _));
        Assert.DoesNotContain(
            "canary",
            JsonSerializer.Serialize(restarted.GetStatus()),
            StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void UnexpectedFailuresOfBothTerminalSinksStaySanitizedAndFailClosed()
    {
        var fixture = new P04ProjectionFixture();
        var persistence = new MemoryProjectionPersistence
        {
            TerminalJournalWriteException = new NotSupportedException(
                "local terminal canary")
        };
        var service = fixture.CreateService(persistence);
        fixture.SeedAuthority(service);
        Assert.True(service.ApplyBridge(fixture.Bridge()).Success);
        persistence.Anchor.UnexpectedCompareExchangeFailuresRemaining = 3;

        var result = service.ApplyBridge(
            fixture.Bridge(contact: "https://both-sinks.example.invalid/v1"));

        Assert.Contains(
            result.Code,
            new[]
            {
                MembershipProjectionCode.PersistenceFailure,
                MembershipProjectionCode.MonotonicAnchorTransient
            });
        Assert.False(service.GetStatus().Ready);
        Assert.Equal("fork-detected", service.GetStatus().State);
        Assert.False(service.TryGetBridge(out _));
        Assert.DoesNotContain(
            "canary",
            JsonSerializer.Serialize(service.GetStatus()),
            StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TerminalSinkCancellationIsNotReducedToInvalidArtifact()
    {
        var fixture = new P04ProjectionFixture();
        var cancellation = new OperationCanceledException(
            "terminal cancellation canary");
        var persistence = new MemoryProjectionPersistence
        {
            TerminalJournalWriteException = cancellation
        };
        var service = fixture.CreateService(persistence);
        fixture.SeedAuthority(service);
        Assert.True(service.ApplyBridge(fixture.Bridge()).Success);

        var thrown = Assert.Throws<OperationCanceledException>(
            () => service.ApplyBridge(
                fixture.Bridge(contact: "https://cancelled-terminal.example.invalid/v1")));

        Assert.Same(cancellation, thrown);
    }

    [Fact]
    public void WrappedTerminalSinkCancellationIsNotReducedToInvalidArtifact()
    {
        var fixture = new P04ProjectionFixture();
        var cancellation = new OperationCanceledException(
            "wrapped terminal cancellation canary");
        var persistence = new MemoryProjectionPersistence
        {
            TerminalJournalWriteException = new AggregateException(cancellation)
        };
        var service = fixture.CreateService(persistence);
        fixture.SeedAuthority(service);
        Assert.True(service.ApplyBridge(fixture.Bridge()).Success);

        var thrown = Assert.Throws<AggregateException>(
            () => service.ApplyBridge(
                fixture.Bridge(contact: "https://wrapped-cancel.example.invalid/v1")));

        Assert.Same(cancellation, Assert.Single(thrown.InnerExceptions));
    }

    [Fact]
    public void TerminalSinkFatalFailureIsNotReducedToInvalidArtifact()
    {
        var fixture = new P04ProjectionFixture();
        var fatal = new OutOfMemoryException("terminal fatal canary");
        var persistence = new MemoryProjectionPersistence
        {
            TerminalJournalWriteException = fatal
        };
        var service = fixture.CreateService(persistence);
        fixture.SeedAuthority(service);
        Assert.True(service.ApplyBridge(fixture.Bridge()).Success);

        var thrown = Assert.Throws<OutOfMemoryException>(
            () => service.ApplyBridge(
                fixture.Bridge(contact: "https://fatal-terminal.example.invalid/v1")));

        Assert.Same(fatal, thrown);
    }

    [Fact]
    public void AuthorityForkTerminalCancellationCrossesEveryReducer()
    {
        var fixture = new P04ProjectionFixture();
        var cancellation = new OperationCanceledException(
            "authority terminal cancellation canary");
        var persistence = new MemoryProjectionPersistence();
        var service = fixture.CreateService(persistence);
        Assert.True(
            service.ApplyGenesis(fixture.GenesisBytes, fixture.GenesisSignatures).Success);
        Assert.True(service.ApplyDelegation(fixture.DelegationBytes).Success);
        persistence.TerminalJournalWriteException = cancellation;

        var thrown = Assert.Throws<OperationCanceledException>(
            () => service.ApplyDelegation(fixture.CompetingDelegation()));

        Assert.Same(cancellation, thrown);
    }

    [Fact]
    public void WrappedAnchorFatalCrossesRetryAndPublicReducer()
    {
        var fixture = new P04ProjectionFixture();
        var persistence = new MemoryProjectionPersistence();
        var service = fixture.CreateService(persistence);
        fixture.SeedAuthority(service);
        var fatal = new OutOfMemoryException("wrapped anchor fatal canary");
        var wrapper = new MembershipProjectionAnchorTransientException(
            "typed transient wrapper canary",
            fatal);
        persistence.Anchor.ReadException = wrapper;

        var thrown = Assert.Throws<MembershipProjectionAnchorTransientException>(
            () => service.ApplyBridge(fixture.Bridge()));

        Assert.Same(wrapper, thrown);
        Assert.Same(fatal, thrown.InnerException);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ExternalTerminalAnchorDominatesMalformedPreparedRecovery(bool oversized)
    {
        var fixture = new P04ProjectionFixture();
        var persistence = new MemoryProjectionPersistence();
        var service = fixture.CreateService(persistence);
        fixture.SeedAuthority(service);
        Assert.True(service.ApplyBridge(fixture.Bridge()).Success);
        persistence.Anchor.PoisonCurrent(new string('a', 64));
        persistence.PreparedTransition = oversized
            ? new byte[fixture.Options().MaximumStateBytes + 1]
            : "{not-json"u8.ToArray();

        var restarted = fixture.CreateService(persistence);

        Assert.False(restarted.GetStatus().Ready);
        Assert.Equal("fork-detected", restarted.GetStatus().State);
        Assert.False(restarted.TryGetBridge(out _));
    }
}
