using System.Net;
using Deep.Registry.Api.DirectoryPublication;

namespace Deep.Registry.Api.Tests;

public sealed class BoundedRequestAdmissionGateTests
{
    [Fact]
    public void Per_source_partition_does_not_starve_an_independent_source()
    {
        var clock = new ManualTimeProvider(DateTimeOffset.FromUnixTimeSeconds(1_700_000_000));
        var gate = Gate(clock, perSource: 2, global: 10);
        var first = IPAddress.Parse("192.0.2.1");
        var second = IPAddress.Parse("192.0.2.2");

        Assert.True(gate.TryAcquire(first).IsAccepted);
        Assert.True(gate.TryAcquire(first).IsAccepted);
        var rejected = gate.TryAcquire(first);
        Assert.False(rejected.IsAccepted);
        Assert.Equal(10U, rejected.RetryAfterSeconds);
        Assert.True(gate.TryAcquire(second).IsAccepted);
    }

    [Fact]
    public void Independent_global_budget_bounds_many_source_partitions()
    {
        var clock = new ManualTimeProvider(DateTimeOffset.FromUnixTimeSeconds(1_700_000_000));
        var gate = Gate(clock, perSource: 2, global: 3);

        Assert.True(gate.TryAcquire(IPAddress.Parse("192.0.2.1")).IsAccepted);
        Assert.True(gate.TryAcquire(IPAddress.Parse("192.0.2.2")).IsAccepted);
        Assert.True(gate.TryAcquire(IPAddress.Parse("192.0.2.3")).IsAccepted);
        Assert.False(gate.TryAcquire(IPAddress.Parse("192.0.2.4")).IsAccepted);
    }

    [Fact]
    public void Window_reset_and_partition_expiry_are_time_bounded()
    {
        var clock = new ManualTimeProvider(DateTimeOffset.FromUnixTimeSeconds(1_700_000_000));
        var gate = Gate(clock, perSource: 1, global: 20, partitions: 16);

        for (var index = 1; index <= 16; index++)
            Assert.True(gate.TryAcquire(IPAddress.Parse($"192.0.2.{index}")).IsAccepted);
        Assert.False(gate.TryAcquire(IPAddress.Parse("198.51.100.1")).IsAccepted);

        clock.Advance(TimeSpan.FromMinutes(2));
        Assert.True(gate.TryAcquire(IPAddress.Parse("198.51.100.1")).IsAccepted);
        Assert.False(gate.TryAcquire(IPAddress.Parse("198.51.100.1")).IsAccepted);
        clock.Advance(TimeSpan.FromSeconds(10));
        Assert.True(gate.TryAcquire(IPAddress.Parse("198.51.100.1")).IsAccepted);
    }

    [Fact]
    public void Ipv4_mapped_ipv6_cannot_bypass_the_same_source_partition()
    {
        var clock = new ManualTimeProvider(DateTimeOffset.FromUnixTimeSeconds(1_700_000_000));
        var gate = Gate(clock, perSource: 1, global: 10);

        Assert.True(gate.TryAcquire(IPAddress.Parse("192.0.2.1")).IsAccepted);
        Assert.False(gate.TryAcquire(IPAddress.Parse("::ffff:192.0.2.1")).IsAccepted);
    }

    [Fact]
    public void Shared_issuance_budget_cannot_exhaust_the_minimum_ledger_over_its_horizon()
    {
        var intersectingWindows =
            ContactResolveIssuanceAdmissionGate.AdmissionSafetyHorizonSeconds /
            ContactResolveIssuanceAdmissionGate.WindowSeconds + 1;
        var worstCaseAdmissions = checked(
            intersectingWindows * ContactResolveIssuanceAdmissionGate.GlobalLimit);

        Assert.Equal(51_846, worstCaseAdmissions);
        Assert.True(worstCaseAdmissions +
            ContactResolveIssuanceAdmissionGate.CrashAndBoundaryMargin <=
            ContactResolveIssuanceAdmissionGate.MinimumLedgerCapacity);
    }

    [Fact]
    public void Did2_enrollment_allows_bounded_same_source_catch_up()
    {
        var clock = new ManualTimeProvider(DateTimeOffset.FromUnixTimeSeconds(1_700_000_000));
        var gate = new DeepIdV2IssuanceAdmissionGate(clock);
        var source = IPAddress.Parse("192.0.2.1");
        for (var index = 0; index < DeepIdV2IssuanceAdmissionGate.PerSourceLimit; index++)
            Assert.True(gate.TryAcquire(source).IsAccepted);
        Assert.Equal(10U, gate.TryAcquire(source).RetryAfterSeconds);
        // A saturated device cannot spend the whole independent global budget.
        Assert.True(gate.TryAcquire(IPAddress.Parse("192.0.2.2")).IsAccepted);
        clock.Advance(TimeSpan.FromSeconds(10));
        Assert.True(gate.TryAcquire(source).IsAccepted);
    }

    [Fact]
    public void Did2_global_budget_remains_bounded_across_source_partitions()
    {
        var clock = new ManualTimeProvider(DateTimeOffset.FromUnixTimeSeconds(1_700_000_000));
        var gate = new DeepIdV2IssuanceAdmissionGate(clock);
        for (var index = 1; index <= DeepIdV2IssuanceAdmissionGate.GlobalLimit; index++)
            Assert.True(gate.TryAcquire(IPAddress.Parse($"192.0.2.{index}")).IsAccepted);
        var refused = gate.TryAcquire(IPAddress.Parse("198.51.100.1"));
        Assert.False(refused.IsAccepted);
        Assert.Equal(10U, refused.RetryAfterSeconds);
        clock.Advance(TimeSpan.FromSeconds(10));
        Assert.True(gate.TryAcquire(IPAddress.Parse("198.51.100.1")).IsAccepted);
    }

    [Fact]
    public void Did2_budget_is_coupled_to_its_independent_full_day_ledger()
    {
        var windows = DeepIdV2IssuanceAdmissionGate.AdmissionSafetyHorizonSeconds /
            DeepIdV2IssuanceAdmissionGate.WindowSeconds + 1;
        var worstCase = checked(DeepIdV2IssuanceAdmissionGate.GlobalLimit +
            windows * DeepIdV2IssuanceAdmissionGate.GlobalRefillLimit);
        Assert.Equal(138_320, worstCase);
        Assert.Equal(200_000, DeepIdV2IssuanceAdmissionGate.MinimumLedgerCapacity);
        Assert.Equal(DeepIdV2IssuanceAdmissionGate.MinimumLedgerCapacity,
            worstCase + DeepIdV2IssuanceAdmissionGate.CrashAndBoundaryMargin);
        Assert.InRange(DeepIdV2IssuanceAdmissionGate.MinimumLedgerCapacity, 16, 1_000_000);
        Assert.True(worstCase > ContactResolveIssuanceAdmissionGate.MinimumLedgerCapacity);
    }

    [Fact]
    public void Did2_refill_limits_sustained_demand_and_never_banks_extra_idle_credit()
    {
        var clock = new ManualTimeProvider(DateTimeOffset.FromUnixTimeSeconds(1_700_000_000));
        var gate = new DeepIdV2IssuanceAdmissionGate(clock);
        for (var index = 1; index <= 64; index++)
            Assert.True(gate.TryAcquire(IPAddress.Parse($"192.0.2.{index}")).IsAccepted);
        clock.Advance(TimeSpan.FromSeconds(10));
        for (var index = 1; index <= 16; index++)
            Assert.True(gate.TryAcquire(IPAddress.Parse($"192.0.2.{index}")).IsAccepted);
        Assert.False(gate.TryAcquire(IPAddress.Parse("198.51.100.1")).IsAccepted);
        clock.Advance(TimeSpan.FromSeconds(-1));
        Assert.False(gate.TryAcquire(IPAddress.Parse("198.51.100.2")).IsAccepted);
        clock.Advance(TimeSpan.FromHours(1));
        for (var index = 1; index <= 64; index++)
            Assert.True(gate.TryAcquire(IPAddress.Parse($"192.0.2.{index}")).IsAccepted);
        Assert.False(gate.TryAcquire(IPAddress.Parse("198.51.100.3")).IsAccepted);
    }

    [Fact]
    public void Did2_publication_and_three_host_refresh_fit_one_bounded_burst()
    {
        // Conservative current initial-publication budget: up to eight client
        // preparation proofs and six fragments to each of two replicas. Each
        // replica remints six placements plus two final-commit proofs, with
        // two background refreshes on each of the three hosts. This is an
        // admission model, not native publication/device delivery evidence.
        var clock = new ManualTimeProvider(DateTimeOffset.FromUnixTimeSeconds(1_700_000_000));
        var gate = new DeepIdV2IssuanceAdmissionGate(clock);
        var client = IPAddress.Parse("192.0.2.10");
        var nodes = new[] { IPAddress.Parse("192.0.2.11"), IPAddress.Parse("192.0.2.12"),
            IPAddress.Parse("192.0.2.13") };
        foreach (var node in nodes)
            for (var i = 0; i < 2; i++) Assert.True(gate.TryAcquire(node).IsAccepted);
        for (var i = 0; i < 8 + 2 * 6; i++) Assert.True(gate.TryAcquire(client).IsAccepted);
        foreach (var node in nodes.Take(2))
            for (var i = 0; i < 6 + 2; i++) Assert.True(gate.TryAcquire(node).IsAccepted);
        Assert.True(gate.TryAcquire(IPAddress.Parse("192.0.2.20")).IsAccepted);
    }

    private static BoundedRequestAdmissionGate Gate(
        TimeProvider clock,
        int perSource,
        int global,
        int partitions = 64) => new(
            clock,
            perSource,
            global,
            TimeSpan.FromSeconds(10),
            TimeSpan.FromMinutes(2),
            partitions);

    private sealed class ManualTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;

        internal void Advance(TimeSpan amount) => now += amount;
    }
}
