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
