using System.Net;
using Deep.Registry.Api.ProductionMailbox;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace Deep.Registry.Api.Tests;

public sealed class ProductionMailboxChallengeAdmissionTests
{
    private static readonly byte[] Closure = Enumerable.Repeat((byte)0x51, 32).ToArray();

    [Fact]
    public void UntrustedPeerCannotSpoofForwardedSource()
    {
        var resolver = Resolver();
        var spoofed = Context("203.0.113.10", "198.51.100.77");
        var direct = Context("203.0.113.10");

        Assert.True(resolver.TryResolve(direct, out var expected));
        Assert.True(resolver.TryResolve(spoofed, out var actual));
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void ExplicitTrustedProxyUsesRightmostUntrustedForwardedSource()
    {
        var resolver = Resolver("10.0.0.0/8");
        var forwarded = Context(
            "10.1.2.3", "192.0.2.123, 198.51.100.77, 10.9.8.7");
        Assert.True(Resolver().TryResolve(
            Context("198.51.100.77"), out var expected));

        Assert.True(resolver.TryResolve(forwarded, out var actual));
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void TrustedProxyWithMalformedForwardingFailsClosed()
    {
        var resolver = Resolver("10.0.0.0/8");

        Assert.False(resolver.TryResolve(
            Context("10.1.2.3", "not-an-ip"), out var sourceKey));
        Assert.Empty(sourceKey);
    }

    [Fact]
    public async Task PerSourceLimitDoesNotConsumeAnotherSourcePartition()
    {
        var store = new InMemoryProductionMailboxStateStore();
        var limits = new ProductionMailboxChallengeAdmissionLimits(10, 1, 10, 1);

        Assert.NotNull(await Create(store, Source(1), limits, 100, 200, 40));
        Assert.Null(await Create(store, Source(1), limits, 100, 200, 40));
        Assert.NotNull(await Create(store, Source(2), limits, 100, 200, 40));
    }

    [Fact]
    public async Task GlobalEmergencyCeilingIsSharedAcrossSources()
    {
        var store = new InMemoryProductionMailboxStateStore();
        var limits = new ProductionMailboxChallengeAdmissionLimits(100, 100, 2, 2);

        Assert.NotNull(await Create(store, Source(1), limits, 100, 200, 40));
        Assert.NotNull(await Create(store, Source(2), limits, 100, 200, 40));
        Assert.Null(await Create(store, Source(3), limits, 100, 200, 40));
    }

    [Fact]
    public async Task ExpiredChallengeIsCleanedOnlyAfterWindowRetentionBoundary()
    {
        var store = new InMemoryProductionMailboxStateStore();
        var limits = new ProductionMailboxChallengeAdmissionLimits(1, 1, 1, 1);
        var source = Source(1);

        Assert.NotNull(await Create(store, source, limits, 100, 101, 40));
        Assert.Null(await Create(store, source, limits, 101, 200, 40));
        Assert.NotNull(await Create(store, source, limits, 102, 200, 101));
    }

    [Fact]
    public async Task ConcurrentAdmissionNeverExceedsConfiguredCaps()
    {
        var store = new InMemoryProductionMailboxStateStore();
        var limits = new ProductionMailboxChallengeAdmissionLimits(4, 4, 4, 4);
        var source = Source(1);

        var results = await Task.WhenAll(Enumerable.Range(0, 32).Select(_ =>
            Create(store, source, limits, 100, 200, 40).AsTask()));

        Assert.Equal(4, results.Count(result => result is not null));
    }

    private static ValueTask<ProductionMailboxChallengeState?> Create(
        IProductionMailboxStateStore store,
        byte[] source,
        ProductionMailboxChallengeAdmissionLimits limits,
        ulong now,
        ulong expires,
        ulong windowStart) => store.CreateChallengeAsync(
            now, expires, Closure, source, limits, windowStart, CancellationToken.None);

    private static ProductionMailboxChallengeSourceResolver Resolver(
        params string[] trusted) => new(Options.Create(new ProductionMailboxOptions
        {
            ChallengeTrustedProxyCidrs = trusted
        }));

    private static DefaultHttpContext Context(string remote, string? forwarded = null)
    {
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = IPAddress.Parse(remote);
        if (forwarded is not null)
            context.Request.Headers["X-Forwarded-For"] = forwarded;
        return context;
    }

    private static byte[] Source(byte value) => Enumerable.Repeat(value, 32).ToArray();
}
