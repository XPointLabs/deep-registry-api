#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Registry.Api.DirectoryPublication;

// Actual durable producer. Both role roots must be explicitly provisioned.
// Current-pair bytes are distribution input, not native admission capabilities.
internal sealed class MailboxRevocationAuthority(
    DeepIdV2MailboxAuthorityContextSource contexts, IDeepIdV2MailboxGrantSignerCustody custody,
    string connectionString, ReadOnlyMemory<byte> configuredNetwork)
{
    internal const ulong RenewalLeadSeconds = 60;
    private readonly byte[] network = configuredNetwork.ToArray();
    private readonly SemaphoreSlim gate = new(1, 1);
    private DeepIdV2MailboxAuthorityContext? observedContext;
    private int stopped;

    internal void MarkRunning() => Volatile.Write(ref stopped, 0);
    internal void MarkStopped() { Volatile.Write(ref stopped, 1); Volatile.Write(ref observedContext, null); }

    internal async ValueTask RefreshAsync(CancellationToken ct)
    {
        RequireRunning(); ct.ThrowIfCancellationRequested();
        if (!await gate.WaitAsync(0, ct).ConfigureAwait(false)) throw new IOException("Mailbox renewal is busy.");
        try
        {
            await contexts.WithCurrentAsync(async (context, token) =>
            {
                RequireRunning(); RequireNetwork(context); Volatile.Write(ref observedContext, context);
                foreach (var role in new[] { MailboxCapabilityDomain.Deposit, MailboxCapabilityDomain.Retrieve })
                {
                    var current = await context.ReadIntervalAsync(token).ConfigureAwait(false);
                    if (current.Policy.ExpiresAtUnixSeconds <= checked(current.Upper + RenewalLeadSeconds))
                        throw new IOException("Mailbox policy requires an authorized successor before renewal.");
                    using var journal = Open(context, current.Policy, role);
                    // At most an identical pending completion and one fresh
                    // cumulative successor per role per refresh. No unbounded loop.
                    for (var step = 0; step < 2; step++)
                    {
                        var state = await journal.ReadIssuerStateAsync(context.Host, token).ConfigureAwait(false);
                        current = await context.ReadIntervalAsync(token).ConfigureAwait(false);
                        var due = state.ExactWinner.IsEmpty || state.HasPending || state.HasUnpublishedRevocations ||
                            MailboxGrantRevocationV1Codec.Decode(state.ExactWinner.Span).ExpiresAt <= checked(current.Upper + RenewalLeadSeconds);
                        if (!due) break;
                        if (current.Policy.ExpiresAtUnixSeconds <= checked(current.Upper + RenewalLeadSeconds))
                            throw new IOException("Mailbox policy requires an authorized successor before renewal.");
                        var signer = context.GuardSigner(custody.Resolve(current.Policy, role));
                        _ = await journal.GetOrIssueNextAsync(context.Host, [], signer, token).ConfigureAwait(false);
                        await context.RequireCurrentAsync(token).ConfigureAwait(false);
                    }
                }
                _ = await ReadCurrentPairAsync(context, token).ConfigureAwait(false);
                RequireRunning(); token.ThrowIfCancellationRequested(); return true;
            }, ct).ConfigureAwait(false);
        }
        finally { gate.Release(); }
    }

    // No proof acquisition or signature on health/readiness. Every read still
    // validates actual source/floor/time and actual signed database state.
    internal async ValueTask RequireReadyAsync(CancellationToken ct)
    {
        RequireRunning(); ct.ThrowIfCancellationRequested();
        if (!await gate.WaitAsync(0, ct).ConfigureAwait(false)) throw new IOException("Mailbox readiness is busy.");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(TimeSpan.FromSeconds(5));
        try
        {
            var context = Volatile.Read(ref observedContext) ?? throw new IOException("Mailbox authority has not observed current sources.");
            _ = await ReadCurrentPairAsync(context, deadline.Token).ConfigureAwait(false);
            RequireRunning(); deadline.Token.ThrowIfCancellationRequested();
        }
        finally { gate.Release(); }
    }

    // One signed historical record; a pending input is never a response.
    // This does not require the latest MGR1 to be fresh, but the complete host is current.
    internal async ValueTask<ReadOnlyMemory<byte>> ReadRetainedAsync(MailboxCapabilityDomain role, ulong generation, CancellationToken ct)
    {
        RequireRunning(); ct.ThrowIfCancellationRequested();
        if (role is not (MailboxCapabilityDomain.Deposit or MailboxCapabilityDomain.Retrieve) || generation is 0 or > 1_048_576)
            throw new ArgumentOutOfRangeException(nameof(generation));
        if (!await gate.WaitAsync(0, ct).ConfigureAwait(false)) throw new IOException("Mailbox retained distribution is busy.");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(TimeSpan.FromSeconds(5));
        try
        {
            var context = Volatile.Read(ref observedContext) ?? throw new IOException("Mailbox authority has not observed current sources.");
            RequireNetwork(context);
            var current = await context.ReadIntervalAsync(deadline.Token).ConfigureAwait(false);
            using var journal = Open(context, current.Policy, role);
            var exact = await journal.ReadSignedStepAsync(context.Host, generation, deadline.Token).ConfigureAwait(false);
            await context.RequireCurrentAsync(deadline.Token).ConfigureAwait(false);
            RequireRunning(); deadline.Token.ThrowIfCancellationRequested(); return exact;
        }
        finally { gate.Release(); }
    }

    private async ValueTask<ReadOnlyMemory<byte>[]> ReadCurrentPairAsync(DeepIdV2MailboxAuthorityContext context, CancellationToken ct)
    {
        RequireNetwork(context); var current = await context.ReadIntervalAsync(ct).ConfigureAwait(false);
        var result = new ReadOnlyMemory<byte>[2];
        foreach (var role in new[] { MailboxCapabilityDomain.Deposit, MailboxCapabilityDomain.Retrieve })
        {
            using var journal = Open(context, current.Policy, role);
            var state = await journal.ReadIssuerStateAsync(context.Host, ct).ConfigureAwait(false);
            if (state.ExactWinner.IsEmpty || state.HasPending || state.HasUnpublishedRevocations)
                throw new IOException("Mailbox current cumulative winner is unavailable.");
            // Verifies current signed bytes only. The unused closed plan is
            // neither an enrollment operation nor a committed native floor.
            _ = await MailboxGrantRevocationV1Verifier.PlanInitialEnrollmentAsync(context.Host, state.ExactWinner, ct).ConfigureAwait(false);
            result[(int)role - 1] = state.ExactWinner.ToArray();
        }
        // Recheck both records after the other role/database callbacks.
        foreach (var role in new[] { MailboxCapabilityDomain.Deposit, MailboxCapabilityDomain.Retrieve })
        {
            using var journal = Open(context, current.Policy, role);
            var readBack = await journal.ReadIssuerStateAsync(context.Host, ct).ConfigureAwait(false);
            var exact = result[(int)role - 1];
            if (readBack.HasPending || readBack.HasUnpublishedRevocations ||
                !CryptographicOperations.FixedTimeEquals(exact.Span, readBack.ExactWinner.Span))
                throw new IOException("Mailbox cumulative winner changed during readiness read-back.");
            _ = await MailboxGrantRevocationV1Verifier.PlanInitialEnrollmentAsync(context.Host, exact, ct).ConfigureAwait(false);
        }
        await context.RequireCurrentAsync(ct).ConfigureAwait(false); return result;
    }
    private MailboxRevocationJournal Open(DeepIdV2MailboxAuthorityContext context, VerifiedMailboxAuthorityV2 policy, MailboxCapabilityDomain role) =>
        new(connectionString, context.Host.NetworkId.Span, [.. "PMA2"u8, 0, 1, .. policy.CoreHash.Span], role, policy.ResolveIssuer(role).PublicKey.Span);
    private void RequireNetwork(DeepIdV2MailboxAuthorityContext context)
    {
        if (network.Length != 16 || !CryptographicOperations.FixedTimeEquals(network, context.Host.NetworkId.Span))
            throw new CryptographicException("Mailbox configured network differs from actual current authority.");
    }
    private void RequireRunning()
    { if (Volatile.Read(ref stopped) != 0) throw new IOException("Mailbox authority is stopped."); }
}

internal sealed class MailboxRevocationRenewalWorker(MailboxRevocationAuthority authority, ILogger<MailboxRevocationRenewalWorker> logger)
    : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var failures = 0;
        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                try { await authority.RefreshAsync(stoppingToken).ConfigureAwait(false); failures = 0; }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
                catch (Exception error) when (error is IOException or CryptographicException or InvalidOperationException or
                    UnauthorizedAccessException or ArgumentException or FormatException or OverflowException or
                    OnionBoundaryException or Npgsql.NpgsqlException or OperationCanceledException or TimeoutException)
                {
                    failures = Math.Min(failures + 1, 4);
                    // Coarse category only, never error messages, identifiers,
                    // paths, signed records, database configuration or keys.
                    logger.LogWarning("Mailbox renewal unavailable ({Category}).", error.GetType().Name);
                }
                var seconds = failures == 0 ? 15 : Math.Min(60, 5 * (1 << failures));
                await Task.Delay(TimeSpan.FromSeconds(seconds + Random.Shared.Next(0, 3)), stoppingToken).ConfigureAwait(false);
            }
        }
        finally { authority.MarkStopped(); }
    }
    public override Task StartAsync(CancellationToken cancellationToken)
    { cancellationToken.ThrowIfCancellationRequested(); authority.MarkRunning(); return base.StartAsync(cancellationToken); }
    public override async Task StopAsync(CancellationToken cancellationToken)
    { authority.MarkStopped(); await base.StopAsync(cancellationToken).ConfigureAwait(false); }
}
#endif
