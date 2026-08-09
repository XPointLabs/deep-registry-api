using System.Security.Cryptography;

namespace Deep.Registry.Api.ProductionMailbox;

internal interface IProductionMailboxV2CapacityGate
{
    ValueTask EnsureReservedAsync(
        ReadOnlyMemory<byte> promotionStateKey,
        CancellationToken cancellationToken);
}

internal sealed class ProductionMailboxV2PublisherTestHooks
{
    internal Action? AfterAttemptPersisted { get; init; }
    internal Action? AfterTransportAccepted { get; init; }
    internal Action? AfterAcknowledged { get; init; }
    internal Action? BeforeFinalize { get; init; }
}

internal sealed class ProductionMailboxV2Publisher(
    IProductionMailboxV2PublicationStateStore state,
    IProductionMailboxV2CapacityGate capacity,
    IProductionMailboxV2ClosureTransport transport,
    IProductionMailboxClosurePublisherSigner signer,
    ReadOnlyMemory<byte> publisherPublicKey,
    TimeProvider? timeProvider = null,
    uint commandMaximumSkewSeconds = 300,
    uint capacityRenewalMarginSeconds = 300,
    ProductionMailboxV2PublisherTestHooks? testHooks = null)
{
    private readonly byte[] publisherPublicKey = FreezePublicKey(publisherPublicKey);
    private readonly TimeProvider timeProvider = timeProvider ?? TimeProvider.System;

    internal async ValueTask<ProductionMailboxV2ActivationCommitStatus> PublishAsync(
        ReadOnlyMemory<byte> activationStateKey,
        CancellationToken cancellationToken)
    {
        var key = ProductionMailboxRouteContinuityStateGuard.FreezeKey(activationStateKey);
        var current = await state.GetCurrentV2ActivationForPublicationAsync(key,
            capacityRenewalMarginSeconds, cancellationToken);
        if (current.Status != ProductionMailboxV2ActivationCommitStatus.Accepted)
            return current.Status;
        var activation = current.State!;
        if (!Fixed(activation.PublisherPublicKey.Span, publisherPublicKey))
            return ProductionMailboxV2ActivationCommitStatus.Conflict;

        // Reserve every exact target before the first network publication side effect.
        await capacity.EnsureReservedAsync(activation.PromotionStateKey, cancellationToken);
        current = await state.GetCurrentV2ActivationForPublicationAsync(key,
            capacityRenewalMarginSeconds, cancellationToken);
        if (current.Status != ProductionMailboxV2ActivationCommitStatus.Accepted)
            return current.Status;
        activation = current.State!;
        foreach (var pendingTarget in activation.Targets.Where(static value => !value.Acknowledged))
        {
            cancellationToken.ThrowIfCancellationRequested();
            current = await state.GetCurrentV2ActivationForPublicationAsync(key,
                capacityRenewalMarginSeconds, cancellationToken);
            if (current.Status != ProductionMailboxV2ActivationCommitStatus.Accepted)
                return current.Status;
            activation = current.State!;
            var targetState = activation.Targets.Single(value =>
                Fixed(value.ReplicaId.Span, pendingTarget.ReplicaId.Span));
            var target = new ProductionMailboxV2Target(targetState.ReplicaId.ToArray(),
                targetState.Endpoint, targetState.CurrentSpkiSha256.ToArray(),
                targetState.NextSpkiSha256.ToArray());
            var command = SelectReplayableAttempt(targetState);
            if (command is null)
            {
                var materialized = new ProductionMailboxV2MaterializedCache(
                    activation.CanonicalEnvelope.ToArray(), activation.EnvelopeSha256.ToArray(),
                    activation.LineageCommitment.ToArray(), activation.CacheSalt.ToArray());
                var now = Now();
                var candidate = await ProductionMailboxV2WireCodec.CreateCommandAsync(
                    materialized, target.ReplicaId, activation.CohortId, now, signer,
                    publisherPublicKey, cancellationToken);
                if (!await state.RecordV2PublicationAttemptAsync(key, target.ReplicaId,
                        candidate, commandMaximumSkewSeconds,
                        capacityRenewalMarginSeconds, cancellationToken))
                {
                    current = await state.GetCurrentV2ActivationForPublicationAsync(key,
                        capacityRenewalMarginSeconds, cancellationToken);
                    if (current.Status != ProductionMailboxV2ActivationCommitStatus.Accepted)
                        return current.Status;
                    activation = current.State!;
                    targetState = activation.Targets.Single(value =>
                        Fixed(value.ReplicaId.Span, target.ReplicaId.Span));
                    command = SelectReplayableAttempt(targetState);
                    if (command is null) return ProductionMailboxV2ActivationCommitStatus.Incomplete;
                }
                else
                {
                    current = await state.GetCurrentV2ActivationForPublicationAsync(key,
                        capacityRenewalMarginSeconds, cancellationToken);
                    if (current.Status != ProductionMailboxV2ActivationCommitStatus.Accepted)
                        return current.Status;
                    activation = current.State!;
                    targetState = activation.Targets.Single(value =>
                        Fixed(value.ReplicaId.Span, target.ReplicaId.Span));
                    command = targetState.CanonicalAttempt?.ToArray()
                        ?? throw new InvalidDataException("Durable PMP2 attempt disappeared.");
                    testHooks?.AfterAttemptPersisted?.Invoke();
                }
            }
            var attemptHash = SHA256.HashData(command);
            if (!await transport.PrepositionV2Async(target, command, cancellationToken))
                return ProductionMailboxV2ActivationCommitStatus.Incomplete;
            testHooks?.AfterTransportAccepted?.Invoke();
            if (!await state.AcknowledgeV2PublicationAttemptAsync(key, target.ReplicaId,
                    attemptHash, cancellationToken))
                return ProductionMailboxV2ActivationCommitStatus.Incomplete;
            testHooks?.AfterAcknowledged?.Invoke();
        }

        // A sweep can be long. Renew again before the authoritative transactional finalizer.
        await capacity.EnsureReservedAsync(activation.PromotionStateKey, cancellationToken);
        testHooks?.BeforeFinalize?.Invoke();
        return await state.TryFinalizeV2ActivationAsync(key,
            capacityRenewalMarginSeconds, cancellationToken);
    }

    private byte[]? SelectReplayableAttempt(ProductionMailboxV2ActivationTargetState target)
    {
        if (target.CanonicalAttempt is not { } command
            || target.AttemptedAtUnixSeconds is not { } attemptedAt) return null;
        var now = Now();
        return ProductionMailboxV2AttemptGuard.IsFresh(
            attemptedAt, now, commandMaximumSkewSeconds) ? command.ToArray() : null;
    }

    private ulong Now() => checked((ulong)timeProvider.GetUtcNow().ToUnixTimeSeconds());

    private static byte[] FreezePublicKey(ReadOnlyMemory<byte> value)
    {
        if (value.Length != 32 || value.Span.IndexOfAnyExcept((byte)0) < 0)
            throw new InvalidDataException("PMP2 publisher public key is invalid.");
        return value.ToArray();
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}
