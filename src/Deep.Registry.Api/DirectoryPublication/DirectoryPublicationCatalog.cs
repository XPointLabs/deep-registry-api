using System.Security.Cryptography;

namespace Deep.Registry.Api.DirectoryPublication;

internal sealed class DirectoryPublicationCatalog
{
    internal const int NetworkIdBytes = 16;
    internal const int HashBytes = 32;

    private readonly byte[] expectedNetworkId;
    private readonly IDirectoryCanonicalPublicationVerifier verifier;
    private readonly IDirectoryCatalogPersistence persistence;
    private readonly DirectoryCatalogLimits limits;
    private readonly SemaphoreSlim operationGate = new(1, 1);
    private readonly object stateGate = new();

    private DirectoryCatalogState state;
    private bool quarantined;

    internal DirectoryPublicationCatalog(
        string statePath,
        ReadOnlySpan<byte> expectedNetworkId,
        IDirectoryCanonicalPublicationVerifier verifier,
        DirectoryCatalogLimits? limits = null)
        : this(
            new FileDirectoryCatalogPersistence(statePath),
            expectedNetworkId,
            verifier,
            limits)
    {
    }

    internal DirectoryPublicationCatalog(
        IDirectoryCatalogPersistence persistence,
        ReadOnlySpan<byte> expectedNetworkId,
        IDirectoryCanonicalPublicationVerifier verifier,
        DirectoryCatalogLimits? limits = null)
    {
        ArgumentNullException.ThrowIfNull(persistence);
        ArgumentNullException.ThrowIfNull(verifier);
        if (expectedNetworkId.Length != NetworkIdBytes || IsZero(expectedNetworkId))
        {
            throw new ArgumentException(
                "A non-zero 16-byte XPoint network ID is required.",
                nameof(expectedNetworkId));
        }

        this.persistence = persistence;
        this.expectedNetworkId = expectedNetworkId.ToArray();
        this.verifier = verifier;
        this.limits = limits ?? new DirectoryCatalogLimits();
        this.limits.Validate();
        state = DirectoryCatalogState.Empty(expectedNetworkId);

        using var lease = persistence.AcquireExclusiveLease();
        ReloadUnderLease();
    }

    internal bool IsQuarantined
    {
        get
        {
            lock (stateGate)
            {
                return quarantined;
            }
        }
    }

    internal bool IsForkLatched
    {
        get
        {
            lock (stateGate)
            {
                return state.ForkEvidence is not null;
            }
        }
    }

    internal int HistoryCount
    {
        get
        {
            lock (stateGate)
            {
                EnsureNotQuarantined();
                return state.Segments.Count;
            }
        }
    }

    internal DirectoryCatalogAnchor CurrentAnchor
    {
        get
        {
            lock (stateGate)
            {
                EnsureNotQuarantined();
                return AnchorOf(state);
            }
        }
    }

    internal DirectoryCatalogIoMetrics IoMetrics => persistence.IoMetrics;
    internal long MaximumTotalOnDiskBytes => limits.MaximumTotalOnDiskBytes;

    internal DirectoryCatalogPublication? GetCurrent()
    {
        return ReadUnderFreshLease(static value => value.Segments.LastOrDefault());
    }

    internal DirectoryCatalogPublication? Get(ulong generation)
    {
        return ReadUnderFreshLease(value => FindGeneration(value, generation));
    }

    internal DirectoryMirrorArtifact GetManifestArtifact()
    {
        operationGate.Wait();
        try
        {
            using var lease = persistence.AcquireExclusiveLease();
            ReloadUnderLease();
            EnsureNotQuarantined();
            var encoded = DirectoryCatalogManifestCodec.Encode(state, limits);
            return new DirectoryMirrorArtifact(encoded, SHA256.HashData(encoded));
        }
        finally
        {
            operationGate.Release();
        }
    }

    internal DirectoryMirrorArtifact? GetGenerationArtifact(ulong generation)
    {
        operationGate.Wait();
        try
        {
            using var lease = persistence.AcquireExclusiveLease();
            ReloadUnderLease();
            EnsureNotQuarantined();
            var entry = FindGeneration(state, generation);
            if (entry is null)
            {
                return null;
            }

            var publication = ReadUnderLease(entry);
            var encoded = DirectoryCatalogSegmentCodec.Encode(
                expectedNetworkId,
                publication,
                limits);
            return new DirectoryMirrorArtifact(encoded, entry.SegmentHash);
        }
        catch (DirectoryCatalogException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is InvalidDataException or FormatException or OverflowException)
        {
            QuarantineUnderLease();
            throw Error(
                DirectoryCatalogError.CorruptStateQuarantined,
                "A retained directory generation is corrupt and was quarantined.",
                exception);
        }
        finally
        {
            operationGate.Release();
        }
    }

    internal DirectoryMirrorArtifact? GetCurrentHeadArtifact()
    {
        operationGate.Wait();
        try
        {
            using var lease = persistence.AcquireExclusiveLease();
            ReloadUnderLease();
            EnsureNotQuarantined();
            var entry = state.Segments.LastOrDefault();
            if (entry is null)
            {
                return null;
            }

            var publication = ReadUnderLease(entry);
            var head = publication.Artifacts.Single(
                static artifact => artifact.Kind == DirectoryArtifactKind.CurrentNetworkViewHead);
            return new DirectoryMirrorArtifact(head.CanonicalBytes, head.ArtifactHash);
        }
        catch (DirectoryCatalogException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is InvalidDataException or FormatException or OverflowException)
        {
            QuarantineUnderLease();
            throw Error(
                DirectoryCatalogError.CorruptStateQuarantined,
                "The current directory head is corrupt and was quarantined.",
                exception);
        }
        finally
        {
            operationGate.Release();
        }
    }

    internal async ValueTask<DirectoryCatalogPublishResult> PublishAsync(
        DirectoryPublicationCandidate candidate,
        DirectoryCatalogAnchor expectedCurrent,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        var frozenCandidate = candidate.Freeze();
        ValidateCandidateBounds(frozenCandidate);

        await RefreshBeforeVerificationAsync(cancellationToken).ConfigureAwait(false);

        VerifiedDirectoryPublication verified;
        try
        {
            verified = await verifier.VerifyAsync(frozenCandidate, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is FormatException or InvalidDataException or
            CryptographicException or ArgumentException)
        {
            throw Error(
                DirectoryCatalogError.CanonicalVerificationFailed,
                "The canonical directory publication did not verify.",
                exception);
        }

        if (verified is null)
        {
            throw Error(
                DirectoryCatalogError.CanonicalVerificationFailed,
                "The canonical verifier returned no typed publication.");
        }

        var publication = ValidateAndFreezeVerification(frozenCandidate, verified);

        await operationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var lease = persistence.AcquireExclusiveLease(cancellationToken);
            ReloadUnderLease();
            EnsureNotQuarantined();

            if (state.ForkEvidence is not null)
            {
                throw Error(
                    DirectoryCatalogError.ForkLatched,
                    "Directory publication is disabled by a durable fork latch.");
            }

            var sameGeneration = FindGeneration(state, publication.Generation);
            if (sameGeneration is not null)
            {
                var accepted = ReadUnderLease(sameGeneration);
                if (ExactEquals(accepted, publication))
                {
                    return new DirectoryCatalogPublishResult(
                        DirectoryCatalogPublishStatus.ExactReplay,
                        AnchorOf(state));
                }

                LatchForkUnderLease(accepted, publication);
                throw Error(
                    DirectoryCatalogError.ForkLatched,
                    "Different verified canonical bytes were observed for one directory generation.");
            }

            var current = state.Segments.LastOrDefault();
            if (current is not null && publication.Generation < current.Generation)
            {
                throw Error(
                    DirectoryCatalogError.Rollback,
                    "Directory publication generation is older than the durable current generation.");
            }

            var actualAnchor = AnchorOf(state);
            if (expectedCurrent != actualAnchor)
            {
                throw Error(
                    DirectoryCatalogError.CompareExchangeMismatch,
                    "Directory publication compare-and-swap anchor is stale.");
            }

            if (current is not null &&
                (current.Generation == ulong.MaxValue ||
                 publication.Generation != current.Generation + 1))
            {
                throw Error(
                    DirectoryCatalogError.GenerationGap,
                    "Directory publication generations must advance by exactly one.");
            }

            if (state.Segments.Count >= limits.MaximumHistoryEntries)
            {
                throw Error(
                    DirectoryCatalogError.HistoryCapacityReached,
                    "Directory publication history reached its configured hard limit.");
            }

            try
            {
                var next = persistence.Append(
                    state,
                    publication,
                    expectedNetworkId,
                    limits);
                SetState(next);
                return new DirectoryCatalogPublishResult(
                    DirectoryCatalogPublishStatus.Published,
                    AnchorOf(next));
            }
            catch (DirectoryCatalogException)
            {
                throw;
            }
            catch (Exception exception) when (
                exception is InvalidDataException or FormatException or OverflowException)
            {
                QuarantineUnderLease();
                throw Error(
                    DirectoryCatalogError.CorruptStateQuarantined,
                    "Directory catalog persistence failed closed and was quarantined.",
                    exception);
            }
        }
        finally
        {
            operationGate.Release();
        }
    }

    internal async ValueTask<DirectoryCatalogCompactionResult> CompactAsync(
        DirectoryCatalogCompactionCapability capability,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(capability);
        await operationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var lease = persistence.AcquireExclusiveLease(cancellationToken);
            ReloadUnderLease();
            EnsureNotQuarantined();
            if (state.ForkEvidence is not null)
            {
                throw Error(
                    DirectoryCatalogError.ForkLatched,
                    "Directory compaction is disabled by a durable fork latch.");
            }
            if (!CryptographicOperations.FixedTimeEquals(
                    capability.NetworkId.Span,
                    expectedNetworkId))
            {
                throw Error(
                    DirectoryCatalogError.CompactionNotAuthorized,
                    "The compaction capability belongs to another network.");
            }

            var priorReceipt = state.LastCompaction;
            if (priorReceipt is not null &&
                priorReceipt.RetainedTargetGeneration == capability.TargetGeneration &&
                CryptographicOperations.FixedTimeEquals(
                    priorReceipt.CapabilityHash,
                    capability.CapabilityHash.Span))
            {
                return new DirectoryCatalogCompactionResult(
                    DirectoryCatalogCompactionStatus.ExactReplay,
                    AnchorOf(state),
                    state.Segments[0].Generation,
                    state.Segments.Count);
            }

            var targetIndex = IndexOfGeneration(state.Segments, capability.TargetGeneration);
            if (targetIndex <= 0 ||
                state.Segments.Count - targetIndex < DirectoryCatalogLimits.RequiredMinimumHistoryEntries ||
                targetIndex > DirectoryCatalogLimits.MaximumCompactionSourceProofs)
            {
                throw Error(
                    DirectoryCatalogError.CompactionTargetMismatch,
                    "The verified compaction target does not leave the mandatory retained suffix.");
            }

            var sources = capability.Sources;
            if (sources.Count != targetIndex)
            {
                throw Error(
                    DirectoryCatalogError.CompactionCoverageMismatch,
                    "The compaction capability does not cover every removable protected LKG.");
            }

            var target = ReadUnderLease(state.Segments[targetIndex]);
            if (!CryptographicOperations.FixedTimeEquals(
                    target.ProtectedLkgFingerprint,
                    capability.TargetProtectedLkgFingerprint.Span))
            {
                throw Error(
                    DirectoryCatalogError.CompactionTargetMismatch,
                    "The compaction capability target differs from the retained catalog target.");
            }

            var proofHashes = new HashSet<string>(StringComparer.Ordinal);
            for (var index = 0; index < targetIndex; index++)
            {
                var entry = state.Segments[index];
                var publication = ReadUnderLease(entry);
                var source = sources[index];
                if (source.Generation != entry.Generation ||
                    !CryptographicOperations.FixedTimeEquals(
                        source.ProtectedLkgFingerprint.Span,
                        publication.ProtectedLkgFingerprint))
                {
                    throw Error(
                        DirectoryCatalogError.CompactionCoverageMismatch,
                        "A removable generation lacks its exact source-specific protected-LKG proof.");
                }
                if (!proofHashes.Add(Convert.ToHexString(source.SourceSpecificProofHash.Span)))
                {
                    throw Error(
                        DirectoryCatalogError.CompactionCoverageMismatch,
                        "One common proof cannot authorize more than one protected LKG.");
                }
                if (capability.CurrentTrustedLowerUnixSeconds <
                        publication.RetentionStartedAtTrustedUnixSeconds ||
                    capability.CurrentTrustedLowerUnixSeconds -
                        publication.RetentionStartedAtTrustedUnixSeconds <
                        DirectoryCatalogLimits.RequiredRetentionSeconds)
                {
                    throw Error(
                        DirectoryCatalogError.CompactionPremature,
                        "A removable generation has not completed the authenticated 400-day retention horizon.");
                }
            }

            try
            {
                var next = persistence.Compact(
                    state,
                    new DirectoryCatalogCompactionPlan(
                        targetIndex,
                        capability.TargetGeneration,
                        capability.CapabilityHash.Span),
                    expectedNetworkId,
                    limits);
                SetState(next);
                return new DirectoryCatalogCompactionResult(
                    DirectoryCatalogCompactionStatus.Compacted,
                    AnchorOf(next),
                    next.Segments[0].Generation,
                    next.Segments.Count);
            }
            catch (DirectoryCatalogException)
            {
                throw;
            }
            catch (Exception exception) when (
                exception is InvalidDataException or FormatException or OverflowException or
                CryptographicException)
            {
                QuarantineUnderLease();
                throw Error(
                    DirectoryCatalogError.CorruptStateQuarantined,
                    "Directory compaction persistence failed closed and was quarantined.",
                    exception);
            }
        }
        finally
        {
            operationGate.Release();
        }
    }

    private async ValueTask RefreshBeforeVerificationAsync(CancellationToken cancellationToken)
    {
        await operationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var lease = persistence.AcquireExclusiveLease(cancellationToken);
            ReloadUnderLease();
            EnsureNotQuarantined();
            if (state.ForkEvidence is not null)
            {
                throw Error(
                    DirectoryCatalogError.ForkLatched,
                    "Directory publication is disabled by a durable fork latch.");
            }
        }
        finally
        {
            operationGate.Release();
        }
    }

    private DirectoryCatalogPublication? ReadUnderFreshLease(
        Func<DirectoryCatalogState, DirectoryCatalogSegmentEntry?> selectEntry)
    {
        operationGate.Wait();
        try
        {
            using var lease = persistence.AcquireExclusiveLease();
            ReloadUnderLease();
            EnsureNotQuarantined();
            var entry = selectEntry(state);
            if (entry is null)
            {
                return null;
            }

            try
            {
                return new DirectoryCatalogPublication(ReadUnderLease(entry));
            }
            catch (DirectoryCatalogException)
            {
                throw;
            }
            catch (Exception exception) when (
                exception is InvalidDataException or FormatException or OverflowException)
            {
                QuarantineUnderLease();
                throw Error(
                    DirectoryCatalogError.CorruptStateQuarantined,
                    "A retained directory segment is corrupt and was quarantined.",
                    exception);
            }
        }
        finally
        {
            operationGate.Release();
        }
    }

    private StoredDirectoryPublication ReadUnderLease(DirectoryCatalogSegmentEntry entry) =>
        persistence.ReadPublication(entry, expectedNetworkId, limits);

    private void ReloadUnderLease()
    {
        if (persistence.IsQuarantined)
        {
            lock (stateGate)
            {
                quarantined = true;
            }

            return;
        }

        try
        {
            SetState(persistence.LoadAndRecover(expectedNetworkId, limits));
        }
        catch (Exception exception) when (
            exception is InvalidDataException or FormatException or OverflowException or
            CryptographicException)
        {
            _ = exception;
            QuarantineUnderLease();
        }
    }

    private void LatchForkUnderLease(
        StoredDirectoryPublication first,
        StoredDirectoryPublication second)
    {
        var evidence = new DirectoryForkEvidence(
            first.Generation,
            first.PublicationHash.ToArray(),
            second.PublicationHash.ToArray());
        SetState(persistence.LatchFork(state, evidence, limits));
    }

    private StoredDirectoryPublication ValidateAndFreezeVerification(
        FrozenDirectoryPublicationCandidate candidate,
        VerifiedDirectoryPublication verified)
    {
        if (!CryptographicOperations.FixedTimeEquals(
                verified.NetworkId.Span,
                expectedNetworkId))
        {
            throw Error(
                DirectoryCatalogError.WrongNetwork,
                "Verified directory publication belongs to another XPoint network.");
        }

        var candidateArtifacts = candidate.Artifacts();
        var verifiedArtifacts = verified.Artifacts;
        if (candidateArtifacts.Count != verifiedArtifacts.Count)
        {
            throw Error(
                DirectoryCatalogError.VerificationMismatch,
                "The verifier changed the directory publication closure.");
        }

        for (var index = 0; index < candidateArtifacts.Count; index++)
        {
            var source = candidateArtifacts[index];
            var output = verifiedArtifacts[index];
            if (source.Kind != output.Kind ||
                !source.Bytes.Span.SequenceEqual(output.CanonicalBytes.Span))
            {
                throw Error(
                    DirectoryCatalogError.VerificationMismatch,
                    "The verifier did not return the exact submitted canonical bytes.");
            }
        }

        var stored = verified.ToStored();
        foreach (var artifact in stored.Artifacts)
        {
            if (artifact.CanonicalBytes.Length > limits.MaximumArtifactBytes ||
                artifact.ArtifactHash.Length != HashBytes ||
                artifact.CoreHash.Length != HashBytes ||
                artifact.CoreHash.AsSpan().IndexOfAnyExcept((byte)0) < 0 ||
                !CryptographicOperations.FixedTimeEquals(
                    artifact.ArtifactHash,
                    SHA256.HashData(artifact.CanonicalBytes)))
            {
                throw Error(
                    DirectoryCatalogError.VerificationMismatch,
                    "The typed verifier returned invalid canonical bytes or hashes.");
            }
        }

        return stored;
    }

    private void ValidateCandidateBounds(FrozenDirectoryPublicationCandidate candidate)
    {
        var artifacts = candidate.Artifacts();
        if (artifacts.Count is not (3 or 5))
        {
            throw Error(
                DirectoryCatalogError.BoundsExceeded,
                "A directory publication must contain exactly three or five artifacts.");
        }

        foreach (var (_, bytes) in artifacts)
        {
            if (bytes.IsEmpty || bytes.Length > limits.MaximumArtifactBytes)
            {
                throw Error(
                    DirectoryCatalogError.BoundsExceeded,
                    "A directory artifact is empty or exceeds the canonical byte limit.");
            }
        }
    }

    private void QuarantineUnderLease()
    {
        persistence.Quarantine();
        lock (stateGate)
        {
            quarantined = true;
        }
    }

    private void SetState(DirectoryCatalogState value)
    {
        lock (stateGate)
        {
            state = value;
            quarantined = false;
        }
    }

    private void EnsureNotQuarantined()
    {
        if (quarantined)
        {
            throw Error(
                DirectoryCatalogError.CorruptStateQuarantined,
                "Directory catalog state is quarantined and cannot be trusted.");
        }
    }

    private static DirectoryCatalogSegmentEntry? FindGeneration(
        DirectoryCatalogState value,
        ulong generation)
    {
        if (value.Segments.Count == 0 ||
            generation < value.Segments[0].Generation ||
            generation > value.Segments[^1].Generation)
        {
            return null;
        }

        var offset = generation - value.Segments[0].Generation;
        return offset > int.MaxValue || offset >= (ulong)value.Segments.Count
            ? null
            : value.Segments[(int)offset];
    }

    private static int IndexOfGeneration(
        IReadOnlyList<DirectoryCatalogSegmentEntry> entries,
        ulong generation)
    {
        if (entries.Count == 0 || generation < entries[0].Generation ||
            generation > entries[^1].Generation)
        {
            return -1;
        }
        var offset = generation - entries[0].Generation;
        return offset > int.MaxValue || offset >= (ulong)entries.Count ? -1 : (int)offset;
    }

    private static DirectoryCatalogAnchor AnchorOf(DirectoryCatalogState value)
    {
        var current = value.Segments.LastOrDefault();
        return current is null
            ? DirectoryCatalogAnchor.Empty
            : new DirectoryCatalogAnchor(current.Generation, current.PublicationHash);
    }

    private static bool ExactEquals(
        StoredDirectoryPublication first,
        StoredDirectoryPublication second)
    {
        if (first.Generation != second.Generation ||
            first.Artifacts.Count != second.Artifacts.Count)
        {
            return false;
        }

        for (var index = 0; index < first.Artifacts.Count; index++)
        {
            var left = first.Artifacts[index];
            var right = second.Artifacts[index];
            if (left.Kind != right.Kind ||
                !left.CanonicalBytes.AsSpan().SequenceEqual(right.CanonicalBytes) ||
                !CryptographicOperations.FixedTimeEquals(left.ArtifactHash, right.ArtifactHash) ||
                !CryptographicOperations.FixedTimeEquals(left.CoreHash, right.CoreHash))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsZero(ReadOnlySpan<byte> value)
    {
        var aggregate = 0;
        foreach (var item in value)
        {
            aggregate |= item;
        }

        return aggregate == 0;
    }

    private static DirectoryCatalogException Error(
        DirectoryCatalogError error,
        string message,
        Exception? innerException = null) =>
        new(error, message, innerException);
}
