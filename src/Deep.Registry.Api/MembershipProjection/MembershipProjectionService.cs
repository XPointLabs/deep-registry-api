using System.Security.Cryptography;
using System.Text.Json;
using Deep.Protocol.DeepExtension.Membership;
using Microsoft.Extensions.Options;

namespace Deep.Registry.Api;

public sealed class MembershipProjectionService
{
    internal const string StateSchema = "deep.registry.membership-projection.v1";
    internal const int HardMaximumStateBytes = 1024 * 1024;
    internal const int HardMaximumArtifactBytes = 1024 * 1024;
    private const int HardMaximumTerminalEvidenceBytes = 8 * 1024 * 1024;
    private const int TransientRetryLimit = 3;
    private static readonly ulong MaximumUnixSeconds =
        checked((ulong)DateTimeOffset.MaxValue.ToUnixTimeSeconds());

    private readonly object _gate = new();
    private readonly MembershipProjectionOptions _options;
    private readonly TimeProvider _timeProvider;
    private readonly P04MembershipArtifactVerifier _artifactVerifier;
    private readonly IMembershipProjectionPersistence _persistence;
    private readonly MembershipProjectionMonotonicBoundary _monotonicBoundary;
    private PersistedMembershipProjection? _state;
    private string _persistedStateSha256 = "";
    private bool _unsafeLatch;
    private bool _monotonicConflict;
    private bool _anchorTransient;
    private bool _continuityBusy;
    private bool _loadDeferred;
    private bool _preparedTransitionPresent;
    private bool _corruptStatePresent;
    private bool _configurationInvalid;

    private long _accepted;
    private long _idempotent;
    private long _verifierUnavailable;
    private long _invalidArtifact;
    private long _invalidSigner;
    private long _rollback;
    private long _sequenceGap;
    private long _fork;
    private long _expired;
    private long _clockSkew;
    private long _corruptStateRecoveries;
    private long _persistenceFailures;
    private long _sourceFailures;
    private long _anchorTransientEvents;
    private long _continuityBusyEvents;
    private long _monotonicConflictEvents;

    public MembershipProjectionService(
        IOptions<MembershipProjectionOptions> options,
        TimeProvider timeProvider,
        P04MembershipArtifactVerifier artifactVerifier)
        : this(
            options,
            timeProvider,
            artifactVerifier,
            new FileMembershipProjectionPersistence(ResolveStatePath(options.Value)),
            MembershipProjectionMonotonicBoundary.Create([]))
    {
    }

    public MembershipProjectionService(
        IOptions<MembershipProjectionOptions> options,
        TimeProvider timeProvider,
        P04MembershipArtifactVerifier artifactVerifier,
        IMembershipProjectionPersistence persistence)
        : this(
            options,
            timeProvider,
            artifactVerifier,
            persistence,
            MembershipProjectionMonotonicBoundary.Create([]))
    {
    }

    public MembershipProjectionService(
        IOptions<MembershipProjectionOptions> options,
        TimeProvider timeProvider,
        P04MembershipArtifactVerifier artifactVerifier,
        IMembershipProjectionPersistence persistence,
        MembershipProjectionMonotonicBoundary monotonicBoundary)
    {
        _options = options.Value;
        _timeProvider = timeProvider;
        _artifactVerifier = artifactVerifier;
        _persistence = persistence;
        _monotonicBoundary = monotonicBoundary;
        _configurationInvalid = !HasValidConfiguredLimits();

        if (_options.Enabled &&
            _artifactVerifier.IsAvailable &&
            _monotonicBoundary.IsAvailable &&
            !_configurationInvalid)
        {
            LoadState();
        }
    }

    public MembershipProjectionApplyResult ApplyGenesis(
        ReadOnlySpan<byte> canonicalGenesis,
        IReadOnlyList<MembershipSignature> signatures)
    {
        lock (_gate)
        {
            var gate = CheckIngress(canonicalGenesis.Length);
            if (gate is not null)
            {
                return gate;
            }

            var genesisBytes = canonicalGenesis.ToArray();
            return WithContinuityLease(() =>
            {
                try
                {
                    var expectedNetworkId = DecodeFixedHex(
                        _options.ExpectedNetworkIdHex,
                        MembershipLimits.NetworkIdLength);
                    var expectedGenesisHash = DecodeFixedHex(
                        _options.ExpectedGenesisSha256Hex,
                        MembershipLimits.HashLength);
                    var genesis = MembershipContractVerifier.ImportSelfHostedGenesis(
                        genesisBytes,
                        expectedNetworkId,
                        expectedGenesisHash,
                        signatures,
                        _artifactVerifier.Required);
                    ValidateTimestampBounds(genesis.IssuedAtUnixSeconds);
                    var canonicalHash = MembershipContractHash.Sha256(genesisBytes);

                    if (_state is not null)
                    {
                        if (string.Equals(
                                _state.GenesisSha256,
                                Convert.ToHexString(canonicalHash).ToLowerInvariant(),
                                StringComparison.Ordinal))
                        {
                            return Count(MembershipProjectionApplyResult.Idempotent());
                        }

                        return Count(Rejection(MembershipProjectionCode.WrongNetwork));
                    }

                    var anchor = ToPersistedLkg(new MembershipLastKnownGood
                    {
                        NetworkId = genesis.NetworkId.ToArray(),
                        PolicyVersion = genesis.PolicyVersion,
                        Sequence = genesis.GenesisSequence,
                        CanonicalHash = canonicalHash
                    });
                    var next = new PersistedMembershipProjection
                    {
                        ContractIdentifier = _options.ContractIdentifier,
                        PackageVersion = _options.PackageVersion,
                        NetworkIdHex = Convert.ToHexString(genesis.NetworkId.Span).ToLowerInvariant(),
                        GenesisSha256 = Convert.ToHexString(canonicalHash).ToLowerInvariant(),
                        GenesisBytesBase64 = Convert.ToBase64String(genesisBytes),
                        GenesisSignatures = signatures.Select(ToPersistedSignature).ToArray(),
                        AuthorityLkg = anchor,
                        AuthorityPredecessorLkg = anchor,
                        Bridge = new PersistedContentDomain
                        {
                            Lkg = anchor,
                            PredecessorLkg = anchor,
                            AcceptedAuthorityLkg = anchor
                        },
                        Membership = new PersistedContentDomain
                        {
                            Lkg = anchor,
                            PredecessorLkg = anchor,
                            AcceptedAuthorityLkg = anchor
                        }
                    };

                    return Persist(next);
                }
                catch (Exception exception)
                {
                    return Count(Rejection(MapException(exception)));
                }
            });
        }
    }

    public MembershipProjectionApplyResult ApplyDelegation(ReadOnlySpan<byte> signedDelegation)
    {
        lock (_gate)
        {
            var gate = CheckStatefulIngress(signedDelegation.Length);
            if (gate is not null)
            {
                return gate;
            }

            var delegationBytes = signedDelegation.ToArray();
            return WithContinuityLease(() =>
            {
                try
                {
                    var bytes = delegationBytes;
                    var current = _state!;
                    if (IsSameAuthorityEnvelope(current, "delegation", bytes))
                    {
                        return Count(MembershipProjectionApplyResult.Idempotent());
                    }

                    var delegation = MembershipContractCodec.DecodeSignedDelegation(bytes);
                    ValidateTimestampBounds(
                        delegation.IssuedAtUnixSeconds,
                        delegation.ValidFromUnixSeconds,
                        delegation.ValidUntilUnixSeconds);
                    if (delegation.Sequence <= current.AuthorityLkg.Sequence)
                    {
                        return HandleAuthorityConflict("delegation", bytes, delegation.Sequence);
                    }

                    var verified = MembershipContractVerifier.VerifyDelegation(
                        delegation,
                        DecodeGenesis(current),
                        ToLkg(current.AuthorityLkg),
                        NowUnixSeconds(),
                        _options.AllowedClockSkewSeconds,
                        _options.ClientProtocol,
                        _artifactVerifier.Required);
                    var next = current with
                    {
                        AuthorityPredecessorLkg = current.AuthorityLkg,
                        AuthorityLkg = ToPersistedLkg(verified.NextAuthorityLastKnownGood),
                        AuthorityEnvelopeKind = "delegation",
                        AuthorityEnvelopeBase64 = Convert.ToBase64String(bytes),
                        ActiveDelegationBase64 = Convert.ToBase64String(bytes)
                    };
                    return Persist(next);
                }
                catch (Exception exception)
                {
                    return Count(Rejection(MapException(exception)));
                }
            });
        }
    }

    public MembershipProjectionApplyResult ApplyRevocation(ReadOnlySpan<byte> signedRevocation)
    {
        lock (_gate)
        {
            var gate = CheckStatefulIngress(signedRevocation.Length);
            if (gate is not null)
            {
                return gate;
            }

            var revocationBytes = signedRevocation.ToArray();
            return WithContinuityLease(() =>
            {
                try
                {
                    var bytes = revocationBytes;
                    var current = _state!;
                    if (IsSameAuthorityEnvelope(current, "revocation", bytes))
                    {
                        return Count(MembershipProjectionApplyResult.Idempotent());
                    }

                    var revocation = MembershipContractCodec.DecodeSignedRevocation(bytes);
                    ValidateTimestampBounds(
                        revocation.IssuedAtUnixSeconds,
                        revocation.ValidFromUnixSeconds,
                        revocation.ValidUntilUnixSeconds);
                    if (revocation.Sequence <= current.AuthorityLkg.Sequence)
                    {
                        return HandleAuthorityConflict("revocation", bytes, revocation.Sequence);
                    }

                    var verified = MembershipContractVerifier.VerifyRevocation(
                        revocation,
                        DecodeGenesis(current),
                        ToLkg(current.AuthorityLkg),
                        NowUnixSeconds(),
                        _options.AllowedClockSkewSeconds,
                        _options.ClientProtocol,
                        _artifactVerifier.Required);
                    var revokedHash = Convert.ToHexString(revocation.DelegationHash.Span).ToLowerInvariant();
                    var revoked = current.RevokedDelegationHashes
                        .Append(revokedHash)
                        .Distinct(StringComparer.Ordinal)
                        .TakeLast(MembershipLimits.MaximumRevokedDelegationHashes)
                        .ToArray();
                    var next = current with
                    {
                        AuthorityPredecessorLkg = current.AuthorityLkg,
                        AuthorityLkg = ToPersistedLkg(verified.NextAuthorityLastKnownGood),
                        AuthorityEnvelopeKind = "revocation",
                        AuthorityEnvelopeBase64 = Convert.ToBase64String(bytes),
                        // Authority LKG now pins the revocation, not any prior
                        // delegation. Content verification remains fail-closed
                        // until a new delegation advances the authority chain.
                        ActiveDelegationBase64 = "",
                        RevokedDelegationHashes = revoked
                    };
                    return Persist(next);
                }
                catch (Exception exception)
                {
                    return Count(Rejection(MapException(exception)));
                }
            });
        }
    }

    public MembershipProjectionApplyResult ApplyBridge(ReadOnlySpan<byte> signedBridge)
    {
        lock (_gate)
        {
            var gate = CheckStatefulIngress(signedBridge.Length);
            if (gate is not null)
            {
                return gate;
            }

            var bytes = signedBridge.ToArray();
            return WithContinuityLease(
                () => ApplyContent(bytes, isBridge: true));
        }
    }

    public MembershipProjectionApplyResult ApplyMembership(ReadOnlySpan<byte> signedMembership)
    {
        lock (_gate)
        {
            var gate = CheckStatefulIngress(signedMembership.Length);
            if (gate is not null)
            {
                return gate;
            }

            var bytes = signedMembership.ToArray();
            return WithContinuityLease(
                () => ApplyContent(bytes, isBridge: false));
        }
    }

    public MembershipProjectionStatus GetStatus()
    {
        lock (_gate)
        {
            ObserveContinuityForReadNoLock();
            var ready = IsReadyNoLock();
            var bridge = _state?.Bridge;
            return new MembershipProjectionStatus(
                _options.Enabled,
                ready,
                _artifactVerifier.IsAvailable,
                StateCodeNoLock(),
                HasEnvelope(bridge) ? bridge!.Lkg.Sequence : null,
                HasEnvelope(bridge) ? Sha256Hex(DecodeOptionalBase64(bridge!.EnvelopeBase64)) : null,
                HasEnvelope(bridge)
                    ? DateTimeOffset.FromUnixTimeSeconds(bridge!.ValidUntilUnixSeconds)
                    : null,
                new MembershipProjectionCounters(
                    Interlocked.Read(ref _accepted),
                    Interlocked.Read(ref _idempotent),
                    Interlocked.Read(ref _verifierUnavailable),
                    Interlocked.Read(ref _invalidArtifact),
                    Interlocked.Read(ref _invalidSigner),
                    Interlocked.Read(ref _rollback),
                    Interlocked.Read(ref _sequenceGap),
                    Interlocked.Read(ref _fork),
                    Interlocked.Read(ref _expired),
                    Interlocked.Read(ref _clockSkew),
                    Interlocked.Read(ref _corruptStateRecoveries),
                    Interlocked.Read(ref _persistenceFailures),
                    Interlocked.Read(ref _sourceFailures),
                    Interlocked.Read(ref _anchorTransientEvents),
                    Interlocked.Read(ref _continuityBusyEvents),
                    Interlocked.Read(ref _monotonicConflictEvents)));
        }
    }

    public bool TryGetBridge(out MembershipProjectionBridgeArtifact? artifact)
    {
        lock (_gate)
        {
            ObserveContinuityForReadNoLock();
            if (!IsReadyNoLock() || !HasEnvelope(_state?.Bridge))
            {
                artifact = null;
                return false;
            }

            var bytes = DecodeOptionalBase64(_state!.Bridge.EnvelopeBase64);
            artifact = new MembershipProjectionBridgeArtifact(
                bytes,
                Sha256Hex(bytes),
                DateTimeOffset.FromUnixTimeSeconds(_state.Bridge.ValidUntilUnixSeconds));
            return true;
        }
    }

    public void RecordSourceFailure() => Interlocked.Increment(ref _sourceFailures);

    private void ObserveContinuityForReadNoLock()
    {
        if (!_options.Enabled ||
            !_artifactVerifier.IsAvailable ||
            !_monotonicBoundary.IsAvailable ||
            _configurationInvalid ||
            _monotonicConflict ||
            _unsafeLatch)
        {
            return;
        }

        if (_loadDeferred || _preparedTransitionPresent)
        {
            LoadState();
            return;
        }

        try
        {
            using var lease = AcquireContinuityLeaseWithRetry();
            if (CheckTerminalJournalNoLock())
            {
                return;
            }

            if (_corruptStatePresent)
            {
                var recoveryAnchor = ReadAnchorWithRetry();
                _ = _persistence.Read(_options.MaximumStateBytes);
                if (recoveryAnchor.TerminalUnsafe)
                {
                    _unsafeLatch = true;
                }

                return;
            }

            if (!ValidateContinuityNoLock())
            {
                MarkMonotonicConflict();
            }
        }
        catch (MembershipProjectionLeaseBusyException)
        {
            MarkContinuityBusy();
        }
        catch (MembershipProjectionAnchorTransientException)
        {
            MarkAnchorTransient();
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            MarkMonotonicConflict();
        }
    }

    private MembershipProjectionApplyResult ApplyContent(
        ReadOnlySpan<byte> signedArtifact,
        bool isBridge)
    {
        if (string.IsNullOrWhiteSpace(_state!.ActiveDelegationBase64))
        {
            return Count(Rejection(MembershipProjectionCode.StateUnavailable));
        }

        try
        {
            var bytes = signedArtifact.ToArray();
            var current = _state;
            var domain = isBridge ? current.Bridge : current.Membership;
            if (HasEnvelope(domain) &&
                DecodeOptionalBase64(domain.EnvelopeBase64).AsSpan().SequenceEqual(bytes))
            {
                return Count(MembershipProjectionApplyResult.Idempotent());
            }

            var sequence = isBridge
                ? MembershipContractCodec.DecodeSignedBridge(bytes).Statement.Sequence
                : MembershipContractCodec.DecodeSignedMembership(bytes).Statement.Sequence;
            if (sequence <= domain.Lkg.Sequence)
            {
                return HandleContentConflict(bytes, sequence, isBridge);
            }

            if (domain.Lkg.Sequence == ulong.MaxValue)
            {
                return Count(Rejection(MembershipProjectionCode.SequenceOverflow));
            }

            if (sequence != domain.Lkg.Sequence + 1)
            {
                return Count(Rejection(MembershipProjectionCode.SequenceGap));
            }

            var context = BuildContext(current, domain.Lkg, NowUnixSeconds());
            PersistedContentDomain nextDomain;
            if (isBridge)
            {
                var signed = MembershipContractCodec.DecodeSignedBridge(bytes);
                ValidateTimestampBounds(
                    signed.Statement.IssuedAtUnixSeconds,
                    signed.Statement.ValidFromUnixSeconds,
                    signed.Statement.ValidUntilUnixSeconds);
                var verified = MembershipContractVerifier.VerifyBridge(
                    signed,
                    context,
                    _artifactVerifier.Required);
                nextDomain = new PersistedContentDomain
                {
                    PredecessorLkg = domain.Lkg,
                    Lkg = ToPersistedLkg(verified.NextLastKnownGood),
                    EnvelopeBase64 = Convert.ToBase64String(bytes),
                    ValidUntilUnixSeconds = checked((long)signed.Statement.ValidUntilUnixSeconds),
                    AcceptedAuthorityLkg = current.AuthorityLkg,
                    AcceptedDelegationBase64 = current.ActiveDelegationBase64
                };
            }
            else
            {
                var signed = MembershipContractCodec.DecodeSignedMembership(bytes);
                ValidateTimestampBounds(
                    signed.Statement.IssuedAtUnixSeconds,
                    signed.Statement.ValidFromUnixSeconds,
                    signed.Statement.ValidUntilUnixSeconds);
                var verified = MembershipContractVerifier.VerifyMembership(
                    signed,
                    context,
                    _artifactVerifier.Required);
                nextDomain = new PersistedContentDomain
                {
                    PredecessorLkg = domain.Lkg,
                    Lkg = ToPersistedLkg(verified.NextLastKnownGood),
                    EnvelopeBase64 = Convert.ToBase64String(bytes),
                    ValidUntilUnixSeconds = checked((long)signed.Statement.ValidUntilUnixSeconds),
                    AcceptedAuthorityLkg = current.AuthorityLkg,
                    AcceptedDelegationBase64 = current.ActiveDelegationBase64
                };
            }

            var next = isBridge
                ? current with { Bridge = nextDomain }
                : current with { Membership = nextDomain };
            return Persist(next);
        }
        catch (Exception exception)
        {
            return Count(Rejection(MapException(exception)));
        }
    }

    private MembershipProjectionApplyResult HandleContentConflict(
        byte[] candidate,
        ulong candidateSequence,
        bool isBridge)
    {
        var current = _state!;
        var domain = isBridge ? current.Bridge : current.Membership;
        if (candidateSequence < domain.Lkg.Sequence ||
            !HasEnvelope(domain) ||
            candidateSequence != domain.Lkg.Sequence)
        {
            return Count(Rejection(MembershipProjectionCode.Rollback));
        }

        try
        {
            var context = BuildAcceptedContentContext(
                current,
                domain,
                domain.PredecessorLkg,
                NowUnixSeconds());
            byte[] firstEnvelope;
            byte[] firstCanonical;
            byte[] secondCanonical;
            byte[] previousHash;
            if (isBridge)
            {
                firstEnvelope = DecodeOptionalBase64(domain.EnvelopeBase64);
                var first = MembershipContractCodec.DecodeSignedBridge(firstEnvelope);
                var second = MembershipContractCodec.DecodeSignedBridge(candidate);
                _ = MembershipContractVerifier.CreateBridgeForkEvidence(
                    first,
                    second,
                    context,
                    _artifactVerifier.Required);
                firstCanonical = MembershipContractCodec.GetBridgeSigningBytes(
                    first.Statement);
                secondCanonical = MembershipContractCodec.GetBridgeSigningBytes(
                    second.Statement);
                previousHash = first.Statement.PreviousHash.ToArray();
            }
            else
            {
                firstEnvelope = DecodeOptionalBase64(domain.EnvelopeBase64);
                var first = MembershipContractCodec.DecodeSignedMembership(firstEnvelope);
                var second = MembershipContractCodec.DecodeSignedMembership(candidate);
                _ = MembershipContractVerifier.CreateForkEvidence(
                    first,
                    second,
                    context,
                    _artifactVerifier.Required);
                firstCanonical = MembershipContractCodec.GetMembershipSigningBytes(
                    first.Statement);
                secondCanonical = MembershipContractCodec.GetMembershipSigningBytes(
                    second.Statement);
                previousHash = first.Statement.PreviousHash.ToArray();
            }

            _unsafeLatch = true;
            var forkRecord = new PersistedForkRecord
            {
                Domain = isBridge ? "bridge" : "membership",
                Sequence = candidateSequence,
                PreviousHashHex = Convert.ToHexString(previousHash).ToLowerInvariant(),
                FirstEnvelopeBase64 = Convert.ToBase64String(firstEnvelope),
                SecondEnvelopeBase64 = Convert.ToBase64String(candidate),
                FirstCanonicalStatementBase64 = Convert.ToBase64String(firstCanonical),
                SecondCanonicalStatementBase64 = Convert.ToBase64String(secondCanonical),
                FirstHashHex = Sha256Hex(firstCanonical),
                SecondHashHex = Sha256Hex(secondCanonical)
            };
            var poisonFailure = PoisonForkNoLock(forkRecord);
            if (poisonFailure is not null)
            {
                Interlocked.Increment(ref _fork);
                return poisonFailure;
            }

            var persisted = Persist(
                current with
                {
                    ForkDetected = true,
                    ForkRecords = current.ForkRecords
                        .Append(forkRecord)
                        .TakeLast(16)
                        .ToArray()
                },
                MembershipProjectionCode.ForkDetected);
            Interlocked.Increment(ref _fork);
            return persisted.Success
                ? MembershipProjectionApplyResult.Rejected(MembershipProjectionCode.ForkDetected)
                : persisted;
        }
        catch (Exception exception)
        {
            return Count(Rejection(MapException(exception)));
        }
    }

    private MembershipProjectionApplyResult HandleAuthorityConflict(
        string kind,
        byte[] candidate,
        ulong candidateSequence)
    {
        var current = _state!;
        if (candidateSequence < current.AuthorityLkg.Sequence ||
            string.IsNullOrWhiteSpace(current.AuthorityEnvelopeBase64) ||
            candidateSequence != current.AuthorityLkg.Sequence)
        {
            return Count(Rejection(MembershipProjectionCode.Rollback));
        }

        try
        {
            var genesis = DecodeGenesis(current);
            var predecessor = ToLkg(current.AuthorityPredecessorLkg);
            var firstEnvelope = DecodeOptionalBase64(current.AuthorityEnvelopeBase64);
            byte[] firstCanonical;
            byte[] secondCanonical;
            byte[] previousHash;
            if (kind == "delegation" && current.AuthorityEnvelopeKind == "delegation")
            {
                var first = MembershipContractCodec.DecodeSignedDelegation(firstEnvelope);
                var second = MembershipContractCodec.DecodeSignedDelegation(candidate);
                _ = MembershipContractVerifier.CreateDelegationForkEvidence(
                    first,
                    second,
                    genesis,
                    predecessor,
                    NowUnixSeconds(),
                    _options.AllowedClockSkewSeconds,
                    _options.ClientProtocol,
                    _artifactVerifier.Required);
                firstCanonical = MembershipContractCodec.GetDelegationSigningBytes(first);
                secondCanonical = MembershipContractCodec.GetDelegationSigningBytes(second);
                previousHash = first.PreviousHash.ToArray();
            }
            else if (kind == "revocation" && current.AuthorityEnvelopeKind == "revocation")
            {
                var first = MembershipContractCodec.DecodeSignedRevocation(firstEnvelope);
                var second = MembershipContractCodec.DecodeSignedRevocation(candidate);
                _ = MembershipContractVerifier.CreateRevocationForkEvidence(
                    first,
                    second,
                    genesis,
                    predecessor,
                    NowUnixSeconds(),
                    _options.AllowedClockSkewSeconds,
                    _options.ClientProtocol,
                    _artifactVerifier.Required);
                firstCanonical = MembershipContractCodec.GetRevocationSigningBytes(first);
                secondCanonical = MembershipContractCodec.GetRevocationSigningBytes(second);
                previousHash = first.PreviousHash.ToArray();
            }
            else
            {
                return Count(Rejection(MembershipProjectionCode.Rollback));
            }

            _unsafeLatch = true;
            var forkRecord = new PersistedForkRecord
            {
                Domain = $"authority-{kind}",
                Sequence = candidateSequence,
                PreviousHashHex = Convert.ToHexString(previousHash).ToLowerInvariant(),
                FirstEnvelopeBase64 = Convert.ToBase64String(firstEnvelope),
                SecondEnvelopeBase64 = Convert.ToBase64String(candidate),
                FirstCanonicalStatementBase64 = Convert.ToBase64String(firstCanonical),
                SecondCanonicalStatementBase64 = Convert.ToBase64String(secondCanonical),
                FirstHashHex = Sha256Hex(firstCanonical),
                SecondHashHex = Sha256Hex(secondCanonical)
            };
            var poisonFailure = PoisonForkNoLock(forkRecord);
            if (poisonFailure is not null)
            {
                Interlocked.Increment(ref _fork);
                return poisonFailure;
            }

            var persisted = Persist(
                current with
                {
                    ForkDetected = true,
                    ForkRecords = current.ForkRecords
                        .Append(forkRecord)
                        .TakeLast(16)
                        .ToArray()
                },
                MembershipProjectionCode.ForkDetected);
            Interlocked.Increment(ref _fork);
            return persisted.Success
                ? MembershipProjectionApplyResult.Rejected(MembershipProjectionCode.ForkDetected)
                : persisted;
        }
        catch (Exception exception)
        {
            return Count(Rejection(MapException(exception)));
        }
    }

    private MembershipProjectionApplyResult? PoisonForkNoLock(
        PersistedForkRecord forkRecord)
    {
        var evidenceBytes = JsonSerializer.SerializeToUtf8Bytes(
            forkRecord,
            MembershipProjectionJson.Options);
        var evidenceSha256 = Sha256Hex(evidenceBytes);
        var journalBytes = JsonSerializer.SerializeToUtf8Bytes(
            new PersistedTerminalUnsafeJournal
            {
                EvidenceSha256 = evidenceSha256,
                Domain = forkRecord.Domain,
                Sequence = forkRecord.Sequence
            },
            MembershipProjectionJson.Options);
        var fullEvidenceBytes = JsonSerializer.SerializeToUtf8Bytes(
            new PersistedTerminalUnsafeEvidence
            {
                EvidenceSha256 = evidenceSha256,
                Evidence = forkRecord
            },
            MembershipProjectionJson.Options);
        var markerDurable = false;
        try
        {
            if (journalBytes.Length > _options.MaximumStateBytes)
            {
                throw new InvalidDataException(
                    "The compact terminal marker exceeds the configured state limit.");
            }

            _persistence.WriteTerminalJournal(journalBytes);
            markerDurable = true;
        }
        catch (Exception exception) when (IsRecoverableBackendException(exception))
        {
            Interlocked.Increment(ref _persistenceFailures);
        }

        MembershipProjectionApplyResult? anchorFailure = null;
        var anchorDurable = false;
        try
        {
            var expected = ReadAnchorWithRetry();
            if (expected.TerminalUnsafe)
            {
                anchorDurable = true;
            }
            else if (_state is null ||
                     expected.Generation != _state.Generation ||
                     !string.Equals(
                         expected.StateSha256,
                         _persistedStateSha256,
                         StringComparison.Ordinal))
            {
                MarkMonotonicConflict();
                anchorFailure = MembershipProjectionApplyResult.Rejected(
                    MembershipProjectionCode.MonotonicConflict);
            }
            else
            {
                var poisoned = expected with
                {
                    TerminalUnsafe = true,
                    UnsafeEvidenceSha256 = evidenceSha256
                };
                if (CommitAnchorWithReconciliation(expected, poisoned))
                {
                    anchorDurable = true;
                }
                else
                {
                    MarkMonotonicConflict();
                    anchorFailure = MembershipProjectionApplyResult.Rejected(
                        MembershipProjectionCode.MonotonicConflict);
                }
            }
        }
        catch (MembershipProjectionAnchorTransientException)
        {
            MarkAnchorTransient();
            anchorFailure = MembershipProjectionApplyResult.Rejected(
                MembershipProjectionCode.MonotonicAnchorTransient);
        }
        catch (Exception exception) when (IsRecoverableBackendException(exception))
        {
            MarkAnchorTransient();
            anchorFailure = MembershipProjectionApplyResult.Rejected(
                MembershipProjectionCode.MonotonicAnchorTransient);
        }

        try
        {
            if (fullEvidenceBytes.Length <= HardMaximumTerminalEvidenceBytes)
            {
                _persistence.WriteTerminalEvidence(fullEvidenceBytes);
            }
            else
            {
                Interlocked.Increment(ref _persistenceFailures);
            }
        }
        catch (Exception exception) when (IsRecoverableBackendException(exception))
        {
            // Full candidates remain best-effort after a compact marker or
            // external terminal anchor has made the unsafe decision durable.
            Interlocked.Increment(ref _persistenceFailures);
        }

        if (!markerDurable && !anchorDurable)
        {
            return anchorFailure ??
                   MembershipProjectionApplyResult.Rejected(
                       MembershipProjectionCode.PersistenceFailure);
        }

        return anchorFailure;
    }

    private bool CheckTerminalJournalNoLock()
    {
        byte[]? bytes;
        try
        {
            bytes = _persistence.ReadTerminalJournal(_options.MaximumStateBytes);
        }
        catch (Exception exception) when (IsRecoverableBackendException(exception))
        {
            _unsafeLatch = true;
            Interlocked.Increment(ref _persistenceFailures);
            return true;
        }

        if (bytes is null)
        {
            return false;
        }

        _unsafeLatch = true;
        try
        {
            var journal = JsonSerializer.Deserialize<PersistedTerminalUnsafeJournal>(
                              bytes,
                              MembershipProjectionJson.Options)
                          ?? throw new InvalidDataException();
            if (!string.Equals(
                    journal.Schema,
                    PersistedTerminalUnsafeJournal.CurrentSchema,
                    StringComparison.Ordinal) ||
                string.IsNullOrWhiteSpace(journal.Domain) ||
                journal.Sequence == 0 ||
                journal.EvidenceSha256.Length != MembershipLimits.HashLength * 2 ||
                !journal.EvidenceSha256.All(Uri.IsHexDigit))
            {
                throw new InvalidDataException();
            }
        }
        catch (Exception exception) when (IsPersistedStateValidationException(exception))
        {
            // Any present but malformed terminal marker is still terminal unsafe.
        }

        return true;
    }

    private MembershipProjectionApplyResult? CheckStatefulIngress(int length)
    {
        var gate = CheckIngress(length);
        if (gate is not null)
        {
            return gate;
        }

        if (_loadDeferred ||
            _preparedTransitionPresent ||
            _anchorTransient ||
            _continuityBusy)
        {
            LoadState();
        }

        if (_continuityBusy)
        {
            return MembershipProjectionApplyResult.Rejected(
                MembershipProjectionCode.ContinuityBusy);
        }

        if (_unsafeLatch)
        {
            return MembershipProjectionApplyResult.Rejected(
                MembershipProjectionCode.ForkDetected);
        }

        if (_monotonicConflict)
        {
            return MembershipProjectionApplyResult.Rejected(
                MembershipProjectionCode.MonotonicConflict);
        }

        if (_anchorTransient)
        {
            return MembershipProjectionApplyResult.Rejected(
                MembershipProjectionCode.MonotonicAnchorTransient);
        }

        return _state is null
            ? Count(Rejection(MembershipProjectionCode.StateUnavailable))
            : null;
    }

    private MembershipProjectionApplyResult? CheckIngress(int length)
    {
        if (!_options.Enabled)
        {
            return MembershipProjectionApplyResult.Rejected(MembershipProjectionCode.Disabled);
        }

        if (!_artifactVerifier.IsAvailable)
        {
            Interlocked.Increment(ref _verifierUnavailable);
            return MembershipProjectionApplyResult.Rejected(
                MembershipProjectionCode.VerifierUnavailable);
        }

        if (!_monotonicBoundary.IsAvailable)
        {
            return MembershipProjectionApplyResult.Rejected(
                MembershipProjectionCode.MonotonicAnchorUnavailable);
        }

        if (_configurationInvalid ||
            length is <= 0 ||
            length > _options.MaximumArtifactBytes)
        {
            return Count(Rejection(MembershipProjectionCode.InvalidLength));
        }

        if (!string.Equals(
                _options.ContractIdentifier,
                MembershipContractVersion.Identifier,
                StringComparison.Ordinal) ||
            !string.Equals(_options.PackageVersion, "0.3.0-p04.b887fa0", StringComparison.Ordinal))
        {
            return Count(Rejection(MembershipProjectionCode.InvalidArtifact));
        }

        return null;
    }

    private bool HasValidConfiguredLimits() =>
        _options.MaximumArtifactBytes is > 0 and <= HardMaximumArtifactBytes &&
        _options.MaximumStateBytes is > 0 and <= HardMaximumStateBytes;

    private MembershipProjectionApplyResult WithContinuityLease(
        Func<MembershipProjectionApplyResult> action)
    {
        if (!_options.Enabled)
        {
            return MembershipProjectionApplyResult.Rejected(MembershipProjectionCode.Disabled);
        }

        if (!_artifactVerifier.IsAvailable)
        {
            Interlocked.Increment(ref _verifierUnavailable);
            return MembershipProjectionApplyResult.Rejected(
                MembershipProjectionCode.VerifierUnavailable);
        }

        if (!_monotonicBoundary.IsAvailable)
        {
            return MembershipProjectionApplyResult.Rejected(
                MembershipProjectionCode.MonotonicAnchorUnavailable);
        }

        if (_configurationInvalid)
        {
            return MembershipProjectionApplyResult.Rejected(
                MembershipProjectionCode.InvalidLength);
        }

        if (_monotonicConflict)
        {
            return MembershipProjectionApplyResult.Rejected(
                MembershipProjectionCode.MonotonicConflict);
        }

        if (_unsafeLatch)
        {
            return MembershipProjectionApplyResult.Rejected(
                MembershipProjectionCode.ForkDetected);
        }

        if (_loadDeferred ||
            _preparedTransitionPresent ||
            _anchorTransient ||
            _continuityBusy)
        {
            LoadState();
            if (_unsafeLatch)
            {
                return MembershipProjectionApplyResult.Rejected(
                    MembershipProjectionCode.ForkDetected);
            }

            if (_continuityBusy)
            {
                return MembershipProjectionApplyResult.Rejected(
                    MembershipProjectionCode.ContinuityBusy);
            }

            if (_anchorTransient || _loadDeferred || _preparedTransitionPresent)
            {
                return MembershipProjectionApplyResult.Rejected(
                    MembershipProjectionCode.MonotonicAnchorTransient);
            }
        }

        try
        {
            using var lease = AcquireContinuityLeaseWithRetry();
            if (CheckTerminalJournalNoLock())
            {
                return MembershipProjectionApplyResult.Rejected(
                    MembershipProjectionCode.ForkDetected);
            }

            if (!ValidateContinuityNoLock())
            {
                MarkMonotonicConflict();
                return MembershipProjectionApplyResult.Rejected(
                    MembershipProjectionCode.MonotonicConflict);
            }

            if (_unsafeLatch)
            {
                return MembershipProjectionApplyResult.Rejected(
                    MembershipProjectionCode.ForkDetected);
            }

            return action();
        }
        catch (MembershipProjectionLeaseBusyException)
        {
            MarkContinuityBusy();
            return MembershipProjectionApplyResult.Rejected(
                MembershipProjectionCode.ContinuityBusy);
        }
        catch (MembershipProjectionAnchorTransientException)
        {
            MarkAnchorTransient();
            return MembershipProjectionApplyResult.Rejected(
                MembershipProjectionCode.MonotonicAnchorTransient);
        }
        catch (MonotonicAnchorUnavailableException)
        {
            return MembershipProjectionApplyResult.Rejected(
                MembershipProjectionCode.MonotonicAnchorUnavailable);
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            MarkMonotonicConflict();
            return MembershipProjectionApplyResult.Rejected(
                MembershipProjectionCode.MonotonicConflict);
        }
    }

    private bool ValidateContinuityNoLock()
    {
        if (CheckTerminalJournalNoLock())
        {
            return true;
        }

        var anchor = ReadAnchorWithRetry();
        var bytes = _persistence.Read(_options.MaximumStateBytes);
        if (anchor.TerminalUnsafe)
        {
            _unsafeLatch = true;
        }

        if (_state is null)
        {
            var isEmpty = bytes is null && IsEmptyAnchor(anchor);
            if (isEmpty)
            {
                _corruptStatePresent = false;
            }

            return isEmpty;
        }

        if (bytes is null)
        {
            return false;
        }

        var stateHash = Sha256Hex(bytes);
        return _state.Generation == anchor.Generation &&
               string.Equals(
                   stateHash,
                   anchor.StateSha256,
                   StringComparison.Ordinal) &&
               string.Equals(
                   stateHash,
                   _persistedStateSha256,
                   StringComparison.Ordinal);
    }

    private IDisposable AcquireContinuityLeaseWithRetry()
    {
        MembershipProjectionLeaseBusyException? last = null;
        for (var attempt = 0; attempt < TransientRetryLimit; attempt++)
        {
            try
            {
                var lease = _persistence.AcquireExclusiveLease();
                _continuityBusy = false;
                return lease;
            }
            catch (MembershipProjectionLeaseBusyException exception)
            {
                last = exception;
                Thread.Yield();
            }
        }

        throw last ?? new MembershipProjectionLeaseBusyException(
            "The membership projection continuity lease is busy.",
            new IOException());
    }

    private MembershipProjectionAnchor ReadAnchorWithRetry()
    {
        MembershipProjectionAnchorTransientException? last = null;
        for (var attempt = 0; attempt < TransientRetryLimit; attempt++)
        {
            try
            {
                var anchor = _monotonicBoundary.Required.Read();
                _anchorTransient = false;
                return anchor;
            }
            catch (MembershipProjectionAnchorTransientException exception)
            {
                last = exception;
                Thread.Yield();
            }
            catch (Exception exception) when (IsRecoverableBackendException(exception))
            {
                last = new MembershipProjectionAnchorTransientException(
                    "The external monotonic anchor is temporarily unavailable.",
                    exception);
                Thread.Yield();
            }
        }

        throw last ?? new MembershipProjectionAnchorTransientException(
            "The external monotonic anchor is temporarily unavailable.");
    }

    private bool CommitAnchorWithReconciliation(
        MembershipProjectionAnchor expected,
        MembershipProjectionAnchor next)
    {
        MembershipProjectionAnchorTransientException? last = null;
        for (var attempt = 0; attempt < TransientRetryLimit; attempt++)
        {
            try
            {
                var exchanged = _monotonicBoundary.Required.CompareExchange(
                    expected,
                    next);
                var observed = ReadAnchorWithRetry();
                if (observed == next)
                {
                    _anchorTransient = false;
                    return true;
                }

                if (observed != expected)
                {
                    return false;
                }

                if (exchanged)
                {
                    return false;
                }
            }
            catch (MembershipProjectionAnchorTransientException exception)
            {
                last = exception;
                var observed = ReadAnchorWithRetry();
                if (observed == next)
                {
                    _anchorTransient = false;
                    return true;
                }

                if (observed != expected)
                {
                    return false;
                }
            }
            catch (Exception exception) when (IsRecoverableBackendException(exception))
            {
                last = new MembershipProjectionAnchorTransientException(
                    "The external monotonic anchor compare/exchange is temporarily unavailable.",
                    exception);
                var observed = ReadAnchorWithRetry();
                if (observed == next)
                {
                    _anchorTransient = false;
                    return true;
                }

                if (observed != expected)
                {
                    return false;
                }
            }

            Thread.Yield();
        }

        throw last ?? new MembershipProjectionAnchorTransientException(
            "The external monotonic anchor did not commit the prepared generation.");
    }

    private static bool IsEmptyAnchor(MembershipProjectionAnchor anchor) =>
        anchor.Generation == 0 &&
        string.IsNullOrEmpty(anchor.StateSha256) &&
        !anchor.TerminalUnsafe &&
        string.IsNullOrEmpty(anchor.UnsafeEvidenceSha256);

    private MembershipProjectionApplyResult Persist(
        PersistedMembershipProjection next,
        MembershipProjectionCode successCode = MembershipProjectionCode.Accepted)
    {
        try
        {
            var expectedAnchor = ReadAnchorWithRetry();
            if ((_state is null && expectedAnchor.Generation != 0) ||
                (_state is not null && expectedAnchor.Generation != _state.Generation) ||
                expectedAnchor.Generation == long.MaxValue)
            {
                MarkMonotonicConflict();
                return MembershipProjectionApplyResult.Rejected(
                    MembershipProjectionCode.MonotonicConflict);
            }

            next = next with { Generation = expectedAnchor.Generation + 1 };
            var bytes = JsonSerializer.SerializeToUtf8Bytes(next, MembershipProjectionJson.Options);
            if (bytes.Length > _options.MaximumStateBytes)
            {
                return Count(Rejection(MembershipProjectionCode.InvalidLength));
            }

            var stateHash = Sha256Hex(bytes);
            var nextAnchor = new MembershipProjectionAnchor(
                next.Generation,
                stateHash,
                expectedAnchor.TerminalUnsafe,
                expectedAnchor.UnsafeEvidenceSha256);
            var preparedBytes = JsonSerializer.SerializeToUtf8Bytes(
                new PersistedPreparedTransition
                {
                    ExpectedAnchor = expectedAnchor,
                    NextAnchor = nextAnchor
                },
                MembershipProjectionJson.Options);
            if (preparedBytes.Length > _options.MaximumStateBytes)
            {
                return Count(Rejection(MembershipProjectionCode.InvalidLength));
            }

            _persistence.WritePreparedTransition(preparedBytes);
            _preparedTransitionPresent = true;
            _persistence.Write(bytes);
            if (!CommitAnchorWithReconciliation(expectedAnchor, nextAnchor))
            {
                MarkMonotonicConflict();
                return MembershipProjectionApplyResult.Rejected(
                    MembershipProjectionCode.MonotonicConflict);
            }

            _persistence.ClearPreparedTransition();
            _preparedTransitionPresent = false;
            _state = next;
            _persistedStateSha256 = stateHash;
            _corruptStatePresent = false;
            _loadDeferred = false;
            _continuityBusy = false;
            _anchorTransient = false;
            return successCode == MembershipProjectionCode.Accepted
                ? Count(MembershipProjectionApplyResult.Accepted())
                : new MembershipProjectionApplyResult(true, successCode);
        }
        catch (MembershipProjectionAnchorTransientException)
        {
            MarkAnchorTransient();
            _loadDeferred = true;
            return MembershipProjectionApplyResult.Rejected(
                MembershipProjectionCode.MonotonicAnchorTransient);
        }
        catch
        {
            if (_preparedTransitionPresent)
            {
                _loadDeferred = true;
            }

            Interlocked.Increment(ref _persistenceFailures);
            return MembershipProjectionApplyResult.Rejected(
                MembershipProjectionCode.PersistenceFailure);
        }
    }

    private void LoadState()
    {
        _loadDeferred = false;
        try
        {
            using var lease = AcquireContinuityLeaseWithRetry();
            if (CheckTerminalJournalNoLock())
            {
                return;
            }

            var anchor = ReadAnchorWithRetry();
            if (anchor.TerminalUnsafe)
            {
                _unsafeLatch = true;
                return;
            }

            byte[]? bytes;
            try
            {
                bytes = _persistence.Read(_options.MaximumStateBytes);
            }
            catch (InvalidDataException)
            {
                QuarantineCorruptState();
                return;
            }

            PersistedPreparedTransition? prepared;
            try
            {
                var preparedBytes = _persistence.ReadPreparedTransition(
                    _options.MaximumStateBytes);
                prepared = preparedBytes is null
                    ? null
                    : DecodePreparedTransition(preparedBytes);
                _preparedTransitionPresent = prepared is not null;
            }
            catch (Exception exception) when (
                exception is InvalidDataException or JsonException or FormatException)
            {
                _preparedTransitionPresent = true;
                MarkMonotonicConflict();
                return;
            }

            if (bytes is null)
            {
                if (prepared is not null)
                {
                    if (anchor == prepared.ExpectedAnchor &&
                        IsEmptyAnchor(prepared.ExpectedAnchor))
                    {
                        _persistence.ClearPreparedTransition();
                        _preparedTransitionPresent = false;
                    }
                    else
                    {
                        MarkMonotonicConflict();
                        return;
                    }
                }

                if (!IsEmptyAnchor(anchor) && !anchor.TerminalUnsafe)
                {
                    MarkMonotonicConflict();
                }

                return;
            }

            PersistedMembershipProjection state;
            try
            {
                state = JsonSerializer.Deserialize<PersistedMembershipProjection>(
                            bytes,
                            MembershipProjectionJson.Options)
                        ?? throw new InvalidDataException();
                ValidatePersistedState(state);
            }
            catch (Exception exception) when (IsPersistedStateValidationException(exception))
            {
                QuarantineCorruptState();
                return;
            }

            var stateHash = Sha256Hex(bytes);
            if (prepared is not null)
            {
                var matchesExpected =
                    state.Generation == prepared.ExpectedAnchor.Generation &&
                    string.Equals(
                        stateHash,
                        prepared.ExpectedAnchor.StateSha256,
                        StringComparison.Ordinal);
                var matchesNext =
                    state.Generation == prepared.NextAnchor.Generation &&
                    string.Equals(
                        stateHash,
                        prepared.NextAnchor.StateSha256,
                        StringComparison.Ordinal);

                if (matchesExpected && anchor == prepared.ExpectedAnchor)
                {
                    _persistence.ClearPreparedTransition();
                    _preparedTransitionPresent = false;
                }
                else if (matchesNext)
                {
                    if (anchor == prepared.ExpectedAnchor)
                    {
                        if (!CommitAnchorWithReconciliation(
                                prepared.ExpectedAnchor,
                                prepared.NextAnchor))
                        {
                            MarkMonotonicConflict();
                            return;
                        }

                        anchor = prepared.NextAnchor;
                    }
                    else if (anchor != prepared.NextAnchor)
                    {
                        MarkMonotonicConflict();
                        return;
                    }

                    _persistence.ClearPreparedTransition();
                    _preparedTransitionPresent = false;
                }
                else
                {
                    MarkMonotonicConflict();
                    return;
                }
            }

            if (state.Generation != anchor.Generation ||
                !string.Equals(
                    stateHash,
                    anchor.StateSha256,
                    StringComparison.Ordinal))
            {
                MarkMonotonicConflict();
                return;
            }

            _state = state;
            _persistedStateSha256 = stateHash;
            _unsafeLatch =
                anchor.TerminalUnsafe ||
                state.ForkDetected ||
                state.ForkRecords.Count > 0;
            _corruptStatePresent = false;
            _continuityBusy = false;
            _anchorTransient = false;
        }
        catch (MonotonicAnchorUnavailableException)
        {
            // Constructor already guards this path; retain a fail-closed fallback.
        }
        catch (MembershipProjectionLeaseBusyException)
        {
            MarkContinuityBusy();
            _loadDeferred = true;
        }
        catch (MembershipProjectionAnchorTransientException)
        {
            MarkAnchorTransient();
            _loadDeferred = true;
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException)
        {
            MarkMonotonicConflict();
        }
    }

    private static PersistedPreparedTransition DecodePreparedTransition(
        ReadOnlySpan<byte> bytes)
    {
        var prepared = JsonSerializer.Deserialize<PersistedPreparedTransition>(
                           bytes,
                           MembershipProjectionJson.Options)
                       ?? throw new InvalidDataException();
        if (!string.Equals(
                prepared.Schema,
                PersistedPreparedTransition.CurrentSchema,
                StringComparison.Ordinal) ||
            prepared.ExpectedAnchor is null ||
            prepared.NextAnchor is null ||
            prepared.ExpectedAnchor.Generation < 0 ||
            prepared.ExpectedAnchor.Generation == long.MaxValue ||
            prepared.NextAnchor.Generation != prepared.ExpectedAnchor.Generation + 1 ||
            string.IsNullOrWhiteSpace(prepared.NextAnchor.StateSha256) ||
            prepared.NextAnchor.StateSha256.Length != MembershipLimits.HashLength * 2 ||
            !prepared.NextAnchor.StateSha256.All(Uri.IsHexDigit) ||
            prepared.NextAnchor.TerminalUnsafe !=
            prepared.ExpectedAnchor.TerminalUnsafe ||
            !string.Equals(
                prepared.NextAnchor.UnsafeEvidenceSha256,
                prepared.ExpectedAnchor.UnsafeEvidenceSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException();
        }

        if (prepared.ExpectedAnchor.Generation == 0)
        {
            if (!IsEmptyAnchor(prepared.ExpectedAnchor))
            {
                throw new InvalidDataException();
            }
        }
        else if (prepared.ExpectedAnchor.StateSha256.Length !=
                 MembershipLimits.HashLength * 2 ||
                 !prepared.ExpectedAnchor.StateSha256.All(Uri.IsHexDigit))
        {
            throw new InvalidDataException();
        }

        return prepared;
    }

    private void QuarantineCorruptState()
    {
        try
        {
            _persistence.Quarantine();
        }
        catch
        {
            // Fail closed even if the best-effort quarantine rename fails.
        }

        Interlocked.Increment(ref _corruptStateRecoveries);
        _state = null;
        _persistedStateSha256 = "";
        _corruptStatePresent = true;
        _loadDeferred = false;
    }

    private static bool IsPersistedStateValidationException(Exception exception) =>
        exception is InvalidDataException or
            FormatException or
            JsonException or
            MembershipContractException or
            OverflowException or
            ArgumentException or
            NullReferenceException;

    private void ValidatePersistedState(PersistedMembershipProjection state)
    {
        if (!string.Equals(state.Schema, StateSchema, StringComparison.Ordinal) ||
            !string.Equals(
                state.ContractIdentifier,
                MembershipContractVersion.Identifier,
                StringComparison.Ordinal) ||
            !string.Equals(state.PackageVersion, "0.3.0-p04.b887fa0", StringComparison.Ordinal))
        {
            throw new InvalidDataException();
        }

        var genesisBytes = DecodeRequiredBase64(state.GenesisBytesBase64);
        var signatures = state.GenesisSignatures.Select(ToSignature).ToArray();
        var genesis = MembershipContractVerifier.ImportSelfHostedGenesis(
            genesisBytes,
            DecodeFixedHex(_options.ExpectedNetworkIdHex, MembershipLimits.NetworkIdLength),
            DecodeFixedHex(_options.ExpectedGenesisSha256Hex, MembershipLimits.HashLength),
            signatures,
            _artifactVerifier.Required);
        ValidateTimestampBounds(genesis.IssuedAtUnixSeconds);
        var genesisHash = MembershipContractHash.Sha256(genesisBytes);
        if (!string.Equals(
                state.NetworkIdHex,
                Convert.ToHexString(genesis.NetworkId.Span).ToLowerInvariant(),
                StringComparison.Ordinal) ||
            !string.Equals(
                state.GenesisSha256,
                Convert.ToHexString(genesisHash).ToLowerInvariant(),
                StringComparison.Ordinal))
        {
            throw new InvalidDataException();
        }

        ValidateLkg(state.AuthorityLkg, genesis);
        ValidateLkg(state.AuthorityPredecessorLkg, genesis);
        ValidateDomain(state.Bridge, genesis);
        ValidateDomain(state.Membership, genesis);
        var genesisAnchor = new MembershipLastKnownGood
        {
            NetworkId = genesis.NetworkId.ToArray(),
            PolicyVersion = genesis.PolicyVersion,
            Sequence = genesis.GenesisSequence,
            CanonicalHash = genesisHash
        };

        byte[]? activeBytes = null;
        if (!string.IsNullOrWhiteSpace(state.ActiveDelegationBase64))
        {
            activeBytes = DecodeRequiredBase64(state.ActiveDelegationBase64);
            var active = MembershipContractCodec.DecodeSignedDelegation(
                activeBytes);
            ValidateTimestampBounds(
                active.IssuedAtUnixSeconds,
                active.ValidFromUnixSeconds,
                active.ValidUntilUnixSeconds);
        }

        if (!string.IsNullOrWhiteSpace(state.AuthorityEnvelopeBase64))
        {
            var authorityTime = AuthorityVerificationTime(state);
            if (state.AuthorityEnvelopeKind == "delegation")
            {
                var authorityBytes = DecodeRequiredBase64(state.AuthorityEnvelopeBase64);
                var delegation = MembershipContractCodec.DecodeSignedDelegation(authorityBytes);
                ValidateTimestampBounds(
                    delegation.IssuedAtUnixSeconds,
                    delegation.ValidFromUnixSeconds,
                    delegation.ValidUntilUnixSeconds);
                var verified = MembershipContractVerifier.VerifyDelegation(
                    delegation,
                    genesis,
                    ToLkg(state.AuthorityPredecessorLkg),
                    authorityTime,
                    _options.AllowedClockSkewSeconds,
                    _options.ClientProtocol,
                    _artifactVerifier.Required);
                RequireSameLkg(verified.NextAuthorityLastKnownGood, state.AuthorityLkg);
                if (activeBytes is null ||
                    !authorityBytes.AsSpan().SequenceEqual(activeBytes))
                {
                    throw new InvalidDataException();
                }
            }
            else if (state.AuthorityEnvelopeKind == "revocation")
            {
                var revocation = MembershipContractCodec.DecodeSignedRevocation(
                    DecodeRequiredBase64(state.AuthorityEnvelopeBase64));
                ValidateTimestampBounds(
                    revocation.IssuedAtUnixSeconds,
                    revocation.ValidFromUnixSeconds,
                    revocation.ValidUntilUnixSeconds);
                var verified = MembershipContractVerifier.VerifyRevocation(
                    revocation,
                    genesis,
                    ToLkg(state.AuthorityPredecessorLkg),
                    authorityTime,
                    _options.AllowedClockSkewSeconds,
                    _options.ClientProtocol,
                    _artifactVerifier.Required);
                RequireSameLkg(verified.NextAuthorityLastKnownGood, state.AuthorityLkg);
                var revokedHash = Convert.ToHexString(
                        revocation.DelegationHash.Span)
                    .ToLowerInvariant();
                if (activeBytes is not null ||
                    !state.RevokedDelegationHashes.Contains(
                        revokedHash,
                        StringComparer.Ordinal))
                {
                    throw new InvalidDataException();
                }
            }
            else
            {
                throw new InvalidDataException();
            }
        }
        else
        {
            if (activeBytes is not null)
            {
                throw new InvalidDataException();
            }

            RequireSameLkg(genesisAnchor, state.AuthorityLkg);
            RequireSameLkg(genesisAnchor, state.AuthorityPredecessorLkg);
        }

        if (!HasEnvelope(state.Bridge))
        {
            RequireSameLkg(genesisAnchor, state.Bridge.Lkg);
            RequireSameLkg(genesisAnchor, state.Bridge.PredecessorLkg);
        }

        if (!HasEnvelope(state.Membership))
        {
            RequireSameLkg(genesisAnchor, state.Membership.Lkg);
            RequireSameLkg(genesisAnchor, state.Membership.PredecessorLkg);
        }

        if (state.Generation <= 0 ||
            state.ForkRecords.Count > 16 ||
            state.RevokedDelegationHashes.Count >
            MembershipLimits.MaximumRevokedDelegationHashes)
        {
            throw new InvalidDataException();
        }

        foreach (var revokedHash in state.RevokedDelegationHashes)
        {
            _ = DecodeFixedHex(revokedHash, MembershipLimits.HashLength);
        }

        ValidatePersistedContent(state.Bridge, true, genesis);
        ValidatePersistedContent(state.Membership, false, genesis);
        ValidateForkRecords(state);
    }

    private void ValidatePersistedContent(
        PersistedContentDomain domain,
        bool isBridge,
        NetworkGenesis genesis)
    {
        if (!HasEnvelope(domain))
        {
            return;
        }

        var bytes = DecodeRequiredBase64(domain.EnvelopeBase64);
        var bridge = isBridge
            ? MembershipContractCodec.DecodeSignedBridge(bytes)
            : null;
        var membership = isBridge
            ? null
            : MembershipContractCodec.DecodeSignedMembership(bytes);
        var signedValidFrom = isBridge
            ? bridge!.Statement.ValidFromUnixSeconds
            : membership!.Statement.ValidFromUnixSeconds;
        var signedValidUntil = isBridge
            ? bridge!.Statement.ValidUntilUnixSeconds
            : membership!.Statement.ValidUntilUnixSeconds;
        var issuedAt = isBridge
            ? bridge!.Statement.IssuedAtUnixSeconds
            : membership!.Statement.IssuedAtUnixSeconds;
        ValidateTimestampBounds(issuedAt, signedValidFrom, signedValidUntil);
        if (signedValidUntil != checked((ulong)domain.ValidUntilUnixSeconds))
        {
            throw new InvalidDataException();
        }

        var acceptedDelegationBytes = DecodeRequiredBase64(
            domain.AcceptedDelegationBase64);
        var acceptedDelegation = MembershipContractCodec.DecodeSignedDelegation(
            acceptedDelegationBytes);
        ValidateTimestampBounds(
            acceptedDelegation.IssuedAtUnixSeconds,
            acceptedDelegation.ValidFromUnixSeconds,
            acceptedDelegation.ValidUntilUnixSeconds);
        ValidateLkg(domain.AcceptedAuthorityLkg, genesis);
        ValidateAcceptedDelegation(
            acceptedDelegation,
            domain.AcceptedAuthorityLkg,
            genesis);
        var context = new MembershipVerificationContext
        {
            Genesis = genesis,
            ActiveDelegation = acceptedDelegation,
            AuthorityLastKnownGood = ToLkg(domain.AcceptedAuthorityLkg),
            RevokedDelegationHashes = [],
            LastKnownGood = ToLkg(domain.PredecessorLkg),
            VerificationTimeUnixSeconds = signedValidFrom,
            AllowedClockSkewSeconds = _options.AllowedClockSkewSeconds,
            ClientProtocol = _options.ClientProtocol
        };

        MembershipLastKnownGood actual;
        if (isBridge)
        {
            actual = MembershipContractVerifier.VerifyBridge(
                bridge!,
                context,
                _artifactVerifier.Required).NextLastKnownGood;
        }
        else
        {
            actual = MembershipContractVerifier.VerifyMembership(
                membership!,
                context,
                _artifactVerifier.Required).NextLastKnownGood;
        }

        RequireSameLkg(actual, domain.Lkg);
    }

    private void ValidateAcceptedDelegation(
        SignerDelegation delegation,
        PersistedLastKnownGood acceptedAuthority,
        NetworkGenesis genesis)
    {
        if (delegation.Sequence == 0)
        {
            throw new InvalidDataException();
        }

        var predecessor = new MembershipLastKnownGood
        {
            NetworkId = delegation.NetworkId.ToArray(),
            PolicyVersion = delegation.PolicyVersion,
            Sequence = delegation.Sequence - 1,
            CanonicalHash = delegation.PreviousHash.ToArray()
        };
        var verified = MembershipContractVerifier.VerifyDelegation(
            delegation,
            genesis,
            predecessor,
            delegation.ValidFromUnixSeconds,
            _options.AllowedClockSkewSeconds,
            _options.ClientProtocol,
            _artifactVerifier.Required);
        RequireSameLkg(verified.NextAuthorityLastKnownGood, acceptedAuthority);
    }

    private MembershipVerificationContext BuildContext(
        PersistedMembershipProjection state,
        PersistedLastKnownGood lastKnownGood,
        ulong verificationTime)
    {
        var delegationBytes = DecodeRequiredBase64(state.ActiveDelegationBase64);
        return new MembershipVerificationContext
        {
            Genesis = DecodeGenesis(state),
            ActiveDelegation = MembershipContractCodec.DecodeSignedDelegation(delegationBytes),
            AuthorityLastKnownGood = ToLkg(state.AuthorityLkg),
            RevokedDelegationHashes = state.RevokedDelegationHashes
                .Select(value => (ReadOnlyMemory<byte>)DecodeFixedHex(
                    value,
                    MembershipLimits.HashLength))
                .ToArray(),
            LastKnownGood = ToLkg(lastKnownGood),
            VerificationTimeUnixSeconds = verificationTime,
            AllowedClockSkewSeconds = _options.AllowedClockSkewSeconds,
            ClientProtocol = _options.ClientProtocol
        };
    }

    private MembershipVerificationContext BuildAcceptedContentContext(
        PersistedMembershipProjection state,
        PersistedContentDomain domain,
        PersistedLastKnownGood lastKnownGood,
        ulong verificationTime)
    {
        var delegationBytes = DecodeRequiredBase64(domain.AcceptedDelegationBase64);
        return new MembershipVerificationContext
        {
            Genesis = DecodeGenesis(state),
            ActiveDelegation = MembershipContractCodec.DecodeSignedDelegation(delegationBytes),
            AuthorityLastKnownGood = ToLkg(domain.AcceptedAuthorityLkg),
            RevokedDelegationHashes = [],
            LastKnownGood = ToLkg(lastKnownGood),
            VerificationTimeUnixSeconds = verificationTime,
            AllowedClockSkewSeconds = _options.AllowedClockSkewSeconds,
            ClientProtocol = _options.ClientProtocol
        };
    }

    private void ValidateForkRecords(PersistedMembershipProjection state)
    {
        foreach (var record in state.ForkRecords)
        {
            if (record.Domain.StartsWith("authority-", StringComparison.Ordinal))
            {
                ValidateAuthorityForkRecord(state, record);
                continue;
            }

            var isBridge = string.Equals(record.Domain, "bridge", StringComparison.Ordinal);
            if (!isBridge &&
                !string.Equals(record.Domain, "membership", StringComparison.Ordinal))
            {
                throw new InvalidDataException();
            }

            var domain = isBridge ? state.Bridge : state.Membership;
            if (!HasEnvelope(domain) ||
                record.Sequence != domain.Lkg.Sequence ||
                !string.Equals(
                    record.PreviousHashHex,
                    domain.PredecessorLkg.CanonicalHashHex,
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException();
            }

            var firstEnvelope = DecodeRequiredBase64(record.FirstEnvelopeBase64);
            var secondEnvelope = DecodeRequiredBase64(record.SecondEnvelopeBase64);
            var firstCanonical = DecodeRequiredBase64(
                record.FirstCanonicalStatementBase64);
            var secondCanonical = DecodeRequiredBase64(
                record.SecondCanonicalStatementBase64);
            if (!string.Equals(
                    record.FirstHashHex,
                    Sha256Hex(firstCanonical),
                    StringComparison.Ordinal) ||
                !string.Equals(
                    record.SecondHashHex,
                    Sha256Hex(secondCanonical),
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException();
            }

            var context = BuildAcceptedContentContext(
                state,
                domain,
                domain.PredecessorLkg,
                AuthorityVerificationTimeForContent(domain, isBridge));
            if (isBridge)
            {
                var first = MembershipContractCodec.DecodeSignedBridge(firstEnvelope);
                var second = MembershipContractCodec.DecodeSignedBridge(secondEnvelope);
                if (!firstCanonical.AsSpan().SequenceEqual(
                        MembershipContractCodec.GetBridgeSigningBytes(first.Statement)) ||
                    !secondCanonical.AsSpan().SequenceEqual(
                        MembershipContractCodec.GetBridgeSigningBytes(second.Statement)))
                {
                    throw new InvalidDataException();
                }

                _ = MembershipContractVerifier.CreateBridgeForkEvidence(
                    first,
                    second,
                    context,
                    _artifactVerifier.Required);
            }
            else
            {
                var first = MembershipContractCodec.DecodeSignedMembership(firstEnvelope);
                var second = MembershipContractCodec.DecodeSignedMembership(secondEnvelope);
                if (!firstCanonical.AsSpan().SequenceEqual(
                        MembershipContractCodec.GetMembershipSigningBytes(first.Statement)) ||
                    !secondCanonical.AsSpan().SequenceEqual(
                        MembershipContractCodec.GetMembershipSigningBytes(second.Statement)))
                {
                    throw new InvalidDataException();
                }

                _ = MembershipContractVerifier.CreateForkEvidence(
                    first,
                    second,
                    context,
                    _artifactVerifier.Required);
            }
        }
    }

    private void ValidateAuthorityForkRecord(
        PersistedMembershipProjection state,
        PersistedForkRecord record)
    {
        if (record.Sequence != state.AuthorityLkg.Sequence ||
            !string.Equals(
                record.PreviousHashHex,
                state.AuthorityPredecessorLkg.CanonicalHashHex,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException();
        }

        var firstEnvelope = DecodeRequiredBase64(record.FirstEnvelopeBase64);
        var secondEnvelope = DecodeRequiredBase64(record.SecondEnvelopeBase64);
        var firstCanonical = DecodeRequiredBase64(record.FirstCanonicalStatementBase64);
        var secondCanonical = DecodeRequiredBase64(record.SecondCanonicalStatementBase64);
        if (!string.Equals(record.FirstHashHex, Sha256Hex(firstCanonical), StringComparison.Ordinal) ||
            !string.Equals(record.SecondHashHex, Sha256Hex(secondCanonical), StringComparison.Ordinal))
        {
            throw new InvalidDataException();
        }

        var genesis = DecodeGenesis(state);
        var predecessor = ToLkg(state.AuthorityPredecessorLkg);
        if (record.Domain == "authority-delegation")
        {
            var first = MembershipContractCodec.DecodeSignedDelegation(firstEnvelope);
            var second = MembershipContractCodec.DecodeSignedDelegation(secondEnvelope);
            if (!firstCanonical.AsSpan().SequenceEqual(
                    MembershipContractCodec.GetDelegationSigningBytes(first)) ||
                !secondCanonical.AsSpan().SequenceEqual(
                    MembershipContractCodec.GetDelegationSigningBytes(second)))
            {
                throw new InvalidDataException();
            }

            _ = MembershipContractVerifier.CreateDelegationForkEvidence(
                first,
                second,
                genesis,
                predecessor,
                first.ValidFromUnixSeconds,
                _options.AllowedClockSkewSeconds,
                _options.ClientProtocol,
                _artifactVerifier.Required);
        }
        else if (record.Domain == "authority-revocation")
        {
            var first = MembershipContractCodec.DecodeSignedRevocation(firstEnvelope);
            var second = MembershipContractCodec.DecodeSignedRevocation(secondEnvelope);
            if (!firstCanonical.AsSpan().SequenceEqual(
                    MembershipContractCodec.GetRevocationSigningBytes(first)) ||
                !secondCanonical.AsSpan().SequenceEqual(
                    MembershipContractCodec.GetRevocationSigningBytes(second)))
            {
                throw new InvalidDataException();
            }

            _ = MembershipContractVerifier.CreateRevocationForkEvidence(
                first,
                second,
                genesis,
                predecessor,
                first.ValidFromUnixSeconds,
                _options.AllowedClockSkewSeconds,
                _options.ClientProtocol,
                _artifactVerifier.Required);
        }
        else
        {
            throw new InvalidDataException();
        }
    }

    private bool IsReadyNoLock()
    {
        if (!_options.Enabled ||
            !_artifactVerifier.IsAvailable ||
            !_monotonicBoundary.IsAvailable ||
            _configurationInvalid ||
            _monotonicConflict ||
            _unsafeLatch ||
            _anchorTransient ||
            _continuityBusy ||
            _loadDeferred ||
            _preparedTransitionPresent ||
            _corruptStatePresent ||
            _state is null ||
            _state.ForkDetected ||
            string.IsNullOrWhiteSpace(_state.ActiveDelegationBase64) ||
            !HasEnvelope(_state.Bridge))
        {
            return false;
        }

        if (!SameLkg(_state.Bridge.AcceptedAuthorityLkg, _state.AuthorityLkg) ||
            !DecodeRequiredBase64(_state.Bridge.AcceptedDelegationBase64)
                .AsSpan()
                .SequenceEqual(DecodeRequiredBase64(_state.ActiveDelegationBase64)))
        {
            return false;
        }

        var now = _timeProvider.GetUtcNow().ToUnixTimeSeconds();
        var bridge = MembershipContractCodec.DecodeSignedBridge(
            DecodeRequiredBase64(_state.Bridge.EnvelopeBase64)).Statement;
        if (now < checked((long)bridge.ValidFromUnixSeconds) ||
            now > checked((long)bridge.ValidUntilUnixSeconds))
        {
            return false;
        }

        var delegation = MembershipContractCodec.DecodeSignedDelegation(
            DecodeRequiredBase64(_state.ActiveDelegationBase64));
        return now >= checked((long)delegation.ValidFromUnixSeconds) &&
               now <= checked((long)delegation.ValidUntilUnixSeconds);
    }

    private string StateCodeNoLock()
    {
        if (!_options.Enabled)
        {
            return "disabled";
        }

        if (!_artifactVerifier.IsAvailable)
        {
            return "verifier-unavailable";
        }

        if (!_monotonicBoundary.IsAvailable)
        {
            return "monotonic-anchor-unavailable";
        }

        if (_configurationInvalid)
        {
            return "invalid-configuration";
        }

        if (_unsafeLatch)
        {
            return "fork-detected";
        }

        if (_monotonicConflict)
        {
            return "monotonic-conflict";
        }

        if (_anchorTransient || _preparedTransitionPresent)
        {
            return "monotonic-anchor-transient";
        }

        if (_continuityBusy || _loadDeferred)
        {
            return "continuity-busy";
        }

        if (_corruptStatePresent)
        {
            return "corrupt-state";
        }

        if (_state is null)
        {
            return "state-unavailable";
        }

        if (_state.ForkDetected)
        {
            return "fork-detected";
        }

        if (!HasEnvelope(_state.Bridge))
        {
            return "bridge-unavailable";
        }

        if (string.IsNullOrWhiteSpace(_state.ActiveDelegationBase64) ||
            !SameLkg(_state.Bridge.AcceptedAuthorityLkg, _state.AuthorityLkg) ||
            !DecodeRequiredBase64(_state.Bridge.AcceptedDelegationBase64)
                .AsSpan()
                .SequenceEqual(DecodeRequiredBase64(_state.ActiveDelegationBase64)))
        {
            return "authority-transition";
        }

        return IsReadyNoLock() ? "current" : "stale";
    }

    private void MarkAnchorTransient()
    {
        _anchorTransient = true;
        Interlocked.Increment(ref _anchorTransientEvents);
    }

    private void MarkContinuityBusy()
    {
        _continuityBusy = true;
        Interlocked.Increment(ref _continuityBusyEvents);
    }

    private void MarkMonotonicConflict()
    {
        if (!_monotonicConflict)
        {
            Interlocked.Increment(ref _monotonicConflictEvents);
        }

        _monotonicConflict = true;
    }

    private MembershipProjectionApplyResult Count(MembershipProjectionApplyResult result)
    {
        if (result.Success)
        {
            if (result.Code == MembershipProjectionCode.Accepted)
            {
                Interlocked.Increment(ref _accepted);
            }
            else if (result.Code == MembershipProjectionCode.Idempotent)
            {
                Interlocked.Increment(ref _idempotent);
            }

            return result;
        }

        switch (result.Code)
        {
            case MembershipProjectionCode.InvalidArtifact:
            case MembershipProjectionCode.InvalidLength:
                Interlocked.Increment(ref _invalidArtifact);
                break;
            case MembershipProjectionCode.InvalidSignature:
            case MembershipProjectionCode.InvalidSigner:
                Interlocked.Increment(ref _invalidSigner);
                break;
            case MembershipProjectionCode.Rollback:
                Interlocked.Increment(ref _rollback);
                break;
            case MembershipProjectionCode.SequenceGap:
            case MembershipProjectionCode.SequenceOverflow:
                Interlocked.Increment(ref _sequenceGap);
                break;
            case MembershipProjectionCode.Expired:
            case MembershipProjectionCode.NotYetValid:
                Interlocked.Increment(ref _expired);
                break;
            case MembershipProjectionCode.ClockSkew:
                Interlocked.Increment(ref _clockSkew);
                break;
        }

        return result;
    }

    private static MembershipProjectionApplyResult Rejection(MembershipProjectionCode code) =>
        MembershipProjectionApplyResult.Rejected(code);

    private static bool IsRecoverableBackendException(Exception exception) =>
        exception is not (
            OperationCanceledException or
            OutOfMemoryException or
            StackOverflowException or
            AccessViolationException or
            AppDomainUnloadedException);

    private static MembershipProjectionCode MapException(Exception exception) =>
        exception switch
        {
            MembershipTimestampOutOfRangeException =>
                MembershipProjectionCode.TimestampOutOfRange,
            MembershipVerifierUnavailableException =>
                MembershipProjectionCode.VerifierUnavailable,
            OverflowException => MembershipProjectionCode.SequenceOverflow,
            FormatException => MembershipProjectionCode.InvalidArtifact,
            JsonException => MembershipProjectionCode.InvalidArtifact,
            MembershipContractException contract => contract.Error switch
            {
                MembershipContractError.InvalidLength => MembershipProjectionCode.InvalidLength,
                MembershipContractError.InvalidSignature => MembershipProjectionCode.InvalidSignature,
                MembershipContractError.UnknownSigner or
                    MembershipContractError.DuplicateSigner or
                    MembershipContractError.WrongSignerRole or
                    MembershipContractError.WrongSignatureDomain or
                    MembershipContractError.InsufficientQuorum =>
                    MembershipProjectionCode.InvalidSigner,
                MembershipContractError.NetworkMismatch or
                    MembershipContractError.AuthorityMismatch =>
                    MembershipProjectionCode.WrongNetwork,
                MembershipContractError.PolicyMismatch or
                    MembershipContractError.InvalidPolicy =>
                    MembershipProjectionCode.WrongPolicy,
                MembershipContractError.ProtocolMismatch =>
                    MembershipProjectionCode.WrongProtocol,
                MembershipContractError.InvalidSequence =>
                    MembershipProjectionCode.SequenceGap,
                MembershipContractError.PreviousHashMismatch =>
                    MembershipProjectionCode.Rollback,
                MembershipContractError.SequenceOverflow =>
                    MembershipProjectionCode.SequenceOverflow,
                MembershipContractError.ForkDetected or
                    MembershipContractError.NotForkEvidence =>
                    MembershipProjectionCode.ForkDetected,
                MembershipContractError.Expired => MembershipProjectionCode.Expired,
                MembershipContractError.NotYetValid => MembershipProjectionCode.NotYetValid,
                MembershipContractError.ClockSkewOutOfRange =>
                    MembershipProjectionCode.ClockSkew,
                MembershipContractError.RevokedDelegation =>
                    MembershipProjectionCode.RevokedDelegation,
                _ => MembershipProjectionCode.InvalidArtifact
            },
            _ => MembershipProjectionCode.InvalidArtifact
        };

    private static bool IsSameAuthorityEnvelope(
        PersistedMembershipProjection state,
        string kind,
        ReadOnlySpan<byte> bytes) =>
        string.Equals(state.AuthorityEnvelopeKind, kind, StringComparison.Ordinal) &&
        !string.IsNullOrWhiteSpace(state.AuthorityEnvelopeBase64) &&
        DecodeOptionalBase64(state.AuthorityEnvelopeBase64).AsSpan().SequenceEqual(bytes);

    private static bool HasEnvelope(PersistedContentDomain? domain) =>
        domain is not null && !string.IsNullOrWhiteSpace(domain.EnvelopeBase64);

    private static NetworkGenesis DecodeGenesis(PersistedMembershipProjection state) =>
        MembershipContractCodec.DecodeGenesis(DecodeRequiredBase64(state.GenesisBytesBase64));

    private static PersistedSignature ToPersistedSignature(MembershipSignature signature) =>
        new()
        {
            SignerIdHex = Convert.ToHexString(signature.SignerId.Span).ToLowerInvariant(),
            Domain = (byte)signature.Domain,
            SignatureBase64 = Convert.ToBase64String(signature.Signature.Span)
        };

    private static MembershipSignature ToSignature(PersistedSignature signature) =>
        new()
        {
            SignerId = DecodeFixedHex(signature.SignerIdHex, MembershipLimits.SignerIdLength),
            Domain = (MembershipSignatureDomain)signature.Domain,
            Signature = DecodeRequiredBase64(signature.SignatureBase64)
        };

    private static PersistedLastKnownGood ToPersistedLkg(MembershipLastKnownGood value) =>
        new()
        {
            NetworkIdHex = Convert.ToHexString(value.NetworkId.Span).ToLowerInvariant(),
            PolicyVersion = value.PolicyVersion,
            Sequence = value.Sequence,
            CanonicalHashHex = Convert.ToHexString(value.CanonicalHash.Span).ToLowerInvariant()
        };

    private static MembershipLastKnownGood ToLkg(PersistedLastKnownGood value) =>
        new()
        {
            NetworkId = DecodeFixedHex(value.NetworkIdHex, MembershipLimits.NetworkIdLength),
            PolicyVersion = value.PolicyVersion,
            Sequence = value.Sequence,
            CanonicalHash = DecodeFixedHex(value.CanonicalHashHex, MembershipLimits.HashLength)
        };

    private static void ValidateLkg(PersistedLastKnownGood value, NetworkGenesis genesis)
    {
        if (!string.Equals(
                value.NetworkIdHex,
                Convert.ToHexString(genesis.NetworkId.Span).ToLowerInvariant(),
                StringComparison.Ordinal) ||
            value.PolicyVersion != genesis.PolicyVersion ||
            value.Sequence == 0)
        {
            throw new InvalidDataException();
        }

        _ = DecodeFixedHex(value.CanonicalHashHex, MembershipLimits.HashLength);
    }

    private static void ValidateDomain(PersistedContentDomain domain, NetworkGenesis genesis)
    {
        ValidateLkg(domain.Lkg, genesis);
        ValidateLkg(domain.PredecessorLkg, genesis);
        ValidateLkg(domain.AcceptedAuthorityLkg, genesis);
    }

    private static bool SameLkg(
        PersistedLastKnownGood first,
        PersistedLastKnownGood second) =>
        first.Sequence == second.Sequence &&
        first.PolicyVersion == second.PolicyVersion &&
        string.Equals(first.NetworkIdHex, second.NetworkIdHex, StringComparison.Ordinal) &&
        string.Equals(
            first.CanonicalHashHex,
            second.CanonicalHashHex,
            StringComparison.Ordinal);

    private static void RequireSameLkg(
        MembershipLastKnownGood actual,
        PersistedLastKnownGood expected)
    {
        if (actual.Sequence != expected.Sequence ||
            actual.PolicyVersion != expected.PolicyVersion ||
            !actual.NetworkId.Span.SequenceEqual(
                DecodeFixedHex(expected.NetworkIdHex, MembershipLimits.NetworkIdLength)) ||
            !actual.CanonicalHash.Span.SequenceEqual(
                DecodeFixedHex(expected.CanonicalHashHex, MembershipLimits.HashLength)))
        {
            throw new InvalidDataException();
        }
    }

    private static ulong AuthorityVerificationTime(PersistedMembershipProjection state)
    {
        if (state.AuthorityEnvelopeKind == "delegation")
        {
            var delegation = MembershipContractCodec.DecodeSignedDelegation(
                DecodeRequiredBase64(state.AuthorityEnvelopeBase64));
            return delegation.ValidFromUnixSeconds;
        }

        var revocation = MembershipContractCodec.DecodeSignedRevocation(
            DecodeRequiredBase64(state.AuthorityEnvelopeBase64));
        return revocation.ValidFromUnixSeconds;
    }

    private static ulong AuthorityVerificationTimeForContent(
        PersistedContentDomain domain,
        bool isBridge)
    {
        var bytes = DecodeRequiredBase64(domain.EnvelopeBase64);
        return isBridge
            ? MembershipContractCodec.DecodeSignedBridge(bytes).Statement.ValidFromUnixSeconds
            : MembershipContractCodec.DecodeSignedMembership(bytes).Statement.ValidFromUnixSeconds;
    }

    private static void ValidateTimestampBounds(params ulong[] values)
    {
        if (values.Any(value => value > MaximumUnixSeconds))
        {
            throw new MembershipTimestampOutOfRangeException();
        }
    }

    private ulong NowUnixSeconds()
    {
        var value = _timeProvider.GetUtcNow().ToUnixTimeSeconds();
        return value < 0 ? 0UL : checked((ulong)value);
    }

    private static byte[] DecodeFixedHex(string value, int expectedBytes)
    {
        if (string.IsNullOrWhiteSpace(value) ||
            value.Length != expectedBytes * 2 ||
            !value.All(Uri.IsHexDigit))
        {
            throw new FormatException();
        }

        return Convert.FromHexString(value);
    }

    private static byte[] DecodeRequiredBase64(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new FormatException();
        }

        return Convert.FromBase64String(value);
    }

    private static byte[] DecodeOptionalBase64(string value) =>
        string.IsNullOrWhiteSpace(value) ? [] : Convert.FromBase64String(value);

    private static string Sha256Hex(ReadOnlySpan<byte> value) =>
        Convert.ToHexString(SHA256.HashData(value)).ToLowerInvariant();

    internal static string ResolveStatePath(MembershipProjectionOptions options) =>
        string.IsNullOrWhiteSpace(options.StatePath)
            ? Path.Combine(
                AppContext.BaseDirectory,
                "artifacts",
                "membership-projection-state.json")
            : options.StatePath;
}

internal sealed class MembershipTimestampOutOfRangeException : Exception;
