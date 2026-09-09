using System.Security.Cryptography;
using System.Buffers.Binary;
using System.Text;

#if DEEP_PROTOCOL_DIRECTORY_V1
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
#endif

namespace Deep.Registry.Api.DirectoryPublication;

internal sealed class ProductionDirectoryCanonicalPublicationVerifier : IDirectoryCanonicalPublicationVerifier
{
    private readonly DirectoryPublicationTrustAnchor trustAnchor;
    private readonly IDirectoryPublicationMonotonicClock monotonicClock;
    private readonly IDirectoryPublicationLiveChallengeAuthority challengeAuthority;
    private readonly IDirectoryPublicationProtectedNetworkLkgSource? protectedNetworkLkgSource;

    internal ProductionDirectoryCanonicalPublicationVerifier(
        DirectoryPublicationTrustAnchor trustAnchor,
        IDirectoryPublicationMonotonicClock monotonicClock,
        IDirectoryPublicationLiveChallengeAuthority challengeAuthority,
        IDirectoryPublicationProtectedNetworkLkgSource? protectedNetworkLkgSource = null)
    {
        this.trustAnchor = trustAnchor ?? throw new ArgumentNullException(nameof(trustAnchor));
        this.monotonicClock = monotonicClock ?? throw new ArgumentNullException(nameof(monotonicClock));
        this.challengeAuthority = challengeAuthority ?? throw new ArgumentNullException(nameof(challengeAuthority));
        this.protectedNetworkLkgSource = protectedNetworkLkgSource;
    }

    internal static bool HasRequiredProtocolSurface
    {
        get
        {
#if DEEP_PROTOCOL_DIRECTORY_V1
            return true;
#else
            return false;
#endif
        }
    }

    public async ValueTask<VerifiedDirectoryPublication> VerifyAsync(
        FrozenDirectoryPublicationCandidate candidate,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        cancellationToken.ThrowIfCancellationRequested();
#if !DEEP_PROTOCOL_DIRECTORY_V1
        await ValueTask.CompletedTask;
        throw Error(
            DirectoryCanonicalVerificationError.ProtocolSurfaceUnavailable,
            "The production Deep.Protocol pin does not yet export the DIRECTORY-01 verified producer surface.");
#else
        var closure = candidate.VerificationClosure;
        ValidateTerminalClosure(candidate, closure);

        VerifiedXPointNetworkAuthority authority;
        try
        {
            authority = XPointNetworkAuthorityVerifier.Verify(
                new XPointNetworkGenesisPin(
                    trustAnchor.NetworkId.Span,
                    trustAnchor.AuthorityCoreHash.Span),
                closure.AuthorityChain,
                closure.TimeSourcePolicyChain);
        }
        catch (XPointNetworkAuthorityVerificationException exception)
        {
            var error = StringComparer.Ordinal.Equals(exception.Code, "NetworkMismatch")
                ? DirectoryCanonicalVerificationError.WrongNetwork
                : DirectoryCanonicalVerificationError.AuthorityClosureInvalid;
            throw Error(error, "The exact XNA1/DTS1 authority lineage did not verify.", exception);
        }

        if (!Fixed(authority.NetworkId.Span, trustAnchor.NetworkId.Span))
        {
            throw Error(
                DirectoryCanonicalVerificationError.WrongNetwork,
                "The verified XNA1 authority belongs to another network.");
        }

        // Reject unauthenticated authority material before touching the durable
        // one-use challenge ledger. The ledger remains the sole source of the
        // nonce/window capability used by the public freshness producer.
        var challenge = await challengeAuthority.VerifyAndConsumeAsync(
            closure.CallerNonce,
            closure.MonotonicBootId,
            closure.NonceCreatedAtMonotonicSeconds,
            closure.ResponseReceivedAtMonotonicSeconds,
            closure.CurrentMonotonicSeconds,
            cancellationToken).ConfigureAwait(false);
        ValidateChallenge(closure, challenge);

        var now = await monotonicClock.ReadAsync(cancellationToken).ConfigureAwait(false);
        if (!Fixed(now.BootId.Span, challenge.BootId.Span) ||
            now.SampleSeconds < challenge.CurrentMonotonicSeconds)
        {
            throw Error(
                DirectoryCanonicalVerificationError.FreshnessClosureInvalid,
                "The consumed DTT1 challenge is outside the current protected monotonic boot/sample.");
        }

        VerifiedAccountDirectoryFreshness freshness;
        try
        {
            freshness = AccountDirectoryCurrentProofVerifier.Verify(
                authority,
                closure.ExactDirectoryHead,
                closure.ExactLiveTimeAttestation,
                closure.ExactDirectoryProof,
                challenge.Nonce.Span,
                closure.QueriedDirectoryLeafKey.Span,
                new AccountDirectoryMonotonicRequestWindow(
                    challenge.BootId.Span,
                    challenge.NonceCreatedAtMonotonicSeconds,
                    challenge.ResponseReceivedAtMonotonicSeconds,
                    challenge.CurrentMonotonicSeconds),
                protectedLkg: null,
                currentCheckpoint: null,
                closure.SupportedReader);
        }
        catch (AccountDirectoryFreshnessVerificationException exception)
        {
            var error = StringComparer.Ordinal.Equals(exception.Code, "NetworkMismatch")
                ? DirectoryCanonicalVerificationError.WrongNetwork
                : DirectoryCanonicalVerificationError.FreshnessClosureInvalid;
            throw Error(error, "The nonce-bound DTT1/ADH1/ADP1 freshness closure did not verify.", exception);
        }

        var trustedTime = new OnionTrustedTimeAuthority(new MonotonicClockAdapter(monotonicClock));
        VerifiedOnionNetworkContext network;
        VerifiedXPointNetworkForwardCheckpoint? forward = null;
        var hasReset = candidate.HasNetworkForwardReset;
        try
        {
            if (!hasReset)
            {
                network = await OnionNetworkContextVerifier.VerifyAsync(
                    authority,
                    freshness,
                    closure.NetworkPolicyChain,
                    closure.NetworkViewChain,
                    closure.NetworkViewHeadChain,
                    closure.ActiveNodeDescriptors,
                    closure.MailboxTopologyChain,
                    protectedPrevious: null,
                    trustedTime,
                    cancellationToken).ConfigureAwait(false);
            }
            else
            {
                if (protectedNetworkLkgSource is null)
                {
                    throw Error(
                        DirectoryCanonicalVerificationError.ProtectedNetworkLkgRequired,
                        "XNF1/NFP1 verification requires an independently protected prior network LKG source.");
                }

                var protectedValue = await protectedNetworkLkgSource.ReadAsync(
                    trustAnchor.NetworkId,
                    cancellationToken).ConfigureAwait(false);
                if (protectedValue is null)
                {
                    throw Error(
                        DirectoryCanonicalVerificationError.ProtectedNetworkLkgRequired,
                        "No protected prior network LKG is available for XNF1/NFP1 verification.");
                }

                var protectedLkg = ToProtocolLkg(protectedValue);
                forward = await XPointNetworkForwardCheckpointVerifier.VerifyAsync(
                    authority,
                    freshness,
                    protectedLkg,
                    closure.ResetAuthorityChain,
                    closure.NetworkForwardCheckpointChain,
                    candidate.NetworkForwardProof!.Value,
                    candidate.CurrentNetworkView,
                    candidate.CurrentNetworkViewHead,
                    trustedTime,
                    cancellationToken).ConfigureAwait(false);
                network = await OnionNetworkContextVerifier.VerifyFromForwardCheckpointAsync(
                    authority,
                    freshness,
                    forward,
                    closure.NetworkPolicyChain[^1],
                    closure.ActiveNodeDescriptors,
                    closure.MailboxTopologyChain[^1],
                    trustedTime,
                    cancellationToken).ConfigureAwait(false);
            }
        }
        catch (DirectoryCanonicalVerificationException)
        {
            throw;
        }
        catch (XPointNetworkForwardCheckpointVerificationException exception)
        {
            throw Error(
                DirectoryCanonicalVerificationError.ResetClosureInvalid,
                "The exact XNF1/NFP1 reset closure did not verify.",
                exception);
        }
        catch (OnionBoundaryException exception)
        {
            throw Error(
                hasReset
                    ? DirectoryCanonicalVerificationError.ResetClosureInvalid
                    : DirectoryCanonicalVerificationError.CurrentNetworkClosureInvalid,
                "The exact XVP1/XNV1/XNH1/XND1/PMT2 current network closure did not verify.",
                exception);
        }

        byte[] viewHash;
        byte[] headHash;
        byte[] pmtHash;
        XPointNetworkProtectedLkg lkg = null!;
        try
        {
            network.EnsureCurrent();
            lkg = network.ProtectedLkg ?? throw Error(
                DirectoryCanonicalVerificationError.CurrentNetworkClosureInvalid,
                "The Protocol producer returned no protected network LKG.");
            if (!Fixed(network.NetworkId.Span, trustAnchor.NetworkId.Span) ||
                !Fixed(lkg.NetworkId.Span, trustAnchor.NetworkId.Span))
            {
                throw Error(DirectoryCanonicalVerificationError.WrongNetwork,
                    "The verified current network context belongs to another network.");
            }

            viewHash = RequireCoreHash(lkg.ViewCoreReference.Span, "XNV1");
            headHash = RequireCoreHash(lkg.HeadCoreReference.Span, "XNH1");
            pmtHash = ContactCodec.Decode("PMT2", candidate.CurrentMailboxTopology.Span).CoreHash.ToArray();
        }
        catch (DirectoryCanonicalVerificationException)
        {
            throw;
        }
        catch (Exception exception) when (exception is OnionBoundaryException or FormatException or ArgumentException or CryptographicException)
        {
            throw Error(
                hasReset
                    ? DirectoryCanonicalVerificationError.ResetClosureInvalid
                    : DirectoryCanonicalVerificationError.CurrentNetworkClosureInvalid,
                "The verified Protocol result could not be materialized as the exact terminal publication.",
                exception);
        }
        var verifiedView = new VerifiedDirectoryArtifact(
            DirectoryArtifactKind.CurrentNetworkView, candidate.CurrentNetworkView.Span, viewHash);
        var verifiedHead = new VerifiedDirectoryArtifact(
            DirectoryArtifactKind.CurrentNetworkViewHead, candidate.CurrentNetworkViewHead.Span, headHash);
        var verifiedTopology = new VerifiedDirectoryArtifact(
            DirectoryArtifactKind.CurrentMailboxTopology, candidate.CurrentMailboxTopology.Span, pmtHash);

        if (forward is null)
        {
            return new VerifiedDirectoryPublication(
                trustAnchor.NetworkId.Span,
                lkg.ViewGeneration,
                DirectoryPublicationProtectedLkgFingerprint.RetentionFromVerifiedProtocol(
                    freshness,
                    lkg),
                verifiedView,
                verifiedHead,
                verifiedTopology);
        }

        var checkpointHash = RequireCoreHash(
            forward.TerminalCheckpointCoreReference.Span,
            "XNF1");
        byte[] proofHash;
        try
        {
            if (!Fixed(forward.ExactNfp1.Span, candidate.NetworkForwardProof!.Value.Span))
            {
                throw Error(
                    DirectoryCanonicalVerificationError.ClosureMismatch,
                    "The verified NFP1 differs from the distributable reset proof.");
            }
            proofHash = ComputeExactRecordCoreHash(
                "Deep/XPoint/V1/NFP1/exact",
                forward.ExactNfp1.Span);
        }
        catch (DirectoryCanonicalVerificationException)
        {
            throw;
        }
        catch (Exception exception) when (exception is FormatException or ArgumentException or CryptographicException)
        {
            throw Error(
                DirectoryCanonicalVerificationError.ResetClosureInvalid,
                "The verified NFP1 core identity could not be materialized.",
                exception);
        }
        return new VerifiedDirectoryPublication(
            trustAnchor.NetworkId.Span,
            lkg.ViewGeneration,
            DirectoryPublicationProtectedLkgFingerprint.RetentionFromVerifiedProtocol(
                freshness,
                lkg),
            verifiedView,
            verifiedHead,
            verifiedTopology,
            new VerifiedDirectoryArtifact(
                DirectoryArtifactKind.NetworkForwardCheckpoint,
                candidate.NetworkForwardCheckpoint!.Value.Span,
                checkpointHash),
            new VerifiedDirectoryArtifact(
                DirectoryArtifactKind.NetworkForwardProof,
                candidate.NetworkForwardProof.Value.Span,
                proofHash));
#endif
    }

#if DEEP_PROTOCOL_DIRECTORY_V1
    private static void ValidateTerminalClosure(
        FrozenDirectoryPublicationCandidate candidate,
        FrozenDirectoryPublicationVerificationClosure closure)
    {
        if (!Fixed(candidate.CurrentNetworkView.Span, closure.NetworkViewChain[^1].Span) ||
            !Fixed(candidate.CurrentNetworkViewHead.Span, closure.NetworkViewHeadChain[^1].Span) ||
            !Fixed(candidate.CurrentMailboxTopology.Span, closure.MailboxTopologyChain[^1].Span))
        {
            throw Error(
                DirectoryCanonicalVerificationError.ClosureMismatch,
                "The distributable artifacts differ from the terminal exact verification closure.");
        }

        var hasReset = candidate.HasNetworkForwardReset;
        if (hasReset != (closure.NetworkForwardCheckpointChain.Count > 0) ||
            hasReset != (closure.ResetAuthorityChain.Count > 0) ||
            hasReset && !Fixed(
                candidate.NetworkForwardCheckpoint!.Value.Span,
                closure.NetworkForwardCheckpointChain[^1].Span))
        {
            throw Error(
                DirectoryCanonicalVerificationError.ClosureMismatch,
                "The XNF1/NFP1 publication and reset verification closure differ.");
        }
    }

    private static void ValidateChallenge(
        FrozenDirectoryPublicationVerificationClosure closure,
        VerifiedDirectoryPublicationChallenge challenge)
    {
        ArgumentNullException.ThrowIfNull(challenge);
        if (!Fixed(challenge.Nonce.Span, closure.CallerNonce.Span) ||
            !Fixed(challenge.BootId.Span, closure.MonotonicBootId.Span) ||
            challenge.NonceCreatedAtMonotonicSeconds != closure.NonceCreatedAtMonotonicSeconds ||
            challenge.ResponseReceivedAtMonotonicSeconds != closure.ResponseReceivedAtMonotonicSeconds ||
            challenge.CurrentMonotonicSeconds != closure.CurrentMonotonicSeconds)
        {
            throw Error(
                DirectoryCanonicalVerificationError.FreshnessClosureInvalid,
                "The durable live-challenge authority returned a different nonce/window.");
        }
    }

    private static XPointNetworkProtectedLkg ToProtocolLkg(
        DirectoryPublicationProtectedNetworkLkg value) =>
        new(
            value.NetworkId,
            value.HeadCoreReference,
            value.HeadTreeSize,
            value.HeadRoot,
            value.ViewCoreReference,
            value.ViewGeneration,
            value.AuthorityCoreReference,
            value.LastForwardCheckpointCoreReference,
            value.LastForwardCheckpointGeneration);

    private static byte[] RequireCoreHash(ReadOnlySpan<byte> reference, string magic)
    {
        if (reference.Length != 38 ||
            !reference[..4].SequenceEqual(System.Text.Encoding.ASCII.GetBytes(magic)) ||
            reference[4] != 0 || reference[5] != 1 || reference[6..].IndexOfAnyExcept((byte)0) < 0)
        {
            throw Error(
                DirectoryCanonicalVerificationError.CurrentNetworkClosureInvalid,
                $"The Protocol producer returned an invalid {magic} core reference.");
        }
        return reference[6..].ToArray();
    }

    private static byte[] ComputeExactRecordCoreHash(string domain, ReadOnlySpan<byte> canonicalBytes)
    {
        var domainBytes = Encoding.ASCII.GetBytes(domain);
        var preimage = new byte[checked(domainBytes.Length + 1 + sizeof(uint) + canonicalBytes.Length)];
        domainBytes.CopyTo(preimage, 0);
        BinaryPrimitives.WriteUInt32BigEndian(
            preimage.AsSpan(domainBytes.Length + 1),
            checked((uint)canonicalBytes.Length));
        canonicalBytes.CopyTo(preimage.AsSpan(domainBytes.Length + 1 + sizeof(uint)));
        return SHA256.HashData(preimage);
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    private sealed class MonotonicClockAdapter(IDirectoryPublicationMonotonicClock source)
        : IOnionMonotonicClock
    {
        public async ValueTask<OnionMonotonicReading> ReadAsync(CancellationToken cancellationToken)
        {
            var reading = await source.ReadAsync(cancellationToken).ConfigureAwait(false);
            return new OnionMonotonicReading(reading.BootId.Span, reading.SampleSeconds);
        }
    }
#endif

    private static DirectoryCanonicalVerificationException Error(
        DirectoryCanonicalVerificationError error,
        string message,
        Exception? innerException = null) =>
        new(error, message, innerException);
}
