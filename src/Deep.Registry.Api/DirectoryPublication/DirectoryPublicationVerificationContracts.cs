using System.Security.Cryptography;

namespace Deep.Registry.Api.DirectoryPublication;

internal sealed class DirectoryPublicationVerificationClosure
{
    internal const int MaximumAuthorityChainEntries = 64;
    internal const int MaximumSuccessorChainEntries = 4_096;
    internal const int MaximumNodeDescriptors = 512;
    internal const int MaximumForwardCheckpointEntries = 64;
    internal const long MaximumTotalClosureBytes = 64L * 1024 * 1024;

    private readonly byte[][] authorityChain;
    private readonly byte[][] timeSourcePolicyChain;
    private readonly byte[][] networkPolicyChain;
    private readonly byte[][] networkViewChain;
    private readonly byte[][] networkViewHeadChain;
    private readonly byte[][] activeNodeDescriptors;
    private readonly byte[][] mailboxTopologyChain;
    private readonly byte[][] resetAuthorityChain;
    private readonly byte[][] networkForwardCheckpointChain;
    private readonly byte[] exactDirectoryHead;
    private readonly byte[] exactLiveTimeAttestation;
    private readonly byte[] exactDirectoryProof;
    private readonly byte[] callerNonce;
    private readonly byte[] queriedDirectoryLeafKey;
    private readonly byte[] monotonicBootId;

    internal DirectoryPublicationVerificationClosure(
        IReadOnlyList<ReadOnlyMemory<byte>> exactOrderedXna1AuthorityChain,
        IReadOnlyList<ReadOnlyMemory<byte>> exactOrderedDts1PolicyChain,
        IReadOnlyList<ReadOnlyMemory<byte>> exactOrderedXvp1Chain,
        IReadOnlyList<ReadOnlyMemory<byte>> exactOrderedXnv1Chain,
        IReadOnlyList<ReadOnlyMemory<byte>> exactOrderedXnh1Chain,
        IReadOnlyList<ReadOnlyMemory<byte>> exactActiveXnd1,
        IReadOnlyList<ReadOnlyMemory<byte>> exactOrderedPmt2Chain,
        ReadOnlySpan<byte> exactAdh1,
        ReadOnlySpan<byte> exactDtt1,
        ReadOnlySpan<byte> exactAdp1,
        ReadOnlySpan<byte> callerNonce,
        ReadOnlySpan<byte> queriedDirectoryLeafKey,
        ReadOnlySpan<byte> monotonicBootId,
        ulong nonceCreatedAtMonotonicSeconds,
        ulong responseReceivedAtMonotonicSeconds,
        ulong currentMonotonicSeconds,
        ushort supportedReader,
        IReadOnlyList<ReadOnlyMemory<byte>>? exactOrderedResetXna1AuthorityChain = null,
        IReadOnlyList<ReadOnlyMemory<byte>>? exactOrderedXnf1Chain = null)
    {
        ArgumentNullException.ThrowIfNull(exactOrderedXna1AuthorityChain);
        ArgumentNullException.ThrowIfNull(exactOrderedDts1PolicyChain);
        ArgumentNullException.ThrowIfNull(exactOrderedXvp1Chain);
        ArgumentNullException.ThrowIfNull(exactOrderedXnv1Chain);
        ArgumentNullException.ThrowIfNull(exactOrderedXnh1Chain);
        ArgumentNullException.ThrowIfNull(exactActiveXnd1);
        ArgumentNullException.ThrowIfNull(exactOrderedPmt2Chain);
        if (exactOrderedXnv1Chain.Count != exactOrderedXnh1Chain.Count)
        {
            throw new ArgumentException("XNV1 and XNH1 successor chains must have equal cardinality.");
        }
        if (supportedReader == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(supportedReader));
        }
        if (nonceCreatedAtMonotonicSeconds > responseReceivedAtMonotonicSeconds ||
            responseReceivedAtMonotonicSeconds > currentMonotonicSeconds)
        {
            throw new ArgumentException("The live challenge monotonic samples are not ordered.");
        }

        long totalBytes = 0;
        authorityChain = CopyChain(exactOrderedXna1AuthorityChain, 1, MaximumAuthorityChainEntries,
            nameof(exactOrderedXna1AuthorityChain), ref totalBytes);
        timeSourcePolicyChain = CopyChain(exactOrderedDts1PolicyChain, 1, MaximumAuthorityChainEntries,
            nameof(exactOrderedDts1PolicyChain), ref totalBytes);
        networkPolicyChain = CopyChain(exactOrderedXvp1Chain, 1, MaximumSuccessorChainEntries,
            nameof(exactOrderedXvp1Chain), ref totalBytes);
        networkViewChain = CopyChain(exactOrderedXnv1Chain, 1, MaximumSuccessorChainEntries,
            nameof(exactOrderedXnv1Chain), ref totalBytes);
        networkViewHeadChain = CopyChain(exactOrderedXnh1Chain, 1, MaximumSuccessorChainEntries,
            nameof(exactOrderedXnh1Chain), ref totalBytes);
        activeNodeDescriptors = CopyChain(exactActiveXnd1, 3, MaximumNodeDescriptors,
            nameof(exactActiveXnd1), ref totalBytes);
        mailboxTopologyChain = CopyChain(exactOrderedPmt2Chain, 1, MaximumSuccessorChainEntries,
            nameof(exactOrderedPmt2Chain), ref totalBytes);
        resetAuthorityChain = CopyChain(exactOrderedResetXna1AuthorityChain ?? [], 0,
            MaximumAuthorityChainEntries, nameof(exactOrderedResetXna1AuthorityChain), ref totalBytes);
        networkForwardCheckpointChain = CopyChain(exactOrderedXnf1Chain ?? [], 0,
            MaximumForwardCheckpointEntries, nameof(exactOrderedXnf1Chain), ref totalBytes);
        exactDirectoryHead = CopyArtifact(exactAdh1, nameof(exactAdh1), ref totalBytes);
        exactLiveTimeAttestation = CopyArtifact(exactDtt1, nameof(exactDtt1), ref totalBytes);
        exactDirectoryProof = CopyArtifact(exactAdp1, nameof(exactAdp1), ref totalBytes);
        this.callerNonce = CopyFixed(callerNonce, 32, nameof(callerNonce), ref totalBytes);
        this.queriedDirectoryLeafKey = CopyFixed(
            queriedDirectoryLeafKey, 32, nameof(queriedDirectoryLeafKey), ref totalBytes);
        this.monotonicBootId = CopyFixed(monotonicBootId, 16, nameof(monotonicBootId), ref totalBytes);
        NonceCreatedAtMonotonicSeconds = nonceCreatedAtMonotonicSeconds;
        ResponseReceivedAtMonotonicSeconds = responseReceivedAtMonotonicSeconds;
        CurrentMonotonicSeconds = currentMonotonicSeconds;
        SupportedReader = supportedReader;
    }

    internal IReadOnlyList<ReadOnlyMemory<byte>> AuthorityChain => Memories(authorityChain);
    internal IReadOnlyList<ReadOnlyMemory<byte>> TimeSourcePolicyChain => Memories(timeSourcePolicyChain);
    internal IReadOnlyList<ReadOnlyMemory<byte>> NetworkPolicyChain => Memories(networkPolicyChain);
    internal IReadOnlyList<ReadOnlyMemory<byte>> NetworkViewChain => Memories(networkViewChain);
    internal IReadOnlyList<ReadOnlyMemory<byte>> NetworkViewHeadChain => Memories(networkViewHeadChain);
    internal IReadOnlyList<ReadOnlyMemory<byte>> ActiveNodeDescriptors => Memories(activeNodeDescriptors);
    internal IReadOnlyList<ReadOnlyMemory<byte>> MailboxTopologyChain => Memories(mailboxTopologyChain);
    internal IReadOnlyList<ReadOnlyMemory<byte>> ResetAuthorityChain => Memories(resetAuthorityChain);
    internal IReadOnlyList<ReadOnlyMemory<byte>> NetworkForwardCheckpointChain => Memories(networkForwardCheckpointChain);
    internal ReadOnlyMemory<byte> ExactDirectoryHead => exactDirectoryHead.ToArray();
    internal ReadOnlyMemory<byte> ExactLiveTimeAttestation => exactLiveTimeAttestation.ToArray();
    internal ReadOnlyMemory<byte> ExactDirectoryProof => exactDirectoryProof.ToArray();
    internal ReadOnlyMemory<byte> CallerNonce => callerNonce.ToArray();
    internal ReadOnlyMemory<byte> QueriedDirectoryLeafKey => queriedDirectoryLeafKey.ToArray();
    internal ReadOnlyMemory<byte> MonotonicBootId => monotonicBootId.ToArray();
    internal ulong NonceCreatedAtMonotonicSeconds { get; }
    internal ulong ResponseReceivedAtMonotonicSeconds { get; }
    internal ulong CurrentMonotonicSeconds { get; }
    internal ushort SupportedReader { get; }
    internal FrozenDirectoryPublicationVerificationClosure Freeze() => new(this);

    private static byte[][] CopyChain(
        IReadOnlyList<ReadOnlyMemory<byte>> values,
        int minimumCount,
        int maximumCount,
        string parameterName,
        ref long totalBytes)
    {
        if (values.Count < minimumCount || values.Count > maximumCount)
        {
            throw new ArgumentOutOfRangeException(parameterName);
        }
        var result = new byte[values.Count][];
        for (var index = 0; index < values.Count; index++)
        {
            result[index] = CopyArtifact(values[index].Span, parameterName, ref totalBytes);
        }
        return result;
    }

    private static byte[] CopyArtifact(ReadOnlySpan<byte> value, string parameterName, ref long totalBytes)
    {
        if (value.IsEmpty || value.Length > DirectoryCatalogLimits.AbsoluteMaximumArtifactBytes)
        {
            throw new ArgumentOutOfRangeException(parameterName);
        }
        totalBytes = checked(totalBytes + value.Length);
        if (totalBytes > MaximumTotalClosureBytes)
        {
            throw new ArgumentOutOfRangeException(parameterName, "The exact verification closure exceeds 64 MiB.");
        }
        return value.ToArray();
    }

    private static byte[] CopyFixed(
        ReadOnlySpan<byte> value,
        int expectedLength,
        string parameterName,
        ref long totalBytes)
    {
        if (value.Length != expectedLength || IsZero(value))
        {
            throw new ArgumentException($"{parameterName} has an invalid fixed-width value.", parameterName);
        }
        totalBytes = checked(totalBytes + value.Length);
        return value.ToArray();
    }

    private static bool IsZero(ReadOnlySpan<byte> value)
    {
        var aggregate = 0;
        foreach (var item in value) aggregate |= item;
        return aggregate == 0;
    }

    private static IReadOnlyList<ReadOnlyMemory<byte>> Memories(byte[][] values) =>
        values.Select(static value => (ReadOnlyMemory<byte>)value.ToArray()).ToArray();
}

internal sealed class FrozenDirectoryPublicationVerificationClosure
{
    internal FrozenDirectoryPublicationVerificationClosure(DirectoryPublicationVerificationClosure source)
    {
        AuthorityChain = Own(source.AuthorityChain);
        TimeSourcePolicyChain = Own(source.TimeSourcePolicyChain);
        NetworkPolicyChain = Own(source.NetworkPolicyChain);
        NetworkViewChain = Own(source.NetworkViewChain);
        NetworkViewHeadChain = Own(source.NetworkViewHeadChain);
        ActiveNodeDescriptors = Own(source.ActiveNodeDescriptors);
        MailboxTopologyChain = Own(source.MailboxTopologyChain);
        ResetAuthorityChain = Own(source.ResetAuthorityChain);
        NetworkForwardCheckpointChain = Own(source.NetworkForwardCheckpointChain);
        ExactDirectoryHead = source.ExactDirectoryHead.ToArray();
        ExactLiveTimeAttestation = source.ExactLiveTimeAttestation.ToArray();
        ExactDirectoryProof = source.ExactDirectoryProof.ToArray();
        CallerNonce = source.CallerNonce.ToArray();
        QueriedDirectoryLeafKey = source.QueriedDirectoryLeafKey.ToArray();
        MonotonicBootId = source.MonotonicBootId.ToArray();
        NonceCreatedAtMonotonicSeconds = source.NonceCreatedAtMonotonicSeconds;
        ResponseReceivedAtMonotonicSeconds = source.ResponseReceivedAtMonotonicSeconds;
        CurrentMonotonicSeconds = source.CurrentMonotonicSeconds;
        SupportedReader = source.SupportedReader;
    }

    internal IReadOnlyList<ReadOnlyMemory<byte>> AuthorityChain { get; }
    internal IReadOnlyList<ReadOnlyMemory<byte>> TimeSourcePolicyChain { get; }
    internal IReadOnlyList<ReadOnlyMemory<byte>> NetworkPolicyChain { get; }
    internal IReadOnlyList<ReadOnlyMemory<byte>> NetworkViewChain { get; }
    internal IReadOnlyList<ReadOnlyMemory<byte>> NetworkViewHeadChain { get; }
    internal IReadOnlyList<ReadOnlyMemory<byte>> ActiveNodeDescriptors { get; }
    internal IReadOnlyList<ReadOnlyMemory<byte>> MailboxTopologyChain { get; }
    internal IReadOnlyList<ReadOnlyMemory<byte>> ResetAuthorityChain { get; }
    internal IReadOnlyList<ReadOnlyMemory<byte>> NetworkForwardCheckpointChain { get; }
    internal ReadOnlyMemory<byte> ExactDirectoryHead { get; }
    internal ReadOnlyMemory<byte> ExactLiveTimeAttestation { get; }
    internal ReadOnlyMemory<byte> ExactDirectoryProof { get; }
    internal ReadOnlyMemory<byte> CallerNonce { get; }
    internal ReadOnlyMemory<byte> QueriedDirectoryLeafKey { get; }
    internal ReadOnlyMemory<byte> MonotonicBootId { get; }
    internal ulong NonceCreatedAtMonotonicSeconds { get; }
    internal ulong ResponseReceivedAtMonotonicSeconds { get; }
    internal ulong CurrentMonotonicSeconds { get; }
    internal ushort SupportedReader { get; }

    private static IReadOnlyList<ReadOnlyMemory<byte>> Own(IReadOnlyList<ReadOnlyMemory<byte>> source) =>
        source.Select(static value => (ReadOnlyMemory<byte>)value.ToArray()).ToArray();
}

internal sealed class DirectoryPublicationTrustAnchor
{
    private readonly byte[] networkId;
    private readonly byte[] authorityCoreHash;

    internal DirectoryPublicationTrustAnchor(
        ReadOnlySpan<byte> networkId,
        ulong authorityGeneration,
        ReadOnlySpan<byte> authorityCoreHash)
    {
        if (authorityGeneration != 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(authorityGeneration),
                "The release trust anchor must pin generation-zero XNA1.");
        }
        this.networkId = CopyNonZero(networkId, 16, nameof(networkId));
        AuthorityGeneration = authorityGeneration;
        this.authorityCoreHash = CopyNonZero(authorityCoreHash, 32, nameof(authorityCoreHash));
    }

    internal ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    internal ulong AuthorityGeneration { get; }
    internal ReadOnlyMemory<byte> AuthorityCoreHash => authorityCoreHash.ToArray();

    private static byte[] CopyNonZero(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException($"{name} has an invalid value.", name);
        }
        return value.ToArray();
    }
}

internal sealed class DirectoryPublicationProtectedNetworkLkg
{
    private readonly byte[] networkId;
    private readonly byte[] headCoreReference;
    private readonly byte[] headRoot;
    private readonly byte[] viewCoreReference;
    private readonly byte[] authorityCoreReference;
    private readonly byte[]? lastForwardCheckpointCoreReference;

    internal DirectoryPublicationProtectedNetworkLkg(
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> headCoreReference,
        ulong headTreeSize,
        ReadOnlySpan<byte> headRoot,
        ReadOnlySpan<byte> viewCoreReference,
        ulong viewGeneration,
        ReadOnlySpan<byte> authorityCoreReference,
        ReadOnlySpan<byte> lastForwardCheckpointCoreReference = default,
        ulong? lastForwardCheckpointGeneration = null)
    {
        this.networkId = CopyNonZero(networkId, 16, nameof(networkId));
        this.headCoreReference = CopyReference(headCoreReference, "XNH1", nameof(headCoreReference));
        HeadTreeSize = headTreeSize;
        this.headRoot = CopyNonZero(headRoot, 32, nameof(headRoot));
        this.viewCoreReference = CopyReference(viewCoreReference, "XNV1", nameof(viewCoreReference));
        ViewGeneration = viewGeneration;
        this.authorityCoreReference = CopyReference(authorityCoreReference, "XNA1", nameof(authorityCoreReference));
        if (lastForwardCheckpointCoreReference.IsEmpty != !lastForwardCheckpointGeneration.HasValue)
        {
            throw new ArgumentException("The protected XNF1 reference and generation must be supplied together.");
        }
        if (!lastForwardCheckpointCoreReference.IsEmpty)
        {
            this.lastForwardCheckpointCoreReference = CopyReference(
                lastForwardCheckpointCoreReference, "XNF1", nameof(lastForwardCheckpointCoreReference));
            LastForwardCheckpointGeneration = lastForwardCheckpointGeneration;
        }
    }

    internal ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    internal ReadOnlyMemory<byte> HeadCoreReference => headCoreReference.ToArray();
    internal ulong HeadTreeSize { get; }
    internal ReadOnlyMemory<byte> HeadRoot => headRoot.ToArray();
    internal ReadOnlyMemory<byte> ViewCoreReference => viewCoreReference.ToArray();
    internal ulong ViewGeneration { get; }
    internal ReadOnlyMemory<byte> AuthorityCoreReference => authorityCoreReference.ToArray();
    internal ReadOnlyMemory<byte> LastForwardCheckpointCoreReference =>
        lastForwardCheckpointCoreReference?.ToArray() ?? ReadOnlyMemory<byte>.Empty;
    internal ulong? LastForwardCheckpointGeneration { get; }

    private static byte[] CopyNonZero(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException($"{name} has an invalid value.", name);
        }
        return value.ToArray();
    }

    private static byte[] CopyReference(ReadOnlySpan<byte> value, string magic, string name)
    {
        if (value.Length != 38 || !value[..4].SequenceEqual(System.Text.Encoding.ASCII.GetBytes(magic)) ||
            value[4] != 0 || value[5] != 1 || value[6..].IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException($"{name} is not an exact {magic} version-1 core reference.", name);
        }
        return value.ToArray();
    }
}

internal readonly record struct DirectoryPublicationMonotonicReading(
    ReadOnlyMemory<byte> BootId,
    ulong SampleSeconds);

internal interface IDirectoryPublicationMonotonicClock
{
    ValueTask<DirectoryPublicationMonotonicReading> ReadAsync(CancellationToken cancellationToken);
}

internal sealed class VerifiedDirectoryPublicationChallenge
{
    private readonly byte[] nonce;
    private readonly byte[] bootId;

    internal VerifiedDirectoryPublicationChallenge(
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> bootId,
        ulong nonceCreatedAtMonotonicSeconds,
        ulong responseReceivedAtMonotonicSeconds,
        ulong currentMonotonicSeconds)
    {
        if (nonce.Length != 32 || nonce.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException("The verified challenge nonce must be 32 non-zero bytes.", nameof(nonce));
        }
        if (bootId.Length != 16 || bootId.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException("The verified challenge boot ID must be 16 non-zero bytes.", nameof(bootId));
        }
        if (nonceCreatedAtMonotonicSeconds > responseReceivedAtMonotonicSeconds ||
            responseReceivedAtMonotonicSeconds > currentMonotonicSeconds)
        {
            throw new ArgumentException("The verified challenge monotonic samples are not ordered.");
        }
        nonce.CopyTo(this.nonce = new byte[nonce.Length]);
        bootId.CopyTo(this.bootId = new byte[bootId.Length]);
        NonceCreatedAtMonotonicSeconds = nonceCreatedAtMonotonicSeconds;
        ResponseReceivedAtMonotonicSeconds = responseReceivedAtMonotonicSeconds;
        CurrentMonotonicSeconds = currentMonotonicSeconds;
    }

    internal ReadOnlyMemory<byte> Nonce => nonce.ToArray();
    internal ReadOnlyMemory<byte> BootId => bootId.ToArray();
    internal ulong NonceCreatedAtMonotonicSeconds { get; }
    internal ulong ResponseReceivedAtMonotonicSeconds { get; }
    internal ulong CurrentMonotonicSeconds { get; }
}

/// <summary>
/// Owns the durable, one-use DTT1 request ledger. Implementations return a typed
/// challenge only after matching and consuming the exact journaled nonce/window.
/// </summary>
internal interface IDirectoryPublicationLiveChallengeAuthority
{
    ValueTask<VerifiedDirectoryPublicationChallenge> VerifyAndConsumeAsync(
        ReadOnlyMemory<byte> nonce,
        ReadOnlyMemory<byte> bootId,
        ulong nonceCreatedAtMonotonicSeconds,
        ulong responseReceivedAtMonotonicSeconds,
        ulong currentMonotonicSeconds,
        CancellationToken cancellationToken);
}

/// <summary>
/// Supplies the independently protected network LKG required by the Protocol
/// XNF1/NFP1 verifier. Candidate bytes can never supply this trust anchor.
/// </summary>
internal interface IDirectoryPublicationProtectedNetworkLkgSource
{
    ValueTask<DirectoryPublicationProtectedNetworkLkg?> ReadAsync(
        ReadOnlyMemory<byte> expectedNetworkId,
        CancellationToken cancellationToken);
}

internal enum DirectoryCanonicalVerificationError
{
    ProtocolSurfaceUnavailable,
    ClosureMismatch,
    WrongNetwork,
    AuthorityClosureInvalid,
    FreshnessClosureInvalid,
    CurrentNetworkClosureInvalid,
    ProtectedNetworkLkgRequired,
    ResetClosureInvalid
}

internal sealed class DirectoryCanonicalVerificationException : CryptographicException
{
    internal DirectoryCanonicalVerificationException(
        DirectoryCanonicalVerificationError error,
        string message,
        Exception? innerException = null)
        : base(message, innerException) => Error = error;

    internal DirectoryCanonicalVerificationError Error { get; }
}
