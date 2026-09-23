#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Registry.Api.DirectoryPublication;

/// <summary>
/// ADA2-only HMAC-protected state with one file lease spanning read,
/// verification and append-only commit. An independent protected latest-head
/// floor is still required to detect replacement by an older valid HMAC file
/// across restarts. No ADA1 migration path exists.
/// </summary>
internal sealed class DeepIdV2DirectoryStateStore : IDisposable
{
    private readonly string statePath;
    private readonly byte[] integrityKey;
    private readonly byte[] networkId;
    private readonly DeepIdV2DirectoryBootstrapSource bootstrapSource;
    private readonly VerifiedXPointNetworkAuthority authority;
    private readonly IDeepMlDsa65Verifier mlDsa65;
    private readonly ushort deploymentProfileId;
    private bool disposed;

    internal DeepIdV2DirectoryStateStore(string statePath,
        ReadOnlySpan<byte> integrityKey,
        ReadOnlySpan<byte> networkId,
        DeepIdV2DirectoryBootstrapSource bootstrapSource,
        VerifiedXPointNetworkAuthority authority,
        IDeepMlDsa65Verifier mlDsa65,
        ushort deploymentProfileId)
    {
        if (string.IsNullOrWhiteSpace(statePath) ||
            integrityKey.Length != 32 ||
            integrityKey.IndexOfAnyExcept((byte)0) < 0 ||
            networkId.Length != 16 ||
            networkId.IndexOfAnyExcept((byte)0) < 0 ||
            deploymentProfileId == 0)
            throw new ArgumentException("ADA2 store configuration is invalid.");
        this.bootstrapSource = bootstrapSource ??
            throw new ArgumentNullException(nameof(bootstrapSource));
        this.authority = authority ?? throw new ArgumentNullException(nameof(authority));
        this.mlDsa65 = mlDsa65 ?? throw new ArgumentNullException(nameof(mlDsa65));
        if (!Fixed(networkId, authority.NetworkId.Span))
            throw new ArgumentException("ADA2 store and XPoint authority networks differ.");
        this.statePath = Path.GetFullPath(statePath);
        this.integrityKey = integrityKey.ToArray();
        this.networkId = networkId.ToArray();
        this.deploymentProfileId = deploymentProfileId;
    }

    internal Lease Open(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        var fileLease = DirectoryPublicationProtectedFile.AcquireLease(
            statePath, cancellationToken);
        return new Lease(this, fileLease);
    }

    public void Dispose()
    {
        if (disposed) return;
        disposed = true;
        CryptographicOperations.ZeroMemory(integrityKey);
        CryptographicOperations.ZeroMemory(networkId);
    }

    internal sealed class Lease : IDisposable
    {
        private readonly DeepIdV2DirectoryStateStore owner;
        private readonly IDisposable fileLease;
        private DeepIdV2RestoredAuthorityState? previouslyRead;
        private bool disposed;

        internal Lease(DeepIdV2DirectoryStateStore owner, IDisposable fileLease)
        {
            this.owner = owner;
            this.fileLease = fileLease;
        }

        internal DeepIdV2RestoredAuthorityState Read(ulong trustedUnixSeconds)
        {
            RequireOpen();
            var genesis = owner.bootstrapSource.Read(owner.authority);
            if (!File.Exists(owner.statePath))
                throw new InvalidDataException(
                    "ADA2 protected state is missing; implicit genesis would permit rollback.");
            DeepIdV2DirectoryStateRows rows;
            var encoded = DirectoryPublicationProtectedFile.ReadBounded(
                owner.statePath,
                DeepIdV2DirectoryStateCodec.MaximumPayloadBytes + 32);
            try
            {
                var payload = DirectoryPublicationProtectedFile.Verify(
                    encoded, owner.integrityKey);
                rows = DeepIdV2DirectoryStateCodec.Decode(payload,
                    owner.networkId);
            }
            finally { CryptographicOperations.ZeroMemory(encoded); }
            previouslyRead = DeepIdV2DirectoryStateRestorer.Restore(
                owner.authority, genesis, rows, trustedUnixSeconds,
                owner.deploymentProfileId, owner.mlDsa65);
            return previouslyRead;
        }

        internal DeepIdV2RestoredAuthorityState Write(
            DeepIdV2DirectoryStateRows candidate,
            ulong trustedUnixSeconds)
        {
            RequireOpen();
            ArgumentNullException.ThrowIfNull(candidate);
            var prior = previouslyRead ?? throw new InvalidOperationException(
                "ADA2 state must be read under this lease before mutation.");
            RequireAppendOnly(prior, candidate);
            var genesis = owner.bootstrapSource.Read(owner.authority);
            var verified = DeepIdV2DirectoryStateRestorer.Restore(
                owner.authority, genesis, candidate, trustedUnixSeconds,
                owner.deploymentProfileId, owner.mlDsa65);
            var payload = DeepIdV2DirectoryStateCodec.Encode(
                owner.networkId, candidate);
            var encoded = DirectoryPublicationProtectedFile.Protect(
                payload, owner.integrityKey);
            try
            {
                DirectoryPublicationProtectedFile.WriteAtomic(
                    owner.statePath, encoded);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(payload);
                CryptographicOperations.ZeroMemory(encoded);
            }
            previouslyRead = verified;
            return verified;
        }

        private static void RequireAppendOnly(
            DeepIdV2RestoredAuthorityState prior,
            DeepIdV2DirectoryStateRows candidate)
        {
            if (candidate.Heads.Count < prior.Heads.Count ||
                candidate.Transitions.Count < prior.Transitions.Count ||
                candidate.Admissions.Count < prior.AdmissionRows.Count)
                throw new InvalidDataException("ADA2 mutation rolls back protected rows.");
            for (var index = 0; index < prior.Heads.Count; index++)
                if (!Fixed(candidate.Heads[index].ExactAdh1.Span,
                        prior.Heads[index].ExactAdh1.Span) ||
                    !Fixed(candidate.Heads[index].CoreHash.Span,
                        prior.Heads[index].CoreHash.Span))
                    throw new InvalidDataException("ADA2 mutation replaces a signed head.");
            for (var index = 0; index < prior.Transitions.Count; index++)
                if (!Fixed(candidate.Transitions[index].Span,
                        prior.Transitions[index].Span))
                    throw new InvalidDataException("ADA2 mutation replaces a V2 transition.");
            for (var index = 0; index < prior.AdmissionRows.Count; index++)
                if (candidate.Admissions[index].VerifiedAtUnixSeconds !=
                        prior.AdmissionRows[index].VerifiedAtUnixSeconds ||
                    !Fixed(candidate.Admissions[index].ExactDga1V2.Span,
                        prior.AdmissionRows[index].ExactDga1V2.Span))
                    throw new InvalidDataException("ADA2 mutation replaces an admission.");
        }

        private void RequireOpen()
        {
            ObjectDisposedException.ThrowIf(disposed || owner.disposed, this);
        }

        public void Dispose()
        {
            if (disposed) return;
            disposed = true;
            fileLease.Dispose();
        }
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length &&
        CryptographicOperations.FixedTimeEquals(left, right);
}
#endif
