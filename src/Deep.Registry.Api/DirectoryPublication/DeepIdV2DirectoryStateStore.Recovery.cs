#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Security.Cryptography;

namespace Deep.Registry.Api.DirectoryPublication;

internal sealed partial class DeepIdV2DirectoryStateStore
{
    internal sealed partial class Lease
    {
        // Only the mutation owner invokes this under its existing authority
        // gate/time budget/file lease. Readiness/proof reads never complete CAS.
        internal async ValueTask RecoverPendingAsync(ulong trustedUnixSeconds, CancellationToken ct)
        {
            RequireOpen(); ct.ThrowIfCancellationRequested();
            var pendingPath = owner.statePath + ".pending";
            if (!File.Exists(pendingPath)) return;
            previouslyRead = null;
            var floor = owner.latestHeadFloor ?? throw new InvalidOperationException(
                "DID2 commit recovery requires its independent latest-head floor.");
            var priorBytes = DirectoryPublicationProtectedFile.ReadBounded(owner.statePath,
                DeepIdV2DirectoryStateCodec.MaximumPayloadBytes + 32);
            var preparedBytes = Array.Empty<byte>();
            try
            {
                preparedBytes = DirectoryPublicationProtectedFile.ReadBounded(pendingPath,
                    DeepIdV2DirectoryStateCodec.MaximumPayloadBytes + 32);
                var priorRows = DeepIdV2DirectoryStateCodec.Decode(
                    DirectoryPublicationProtectedFile.Verify(priorBytes, owner.integrityKey), owner.networkId);
                var preparedRows = DeepIdV2DirectoryStateCodec.Decode(
                    DirectoryPublicationProtectedFile.Verify(preparedBytes, owner.integrityKey), owner.networkId);
                var genesis = owner.bootstrapSource.Read(owner.authority);
                var prior = DeepIdV2DirectoryStateRestorer.Restore(owner.authority, genesis, priorRows,
                    trustedUnixSeconds, owner.deploymentProfileId, owner.mlDsa65);
                var prepared = DeepIdV2DirectoryStateRestorer.Restore(owner.authority, genesis, preparedRows,
                    trustedUnixSeconds, owner.deploymentProfileId, owner.mlDsa65);
                var alreadyLocal = Fixed(priorBytes, preparedBytes);
                if (!alreadyLocal)
                {
                    RequireAppendOnly(prior, preparedRows);
                    if (prepared.Heads.Count != prior.Heads.Count + 1 ||
                        prepared.CurrentHead.LogGeneration != checked(prior.CurrentHead.LogGeneration + 1))
                        throw new InvalidDataException("DID2 prepared commit is not one exact successor.");
                }
                // A missing/unavailable floor is never reconstructed from
                // pending bytes. Candidate equality independently proves the
                // ambiguous advance completed; otherwise exact predecessor CAS.
                try { await floor.RequireCurrentAsync(prepared.CurrentHead, ct).ConfigureAwait(false); }
                catch (Exception error) when (!alreadyLocal && (error is InvalidDataException or CryptographicException))
                {
                    await floor.RequireCurrentAsync(prior.CurrentHead, ct).ConfigureAwait(false);
                    await floor.AdvanceAsync(prior.CurrentHead, prepared.CurrentHead, ct).ConfigureAwait(false);
                    await floor.RequireCurrentAsync(prepared.CurrentHead, ct).ConfigureAwait(false);
                }
                ct.ThrowIfCancellationRequested();
                if (!alreadyLocal) DirectoryPublicationProtectedFile.WriteAtomic(owner.statePath, preparedBytes);
                File.Delete(pendingPath);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(priorBytes);
                CryptographicOperations.ZeroMemory(preparedBytes);
            }
        }
    }
}
#endif
