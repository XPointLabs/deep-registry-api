#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Registry.Api.DirectoryPublication;

internal sealed class DeepIdV2RestoredAuthorityState
{
    internal DeepIdV2RestoredAuthorityState(
        IReadOnlyList<AccountDirectoryProtectedLkg> heads,
        IReadOnlyList<ReadOnlyMemory<byte>> transitions,
        IReadOnlyList<DeepIdV2DirectoryAdmissionRow> admissionRows,
        IReadOnlyList<VerifiedAdc1V2> checkpoints)
    {
        Heads = heads.ToArray();
        Transitions = transitions.Select(static value =>
            (ReadOnlyMemory<byte>)value.ToArray()).ToArray();
        AdmissionRows = admissionRows.ToArray();
        CurrentCheckpoints = checkpoints.ToArray();
    }

    internal IReadOnlyList<AccountDirectoryProtectedLkg> Heads { get; }
    internal AccountDirectoryProtectedLkg CurrentHead => Heads[^1];
    internal IReadOnlyList<ReadOnlyMemory<byte>> Transitions { get; }
    internal IReadOnlyList<DeepIdV2DirectoryAdmissionRow> AdmissionRows { get; }
    internal IReadOnlyList<VerifiedAdc1V2> CurrentCheckpoints { get; }
}

/// <summary>
/// Promotes authenticated ADA2 rows only after full signed-head, PQ genesis
/// admission and V2 journal/map replay. Successor bindings are not admitted
/// until their separate lineage verifier is implemented.
/// </summary>
internal static class DeepIdV2DirectoryStateRestorer
{
    internal static DeepIdV2RestoredAuthorityState Restore(
        VerifiedXPointNetworkAuthority authority,
        AccountDirectoryProtectedLkg pinnedGenesis,
        DeepIdV2DirectoryStateRows rows,
        ulong trustedUnixSeconds,
        ushort deploymentProfileId,
        IDeepMlDsa65Verifier mlDsa65)
    {
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(pinnedGenesis);
        ArgumentNullException.ThrowIfNull(rows);
        ArgumentNullException.ThrowIfNull(mlDsa65);
        if (trustedUnixSeconds == 0 || deploymentProfileId == 0 ||
            rows.Heads.Count == 0)
            throw new InvalidDataException("ADA2 restore requires trusted time, profile and genesis.");
        if (!Fixed(rows.Heads[0].ExactAdh1.Span,
                pinnedGenesis.ExactAdh1.Span) ||
            !Fixed(rows.Heads[0].CoreHash.Span,
                pinnedGenesis.CoreHash.Span))
            throw new InvalidDataException(
                "ADA2 state is not rooted in the separately pinned DID2 genesis.");

        var heads = new List<AccountDirectoryProtectedLkg>(rows.Heads.Count)
        {
            DeepIdV2DirectoryBootstrapVerifier.RestoreGenesis(
                authority, pinnedGenesis.ExactAdh1,
                pinnedGenesis.CoreHash.Span)
        };
        foreach (var row in rows.Heads.Skip(1))
        {
            var next = AccountDirectoryProtectedLkgFactory.Restore(
                authority, row.ExactAdh1, row.CoreHash.Span);
            var previous = heads[^1];
            if (next.Head.MinimumReader < 2 ||
                next.LogGeneration != checked(previous.LogGeneration + 1) ||
                next.TreeSize < previous.TreeSize ||
                !Fixed(next.Head.PredecessorAdh1CoreHash.Span,
                    previous.CoreHash.Span))
                throw new InvalidDataException(
                    "ADA2 signed head history is not a contiguous V2 lineage.");
            heads.Add(next);
        }

        if (rows.Transitions.Count != rows.Admissions.Count)
            throw new InvalidDataException(
                "ADA2 genesis-only journal and admission counts differ.");
        var operationIds = new HashSet<string>(StringComparer.Ordinal);
        var leaves = new HashSet<string>(StringComparer.Ordinal);
        var checkpoints = new List<VerifiedAdc1V2>(rows.Admissions.Count);
        foreach (var row in rows.Admissions)
        {
            var request = DeepIdV2GenesisAdmissionWireCodec.DecodeRequest(
                row.ExactDga1V2.Span);
            if (!operationIds.Add(Convert.ToHexString(request.OperationId.Span)) ||
                row.VerifiedAtUnixSeconds == 0 ||
                row.VerifiedAtUnixSeconds > trustedUnixSeconds)
                throw new InvalidDataException(
                    "ADA2 repeats an operation ID or has an invalid verification time.");
            var checkpoint = DeepIdV2GenesisAdmissionVerifier.Verify(
                request.Admission, row.VerifiedAtUnixSeconds, deploymentProfileId, 2,
                mlDsa65);
            if (!Fixed(checkpoint.Checkpoint.NetworkId.Span,
                    authority.NetworkId.Span) ||
                !leaves.Add(Convert.ToHexString(
                    checkpoint.Checkpoint.DirectoryLeafKey.Span)))
                throw new InvalidDataException(
                    "ADA2 contains a cross-network or duplicate DID2 leaf.");
            checkpoints.Add(checkpoint);
        }

        if (heads[^1].TreeSize != (ulong)rows.Transitions.Count)
            throw new InvalidDataException(
                "ADA2 final head does not commit the complete V2 journal.");
        foreach (var head in heads)
        {
            if (head.TreeSize > (ulong)rows.Transitions.Count)
                throw new InvalidDataException(
                    "ADA2 intermediate head exceeds the verified V2 journal.");
            var prefix = checked((int)head.TreeSize);
            var prefixCheckpoints = checkpoints.Take(prefix).ToArray();
            var query = prefixCheckpoints.Length == 0
                ? Enumerable.Repeat((byte)1, 32).ToArray()
                : prefixCheckpoints[0].Checkpoint.DirectoryLeafKey.ToArray();
            _ = DeepIdV2DirectoryProofMaterialAuthor.Create(head,
                rows.Transitions.Take(prefix).ToArray(), prefixCheckpoints,
                query);
        }
        return new DeepIdV2RestoredAuthorityState(heads, rows.Transitions,
            rows.Admissions, checkpoints);
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length &&
        CryptographicOperations.FixedTimeEquals(left, right);
}
#endif
