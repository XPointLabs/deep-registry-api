#if DEEP_PROTOCOL_DIRECTORY_V1
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;

namespace Deep.Registry.Api.DirectoryPublication;

/// <summary>Independent public credential and authenticated ADA2 floor, never candidate-supplied.</summary>
internal sealed record DirectoryPublicationDid2ProofContext(
    ParsedDid2 RequestedDid2,
    AccountDirectoryProtectedLkg ProtectedHead,
    ushort DeploymentProfileId);

internal interface IDirectoryPublicationDid2ProofContextSource
{
    ValueTask<DirectoryPublicationDid2ProofContext> ReadAsync(CancellationToken cancellationToken);
}

internal sealed class DirectoryPublicationDid2ProofContextSource : IDirectoryPublicationDid2ProofContextSource
{
    private readonly ParsedDid2 requestedDid2;
    private readonly DeepIdV2DirectoryProofIssuer proofIssuer;
    private readonly ushort deploymentProfileId;

    internal DirectoryPublicationDid2ProofContextSource(string requestedDid2Path,
        DeepIdV2DirectoryProofIssuer proofIssuer, ushort deploymentProfileId)
    {
        if (string.IsNullOrWhiteSpace(requestedDid2Path) || !Path.IsPathFullyQualified(requestedDid2Path))
            throw new ArgumentException("An absolute public DID2 credential path is required.", nameof(requestedDid2Path));
        if (deploymentProfileId == 0)
            throw new ArgumentOutOfRangeException(nameof(deploymentProfileId));
        this.proofIssuer = proofIssuer ?? throw new ArgumentNullException(nameof(proofIssuer));
        this.deploymentProfileId = deploymentProfileId;
        requestedDid2 = DeepIdV2Codec.DecodeDid2(DirectoryPublicationProtectedFile.ReadBounded(
            requestedDid2Path, DeepIdV2Codec.Did2Length));
    }

    public async ValueTask<DirectoryPublicationDid2ProofContext> ReadAsync(CancellationToken cancellationToken) =>
        new(requestedDid2, await proofIssuer.ReadCurrentHeadAsync(cancellationToken).ConfigureAwait(false),
            deploymentProfileId);
}
#endif
