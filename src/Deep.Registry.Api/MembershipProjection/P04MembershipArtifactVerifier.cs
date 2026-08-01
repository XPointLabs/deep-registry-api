using Deep.Protocol.DeepExtension.Membership;

namespace Deep.Registry.Api;

public sealed class P04MembershipArtifactVerifier
{
    private readonly IMembershipSignatureVerifier? _verifier;

    private P04MembershipArtifactVerifier(IMembershipSignatureVerifier? verifier)
    {
        _verifier = verifier;
    }

    public bool IsAvailable => _verifier is not null;

    internal IMembershipSignatureVerifier Required =>
        _verifier ?? throw new MembershipVerifierUnavailableException();

    public static P04MembershipArtifactVerifier Create(
        IEnumerable<IMembershipSignatureVerifier> verifiers)
    {
        ArgumentNullException.ThrowIfNull(verifiers);
        var values = verifiers.Take(2).ToArray();
        return new P04MembershipArtifactVerifier(values.Length == 1 ? values[0] : null);
    }
}

internal sealed class MembershipVerifierUnavailableException : Exception;
