namespace Deep.Registry.Api;

public sealed record MembershipProjectionAnchor(
    long Generation,
    string StateSha256,
    bool TerminalUnsafe = false,
    string UnsafeEvidenceSha256 = "")
{
    public static MembershipProjectionAnchor Empty { get; } = new(0, "");
}

public interface IMembershipProjectionMonotonicAnchor
{
    MembershipProjectionAnchor Read();

    bool CompareExchange(
        MembershipProjectionAnchor expected,
        MembershipProjectionAnchor next);
}

public sealed class MembershipProjectionMonotonicBoundary
{
    private readonly IMembershipProjectionMonotonicAnchor? _anchor;

    private MembershipProjectionMonotonicBoundary(
        IMembershipProjectionMonotonicAnchor? anchor)
    {
        _anchor = anchor;
    }

    public bool IsAvailable => _anchor is not null;

    internal IMembershipProjectionMonotonicAnchor Required =>
        _anchor ?? throw new MonotonicAnchorUnavailableException();

    public static MembershipProjectionMonotonicBoundary Create(
        IEnumerable<IMembershipProjectionMonotonicAnchor> anchors)
    {
        ArgumentNullException.ThrowIfNull(anchors);
        var values = anchors.Take(2).ToArray();
        return new MembershipProjectionMonotonicBoundary(
            values.Length == 1 ? values[0] : null);
    }
}

internal sealed class MonotonicAnchorUnavailableException : Exception;

public sealed class MembershipProjectionAnchorTransientException : Exception
{
    public MembershipProjectionAnchorTransientException(string message)
        : base(message)
    {
    }

    public MembershipProjectionAnchorTransientException(
        string message,
        Exception innerException)
        : base(message, innerException)
    {
    }
}
