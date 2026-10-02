namespace Deep.Registry.Api.DirectoryPublication;

internal sealed class ContactResolveDirectoryAdmissionException : IOException
{
    internal ContactResolveDirectoryAdmissionException(string message) : base(message) { }
}

internal sealed class ContactResolveDirectoryPackageUnavailableException : IOException
{
    internal ContactResolveDirectoryPackageUnavailableException()
        : base("The threshold ContactResolve directory package issuer is unavailable.")
    {
    }
}

internal sealed class ContactResolveDirectoryTargetNotFoundException : Exception
{
    internal ContactResolveDirectoryTargetNotFoundException()
        : base("The requested current directory value is not available.")
    {
    }
}
