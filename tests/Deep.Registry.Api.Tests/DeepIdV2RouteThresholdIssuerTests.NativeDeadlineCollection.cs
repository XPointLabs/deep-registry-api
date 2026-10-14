#if DEEP_PROTOCOL_DIRECTORY_V1
namespace Deep.Registry.Api.Tests;

// These fixtures exercise genuine TLS/native I/O under the unchanged product
// deadlines. Unrelated catalog/PQ/DB test collections must not turn their
// scheduling into an accidental load benchmark. Concurrency explicitly driven
// inside each scenario is retained; production-load acceptance is separate.
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class NativeIssuerDeadlineCollection
{
    public const string Name = "Registry native issuer socket deadlines";
}
#endif
