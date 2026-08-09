extern alias xnode;

using Deep.Registry.Api.ProductionMailbox;
using ActualXNode = xnode::XNode;

namespace Deep.Registry.Api.Tests;

public sealed class ProductionMailboxV2XNodeContractTests
{
    [Fact]
    public void RegistryWireConstantsMatchCommittedActualXNode()
    {
        Assert.Equal(ActualXNode.ProductionMailboxClosureEnvelopeCodec.HeaderLength,
            ProductionMailboxV2WireCodec.EnvelopeHeaderLength);
        Assert.Equal(ActualXNode.ProductionMailboxClosureEnvelopeCodec.MaximumEnvelopeBytes,
            ProductionMailboxV2WireCodec.MaximumEnvelopeBytes);
        Assert.Equal(ActualXNode.ProductionMailboxPrepositionCommandCodec.HeaderLength,
            ProductionMailboxV2WireCodec.CommandHeaderLength);
        Assert.Equal(ActualXNode.ProductionMailboxPrepositionCommandCodec.MaximumCommandBytes,
            ProductionMailboxV2WireCodec.MaximumCommandBytes);
        Assert.Equal("/api/peer/production-mailbox/closure",
            ActualXNode.ProductionMailboxClosureHttpContract.PrepositionRoute);
        Assert.Equal("application/vnd.deep.production-mailbox-preposition-command",
            ActualXNode.ProductionMailboxClosureHttpContract.PrepositionMediaType);
    }
}
