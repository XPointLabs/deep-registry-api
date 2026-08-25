using System.Text.Json;
using System.Text.Json.Serialization;
using XNodePrivacyContact = XNode.Registry.NativePrivacyContact;

namespace Deep.Registry.Api.Tests;

public sealed class PrivacyContactXNodeContractTests
{
    [Fact]
    public void RegistryModelConsumesExactXNodePrivacyContactJson()
    {
        var xnodeContact = new XNodePrivacyContact(
            new string('1', 64),
            new string('2', 64),
            "https://node.example/api/peer/privacy/v1/frame",
            ["privacy-routing-v1"],
            1_700_000_000,
            1_700_000_600,
            new string('3', 128));
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web)
        {
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
        };

        var json = JsonSerializer.Serialize(xnodeContact, options);
        var registryContact = JsonSerializer.Deserialize<NativePrivacyContact>(json, options);

        Assert.NotNull(registryContact);
        Assert.Equal(xnodeContact.RouterId, registryContact.RouterId);
        Assert.Equal(xnodeContact.X25519PublicKey, registryContact.X25519PublicKey);
        Assert.Equal(xnodeContact.PeerEndpoint, registryContact.PeerEndpoint);
        Assert.Equal(xnodeContact.Capabilities, registryContact.Capabilities);
        Assert.Equal(xnodeContact.SignedAtUnixSeconds, registryContact.SignedAtUnixSeconds);
        Assert.Equal(xnodeContact.ExpiresAtUnixSeconds, registryContact.ExpiresAtUnixSeconds);
        Assert.Equal(xnodeContact.Signature, registryContact.Signature);
    }
}
