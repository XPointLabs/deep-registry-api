#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Text;
using System.Text.Json;
using Deep.Registry.Api.DirectoryPublication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Deep.Registry.Api.Tests;

public sealed class DeepIdV2MailboxGrantHttpTests
{
    [Theory]
    [InlineData("{}")]
    [InlineData("[]")]
    [InlineData("null")]
    [InlineData("{\"extra\":1}")]
    [InlineData("{\"exactXmg1\":\"a\",\"exactXmg1\":\"b\"}")]
    [InlineData("{\"ExactXmg1\":\"a\"}")]
    public void ClosedJsonRejectsMissingUnknownDuplicateForeignCaseAndMalformedObjects(string json) =>
        Assert.Throws<JsonException>(() => DeepIdV2MailboxGrantHosting.DecodeRequest(Encoding.UTF8.GetBytes(json)));

    [Fact]
    public void TruncatedJsonRejectsWithFrameworkJsonReaderError()
    {
        // JsonReaderException is the framework's sealed subtype; the endpoint
        // catches the documented JsonException family, not an exact leaf type.
        var error = Assert.ThrowsAny<JsonException>(() => DeepIdV2MailboxGrantHosting.DecodeRequest(Encoding.UTF8.GetBytes("{\"exactXmg1\":")));
        Assert.Equal("JsonReaderException", error.GetType().Name);
    }

    [Fact]
    public void WholeBodyBoundPrecedesJsonAndPrivateAuthorityIsDisabledByDefault()
    {
        Assert.Throws<JsonException>(() => DeepIdV2MailboxGrantHosting.DecodeRequest(new byte[DeepIdV2MailboxGrantHosting.MaximumBodyBytes + 1]));
        Assert.Throws<JsonException>(() => DeepIdV2MailboxGrantHosting.DecodeRequest(ReadOnlyMemory<byte>.Empty));
        var services = new ServiceCollection();
        Assert.False(services.AddDeepIdV2MailboxGrants(new ConfigurationBuilder().Build()));
        Assert.Empty(services);
        var enabled = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> {
            ["DeepIdV2MailboxGrantAuthority:Enabled"] = "true" }).Build();
        Assert.Throws<InvalidOperationException>(() => services.AddDeepIdV2MailboxGrants(enabled));
        Assert.Empty(services);
    }

    [Fact]
    public void AdmissionReplayIsBoundedWithoutEvictingLiveEntries()
    {
        var guard = new DeepIdV2MailboxGrantReplayGuard(); var node = Enumerable.Repeat((byte)1, 32).ToArray();
        byte[] Nonce(int value) { var bytes = new byte[32]; BitConverter.GetBytes(value).CopyTo(bytes, 0); bytes[^1] = 1; return bytes; }
        Assert.True(guard.TryAccept(node, Nonce(0), 100, 110));
        Assert.False(guard.TryAccept(node, Nonce(0), 100, 110));
        for (var index = 1; index < 4_096; index++) Assert.True(guard.TryAccept(node, Nonce(index), 100, 110));
        Assert.False(guard.TryAccept(node, Nonce(4_096), 100, 110));
        Assert.False(guard.TryAccept(node, Nonce(0), 289, 299));
        Assert.True(guard.TryAccept(node, Nonce(4_096), 290, 300));
    }
}
#endif
