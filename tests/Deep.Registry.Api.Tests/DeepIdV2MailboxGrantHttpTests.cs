#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV2;
using Deep.Protocol.ContactV1;
using Deep.Protocol.XPointNetworkV1;
using Sodium;
using XNode.IntegrationTests.Runtime;
using Deep.Registry.Api.DirectoryPublication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Deep.Registry.Api.Tests;

public sealed class DeepIdV2MailboxGrantHttpTests
{
    [Fact]
    public async Task PrivateGrantContextWaitsWithinCallerBudgetWithoutReleasingAnotherOwner()
    {
        // Admission only: null dependencies must never be reached by a cancelled
        // waiter. This is not proof, grant, signer, database or device evidence.
        var path = Path.Combine(Path.GetTempPath(), "deep-grant-admission-" + Guid.NewGuid().ToString("N") + ".bin");
        await File.WriteAllBytesAsync(path, [1]);
        try
        {
            using var distribution = new XPointNetworkClosureDistribution(new() {
                NetworkIdHex = new string('1', 32), BundlePath = path });
            var source = new DeepIdV2MailboxAuthorityContextSource(null!, null!, distribution, null!, null!);
            using var cancellation = new CancellationTokenSource(); var callbacks = 0;
            Assert.True(distribution.TryEnter());
            var waiting = source.WithCurrentAsync<int>(MailboxContextAdmission.PrivateIssuer,
                (_, _) => { callbacks++; return ValueTask.FromResult(1); }, cancellation.Token).AsTask();
            Exception? stopped = null;
            try { Assert.False(waiting.IsCompleted); Assert.False(distribution.TryEnter()); }
            finally { cancellation.Cancel(); stopped = await Record.ExceptionAsync(() => waiting); }
            Assert.IsAssignableFrom<OperationCanceledException>(stopped);
            Assert.Equal(0, callbacks); Assert.False(distribution.TryEnter());
            distribution.Exit();
            Assert.True(await distribution.TryEnterCurrentIssuerAsync(default)); distribution.Exit();
        }
        finally { File.Delete(path); }
    }

    [Theory]
    [InlineData("background")]
    [InlineData("occupied-private-queue")]
    [InlineData("unknown-mode")]
    public async Task PrivateGrantAdmissionKeepsOneSharedWaiterAndBackgroundNonQueuing(string mode)
    {
        // Admission only; no proof/signature/database or delivery claim.
        var path = Path.Combine(Path.GetTempPath(), "deep-grant-admission-" + Guid.NewGuid().ToString("N") + ".bin");
        await File.WriteAllBytesAsync(path, [1]);
        try
        {
            using var distribution = new XPointNetworkClosureDistribution(new() {
                NetworkIdHex = new string('1', 32), BundlePath = path });
            var source = new DeepIdV2MailboxAuthorityContextSource(null!, null!, distribution, null!, null!);
            using var cancellation = new CancellationTokenSource(); var callbacks = 0;
            Assert.True(distribution.TryEnter()); Task<bool>? queued = null;
            try
            {
                if (mode == "occupied-private-queue") queued = distribution.TryEnterCurrentIssuerAsync(cancellation.Token).AsTask();
                var selected = mode == "background" ? MailboxContextAdmission.Background :
                    mode == "unknown-mode" ? (MailboxContextAdmission)99 : MailboxContextAdmission.PrivateIssuer;
                Task<int> Attempt() => source.WithCurrentAsync<int>(selected,
                    (_, _) => { callbacks++; return ValueTask.FromResult(1); }, default).AsTask();
                if (mode == "unknown-mode") await Assert.ThrowsAsync<ArgumentOutOfRangeException>(Attempt);
                else await Assert.ThrowsAsync<IOException>(Attempt);
                Assert.Equal(0, callbacks); Assert.False(distribution.TryEnter());
                queued ??= distribution.TryEnterCurrentIssuerAsync(cancellation.Token).AsTask();
                Assert.False(queued.IsCompleted); // Rejection neither occupied nor released the other queue slot.
                cancellation.Cancel(); await Assert.ThrowsAnyAsync<OperationCanceledException>(() => queued);
                Assert.False(distribution.TryEnter());
            }
            finally
            {
                cancellation.Cancel();
                if (queued is not null) _ = await Record.ExceptionAsync(() => queued);
                distribution.Exit();
            }
            Assert.True(await distribution.TryEnterCurrentIssuerAsync(default)); distribution.Exit();
        }
        finally { File.Delete(path); }
    }

    [Theory]
    [InlineData(0, false)] [InlineData(1, false)] [InlineData(2, false)]
    [InlineData(3, false)] [InlineData(2, true)]
    public void PrivateGrantDiagnosticsAreClosedBoundedAndDoNotEscape(int phaseValue, bool sinkThrows)
    {
        var phase = (DeepIdV2MailboxGrantAdmission.FailurePhase)phaseValue;
        var admission = new DeepIdV2MailboxGrantAdmission(); var logger = new GrantDiagnosticLogger { Throw = sinkThrows };
        var error = new CryptographicException("private-sentinel-do-not-log"); error.Data["private-key"] = "private-sentinel-do-not-log";
        admission.Report(logger, phase, 400, error); admission.Report(logger, phase, 400, error);
        var entry = Assert.Single(logger.Entries);
        Assert.Equal(new[] { "Category", "CodeMethod", "CodeOffset", "Phase", "Status", "{OriginalFormat}" }, entry.Keys.Order(StringComparer.Ordinal));
        Assert.Equal("cryptographic", entry["Category"]); Assert.Equal(phase, entry["Phase"]); Assert.Equal(400, entry["Status"]);
        Assert.Equal("Unclassified", entry["CodeMethod"]); Assert.Equal(-1, entry["CodeOffset"]);
        Assert.All(entry.Values, value => Assert.DoesNotContain("private-sentinel", value?.ToString() ?? string.Empty));
        Assert.All(logger.ExceptionArguments, value => Assert.Null(value));
        Assert.True(admission.TryEnter()); admission.Exit(); // Diagnostic state is not admission/custody.
    }

    private sealed class GrantDiagnosticLogger : ILogger
    {
        internal bool Throw;
        internal List<Dictionary<string, object?>> Entries { get; } = [];
        internal List<Exception?> ExceptionArguments { get; } = [];
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel level) => true;
        public void Log<TState>(LogLevel level, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            Entries.Add(((IEnumerable<KeyValuePair<string, object?>>)(object)state!).ToDictionary(pair => pair.Key, pair => pair.Value));
            ExceptionArguments.Add(exception);
            if (Throw) throw new InvalidOperationException("Injected diagnostic sink failure.");
        }
    }

    [Theory]
    [InlineData("ProductionMailbox", "false")]
    [InlineData("ProductionMailbox:Enabled", "false")]
    [InlineData("ProductionMailbox:Unknown", "unused")]
    public void RetiredCompositionRejectsConfigurationBeforeRegisteringAnyService(string key, string value)
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { [key] = value }).Build();
        var services = new ServiceCollection();
        Assert.Throws<InvalidOperationException>(() => RetiredMailboxConfiguration.RequireAbsent(configuration));
        Assert.Throws<InvalidOperationException>(() => services.AddDeepIdV2MailboxGrants(configuration));
        Assert.Empty(services);
    }

    [Fact]
    public void ActualRegistryAssemblyHasNoRetiredMailboxCompositionOrSoftwareSigner()
    {
        var types = typeof(UnixSocketEd25519ExternalSigner).Assembly.GetTypes();
        Assert.DoesNotContain(types, type => type.Namespace == "Deep.Registry.Api.ProductionMailbox");
        Assert.DoesNotContain(types, type => type.Name == "DevelopmentSoftwareEd25519Signer");
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("[]")]
    [InlineData("null")]
    [InlineData("{\"extra\":1}")]
    [InlineData("{\"exactXmg2\":\"a\",\"exactXmg2\":\"b\"}")]
    [InlineData("{\"ExactXmg2\":\"a\"}")]
    [InlineData("{\"exactXmg1\":\"a\"}")]
    public void ClosedJsonRejectsMissingUnknownDuplicateForeignCaseAndMalformedObjects(string json) =>
        Assert.Throws<JsonException>(() => DeepIdV2MailboxGrantHosting.DecodeRequest(Encoding.UTF8.GetBytes(json)));

    [Fact]
    public void TruncatedJsonRejectsWithFrameworkJsonReaderError()
    {
        // JsonReaderException is the framework's sealed subtype; the endpoint
        // catches the documented JsonException family, not an exact leaf type.
        var error = Assert.ThrowsAny<JsonException>(() => DeepIdV2MailboxGrantHosting.DecodeRequest(Encoding.UTF8.GetBytes("{\"exactXmg2\":")));
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

    [Theory]
    [InlineData("current")]
    [InlineData("retained")]
    [InlineData("unknown-kind")]
    [InlineData("zero-kind")]
    [InlineData("missing-kind")]
    [InlineData("missing-horizon")]
    [InlineData("current-with-horizon")]
    [InlineData("current-zero-expiry")]
    [InlineData("retained-zero-horizon")]
    [InlineData("retained-current-expiry")]
    [InlineData("retained-deposit")]
    [InlineData("retained-failure")]
    [InlineData("retained-disposition")]
    [InlineData("foreign-kind-type")]
    public async Task PrivateIngressRequiresExplicitClosedKindAndDisjointHorizonFields(string mode)
    {
        using var fixture = await DeepIdV2PublicationAuthorityFixture.CreateAsync(authorContactPublication: true);
        using var holder = new JsonGrantHolder();
        var current = mode is "current" or "current-with-horizon" or "current-zero-expiry";
        var authored = current || mode == "retained-deposit"
            ? await DeepIdV2MailboxGrantRequestAuthor.AuthorDepositAsync(fixture.ContactRoute, fixture.ContactPublication.LocatorHash, holder)
            : await DeepIdV2MailboxGrantRequestAuthor.AuthorRetrieveAsync(fixture.ContactRoute, fixture.ContactPublication.LocatorHash,
                fixture.ContactOwnedRequest.OwnerRetrieveCapability, holder);
        static string B64(ReadOnlyMemory<byte> bytes) => Convert.ToBase64String(bytes.Span).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var nodeId = Convert.ToHexStringLower(Enumerable.Repeat((byte)1, 32).ToArray());
        var root = new JsonObject {
            ["exactXmg2"] = B64(authored.ExactXmg2), ["resultCode"] = 1,
            ["exactRouteClosure"] = B64(fixture.ContactRoute.ExactRouteClosure), ["routeDisposition"] = 1,
            ["routeEffectiveExpiresAtUnixSeconds"] = current ? 1_200UL : 0UL,
            ["resultExpiresAtUnixSeconds"] = BinaryPrimitives.ReadUInt64BigEndian(authored.Record.Field(10).Span),
            ["nodeId"] = nodeId, ["issuedAtUnixSeconds"] = 1_100UL,
            ["nonce"] = B64(Enumerable.Repeat((byte)1, 32).ToArray()), ["signature"] = B64(new byte[64]),
            ["replicaEvidence"] = new JsonArray(new JsonObject { ["replicaId"] = nodeId, ["signature"] = B64(Enumerable.Repeat((byte)1, 64).ToArray()) },
                new JsonObject { ["replicaId"] = nodeId, ["signature"] = B64(Enumerable.Repeat((byte)1, 64).ToArray()) }),
            ["evidenceKind"] = current ? 1 : 2, ["readUntilUnixSeconds"] = current ? 0UL : 1_000_000UL
        };
        switch (mode) {
            case "unknown-kind": root["evidenceKind"] = 99; break;
            case "zero-kind": root["evidenceKind"] = 0; break;
            case "missing-kind": root.Remove("evidenceKind"); break;
            case "missing-horizon": root.Remove("readUntilUnixSeconds"); break;
            case "current-with-horizon": root["readUntilUnixSeconds"] = 1UL; break;
            case "current-zero-expiry": root["routeEffectiveExpiresAtUnixSeconds"] = 0UL; break;
            case "retained-zero-horizon": root["readUntilUnixSeconds"] = 0UL; break;
            case "retained-current-expiry": root["routeEffectiveExpiresAtUnixSeconds"] = 1UL; break;
            case "retained-failure": root["resultCode"] = 4; break;
            case "retained-disposition": root["routeDisposition"] = 2; break;
            case "foreign-kind-type": root["evidenceKind"] = "2"; break;
        }
        var body = Encoding.UTF8.GetBytes(root.ToJsonString());
        if (mode is "current" or "retained") {
            var parsed = DeepIdV2MailboxGrantHosting.DecodeRequest(body);
            Assert.Equal(current ? DeepIdV2MailboxGrantEvidenceKind.CurrentRoute : DeepIdV2MailboxGrantEvidenceKind.RetainedRead,
                parsed.EvidenceKind); Assert.Equal(current ? 0UL : 1_000_000UL, parsed.ReadUntil);
            // Parsing these intentionally unsigned/duplicate store inputs is not
            // issuance authority. Actual current closed verifier rejects them.
        } else if (mode == "retained-deposit")
            Assert.Throws<ArgumentException>(() => DeepIdV2MailboxGrantHosting.DecodeRequest(body));
        else Assert.Throws<JsonException>(() => DeepIdV2MailboxGrantHosting.DecodeRequest(body));
    }
    private sealed class JsonGrantHolder : IReachabilityMailboxHolderSigner, IDisposable
    {
        private readonly KeyPair pair = PublicKeyAuth.GenerateKeyPair(Enumerable.Repeat((byte)0x57, 32).ToArray());
        public ReadOnlyMemory<byte> Ed25519PublicKey => pair.PublicKey.ToArray();
        public ValueTask<int> SignMailboxGrantRequestAsync(ReadOnlyMemory<byte> input, Memory<byte> output, CancellationToken ct)
        { ct.ThrowIfCancellationRequested(); PublicKeyAuth.SignDetached(input.ToArray(), pair.PrivateKey).CopyTo(output); return ValueTask.FromResult(64); }
        public void Dispose() => CryptographicOperations.ZeroMemory(pair.PrivateKey);
    }
}
#endif
