#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Buffers.Binary;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepNative;
using Deep.Protocol.XPointNetworkV1;
using Deep.Registry.Api.DirectoryPublication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Sodium;

namespace Deep.Registry.Api.Tests;

public sealed class ProductionContactResolveDirectoryPackageIssuerTests
{
    [Theory]
    [InlineData(false, AccountDirectoryAdp1ResultKind.NonMembership)]
    [InlineData(true, AccountDirectoryAdp1ResultKind.CurrentValue)]
    public async Task Production_http_issues_real_nonce_bound_current_and_nonmembership_proofs(
        bool currentValue,
        AccountDirectoryAdp1ResultKind expectedKind)
    {
        using var fixture = ContactResolveAuthoringFixture.Create(currentValue);
        var ledgerPath = NewLedgerPath();
        try
        {
            await using var app = await StartAsync(
                fixture,
                new ProtectedFileContactResolveOneUseRequestLedger(
                    ledgerPath, fixture.Network, Bytes(0xd1, 32)));
            var nonce = Bytes(currentValue ? (byte)0x31 : (byte)0x32, 32);
            var boot = Bytes(currentValue ? (byte)0x41 : (byte)0x42, 16);

            var response = await Client(app).PostAsync(
                ContactResolveDirectoryPackageHostingExtensions.EndpointPath,
                Content(EncodeRequest(fixture.Network, nonce, boot, 901)));

            Assert.True(
                response.StatusCode == HttpStatusCode.OK,
                $"Expected 200, got {(int)response.StatusCode}: {await response.Content.ReadAsStringAsync()}");
            var package = DecodeProofPackage(await response.Content.ReadAsByteArrayAsync());
            Assert.Equal(nonce, package.Nonce);
            Assert.Equal(boot, package.BootId);
            Assert.Equal(901UL, package.ClientSample);
            Assert.Equal(expectedKind, AccountDirectoryAdp1Codec.Decode(package.ExactAdp1).ResultKind);
            var dtt = AccountDirectoryDtt1Codec.Decode(package.ExactDtt1);
            Assert.Equal(nonce, dtt.ClientNonce.ToArray());
            Assert.Equal(2, dtt.Witnesses.Count);
        }
        finally
        {
            DeleteDirectory(ledgerPath);
        }
    }

    [Fact]
    public async Task Protected_request_ledger_rejects_replay_after_restart_and_changed_boot()
    {
        using var fixture = ContactResolveAuthoringFixture.Create(currentValue: false);
        var ledgerPath = NewLedgerPath();
        var key = Bytes(0xd2, 32);
        var nonce = Bytes(0x51, 32);
        var firstBoot = Bytes(0x52, 16);
        try
        {
            await using (var first = await StartAsync(
                fixture,
                new ProtectedFileContactResolveOneUseRequestLedger(
                    ledgerPath, fixture.Network, key)))
            {
                var accepted = await Client(first).PostAsync(
                    ContactResolveDirectoryPackageHostingExtensions.EndpointPath,
                    Content(EncodeRequest(fixture.Network, nonce, firstBoot, 100)));
                Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
            }

            await using (var restarted = await StartAsync(
                fixture,
                    new ProtectedFileContactResolveOneUseRequestLedger(
                        ledgerPath, fixture.Network, key)))
            {
                var exactReplay = await Client(restarted).PostAsync(
                    ContactResolveDirectoryPackageHostingExtensions.EndpointPath,
                    Content(EncodeRequest(fixture.Network, nonce, firstBoot, 100)));
                var changedBoot = await Client(restarted).PostAsync(
                    ContactResolveDirectoryPackageHostingExtensions.EndpointPath,
                    Content(EncodeRequest(fixture.Network, nonce, Bytes(0x53, 16), 101)));

                Assert.Equal(HttpStatusCode.ServiceUnavailable, exactReplay.StatusCode);
                Assert.Equal(HttpStatusCode.ServiceUnavailable, changedBoot.StatusCode);
                Assert.Equal("contact-resolve-issuer-unavailable", await FailureCode(exactReplay));
                Assert.Equal("contact-resolve-issuer-unavailable", await FailureCode(changedBoot));
            }

            await using var freshHost = await StartAsync(
                fixture,
                new ProtectedFileContactResolveOneUseRequestLedger(
                    ledgerPath, fixture.Network, key));
            var freshNonce = await Client(freshHost).PostAsync(
                ContactResolveDirectoryPackageHostingExtensions.EndpointPath,
                Content(EncodeRequest(fixture.Network, Bytes(0x54, 32), Bytes(0x53, 16), 101)));
            Assert.Equal(HttpStatusCode.OK, freshNonce.StatusCode);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            DeleteDirectory(ledgerPath);
        }
    }

    [Fact]
    public void Protected_request_ledger_rejects_reparse_root_when_supported()
    {
        var ledgerPath = NewLedgerPath();
        var outside = ledgerPath + "-outside";
        Directory.CreateDirectory(outside);
        try
        {
            try
            {
                Directory.CreateSymbolicLink(ledgerPath, outside);
            }
            catch (Exception exception) when (exception is UnauthorizedAccessException or
                PlatformNotSupportedException or IOException)
            {
                return;
            }

            Assert.Throws<InvalidDataException>(() =>
                new ProtectedFileContactResolveOneUseRequestLedger(
                    ledgerPath, Bytes(0x11, 16), Bytes(0xd2, 32)));
        }
        finally
        {
            if (Directory.Exists(ledgerPath)) Directory.Delete(ledgerPath);
            DeleteDirectory(outside);
        }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    public async Task Insufficient_or_duplicate_witness_custody_fails_closed(int mode)
    {
        using var fixture = ContactResolveAuthoringFixture.Create(currentValue: false);
        var ledgerPath = NewLedgerPath();
        try
        {
            var invalid = mode == 0
                ? fixture.Signers.Take(1).ToArray()
                : new[] { fixture.Signers[0], fixture.Signers[0] };
            await using var app = await StartAsync(
                fixture,
                new ProtectedFileContactResolveOneUseRequestLedger(
                    ledgerPath, fixture.Network, Bytes(0xd3, 32)),
                signers: invalid);

            var response = await Client(app).PostAsync(
                ContactResolveDirectoryPackageHostingExtensions.EndpointPath,
                Content(EncodeRequest(fixture.Network, Bytes((byte)(0x61 + mode), 32), Bytes(0x63, 16), 200)));

            Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
            Assert.Equal("contact-resolve-issuer-unavailable", await FailureCode(response));
        }
        finally
        {
            DeleteDirectory(ledgerPath);
        }
    }

    [Fact]
    public async Task Missing_or_unavailable_authoritative_source_never_activates_issuer()
    {
        using var fixture = ContactResolveAuthoringFixture.Create(currentValue: false);
        var network = fixture.Network;

        await using var missing = await StartWithRegistrationsAsync(network, _ => { });
        var missingResponse = await Client(missing).PostAsync(
            ContactResolveDirectoryPackageHostingExtensions.EndpointPath,
            Content(EncodeRequest(network, Bytes(0x71, 32), Bytes(0x72, 16), 300)));
        Assert.Equal(HttpStatusCode.ServiceUnavailable, missingResponse.StatusCode);

        var ledgerPath = NewLedgerPath();
        try
        {
            await using var unavailable = await StartAsync(
                fixture,
                new ProtectedFileContactResolveOneUseRequestLedger(
                    ledgerPath, network, Bytes(0xd4, 32)),
                snapshotSource: new ThrowingSnapshotSource());
            var unavailableResponse = await Client(unavailable).PostAsync(
                ContactResolveDirectoryPackageHostingExtensions.EndpointPath,
                Content(EncodeRequest(network, Bytes(0x73, 32), Bytes(0x74, 16), 301)));
            Assert.Equal(HttpStatusCode.ServiceUnavailable, unavailableResponse.StatusCode);
            Assert.Equal("contact-resolve-issuer-unavailable", await FailureCode(unavailableResponse));
        }
        finally
        {
            DeleteDirectory(ledgerPath);
        }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    public async Task Production_composition_stays_unavailable_when_any_required_boundary_is_missing(
        int omittedBoundary)
    {
        using var fixture = ContactResolveAuthoringFixture.Create(currentValue: false);
        var ledgerPath = NewLedgerPath();
        try
        {
            await using var app = await StartWithRegistrationsAsync(fixture.Network, services =>
            {
                if (omittedBoundary != 0)
                    services.AddSingleton<IContactResolveCanonicalDirectorySnapshotSource>(
                        new CountingSnapshotSource(fixture.Snapshot));
                if (omittedBoundary != 1)
                    services.AddSingleton<IContactResolveDirectoryProofMaterialSource>(
                        new FixedProofSource(fixture.ProofMaterial));
                if (omittedBoundary != 2)
                    services.AddSingleton<IContactResolveDtt1WitnessCustody>(
                        new FixedWitnessCustody(fixture.Signers));
                if (omittedBoundary != 3)
                    services.AddSingleton<IContactResolveOneUseRequestLedger>(
                        new ProtectedFileContactResolveOneUseRequestLedger(
                            ledgerPath, fixture.Network, Bytes(0xd6, 32)));
                if (omittedBoundary != 4)
                    services.AddSingleton<IContactResolveTrustedTimeContextSource>(
                        new FixedTrustedTimeSource());
            });

            var response = await Client(app).PostAsync(
                ContactResolveDirectoryPackageHostingExtensions.EndpointPath,
                Content(EncodeRequest(
                    fixture.Network, Bytes(checked((byte)(0x80 + omittedBoundary)), 32),
                    Bytes(0x86, 16), 400)));

            Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
            Assert.Equal("contact-resolve-issuer-unavailable", await FailureCode(response));
        }
        finally
        {
            DeleteDirectory(ledgerPath);
        }
    }

    [Fact]
    public async Task Invalid_protected_monotonic_context_fails_before_authoring_and_ledger()
    {
        using var fixture = ContactResolveAuthoringFixture.Create(currentValue: false);
        var ledgerPath = NewLedgerPath();
        try
        {
            await using var app = await StartWithRegistrationsAsync(fixture.Network, services =>
                services.AddContactResolveDirectoryPackageIssuerForUat(
                    new CountingSnapshotSource(fixture.Snapshot),
                    new FixedProofSource(fixture.ProofMaterial),
                    new FixedWitnessCustody(fixture.Signers),
                    new ProtectedFileContactResolveOneUseRequestLedger(
                        ledgerPath, fixture.Network, Bytes(0xd7, 32)),
                    new FixedTrustedTimeSource(new ContactResolveTrustedTimeContext(
                        new byte[16], 1, 1_700_000_200, 5))));

            var response = await Client(app).PostAsync(
                ContactResolveDirectoryPackageHostingExtensions.EndpointPath,
                Content(EncodeRequest(fixture.Network, Bytes(0x88, 32), Bytes(0x89, 16), 401)));

            Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
            Assert.Empty(Directory.Exists(ledgerPath)
                ? Directory.EnumerateFiles(ledgerPath, "*.request", SearchOption.AllDirectories)
                : []);
        }
        finally
        {
            DeleteDirectory(ledgerPath);
        }
    }

    [Fact]
    public async Task Wrong_network_is_rejected_before_production_sources_and_ledger()
    {
        using var fixture = ContactResolveAuthoringFixture.Create(currentValue: false);
        var ledgerPath = NewLedgerPath();
        var source = new CountingSnapshotSource(fixture.Snapshot);
        try
        {
            await using var app = await StartAsync(
                fixture,
                new ProtectedFileContactResolveOneUseRequestLedger(
                    ledgerPath, fixture.Network, Bytes(0xd5, 32)),
                snapshotSource: source);
            var response = await Client(app).PostAsync(
                ContactResolveDirectoryPackageHostingExtensions.EndpointPath,
                Content(EncodeRequest(Bytes(0x7f, 16), Bytes(0x75, 32), Bytes(0x76, 16), 302)));

            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Equal("contact-resolve-wrong-network", await FailureCode(response));
            Assert.Equal(0, source.Calls);
            Assert.Empty(Directory.Exists(ledgerPath)
                ? Directory.EnumerateFiles(ledgerPath, "*.request", SearchOption.AllDirectories)
                : []);
        }
        finally
        {
            DeleteDirectory(ledgerPath);
        }
    }

    [Fact]
    public async Task Durable_admission_rejection_occurs_after_authority_snapshot_but_before_custody_work()
    {
        using var fixture = ContactResolveAuthoringFixture.Create(currentValue: false);
        var source = new CountingSnapshotSource(fixture.Snapshot);
        await using var app = await StartAsync(
            fixture,
            new RejectingAdmissionLedger(),
            snapshotSource: source);

        var response = await Client(app).PostAsync(
            ContactResolveDirectoryPackageHostingExtensions.EndpointPath,
            Content(EncodeRequest(
                fixture.Network, Bytes(0x77, 32), Bytes(0x78, 16), 303)));

        Assert.Equal(HttpStatusCode.TooManyRequests, response.StatusCode);
        Assert.Equal("contact-resolve-rate-limited", await FailureCode(response));
        Assert.Equal(1, source.Calls);
    }

    private static async Task<WebApplication> StartAsync(
        ContactResolveAuthoringFixture fixture,
        IContactResolveOneUseRequestLedger ledger,
        IReadOnlyList<IAccountDirectoryDtt1WitnessSigner>? signers = null,
        IContactResolveCanonicalDirectorySnapshotSource? snapshotSource = null) =>
        await StartWithRegistrationsAsync(fixture.Network, services =>
            services.AddContactResolveDirectoryPackageIssuerForUat(
                snapshotSource ?? new CountingSnapshotSource(fixture.Snapshot),
                new FixedProofSource(fixture.ProofMaterial),
                new FixedWitnessCustody(signers ?? fixture.Signers),
                ledger,
                new FixedTrustedTimeSource()));

    private static async Task<WebApplication> StartWithRegistrationsAsync(
        byte[] network,
        Action<IServiceCollection> register)
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(
            new Dictionary<string, string?>
            {
                ["DirectoryPublication:NetworkIdHex"] = Convert.ToHexString(network),
            }).Build();
        var builder = WebApplication.CreateBuilder();
        builder.Environment.EnvironmentName = "Development";
        builder.WebHost.UseTestServer();
        var state = builder.Services.AddContactResolveDirectoryPackages(configuration);
        register(builder.Services);
        var app = builder.Build();
        app.UseDeveloperExceptionPage();
        app.MapContactResolveDirectoryPackageEndpoint(state);
        await app.StartAsync();
        return app;
    }

    private static HttpClient Client(WebApplication app)
    {
        var client = app.GetTestClient();
        client.BaseAddress = new Uri("https://localhost");
        return client;
    }

    private static ByteArrayContent Content(byte[] bytes)
    {
        var content = new ByteArrayContent(bytes);
        content.Headers.ContentType = new MediaTypeHeaderValue(
            ContactResolveDirectoryPackageCodec.RequestMediaType);
        return content;
    }

    private static byte[] EncodeRequest(byte[] network, byte[] nonce, byte[] boot, ulong sample)
    {
        var output = new byte[84];
        "CDQ1"u8.CopyTo(output);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(4), 1);
        BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(8), checked((uint)output.Length));
        network.CopyTo(output, 12);
        nonce.CopyTo(output, 28);
        boot.CopyTo(output, 60);
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(76), sample);
        return output;
    }

    private static DecodedProofPackage DecodeProofPackage(byte[] response)
    {
        Assert.True(response.AsSpan(0, 4).SequenceEqual("CDR1"u8));
        var nonce = response.AsSpan(28, 32).ToArray();
        var boot = response.AsSpan(60, 16).ToArray();
        var sample = BinaryPrimitives.ReadUInt64BigEndian(response.AsSpan(76));
        var offset = 116;
        SkipChain(response, ref offset);
        SkipChain(response, ref offset);
        _ = ReadArtifact(response, ref offset);
        var dtt = ReadArtifact(response, ref offset);
        var adp = ReadArtifact(response, ref offset);
        return new DecodedProofPackage(nonce, boot, sample, dtt, adp);
    }

    private static void SkipChain(byte[] value, ref int offset)
    {
        var count = BinaryPrimitives.ReadUInt32BigEndian(value.AsSpan(offset));
        offset += 4;
        for (var index = 0; index < count; index++) _ = ReadArtifact(value, ref offset);
    }

    private static byte[] ReadArtifact(byte[] value, ref int offset)
    {
        var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(value.AsSpan(offset)));
        offset += 4;
        var result = value.AsSpan(offset, length).ToArray();
        offset += length;
        return result;
    }

    private static async Task<string> FailureCode(HttpResponseMessage response)
    {
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return json.RootElement.GetProperty("code").GetString()!;
    }

    private static string NewLedgerPath() => Path.Combine(
        Path.GetTempPath(), "deep-registry-contact-resolve-tests", Guid.NewGuid().ToString("N"));

    private static void DeleteDirectory(string path)
    {
        if (Directory.Exists(path)) Directory.Delete(path, recursive: true);
    }

    private static byte[] Bytes(byte value, int length) =>
        Enumerable.Repeat(value, length).ToArray();

    private sealed record DecodedProofPackage(
        byte[] Nonce,
        byte[] BootId,
        ulong ClientSample,
        byte[] ExactDtt1,
        byte[] ExactAdp1);

    private sealed class CountingSnapshotSource(ContactResolveCanonicalDirectorySnapshot snapshot) :
        IContactResolveCanonicalDirectorySnapshotSource
    {
        internal int Calls { get; private set; }

        public ValueTask<ContactResolveCanonicalDirectorySnapshot> ReadAsync(
            ContactResolveDirectoryPackageRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls++;
            return ValueTask.FromResult(snapshot);
        }
    }

    private sealed class RejectingAdmissionLedger : IContactResolveOneUseRequestLedger
    {
        public ValueTask ConsumeAsync(
            ContactResolveDirectoryPackageRequest request,
            ContactResolveTrustedTimeContext trustedTime,
            AccountDirectoryDtt1IssuanceEpoch issuanceEpoch,
            CancellationToken cancellationToken) =>
            ValueTask.FromException(new ContactResolveDirectoryAdmissionException("bounded"));
    }

    private sealed class ThrowingSnapshotSource : IContactResolveCanonicalDirectorySnapshotSource
    {
        public ValueTask<ContactResolveCanonicalDirectorySnapshot> ReadAsync(
            ContactResolveDirectoryPackageRequest request,
            CancellationToken cancellationToken) => throw new IOException("canonical source unavailable");
    }

    private sealed class FixedProofSource(AccountDirectoryAdp1ProofMaterial proof) :
        IContactResolveDirectoryProofMaterialSource
    {
        public ValueTask<AccountDirectoryAdp1ProofMaterial> ReadAsync(
            ContactResolveCanonicalDirectorySnapshot snapshot,
            ContactResolveDirectoryPackageRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(proof);
        }
    }

    private sealed class FixedWitnessCustody(
        IReadOnlyList<IAccountDirectoryDtt1WitnessSigner> signers) :
        IContactResolveDtt1WitnessCustody
    {
        public ValueTask<IReadOnlyList<IAccountDirectoryDtt1WitnessSigner>> GetSignersAsync(
            VerifiedXPointNetworkAuthority authority,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(signers);
        }
    }

    private sealed class FixedTrustedTimeSource : IContactResolveTrustedTimeContextSource
    {
        private readonly ContactResolveTrustedTimeContext value;

        internal FixedTrustedTimeSource()
            : this(new ContactResolveTrustedTimeContext(
                Bytes(0xc1, 16), 4_000, 1_700_000_200, 5))
        {
        }

        internal FixedTrustedTimeSource(ContactResolveTrustedTimeContext value) =>
            this.value = value;

        public ValueTask<ContactResolveTrustedTimeContext> ReadAsync(
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(value);
        }
    }
}

internal sealed class ContactResolveAuthoringFixture : IDisposable
{
    private readonly KeyPair root;
    private readonly Witness[] witnesses;

    private ContactResolveAuthoringFixture(
        byte[] network,
        KeyPair root,
        Witness[] witnesses,
        byte[] exactXna1,
        byte[] exactDts1,
        VerifiedXPointNetworkAuthority authority,
        ContactResolveCanonicalDirectorySnapshot snapshot,
        AccountDirectoryAdp1ProofMaterial proofMaterial)
    {
        Network = network;
        this.root = root;
        this.witnesses = witnesses;
        ExactXna1 = exactXna1;
        ExactDts1 = exactDts1;
        Authority = authority;
        Snapshot = snapshot;
        ProofMaterial = proofMaterial;
        Signers = witnesses.Take(2)
            .Select(static witness => (IAccountDirectoryDtt1WitnessSigner)new WitnessSigner(witness))
            .ToArray();
    }

    internal byte[] Network { get; }
    internal byte[] ExactXna1 { get; }
    internal byte[] ExactDts1 { get; }
    internal VerifiedXPointNetworkAuthority Authority { get; }
    internal ContactResolveCanonicalDirectorySnapshot Snapshot { get; }
    internal AccountDirectoryAdp1ProofMaterial ProofMaterial { get; }
    internal IReadOnlyList<IAccountDirectoryDtt1WitnessSigner> Signers { get; }

    internal static ContactResolveAuthoringFixture Create(bool currentValue)
    {
        var network = Bytes(0x11, 16);
        var root = PublicKeyAuth.GenerateKeyPair(Bytes(0x20, 32));
        var witnesses = Enumerable.Range(0, 3).Select(index => new Witness(
            Bytes(checked((byte)(0x40 + index)), 32),
            PublicKeyAuth.GenerateKeyPair(Bytes(checked((byte)(0x50 + index)), 32)),
            Bytes(checked((byte)(0x60 + index)), 32))).ToArray();
        var exactDts1 = CreateDts1(network, root);
        var policyHash = AccountDirectoryCrypto.ComputeDts1PolicyHash(
            AccountDirectoryDts1Codec.Decode(exactDts1));
        var exactXna1 = CreateXna1(network, root, witnesses, policyHash);
        var xna = XPointNetworkCodec.Parse<Xna1Record>(exactXna1);
        var authority = XPointNetworkAuthorityVerifier.Verify(
            new XPointNetworkGenesisPin(network, xna.CoreHash.Span),
            [exactXna1],
            [exactDts1]);
        var currentXnv1 = CreateCurrentXnv1(network, authority, witnesses);

        AccountDirectoryProtectedLkg currentHead;
        AccountDirectoryAdp1ProofMaterial proof;
        if (currentValue)
        {
            var checkpoint = IdentityFixture.CreateVerifiedCheckpoint();
            var oldHead = CreateHead(network, authority, witnesses, 0, new byte[32], 0,
                AccountDirectoryRfc6962.ComputeEmptyTreeHash(),
                AccountDirectorySparseMap.EmptyMapRoot.ToArray());
            var callerLkg = new AccountDirectoryProtectedLkg(AccountDirectoryAdh1Codec.Encode(oldHead));
            var adcReference = Reference(
                "ADC1", AccountDirectoryCrypto.ComputeAdc1ArtifactHash(checkpoint.Checkpoint));
            var query = checkpoint.Checkpoint.DirectoryLeafKey.ToArray();
            var bitmap = new byte[32];
            var mapRoot = AccountDirectorySparseMap.ComputePresentRoot(query, adcReference, bitmap, []);
            var transition = Join(
                U16(1), U64(0), query, new byte[38], adcReference,
                AccountDirectorySparseMap.EmptyMapRoot.ToArray(), mapRoot);
            var commitment = AccountDirectoryCrypto.Sha256Domain(
                "Deep/AccountDirectory/V1/transition", transition);
            var head = CreateHead(network, authority, witnesses, 1, callerLkg.CoreHash.ToArray(), 1,
                AccountDirectoryRfc6962.ComputeLeafHash(commitment), mapRoot);
            currentHead = new AccountDirectoryProtectedLkg(AccountDirectoryAdh1Codec.Encode(head));
            proof = AccountDirectoryAdp1ProofMaterial.CurrentValue(
                checkpoint, callerLkg, [], ReadOnlyMemory<byte>.Empty,
                bitmap, [], transition, 0, []);
        }
        else
        {
            var head = CreateHead(network, authority, witnesses, 0, new byte[32], 0,
                AccountDirectoryRfc6962.ComputeEmptyTreeHash(),
                AccountDirectorySparseMap.EmptyMapRoot.ToArray());
            currentHead = new AccountDirectoryProtectedLkg(AccountDirectoryAdh1Codec.Encode(head));
            proof = AccountDirectoryAdp1ProofMaterial.NonMembership(
                Bytes(0x32, 32), null, [], ReadOnlyMemory<byte>.Empty,
                new byte[32], []);
        }

        var snapshot = new ContactResolveCanonicalDirectorySnapshot(
            network,
            authority,
            currentHead,
            currentXnv1,
            1,
            [exactXna1],
            [exactDts1],
            [Bytes(0x81, 8)],
            [currentXnv1],
            [Bytes(0x82, 8)],
            [Bytes(0x83, 8), Bytes(0x84, 8), Bytes(0x85, 8)],
            [Bytes(0x86, 8)]);
        return new ContactResolveAuthoringFixture(
            network, root, witnesses, exactXna1, exactDts1, authority, snapshot, proof);
    }

    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(root.PrivateKey);
        foreach (var witness in witnesses)
            CryptographicOperations.ZeroMemory(witness.Key.PrivateKey);
    }

    private static AccountDirectoryAdh1 CreateHead(
        byte[] network,
        VerifiedXPointNetworkAuthority authority,
        Witness[] witnesses,
        ulong generation,
        byte[] predecessor,
        ulong treeSize,
        byte[] appendRoot,
        byte[] mapRoot)
    {
        var selected = witnesses.Take(2).OrderBy(static value => value.Id, ByteArrayComparer.Instance).ToArray();
        var placeholders = selected.Select((value, index) => new AccountDirectoryAdh1WitnessEntry(
            value.Id, Bytes(checked((byte)(0x70 + index)), 64))).ToArray();
        var unsigned = new AccountDirectoryAdh1(
            network, generation, predecessor, treeSize, appendRoot, mapRoot,
            authority.AuthorityCoreReference.Span, authority.DirectoryWitnessPolicyHash.Span,
            1_700_000_000, 1_700_010_000, 1, placeholders);
        var input = AccountDirectoryCrypto.ComputeAdh1SigningInput(unsigned);
        var receipts = selected.Select(value => new AccountDirectoryAdh1WitnessEntry(
            value.Id, PublicKeyAuth.SignDetached(input, value.Key.PrivateKey))).ToArray();
        CryptographicOperations.ZeroMemory(input);
        return new AccountDirectoryAdh1(
            network, generation, predecessor, treeSize, appendRoot, mapRoot,
            authority.AuthorityCoreReference.Span, authority.DirectoryWitnessPolicyHash.Span,
            1_700_000_000, 1_700_010_000, 1, receipts);
    }

    private static byte[] CreateCurrentXnv1(
        byte[] network,
        VerifiedXPointNetworkAuthority authority,
        Witness[] witnesses)
    {
        ReadOnlyMemory<byte>[] fields =
        [
            network, U64(0), new byte[32], Bytes(0x91, 32), U64(1), Bytes(0x92, 32),
            authority.AuthorityCoreReference, authority.DirectoryWitnessPolicyHash,
            Reference("XVP1", Bytes(0x93, 32)), U16(1), U16(3),
            Join(Reference("XND1", Bytes(0x94, 32)), Reference("XND1", Bytes(0x95, 32)),
                Reference("XND1", Bytes(0x96, 32))),
            U16(0), ReadOnlyMemory<byte>.Empty, U16(0), ReadOnlyMemory<byte>.Empty,
            U16(1), Reference("XCB1", Bytes(0x97, 32)),
            U64(1), U64(1_699_999_000), U64(1_700_010_000), U16(1), new byte[] { 2 },
            Join(witnesses[0].Id, Bytes(0xa1, 64), witnesses[1].Id, Bytes(0xa2, 64)),
        ];
        var provisional = XPointNetworkCodec.Parse<Xnv1Record>(
            XPointNetworkCodec.Write(XPointNetworkRegistry.Xnv1, fields));
        var input = XPointNetworkCrypto.ComputeSigningInput(provisional);
        fields[23] = Join(
            witnesses[0].Id, PublicKeyAuth.SignDetached(input, witnesses[0].Key.PrivateKey),
            witnesses[1].Id, PublicKeyAuth.SignDetached(input, witnesses[1].Key.PrivateKey));
        CryptographicOperations.ZeroMemory(input);
        return XPointNetworkCodec.Write(XPointNetworkRegistry.Xnv1, fields);
    }

    private static byte[] CreateDts1(byte[] network, KeyPair root)
    {
        var sources = new[]
        {
            new AccountDirectoryDts1Source(Bytes(0x10, 32), Bytes(0x12, 32), 1,
                "time-a.example", 443, Bytes(0x14, 32), 5),
            new AccountDirectoryDts1Source(Bytes(0x11, 32), Bytes(0x13, 32), 1,
                "time-b.example", 443, Bytes(0x15, 32), 5),
        };
        var rootId = Bytes(0x20, 32);
        var unsigned = new AccountDirectoryDts1(
            network, 0, new byte[32], sources, 2, 2, 30, 5,
            1_699_000_000, 1_701_000_000, 1, 0,
            [new AccountDirectoryDts1RootReceipt(rootId, Bytes(0x21, 64))]);
        var signature = PublicKeyAuth.SignDetached(
            AccountDirectoryCrypto.ComputeDts1SigningInput(unsigned), root.PrivateKey);
        return AccountDirectoryDts1Codec.Encode(new AccountDirectoryDts1(
            network, 0, new byte[32], sources, 2, 2, 30, 5,
            1_699_000_000, 1_701_000_000, 1, 0,
            [new AccountDirectoryDts1RootReceipt(rootId, signature)]));
    }

    private static byte[] CreateXna1(
        byte[] network,
        KeyPair root,
        Witness[] witnesses,
        byte[] policyHash)
    {
        ReadOnlyMemory<byte>[] fields = new ReadOnlyMemory<byte>[20];
        fields[0] = network; fields[1] = U64(0); fields[2] = new byte[32]; fields[3] = new byte[] { 1 };
        fields[4] = Join(Bytes(0x20, 32), U64(0), root.PublicKey); fields[5] = new byte[] { 1 };
        fields[6] = U64(0); fields[7] = U16(1); fields[8] = new byte[] { 3 };
        fields[9] = Join(witnesses.Select(value => Join(
            value.Id, U64(0), value.Key.PublicKey, value.FailureDomain)).ToArray());
        fields[10] = new byte[] { 2 }; fields[11] = Reference("DTS1", policyHash); fields[12] = policyHash;
        fields[13] = U32(30); fields[14] = U64(1); fields[15] = U64(1_699_000_000);
        fields[16] = U64(1_699_000_000); fields[17] = U64(1_710_000_000); fields[18] = new byte[] { 1 };
        fields[19] = Join(Bytes(0x20, 32), Bytes(0x22, 64));
        var unsigned = XPointNetworkCodec.Parse<Xna1Record>(
            XPointNetworkCodec.Write(XPointNetworkRegistry.Xna1, fields));
        fields[19] = Join(Bytes(0x20, 32), PublicKeyAuth.SignDetached(
            XPointNetworkCrypto.ComputeSigningInput(unsigned), root.PrivateKey));
        return XPointNetworkCodec.Write(XPointNetworkRegistry.Xna1, fields);
    }

    private static byte[] Bytes(byte value, int length) => Enumerable.Repeat(value, length).ToArray();
    private static byte[] Reference(string magic, ReadOnlySpan<byte> hash)
    {
        var result = new byte[38];
        Encoding.ASCII.GetBytes(magic).CopyTo(result, 0);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(4), 1);
        hash.CopyTo(result.AsSpan(6));
        return result;
    }
    private static byte[] Join(params byte[][] values)
    {
        var result = new byte[values.Sum(static value => value.Length)];
        var offset = 0;
        foreach (var value in values) { value.CopyTo(result, offset); offset += value.Length; }
        return result;
    }
    private static byte[] U16(ushort value) { var result = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(result, value); return result; }
    private static byte[] U32(uint value) { var result = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(result, value); return result; }
    private static byte[] U64(ulong value) { var result = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(result, value); return result; }

    private sealed record Witness(byte[] Id, KeyPair Key, byte[] FailureDomain);
    private sealed class WitnessSigner(Witness witness) : IAccountDirectoryDtt1WitnessSigner
    {
        public ReadOnlyMemory<byte> WitnessId => witness.Id.ToArray();
        public ValueTask<ReadOnlyMemory<byte>> SignDtt1Async(
            ReadOnlyMemory<byte> signingInput,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult<ReadOnlyMemory<byte>>(
                PublicKeyAuth.SignDetached(signingInput.ToArray(), witness.Key.PrivateKey));
        }
    }
    private sealed class ByteArrayComparer : IComparer<byte[]>
    {
        internal static readonly ByteArrayComparer Instance = new();
        public int Compare(byte[]? left, byte[]? right) => left.AsSpan().SequenceCompareTo(right);
    }

    private sealed class IdentityFixture
    {
        private readonly byte[] network;
        private readonly byte[] accountId;
        private readonly KeyPair deviceIssuerKey;
        private readonly VerifiedAccount account;
        private readonly VerifiedRevocationState revocations;
        private readonly VerifiedDab1 binding;
        private readonly VerifiedDmd1 directory;

        private IdentityFixture(
            byte[] network,
            byte[] accountId,
            KeyPair deviceIssuerKey,
            VerifiedAccount account,
            VerifiedRevocationState revocations,
            VerifiedDab1 binding,
            VerifiedDmd1 directory)
        {
            this.network = network;
            this.accountId = accountId;
            this.deviceIssuerKey = deviceIssuerKey;
            this.account = account;
            this.revocations = revocations;
            this.binding = binding;
            this.directory = directory;
        }

        internal static VerifiedAccountDirectoryCheckpoint CreateVerifiedCheckpoint()
        {
            var fixture = Create();
            ReadOnlyMemory<byte>[] revoked = [];
            var leaf = AccountDirectoryAdc1Verifier.ComputeDirectoryLeafKey(
                fixture.network, fixture.binding.DeepId.CanonicalBytes.Span);
            var revokedHash = AccountDirectoryAdc1Verifier.ComputeRevokedDcaAuthorizationIdsHash(revoked);
            var unsigned = new AccountDirectoryAdc1(
                fixture.network, leaf, 1, 0, new byte[32],
                AccountDirectoryCrypto.CreateReference("DPA1"u8, 1, fixture.account.Certificate.CanonicalHash.Span),
                AccountDirectoryCrypto.CreateReference("DRS1"u8, 1, fixture.revocations.Snapshot.CanonicalHash.Span),
                fixture.directory.Record.RecordHash.Span,
                fixture.binding.Record.RecordHash.Span,
                revokedHash,
                1_700_000_123,
                1,
                Bytes(0x01, 64));
            var signature = PublicKeyAuth.SignDetached(
                AccountDirectoryCrypto.ComputeAdc1SigningInput(unsigned),
                fixture.deviceIssuerKey.PrivateKey);
            var checkpoint = new AccountDirectoryAdc1(
                unsigned.NetworkId.Span, unsigned.DirectoryLeafKey.Span, unsigned.AccountGeneration,
                unsigned.CheckpointGeneration, unsigned.PredecessorCheckpointHash.Span,
                unsigned.ExactDpa1Reference.Span, unsigned.ExactDrs1Reference.Span,
                unsigned.ExactDmd1Hash.Span, unsigned.ExactDab1Hash.Span,
                unsigned.RevokedDcaAuthorizationIdsHash.Span, unsigned.IssuedAt,
                unsigned.MinimumReader, signature);
            return AccountDirectoryAdc1Verifier.Verify(
                checkpoint, fixture.binding, fixture.directory, revoked, 1);
        }

        private static IdentityFixture Create()
        {
            var network = Bytes(0x11, 16);
            var accountId = Bytes(0x22, 32);
            var deviceId = Bytes(0x33, 32);
            var addressKey = PublicKeyAuth.GenerateKeyPair();
            var accountKey = PublicKeyAuth.GenerateKeyPair();
            var deviceIssuerKey = PublicKeyAuth.GenerateKeyPair();
            var revocationKey = PublicKeyAuth.GenerateKeyPair();
            var resetKey = PublicKeyAuth.GenerateKeyPair();
            var dpaFields = MinimumFields(RecordDefinitions.Dpa1);
            dpaFields[0] = network; dpaFields[1] = U64(1); dpaFields[2] = U64(1);
            dpaFields[4] = accountKey.PublicKey; dpaFields[5] = deviceIssuerKey.PublicKey;
            dpaFields[6] = revocationKey.PublicKey; dpaFields[7] = resetKey.PublicKey;
            dpaFields[8] = Bytes(0x44, 32); dpaFields[9] = U64(100); dpaFields[10] = U64(1);
            dpaFields[11] = U16(ArtifactRegistry.IdentityAuthV1Ed25519);
            var certificate = IdentityCodec.DecodeAccountCertificate(
                CanonicalGrammar.Encode(RecordDefinitions.Dpa1, dpaFields));
            var account = new VerifiedAccount(certificate, accountId);
            var drs = CreateRevocations(network, accountId);
            var revocations = new VerifiedRevocationState(account, drs, new RevocationCatalog([]));

            var deviceEd = PublicKeyAuth.GenerateKeyPair();
            var dpdFields = MinimumFields(RecordDefinitions.Dpd1);
            dpdFields[0] = network; dpdFields[1] = accountId; dpdFields[2] = U64(1);
            dpdFields[3] = deviceId; dpdFields[4] = U64(1); dpdFields[5] = deviceEd.PublicKey;
            dpdFields[6] = Bytes(0x51, 32); dpdFields[7] = Bytes(0x52, 32);
            dpdFields[8] = U64(1); dpdFields[10] = Bytes(0x53, 32);
            dpdFields[11] = U64(drs.Revision); dpdFields[12] = ArtifactReference(drs).CanonicalBytes;
            dpdFields[13] = U64(drs.EntryCount); dpdFields[14] = drs.CurrentHead;
            dpdFields[15] = U64(100); dpdFields[16] = U64(1_000);
            dpdFields[17] = U64((ulong)DeviceCapabilities.MailboxRoleIssuer);
            dpdFields[18] = U16(ArtifactRegistry.IdentityAuthV1Ed25519);
            dpdFields[20] = Bytes(0x55, 32);
            var deviceCertificate = IdentityCodec.DecodeDeviceCertificate(
                CanonicalGrammar.Encode(RecordDefinitions.Dpd1, dpdFields));
            var device = new VerifiedDevice(deviceCertificate, revocations,
                new X25519Possession(X25519PossessionRole.Device, dpdFields[20].Span));
            var identity = ApplicationCoreVerifier.CreateIdentityClosure(account, revocations, [device]);
            var deepId = ApplicationCoreCodec.AuthorDid1(addressKey.PublicKey, Bytes(0x66, 16));
            var realm = ApplicationCoreCodec.DeriveIdentityRealmId(network, 7);
            var dpa = ArtifactReference(certificate);
            var unsignedDab = ApplicationCoreCodec.AuthorDab1(
                deepId.RecordHash.Span, realm.Span, 0, new byte[32], accountId, 1, dpa,
                new byte[64], new byte[64]);
            var dab = ApplicationCoreCodec.AuthorDab1(
                deepId.RecordHash.Span, realm.Span, 0, new byte[32], accountId, 1, dpa,
                PublicKeyAuth.SignDetached(unsignedDab.AddressSignatureInput.ToArray(), addressKey.PrivateKey),
                PublicKeyAuth.SignDetached(unsignedDab.AccountSignatureInput.ToArray(), accountKey.PrivateKey));
            var binding = ApplicationCoreVerifier.VerifyDab1(dab, deepId, identity, 7);
            var entry = new DeviceDirectoryEntry(deviceId, ArtifactReference(deviceCertificate));
            var unsignedDmd = ApplicationCoreCodec.AuthorDmd1(
                network, accountId, 1, ArtifactReference(certificate), ArtifactReference(drs),
                1, new byte[32], [entry], 100, new byte[64]);
            var signedDmd = ApplicationCoreCodec.AuthorDmd1(
                network, accountId, 1, ArtifactReference(certificate), ArtifactReference(drs),
                1, new byte[32], [entry], 100,
                PublicKeyAuth.SignDetached(unsignedDmd.SignatureInput.ToArray(), deviceIssuerKey.PrivateKey));
            var directory = ApplicationCoreVerifier.VerifyDmd1(signedDmd, identity);
            return new IdentityFixture(network, accountId, deviceIssuerKey, account, revocations, binding, directory);
        }

        private static RevocationSnapshot CreateRevocations(byte[] network, byte[] account)
        {
            var fields = MinimumFields(RecordDefinitions.Drs1);
            fields[0] = network; fields[1] = account; fields[2] = U64(1);
            fields[3] = U64(1); fields[4] = U64(100); fields[7] = Bytes(0x77, 32);
            return IdentityCodec.DecodeRevocationSnapshot(
                CanonicalGrammar.Encode(RecordDefinitions.Drs1, fields));
        }

        private static ApplicationArtifactReference ArtifactReference(CanonicalIdentityArtifact artifact) =>
            ApplicationCoreCodec.CreateArtifactReference(
                (ushort)artifact.ArtifactType,
                checked((uint)artifact.CanonicalBytes.Length),
                artifact.CanonicalHash.Span);

        private static ReadOnlyMemory<byte>[] MinimumFields(RecordDefinition definition) =>
            definition.Fields.Select(static field =>
                (ReadOnlyMemory<byte>)new byte[field.MinimumLength]).ToArray();
    }
}
#endif
