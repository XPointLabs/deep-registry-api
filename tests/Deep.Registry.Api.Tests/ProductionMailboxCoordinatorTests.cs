using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.DeepExtension.MailboxAuthority;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.MailboxTopology;
using Deep.Protocol.DeepExtension.MembershipRoutes;
using Deep.Registry.Api.ProductionMailbox;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Hosting;
using Sodium;

namespace Deep.Registry.Api.Tests;

public sealed class ProductionMailboxCoordinatorTests
{
    [Fact]
    public async Task AnonymousBaseIssuance_IsCanonicalIdempotentAndBindsCurrentNext()
    {
        using var fixture = Fixture.Create();
        var state = new InMemoryProductionMailboxStateStore();
        using var signer = new DevelopmentSoftwareEd25519Signer(fixture.IssuerSeedPath);
        var coordinator = fixture.Coordinator(state, signer);
        var request = await fixture.RequestAsync(coordinator);
        var first = await coordinator.IssueAsync(request, CancellationToken.None);
        var secondRequest = await fixture.RequestAsync(coordinator);
        var second = await coordinator.IssueAsync(secondRequest, CancellationToken.None);

        Assert.Equal("production-mailbox-credential-bundle.v1", first.Schema);
        Assert.False(first.Limits.Entitled);
        Assert.Equal(64UL * 1024 * 1024, first.Limits.StoredBytes);
        Assert.Equal(first.IdempotencyKey, second.IdempotencyKey);
        Assert.Equal(first.Selections.Select(x => x.CanonicalBase64Url),
            second.Selections.Select(x => x.CanonicalBase64Url));
        Assert.Equal(first.Grants.Select(x => x.CanonicalBase64Url),
            second.Grants.Select(x => x.CanonicalBase64Url));
        Assert.Equal(2, first.Selections.Count);
        Assert.Equal(2, first.Grants.Count);
        Assert.Equal(ProductionMailboxIssuanceIntent.LocalOwner, first.Intent);
        Assert.All(first.Grants, grant => Assert.Equal("retrieve", grant.Domain));
        foreach (var artifact in new[] { first.Authority, first.Revocation, first.Topology })
        {
            var canonical = Decode(artifact.CanonicalBase64Url);
            Assert.Equal(artifact.Sha256, Convert.ToHexStringLower(SHA256.HashData(canonical)));
            Assert.Equal($"/api/production-mailbox/artifacts/{artifact.Sha256}/{artifact.FileName}",
                artifact.ContentPath);
        }

        foreach (var selection in first.Selections)
        {
            Assert.Equal(2, selection.Replicas.Count);
            Assert.All(selection.Replicas, replica => Assert.NotEqual(
                replica.CurrentSpkiSha256, replica.NextSpkiSha256));
            var canonical = Decode(selection.CanonicalBase64Url);
            var verified = ProductionMailboxSelectionVerifier.Verify(
                canonical, fixture.Artifacts.Authority, fixture.Artifacts.Topology,
                new BlindedPlacementId(Decode(first.BlindedPlacementId)), Fixture.Now, 0,
                new SodiumProductionMailboxTopologySignatureVerifier());
            Assert.Equal(2, verified.Replicas.Count);
        }
        foreach (var grantEnvelope in first.Grants)
        {
            var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(
                Decode(grantEnvelope.CanonicalBase64Url));
            Assert.Equal(fixture.HolderPublicKey, grant.HolderPublicKey.ToArray());
            Assert.Equal(MailboxPlacementCommitment.Compute(
                new BlindedPlacementId(Decode(first.BlindedPlacementId))), grant.PlacementCommitment.ToArray());
            Assert.True(new SodiumMailboxCapabilityCrypto().VerifyIssuer(
                fixture.IssuerPublicKey,
                MailboxAuthenticatedCapabilityCodec.GetGrantSigningBytes(grant),
                grant.IssuerSignature.Span));
        }
        var counters = coordinator.GetCounters();
        Assert.Equal(1, counters.BundlesIssued);
        Assert.Equal(1, counters.BundlesReplayed);
        var responseJson = System.Text.Json.JsonSerializer.Serialize(first);
        Assert.DoesNotContain(request.Challenge, responseJson, StringComparison.Ordinal);
        Assert.DoesNotContain(request.HolderProofSignature, responseJson, StringComparison.Ordinal);
        Assert.DoesNotContain(request.SigningCertificateSha256, responseJson, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ConcurrentIssuance_ReturnsOneDeterministicOutcome()
    {
        using var fixture = Fixture.Create(maximumChallenges: 32);
        var state = new InMemoryProductionMailboxStateStore();
        using var signer = new DevelopmentSoftwareEd25519Signer(fixture.IssuerSeedPath);
        var coordinator = fixture.Coordinator(state, signer);
        var requests = new List<ProductionMailboxIssueRequest>();
        for (var index = 0; index < 12; index++) requests.Add(await fixture.RequestAsync(coordinator));
        var bundles = await Task.WhenAll(requests.Select(request =>
            coordinator.IssueAsync(request, CancellationToken.None).AsTask()));
        Assert.Single(bundles.Select(bundle => bundle.IdempotencyKey).Distinct(StringComparer.Ordinal));
        Assert.Single(bundles.Select(bundle => bundle.Grants[0].CanonicalBase64Url).Distinct(StringComparer.Ordinal));
        Assert.Equal(1, coordinator.GetCounters().BundlesIssued);
        Assert.Equal(11, coordinator.GetCounters().BundlesReplayed);
    }

    [Fact]
    public async Task SelectionAttestationChallengeRevocationAndSignerFailures_FailClosed()
    {
        using var fixture = Fixture.Create();
        var state = new InMemoryProductionMailboxStateStore();
        using var signer = new DevelopmentSoftwareEd25519Signer(fixture.IssuerSeedPath);
        var coordinator = fixture.Coordinator(state, signer);

        var mismatch = await fixture.RequestAsync(coordinator);
        mismatch = mismatch with { SelectionInputCommitment = B64(Fixture.Bytes(220, 32)) };
        Assert.Equal(ProductionMailboxIssueError.InvalidHolderProof,
            (await Assert.ThrowsAsync<ProductionMailboxIssueException>(() =>
                coordinator.IssueAsync(mismatch, CancellationToken.None).AsTask())).Error);

        var badAttestation = await fixture.RequestAsync(coordinator);
        badAttestation = fixture.Resign(badAttestation with { BuildArtifactSha256 = B64(Fixture.Bytes(221, 32)) });
        var metadataOnly = await coordinator.IssueAsync(badAttestation, CancellationToken.None);
        Assert.Equal(badAttestation.HolderEd25519PublicKey, metadataOnly.HolderEd25519PublicKey);

        var consumed = await fixture.RequestAsync(coordinator);
        _ = await coordinator.IssueAsync(consumed, CancellationToken.None);
        Assert.Equal(ProductionMailboxIssueError.InvalidChallenge,
            (await Assert.ThrowsAsync<ProductionMailboxIssueException>(() =>
                coordinator.IssueAsync(consumed, CancellationToken.None).AsTask())).Error);

        await coordinator.RevokeHolderAsync(fixture.HolderPublicKey, CancellationToken.None);
        var revoked = await fixture.RequestAsync(coordinator);
        Assert.Equal(ProductionMailboxIssueError.Revoked,
            (await Assert.ThrowsAsync<ProductionMailboxIssueException>(() =>
                coordinator.IssueAsync(revoked, CancellationToken.None).AsTask())).Error);

        var badSignatureCoordinator = fixture.Coordinator(
            new InMemoryProductionMailboxStateStore(), new InvalidSigner());
        var badSignature = await fixture.RequestAsync(badSignatureCoordinator);
        Assert.Equal(ProductionMailboxIssueError.IssuerUnavailable,
            (await Assert.ThrowsAsync<ProductionMailboxIssueException>(() =>
                badSignatureCoordinator.IssueAsync(badSignature, CancellationToken.None).AsTask())).Error);
    }

    [Fact]
    public async Task PaidEntitlement_IsRejectedUntilNodeEnforcedQuotaExists()
    {
        using var fixture = Fixture.Create();
        using var signer = new DevelopmentSoftwareEd25519Signer(fixture.IssuerSeedPath);
        var coordinator = fixture.Coordinator(new InMemoryProductionMailboxStateStore(), signer);
        var request = await fixture.RequestAsync(coordinator);
        request = fixture.Resign(request with
            { OpaqueEntitlement = B64(Encoding.ASCII.GetBytes("opaque-paid-proof")) });
        Assert.Equal(ProductionMailboxIssueError.InvalidEntitlement,
            (await Assert.ThrowsAsync<ProductionMailboxIssueException>(() =>
                coordinator.IssueAsync(request, CancellationToken.None).AsTask())).Error);
    }

    [Fact]
    public async Task HolderProof_BindsCanonicalIdempotencyAndOpaqueEntitlement()
    {
        using var fixture = Fixture.Create(maximumChallenges: 8);
        using var signer = new DevelopmentSoftwareEd25519Signer(fixture.IssuerSeedPath);
        var coordinator = fixture.Coordinator(new InMemoryProductionMailboxStateStore(), signer);

        var wrongIdempotency = await fixture.RequestAsync(coordinator);
        wrongIdempotency = fixture.SignExact(wrongIdempotency with
            { IdempotencyKey = B64(Fixture.Bytes(201, 32)) });
        Assert.Equal(ProductionMailboxIssueError.InvalidRequest,
            (await Assert.ThrowsAsync<ProductionMailboxIssueException>(() =>
                coordinator.IssueAsync(wrongIdempotency, CancellationToken.None).AsTask())).Error);

        var substituted = await fixture.RequestAsync(coordinator);
        substituted = fixture.Resign(substituted with
            { OpaqueEntitlement = B64(Encoding.ASCII.GetBytes("opaque-paid-proof")) });
        substituted = substituted with
            { OpaqueEntitlement = B64(Encoding.ASCII.GetBytes("substituted-proof")) };
        Assert.Equal(ProductionMailboxIssueError.InvalidEntitlement,
            (await Assert.ThrowsAsync<ProductionMailboxIssueException>(() =>
                coordinator.IssueAsync(substituted, CancellationToken.None).AsTask())).Error);
    }

    [Fact]
    public async Task OwnerBinding_PreventsFirstClaim_AllowsRotation_AndPeerGetsDepositOnly()
    {
        using var fixture = Fixture.Create(maximumChallenges: 32);
        var state = new InMemoryProductionMailboxStateStore();
        using var signer = new DevelopmentSoftwareEd25519Signer(fixture.IssuerSeedPath);
        var coordinator = fixture.Coordinator(state, signer);
        var original = await coordinator.IssueAsync(
            await fixture.RequestAsync(coordinator), CancellationToken.None);

        var rotatedHolder = PublicKeyAuth.GenerateKeyPair(Fixture.Bytes(140, 32));
        var rotation = await fixture.RequestAsync(
            coordinator, ProductionMailboxIssuanceIntent.LocalOwner,
            rotatedHolder.PublicKey, rotatedHolder.PrivateKey,
            fixture.OwnerPublicKey, fixture.OwnerPrivateKey);
        var rotated = await coordinator.IssueAsync(rotation, CancellationToken.None);
        Assert.Equal(original.BlindedMailboxId, rotated.BlindedMailboxId);
        Assert.Equal(original.BlindedPlacementId, rotated.BlindedPlacementId);
        Assert.All(rotated.Grants, grant => Assert.Equal(
            rotatedHolder.PublicKey,
            MailboxAuthenticatedCapabilityCodec.DecodeGrant(Decode(grant.CanonicalBase64Url))
                .HolderPublicKey.ToArray()));

        var attackerHolder = PublicKeyAuth.GenerateKeyPair(Fixture.Bytes(150, 32));
        var attackerOwner = PublicKeyAuth.GenerateKeyPair(Fixture.Bytes(160, 32));
        var attackerRequest = await fixture.RequestAsync(
            coordinator, ProductionMailboxIssuanceIntent.LocalOwner,
            attackerHolder.PublicKey, attackerHolder.PrivateKey,
            attackerOwner.PublicKey, attackerOwner.PrivateKey);
        var attackerBundle = await coordinator.IssueAsync(attackerRequest, CancellationToken.None);
        Assert.NotEqual(original.BlindedMailboxId, attackerBundle.BlindedMailboxId);
        Assert.NotEqual(original.BlindedPlacementId, attackerBundle.BlindedPlacementId);

        var peer = await fixture.RequestAsync(
            coordinator, ProductionMailboxIssuanceIntent.PeerDeposit,
            attackerHolder.PublicKey, attackerHolder.PrivateKey,
            fixture.OwnerPublicKey, null);
        Assert.Equal(ProductionMailboxIssueError.RouteAdvertisementRequired,
            (await Assert.ThrowsAsync<ProductionMailboxIssueException>(() =>
                coordinator.IssueAsync(peer, CancellationToken.None).AsTask())).Error);

        var intentReplay = peer with { Intent = ProductionMailboxIssuanceIntent.LocalOwner };
        Assert.Equal(ProductionMailboxIssueError.InvalidHolderProof,
            (await Assert.ThrowsAsync<ProductionMailboxIssueException>(() =>
                coordinator.IssueAsync(intentReplay, CancellationToken.None).AsTask())).Error);

        await coordinator.RevokeHolderAsync(fixture.HolderPublicKey, CancellationToken.None);
        var afterRevocation = await fixture.RequestAsync(
            coordinator, ProductionMailboxIssuanceIntent.LocalOwner,
            rotatedHolder.PublicKey, rotatedHolder.PrivateKey,
            fixture.OwnerPublicKey, fixture.OwnerPrivateKey);
        _ = await coordinator.IssueAsync(afterRevocation, CancellationToken.None);
    }

    [Fact]
    public void ProductionComposition_RejectsSoftwareSignerAndMissingSocket()
    {
        using var fixture = Fixture.Create();
        var software = fixture.OptionsDictionary();
        software["ProductionMailbox:DevelopmentSoftwareSignerSeedPath"] = fixture.IssuerSeedPath;
        software["ProductionMailbox:ExternalSignerSocketPath"] = "";
        Assert.True(Assert.ThrowsAny<Exception>(() => ResolveSigner(software))
            is InvalidOperationException or PlatformNotSupportedException);

        var missing = fixture.OptionsDictionary();
        missing["ProductionMailbox:DevelopmentSoftwareSignerSeedPath"] = "";
        missing["ProductionMailbox:ExternalSignerSocketPath"] = "";
        Assert.True(Assert.ThrowsAny<Exception>(() => ResolveSigner(missing))
            is InvalidOperationException or PlatformNotSupportedException);
    }

    [Fact]
    public void ArtifactLoad_RejectsStaleOrTamperedClosure()
    {
        using var fixture = Fixture.Create();
        var stale = new FixedTimeProvider(DateTimeOffset.FromUnixTimeSeconds(
            checked((long)Fixture.Now + 10_000)));
        Assert.ThrowsAny<Exception>(() => ProductionMailboxArtifacts.Load(fixture.Options, stale));
        var bytes = File.ReadAllBytes(fixture.Options.TopologyPath);
        bytes[^1] ^= 1;
        File.WriteAllBytes(fixture.Options.TopologyPath, bytes);
        Assert.Throws<ProductionMailboxTopologyException>(() =>
            ProductionMailboxArtifacts.Load(fixture.Options, fixture.TimeProvider));
    }

    [Fact]
    public async Task ArtifactFreshness_IsCheckedPerRequestBeforeIssuerUse()
    {
        using var fixture = Fixture.Create();
        var signer = new CountingSigner();
        var coordinator = fixture.Coordinator(new InMemoryProductionMailboxStateStore(), signer);
        var request = await fixture.RequestAsync(coordinator);
        fixture.TimeProvider.Set(Fixture.Now + 2_000);

        Assert.Equal(ProductionMailboxIssueError.IssuerUnavailable,
            (await Assert.ThrowsAsync<ProductionMailboxIssueException>(() =>
                coordinator.IssueAsync(request, CancellationToken.None).AsTask())).Error);
        Assert.Equal(0, signer.Calls);
        Assert.Equal(ProductionMailboxIssueError.IssuerUnavailable,
            (await Assert.ThrowsAsync<ProductionMailboxIssueException>(() =>
                coordinator.CreateChallengeAsync(CancellationToken.None).AsTask())).Error);
    }

    [Fact]
    public async Task IssueReloadInterleaving_RetainsExactContentAddressedClosure()
    {
        using var first = Fixture.Create();
        using var second = Fixture.Create(artifactSeedOffset: 1);
        var provider = new ProductionMailboxArtifactProvider(first.Options, first.TimeProvider);
        using var signer = new DevelopmentSoftwareEd25519Signer(first.IssuerSeedPath);
        var coordinator = new ProductionMailboxCoordinator(
            Microsoft.Extensions.Options.Options.Create(first.Options), provider.Current, signer,
            new InMemoryProductionMailboxStateStore(), first.TimeProvider,
            new ProductionMailboxMetrics());
        var request = await first.RequestAsync(coordinator);
        var oldAuthorityHash = Convert.ToHexStringLower(first.Artifacts.AuthoritySha256);

        provider.PublishVerified(second.Artifacts, Fixture.Now);
        var bundle = await coordinator.IssueAsync(request, CancellationToken.None);

        Assert.Equal(oldAuthorityHash, bundle.Authority.Sha256);
        Assert.Equal(first.Artifacts.AuthorityBytes, Decode(bundle.Authority.CanonicalBase64Url));
        Assert.True(provider.TryGetArtifact(oldAuthorityHash, "authority.pma1",
            out var retained, out var mediaType));
        Assert.Equal(first.Artifacts.AuthorityBytes, retained);
        Assert.Equal(ProductionMailboxMediaTypes.Authority, mediaType);
        Assert.NotEqual(oldAuthorityHash,
            Convert.ToHexStringLower(provider.Current.AuthoritySha256));
    }

    [Fact]
    public void ArtifactCatalog_RejectsReloadBeforeEvictingAnUnexpiredClosure()
    {
        using var first = Fixture.Create();
        using var second = Fixture.Create(artifactSeedOffset: 1);
        first.Options.MaximumRetainedArtifactClosures = 1;
        var provider = new ProductionMailboxArtifactProvider(first.Options, first.TimeProvider);

        Assert.Throws<InvalidOperationException>(() =>
            provider.PublishVerified(second.Artifacts, Fixture.Now));
        Assert.Equal(first.Artifacts.AuthoritySha256, provider.Current.AuthoritySha256);
    }

    [Fact]
    public async Task HttpArtifacts_UseExactMediaTypeAndEtag_WhileAdminIsPrivate()
    {
        using var fixture = Fixture.Create();
        using var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment(Environments.Development);
            builder.UseSetting("ProductionMailbox:Enabled", "true");
            builder.ConfigureAppConfiguration((_, configuration) =>
                configuration.AddInMemoryCollection(fixture.OptionsDictionary()));
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<TimeProvider>();
                services.AddSingleton<TimeProvider>(fixture.TimeProvider);
            });
        });
        using var client = factory.CreateClient();
        var authorityHash = Convert.ToHexStringLower(fixture.Artifacts.AuthoritySha256);
        var authorityPath = $"/api/production-mailbox/artifacts/{authorityHash}/authority.pma1";
        using var first = await client.GetAsync(authorityPath);
        Assert.Equal(System.Net.HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(ProductionMailboxMediaTypes.Authority, first.Content.Headers.ContentType?.MediaType);
        Assert.NotNull(first.Headers.ETag);
        using var cached = new HttpRequestMessage(HttpMethod.Get,
            authorityPath);
        cached.Headers.IfNoneMatch.Add(first.Headers.ETag!);
        using var notModified = await client.SendAsync(cached);
        Assert.Equal(System.Net.HttpStatusCode.NotModified, notModified.StatusCode);
        using var mutableAlias = await client.GetAsync(
            "/api/production-mailbox/artifacts/authority.pma1");
        Assert.Equal(System.Net.HttpStatusCode.NotFound, mutableAlias.StatusCode);
        using var admin = await client.GetAsync("/api/internal/production-mailbox/runtime");
        Assert.Equal(System.Net.HttpStatusCode.Unauthorized, admin.StatusCode);
        fixture.TimeProvider.Set(Fixture.Now + 2_000);
        using var unavailable = await client.PostAsync(
            "/api/production-mailbox/challenges", content: null);
        Assert.Equal(System.Net.HttpStatusCode.ServiceUnavailable, unavailable.StatusCode);
    }

    private static IEd25519ExternalSigner ResolveSigner(Dictionary<string, string?> values)
    {
        var configuration = new Microsoft.Extensions.Configuration.ConfigurationBuilder()
            .AddInMemoryCollection(values).Build();
        var services = new Microsoft.Extensions.DependencyInjection.ServiceCollection();
        services.AddSingleton<TimeProvider>(TimeProvider.System);
        _ = services.AddProductionMailbox(configuration, new FakeEnvironment("Production"));
        using var provider = services.BuildServiceProvider();
        return provider.GetRequiredService<IEd25519ExternalSigner>();
    }

    private sealed class FakeEnvironment(string name) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = name;
        public string ApplicationName { get; set; } = "tests";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }

    private sealed class InvalidSigner : IEd25519ExternalSigner
    {
        public ValueTask<byte[]> SignAsync(ReadOnlyMemory<byte> signingBytes, CancellationToken cancellationToken) =>
            ValueTask.FromResult(Fixture.Bytes(230, 64));
    }

    private sealed class CountingSigner : IEd25519ExternalSigner
    {
        private int calls;
        public int Calls => Volatile.Read(ref calls);
        public ValueTask<byte[]> SignAsync(
            ReadOnlyMemory<byte> signingBytes,
            CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref calls);
            return ValueTask.FromResult(Fixture.Bytes(230, 64));
        }
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        private long unixSeconds = now.ToUnixTimeSeconds();
        public override DateTimeOffset GetUtcNow() =>
            DateTimeOffset.FromUnixTimeSeconds(Interlocked.Read(ref unixSeconds));
        public void Set(ulong value) => Interlocked.Exchange(ref unixSeconds, checked((long)value));
    }

    private sealed class Fixture : IDisposable
    {
        public const ulong Now = 2_100_000_000;
        private readonly string root;
        private Fixture(string root, ProductionMailboxOptions options, FixedTimeProvider timeProvider,
            ProductionMailboxArtifacts artifacts, byte[] issuerPublicKey, byte[] holderPublicKey,
            byte[] holderPrivateKey, byte[] ownerPublicKey, byte[] ownerPrivateKey,
            int maximumChallenges)
        {
            this.root = root; Options = options; TimeProvider = timeProvider; Artifacts = artifacts;
            IssuerPublicKey = issuerPublicKey; HolderPublicKey = holderPublicKey;
            HolderPrivateKey = holderPrivateKey; OwnerPublicKey = ownerPublicKey;
            OwnerPrivateKey = ownerPrivateKey; MaximumChallenges = maximumChallenges;
            IssuerSeedPath = Path.Combine(root, "issuer.seed");
        }

        public ProductionMailboxOptions Options { get; }
        public FixedTimeProvider TimeProvider { get; }
        public ProductionMailboxArtifacts Artifacts { get; }
        public byte[] IssuerPublicKey { get; }
        public byte[] HolderPublicKey { get; }
        public byte[] HolderPrivateKey { get; }
        public byte[] OwnerPublicKey { get; }
        public byte[] OwnerPrivateKey { get; }
        public string IssuerSeedPath { get; }
        public int MaximumChallenges { get; }

        public static Fixture Create(int maximumChallenges = 16, byte artifactSeedOffset = 0)
        {
            var root = Path.Combine(Path.GetTempPath(), "deep-pma-tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(root);
            var proofRoot = Path.Combine(root, "proofs"); Directory.CreateDirectory(proofRoot);
            var issuerSeed = Bytes(unchecked((byte)(30 + artifactSeedOffset)), 32);
            var issuer = PublicKeyAuth.GenerateKeyPair(issuerSeed);
            var mrX = PublicKeyAuth.GenerateKeyPair(Bytes(unchecked((byte)(60 + artifactSeedOffset)), 32));
            var holder = PublicKeyAuth.GenerateKeyPair(Bytes(unchecked((byte)(90 + artifactSeedOffset)), 32));
            var owner = PublicKeyAuth.GenerateKeyPair(Bytes(unchecked((byte)(100 + artifactSeedOffset)), 32));
            File.WriteAllBytes(Path.Combine(root, "issuer.seed"), issuerSeed);
            var current = Descriptors(9, Now - 200, Now + 1_000);
            var next = Descriptors(10, Now - 10, Now + 1_200);
            var draft = Authority(issuer.PublicKey, mrX.PublicKey,
                MembershipRouteDescriptorCodec.ComputeRoot(current),
                MembershipRouteDescriptorCodec.ComputeRoot(next));
            var unsignedRevocation = new ProductionMailboxRevocationSnapshot
            {
                NetworkId = draft.NetworkId,
                AuthorityGeneration = draft.AuthorityGeneration,
                AuthorityBindingHash = ProductionMailboxRevocationSnapshotCodec.ComputeAuthorityBindingHash(draft),
                RevocationGeneration = draft.Revocation.Generation,
                RevocationHeadHash = draft.Revocation.HeadHash,
                PreviousRevocationHeadHash = draft.Revocation.PreviousHeadHash,
                IssuedAtUnixSeconds = draft.Revocation.IssuedAtUnixSeconds,
                ExpiresAtUnixSeconds = draft.Revocation.ExpiresAtUnixSeconds,
                RevokedGrantSerials = [],
                IssuerSignature = new byte[64]
            };
            var revocation = unsignedRevocation with
            {
                IssuerSignature = PublicKeyAuth.SignDetached(
                    ProductionMailboxRevocationSnapshotCodec.GetSigningBytes(unsignedRevocation), issuer.PrivateKey)
            };
            var revocationBytes = ProductionMailboxRevocationSnapshotCodec.Encode(revocation);
            var authority = SignAuthority(draft with
            {
                Revocation = draft.Revocation with { SnapshotHash = SHA256.HashData(revocationBytes) }
            }, mrX.PrivateKey);
            var authorityBytes = ProductionMailboxAuthorityCodec.Encode(authority);
            var verifiedAuthority = ProductionMailboxAuthorityVerifier.Verify(authority,
                AuthorityContext(authority, mrX.PublicKey), new SodiumProductionMailboxAuthoritySignatureVerifier());
            var topology = new ProductionMailboxTopologySnapshot
            {
                NetworkId = authority.NetworkId,
                AuthorityGeneration = authority.AuthorityGeneration,
                CanonicalAuthorityHash = verifiedAuthority.CanonicalAuthorityHash,
                TopologyGeneration = 3,
                PreviousTopologyHash = Bytes(120, 32),
                IssuedAtUnixSeconds = Now - 5,
                ExpiresAtUnixSeconds = Now + 500,
                CurrentEpoch = TopologyEpoch(authority.CurrentEpoch, current),
                NextEpoch = TopologyEpoch(authority.NextEpoch, next),
                IssuerSignature = new byte[64]
            };
            topology = SignTopology(topology, issuer.PrivateKey);
            var topologyBytes = ProductionMailboxTopologyCodec.Encode(topology);
            WriteProofs(proofRoot, current); WriteProofs(proofRoot, next);
            var authorityPath = Path.Combine(root, "authority.pma1"); File.WriteAllBytes(authorityPath, authorityBytes);
            var revocationPath = Path.Combine(root, "revocations.pmr1"); File.WriteAllBytes(revocationPath, revocationBytes);
            var topologyPath = Path.Combine(root, "topology.pmt1"); File.WriteAllBytes(topologyPath, topologyBytes);
            var options = new ProductionMailboxOptions
            {
                Enabled = true, AuthorityPath = authorityPath, RevocationPath = revocationPath,
                TopologyPath = topologyPath, MembershipProofDirectory = proofRoot,
                PinnedMrXPublicKeySha256 = Hex(SHA256.HashData(mrX.PublicKey)),
                ExpectedNetworkId = Hex(authority.NetworkId.Span),
                PreviousAuthorityGeneration = 6, PreviousAuthorityHash = Hex(authority.PreviousAuthorityHash.Span),
                PreviousRevocationGeneration = 5, PreviousRevocationHeadHash = Hex(authority.Revocation.PreviousHeadHash.Span),
                PreviousRevocationSnapshotHash = Hex(Bytes(23, 32)),
                PreviousTopologyGeneration = 2, PreviousTopologyHash = Hex(topology.PreviousTopologyHash.Span),
                ClockSkewSeconds = 0, SelectionLifetimeSeconds = 300, ChallengeLifetimeSeconds = 300,
                ProofOfWorkLeadingZeroBits = 8, MaximumChallengesPerWindow = maximumChallenges,
                ChallengeWindowSeconds = 60, UseDevelopmentInMemoryState = true,
                DevelopmentSoftwareSignerSeedPath = Path.Combine(root, "issuer.seed")
            };
            var time = new FixedTimeProvider(DateTimeOffset.FromUnixTimeSeconds(checked((long)Now)));
            var artifacts = ProductionMailboxArtifacts.Load(options, time);
            return new Fixture(root, options, time, artifacts, issuer.PublicKey,
                holder.PublicKey, holder.PrivateKey, owner.PublicKey, owner.PrivateKey,
                maximumChallenges);
        }

        public ProductionMailboxCoordinator Coordinator(
            IProductionMailboxStateStore state,
            IEd25519ExternalSigner signer) => new(
                Microsoft.Extensions.Options.Options.Create(Options), Artifacts, signer, state,
                TimeProvider, new ProductionMailboxMetrics());

        public Task<ProductionMailboxIssueRequest> RequestAsync(ProductionMailboxCoordinator coordinator) =>
            RequestAsync(coordinator, ProductionMailboxIssuanceIntent.LocalOwner,
                HolderPublicKey, HolderPrivateKey, OwnerPublicKey, OwnerPrivateKey);

        public async Task<ProductionMailboxIssueRequest> RequestAsync(
            ProductionMailboxCoordinator coordinator,
            ProductionMailboxIssuanceIntent intent,
            byte[] holderPublicKey,
            byte[] holderPrivateKey,
            byte[] ownerPublicKey,
            byte[]? ownerPrivateKey)
        {
            var challenge = await coordinator.CreateChallengeAsync(CancellationToken.None);
            var id = Decode(challenge.ChallengeId); var value = Decode(challenge.Challenge);
            var nonce = Solve(id, value, challenge.LeadingZeroBits);
            var route = DeriveOwnerRoute(ownerPublicKey);
            var mailbox = intent == ProductionMailboxIssuanceIntent.LocalOwner ? "" : B64(route.MailboxId);
            var placement = intent == ProductionMailboxIssuanceIntent.LocalOwner ? "" : B64(route.PlacementId);
            var selection = intent == ProductionMailboxIssuanceIntent.LocalOwner ? "" : B64(route.SelectionCommitment);
            var certificate = Bytes(15, 32); var artifact = Bytes(17, 32);
            var request = new ProductionMailboxIssueRequest(
                B64(holderPublicKey), B64(ownerPublicKey), intent,
                ProductionMailboxClientPlatform.Android,
                B64(certificate), B64(artifact), "", B64(new byte[32]), mailbox, placement, selection,
                challenge.ChallengeId, challenge.Challenge, nonce,
                "", null, null);
            return Resign(request, holderPrivateKey, ownerPrivateKey);
        }

        public ProductionMailboxIssueRequest Resign(
            ProductionMailboxIssueRequest request,
            byte[]? holderPrivateKey = null,
            byte[]? ownerPrivateKey = null)
        {
            var entitlement = string.IsNullOrEmpty(request.OpaqueEntitlement)
                ? Array.Empty<byte>() : Decode(request.OpaqueEntitlement);
            var entitlementCommitment = entitlement.Length == 0
                ? new byte[32] : SHA256.HashData(entitlement);
            var canonical = request with { EntitlementCommitment = B64(entitlementCommitment) };
            canonical = canonical with { IdempotencyKey = B64(ComputeIdempotencyKey(canonical)) };
            return SignExact(canonical, holderPrivateKey, ownerPrivateKey);
        }

        public ProductionMailboxIssueRequest SignExact(
            ProductionMailboxIssueRequest request,
            byte[]? holderPrivateKey = null,
            byte[]? ownerPrivateKey = null)
        {
            var proof = ProductionMailboxHolderProof.GetSigningBytes(ProofInput(request));
            return request with
            {
                HolderProofSignature = B64(PublicKeyAuth.SignDetached(proof, holderPrivateKey ?? HolderPrivateKey)),
                OwnerProofSignature = request.Intent == ProductionMailboxIssuanceIntent.LocalOwner
                    ? B64(PublicKeyAuth.SignDetached(proof, ownerPrivateKey ?? OwnerPrivateKey)) : null
            };
        }

        private ProductionMailboxHolderProofInput ProofInput(ProductionMailboxIssueRequest request) => new()
        {
            Intent = request.Intent,
            Platform = request.Platform,
            NetworkId = Artifacts.Authority.Authority.NetworkId,
            CanonicalAuthorityHash = Artifacts.AuthoritySha256,
            HolderEd25519PublicKey = Decode(request.HolderEd25519PublicKey),
            MailboxOwnerEd25519PublicKey = Decode(request.MailboxOwnerEd25519PublicKey),
            BlindedMailboxId = string.IsNullOrEmpty(request.BlindedMailboxId) ? new byte[32] : Decode(request.BlindedMailboxId),
            BlindedPlacementId = string.IsNullOrEmpty(request.BlindedPlacementId) ? new byte[32] : Decode(request.BlindedPlacementId),
            SelectionInputCommitment = string.IsNullOrEmpty(request.SelectionInputCommitment) ? new byte[32] : Decode(request.SelectionInputCommitment),
            SigningCertificateSha256 = Decode(request.SigningCertificateSha256),
            BuildArtifactSha256 = Decode(request.BuildArtifactSha256),
            IdempotencyKey = Decode(request.IdempotencyKey),
            EntitlementCommitment = Decode(request.EntitlementCommitment),
            ChallengeId = Decode(request.ChallengeId),
            Challenge = Decode(request.Challenge),
            ProofOfWorkNonce = request.ProofOfWorkNonce
        };

        private byte[] ComputeIdempotencyKey(ProductionMailboxIssueRequest request) => DomainHash(
            "Deep/production-mailbox/issuance-idempotency/v1",
            Artifacts.AuthoritySha256, Artifacts.RevocationSha256, Artifacts.TopologySha256,
            Decode(request.HolderEd25519PublicKey), Decode(request.MailboxOwnerEd25519PublicKey),
            string.IsNullOrEmpty(request.BlindedMailboxId) ? new byte[32] : Decode(request.BlindedMailboxId),
            string.IsNullOrEmpty(request.BlindedPlacementId) ? new byte[32] : Decode(request.BlindedPlacementId),
            string.IsNullOrEmpty(request.SelectionInputCommitment) ? new byte[32] : Decode(request.SelectionInputCommitment),
            [(byte)request.Intent], [(byte)request.Platform], Decode(request.SigningCertificateSha256),
            Decode(request.BuildArtifactSha256), Decode(request.EntitlementCommitment));

        public OwnerRoute DeriveOwnerRoute(byte[] ownerPublicKey)
        {
            var transcript = DomainHash("Deep/production-mailbox/owner-route-prf-input/v1",
                Artifacts.Authority.Authority.NetworkId.ToArray(), Artifacts.AuthoritySha256, ownerPublicKey);
            var issuer = PublicKeyAuth.GenerateKeyPair(File.ReadAllBytes(IssuerSeedPath));
            var issuerOutput = PublicKeyAuth.SignDetached(transcript, issuer.PrivateKey);
            var mailbox = DomainHash("Deep/production-mailbox/blinded-mailbox-id/v1",
                Artifacts.Authority.Authority.NetworkId.ToArray(), ownerPublicKey, issuerOutput);
            var placement = DomainHash("Deep/production-mailbox/blinded-placement-id/v1",
                Artifacts.Authority.Authority.NetworkId.ToArray(), ownerPublicKey, issuerOutput);
            return new OwnerRoute(mailbox, placement,
                ProductionMailboxReplicaSelection.ComputeSelectionInputCommitment(new BlindedPlacementId(placement)));
        }

        public Dictionary<string, string?> OptionsDictionary() => new()
        {
            ["ProductionMailbox:Enabled"] = "true",
            ["ProductionMailbox:UseDevelopmentInMemoryState"] = "true",
            ["ProductionMailbox:AuthorityPath"] = Options.AuthorityPath,
            ["ProductionMailbox:RevocationPath"] = Options.RevocationPath,
            ["ProductionMailbox:TopologyPath"] = Options.TopologyPath,
            ["ProductionMailbox:MembershipProofDirectory"] = Options.MembershipProofDirectory,
            ["ProductionMailbox:PinnedMrXPublicKeySha256"] = Options.PinnedMrXPublicKeySha256,
            ["ProductionMailbox:ExpectedNetworkId"] = Options.ExpectedNetworkId,
            ["ProductionMailbox:PreviousAuthorityGeneration"] = Options.PreviousAuthorityGeneration.ToString(),
            ["ProductionMailbox:PreviousAuthorityHash"] = Options.PreviousAuthorityHash,
            ["ProductionMailbox:PreviousRevocationGeneration"] = Options.PreviousRevocationGeneration.ToString(),
            ["ProductionMailbox:PreviousRevocationHeadHash"] = Options.PreviousRevocationHeadHash,
            ["ProductionMailbox:PreviousRevocationSnapshotHash"] = Options.PreviousRevocationSnapshotHash,
            ["ProductionMailbox:PreviousTopologyGeneration"] = Options.PreviousTopologyGeneration.ToString(),
            ["ProductionMailbox:PreviousTopologyHash"] = Options.PreviousTopologyHash,
            ["ProductionMailbox:ClockSkewSeconds"] = "0",
            ["ProductionMailbox:SelectionLifetimeSeconds"] = Options.SelectionLifetimeSeconds.ToString(),
            ["ProductionMailbox:ChallengeLifetimeSeconds"] = Options.ChallengeLifetimeSeconds.ToString(),
            ["ProductionMailbox:ProofOfWorkLeadingZeroBits"] = Options.ProofOfWorkLeadingZeroBits.ToString(),
            ["ProductionMailbox:MaximumChallengesPerWindow"] = Options.MaximumChallengesPerWindow.ToString(),
            ["ProductionMailbox:ChallengeWindowSeconds"] = Options.ChallengeWindowSeconds.ToString(),
            ["ProductionMailbox:DevelopmentSoftwareSignerSeedPath"] = Options.DevelopmentSoftwareSignerSeedPath
        };

        public void Dispose()
        {
            if (Directory.Exists(root)) Directory.Delete(root, true);
        }

        private static ProductionMailboxAuthority Authority(byte[] issuer, byte[] mrX, byte[] currentRoot, byte[] nextRoot) => new()
        {
            DevelopmentOnly = false, Environment = ProductionMailboxAuthorityEnvironment.Production,
            Transport = ProductionMailboxAuthorityTransport.AuthenticatedMau2,
            Ownership = ProductionMailboxAuthorityOwnership.OfficialManaged,
            EndpointPolicy = ProductionMailboxAuthorityEndpointPolicy.PublicHttpsOnly,
            NetworkId = Bytes(1, 16), AuthorityGeneration = 7, PreviousAuthorityHash = Bytes(2, 32),
            MailboxIssuerEd25519PublicKey = issuer, MrXApprovalEd25519PublicKey = mrX,
            Coordinator = Endpoint("https://coord.example.net/", 4),
            NodeIngress = Endpoint("https://ingress.example.net/mau2/", 6),
            CurrentEpoch = Epoch(9, 70, currentRoot, Bytes(8, 32), Now - 200, Now + 1_000),
            NextEpoch = Epoch(10, 71, nextRoot, Bytes(10, 32), Now - 10, Now + 1_200),
            Revocation = new ProductionMailboxAuthorityRevocation
            {
                SnapshotHash = Bytes(12, 32), HeadHash = Bytes(13, 32), PreviousHeadHash = Bytes(22, 32),
                Generation = 6, IssuedAtUnixSeconds = Now - 20, ExpiresAtUnixSeconds = Now + 800
            },
            MrXApproval = new ProductionMailboxAuthorityApproval
            {
                AuthorityPayloadHash = Bytes(14, 32),
                AllowedAndroidSigningCertificateSha256 = [Bytes(15, 32)],
                AllowedWindowsSigningCertificateSha256 = [Bytes(16, 32)],
                AndroidReleaseBuildArtifactSha256 = [Bytes(17, 32)],
                WindowsReleaseBuildArtifactSha256 = [Bytes(18, 32)],
                RolloutNotBeforeUnixSeconds = Now - 30, RolloutNotAfterUnixSeconds = Now + 800
            }, Signature = new byte[64]
        };

        private static ProductionMailboxAuthorityVerificationContext AuthorityContext(ProductionMailboxAuthority authority, byte[] mrX) => new()
        {
            PinnedMrXPublicKeySha256 = SHA256.HashData(mrX), ExpectedNetworkId = authority.NetworkId,
            LastCommittedGeneration = 6, LastCommittedAuthorityHash = authority.PreviousAuthorityHash,
            LastCommittedRevocationGeneration = 5, LastCommittedRevocationHeadHash = authority.Revocation.PreviousHeadHash,
            LastCommittedRevocationSnapshotHash = Bytes(23, 32), NowUnixSeconds = Now, ClockSkewSeconds = 0
        };

        private static ProductionMailboxAuthority SignAuthority(ProductionMailboxAuthority value, byte[] key)
        {
            var bound = value with { MrXApproval = value.MrXApproval with
                { AuthorityPayloadHash = ProductionMailboxAuthorityCodec.ComputePayloadHash(value) }, Signature = new byte[64] };
            return bound with { Signature = PublicKeyAuth.SignDetached(ProductionMailboxAuthorityCodec.GetSigningBytes(bound), key) };
        }
        private static ProductionMailboxTopologySnapshot SignTopology(ProductionMailboxTopologySnapshot value, byte[] key)
        {
            var unsigned = value with { IssuerSignature = new byte[64] };
            return unsigned with { IssuerSignature = PublicKeyAuth.SignDetached(ProductionMailboxTopologyCodec.GetSigningBytes(unsigned), key) };
        }
        private static ProductionMailboxAuthorityEndpoint Endpoint(string uri, byte seed) => new()
            { Uri = uri, CurrentSpkiSha256 = Bytes(seed, 32), NextSpkiSha256 = Bytes((byte)(seed + 1), 32) };
        private static ProductionMailboxAuthorityEpoch Epoch(ulong epoch, ulong generation, byte[] membership, byte[] topologyPlacement, ulong from, ulong until) => new()
            { Epoch = epoch, Generation = generation, MembershipCommitment = membership, TopologyPlacementCommitment = topologyPlacement,
                NotBeforeUnixSeconds = from, NotAfterUnixSeconds = until };
        private static ProductionMailboxTopologyEpoch TopologyEpoch(ProductionMailboxAuthorityEpoch epoch, MembershipRouteDescriptor[] descriptors) => new()
        {
            Epoch = epoch.Epoch, Generation = epoch.Generation, MembershipCommitment = epoch.MembershipCommitment,
            TopologyPlacementCommitment = epoch.TopologyPlacementCommitment,
            NotBeforeUnixSeconds = epoch.NotBeforeUnixSeconds, NotAfterUnixSeconds = epoch.NotAfterUnixSeconds,
            Nodes = descriptors.Select((descriptor, index) => new ProductionMailboxTopologyNode
            {
                NodeId = descriptor.RouterId, HttpsEndpoint = $"https://node-{index + 1}.example.net/",
                CurrentSpkiSha256 = Bytes((byte)(130 + index * 2), 32),
                NextSpkiSha256 = Bytes((byte)(131 + index * 2), 32)
            }).ToArray()
        };
        private static MembershipRouteDescriptor[] Descriptors(ulong epoch, ulong from, ulong until) =>
            [Descriptor(0x10, epoch, from, until), Descriptor(0x40, epoch, from, until), Descriptor(0x70, epoch, from, until)];
        private static MembershipRouteDescriptor Descriptor(int start, ulong epoch, ulong from, ulong until) => new()
        {
            RouterId = Range(start, 32), Ed25519PublicKey = Range(start + 32, 32), X25519PublicKey = Range(start + 64, 32),
            RpcEndpoint = $"https://route-{start}.example.net/", Roles = MembershipRouteRole.Storage,
            Capabilities = MembershipRouteCapability.Storage, Epoch = epoch,
            ValidFromUnixSeconds = from, ValidUntilUnixSeconds = until
        };
        private static void WriteProofs(string root, MembershipRouteDescriptor[] descriptors)
        {
            var proofs = MembershipRouteDescriptorCodec.BuildProofs(descriptors);
            for (var index = 0; index < descriptors.Length; index++)
            {
                var descriptor = descriptors[index];
                var mip = new MailboxReplicaMembershipProof
                {
                    ReplicaId = descriptor.RouterId, SigningPublicKey = descriptor.Ed25519PublicKey,
                    Epoch = descriptor.Epoch, MembershipCommitment = MembershipRouteDescriptorCodec.ComputeRoot(descriptors),
                    CanonicalInclusionProof = MailboxReplicaRouteProofCodec.Encode(descriptor, proofs[index])
                };
                File.WriteAllBytes(Path.Combine(root,
                    $"{descriptor.Epoch}-{Convert.ToHexStringLower(descriptor.RouterId.Span)}.mip1"),
                    MailboxPeerReplicationCodec.EncodeMembershipProof(mip));
            }
        }
        private static ulong Solve(byte[] id, byte[] challenge, int bits)
        {
            var encoded = new byte[8];
            for (ulong nonce = 0; nonce < ulong.MaxValue; nonce++)
            {
                using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                hash.AppendData(Encoding.UTF8.GetBytes("Deep/production-mailbox/pow/v1"));
                hash.AppendData(id); hash.AppendData(challenge);
                BinaryPrimitives.WriteUInt64BigEndian(encoded, nonce); hash.AppendData(encoded);
                var digest = hash.GetHashAndReset();
                var remaining = bits; var valid = true;
                foreach (var value in digest)
                {
                    if (remaining <= 0) break;
                    var required = Math.Min(remaining, 8);
                    if ((value >> (8 - required)) != 0) { valid = false; break; }
                    remaining -= required;
                }
                if (valid) return nonce;
            }
            throw new InvalidOperationException();
        }
        public static byte[] Bytes(byte seed, int length) => Enumerable.Range(0, length).Select(i => unchecked((byte)(seed + i))).ToArray();
        private static byte[] Range(int start, int length) => Enumerable.Range(start, length).Select(i => unchecked((byte)i)).ToArray();
        private static string Hex(ReadOnlySpan<byte> bytes) => Convert.ToHexStringLower(bytes);
        private static byte[] DomainHash(string domain, params byte[][] values)
        {
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            hash.AppendData(Encoding.UTF8.GetBytes(domain));
            foreach (var value in values) hash.AppendData(value);
            return hash.GetHashAndReset();
        }
        public sealed record OwnerRoute(byte[] MailboxId, byte[] PlacementId, byte[] SelectionCommitment);
    }

    private static string B64(ReadOnlySpan<byte> value) => Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    private static byte[] Decode(string value)
    {
        var padded = value.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(padded + new string('=', (4 - padded.Length % 4) % 4));
    }
}
