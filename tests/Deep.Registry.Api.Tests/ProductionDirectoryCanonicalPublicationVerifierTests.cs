#if DEEP_PROTOCOL_DIRECTORY_V1
using System.IO.Compression;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.XPointNetworkV1;
using Deep.Registry.Api.DirectoryPublication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Sodium;

namespace Deep.Registry.Api.Tests;

public sealed class ProductionDirectoryCanonicalPublicationVerifierTests
{
    private static readonly GoldenFixture Fixture = GoldenFixture.Load();

    [Fact]
    public async Task CanonicalExactClosureProducesOnlyVerifiedTerminalArtifacts()
    {
        var candidate = Fixture.Candidate();

        var verified = await Fixture.Verifier().VerifyAsync(candidate.Freeze(), default);

        Assert.Equal(0UL, verified.Generation);
        Assert.Equal(Fixture.Network, verified.NetworkId.ToArray());
        Assert.Equal(3, verified.Artifacts.Count);
        Assert.Equal(candidate.CurrentNetworkView.ToArray(), verified.Artifacts[0].CanonicalBytes.ToArray());
        Assert.Equal(candidate.CurrentNetworkViewHead.ToArray(), verified.Artifacts[1].CanonicalBytes.ToArray());
        Assert.Equal(candidate.CurrentMailboxTopology.ToArray(), verified.Artifacts[2].CanonicalBytes.ToArray());
    }

    [Fact]
    public async Task TamperedCanonicalArtifactIsRejectedByVerifiedProducer()
    {
        var pmt = Fixture.Candidate().CurrentMailboxTopology.ToArray();
        pmt[^1] ^= 1;
        var candidate = Fixture.Candidate(pmt: pmt);

        var error = await Assert.ThrowsAsync<DirectoryCanonicalVerificationException>(async () =>
            await Fixture.Verifier().VerifyAsync(candidate.Freeze(), default));

        Assert.Equal(DirectoryCanonicalVerificationError.CurrentNetworkClosureInvalid, error.Error);
    }

    [Fact]
    public async Task WrongPinnedNetworkIsRejectedBeforeChallengeConsumption()
    {
        var challenge = new ExactChallengeAuthority();
        var verifier = Fixture.Verifier(
            challengeAuthority: challenge,
            network: Enumerable.Repeat((byte)0x21, 16).ToArray());

        var error = await Assert.ThrowsAsync<DirectoryCanonicalVerificationException>(async () =>
            await verifier.VerifyAsync(Fixture.Candidate().Freeze(), default));

        Assert.Equal(DirectoryCanonicalVerificationError.WrongNetwork, error.Error);
        Assert.Equal(0, challenge.Calls);
    }

    [Fact]
    public async Task ExpiredMonotonicFreshnessIsRejected()
    {
        var verifier = Fixture.Verifier(clockSample: 1_095);

        var error = await Assert.ThrowsAsync<DirectoryCanonicalVerificationException>(async () =>
            await verifier.VerifyAsync(Fixture.Candidate().Freeze(), default));

        Assert.Equal(DirectoryCanonicalVerificationError.CurrentNetworkClosureInvalid, error.Error);
    }

    [Fact]
    public async Task SameGenerationPolicyForkIsRejected()
    {
        var policy = Fixture.Bytes("normal", "xvp");
        var candidate = Fixture.Candidate(policyChain: [policy, policy]);

        var error = await Assert.ThrowsAsync<DirectoryCanonicalVerificationException>(async () =>
            await Fixture.Verifier().VerifyAsync(candidate.Freeze(), default));

        Assert.Equal(DirectoryCanonicalVerificationError.CurrentNetworkClosureInvalid, error.Error);
    }

    [Fact]
    public async Task ResetRequiresIndependentProtectedLkg()
    {
        var error = await Assert.ThrowsAsync<DirectoryCanonicalVerificationException>(async () =>
            await Fixture.Verifier().VerifyAsync(Fixture.Candidate(reset: true).Freeze(), default));

        Assert.Equal(DirectoryCanonicalVerificationError.ProtectedNetworkLkgRequired, error.Error);
    }

    [Fact]
    public async Task ResetClosureIsAcceptedOnlyThroughVerifiedResetProducer()
    {
        var candidate = Fixture.Candidate(reset: true);

        var verified = await Fixture.Verifier(
            protectedLkgSource: new FixedProtectedLkgSource(Fixture.ProtectedLkg))
            .VerifyAsync(candidate.Freeze(), default);

        Assert.Equal(2UL, verified.Generation);
        Assert.Equal(5, verified.Artifacts.Count);
        Assert.Equal(candidate.NetworkForwardCheckpoint!.Value.ToArray(),
            verified.Artifacts[3].CanonicalBytes.ToArray());
        Assert.Equal(candidate.NetworkForwardProof!.Value.ToArray(),
            verified.Artifacts[4].CanonicalBytes.ToArray());
    }

    [Fact]
    public async Task ResetWithTamperedProofIsRejected()
    {
        var proof = Fixture.Candidate(reset: true).NetworkForwardProof!.Value.ToArray();
        proof[^1] ^= 1;
        var candidate = Fixture.Candidate(reset: true, resetProof: proof);

        var error = await Assert.ThrowsAsync<DirectoryCanonicalVerificationException>(async () =>
            await Fixture.Verifier(protectedLkgSource: new FixedProtectedLkgSource(Fixture.ProtectedLkg))
                .VerifyAsync(candidate.Freeze(), default));

        Assert.Equal(DirectoryCanonicalVerificationError.ResetClosureInvalid, error.Error);
    }

    [Fact]
    public async Task ResetPublishesCanonicalNfp1CoreHashNotRawArtifactDigest()
    {
        var candidate = Fixture.Candidate(reset: true);

        var verified = await Fixture.Verifier(
            protectedLkgSource: new FixedProtectedLkgSource(Fixture.ProtectedLkg))
            .VerifyAsync(candidate.Freeze(), default);

        var proof = verified.Artifacts.Single(
            static value => value.Kind == DirectoryArtifactKind.NetworkForwardProof);
        var expected = Sha256Domain(
            "Deep/XPoint/V1/NFP1/exact",
            candidate.NetworkForwardProof!.Value.Span);
        Assert.Equal(expected, proof.CoreHash.ToArray());
        Assert.NotEqual(SHA256.HashData(candidate.NetworkForwardProof.Value.Span), proof.CoreHash.ToArray());
    }

    [Fact]
    public async Task TamperedXna1AuthorityRejectsBeforeChallengeConsumption()
    {
        var challenge = new ExactChallengeAuthority();
        var xna = Fixture.AuthorityBytes();
        xna[^1] ^= 1;

        var error = await Assert.ThrowsAsync<DirectoryCanonicalVerificationException>(async () =>
            await Fixture.Verifier(challengeAuthority: challenge)
                .VerifyAsync(Fixture.Candidate(xna: xna).Freeze(), default));

        Assert.Equal(DirectoryCanonicalVerificationError.AuthorityClosureInvalid, error.Error);
        Assert.Equal(0, challenge.Calls);
    }

    [Fact]
    public async Task TamperedDts1AuthorityRejectsBeforeChallengeConsumption()
    {
        var challenge = new ExactChallengeAuthority();
        var dts = Fixture.TimePolicyBytes();
        dts[^1] ^= 1;

        var error = await Assert.ThrowsAsync<DirectoryCanonicalVerificationException>(async () =>
            await Fixture.Verifier(challengeAuthority: challenge)
                .VerifyAsync(Fixture.Candidate(dts: dts).Freeze(), default));

        Assert.Equal(DirectoryCanonicalVerificationError.AuthorityClosureInvalid, error.Error);
        Assert.Equal(0, challenge.Calls);
    }

    [Fact]
    public async Task Dtt1MustBindExactJournaledNonce()
    {
        var error = await Assert.ThrowsAsync<DirectoryCanonicalVerificationException>(async () =>
            await Fixture.Verifier().VerifyAsync(
                Fixture.Candidate(callerNonce: Repeat(0x76, 32)).Freeze(), default));

        Assert.Equal(DirectoryCanonicalVerificationError.FreshnessClosureInvalid, error.Error);
    }

    [Fact]
    public async Task ChallengeAuthorityCannotSubstituteNonceWindow()
    {
        var error = await Assert.ThrowsAsync<DirectoryCanonicalVerificationException>(async () =>
            await Fixture.Verifier(challengeAuthority: new SubstitutingChallengeAuthority())
                .VerifyAsync(Fixture.Candidate().Freeze(), default));

        Assert.Equal(DirectoryCanonicalVerificationError.FreshnessClosureInvalid, error.Error);
    }

    [Fact]
    public async Task TamperedActiveXnd1IsRejected()
    {
        var nodes = Fixture.NodeBytes("normal").Select(static value => value.ToArray()).ToArray();
        nodes[0][^1] ^= 1;

        var error = await Assert.ThrowsAsync<DirectoryCanonicalVerificationException>(async () =>
            await Fixture.Verifier().VerifyAsync(Fixture.Candidate(
                nodes: nodes.Select(static value => (ReadOnlyMemory<byte>)value).ToArray()).Freeze(), default));

        Assert.Equal(DirectoryCanonicalVerificationError.CurrentNetworkClosureInvalid, error.Error);
    }

    [Theory]
    [InlineData("adh")]
    [InlineData("dtt")]
    [InlineData("adp")]
    public async Task TamperedFreshnessArtifactIsRejected(string artifact)
    {
        var baseline = Fixture.Candidate();
        var bytes = artifact switch
        {
            "adh" => baseline.VerificationClosure.ExactDirectoryHead.ToArray(),
            "dtt" => baseline.VerificationClosure.ExactLiveTimeAttestation.ToArray(),
            "adp" => baseline.VerificationClosure.ExactDirectoryProof.ToArray(),
            _ => throw new InvalidOperationException(),
        };
        bytes[^1] ^= 1;
        var candidate = artifact switch
        {
            "adh" => Fixture.Candidate(adh: bytes),
            "dtt" => Fixture.Candidate(dtt: bytes),
            "adp" => Fixture.Candidate(adp: bytes),
            _ => throw new InvalidOperationException(),
        };

        var error = await Assert.ThrowsAsync<DirectoryCanonicalVerificationException>(async () =>
            await Fixture.Verifier().VerifyAsync(candidate.Freeze(), default));

        Assert.Equal(DirectoryCanonicalVerificationError.FreshnessClosureInvalid, error.Error);
    }

    [Theory]
    [InlineData("xnv")]
    [InlineData("xnh")]
    public async Task TamperedNetworkTerminalIsRejected(string artifact)
    {
        var baseline = Fixture.Candidate();
        var bytes = artifact == "xnv"
            ? baseline.CurrentNetworkView.ToArray()
            : baseline.CurrentNetworkViewHead.ToArray();
        bytes[^1] ^= 1;
        var candidate = artifact == "xnv"
            ? Fixture.Candidate(xnv: bytes)
            : Fixture.Candidate(xnh: bytes);

        var error = await Assert.ThrowsAsync<DirectoryCanonicalVerificationException>(async () =>
            await Fixture.Verifier().VerifyAsync(candidate.Freeze(), default));

        Assert.Equal(DirectoryCanonicalVerificationError.CurrentNetworkClosureInvalid, error.Error);
    }

    [Fact]
    public async Task ResetRejectsProtectedLkgRootSubstitution()
    {
        var valid = Fixture.ProtectedLkg;
        var wrongRoot = valid.HeadRoot.ToArray();
        wrongRoot[^1] ^= 1;
        var substituted = new DirectoryPublicationProtectedNetworkLkg(
            valid.NetworkId.Span,
            valid.HeadCoreReference.Span,
            valid.HeadTreeSize,
            wrongRoot,
            valid.ViewCoreReference.Span,
            valid.ViewGeneration,
            valid.AuthorityCoreReference.Span);

        var error = await Assert.ThrowsAsync<DirectoryCanonicalVerificationException>(async () =>
            await Fixture.Verifier(protectedLkgSource: new FixedProtectedLkgSource(substituted))
                .VerifyAsync(Fixture.Candidate(reset: true).Freeze(), default));

        Assert.Equal(DirectoryCanonicalVerificationError.ResetClosureInvalid, error.Error);
    }

    [Fact]
    public void VerifierSurfaceHasNoBooleanOrRawKeyAuthorityInput()
    {
        var constructors = typeof(ProductionDirectoryCanonicalPublicationVerifier)
            .GetConstructors(System.Reflection.BindingFlags.Instance |
                System.Reflection.BindingFlags.Public |
                System.Reflection.BindingFlags.NonPublic);
        var parameters = constructors.SelectMany(static value => value.GetParameters()).ToArray();

        Assert.DoesNotContain(parameters, static value => value.ParameterType == typeof(bool));
        Assert.DoesNotContain(parameters, static value =>
            value.ParameterType == typeof(byte[]) &&
            value.Name?.Contains("key", StringComparison.OrdinalIgnoreCase) == true);
        Assert.DoesNotContain(parameters, static value =>
            value.ParameterType == typeof(DirectoryPublicationProtectedNetworkLkg));
        Assert.Equal(typeof(ValueTask<VerifiedDirectoryPublication>),
            typeof(IDirectoryCanonicalPublicationVerifier).GetMethod(nameof(IDirectoryCanonicalPublicationVerifier.VerifyAsync))!
                .ReturnType);
    }

    [Fact]
    public async Task FileBackedContactResolveSourceReturnsVerifiedNonMembershipMaterial()
    {
        using var store = FileArtifactStore.Create(Fixture);
        using var source = store.Source();

        var snapshot = await source.ReadAsync(store.Request, default);
        var proof = await source.ReadAsync(snapshot, store.Request, default);

        Assert.Equal(Fixture.Network, snapshot.NetworkId.ToArray());
        Assert.Equal(AccountDirectoryAdp1ResultKind.NonMembership, proof.ResultKind);
        Assert.Equal(Fixture.Candidate().VerificationClosure.QueriedDirectoryLeafKey.ToArray(),
            proof.QueriedDirectoryLeafKey.ToArray());
        Assert.True(File.Exists(store.StatePath));
        Assert.Single(Directory.GetFiles(store.OperationPath, "inventory.json"));
    }

    [Fact]
    public async Task ProductionFileSourceReissuesLiveFreshnessFromImmutableBootstrap()
    {
        using var store = FileArtifactStore.Create(Fixture);
        using var custody = new FixtureProductionWitnessCustody();
        using var source = store.Source(
            new FixedContactResolveTrustedTime(
                205, Repeat(0xd1, 16), 5_000),
            custody);

        var snapshot = await source.ReadAsync(store.Request, default);
        var proof = await source.ReadAsync(snapshot, store.Request, default);

        Assert.Equal(Fixture.Network, snapshot.NetworkId.ToArray());
        Assert.Equal(AccountDirectoryAdp1ResultKind.NonMembership, proof.ResultKind);
        Assert.True(File.Exists(store.StatePath));
    }

    [Fact]
    public async Task FileBackedContactResolveSourceRejectsTamperedArtifact()
    {
        using var store = FileArtifactStore.Create(Fixture);
        var path = store.ArtifactPath("xnh1", 0);
        var tampered = File.ReadAllBytes(path);
        tampered[^1] ^= 1;
        File.WriteAllBytes(path, tampered);
        using var source = store.Source();

        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await source.ReadAsync(store.Request, default));

        Assert.False(File.Exists(store.StatePath));
    }

    [Fact]
    public async Task FileBackedContactResolveSourceRejectsToctouMutationOnFinalReread()
    {
        using var store = FileArtifactStore.Create(Fixture);
        var path = store.ArtifactPath("response-adp1", 0);
        using var source = store.Source(new MutatingContactResolveTrustedTime(() =>
        {
            var changed = File.ReadAllBytes(path);
            changed[^1] ^= 1;
            File.WriteAllBytes(path, changed);
        }));

        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await source.ReadAsync(store.Request, default));

        Assert.False(File.Exists(store.StatePath));
    }

    [Fact]
    public async Task FileBackedContactResolveSourceRejectsReplayedTrustedTimeInterval()
    {
        using var store = FileArtifactStore.Create(Fixture);
        using var source = store.Source(observedUnixTime: 250);

        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await source.ReadAsync(store.Request, default));

        Assert.False(File.Exists(store.StatePath));
    }

    [Fact]
    public async Task FileBackedContactResolveSourceRejectsProtectedRollback()
    {
        using var store = FileArtifactStore.Create(Fixture);
        using (var source = store.Source())
            _ = await source.ReadAsync(store.Request, default);

        var encoded = File.ReadAllBytes(store.StatePath);
        var payload = DirectoryPublicationProtectedFile.Verify(encoded, store.IntegrityKey).ToArray();
        BinaryPrimitives.WriteUInt64BigEndian(payload.AsSpan(22), 1);
        File.WriteAllBytes(store.StatePath,
            DirectoryPublicationProtectedFile.Protect(payload, store.IntegrityKey));
        using var restarted = store.Source();

        var error = await Assert.ThrowsAsync<CryptographicException>(async () =>
            await restarted.ReadAsync(store.Request, default));

        Assert.Contains("rollback", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task FileBackedContactResolveSourceLatchesSameGenerationFork()
    {
        using var store = FileArtifactStore.Create(Fixture);
        using (var source = store.Source())
            _ = await source.ReadAsync(store.Request, default);

        var encoded = File.ReadAllBytes(store.StatePath);
        var payload = DirectoryPublicationProtectedFile.Verify(encoded, store.IntegrityKey).ToArray();
        payload[30] ^= 1;
        File.WriteAllBytes(store.StatePath,
            DirectoryPublicationProtectedFile.Protect(payload, store.IntegrityKey));
        using var restarted = store.Source();

        var fork = await Assert.ThrowsAsync<CryptographicException>(async () =>
            await restarted.ReadAsync(store.Request, default));
        var latched = DirectoryPublicationProtectedFile.Verify(
            File.ReadAllBytes(store.StatePath), store.IntegrityKey);

        Assert.Contains("fork", fork.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(1, latched[^1]);
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await restarted.ReadAsync(store.Request, default));
    }

    [Fact]
    public async Task FileBackedContactResolveSourceRejectsInventoryPathTraversal()
    {
        using var store = FileArtifactStore.Create(Fixture);
        store.RewriteInventory(entry => entry.Role == "response-adp1"
            ? entry with { FileName = "../outside.bin" }
            : entry);
        using var source = store.Source();

        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await source.ReadAsync(store.Request, default));
    }

    [Fact]
    public async Task FileBackedContactResolveSourceRejectsReparseArtifactWhenSupported()
    {
        using var store = FileArtifactStore.Create(Fixture);
        var path = store.ArtifactPath("response-adp1", 0);
        var outside = Path.Combine(store.ParentPath, "outside-adp1.bin");
        File.Move(path, outside);
        try
        {
            File.CreateSymbolicLink(path, outside);
        }
        catch (Exception exception) when (exception is UnauthorizedAccessException or
            PlatformNotSupportedException or IOException)
        {
            return;
        }
        using var source = store.Source();

        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await source.ReadAsync(store.Request, default));
    }

    [Fact]
    public async Task FileBackedTargetedCurrentValueRejectsNonmembershipBeforeAdvancingState()
    {
        using var store = FileArtifactStore.Create(Fixture);
        var exactAdh = File.ReadAllBytes(store.ArtifactPath("adh1", 0));
        var head = AccountDirectoryAdh1Codec.Decode(exactAdh);
        var lookup = Fixture.Candidate().VerificationClosure.QueriedDirectoryLeafKey.ToArray();
        store.PublishAsTargeted(lookup, head.LogGeneration);
        var request = new ContactResolveDirectoryPackageRequest(
            store.Request.NetworkId.ToArray(),
            store.Request.Nonce.ToArray(),
            store.Request.BootId.ToArray(),
            store.Request.NonceCreatedAt,
            null,
            null,
            null,
            lookup,
            head.LogGeneration,
            AccountDirectoryCrypto.ComputeAdh1CoreHash(head),
            requireCurrentValue: true);
        using var source = store.Source();

        await Assert.ThrowsAsync<ContactResolveDirectoryTargetNotFoundException>(async () =>
            await source.ReadAsync(request, default));

        Assert.False(File.Exists(store.StatePath));
    }

    [Fact]
    public async Task FileBackedTargetedCurrentValueRejectsLookupMismatchBeforeAdvancingState()
    {
        using var store = FileArtifactStore.Create(Fixture);
        var exactAdh = File.ReadAllBytes(store.ArtifactPath("adh1", 0));
        var head = AccountDirectoryAdh1Codec.Decode(exactAdh);
        var lookup = Repeat(0xfe, 32);
        store.PublishAsTargeted(lookup, head.LogGeneration);
        var request = new ContactResolveDirectoryPackageRequest(
            store.Request.NetworkId.ToArray(),
            store.Request.Nonce.ToArray(),
            store.Request.BootId.ToArray(),
            store.Request.NonceCreatedAt,
            null,
            null,
            null,
            lookup,
            head.LogGeneration,
            AccountDirectoryCrypto.ComputeAdh1CoreHash(head),
            requireCurrentValue: true);
        using var source = store.Source();

        await Assert.ThrowsAsync<ContactResolveDirectoryTargetNotFoundException>(async () =>
            await source.ReadAsync(request, default));

        Assert.False(File.Exists(store.StatePath));
    }

    [Fact]
    public async Task FileBackedTargetedCurrentValueRejectsPointerGenerationMismatch()
    {
        using var store = FileArtifactStore.Create(Fixture);
        var exactAdh = File.ReadAllBytes(store.ArtifactPath("adh1", 0));
        var head = AccountDirectoryAdh1Codec.Decode(exactAdh);
        var lookup = Fixture.Candidate().VerificationClosure.QueriedDirectoryLeafKey.ToArray();
        store.PublishAsTargeted(lookup, head.LogGeneration + 1);
        var request = new ContactResolveDirectoryPackageRequest(
            store.Request.NetworkId.ToArray(),
            store.Request.Nonce.ToArray(),
            store.Request.BootId.ToArray(),
            store.Request.NonceCreatedAt,
            null,
            null,
            null,
            lookup,
            head.LogGeneration,
            AccountDirectoryCrypto.ComputeAdh1CoreHash(head),
            requireCurrentValue: true);
        using var source = store.Source();

        await Assert.ThrowsAsync<ContactResolveDirectoryTargetNotFoundException>(async () =>
            await source.ReadAsync(request, default));

        Assert.False(File.Exists(store.StatePath));
    }

    [Fact]
    public async Task FileBackedSourceRejectsReparseRootAncestorWhenSupported()
    {
        using var store = FileArtifactStore.Create(Fixture);
        var outside = Path.Combine(store.ParentPath, "reparse-target");
        Directory.Move(store.RootPath, outside);
        try
        {
            Directory.CreateSymbolicLink(store.RootPath, outside);
        }
        catch (Exception exception) when (exception is UnauthorizedAccessException or
            PlatformNotSupportedException or IOException)
        {
            Directory.Move(outside, store.RootPath);
            return;
        }
        using var source = store.Source();

        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await source.ReadAsync(store.Request, default));
    }

    [Fact]
    public void FileBackedCompositionStillRequiresCustodyTimeAndOneUseLedger()
    {
        using var store = FileArtifactStore.Create(Fixture);
        var keyPath = Path.Combine(store.ParentPath, "integrity.key");
        File.WriteAllBytes(keyPath, store.IntegrityKey);
        var values = new Dictionary<string, string?>
        {
            ["DirectoryPublication:NetworkIdHex"] = Convert.ToHexString(Fixture.Network),
            ["ContactResolveDirectoryArtifacts:ReadOnlyRoot"] = store.RootPath,
            ["ContactResolveDirectoryArtifacts:StatePath"] = store.StatePath,
            ["ContactResolveDirectoryArtifacts:IntegrityKeyPath"] = keyPath,
            ["ContactResolveDirectoryArtifacts:NetworkIdHex"] = Convert.ToHexString(Fixture.Network),
            ["ContactResolveDirectoryArtifacts:GenesisAuthorityCoreHashHex"] =
                Convert.ToHexString(Fixture.GenesisAuthorityCoreHash),
        };
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(values).Build();
        var services = new ServiceCollection();

        _ = services.AddContactResolveDirectoryPackages(configuration);
        using var provider = services.BuildServiceProvider();

        Assert.IsType<UnavailableContactResolveDirectoryPackageIssuer>(
            provider.GetRequiredService<IContactResolveDirectoryPackageIssuer>());
    }

    private sealed class FileArtifactStore : IDisposable
    {
        private readonly FileContactResolveDirectoryArtifactInventory inventory;

        private FileArtifactStore(
            string parentPath,
            string rootPath,
            string operationPath,
            string statePath,
            byte[] integrityKey,
            ContactResolveDirectoryPackageRequest request,
            FileContactResolveDirectoryArtifactInventory inventory)
        {
            ParentPath = parentPath;
            RootPath = rootPath;
            OperationPath = operationPath;
            StatePath = statePath;
            IntegrityKey = integrityKey;
            Request = request;
            this.inventory = inventory;
        }

        internal string ParentPath { get; }
        internal string RootPath { get; }
        internal string OperationPath { get; private set; }
        internal string StatePath { get; }
        internal byte[] IntegrityKey { get; }
        internal ContactResolveDirectoryPackageRequest Request { get; }

        internal static FileArtifactStore Create(GoldenFixture fixture)
        {
            var parent = Path.Combine(Path.GetTempPath(), "deep-contact-source-" + Guid.NewGuid().ToString("N"));
            var root = Path.Combine(parent, "readonly");
            var request = new ContactResolveDirectoryPackageRequest(
                fixture.Network,
                Repeat(0x91, 32),
                Repeat(0x92, 16),
                3_000,
                null,
                null,
                null);
            var operation = Path.Combine(root, "bootstrap");
            Directory.CreateDirectory(operation);
            var candidate = fixture.Candidate();
            var closure = candidate.VerificationClosure;
            var artifacts = new List<(string Role, ReadOnlyMemory<byte> Bytes)>();
            Add(artifacts, "xna1", closure.AuthorityChain);
            Add(artifacts, "dts1", closure.TimeSourcePolicyChain);
            artifacts.Add(("adh1", closure.ExactDirectoryHead));
            artifacts.Add(("snapshot-dtt1", closure.ExactLiveTimeAttestation));
            artifacts.Add(("snapshot-adp1", closure.ExactDirectoryProof));
            Add(artifacts, "xvp1", closure.NetworkPolicyChain);
            Add(artifacts, "xnv1", closure.NetworkViewChain);
            Add(artifacts, "xnh1", closure.NetworkViewHeadChain);
            Add(artifacts, "xnd1", closure.ActiveNodeDescriptors);
            Add(artifacts, "pmt2", closure.MailboxTopologyChain);
            artifacts.Add(("response-adp1", closure.ExactDirectoryProof));

            var entries = new List<FileContactResolveDirectoryArtifactInventoryEntry>();
            foreach (var group in artifacts.GroupBy(static item => item.Role))
            {
                var ordinal = 0;
                foreach (var artifact in group)
                {
                    var fileName = $"{group.Key}.{ordinal:D4}.bin";
                    var bytes = artifact.Bytes.ToArray();
                    File.WriteAllBytes(Path.Combine(operation, fileName), bytes);
                    entries.Add(new FileContactResolveDirectoryArtifactInventoryEntry(
                        group.Key, ordinal++, fileName, bytes.Length,
                        Convert.ToHexString(SHA256.HashData(bytes))));
                }
            }
            var inventory = new FileContactResolveDirectoryArtifactInventory(
                FileContactResolveDirectoryArtifactInventoryCodec.CurrentFormat,
                Convert.ToHexString(fixture.Network),
                Convert.ToHexString(fixture.GenesisAuthorityCoreHash),
                closure.SupportedReader,
                Convert.ToHexString(closure.CallerNonce.Span),
                Convert.ToHexString(closure.QueriedDirectoryLeafKey.Span),
                Convert.ToHexString(closure.MonotonicBootId.Span),
                closure.NonceCreatedAtMonotonicSeconds,
                closure.ResponseReceivedAtMonotonicSeconds,
                closure.CurrentMonotonicSeconds,
                entries);
            File.WriteAllBytes(Path.Combine(operation, "inventory.json"),
                FileContactResolveDirectoryArtifactInventoryCodec.EncodeCanonical(inventory));
            return new FileArtifactStore(
                parent, root, operation, Path.Combine(parent, "state", "source.state"),
                Repeat(0xe1, 32), request, inventory);
        }

        internal FileContactResolveDirectoryArtifactSource Source(ulong observedUnixTime = 205) => new(
            RootPath,
            StatePath,
            Fixture.Network,
            Fixture.GenesisAuthorityCoreHash,
            IntegrityKey,
            new FixedContactResolveTrustedTime(observedUnixTime));

        internal FileContactResolveDirectoryArtifactSource Source(
            IContactResolveTrustedTimeContextSource trustedTime) => new(
                RootPath,
                StatePath,
                Fixture.Network,
                Fixture.GenesisAuthorityCoreHash,
                IntegrityKey,
                trustedTime);

        internal FileContactResolveDirectoryArtifactSource Source(
            IContactResolveTrustedTimeContextSource trustedTime,
            IContactResolveDtt1WitnessCustody custody) => new(
                RootPath,
                StatePath,
                Fixture.Network,
                Fixture.GenesisAuthorityCoreHash,
                IntegrityKey,
                trustedTime,
                witnessCustody: custody);

        internal string ArtifactPath(string role, int ordinal) =>
            Path.Combine(OperationPath, $"{role}.{ordinal:D4}.bin");

        internal void PublishAsTargeted(byte[] lookupKey, ulong generation)
        {
            var lookupPath = Path.Combine(
                RootPath, "current-values", Convert.ToHexString(lookupKey).ToLowerInvariant());
            var generationPath = Path.Combine(
                lookupPath, "generations", generation.ToString("D20"));
            Directory.CreateDirectory(Path.GetDirectoryName(generationPath)!);
            Directory.Move(OperationPath, generationPath);
            OperationPath = generationPath;
            Span<byte> pointer = stackalloc byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(pointer, generation);
            File.WriteAllBytes(Path.Combine(lookupPath, "current.bin"), pointer);
        }

        internal void RewriteInventory(
            Func<FileContactResolveDirectoryArtifactInventoryEntry,
                FileContactResolveDirectoryArtifactInventoryEntry> transform)
        {
            var changed = inventory with { Artifacts = inventory.Artifacts.Select(transform).ToArray() };
            File.WriteAllBytes(Path.Combine(OperationPath, "inventory.json"),
                FileContactResolveDirectoryArtifactInventoryCodec.EncodeCanonical(changed));
        }

        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(IntegrityKey);
            if (Directory.Exists(ParentPath)) Directory.Delete(ParentPath, recursive: true);
        }

        private static void Add(
            List<(string Role, ReadOnlyMemory<byte> Bytes)> target,
            string role,
            IReadOnlyList<ReadOnlyMemory<byte>> values)
        {
            foreach (var value in values) target.Add((role, value));
        }
    }

    private sealed class FixedContactResolveTrustedTime(
        ulong observedUnixTime,
        byte[]? bootId = null,
        ulong sample = 1_000) :
        IContactResolveTrustedTimeContextSource
    {
        public ValueTask<ContactResolveTrustedTimeContext> ReadAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(new ContactResolveTrustedTimeContext(
                bootId ?? Repeat(0xc1, 16), sample, observedUnixTime, 5));
        }
    }

    private sealed class FixtureProductionWitnessCustody :
        IContactResolveDtt1WitnessCustody,
        IDisposable
    {
        private readonly FixtureWitnessSigner[] signers = Enumerable.Range(0, 3)
            .Select(index => new FixtureWitnessSigner(
                Repeat(checked((byte)(0x40 + index)), 32),
                Repeat(checked((byte)(0x50 + index)), 32)))
            .ToArray();

        public ValueTask<IReadOnlyList<IAccountDirectoryDtt1WitnessSigner>> GetSignersAsync(
            VerifiedXPointNetworkAuthority authority,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult<IReadOnlyList<IAccountDirectoryDtt1WitnessSigner>>(signers);
        }

        public void Dispose()
        {
            foreach (var signer in signers) signer.Dispose();
        }
    }

    private sealed class FixtureWitnessSigner : IAccountDirectoryDtt1WitnessSigner, IDisposable
    {
        private readonly byte[] id;
        private readonly byte[] privateKey;

        internal FixtureWitnessSigner(byte[] id, byte[] seed)
        {
            this.id = id;
            var pair = PublicKeyAuth.GenerateKeyPair(seed);
            privateKey = pair.PrivateKey.ToArray();
        }

        public ReadOnlyMemory<byte> WitnessId => id;

        public ValueTask<ReadOnlyMemory<byte>> SignDtt1Async(
            ReadOnlyMemory<byte> signingInput,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult<ReadOnlyMemory<byte>>(
                PublicKeyAuth.SignDetached(signingInput.ToArray(), privateKey));
        }

        public void Dispose() => CryptographicOperations.ZeroMemory(privateKey);
    }

    private sealed class MutatingContactResolveTrustedTime(Action mutate) :
        IContactResolveTrustedTimeContextSource
    {
        public ValueTask<ContactResolveTrustedTimeContext> ReadAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            mutate();
            return ValueTask.FromResult(new ContactResolveTrustedTimeContext(
                Repeat(0xc1, 16), 1_000, 205, 5));
        }
    }

    private sealed class GoldenFixture(JsonDocument document)
    {
        // Generated from Deep.Protocol's deterministic public-producer fixture at
        // local closure 0.6.0-local.6c4393402783. Gzip keeps canonical bytes compact.
        private const string CompressedJson =
            "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";

        internal byte[] Network => RootBytes("network");
        internal byte[] GenesisAuthorityCoreHash => RootBytes("anchor");
        internal DirectoryPublicationProtectedNetworkLkg ProtectedLkg => new(
            Bytes("reset", "lkg", "network"),
            Bytes("reset", "lkg", "headRef"),
            Root.GetProperty("reset").GetProperty("lkg").GetProperty("treeSize").GetUInt64(),
            Bytes("reset", "lkg", "root"),
            Bytes("reset", "lkg", "viewRef"),
            Root.GetProperty("reset").GetProperty("lkg").GetProperty("viewGeneration").GetUInt64(),
            Bytes("reset", "lkg", "authorityRef"));

        private JsonElement Root => document.RootElement;

        internal static GoldenFixture Load()
        {
            using var compressed = new MemoryStream(Convert.FromBase64String(CompressedJson), writable: false);
            using var gzip = new GZipStream(compressed, CompressionMode.Decompress);
            using var json = new MemoryStream();
            gzip.CopyTo(json);
            return new GoldenFixture(JsonDocument.Parse(json.ToArray()));
        }

        internal byte[] Bytes(params string[] path)
        {
            var value = Root;
            foreach (var segment in path) value = value.GetProperty(segment);
            return Convert.FromBase64String(value.GetString()!);
        }

        internal DirectoryPublicationCandidate Candidate(
            bool reset = false,
            byte[]? pmt = null,
            IReadOnlyList<ReadOnlyMemory<byte>>? policyChain = null,
            byte[]? resetProof = null,
            byte[]? xna = null,
            byte[]? dts = null,
            byte[]? callerNonce = null,
            IReadOnlyList<ReadOnlyMemory<byte>>? nodes = null,
            byte[]? xnv = null,
            byte[]? xnh = null,
            byte[]? adh = null,
            byte[]? dtt = null,
            byte[]? adp = null)
        {
            var section = reset ? "reset" : "normal";
            var xvp = Bytes(section, "xvp");
            var exactXnv = Bytes(section, "xnv");
            var freshness = BuildFreshness(section, exactXnv);
            xnv ??= exactXnv;
            xnh ??= Bytes(section, "xnh");
            pmt ??= freshness.Pmt;
            var closure = new DirectoryPublicationVerificationClosure(
                [xna ?? RootBytes("xna")],
                [dts ?? RootBytes("dts")],
                policyChain ?? [xvp],
                [xnv],
                [xnh],
                nodes ?? Array(section, "nodes"),
                [pmt],
                adh ?? freshness.Adh,
                dtt ?? freshness.Dtt,
                adp ?? freshness.Adp,
                callerNonce ?? Repeat(0x74, 32),
                Repeat(0x75, 32),
                Repeat(0xc1, 16),
                990,
                995,
                1_000,
                1,
                reset ? [RootBytes("xna")] : [],
                reset ? [Bytes("reset", "xnf")] : []);
            return reset
                ? new DirectoryPublicationCandidate(
                    xnv, xnh, pmt, closure, Bytes("reset", "xnf"),
                    resetProof ?? RebindResetProof(freshness.DttHash))
                : new DirectoryPublicationCandidate(xnv, xnh, pmt, closure);
        }

        internal byte[] AuthorityBytes() => RootBytes("xna");
        internal byte[] TimePolicyBytes() => RootBytes("dts");
        internal IReadOnlyList<ReadOnlyMemory<byte>> NodeBytes(string section) => Array(section, "nodes");

        private FreshnessFixture BuildFreshness(string section, byte[] exactXnv)
        {
            var authority = XPointNetworkAuthorityVerifier.Verify(
                new XPointNetworkGenesisPin(Network, RootBytes("anchor")),
                new ReadOnlyMemory<byte>[] { RootBytes("xna") },
                new ReadOnlyMemory<byte>[] { RootBytes("dts") });
            var view = XPointNetworkCodec.Parse<Xnv1Record>(exactXnv);
            var witnesses = Enumerable.Range(0, 3).Select(index => new Witness(
                Repeat(checked((byte)(0x40 + index)), 32),
                PublicKeyAuth.GenerateKeyPair(Repeat(checked((byte)(0x50 + index)), 32))))
                .ToArray();
            var selected = witnesses.Take(2).OrderBy(static value => value.Id, ByteComparer.Instance).ToArray();
            var placeholderHead = selected.Select((value, index) => new AccountDirectoryAdh1WitnessEntry(
                value.Id, Repeat(checked((byte)(0xa7 + index)), 64))).ToArray();
            var unsignedHead = new AccountDirectoryAdh1(
                Network, 0, new byte[32], 0,
                AccountDirectoryRfc6962.ComputeEmptyTreeHash(),
                AccountDirectorySparseMap.EmptyMapRoot.Span,
                authority.AuthorityCoreReference.Span,
                authority.DirectoryWitnessPolicyHash.Span,
                100, 300, 1, placeholderHead);
            var headInput = AccountDirectoryCrypto.ComputeAdh1SigningInput(unsignedHead);
            var head = new AccountDirectoryAdh1(
                Network, 0, new byte[32], 0,
                AccountDirectoryRfc6962.ComputeEmptyTreeHash(),
                AccountDirectorySparseMap.EmptyMapRoot.Span,
                authority.AuthorityCoreReference.Span,
                authority.DirectoryWitnessPolicyHash.Span,
                100, 300, 1,
                selected.Select(value => new AccountDirectoryAdh1WitnessEntry(
                    value.Id, PublicKeyAuth.SignDetached(headInput, value.Key.PrivateKey))).ToArray());
            var adh = AccountDirectoryAdh1Codec.Encode(head);
            var adhHash = AccountDirectoryCrypto.ComputeAdh1CoreHash(head);
            var nonce = Repeat(0x74, 32);
            var issuanceEpochId = AccountDirectoryDtt1IssuanceEpoch
                .Derive(authority, 200, 5).Id.ToArray();
            var placeholderDtt = selected.Select((value, index) => new AccountDirectoryDtt1WitnessReceipt(
                value.Id, Repeat(checked((byte)(0xb0 + index)), 64))).ToArray();
            var unsignedDtt = new AccountDirectoryDtt1(
                Network, nonce, 200, 5, adhHash, 0, view.CoreHash.Span, view.ViewGeneration,
                authority.AuthorityCoreReference.Span, authority.DirectoryWitnessPolicyHash.Span,
                200, 260, issuanceEpochId, placeholderDtt);
            var dttInput = AccountDirectoryCrypto.ComputeDtt1SigningInput(unsignedDtt);
            var dtt = new AccountDirectoryDtt1(
                Network, nonce, 200, 5, adhHash, 0, view.CoreHash.Span, view.ViewGeneration,
                authority.AuthorityCoreReference.Span, authority.DirectoryWitnessPolicyHash.Span,
                200, 260, issuanceEpochId,
                selected.Select(value => new AccountDirectoryDtt1WitnessReceipt(
                    value.Id, PublicKeyAuth.SignDetached(dttInput, value.Key.PrivateKey))).ToArray());
            var exactDtt = AccountDirectoryDtt1Codec.Encode(dtt);
            var dttHash = AccountDirectoryCrypto.ComputeDtt1CoreHash(dtt);
            var adp = Write("ADP1", 0x0201,
            [
                Network, [2], Repeat(0x75, 32), adh, U64(0), new byte[32],
                [0], [], new byte[32], U16(0), [], [0], [0], [], dttHash,
            ]);

            var pmtRecord = ContactCodec.Decode("PMT2", Bytes(section, "pmt"));
            var pmtFields = Enumerable.Range(1, 16).Select(pmtRecord.Field).ToArray();
            pmtFields[13] = Reference("ADH1", adhHash);
            pmtFields[15] = SignatureRows(selected.Select(static value =>
                (value.Id, Repeat(0xcc, 64))).ToArray());
            var provisional = ContactCodec.AuthorForValidation("PMT2", pmtFields);
            pmtFields[15] = SignatureRows(selected.Select(value =>
                (value.Id, PublicKeyAuth.SignDetached(provisional.SignatureInput.ToArray(), value.Key.PrivateKey))).ToArray());
            var pmt = ContactCodec.AuthorForValidation("PMT2", pmtFields).CanonicalBytes.ToArray();
            return new FreshnessFixture(adh, exactDtt, adp, pmt, dttHash);
        }

        private byte[] RebindResetProof(ReadOnlySpan<byte> dttHash)
        {
            var proof = XPointNetworkCodec.Parse<Nfp1Record>(Bytes("reset", "nfp"));
            var fields = Enumerable.Range(1, 16).Select(tag => proof.FieldSpan(tag).ToArray()).ToArray();
            fields[14] = Reference("DTT1", dttHash);
            return Write("NFP1", 0x0201, fields);
        }

        internal ProductionDirectoryCanonicalPublicationVerifier Verifier(
            ulong clockSample = 1_000,
            IDirectoryPublicationLiveChallengeAuthority? challengeAuthority = null,
            IDirectoryPublicationProtectedNetworkLkgSource? protectedLkgSource = null,
            byte[]? network = null) => new(
                new DirectoryPublicationTrustAnchor(network ?? Network, 0, RootBytes("anchor")),
                new FixedClock(clockSample),
                challengeAuthority ?? new ExactChallengeAuthority(),
                protectedLkgSource);

        private byte[] RootBytes(string name) =>
            Convert.FromBase64String(Root.GetProperty(name).GetString()!);

        private IReadOnlyList<ReadOnlyMemory<byte>> Array(string section, string name) =>
            Root.GetProperty(section).GetProperty(name).EnumerateArray()
                .Select(static item => (ReadOnlyMemory<byte>)Convert.FromBase64String(item.GetString()!))
                .ToArray();
    }

    private sealed class FixedClock(ulong sample) : IDirectoryPublicationMonotonicClock
    {
        public ValueTask<DirectoryPublicationMonotonicReading> ReadAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(new DirectoryPublicationMonotonicReading(Repeat(0xc1, 16), sample));
        }
    }

    private sealed class ExactChallengeAuthority : IDirectoryPublicationLiveChallengeAuthority
    {
        private int calls;
        internal int Calls => Volatile.Read(ref calls);

        public ValueTask<VerifiedDirectoryPublicationChallenge> VerifyAndConsumeAsync(
            ReadOnlyMemory<byte> nonce,
            ReadOnlyMemory<byte> bootId,
            ulong nonceCreatedAtMonotonicSeconds,
            ulong responseReceivedAtMonotonicSeconds,
            ulong currentMonotonicSeconds,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Interlocked.Increment(ref calls);
            return ValueTask.FromResult(new VerifiedDirectoryPublicationChallenge(
                nonce.Span,
                bootId.Span,
                nonceCreatedAtMonotonicSeconds,
                responseReceivedAtMonotonicSeconds,
                currentMonotonicSeconds));
        }
    }

    private sealed class SubstitutingChallengeAuthority : IDirectoryPublicationLiveChallengeAuthority
    {
        public ValueTask<VerifiedDirectoryPublicationChallenge> VerifyAndConsumeAsync(
            ReadOnlyMemory<byte> nonce,
            ReadOnlyMemory<byte> bootId,
            ulong nonceCreatedAtMonotonicSeconds,
            ulong responseReceivedAtMonotonicSeconds,
            ulong currentMonotonicSeconds,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(new VerifiedDirectoryPublicationChallenge(
                Repeat(0x7f, 32),
                bootId.Span,
                nonceCreatedAtMonotonicSeconds,
                responseReceivedAtMonotonicSeconds,
                currentMonotonicSeconds));
        }
    }

    private sealed class FixedProtectedLkgSource(DirectoryPublicationProtectedNetworkLkg value)
        : IDirectoryPublicationProtectedNetworkLkgSource
    {
        public ValueTask<DirectoryPublicationProtectedNetworkLkg?> ReadAsync(
            ReadOnlyMemory<byte> expectedNetworkId,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Assert.Equal(value.NetworkId.ToArray(), expectedNetworkId.ToArray());
            return ValueTask.FromResult<DirectoryPublicationProtectedNetworkLkg?>(value);
        }
    }

    private static byte[] Repeat(byte value, int count) =>
        Enumerable.Repeat(value, count).ToArray();

    private static byte[] Write(string magic, ushort suite, IReadOnlyList<byte[]> fields)
    {
        var output = new byte[checked(12 + fields.Sum(static field => 8 + field.Length))];
        Encoding.ASCII.GetBytes(magic).CopyTo(output, 0);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(4), 1);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(6), suite);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(8), checked((ushort)fields.Count));
        var offset = 12;
        for (var index = 0; index < fields.Count; index++)
        {
            BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(offset), checked((ushort)(index + 1)));
            BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(offset + 4), checked((uint)fields[index].Length));
            offset += 8;
            fields[index].CopyTo(output, offset);
            offset += fields[index].Length;
        }
        return output;
    }

    private static byte[] U16(ushort value)
    {
        var output = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(output, value);
        return output;
    }

    private static byte[] U64(ulong value)
    {
        var output = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(output, value);
        return output;
    }

    private static byte[] Reference(string magic, ReadOnlySpan<byte> hash)
    {
        var output = new byte[38];
        Encoding.ASCII.GetBytes(magic).CopyTo(output, 0);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(4), 1);
        hash.CopyTo(output.AsSpan(6));
        return output;
    }

    private static byte[] SignatureRows(IReadOnlyList<(byte[] Id, byte[] Signature)> rows) =>
        rows.OrderBy(static value => value.Id, ByteComparer.Instance)
            .Select(static value => value.Id.Concat(value.Signature).ToArray())
            .SelectMany(static value => value).ToArray();

    private static byte[] Sha256Domain(string domain, ReadOnlySpan<byte> payload)
    {
        var domainBytes = Encoding.ASCII.GetBytes(domain);
        var preimage = new byte[checked(domainBytes.Length + 1 + sizeof(uint) + payload.Length)];
        domainBytes.CopyTo(preimage, 0);
        BinaryPrimitives.WriteUInt32BigEndian(
            preimage.AsSpan(domainBytes.Length + 1),
            checked((uint)payload.Length));
        payload.CopyTo(preimage.AsSpan(domainBytes.Length + 1 + sizeof(uint)));
        return SHA256.HashData(preimage);
    }

    private sealed record FreshnessFixture(byte[] Adh, byte[] Dtt, byte[] Adp, byte[] Pmt, byte[] DttHash);
    private sealed record Witness(byte[] Id, KeyPair Key);

    private sealed class ByteComparer : IComparer<byte[]>
    {
        internal static readonly ByteComparer Instance = new();
        public int Compare(byte[]? left, byte[]? right) => left.AsSpan().SequenceCompareTo(right);
    }

}
#else
using Deep.Registry.Api.DirectoryPublication;

namespace Deep.Registry.Api.Tests;

public sealed class ProductionDirectoryCanonicalPublicationVerifierTests
{
    [Fact]
    public async Task DefaultProductionPinFailsClosedWithoutDirectoryProtocolSurface()
    {
        Assert.False(ProductionDirectoryCanonicalPublicationVerifier.HasRequiredProtocolSurface);
        var bytes = new byte[] { 1 };
        var closure = new DirectoryPublicationVerificationClosure(
            [bytes], [bytes], [bytes], [bytes], [bytes], [bytes, bytes, bytes], [bytes],
            bytes, bytes, bytes,
            Repeat(1, 32), Repeat(2, 32), Repeat(3, 16), 1, 2, 3, 1);
        var candidate = new DirectoryPublicationCandidate(bytes, bytes, bytes, closure).Freeze();
        var verifier = new ProductionDirectoryCanonicalPublicationVerifier(
            new DirectoryPublicationTrustAnchor(Repeat(4, 16), 0, Repeat(5, 32)),
            new FixedClock(),
            new RejectingChallengeAuthority());

        var error = await Assert.ThrowsAsync<DirectoryCanonicalVerificationException>(async () =>
            await verifier.VerifyAsync(candidate, default));

        Assert.Equal(DirectoryCanonicalVerificationError.ProtocolSurfaceUnavailable, error.Error);
    }

    private sealed class FixedClock : IDirectoryPublicationMonotonicClock
    {
        public ValueTask<DirectoryPublicationMonotonicReading> ReadAsync(CancellationToken cancellationToken) =>
            ValueTask.FromResult(new DirectoryPublicationMonotonicReading(Repeat(3, 16), 3));
    }

    private sealed class RejectingChallengeAuthority : IDirectoryPublicationLiveChallengeAuthority
    {
        public ValueTask<VerifiedDirectoryPublicationChallenge> VerifyAndConsumeAsync(
            ReadOnlyMemory<byte> nonce,
            ReadOnlyMemory<byte> bootId,
            ulong nonceCreatedAtMonotonicSeconds,
            ulong responseReceivedAtMonotonicSeconds,
            ulong currentMonotonicSeconds,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException("The fail-closed profile must not touch the challenge authority.");
    }

    private static byte[] Repeat(byte value, int count) => Enumerable.Repeat(value, count).ToArray();
}
#endif
