#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.XPointNetworkV1;
using Deep.Registry.Api.DirectoryPublication;

namespace Deep.Registry.Api.Tests;

public sealed partial class DeepIdV2DurableGenesisAuthorityTests
{
    private static async Task ExerciseAuthoritySuccessorAsync(Did2DirectoryAuthorityFixture fixture,
        string directory, string statePath, byte[] key, DeepIdV2DirectoryBootstrapSource bootstrap,
        FileContactResolveDtt1WitnessCustody custody, FixedTimeSource time, TrackingLatestHeadFloor floor,
        ReadOnlyMemory<byte> leaf, ReadOnlyMemory<byte> exactDid2)
    {
        var renewal = await fixture.RenewAuthorityAsync(time.UnixTime);
        var root0 = Path.Combine(directory, "genesis.xna1"); var policy0 = Path.Combine(directory, "genesis.dts1");
        var root1 = Path.Combine(directory, "renewed.xna1"); var policy1 = Path.Combine(directory, "renewed.dts1");
        await File.WriteAllBytesAsync(root1, renewal.ExactXna1.ToArray());
        await File.WriteAllBytesAsync(policy1, renewal.ExactDts1.ToArray());
        var roots = new DeepIdV2XPointAuthoritySource(fixture.Network, fixture.Authority.AuthorityCoreHash.Span,
            [root0, root1], [policy0, policy1]);
        var authority = roots.Read();
        var view = Path.Combine(directory, "renewed.xnv1");
        var renewedView = fixture.CreateRenewedView(authority, time.UnixTime);
        await File.WriteAllBytesAsync(view, renewedView);
        await ExerciseHandoverAsync(roots, view, "renewed", custody);

        var rotation = fixture.RotateAuthority(renewal.ExactXna1, renewal.ExactDts1, renewedView, time.UnixTime);
        var root2 = Path.Combine(directory, "rotated.xna1"); var policy2 = Path.Combine(directory, "rotated.dts1");
        var view2 = Path.Combine(directory, "rotated.xnv1");
        await File.WriteAllBytesAsync(root2, rotation.Xna); await File.WriteAllBytesAsync(policy2, rotation.Dts);
        await File.WriteAllBytesAsync(view2, rotation.View);
        var rotatedRoots = new DeepIdV2XPointAuthoritySource(fixture.Network, fixture.Authority.AuthorityCoreHash.Span,
            [root0, root1, root2], [policy0, policy1, policy2]);
        var rotated = rotatedRoots.Read();
        Assert.False(authority.RootKeys[0].Ed25519PublicKey.Span.SequenceEqual(rotated.RootKeys[0].Ed25519PublicKey.Span));
        Assert.All(rotated.WitnessKeys, witness => Assert.DoesNotContain(authority.WitnessKeys,
            old => old.Ed25519PublicKey.Span.SequenceEqual(witness.Ed25519PublicKey.Span)));
        var beforeWrongCustody = await File.ReadAllBytesAsync(statePath); var beforeWrongAdvance = floor.AdvanceCount;
        using (var wrongCustody = new DeepIdV2DurableGenesisAuthority(rotatedRoots, bootstrap, custody, time,
                   statePath, fixture.Network, key, 1, 3_600, floor))
            await Assert.ThrowsAsync<CryptographicException>(() => wrongCustody.RenewHeadIfDueAsync(300).AsTask());
        Assert.Equal(beforeWrongCustody, await File.ReadAllBytesAsync(statePath));
        Assert.Equal(beforeWrongAdvance, floor.AdvanceCount);
        var rotatedOptions = new List<ContactResolveWitnessCustodyOptions>();
        for (var index = 0; index < 2; index++)
        {
            var path = Path.Combine(directory, $"rotated-witness-{index}.seed");
            await File.WriteAllBytesAsync(path, Bytes(32, checked((byte)(0x54 + index))));
            rotatedOptions.Add(new() { WitnessIdHex = Convert.ToHexString(Bytes(32, checked((byte)(0x44 + index)))),
                KeyGeneration = 0, Ed25519SeedPath = path });
        }
        using var rotatedCustody = new FileContactResolveDtt1WitnessCustody(fixture.Network, rotatedOptions);
        await ExerciseHandoverAsync(rotatedRoots, view2, "rotated", rotatedCustody);

        async Task ExerciseHandoverAsync(DeepIdV2XPointAuthoritySource currentRoots, string currentView,
            string scope, FileContactResolveDtt1WitnessCustody currentCustody)
        {
            var currentAuthority = currentRoots.Read();
            var ledger = new ProtectedFileContactResolveOneUseRequestLedger(Path.Combine(directory, scope + "-nonces"),
                fixture.Network, Bytes(32, 0x98));
            using var proofs = new DeepIdV2DirectoryProofIssuer(currentRoots, bootstrap, new DeepIdV2FileCurrentViewSource(currentView),
                currentCustody, ledger, time, statePath, fixture.Network, key, 1, floor);
            var original = await File.ReadAllBytesAsync(statePath);
            var advances = floor.AdvanceCount;
            using (var runtime = Open())
            {
                var unavailable = await Assert.ThrowsAsync<CryptographicException>(() => runtime.RequireReadyAsync().AsTask());
                Assert.Equal("head-authority-renewal", DirectoryPublicationDiagnostics.UnavailableReason(unavailable));
                await Assert.ThrowsAsync<AccountDirectoryProofAuthoringException>(() => proofs.RequireReadyAsync().AsTask());
                Assert.Equal(original, await File.ReadAllBytesAsync(statePath)); Assert.Equal(advances, floor.AdvanceCount);
                Assert.True(await runtime.RenewHeadIfDueAsync(300)); // Original head is still valid, but its authority differs.
                Assert.Equal(advances + 1, floor.AdvanceCount);
                await runtime.RequireReadyAsync(); await proofs.RequireReadyAsync();
                Assert.False(await runtime.RenewHeadIfDueAsync(300));
            }
            var committed = await File.ReadAllBytesAsync(statePath);
            using (var cold = Open())
            {
                await cold.RequireReadyAsync(); Assert.False(await cold.RenewHeadIfDueAsync(300));
                Assert.Equal(committed, await File.ReadAllBytesAsync(statePath)); Assert.Equal(advances + 1, floor.AdvanceCount);
                using var consumerVerifier = DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess();
                AccountDirectoryProtectedLkg currentFloor;
                using (var protectedStore = new DeepIdV2DirectoryStateStore(statePath, key, fixture.Network,
                           bootstrap, currentAuthority, consumerVerifier, 1, floor))
                using (var protectedLease = protectedStore.Open())
                    currentFloor = (await protectedLease.ReadAsync(time.UnixTime + 5)).CurrentHead;
                var result = await proofs.IssueAsync(new DeepIdV2DirectoryProofRequest(fixture.Network, Bytes(32, 0xb1),
                    Bytes(16, 0xc1), 4_000, leaf.Span, currentFloor));
                Assert.Equal(currentAuthority.AuthorityCoreReference.ToArray(),
                    AccountDirectoryAdh1Codec.Decode(result.ExactAdh1.Span).ExactXnaAuthorityCoreReference.ToArray());
                var credential = DeepIdV2Codec.DecodeDid2(exactDid2.Span);
                var lookup = DeepIdV2AccountDirectoryLookupCodec.Author(credential, fixture.Network,
                    currentFloor.LogGeneration, currentFloor.CoreHash.Span, 1, new byte[38], new byte[32]);
                var verified = DeepIdV2DirectoryCurrentProofVerifier.VerifyRequestedDid2(currentAuthority,
                    result.ExactAdh1, result.ExactDtt1, result.ExactAdp1V2, Bytes(32, 0xb1),
                    VerifiedDeepIdV2DirectoryQuery.VerifyDid2(lookup, credential),
                    new AccountDirectoryMonotonicRequestWindow(Bytes(16, 0xc1), 4_000, 4_000, 4_000),
                    currentFloor, 1, 2, consumerVerifier);
                Assert.NotNull(verified.CurrentCheckpoint);
                Assert.True(verified.IsCurrentAtMonotonic(Bytes(16, 0xc1), 4_000));
            }
            using var verifier = DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess();
            using var store = new DeepIdV2DirectoryStateStore(statePath, key, fixture.Network, bootstrap, currentAuthority, verifier, 1, floor);
            using var lease = store.Open(); var restored = await lease.ReadAsync(time.UnixTime + 5);
            Assert.Single(restored.Transitions); Assert.Single(restored.AdmissionRows);
            Assert.Equal(1UL, restored.CurrentHead.TreeSize);
            Assert.Equal(currentAuthority.AuthorityCoreReference.ToArray(), restored.CurrentHead.Head.ExactXnaAuthorityCoreReference.ToArray());
            Assert.Equal(fixture.Authority.AuthorityCoreReference.ToArray(), restored.Heads[0].Head.ExactXnaAuthorityCoreReference.ToArray());

            DeepIdV2DurableGenesisAuthority Open() => new(currentRoots, bootstrap, currentCustody, time, statePath,
                fixture.Network, key, 1, 3_600, floor);
        }
    }
}
#endif
