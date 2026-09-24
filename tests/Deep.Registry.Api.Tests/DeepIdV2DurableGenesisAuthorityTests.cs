#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.XPointNetworkV1;
using Deep.Registry.Api.DirectoryPublication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using System.Net;
using System.Net.Http.Headers;

namespace Deep.Registry.Api.Tests;

public sealed class DeepIdV2DurableGenesisAuthorityTests
{
    [Fact]
    public async Task RealPqGenesisAdvancesAda2OnceAndReturnsExactIdempotentReceipt()
    {
        if (!(OperatingSystem.IsWindows() ||
              (OperatingSystem.IsLinux() &&
               System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture ==
               System.Runtime.InteropServices.Architecture.X64)))
            return;
        using var fixture = ContactResolveAuthoringFixture.Create(currentValue: false);
        var root = Path.Combine(Path.GetTempPath(),
            "deep-did2-real-admission", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var headPath = Path.Combine(root, "genesis.adh1");
            var statePath = Path.Combine(root, "authority.ada2");
            var authorityPath = Path.Combine(root, "genesis.xna1");
            var policyPath = Path.Combine(root, "genesis.dts1");
            var head = fixture.CreateDid2GenesisHead();
            var headHash = AccountDirectoryCrypto.ComputeAdh1CoreHash(
                AccountDirectoryAdh1Codec.Decode(head));
            var networkPin = XPointNetworkCodec.Parse<Xna1Record>(
                fixture.ExactXna1).CoreHash.ToArray();
            var key = Bytes(32, 0x5a);
            await File.WriteAllBytesAsync(headPath, head);
            await File.WriteAllBytesAsync(authorityPath, fixture.ExactXna1);
            await File.WriteAllBytesAsync(policyPath, fixture.ExactDts1);
            var genesisProtectedState = DirectoryPublicationProtectedFile.Protect(
                DeepIdV2DirectoryStateCodec.Encode(fixture.Network,
                    new DeepIdV2DirectoryStateRows(
                        [new DeepIdV2DirectoryHeadRow(head, headHash)],
                        [], [])), key);
            await File.WriteAllBytesAsync(statePath, genesisProtectedState);
            var witnessOptions = new List<ContactResolveWitnessCustodyOptions>();
            for (var index = 0; index < 2; index++)
            {
                var seedPath = Path.Combine(root, $"witness-{index}.seed");
                await File.WriteAllBytesAsync(seedPath,
                    Bytes(32, checked((byte)(0x50 + index))));
                witnessOptions.Add(new ContactResolveWitnessCustodyOptions
                {
                    WitnessIdHex = Convert.ToHexString(
                        Bytes(32, checked((byte)(0x40 + index)))),
                    KeyGeneration = 0,
                    Ed25519SeedPath = seedPath
                });
            }
            using var custody = new FileContactResolveDtt1WitnessCustody(
                fixture.Network, witnessOptions);
            var bootstrap = new DeepIdV2DirectoryBootstrapSource(
                headPath, headHash);
            var networkSource = new DeepIdV2XPointAuthoritySource(
                fixture.Network, networkPin, [authorityPath], [policyPath]);
            var floor = new TrackingLatestHeadFloor(
                bootstrap.Read(networkSource.Read()));
            using var authority = new DeepIdV2DurableGenesisAuthority(
                networkSource, bootstrap, custody, new FixedTimeSource(
                    1_700_000_400), statePath, fixture.Network, key,
                deploymentProfileId: 1, headValiditySeconds: 3_600,
                latestHeadFloor: floor);
            var exactRequest = await File.ReadAllBytesAsync(Path.Combine(
                AppContext.BaseDirectory, "Fixtures", "did2-genesis.dga1v2"));
            Assert.Equal(
                "A6FE30927D2E22C1DD6A09C049E614BA57C0B4E5C83860322ADEF8F6B40CB391",
                Convert.ToHexString(SHA256.HashData(exactRequest)));
            var request = DeepIdV2GenesisAdmissionWireCodec.DecodeRequest(
                exactRequest);
            var first = await authority.AdmitAsync(request);
            Assert.Equal(1, floor.AdvanceCount);
            var firstHead = AccountDirectoryAdh1Codec.Decode(first.ExactAdh1.Span);
            Assert.Equal(1UL, firstHead.TreeSize);
            Assert.Equal((ushort)2, firstHead.MinimumReader);
            Assert.Equal(first.ExactAdh1.ToArray(),
                (await authority.AdmitAsync(request)).ExactAdh1.ToArray());
            var protectedAfterFirst = await File.ReadAllBytesAsync(statePath);
            using (var restarted = new DeepIdV2DurableGenesisAuthority(
                       networkSource, bootstrap, custody, new FixedTimeSource(
                           1_700_000_400), statePath, fixture.Network, key,
                       deploymentProfileId: 1, headValiditySeconds: 3_600,
                       latestHeadFloor: floor))
                Assert.Equal(first.ExactAdh1.ToArray(),
                    (await restarted.AdmitAsync(request)).ExactAdh1.ToArray());
            var duplicateLeaf = new DeepIdV2GenesisAdmissionWireRequest(
                Bytes(32, 0x92), request.Admission);
            await Assert.ThrowsAsync<DeepIdV2AuthorityConflictException>(
                async () => await authority.AdmitAsync(duplicateLeaf));
            var changedDid = request.Admission.ExactDid2.ToArray();
            changedDid[52] ^= 1;
            var conflicting = new DeepIdV2GenesisAdmissionWireRequest(
                request.OperationId.Span,
                new DeepIdV2GenesisAdmissionRequest(
                    request.Admission.ExactDpa1.Span,
                    request.Admission.ExactDrs1.Span,
                    request.Admission.ExactDpd1,
                    changedDid,
                    request.Admission.ExactDab2.Span,
                    request.Admission.ExactDmd1.Span,
                    request.Admission.ExactAdc1V2.Span,
                    request.Admission.RevokedDcaAuthorizationIds));
            await Assert.ThrowsAsync<DeepIdV2AuthorityConflictException>(
                async () => await authority.AdmitAsync(conflicting));
            Assert.Equal(protectedAfterFirst,
                await File.ReadAllBytesAsync(statePath));

            using var verifier = DeepMlDsa65CandidateVerifierFactory
                .OpenForCurrentProcess();
            using var store = new DeepIdV2DirectoryStateStore(statePath,
                key, fixture.Network, bootstrap, networkSource.Read(),
                verifier, 1);
            using var lease = store.Open();
            var restored = lease.Read(1_700_000_405);
            Assert.Single(restored.AdmissionRows);
            Assert.Single(restored.Transitions);
            Assert.Equal(first.ExactAdh1.ToArray(),
                restored.CurrentHead.ExactAdh1.ToArray());

            var material = lease.CreateProofMaterial(
                first.DirectoryLeafKey.Span);
            Assert.Equal(AccountDirectoryAdp1ResultKind.CurrentValue,
                material.ResultKind);
            Assert.Equal(AccountDirectoryAdp1ResultKind.NonMembership,
                lease.CreateProofMaterial(Bytes(32, 0x7e)).ResultKind);
            var observedTime = 1_700_000_405UL;
            var uncertainty = 5U;
            var proofRequest = new AccountDirectoryProofAuthoringRequest(
                fixture.Network, Bytes(32, 0xb1), Bytes(16, 0xb2),
                4_100, restored.CurrentHead.ExactAdh1.Span,
                fixture.Snapshot.ExactCurrentXnv1.Span,
                observedTime, uncertainty,
                observedTime - uncertainty,
                observedTime + uncertainty,
                AccountDirectoryDtt1IssuanceEpoch.Derive(
                    networkSource.Read(), observedTime, uncertainty), 2);
            var issued = await DeepIdV2DirectoryProofAuthor.IssueGenesisAsync(
                networkSource.Read(), proofRequest, material, fixture.Signers,
                deploymentProfileId: 1, verifier);
            var adp = DeepIdV2Adp1Codec.Decode(issued.ExactAdp1V2.Span);
            Assert.Equal(AccountDirectoryAdp1ResultKind.CurrentValue,
                adp.ResultKind);
            Assert.Equal(first.DirectoryLeafKey.ToArray(),
                issued.QueriedDirectoryLeafKey.ToArray());

            lease.Dispose();

            var viewPath = Path.Combine(root, "current.xnv1");
            await File.WriteAllBytesAsync(viewPath,
                fixture.Snapshot.ExactCurrentXnv1.ToArray());
            using var nonceLedger =
                new ProtectedFileContactResolveOneUseRequestLedger(
                    Path.Combine(root, "did2-proof-nonces"), fixture.Network,
                    Bytes(32, 0x5b));
            using var proofIssuer = new DeepIdV2DirectoryProofIssuer(
                networkSource, bootstrap,
                new DeepIdV2FileCurrentViewSource(viewPath), custody,
                nonceLedger, new FixedTimeSource(observedTime),
                statePath, fixture.Network, key, deploymentProfileId: 1,
                latestHeadFloor: floor);
            var liveRequest = new DeepIdV2DirectoryProofRequest(
                fixture.Network, Bytes(32, 0xb3), Bytes(16, 0xb4),
                4_101, first.DirectoryLeafKey.Span);
            var liveProof = await proofIssuer.IssueAsync(liveRequest);
            Assert.Equal(first.ExactAdh1.ToArray(),
                liveProof.ExactAdh1.ToArray());
            Assert.Equal(AccountDirectoryAdp1ResultKind.CurrentValue,
                DeepIdV2Adp1Codec.Decode(liveProof.ExactAdp1V2.Span)
                    .ResultKind);
            await Assert.ThrowsAsync<CryptographicException>(async () =>
                await proofIssuer.IssueAsync(liveRequest));

            var exactDid2 = DeepIdV2Codec.DecodeDid2(
                request.Admission.ExactDid2.Span);
            var lookup = DeepIdV2AccountDirectoryLookupCodec.Author(
                exactDid2, fixture.Network, 0, headHash, 1,
                new byte[38], new byte[32]);
            var wireRequest = DeepIdV2DirectoryProofWireCodec.DecodeRequest(
                DeepIdV2DirectoryProofWireCodec.EncodeRequest(
                    lookup, exactDid2, Bytes(32, 0xb9),
                    Bytes(16, 0xba), 4_104));
            var wireResponse = await proofIssuer.IssueWireAsync(wireRequest);
            var parsedWire = DeepIdV2DirectoryProofWireCodec.DecodeResponse(
                wireResponse, wireRequest);
            Assert.Equal(first.ExactAdh1.ToArray(),
                parsedWire.ExactAdh1.ToArray());
            Assert.Equal(AccountDirectoryAdp1ResultKind.CurrentValue,
                DeepIdV2Adp1Codec.Decode(parsedWire.ExactAdp1V2.Span)
                    .ResultKind);
            var httpRequest = DeepIdV2DirectoryProofWireCodec.EncodeRequest(
                lookup, exactDid2, Bytes(32, 0xbd), Bytes(16, 0xbe), 4_106);
            var httpBuilder = WebApplication.CreateBuilder();
            httpBuilder.WebHost.UseTestServer();
            httpBuilder.Services.AddSingleton(proofIssuer);
            httpBuilder.Services.AddSingleton(TimeProvider.System);
            httpBuilder.Services.AddSingleton<ContactResolveIssuanceAdmissionGate>();
            await using (var app = httpBuilder.Build())
            {
                app.MapDeepIdV2DirectoryAuthorityEndpoint(
                    new DeepIdV2DirectoryAuthorityHostingState(true, true));
                await app.StartAsync();
                using var client = app.GetTestClient();
                using var content = new ByteArrayContent(httpRequest);
                content.Headers.ContentType = new MediaTypeHeaderValue(
                    DeepIdV2DirectoryProofWireCodec.RequestMediaType);
                using var response = await client.PostAsync(
                    DeepIdV2DirectoryAuthorityHostingExtensions.ProofEndpointPath,
                    content);
                Assert.Equal(HttpStatusCode.OK, response.StatusCode);
                var httpProof = DeepIdV2DirectoryProofWireCodec.DecodeResponse(
                    await response.Content.ReadAsByteArrayAsync(),
                    DeepIdV2DirectoryProofWireCodec.DecodeRequest(httpRequest));
                Assert.Equal(first.ExactAdh1.ToArray(),
                    httpProof.ExactAdh1.ToArray());
                using var replay = new ByteArrayContent(httpRequest);
                replay.Headers.ContentType = new MediaTypeHeaderValue(
                    DeepIdV2DirectoryProofWireCodec.RequestMediaType);
                using var replayResponse = await client.PostAsync(
                    DeepIdV2DirectoryAuthorityHostingExtensions.ProofEndpointPath,
                    replay);
                Assert.Equal(HttpStatusCode.ServiceUnavailable,
                    replayResponse.StatusCode);
            }
            var wrongFloor = DeepIdV2AccountDirectoryLookupCodec.Author(
                exactDid2, fixture.Network, 0, Bytes(32, 0x7d), 1,
                new byte[38], new byte[32]);
            await Assert.ThrowsAsync<ContactResolveDirectoryTargetNotFoundException>(
                async () => await proofIssuer.IssueWireAsync(
                    DeepIdV2DirectoryProofWireCodec.DecodeRequest(
                        DeepIdV2DirectoryProofWireCodec.EncodeRequest(
                            wrongFloor, exactDid2, Bytes(32, 0xbb),
                            Bytes(16, 0xbc), 4_105))));

            var legacyFloor = fixture.Snapshot.CurrentDirectoryHead;
            await Assert.ThrowsAsync<CryptographicException>(async () =>
                await proofIssuer.IssueAsync(
                    new DeepIdV2DirectoryProofRequest(fixture.Network,
                        Bytes(32, 0xb5), Bytes(16, 0xb6), 4_102,
                        first.DirectoryLeafKey.Span, legacyFloor)));
            var damagedView = await File.ReadAllBytesAsync(viewPath);
            damagedView[^1] ^= 1;
            await File.WriteAllBytesAsync(viewPath, damagedView);
            await Assert.ThrowsAsync<AccountDirectoryProofAuthoringException>(
                async () => await proofIssuer.IssueAsync(
                    new DeepIdV2DirectoryProofRequest(fixture.Network,
                        Bytes(32, 0xb7), Bytes(16, 0xb8), 4_103,
                        first.DirectoryLeafKey.Span)));
            Assert.True(floor.RequireCount >= 3);
            await File.WriteAllBytesAsync(statePath, genesisProtectedState);
            await Assert.ThrowsAsync<CryptographicException>(async () =>
                await authority.AdmitAsync(request));
            await Assert.ThrowsAsync<CryptographicException>(async () =>
                await proofIssuer.IssueAsync(
                    new DeepIdV2DirectoryProofRequest(fixture.Network,
                        Bytes(32, 0xc4), Bytes(16, 0xc5), 4_107,
                        first.DirectoryLeafKey.Span)));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task ForgedDid2GenesisDoesNotMutatePinnedAda2State()
    {
        if (!(OperatingSystem.IsWindows() ||
              (OperatingSystem.IsLinux() &&
               System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture ==
               System.Runtime.InteropServices.Architecture.X64)))
            return;
        using var fixture = ContactResolveAuthoringFixture.Create(currentValue: false);
        var root = Path.Combine(Path.GetTempPath(),
            "deep-did2-admission", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var headPath = Path.Combine(root, "genesis.adh1");
            var statePath = Path.Combine(root, "authority.ada2");
            var authorityPath = Path.Combine(root, "genesis.xna1");
            var policyPath = Path.Combine(root, "genesis.dts1");
            var witnessPath = Path.Combine(root, "witness.seed");
            var head = fixture.CreateDid2GenesisHead();
            var headHash = AccountDirectoryCrypto.ComputeAdh1CoreHash(
                AccountDirectoryAdh1Codec.Decode(head));
            var networkPin = XPointNetworkCodec.Parse<Xna1Record>(
                fixture.ExactXna1).CoreHash.ToArray();
            var key = Enumerable.Repeat((byte)0x5a, 32).ToArray();
            await File.WriteAllBytesAsync(headPath, head);
            await File.WriteAllBytesAsync(authorityPath, fixture.ExactXna1);
            await File.WriteAllBytesAsync(policyPath, fixture.ExactDts1);
            await File.WriteAllBytesAsync(witnessPath,
                Enumerable.Repeat((byte)0x50, 32).ToArray());
            var initial = new DeepIdV2DirectoryStateRows(
                [new DeepIdV2DirectoryHeadRow(head, headHash)], [], []);
            var payload = DeepIdV2DirectoryStateCodec.Encode(fixture.Network,
                initial);
            var protectedState = DirectoryPublicationProtectedFile.Protect(
                payload, key);
            await File.WriteAllBytesAsync(statePath, protectedState);

            using var custody = new FileContactResolveDtt1WitnessCustody(
                fixture.Network,
                [new ContactResolveWitnessCustodyOptions
                {
                    WitnessIdHex = Convert.ToHexString(
                        Enumerable.Repeat((byte)0x40, 32).ToArray()),
                    KeyGeneration = 1,
                    Ed25519SeedPath = witnessPath
                }]);
            using var authority = new DeepIdV2DurableGenesisAuthority(
                new DeepIdV2XPointAuthoritySource(fixture.Network,
                    networkPin, [authorityPath], [policyPath]),
                new DeepIdV2DirectoryBootstrapSource(headPath, headHash),
                custody,
                new FixedTimeSource(), statePath, fixture.Network, key,
                deploymentProfileId: 1, headValiditySeconds: 3_600);
            var forged = new DeepIdV2GenesisAdmissionWireRequest(
                Enumerable.Repeat((byte)0x91, 32).ToArray(),
                new DeepIdV2GenesisAdmissionRequest(
                    Bytes(644, 2), Bytes(356, 3), [Bytes(776, 4)],
                    Bytes(2036, 5), Bytes(3711, 6), Bytes(426, 7),
                    Bytes(458, 8), []));
            await Assert.ThrowsAsync<AccountDirectoryGenesisAdmissionException>(
                async () => await authority.AdmitAsync(forged));
            Assert.Equal(protectedState, await File.ReadAllBytesAsync(statePath));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static byte[] Bytes(int count, byte value) =>
        Enumerable.Repeat(value, count).ToArray();

    private sealed class TrackingLatestHeadFloor(
        AccountDirectoryProtectedLkg initial) :
        IDeepIdV2DirectoryLatestHeadFloor
    {
        private byte[] currentHash = initial.CoreHash.ToArray();

        public int RequireCount { get; private set; }
        public int AdvanceCount { get; private set; }

        public void RequireCurrent(AccountDirectoryProtectedLkg currentHead)
        {
            RequireCount++;
            if (!CryptographicOperations.FixedTimeEquals(
                    currentHash, currentHead.CoreHash.Span))
                throw new CryptographicException(
                    "The injected DID2 floor rejects rollback.");
        }

        public void Advance(AccountDirectoryProtectedLkg expectedHead,
            AccountDirectoryProtectedLkg nextHead)
        {
            RequireCurrent(expectedHead);
            currentHash = nextHead.CoreHash.ToArray();
            AdvanceCount++;
        }
    }

    private sealed class FixedTimeSource(ulong unixTime = 1_700_000_200)
        : IContactResolveTrustedTimeContextSource
    {
        public ValueTask<ContactResolveTrustedTimeContext> ReadAsync(
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(new ContactResolveTrustedTimeContext(
                Bytes(16, 0xc1), 4_000, unixTime, 5));
        }
    }
}
#endif
