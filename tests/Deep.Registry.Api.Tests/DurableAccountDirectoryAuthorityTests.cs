#if DEEP_PROTOCOL_DIRECTORY_V1
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepNative;
using Deep.Registry.Api.DirectoryPublication;
using Sodium;

namespace Deep.Registry.Api.Tests;

public sealed class DurableAccountDirectoryAuthorityTests
{
    [Fact]
    public async Task GenesisAdmissionIsIdempotentDurableAndImmediatelyQueryable()
    {
        using var fixture = ContactResolveAuthoringFixture.Create(currentValue: false);
        var root = TempPath();
        Directory.CreateDirectory(root);
        try
        {
            var custodyOptions = await WriteWitnessCustodyAsync(root, fixture);
            var statePath = Path.Combine(root, "directory-authority.state");
            var options = new AccountDirectoryAuthorityOptions
            {
                StatePath = statePath,
                DeploymentProfileId = 7,
                SupportedReader = 1,
                HeadValiditySeconds = 1_000,
                RenewalLeadSeconds = 100,
            };
            var admission = ValidAdmission(fixture.Network, Bytes(0x90, 32));
            byte[] firstHead;
            byte[] leaf;

            using (var custody = new FileContactResolveDtt1WitnessCustody(
                       fixture.Network, custodyOptions))
            using (var authority = new DurableAccountDirectoryAuthority(
                       new FixedBootstrap(
                           fixture.Snapshot,
                           fixture.ProofMaterial.QueriedDirectoryLeafKey),
                       custody,
                       // The authenticated clock may trail the account issuer while
                       // the issuance remains inside its declared uncertainty.
                       new FixedTime(1_700_000_119),
                       options,
                       fixture.Network,
                       Bytes(0x70, 32)))
            {
                var first = await authority.AdmitAsync(admission, default);
                var replay = await authority.AdmitAsync(admission, default);
                Assert.Equal(first.ExactAdh1.ToArray(), replay.ExactAdh1.ToArray());
                var head = AccountDirectoryAdh1Codec.Decode(first.ExactAdh1.Span);
                Assert.Equal<ulong>(1, head.LogGeneration);
                Assert.Equal<ulong>(1, head.TreeSize);
                firstHead = first.ExactAdh1.ToArray();
                leaf = first.DirectoryLeafKey.ToArray();
            }

            using (var custody = new FileContactResolveDtt1WitnessCustody(
                       fixture.Network, custodyOptions))
            using (var restored = new DurableAccountDirectoryAuthority(
                       new FixedBootstrap(
                           fixture.Snapshot,
                           fixture.ProofMaterial.QueriedDirectoryLeafKey),
                       custody,
                       new FixedTime(1_700_000_250),
                       options,
                       fixture.Network,
                       Bytes(0x70, 32)))
            {
                var query = new ContactResolveDirectoryPackageRequest(
                    fixture.Network,
                    Bytes(0x35, 32),
                    Bytes(0x36, 16),
                    101,
                    null,
                    null,
                    null,
                    leaf,
                    null,
                    null,
                    true);
                var snapshot = await restored.ReadAsync(query, default);
                Assert.Equal(firstHead, snapshot.CurrentDirectoryHead.ExactAdh1.ToArray());
                var proof = await restored.ReadAsync(snapshot, query, default);
                Assert.Equal(AccountDirectoryAdp1ResultKind.CurrentValue, proof.ResultKind);
                Assert.Equal(leaf, proof.QueriedDirectoryLeafKey.ToArray());
            }
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task RenewalPersistsAndRestoresExactThresholdHeadAndProofState()
    {
        using var fixture = ContactResolveAuthoringFixture.Create(currentValue: false);
        var root = TempPath();
        Directory.CreateDirectory(root);
        try
        {
            var custodyOptions = new List<ContactResolveWitnessCustodyOptions>();
            for (var index = 0; index < 3; index++)
            {
                var seedPath = Path.Combine(root, $"witness-{index}.seed");
                await File.WriteAllBytesAsync(
                    seedPath,
                    Bytes(checked((byte)(0x50 + index)), 32));
                custodyOptions.Add(new ContactResolveWitnessCustodyOptions
                {
                    WitnessIdHex = Convert.ToHexString(
                        fixture.Authority.WitnessKeys[index].Id.Span),
                    KeyGeneration = 0,
                    Ed25519SeedPath = seedPath,
                });
            }
            var statePath = Path.Combine(root, "directory-authority.state");
            var options = new AccountDirectoryAuthorityOptions
            {
                Enabled = true,
                NetworkIdHex = Convert.ToHexString(fixture.Network),
                StatePath = statePath,
                IntegrityKeyPath = Path.Combine(root, "unused.key"),
                DeploymentProfileId = 1,
                SupportedReader = 1,
                HeadValiditySeconds = 1_000,
                RenewalLeadSeconds = 600,
            };
            var request = Request(fixture.Network);
            byte[] firstHead;

            using (var custody = new FileContactResolveDtt1WitnessCustody(
                       fixture.Network, custodyOptions))
            using (var authority = new DurableAccountDirectoryAuthority(
                       new FixedBootstrap(
                           fixture.Snapshot,
                           fixture.ProofMaterial.QueriedDirectoryLeafKey),
                       custody,
                       new FixedTime(1_700_009_500),
                       options,
                       fixture.Network,
                       Bytes(0x70, 32)))
            {
                var snapshot = await authority.ReadAsync(request, default);
                Assert.Equal<ulong>(1, snapshot.CurrentDirectoryHead.LogGeneration);
                Assert.Equal<ulong>(0, snapshot.CurrentDirectoryHead.TreeSize);
                var proof = await authority.ReadAsync(snapshot, request, default);
                Assert.Equal(AccountDirectoryAdp1ResultKind.NonMembership, proof.ResultKind);
                firstHead = snapshot.CurrentDirectoryHead.ExactAdh1.ToArray();
            }

            Assert.True(File.Exists(statePath));
            using (var custody = new FileContactResolveDtt1WitnessCustody(
                       fixture.Network, custodyOptions))
            using (var restored = new DurableAccountDirectoryAuthority(
                       new FixedBootstrap(
                           fixture.Snapshot,
                           fixture.ProofMaterial.QueriedDirectoryLeafKey),
                       custody,
                       new FixedTime(1_700_009_600),
                       options,
                       fixture.Network,
                       Bytes(0x70, 32)))
            {
                var snapshot = await restored.ReadAsync(request, default);
                Assert.Equal(firstHead, snapshot.CurrentDirectoryHead.ExactAdh1.ToArray());
                Assert.Equal<ulong>(1, snapshot.CurrentDirectoryHead.LogGeneration);
            }
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task ChangedProtectedStateFailsClosedBeforeProofPublication()
    {
        using var fixture = ContactResolveAuthoringFixture.Create(currentValue: false);
        var root = TempPath();
        Directory.CreateDirectory(root);
        try
        {
            var custodyOptions = new List<ContactResolveWitnessCustodyOptions>();
            for (var index = 0; index < 3; index++)
            {
                var seedPath = Path.Combine(root, $"witness-{index}.seed");
                await File.WriteAllBytesAsync(
                    seedPath,
                    Bytes(checked((byte)(0x50 + index)), 32));
                custodyOptions.Add(new ContactResolveWitnessCustodyOptions
                {
                    WitnessIdHex = Convert.ToHexString(
                        fixture.Authority.WitnessKeys[index].Id.Span),
                    KeyGeneration = 0,
                    Ed25519SeedPath = seedPath,
                });
            }
            var statePath = Path.Combine(root, "directory-authority.state");
            var options = new AccountDirectoryAuthorityOptions
            {
                StatePath = statePath,
                DeploymentProfileId = 1,
                SupportedReader = 1,
                HeadValiditySeconds = 1_000,
                RenewalLeadSeconds = 600,
            };
            using var custody = new FileContactResolveDtt1WitnessCustody(
                fixture.Network, custodyOptions);
            using var authority = new DurableAccountDirectoryAuthority(
                new FixedBootstrap(
                    fixture.Snapshot,
                    fixture.ProofMaterial.QueriedDirectoryLeafKey),
                custody,
                new FixedTime(1_700_009_500),
                options,
                fixture.Network,
                Bytes(0x70, 32));
            _ = await authority.ReadAsync(Request(fixture.Network), default);
            var changed = await File.ReadAllBytesAsync(statePath);
            changed[^1] ^= 1;
            await File.WriteAllBytesAsync(statePath, changed);

            await Assert.ThrowsAsync<System.Security.Cryptography.CryptographicException>(
                () => authority.ReadAsync(Request(fixture.Network), default).AsTask());
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static ContactResolveDirectoryPackageRequest Request(byte[] network) =>
        new(
            network,
            Bytes(0x31, 32),
            Bytes(0x32, 16),
            100,
            null,
            null,
            null);

    [Fact]
    public async Task UntargetedReadUsesBootstrapLookupKeyInsteadOfCallerNonce()
    {
        using var fixture = ContactResolveAuthoringFixture.Create(currentValue: false);
        var root = TempPath();
        Directory.CreateDirectory(root);
        try
        {
            var custodyOptions = await WriteWitnessCustodyAsync(root, fixture);
            var request = Request(fixture.Network);
            var options = new AccountDirectoryAuthorityOptions
            {
                StatePath = Path.Combine(root, "directory-authority.state"),
                DeploymentProfileId = 1,
                SupportedReader = 1,
                HeadValiditySeconds = 1_000,
                RenewalLeadSeconds = 100,
            };
            using var custody = new FileContactResolveDtt1WitnessCustody(
                fixture.Network, custodyOptions);
            using var authority = new DurableAccountDirectoryAuthority(
                new FixedBootstrap(
                    fixture.Snapshot,
                    fixture.ProofMaterial.QueriedDirectoryLeafKey),
                custody,
                new FixedTime(1_700_000_119),
                options,
                fixture.Network,
                Bytes(0x70, 32));

            var snapshot = await authority.ReadAsync(request, default);
            var proof = await authority.ReadAsync(snapshot, request, default);

            Assert.Equal(
                fixture.ProofMaterial.QueriedDirectoryLeafKey.ToArray(),
                proof.QueriedDirectoryLeafKey.ToArray());
            Assert.NotEqual(
                request.Nonce.ToArray(),
                proof.QueriedDirectoryLeafKey.ToArray());
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static async Task<List<ContactResolveWitnessCustodyOptions>>
        WriteWitnessCustodyAsync(
            string root,
            ContactResolveAuthoringFixture fixture)
    {
        var result = new List<ContactResolveWitnessCustodyOptions>();
        for (var index = 0; index < 3; index++)
        {
            var seedPath = Path.Combine(root, $"authority-witness-{index}.seed");
            await File.WriteAllBytesAsync(
                seedPath,
                Bytes(checked((byte)(0x50 + index)), 32));
            result.Add(new ContactResolveWitnessCustodyOptions
            {
                WitnessIdHex = Convert.ToHexString(
                    fixture.Authority.WitnessKeys[index].Id.Span),
                KeyGeneration = 0,
                Ed25519SeedPath = seedPath,
            });
        }
        return result;
    }

    private static AccountDirectoryGenesisAdmissionWireRequest ValidAdmission(
        byte[] network,
        byte[] operationId)
    {
        var deviceId = Bytes(0x33, 32);
        var addressKey = PublicKeyAuth.GenerateKeyPair(Bytes(0x34, 32));
        var accountKey = PublicKeyAuth.GenerateKeyPair(Bytes(0x35, 32));
        var deviceIssuerKey = PublicKeyAuth.GenerateKeyPair(Bytes(0x36, 32));
        var revocationKey = PublicKeyAuth.GenerateKeyPair(Bytes(0x37, 32));
        var resetKey = PublicKeyAuth.GenerateKeyPair(Bytes(0x38, 32));

        var dpaFields = MinimumFields(RecordDefinitions.Dpa1);
        dpaFields[0] = network;
        dpaFields[1] = U64(1);
        dpaFields[2] = U64(1);
        dpaFields[4] = accountKey.PublicKey;
        dpaFields[5] = deviceIssuerKey.PublicKey;
        dpaFields[6] = revocationKey.PublicKey;
        dpaFields[7] = resetKey.PublicKey;
        dpaFields[8] = Bytes(0x44, 32);
        dpaFields[9] = U64(100);
        dpaFields[10] = U64(1);
        dpaFields[11] = U16(ArtifactRegistry.IdentityAuthV1Ed25519);
        var unsignedDpa = CanonicalGrammar.DecodeOwned(
            CanonicalGrammar.Encode(RecordDefinitions.Dpa1, dpaFields),
            RecordDefinitions.Dpa1);
        var dpaInput = CanonicalGrammar.GetSigningBytes(
            unsignedDpa, "Deep/IdentityAuth/V1/account-certificate");
        dpaFields[12] = PublicKeyAuth.SignDetached(dpaInput, accountKey.PrivateKey);
        dpaFields[13] = PublicKeyAuth.SignDetached(dpaInput, deviceIssuerKey.PrivateKey);
        dpaFields[14] = PublicKeyAuth.SignDetached(dpaInput, revocationKey.PrivateKey);
        dpaFields[15] = PublicKeyAuth.SignDetached(dpaInput, resetKey.PrivateKey);
        var exactDpa = CanonicalGrammar.Encode(RecordDefinitions.Dpa1, dpaFields);
        var account = IdentityVerifier.VerifyAccountCertificate(exactDpa);
        var accountId = account.DeepAccountIdHash.ToArray();

        var drsFields = MinimumFields(RecordDefinitions.Drs1);
        drsFields[0] = network;
        drsFields[1] = accountId;
        drsFields[2] = U64(1);
        drsFields[3] = U64(1);
        drsFields[4] = U64(100);
        drsFields[5] = U64(0);
        drsFields[6] = new byte[38];
        drsFields[7] = IdentityAuthorityVerifier.ComputeKeyHash(
            network, KeyScope.AccountRevocation, accountId, 1,
            revocationKey.PublicKey);
        drsFields[8] = U16(0);
        drsFields[9] = ReadOnlyMemory<byte>.Empty;
        drsFields[10] = new byte[32];
        var unsignedDrs = CanonicalGrammar.DecodeOwned(
            CanonicalGrammar.Encode(RecordDefinitions.Drs1, drsFields),
            RecordDefinitions.Drs1);
        drsFields[11] = PublicKeyAuth.SignDetached(
            CanonicalGrammar.GetSigningBytes(
                unsignedDrs, "Deep/IdentityAuth/V1/revocation-snapshot"),
            revocationKey.PrivateKey);
        var exactDrs = CanonicalGrammar.Encode(RecordDefinitions.Drs1, drsFields);
        var verifier = new IdentityRelativeVerifier();
        var relativeIdentity = verifier.VerifyGenesis(exactDpa, exactDrs, [], 100);
        var revocations = relativeIdentity.Revocations;

        var deviceKey = PublicKeyAuth.GenerateKeyPair(Bytes(0x39, 32));
        var dpdFields = MinimumFields(RecordDefinitions.Dpd1);
        dpdFields[0] = network;
        dpdFields[1] = accountId;
        dpdFields[2] = U64(1);
        dpdFields[3] = deviceId;
        dpdFields[4] = U64(1);
        dpdFields[5] = deviceKey.PublicKey;
        dpdFields[6] = Bytes(0x51, 32);
        dpdFields[7] = Bytes(0x52, 32);
        dpdFields[8] = U64(0);
        dpdFields[9] = new byte[38];
        dpdFields[10] = IdentityAuthorityVerifier.ComputeKeyHash(
            network, KeyScope.DeviceCertificateIssuer, accountId, 1,
            deviceIssuerKey.PublicKey);
        dpdFields[11] = U64(revocations.Snapshot.Revision);
        dpdFields[12] = Reference(revocations.Snapshot).CanonicalBytes;
        dpdFields[13] = U64(revocations.Snapshot.EntryCount);
        dpdFields[14] = revocations.Snapshot.CurrentHead;
        dpdFields[15] = U64(100);
        dpdFields[16] = U64(2_000_000_000);
        dpdFields[17] = U64((ulong)DeviceCapabilities.MailboxRoleIssuer);
        dpdFields[18] = U16(ArtifactRegistry.IdentityAuthV1Ed25519);
        dpdFields[20] = Bytes(0x55, 32);
        var unsignedDpd = CanonicalGrammar.DecodeOwned(
            CanonicalGrammar.Encode(RecordDefinitions.Dpd1, dpdFields),
            RecordDefinitions.Dpd1);
        var dpdInput = CanonicalGrammar.GetSigningBytes(
            unsignedDpd, "Deep/IdentityAuth/V1/device-certificate");
        dpdFields[21] = PublicKeyAuth.SignDetached(dpdInput, deviceKey.PrivateKey);
        dpdFields[22] = PublicKeyAuth.SignDetached(dpdInput, deviceIssuerKey.PrivateKey);
        var exactDpd = CanonicalGrammar.Encode(RecordDefinitions.Dpd1, dpdFields);
        var device = verifier.RestoreDeviceFromRecovery(
            relativeIdentity, exactDpd, 100);
        var identity = ApplicationCoreVerifier.CreateIdentityClosure(
            relativeIdentity, [device]);

        var deepId = ApplicationCoreCodec.AuthorDid1(
            addressKey.PublicKey, Bytes(0x66, 16));
        var realm = ApplicationCoreCodec.DeriveIdentityRealmId(network, 7);
        var dpaReference = Reference(account.Certificate);
        var unsignedDab = ApplicationCoreCodec.AuthorDab1(
            deepId.RecordHash.Span,
            realm.Span,
            0,
            new byte[32],
            accountId,
            1,
            dpaReference,
            new byte[64],
            new byte[64]);
        var binding = ApplicationCoreVerifier.VerifyDab1(
            ApplicationCoreCodec.AuthorDab1(
                deepId.RecordHash.Span,
                realm.Span,
                0,
                new byte[32],
                accountId,
                1,
                dpaReference,
                PublicKeyAuth.SignDetached(
                    unsignedDab.AddressSignatureInput.ToArray(), addressKey.PrivateKey),
                PublicKeyAuth.SignDetached(
                    unsignedDab.AccountSignatureInput.ToArray(), accountKey.PrivateKey)),
            deepId,
            identity,
            7);
        var directoryEntry = new DeviceDirectoryEntry(
            deviceId, Reference(device.Certificate));
        var unsignedDmd = ApplicationCoreCodec.AuthorDmd1(
            network,
            accountId,
            1,
            dpaReference,
            Reference(revocations.Snapshot),
            1,
            new byte[32],
            [directoryEntry],
            100,
            new byte[64]);
        var directory = ApplicationCoreVerifier.VerifyDmd1(
            ApplicationCoreCodec.AuthorDmd1(
                network,
                accountId,
                1,
                dpaReference,
                Reference(revocations.Snapshot),
                1,
                new byte[32],
                [directoryEntry],
                100,
                PublicKeyAuth.SignDetached(
                    unsignedDmd.SignatureInput.ToArray(), deviceIssuerKey.PrivateKey)),
            identity);
        ReadOnlyMemory<byte>[] revoked = [];
        var leaf = AccountDirectoryAdc1Verifier.ComputeDirectoryLeafKey(
            network, deepId.CanonicalBytes.Span);
        var unsignedAdc = new AccountDirectoryAdc1(
            network,
            leaf,
            1,
            0,
            new byte[32],
            AccountDirectoryCrypto.CreateReference(
                "DPA1"u8, 1, account.Certificate.CanonicalHash.Span),
            AccountDirectoryCrypto.CreateReference(
                "DRS1"u8, 1, revocations.Snapshot.CanonicalHash.Span),
            directory.Record.RecordHash.Span,
            binding.Record.RecordHash.Span,
            AccountDirectoryAdc1Verifier.ComputeRevokedDcaAuthorizationIdsHash(revoked),
            1_700_000_123,
            1,
            Bytes(0x01, 64));
        var adcSignature = PublicKeyAuth.SignDetached(
            AccountDirectoryCrypto.ComputeAdc1SigningInput(unsignedAdc),
            deviceIssuerKey.PrivateKey);
        var adc = new AccountDirectoryAdc1(
            unsignedAdc.NetworkId.Span,
            unsignedAdc.DirectoryLeafKey.Span,
            unsignedAdc.AccountGeneration,
            unsignedAdc.CheckpointGeneration,
            unsignedAdc.PredecessorCheckpointHash.Span,
            unsignedAdc.ExactDpa1Reference.Span,
            unsignedAdc.ExactDrs1Reference.Span,
            unsignedAdc.ExactDmd1Hash.Span,
            unsignedAdc.ExactDab1Hash.Span,
            unsignedAdc.RevokedDcaAuthorizationIdsHash.Span,
            unsignedAdc.IssuedAt,
            unsignedAdc.MinimumReader,
            adcSignature);
        _ = AccountDirectoryAdc1Verifier.Verify(
            adc, binding, directory, revoked, 1);
        return new AccountDirectoryGenesisAdmissionWireRequest(
            operationId,
            new AccountDirectoryGenesisAdmissionRequest(
                exactDpa,
                exactDrs,
                [exactDpd],
                deepId.CanonicalBytes.Span,
                binding.Record.CanonicalBytes.Span,
                directory.Record.CanonicalBytes.Span,
                AccountDirectoryAdc1Codec.Encode(adc),
                revoked));
    }

    private static ReadOnlyMemory<byte>[] MinimumFields(RecordDefinition definition) =>
        definition.Fields.Select(static field =>
            (ReadOnlyMemory<byte>)new byte[field.MinimumLength]).ToArray();

    private static ApplicationArtifactReference Reference(CanonicalIdentityArtifact value) =>
        ApplicationCoreCodec.CreateArtifactReference(
            (ushort)value.ArtifactType,
            checked((uint)value.CanonicalBytes.Length),
            value.CanonicalHash.Span);

    private static byte[] U16(ushort value)
    {
        var result = new byte[2];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(result, value);
        return result;
    }

    private static byte[] U64(ulong value)
    {
        var result = new byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(result, value);
        return result;
    }

    private static string TempPath() => Path.Combine(
        Path.GetTempPath(),
        "deep-account-directory-authority",
        Guid.NewGuid().ToString("N"));

    private static byte[] Bytes(byte value, int length) =>
        Enumerable.Repeat(value, length).ToArray();

    private sealed class FixedBootstrap(
        ContactResolveCanonicalDirectorySnapshot snapshot,
        ReadOnlyMemory<byte> defaultDirectoryLookupKey)
        : IAccountDirectoryAuthorityBootstrapSource
    {
        public ValueTask<AccountDirectoryAuthorityBootstrapSnapshot> ReadAsync(
            ContactResolveDirectoryPackageRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(new AccountDirectoryAuthorityBootstrapSnapshot(
                snapshot,
                defaultDirectoryLookupKey));
        }
    }

    private sealed class FixedTime(ulong unixSeconds)
        : IContactResolveTrustedTimeContextSource
    {
        public ValueTask<ContactResolveTrustedTimeContext> ReadAsync(
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(new ContactResolveTrustedTimeContext(
                Bytes(0x33, 16),
                1_000,
                unixSeconds,
                5));
        }
    }
}
#endif
