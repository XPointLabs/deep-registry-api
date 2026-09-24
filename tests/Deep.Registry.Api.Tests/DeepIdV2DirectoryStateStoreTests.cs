#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Registry.Api.DirectoryPublication;

namespace Deep.Registry.Api.Tests;

public sealed class DeepIdV2DirectoryStateStoreTests
{
    [Fact]
    public async Task Ada2ExternalHeadFloorRejectsRollbackAndAdvancesBeforeStateWrite()
    {
        using var fixture = ContactResolveAuthoringFixture.Create(currentValue: false);
        var root = Path.Combine(Path.GetTempPath(),
            "deep-ada2-floor", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var headPath = Path.Combine(root, "did2-genesis.adh1");
            var statePath = Path.Combine(root, "authority.ada2");
            var exactHead = fixture.CreateDid2GenesisHead();
            var hash = AccountDirectoryCrypto.ComputeAdh1CoreHash(
                AccountDirectoryAdh1Codec.Decode(exactHead));
            var key = Enumerable.Repeat((byte)0x5a, 32).ToArray();
            var rows = new DeepIdV2DirectoryStateRows(
                [new DeepIdV2DirectoryHeadRow(exactHead, hash)], [], []);
            await File.WriteAllBytesAsync(headPath, exactHead);
            await File.WriteAllBytesAsync(statePath,
                DirectoryPublicationProtectedFile.Protect(
                    DeepIdV2DirectoryStateCodec.Encode(fixture.Network, rows),
                    key));
            var floor = new TestHeadFloor(hash);
            using var store = new DeepIdV2DirectoryStateStore(statePath, key,
                fixture.Network,
                new DeepIdV2DirectoryBootstrapSource(headPath, hash),
                fixture.Authority, new DenyingVerifier(), 1, floor);

            using (var lease = store.Open())
            {
                _ = await lease.ReadAsync(1_700_000_100);
                floor.RejectAdvance = true;
                var before = await File.ReadAllBytesAsync(statePath);
                await Assert.ThrowsAsync<InvalidDataException>(async () =>
                    await lease.WriteAsync(rows, 1_700_000_100));
                Assert.Equal(before, await File.ReadAllBytesAsync(statePath));
            }

            floor.RejectAdvance = false;
            floor.SetHead(Enumerable.Repeat((byte)0x77, 32).ToArray());
            using var rejected = store.Open();
            await Assert.ThrowsAsync<InvalidDataException>(async () =>
                await rejected.ReadAsync(1_700_000_100));
            await Assert.ThrowsAsync<InvalidOperationException>(async () =>
                await rejected.WriteAsync(rows, 1_700_000_100));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task Ada2RequiresExplicitProvisioningAndHmacAuthenticatedState()
    {
        using var fixture = ContactResolveAuthoringFixture.Create(currentValue: false);
        var root = Path.Combine(Path.GetTempPath(),
            "deep-ada2-store", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var headPath = Path.Combine(root, "did2-genesis.adh1");
            var statePath = Path.Combine(root, "authority.ada2");
            var exactHead = fixture.CreateDid2GenesisHead();
            var hash = AccountDirectoryCrypto.ComputeAdh1CoreHash(
                AccountDirectoryAdh1Codec.Decode(exactHead));
            var key = Enumerable.Repeat((byte)0x5a, 32).ToArray();
            await File.WriteAllBytesAsync(headPath, exactHead);
            using var store = new DeepIdV2DirectoryStateStore(statePath, key,
                fixture.Network,
                new DeepIdV2DirectoryBootstrapSource(headPath, hash),
                fixture.Authority, new DenyingVerifier(), 1);

            using (var lease = store.Open())
                await Assert.ThrowsAsync<InvalidDataException>(async () =>
                    await lease.ReadAsync(1_700_000_100));

            var rows = new DeepIdV2DirectoryStateRows(
                [new DeepIdV2DirectoryHeadRow(exactHead, hash)], [], []);
            var payload = DeepIdV2DirectoryStateCodec.Encode(fixture.Network, rows);
            await File.WriteAllBytesAsync(statePath,
                DirectoryPublicationProtectedFile.Protect(payload, key));
            using (var lease = store.Open())
            {
                var restored = await lease.ReadAsync(1_700_000_100);
                Assert.Equal(exactHead, restored.CurrentHead.ExactAdh1.ToArray());
                await Assert.ThrowsAsync<InvalidDataException>(async () =>
                    await lease.WriteAsync(
                    new DeepIdV2DirectoryStateRows(
                        [new DeepIdV2DirectoryHeadRow(exactHead,
                            Enumerable.Repeat((byte)0x77, 32).ToArray())], [], []),
                    1_700_000_100));
                _ = await lease.WriteAsync(rows, 1_700_000_100);
            }

            var damaged = await File.ReadAllBytesAsync(statePath);
            damaged[^1] ^= 1;
            await File.WriteAllBytesAsync(statePath, damaged);
            using (var lease = store.Open())
                await Assert.ThrowsAsync<System.Security.Cryptography.CryptographicException>(
                    async () => await lease.ReadAsync(1_700_000_100));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private sealed class DenyingVerifier : IDeepMlDsa65Verifier
    {
        public bool Verify(ReadOnlySpan<byte> publicKey1952,
            ReadOnlySpan<byte> message, ReadOnlySpan<byte> context,
            ReadOnlySpan<byte> signature3309) => false;
    }

    private sealed class TestHeadFloor(ReadOnlySpan<byte> initialHash) :
        IDeepIdV2DirectoryLatestHeadFloor
    {
        private byte[] currentHash = initialHash.ToArray();
        internal bool RejectAdvance { get; set; }

        internal void SetHead(ReadOnlySpan<byte> hash) =>
            currentHash = hash.ToArray();

        public ValueTask RequireCurrentAsync(
            AccountDirectoryProtectedLkg currentHead,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!CryptographicOperations.FixedTimeEquals(currentHash,
                    currentHead.CoreHash.Span))
                throw new InvalidDataException("Independent DID2 head floor mismatch.");
            return ValueTask.CompletedTask;
        }

        public async ValueTask AdvanceAsync(AccountDirectoryProtectedLkg expectedHead,
            AccountDirectoryProtectedLkg nextHead,
            CancellationToken cancellationToken = default)
        {
            await RequireCurrentAsync(expectedHead, cancellationToken);
            if (RejectAdvance)
                throw new InvalidDataException("Independent floor write failed.");
            currentHash = nextHead.CoreHash.ToArray();
        }
    }
}
#endif
