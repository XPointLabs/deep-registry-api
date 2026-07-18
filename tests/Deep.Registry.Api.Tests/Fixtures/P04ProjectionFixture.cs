using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.Membership;
using Microsoft.Extensions.Options;

namespace Deep.Registry.Api.Tests.Fixtures;

internal sealed class DeterministicP04Verifier : IMembershipSignatureVerifier
{
    public bool Verify(
        ReadOnlySpan<byte> signerId,
        ReadOnlySpan<byte> publicKey,
        MembershipSignatureDomain domain,
        ReadOnlySpan<byte> signingBytes,
        ReadOnlySpan<byte> signature) =>
        signature.SequenceEqual(SignFramed(signerId, publicKey, signingBytes));

    public byte[] Sign(
        MembershipSignerDescriptor signer,
        MembershipSignatureDomain domain,
        ReadOnlySpan<byte> canonicalStatement) =>
        SignFramed(
            signer.SignerId.Span,
            signer.PublicKey.Span,
            MembershipSigningDomains.Frame(domain, canonicalStatement));

    private static byte[] SignFramed(
        ReadOnlySpan<byte> signerId,
        ReadOnlySpan<byte> publicKey,
        ReadOnlySpan<byte> signingBytes)
    {
        var framed = new byte[signerId.Length + publicKey.Length + signingBytes.Length];
        signerId.CopyTo(framed);
        publicKey.CopyTo(framed.AsSpan(signerId.Length));
        signingBytes.CopyTo(framed.AsSpan(signerId.Length + publicKey.Length));
        return SHA256.HashData(framed);
    }
}

internal sealed class ManualTimeProvider(DateTimeOffset value) : TimeProvider
{
    public DateTimeOffset Value { get; set; } = value;

    public override DateTimeOffset GetUtcNow() => Value;
}

internal sealed class MemoryProjectionPersistence : IMembershipProjectionPersistence
{
    public byte[]? State { get; set; }
    public bool ThrowOnWrite { get; set; }
    public bool Quarantined { get; private set; }

    public byte[]? Read() => State?.ToArray();

    public void Write(ReadOnlySpan<byte> state)
    {
        if (ThrowOnWrite)
        {
            throw new IOException("fixture write failure");
        }

        State = state.ToArray();
    }

    public void Quarantine()
    {
        Quarantined = true;
        State = null;
    }
}

internal sealed class P04ProjectionFixture
{
    public const long NowUnixSeconds = 2_000_000_000;

    private readonly MembershipSignerDescriptor[] _offline;
    private readonly MembershipSignerDescriptor[] _online;

    public P04ProjectionFixture()
    {
        Verifier = new DeterministicP04Verifier();
        Time = new ManualTimeProvider(DateTimeOffset.FromUnixTimeSeconds(NowUnixSeconds));
        _offline = Enumerable.Range(0, 5)
            .Select(index => new MembershipSignerDescriptor
            {
                SignerId = Range(0x10 + index * 16, MembershipLimits.SignerIdLength),
                Role = MembershipSignerRole.OfflineRoot,
                PublicKey = Range(0xe0 + index * 3, MembershipLimits.PublicKeyLength)
            })
            .ToArray();
        _online = Enumerable.Range(0, 3)
            .Select(index => new MembershipSignerDescriptor
            {
                SignerId = Range(0x40 + index * 16, MembershipLimits.SignerIdLength),
                Role = MembershipSignerRole.Online,
                PublicKey = Range(0x80 + index * 3, MembershipLimits.PublicKeyLength)
            })
            .ToArray();
        Genesis = new NetworkGenesis
        {
            NetworkId = Range(0x70, MembershipLimits.NetworkIdLength),
            GenesisSequence = 1,
            PolicyVersion = 1,
            MinimumProtocol = 1,
            MaximumProtocol = 3,
            IssuedAtUnixSeconds = (ulong)NowUnixSeconds - 500,
            Policy = MembershipPolicy.Beta(
                _offline.Select(value => value.SignerId).ToArray()),
            OfflineRoots = _offline
        };
        GenesisBytes = MembershipContractCodec.EncodeGenesis(Genesis);
        GenesisHash = MembershipContractHash.Sha256(GenesisBytes);
        GenesisSignatures = _offline.Take(3)
            .Select(signer => Signature(
                signer,
                MembershipSignatureDomain.Genesis,
                GenesisBytes))
            .ToArray();
        Delegation = BuildDelegation();
        DelegationBytes = MembershipContractCodec.EncodeSignedDelegation(Delegation);
    }

    public DeterministicP04Verifier Verifier { get; }
    public ManualTimeProvider Time { get; }
    public NetworkGenesis Genesis { get; }
    public byte[] GenesisBytes { get; }
    public byte[] GenesisHash { get; }
    public IReadOnlyList<MembershipSignature> GenesisSignatures { get; }
    public SignerDelegation Delegation { get; }
    public byte[] DelegationBytes { get; }

    public MembershipProjectionOptions Options(string? statePath = null) =>
        new()
        {
            Enabled = true,
            StatePath = statePath,
            ExpectedNetworkIdHex =
                Convert.ToHexString(Genesis.NetworkId.Span).ToLowerInvariant(),
            ExpectedGenesisSha256Hex =
                Convert.ToHexString(GenesisHash).ToLowerInvariant(),
            AllowedClockSkewSeconds = 30,
            ClientProtocol = 2
        };

    public MembershipProjectionService CreateService(
        IMembershipProjectionPersistence persistence) =>
        new(
            Microsoft.Extensions.Options.Options.Create(Options()),
            Time,
            P04MembershipArtifactVerifier.Create([Verifier]),
            persistence);

    public void SeedAuthority(MembershipProjectionService service)
    {
        Assert.Equal(
            MembershipProjectionCode.Accepted,
            service.ApplyGenesis(GenesisBytes, GenesisSignatures).Code);
        Assert.Equal(
            MembershipProjectionCode.Accepted,
            service.ApplyDelegation(DelegationBytes).Code);
    }

    public byte[] Bridge(
        ulong sequence = 2,
        ReadOnlyMemory<byte>? previousHash = null,
        string contact = "https://bridge.example.invalid/v1",
        int signerCount = 2,
        ulong? validFrom = null,
        ulong? validUntil = null,
        ReadOnlyMemory<byte>? networkId = null,
        ushort minimumProtocol = 1,
        ushort maximumProtocol = 3)
    {
        var effectiveValidFrom = validFrom ?? (ulong)NowUnixSeconds - 100;
        var effectiveValidUntil = validUntil ?? (ulong)NowUnixSeconds + 1000;
        var statement = new BridgeSnapshot
        {
            NetworkId = networkId?.ToArray() ?? Genesis.NetworkId.ToArray(),
            Sequence = sequence,
            PreviousHash = previousHash?.ToArray() ?? GenesisHash.ToArray(),
            IssuedAtUnixSeconds = effectiveValidFrom,
            ValidFromUnixSeconds = effectiveValidFrom,
            ValidUntilUnixSeconds = effectiveValidUntil,
            MinimumProtocol = minimumProtocol,
            MaximumProtocol = maximumProtocol,
            PolicyVersion = 1,
            EntryContacts =
            [
                new BridgeEntryContact
                {
                    EntryId = Range(0x01, MembershipLimits.SignerIdLength),
                    Contact = contact
                }
            ],
            ForkWitness = new ForkWitnessRecord
            {
                CandidateDomain = MembershipSignatureDomain.Bridge,
                Sequence = sequence,
                PreviousHash = previousHash?.ToArray() ?? GenesisHash.ToArray(),
                CandidateHash = new byte[MembershipLimits.HashLength]
            }
        };
        statement = statement with
        {
            ForkWitness = statement.ForkWitness with
            {
                CandidateHash = MembershipContractHash.Sha256(
                    MembershipContractCodec.GetBridgeCandidateBytes(statement))
            }
        };
        var canonical = MembershipContractCodec.GetBridgeSigningBytes(statement);
        return MembershipContractCodec.EncodeSignedBridge(new SignedBridgeSnapshot
        {
            Statement = statement,
            Signatures = _online.Take(signerCount)
                .Select(signer => Signature(
                    signer,
                    MembershipSignatureDomain.Bridge,
                    canonical))
                .ToArray()
        });
    }

    public byte[] Membership(
        ulong sequence = 2,
        ReadOnlyMemory<byte>? previousHash = null,
        uint memberCount = 3)
    {
        var statement = new NodeMembershipCommitment
        {
            NetworkId = Genesis.NetworkId.ToArray(),
            Sequence = sequence,
            PreviousHash = previousHash?.ToArray() ?? GenesisHash.ToArray(),
            IssuedAtUnixSeconds = (ulong)NowUnixSeconds - 100,
            ValidFromUnixSeconds = (ulong)NowUnixSeconds - 100,
            ValidUntilUnixSeconds = (ulong)NowUnixSeconds + 1000,
            MinimumProtocol = 1,
            MaximumProtocol = 3,
            PolicyVersion = 1,
            MemberCount = memberCount,
            MerkleRoot = Range(0xc0 + (int)memberCount, MembershipLimits.HashLength)
        };
        var canonical = MembershipContractCodec.GetMembershipSigningBytes(statement);
        return MembershipContractCodec.EncodeSignedMembership(new SignedMembershipCommitment
        {
            Statement = statement,
            Signatures = _online.Take(2)
                .Select(signer => Signature(
                    signer,
                    MembershipSignatureDomain.Membership,
                    canonical))
                .ToArray()
        });
    }

    public static byte[] CanonicalBridgeHash(byte[] signedBridge)
    {
        var value = MembershipContractCodec.DecodeSignedBridge(signedBridge);
        return MembershipContractHash.Sha256(
            MembershipContractCodec.GetBridgeSigningBytes(value.Statement));
    }

    public byte[] Revocation()
    {
        var delegationHash = MembershipContractHash.Sha256(
            MembershipContractCodec.GetDelegationSigningBytes(Delegation));
        var unsigned = new SignerRevocation
        {
            NetworkId = Genesis.NetworkId.ToArray(),
            Sequence = 3,
            PreviousHash = delegationHash,
            IssuedAtUnixSeconds = (ulong)NowUnixSeconds - 50,
            ValidFromUnixSeconds = (ulong)NowUnixSeconds - 50,
            ValidUntilUnixSeconds = (ulong)NowUnixSeconds + 1000,
            MinimumProtocol = 1,
            MaximumProtocol = 3,
            PolicyVersion = 1,
            DelegationHash = delegationHash,
            Signatures = []
        };
        var canonical = MembershipContractCodec.GetRevocationSigningBytes(unsigned);
        return MembershipContractCodec.EncodeSignedRevocation(unsigned with
        {
            Signatures = _offline.Take(3)
                .Select(signer => Signature(
                    signer,
                    MembershipSignatureDomain.OfflineRevocation,
                    canonical))
                .ToArray()
        });
    }

    private SignerDelegation BuildDelegation()
    {
        var unsigned = new SignerDelegation
        {
            NetworkId = Genesis.NetworkId.ToArray(),
            Sequence = 2,
            PreviousHash = GenesisHash.ToArray(),
            IssuedAtUnixSeconds = (ulong)NowUnixSeconds - 200,
            ValidFromUnixSeconds = (ulong)NowUnixSeconds - 200,
            ValidUntilUnixSeconds = (ulong)NowUnixSeconds + 2000,
            MinimumProtocol = 1,
            MaximumProtocol = 3,
            PolicyVersion = 1,
            OnlineSigners = _online,
            Signatures = []
        };
        var canonical = MembershipContractCodec.GetDelegationSigningBytes(unsigned);
        return unsigned with
        {
            Signatures = _offline.Take(3)
                .Select(signer => Signature(
                    signer,
                    MembershipSignatureDomain.OfflineDelegation,
                    canonical))
                .ToArray()
        };
    }

    private MembershipSignature Signature(
        MembershipSignerDescriptor signer,
        MembershipSignatureDomain domain,
        ReadOnlySpan<byte> canonical) =>
        new()
        {
            SignerId = signer.SignerId.ToArray(),
            Domain = domain,
            Signature = Verifier.Sign(signer, domain, canonical)
        };

    private static byte[] Range(int start, int length) =>
        Enumerable.Range(start, length).Select(value => unchecked((byte)value)).ToArray();
}
