#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Runtime.Versioning;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.XPointNetworkV1;
using Deep.Registry.Api.DirectoryPublication;
using Sodium;

namespace Deep.Registry.Api.Tests;

public sealed class MailboxRoleSignerTests
{
    private static byte[] B(int length, byte value) => Enumerable.Repeat(value, length).ToArray();
    internal static MailboxAuthenticatedGrant Grant(MailboxCapabilityDomain role, byte[] key) => new() {
        Domain=role, Lifecycle=MailboxCapabilityLifecycle.Active, NetworkId=B(16, 1), Epoch=1, Generation=2,
        Serial=B(16, 2), NotBeforeUnixSeconds=100, ExpiresAtUnixSeconds=200, OverlapUntilUnixSeconds=0,
        PlacementCommitment=B(32, 3), MembershipCommitment=B(32, 4), IssuerPublicKey=key,
        HolderPublicKey=B(32, 5), SelectionInput=B(32, 6), IssuerSignature=B(64, 1) };
    internal static byte[] Revocation(MailboxCapabilityDomain role, byte[] key, int count=0) {
        var serials=new byte[count*16]; for(var i=0;i<count;i++) BinaryPrimitives.WriteUInt32BigEndian(serials.AsSpan(i*16+12), checked((uint)i+1));
        return MailboxGrantRevocationV1Codec.CreateSignatureInput([B(16,1), "PMA2\0\x01"u8.ToArray().Concat(B(32,1)).ToArray(),
            new byte[]{(byte)role}, key, U64(1), new byte[32], U64(100), U64(100), U64(200), U32((uint)count), serials]);
    }
    private static byte[] U64(ulong n){var b=new byte[8];BinaryPrimitives.WriteUInt64BigEndian(b,n);return b;}
    private static byte[] U32(uint n){var b=new byte[4];BinaryPrimitives.WriteUInt32BigEndian(b,n);return b;}

    [Theory]
    [InlineData(MailboxCapabilityDomain.Deposit)] [InlineData(MailboxCapabilityDomain.Retrieve)]
    public void OnlyCanonicalAssignedNetworkKeyAndRoleInputsPass(MailboxCapabilityDomain role)
    {
        var key=B(32,7); var grant=MailboxAuthenticatedCapabilityCodec.GetGrantSigningBytes(Grant(role,key));
        var mgr=Revocation(role,key); var maximum=Revocation(role,key,4096);
        foreach(var input in new[]{grant,mgr,maximum}) {
            MailboxRoleSigner.ValidateSigningInput(input,role,B(16,1),key);
            Assert.Throws<CryptographicException>(()=>MailboxRoleSigner.ValidateSigningInput(input,role,B(16,9),key));
            Assert.Throws<CryptographicException>(()=>MailboxRoleSigner.ValidateSigningInput(input,role,B(16,1),B(32,9)));
            Assert.Throws<CryptographicException>(()=>MailboxRoleSigner.ValidateSigningInput(input,
                role==MailboxCapabilityDomain.Deposit?MailboxCapabilityDomain.Retrieve:MailboxCapabilityDomain.Deposit,B(16,1),key));
        }
        Assert.Equal(UnixSocketEd25519ExternalSigner.MaximumSigningBytes,maximum.Length);
    }

    [Theory]
    [InlineData(0)] [InlineData(1)] [InlineData(2)] [InlineData(3)] [InlineData(4)]
    public void MalformedPurposeOrCanonicalBytesRejectBeforeSigning(int fault)
    {
        var key=B(32,7); var input=fault<2?MailboxAuthenticatedCapabilityCodec.GetGrantSigningBytes(Grant(MailboxCapabilityDomain.Deposit,key)):
            Revocation(MailboxCapabilityDomain.Deposit,key);
        switch(fault) { case 0:input[0]^=1;break;case 1:input[16+7]=1;break;case 2:input[0]^=1;break;case 3:input[32]^=1;break;case 4:input[^1]=1;break; }
        var error=Record.Exception(()=>MailboxRoleSigner.ValidateSigningInput(input,MailboxCapabilityDomain.Deposit,B(16,1),key));
        Assert.NotNull(error);
        Assert.True(error is CryptographicException or MailboxAuthenticatedCapabilityException or Deep.Protocol.ApplicationCore.ApplicationCoreFormatException);
    }

    [LinuxSignerFact]
    [SupportedOSPlatform("linux")]
    public async Task ActualProtectedSocketSignsBothPurposesAndRetainsSeedAcrossRestart()
    {
        var root=Path.Combine(Path.GetTempPath(),"deep-role-signer-"+Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root); File.SetUnixFileMode(root,UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.UserExecute);
        var seedPath=Path.Combine(root,"role.seed");var socket=Path.Combine(root,"role.sock");var seed=B(32,0x41);
        await File.WriteAllBytesAsync(seedPath,seed);File.SetUnixFileMode(seedPath,UnixFileMode.UserRead|UnixFileMode.UserWrite);
        var pair=PublicKeyAuth.GenerateKeyPair(seed);
        try {
            for(var iteration=0;iteration<2;iteration++) {
                using var stopping=new CancellationTokenSource();
                var service=MailboxRoleSigner.RunAsync(new(){Role="deposit",NetworkIdHex=Convert.ToHexString(B(16,1)),SeedPath=seedPath,SocketPath=socket,AllowedPeerUserId=MailboxRoleSigner.GetEffectiveUserId()},stopping.Token);
                var signer=new UnixSocketEd25519ExternalSigner(socket,TimeSpan.FromSeconds(5));
                var until=DateTime.UtcNow.AddSeconds(5);while(!File.Exists(socket)&&!service.IsCompleted&&DateTime.UtcNow<until) await Task.Delay(10);
                try {
                    Assert.False(service.IsCompleted);
                    foreach(var input in new[]{MailboxAuthenticatedCapabilityCodec.GetGrantSigningBytes(Grant(MailboxCapabilityDomain.Deposit,pair.PublicKey)),Revocation(MailboxCapabilityDomain.Deposit,pair.PublicKey,4096)}) {
                        var signature=await signer.SignAsync(input,default);Assert.True(PublicKeyAuth.VerifyDetached(signature,input,pair.PublicKey));
                    }
                    await Assert.ThrowsAsync<IOException>(()=>signer.SignAsync(MailboxAuthenticatedCapabilityCodec.GetGrantSigningBytes(Grant(MailboxCapabilityDomain.Retrieve,pair.PublicKey)),default).AsTask());
                } finally {stopping.Cancel();await service;}
                Assert.False(File.Exists(socket));Assert.Equal(seed,await File.ReadAllBytesAsync(seedPath));
            }
        } finally { CryptographicOperations.ZeroMemory(pair.PrivateKey);Directory.Delete(root,true); }
    }
    private sealed class LinuxSignerFactAttribute:FactAttribute {public LinuxSignerFactAttribute(){if(!OperatingSystem.IsLinux())Skip="Requires real Linux protected signer custody/socket.";}}
    private sealed class LinuxSignerTheoryAttribute:TheoryAttribute {public LinuxSignerTheoryAttribute(){if(!OperatingSystem.IsLinux())Skip="Requires real Linux custody metadata.";}}

    [LinuxSignerTheory]
    [SupportedOSPlatform("linux")]
    [InlineData(0)] [InlineData(1)] [InlineData(2)] [InlineData(3)] [InlineData(4)]
    public async Task InvalidCustodyNeverDeletesOrReplacesTheTarget(int damage)
    {
        var root=Path.Combine(Path.GetTempPath(),"deep-role-negative-"+Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);File.SetUnixFileMode(root,UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.UserExecute);
        var seedPath=Path.Combine(root,"role.seed");var socket=Path.Combine(root,"role.sock");var seed=B(32,0x41);
        await File.WriteAllBytesAsync(seedPath,seed);File.SetUnixFileMode(seedPath,UnixFileMode.UserRead|UnixFileMode.UserWrite);
        try {
            switch(damage) {
                case 0:File.SetUnixFileMode(seedPath,UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.OtherRead);break;
                case 1:await File.WriteAllBytesAsync(seedPath,B(64,0x41));break;
                case 2:await File.WriteAllBytesAsync(socket,B(32,9));File.SetUnixFileMode(socket,UnixFileMode.UserRead|UnixFileMode.UserWrite);break;
                case 3:File.Move(seedPath,Path.Combine(root,"original.seed"));File.CreateSymbolicLink(seedPath,Path.Combine(root,"original.seed"));break;
                case 4:File.SetUnixFileMode(root,UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.UserExecute|UnixFileMode.OtherWrite);break;
            }
            var operation=()=>MailboxRoleSigner.RunAsync(new(){Role="deposit",NetworkIdHex=Convert.ToHexString(B(16,1)),SeedPath=seedPath,SocketPath=socket,AllowedPeerUserId=MailboxRoleSigner.GetEffectiveUserId()},default);
            if(damage==1) await Assert.ThrowsAsync<InvalidDataException>(operation);
            else await Assert.ThrowsAsync<UnauthorizedAccessException>(operation);
            if(damage==2) Assert.Equal(B(32,9),await File.ReadAllBytesAsync(socket));
            Assert.Equal(damage==1?B(64,0x41):seed,await File.ReadAllBytesAsync(seedPath));
        } finally {File.SetUnixFileMode(root,UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.UserExecute);Directory.Delete(root,true);}
    }

    [LinuxSignerFact]
    [SupportedOSPlatform("linux")]
    public async Task ActiveOwnerIsFencedAndWrongPeerUidNeverReceivesASignature()
    {
        var root=Path.Combine(Path.GetTempPath(),"deep-role-fence-"+Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);File.SetUnixFileMode(root,UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.UserExecute);
        var seedPath=Path.Combine(root,"role.seed");var socket=Path.Combine(root,"role.sock");var seed=B(32,0x41);
        await File.WriteAllBytesAsync(seedPath,seed);File.SetUnixFileMode(seedPath,UnixFileMode.UserRead|UnixFileMode.UserWrite);
        using var lifetime=new CancellationTokenSource();var uid=MailboxRoleSigner.GetEffectiveUserId();
        var options=new MailboxRoleSigner.Options(){Role="deposit",NetworkIdHex=Convert.ToHexString(B(16,1)),SeedPath=seedPath,SocketPath=socket,AllowedPeerUserId=checked(uid+1)};
        var server=MailboxRoleSigner.RunAsync(options,lifetime.Token);
        try {
            var until=DateTime.UtcNow.AddSeconds(5);while(!File.Exists(socket)&&!server.IsCompleted&&DateTime.UtcNow<until)await Task.Delay(10);
            Assert.False(server.IsCompleted);
            await Assert.ThrowsAsync<IOException>(()=>MailboxRoleSigner.RunAsync(options,default));
            var signer=new UnixSocketEd25519ExternalSigner(socket,TimeSpan.FromSeconds(5));
            var pair=PublicKeyAuth.GenerateKeyPair(seed);
            try {
                var error=await Record.ExceptionAsync(()=>signer.SignAsync(MailboxAuthenticatedCapabilityCodec.GetGrantSigningBytes(Grant(MailboxCapabilityDomain.Deposit,pair.PublicKey)),default).AsTask());
                Assert.True(error is IOException or System.Net.Sockets.SocketException);
            } finally {CryptographicOperations.ZeroMemory(pair.PrivateKey);}
            Assert.False(server.IsCompleted);Assert.Equal(seed,await File.ReadAllBytesAsync(seedPath));
        } finally {lifetime.Cancel();await server;Directory.Delete(root,true);}
    }
}
#endif
