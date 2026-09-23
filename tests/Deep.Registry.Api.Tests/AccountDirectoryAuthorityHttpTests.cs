#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Net;
using Deep.Registry.Api.DirectoryPublication;
using Deep.Protocol.AccountDirectoryV1;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Deep.Registry.Api.Tests;

public sealed class AccountDirectoryAuthorityHttpTests
{
    [Fact]
    public void LegacyAuthorityRejectsReaderV2AtStartup()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["AccountDirectoryAuthority:Enabled"] = "true",
                ["AccountDirectoryAuthority:NetworkIdHex"] =
                    Convert.ToHexString(Bytes(0x11, 16)),
                ["AccountDirectoryAuthority:StatePath"] = "legacy-state.bin",
                ["AccountDirectoryAuthority:IntegrityKeyPath"] = "legacy-key.bin",
                ["AccountDirectoryAuthority:SupportedReader"] = "2",
                ["ContactResolveProductionAuthority:NetworkIdHex"] =
                    Convert.ToHexString(Bytes(0x11, 16))
            })
            .Build();

        Assert.Throws<InvalidOperationException>(() =>
            new ServiceCollection().AddAccountDirectoryAuthority(configuration));
    }

    [Fact]
    public async Task ExactAdmissionEnvelopeReturnsOpaqueSignedHeadReceipt()
    {
        var root = TempPath();
        Directory.CreateDirectory(root);
        var keyPath = Path.Combine(root, "authority.key");
        await File.WriteAllBytesAsync(keyPath, Bytes(0x71, 32));
        var authority = new FixedAuthority();
        try
        {
            await using var factory = Factory(root, keyPath, authority);
            using var client = factory.CreateClient();
            var encoded = Request();
            using var content = new ByteArrayContent(encoded);
            content.Headers.ContentType = new(
                AccountDirectoryGenesisAdmissionWireCodec.RequestMediaType);

            using var response = await client.PostAsync(
                AccountDirectoryAuthorityHostingExtensions.EndpointPath,
                content);

            var responseBytes = await response.Content.ReadAsByteArrayAsync();
            Assert.True(response.StatusCode == HttpStatusCode.OK,
                $"Unexpected {response.StatusCode}: {System.Text.Encoding.UTF8.GetString(responseBytes)}");
            Assert.Equal(
                AccountDirectoryGenesisAdmissionWireCodec.ResponseMediaType,
                response.Content.Headers.ContentType?.MediaType);
            var receipt = AccountDirectoryGenesisAdmissionWireCodec.DecodeReceipt(
                responseBytes);
            Assert.Equal(Bytes(0x31, 32), receipt.OperationId.ToArray());
            Assert.Equal(Bytes(0x41, 32), receipt.DirectoryLeafKey.ToArray());
            Assert.Equal(1, authority.Calls);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task WrongMediaTypeAndMalformedEnvelopeNeverReachAuthority()
    {
        var root = TempPath();
        Directory.CreateDirectory(root);
        var keyPath = Path.Combine(root, "authority.key");
        await File.WriteAllBytesAsync(keyPath, Bytes(0x71, 32));
        var authority = new FixedAuthority();
        try
        {
            await using var factory = Factory(root, keyPath, authority);
            using var client = factory.CreateClient();
            using var wrong = await client.PostAsync(
                AccountDirectoryAuthorityHostingExtensions.EndpointPath,
                new ByteArrayContent(Request()));
            Assert.Equal(HttpStatusCode.UnsupportedMediaType, wrong.StatusCode);

            using var malformedContent = new ByteArrayContent(Bytes(0x22, 32));
            malformedContent.Headers.ContentType = new(
                AccountDirectoryGenesisAdmissionWireCodec.RequestMediaType);
            using var malformed = await client.PostAsync(
                AccountDirectoryAuthorityHostingExtensions.EndpointPath,
                malformedContent);
            var malformedBody = await malformed.Content.ReadAsStringAsync();
            Assert.True(malformed.StatusCode == HttpStatusCode.BadRequest,
                $"Unexpected {malformed.StatusCode}: {malformedBody}");
            Assert.Equal(0, authority.Calls);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static WebApplicationFactory<Program> Factory(
        string root,
        string keyPath,
        IAccountDirectoryGenesisAuthority authority) =>
        new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            var network = Convert.ToHexString(Bytes(0x11, 16));
            builder.UseSetting("AccountDirectoryAuthority:Enabled", "true");
            builder.UseSetting("AccountDirectoryAuthority:NetworkIdHex", network);
            builder.UseSetting("AccountDirectoryAuthority:StatePath",
                Path.Combine(root, "state.bin"));
            builder.UseSetting("AccountDirectoryAuthority:IntegrityKeyPath", keyPath);
            builder.UseSetting("AccountDirectoryAuthority:DeploymentProfileId", "1");
            builder.UseSetting("AccountDirectoryAuthority:SupportedReader", "1");
            builder.UseSetting("AccountDirectoryAuthority:HeadValiditySeconds", "3600");
            builder.UseSetting("AccountDirectoryAuthority:RenewalLeadSeconds", "300");
            builder.UseSetting("ContactResolveProductionAuthority:NetworkIdHex", network);
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<IAccountDirectoryGenesisAuthority>();
                services.AddSingleton<IAccountDirectoryGenesisAuthority>(authority);
            });
        });

    private static byte[] Request()
    {
        var admission = new AccountDirectoryGenesisAdmissionRequest(
            Bytes(0x01, 1),
            Bytes(0x02, 1),
            [Bytes(0x03, 1)],
            Bytes(0x04, 1),
            Bytes(0x05, 1),
            Bytes(0x06, 1),
            Bytes(0x07, 1),
            []);
        return AccountDirectoryGenesisAdmissionWireCodec.EncodeRequest(
            new AccountDirectoryGenesisAdmissionWireRequest(
                Bytes(0x31, 32), admission));
    }

    private static byte[] Head()
    {
        var head = new AccountDirectoryAdh1(
            Bytes(0x11, 16),
            1,
            Bytes(0x12, 32),
            0,
            AccountDirectoryRfc6962.ComputeEmptyTreeHash(),
            AccountDirectorySparseMap.EmptyMapRoot.Span,
            AccountDirectoryCrypto.CreateReference(
                "XNA1"u8, 1, Bytes(0x13, 32)),
            Bytes(0x14, 32),
            100,
            200,
            1,
            [new AccountDirectoryAdh1WitnessEntry(
                Bytes(0x15, 32), Bytes(0x16, 64))]);
        return AccountDirectoryAdh1Codec.Encode(head);
    }

    private static string TempPath() => Path.Combine(
        Path.GetTempPath(),
        "deep-account-directory-authority-http",
        Guid.NewGuid().ToString("N"));

    private static byte[] Bytes(byte value, int length) =>
        Enumerable.Repeat(value, length).ToArray();

    private sealed class FixedAuthority : IAccountDirectoryGenesisAuthority
    {
        internal int Calls { get; private set; }

        public ValueTask<AccountDirectoryGenesisAdmissionReceipt> AdmitAsync(
            AccountDirectoryGenesisAdmissionWireRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls++;
            return ValueTask.FromResult(
                new AccountDirectoryGenesisAdmissionReceipt(
                    request.OperationId.Span,
                    Bytes(0x41, 32),
                    Head()));
        }
    }
}
#endif
