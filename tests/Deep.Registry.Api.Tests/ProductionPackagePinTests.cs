using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Xml.Linq;

namespace Deep.Registry.Api.Tests;

public sealed class ProductionPackagePinTests
{
    private static readonly IReadOnlyDictionary<string, (long Bytes, string Sha256)>
        PrivacyRoutingPackages =
            new Dictionary<string, (long Bytes, string Sha256)>(StringComparer.Ordinal)
            {
                ["Deep.Protocol.0.5.0-production.e75bfed.nupkg"] = (
                    481_534,
                    "69578c00c503383b149c4e9bccb3f14f87d3608c9781fe684710233059060098"),
                ["Deep.Protocol.MembershipRoutes.0.5.0-production.e75bfed.nupkg"] = (
                    186_954,
                    "5dacdef966835452ffa2c0a404dac72524b508ebeffa3f44b79d5d290c2de75e")
            };

    [Fact]
    public void NuGetConfigurationAndLocks_PinCurrentProtocolToRepositoryVendor()
    {
        var root = RepositoryRoot();
        var config = XDocument.Load(Path.Combine(root, "NuGet.Config"));
        var localSource = config.Descendants("add")
            .Single(element => (string?)element.Attribute("key") == "privacy-routing-vendor");
        Assert.Equal(
            "vendor/privacy-routing-e75bfed",
            (string?)localSource.Attribute("value"));
        var localPatterns = config.Descendants("packageSource")
            .Single(element =>
                (string?)element.Attribute("key") == "privacy-routing-vendor")
            .Elements("package")
            .Select(element => (string?)element.Attribute("pattern"))
            .ToArray();
        Assert.Equal(new[] { "Deep.Protocol", "Deep.Protocol.*" }, localPatterns);
        var remotePatterns = config.Descendants("packageSource")
            .Single(element => (string?)element.Attribute("key") == "nuget.org")
            .Elements("package")
            .Select(element => (string?)element.Attribute("pattern"))
            .ToArray();
        Assert.DoesNotContain("*", remotePatterns);
        Assert.DoesNotContain(
            remotePatterns,
            pattern => pattern?.StartsWith("Deep.", StringComparison.Ordinal) == true);

        foreach (var lockPath in new[]
                 {
                     Path.Combine(root, "src", "Deep.Registry.Api", "packages.lock.json"),
                     Path.Combine(root, "tests", "Deep.Registry.Api.Tests", "packages.lock.json")
                 })
        {
            var dependencies = JsonNode.Parse(File.ReadAllText(lockPath))!
                ["dependencies"]!["net10.0"]!;
            var protocol = dependencies["Deep.Protocol"]!;
            Assert.Equal("0.5.0-production.e75bfed", protocol["resolved"]!.GetValue<string>());
            if (protocol["type"]!.GetValue<string>() == "Direct")
            {
                Assert.Equal(
                    "[0.5.0-production.e75bfed, 0.5.0-production.e75bfed]",
                    protocol["requested"]!.GetValue<string>());
            }
            Assert.Null(dependencies["Deep.Protocol.Abstractions"]);
            Assert.Null(dependencies["Deep.Protocol.Protobuf"]);
        }
    }

    [Fact]
    public void PrivacyRoutingProtocolClosure_IsExactAndPinnedToSourceCommit()
    {
        var vendor = Path.Combine(
            RepositoryRoot(),
            "vendor",
            "privacy-routing-e75bfed");
        var inventory = Directory.GetFiles(vendor, "*.nupkg")
            .Select(Path.GetFileName)
            .Order(StringComparer.Ordinal)
            .ToArray();
        Assert.Equal(PrivacyRoutingPackages.Keys.Order(StringComparer.Ordinal), inventory);

        foreach (var pair in PrivacyRoutingPackages)
        {
            var path = Path.Combine(vendor, pair.Key);
            Assert.Equal(pair.Value.Bytes, new FileInfo(path).Length);
            Assert.Equal(pair.Value.Sha256, Sha256(path));
            using var archive = ZipFile.OpenRead(path);
            var nuspecEntry = Assert.Single(
                archive.Entries,
                entry => entry.FullName.EndsWith(".nuspec", StringComparison.Ordinal));
            using var stream = nuspecEntry.Open();
            var document = XDocument.Load(stream);
            XNamespace ns = document.Root!.Name.Namespace;
            var metadata = document.Root.Element(ns + "metadata")!;
            Assert.Equal(
                "0.5.0-production.e75bfed",
                metadata.Element(ns + "version")!.Value);
            Assert.Equal(
                "e75bfed411cfe13134a55a09a3c754b174f13322",
                metadata.Element(ns + "repository")!.Attribute("commit")!.Value);
        }
    }

    private static string Sha256(string path) =>
        Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).ToLowerInvariant();

    private static string CanonicalTextSha256(string path)
    {
        var canonicalBytes = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false)
            .GetBytes(File.ReadAllText(path).Replace("\r\n", "\n", StringComparison.Ordinal));
        return Convert.ToHexString(SHA256.HashData(canonicalBytes)).ToLowerInvariant();
    }

    private static string RepositoryRoot()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null && !File.Exists(Path.Combine(current.FullName, "Deep.Registry.Api.slnx")))
        {
            current = current.Parent;
        }

        return current?.FullName
               ?? throw new InvalidOperationException("Repository root was not found.");
    }
}
