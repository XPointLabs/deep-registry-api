using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Xml.Linq;

namespace Deep.Registry.Api.Tests;

public sealed class P04PackagePinTests
{
    private static readonly IReadOnlyDictionary<string, string> ExpectedHashes =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["Deep.Protocol.0.3.0-p04.b887fa0.nupkg"] =
                "8ef4e70ad0b6c1cc0087f25c0313d6ab6a5387d16246679e4c10a3c00898a442",
            ["Deep.Protocol.Abstractions.0.3.0-p04.b887fa0.nupkg"] =
                "fc1212a6765f5778188fcb3866ef923023c2253c3ead299a542271f4cc4f844f",
            ["Deep.Protocol.Protobuf.0.3.0-p04.b887fa0.nupkg"] =
                "755a027c58be670151456cc0bca4764731f7c493932d9eedd00c02e704baf818"
        };

    private static readonly IReadOnlyDictionary<string, string> ExpectedProductionMailboxHashes =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["Deep.Protocol.0.4.0-production.eacaeb8.nupkg"] =
                "7e5f1139ab3b4669040bf5349cb56669de04cc281f2197b3184dc27145848e35",
            ["Deep.Protocol.Abstractions.0.4.0-production.eacaeb8.nupkg"] =
                "e0446fae07a597088b7567bfe2a8a9c901503890e86eba568496bbaf06a030d4",
            ["Deep.Protocol.MembershipRoutes.0.4.0-production.eacaeb8.nupkg"] =
                "be5345b5fca1f951d22f912f91daffe7061a5ff4cf38d19dfc3fdb230d58ccdf",
            ["Deep.Protocol.ProfileCarrier.0.4.0-production.eacaeb8.nupkg"] =
                "4f7095010d242be3142c0f93c94d72d544e7deef5aa5b790f999b876726a3460",
            ["Deep.Protocol.Protobuf.0.4.0-production.eacaeb8.nupkg"] =
                "ab1109b269fe8422d7472bb4e724aca96097ee3f96b1815ea11b409d0c87586d"
        };

    [Fact]
    public void VendoredP04Inventory_IsExactAndPinned()
    {
        var vendor = Path.Combine(RepositoryRoot(), "vendor", "p04");
        var packages = Directory.GetFiles(vendor, "*.nupkg")
            .Select(Path.GetFileName)
            .Order(StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(ExpectedHashes.Keys.Order(StringComparer.Ordinal), packages);
        foreach (var pair in ExpectedHashes)
        {
            Assert.Equal(pair.Value, Sha256(Path.Combine(vendor, pair.Key)));
        }

        Assert.Equal(
            "fd3ef27bf0b9272570d6c6e680a3c99e581f6220799d13ee3afbd86ea0e99298",
            CanonicalTextSha256(Path.Combine(vendor, "package-manifest.json")));
        Assert.Equal(
            "758707e4705c0499f546ce1e1e5201df253ef70822225c5fd3086c43d8d9bf45",
            CanonicalTextSha256(Path.Combine(vendor, "membership-contract-v1.json")));
    }

    [Fact]
    public void VendoredP04Packages_EmbedAcceptedVersionAndSourceCommit()
    {
        var vendor = Path.Combine(RepositoryRoot(), "vendor", "p04");
        foreach (var package in ExpectedHashes.Keys)
        {
            using var archive = ZipFile.OpenRead(Path.Combine(vendor, package));
            var nuspecEntry = Assert.Single(
                archive.Entries,
                entry => entry.FullName.EndsWith(".nuspec", StringComparison.OrdinalIgnoreCase));
            using var stream = nuspecEntry.Open();
            var document = XDocument.Load(stream);
            XNamespace ns = document.Root!.Name.Namespace;
            var metadata = document.Root.Element(ns + "metadata")!;

            Assert.Equal("0.3.0-p04.b887fa0", metadata.Element(ns + "version")!.Value);
            Assert.Equal(
                "b887fa088f486390be182cac4cbcb59b60ce8931",
                metadata.Element(ns + "repository")!.Attribute("commit")!.Value);
        }
    }

    [Fact]
    public void ProductionMailboxClosure_IsExactAndPinnedToSourceCommit()
    {
        var vendor = Path.Combine(RepositoryRoot(), "vendor", "pma");
        var packages = Directory.GetFiles(vendor, "*.nupkg")
            .Select(Path.GetFileName)
            .Order(StringComparer.Ordinal)
            .ToArray();
        Assert.Equal(ExpectedProductionMailboxHashes.Keys.Order(StringComparer.Ordinal), packages);
        foreach (var pair in ExpectedProductionMailboxHashes)
        {
            Assert.Equal(pair.Value, Sha256(Path.Combine(vendor, pair.Key)));
            using var archive = ZipFile.OpenRead(Path.Combine(vendor, pair.Key));
            var nuspecEntry = Assert.Single(archive.Entries,
                entry => entry.FullName.EndsWith(".nuspec", StringComparison.OrdinalIgnoreCase));
            using var stream = nuspecEntry.Open();
            var document = XDocument.Load(stream);
            XNamespace ns = document.Root!.Name.Namespace;
            var metadata = document.Root.Element(ns + "metadata")!;
            Assert.Equal("0.4.0-production.eacaeb8", metadata.Element(ns + "version")!.Value);
            Assert.Equal("eacaeb831905d6508fa118ca80c78b4a22a987e6",
                metadata.Element(ns + "repository")!.Attribute("commit")!.Value);
            foreach (var dependency in metadata.Descendants(ns + "dependency")
                         .Where(value => value.Attribute("id")?.Value.StartsWith(
                             "Deep.Protocol", StringComparison.Ordinal) == true))
            {
                var version = dependency.Attribute("version")!.Value;
                Assert.Contains(version, new[]
                {
                    "0.4.0-production.eacaeb8",
                    "[0.4.0-production.eacaeb8]"
                });
                if (pair.Key.StartsWith("Deep.Protocol.ProfileCarrier.", StringComparison.Ordinal))
                    Assert.Equal("[0.4.0-production.eacaeb8]", version);
            }
        }
        Assert.Equal("74bc1bb5a8363ce41505f52abd7365f953f101d21296a5b845c636766c8284f2",
            CanonicalTextSha256(Path.Combine(vendor, "package-manifest.json")));
    }

    [Fact]
    public void NuGetConfigurationAndLocks_PinCurrentProtocolToRepositoryVendor()
    {
        var root = RepositoryRoot();
        var config = XDocument.Load(Path.Combine(root, "NuGet.Config"));
        var localSource = config.Descendants("add")
            .Single(element => (string?)element.Attribute("key") == "pma-vendor");
        Assert.Equal("vendor/pma", (string?)localSource.Attribute("value"));
        var localPatterns = config.Descendants("packageSource")
            .Single(element => (string?)element.Attribute("key") == "pma-vendor")
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
            Assert.Equal("0.4.0-production.eacaeb8", protocol["resolved"]!.GetValue<string>());
            if (protocol["type"]!.GetValue<string>() == "Direct")
            {
                Assert.Equal(
                    "[0.4.0-production.eacaeb8, 0.4.0-production.eacaeb8]",
                    protocol["requested"]!.GetValue<string>());
            }
            Assert.Equal(
                "0.4.0-production.eacaeb8",
                dependencies["Deep.Protocol.Abstractions"]!["resolved"]!.GetValue<string>());
            Assert.Equal(
                "0.4.0-production.eacaeb8",
                dependencies["Deep.Protocol.Protobuf"]!["resolved"]!.GetValue<string>());
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
