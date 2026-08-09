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

    private static readonly IReadOnlyDictionary<string, ProductionPackage> ProductionPackages =
        new Dictionary<string, ProductionPackage>(StringComparer.Ordinal)
        {
            ["Deep.Protocol.0.4.0-production.2eb8b1e.nupkg"] = new(
                "Deep.Protocol", 218_772,
                "247a90915853b274f95f2e2aa69b71689f666d95a29150f45152326988104a8b",
                new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["Deep.Protocol.Abstractions"] = "[0.4.0-production.2eb8b1e]",
                    ["Deep.Protocol.Protobuf"] = "[0.4.0-production.2eb8b1e]"
                }),
            ["Deep.Protocol.Abstractions.0.4.0-production.2eb8b1e.nupkg"] = new(
                "Deep.Protocol.Abstractions", 24_930,
                "66cd9b24bd441daaf9127700d52e577749cb67ed4ba9ab87ce416f1de65dac79",
                new Dictionary<string, string>(StringComparer.Ordinal)),
            ["Deep.Protocol.MembershipRoutes.0.4.0-production.2eb8b1e.nupkg"] = new(
                "Deep.Protocol.MembershipRoutes", 175_350,
                "cf5651b70f66a0e18b43e40274021fa948414aa300c4ce8ba63889f5638dc5c3",
                new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["Deep.Protocol"] = "[0.4.0-production.2eb8b1e]"
                }),
            ["Deep.Protocol.Protobuf.0.4.0-production.2eb8b1e.nupkg"] = new(
                "Deep.Protocol.Protobuf", 50_183,
                "8f8fdd8e0fd7e09e55a7eec95ef190e50d9c7235a769b5407f85adee36d6cfb7",
                new Dictionary<string, string>(StringComparer.Ordinal))
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
        var inventory = Directory.GetFiles(vendor)
            .Select(Path.GetFileName)
            .Order(StringComparer.Ordinal)
            .ToArray();
        Assert.Equal(
            ProductionPackages.Keys.Append("package-manifest.json")
                .Order(StringComparer.Ordinal),
            inventory);
        var observedIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var pair in ProductionPackages)
        {
            var path = Path.Combine(vendor, pair.Key);
            Assert.Equal(pair.Value.Bytes, new FileInfo(path).Length);
            Assert.Equal(pair.Value.Sha256, Sha256(path));
            using var archive = ZipFile.OpenRead(Path.Combine(vendor, pair.Key));
            var nuspecEntry = Assert.Single(archive.Entries,
                entry => string.Equals(entry.FullName, pair.Value.Id + ".nuspec",
                    StringComparison.Ordinal));
            using var stream = nuspecEntry.Open();
            var document = XDocument.Load(stream);
            XNamespace ns = document.Root!.Name.Namespace;
            var metadata = document.Root.Element(ns + "metadata")!;
            Assert.Equal(pair.Value.Id, metadata.Element(ns + "id")!.Value);
            Assert.True(observedIds.Add(pair.Value.Id));
            Assert.Equal("0.4.0-production.2eb8b1e",
                metadata.Element(ns + "version")!.Value);
            var repository = metadata.Element(ns + "repository")!;
            Assert.Equal("git", repository.Attribute("type")!.Value);
            Assert.Equal("https://github.com/XPointLabs/deep-protocol.git",
                repository.Attribute("url")!.Value);
            Assert.Equal("2eb8b1eb4605216b239f63d1ad8e587a28918134",
                repository.Attribute("commit")!.Value);
            var internalDependencies = metadata.Descendants(ns + "dependency")
                .Where(value => value.Attribute("id")?.Value.StartsWith(
                    "Deep.Protocol", StringComparison.Ordinal) == true)
                .ToDictionary(value => value.Attribute("id")!.Value,
                    value => value.Attribute("version")!.Value,
                    StringComparer.Ordinal);
            Assert.Equal(pair.Value.InternalDependencies.OrderBy(static value => value.Key),
                internalDependencies.OrderBy(static value => value.Key));
        }
        var manifestPath = Path.Combine(vendor, "package-manifest.json");
        var manifest = JsonNode.Parse(File.ReadAllText(manifestPath))!;
        Assert.Equal("deep-local-package-manifest.v1",
            manifest["schema"]!.GetValue<string>());
        Assert.Equal("0.4.0-production.2eb8b1e",
            manifest["packageVersion"]!.GetValue<string>());
        Assert.Equal("2eb8b1eb4605216b239f63d1ad8e587a28918134",
            manifest["sourceCommit"]!.GetValue<string>());
        Assert.True(manifest["reproducibleNormalizedBuild"]!.GetValue<bool>());
        Assert.Equal("local-only-not-published",
            manifest["publication"]!.GetValue<string>());
        var entries = manifest["packages"]!.AsArray()
            .ToDictionary(entry => entry!["file"]!.GetValue<string>(),
                entry => (entry!["bytes"]!.GetValue<long>(),
                    entry["sha256"]!.GetValue<string>()),
                StringComparer.Ordinal);
        Assert.Equal(ProductionPackages.Keys.Order(StringComparer.Ordinal),
            entries.Keys.Order(StringComparer.Ordinal));
        foreach (var pair in ProductionPackages)
        {
            Assert.Equal(pair.Value.Bytes, entries[pair.Key].Item1);
            Assert.Equal(pair.Value.Sha256, entries[pair.Key].Item2);
        }
    }

    private sealed record ProductionPackage(
        string Id,
        long Bytes,
        string Sha256,
        IReadOnlyDictionary<string, string> InternalDependencies);

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
            Assert.Equal("0.4.0-production.2eb8b1e", protocol["resolved"]!.GetValue<string>());
            if (protocol["type"]!.GetValue<string>() == "Direct")
            {
                Assert.Equal(
                    "[0.4.0-production.2eb8b1e, 0.4.0-production.2eb8b1e]",
                    protocol["requested"]!.GetValue<string>());
            }
            Assert.Equal(
                "0.4.0-production.2eb8b1e",
                dependencies["Deep.Protocol.Abstractions"]!["resolved"]!.GetValue<string>());
            Assert.Equal(
                "0.4.0-production.2eb8b1e",
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
