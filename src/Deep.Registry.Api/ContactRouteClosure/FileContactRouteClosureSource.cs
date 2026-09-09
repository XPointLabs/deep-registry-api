#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Deep.Protocol.ContactV1;

namespace Deep.Registry.Api.ContactRouteClosure;

internal sealed record FileContactRouteClosureManifest(
    string Format,
    string NetworkIdHex,
    string LocatorHashHex,
    ulong PublicationGeneration,
    IReadOnlyList<FileContactRouteClosureManifestEntry> Artifacts);

internal sealed record FileContactRouteClosureManifestEntry(
    string Role,
    string FileName,
    int Length,
    string Sha256Hex);

internal static class FileContactRouteClosureManifestCodec
{
    internal const string CurrentFormat = "deep-contact-route-closure-readonly-v1";
    internal const int MaximumManifestBytes = 4 * 1024;

    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        WriteIndented = false,
    };

    internal static byte[] EncodeCanonical(FileContactRouteClosureManifest value) =>
        JsonSerializer.SerializeToUtf8Bytes(value, Options);

    internal static FileContactRouteClosureManifest DecodeCanonical(ReadOnlySpan<byte> value)
    {
        if (value.IsEmpty || value.Length > MaximumManifestBytes)
            throw new InvalidDataException("The contact route closure manifest length is invalid.");
        FileContactRouteClosureManifest manifest;
        try
        {
            manifest = JsonSerializer.Deserialize<FileContactRouteClosureManifest>(value, Options)
                ?? throw new InvalidDataException("The contact route closure manifest is empty.");
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("The contact route closure manifest is invalid.", exception);
        }
        if (!value.SequenceEqual(EncodeCanonical(manifest)))
            throw new InvalidDataException("The contact route closure manifest is not canonical JSON.");
        return manifest;
    }
}

/// <summary>
/// Reads immutable publisher-prepared artifacts selected by an atomically replaced `current`
/// pointer. This transport source performs Protocol canonical and graph checks but deliberately
/// does not produce a verified route capability.
/// </summary>
internal sealed class FileContactRouteClosureSource : IContactRouteClosureSource, IDisposable
{
    private const int PointerBytes = 20;
    private const int StatePayloadBytes = 2 + 16 + 32 + 8 + 32 + 1;
    private static readonly string[] Roles =
        ["xir1", "xrr1", "xra1", "xrc1", "xss1", "pmt2", "pms2"];
    private static readonly string[] ResponseRoles =
        ["xrr1", "xra1", "xrc1", "xss1", "pmt2", "pms2"];
    private static readonly IReadOnlyDictionary<string, (string Magic, int Minimum, int Maximum)>
        Definitions = new Dictionary<string, (string, int, int)>(StringComparer.Ordinal)
        {
            ["xir1"] = ("XIR1", 611, 611),
            ["xrr1"] = ("XRR1", 643, 643),
            ["xra1"] = ("XRA1", 550, 550),
            ["xrc1"] = ("XRC1", 940, 4_012),
            ["xss1"] = ("XSS1", 643, 3_523),
            ["pmt2"] = ("PMT2", 842, 11_066),
            ["pms2"] = ("PMS2", 500, 3_476),
        };

    private readonly string rootPath;
    private readonly string publicationsPath;
    private readonly string networkPublicationsPath;
    private readonly string stateRoot;
    private readonly string networkStateRoot;
    private readonly byte[] networkId;
    private readonly byte[] integrityKey;
    private readonly SemaphoreSlim gate = new(1, 1);

    internal FileContactRouteClosureSource(
        string readOnlyRoot,
        string protectedStateRoot,
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> integrityKey)
    {
        if (string.IsNullOrWhiteSpace(readOnlyRoot))
            throw new ArgumentException("A read-only contact route closure root is required.", nameof(readOnlyRoot));
        if (string.IsNullOrWhiteSpace(protectedStateRoot))
            throw new ArgumentException("A protected contact route closure state root is required.", nameof(protectedStateRoot));
        if (networkId.Length != 16 || networkId.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("A non-zero 16-byte network ID is required.", nameof(networkId));
        if (integrityKey.Length != 32 || integrityKey.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("A non-zero 32-byte integrity key is required.", nameof(integrityKey));

        rootPath = Path.TrimEndingDirectorySeparator(Path.GetFullPath(readOnlyRoot));
        RejectReparseAncestors(rootPath);
        publicationsPath = Child(rootPath, "publications");
        var networkHex = LowerHex(networkId);
        networkPublicationsPath = Child(publicationsPath, networkHex);
        stateRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(protectedStateRoot));
        RejectReparseAncestors(stateRoot);
        networkStateRoot = Child(stateRoot, networkHex);
        if (IsWithin(stateRoot, rootPath) || IsWithin(rootPath, stateRoot) ||
            StringComparerForPaths.Equals(stateRoot, rootPath))
            throw new ArgumentException(
                "Protected contact route closure state must be outside the read-only root.",
                nameof(protectedStateRoot));
        this.networkId = networkId.ToArray();
        this.integrityKey = integrityKey.ToArray();
    }

    public async ValueTask<ReadOnlyMemory<byte>> ReadAsync(
        ReadOnlyMemory<byte> requestedNetworkId,
        ReadOnlyMemory<byte> locatorHash,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (requestedNetworkId.Length != 16 || locatorHash.Length != 32 ||
            !Fixed(requestedNetworkId.Span, networkId) ||
            locatorHash.Span.IndexOfAnyExcept((byte)0) < 0)
            throw new ContactRouteClosureNotFoundException();

        EnsureGlobalReadOnlyTree();
        var locatorHex = LowerHex(locatorHash.Span);
        string publicationRoot;
        try
        {
            publicationRoot = ResolvePublicationRoot(locatorHex);
            if (!Directory.Exists(publicationRoot))
                throw new ContactRouteClosureNotFoundException();
        }
        catch (ContactRouteClosureNotFoundException)
        {
            throw;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or
            InvalidDataException)
        {
            throw new ContactRouteClosurePublicationRejectedException(
                "The locator publication path was rejected.", exception);
        }

        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var statePath = EnsureStatePath(locatorHex);
            using var lease = AcquireStateLease(statePath, cancellationToken);
            try
            {
                EnsureDirectory(publicationRoot);
                var pointerPath = Child(publicationRoot, "current");
                if (!File.Exists(pointerPath))
                    throw new ContactRouteClosureNotFoundException();
                var firstPointer = ReadExactFile(pointerPath, PointerBytes, PointerBytes);
                var generation = DecodePointer(firstPointer);
                var generationsPath = Child(publicationRoot, "generations");
                EnsureDirectory(generationsPath);
                var generationPath = Child(generationsPath, Encoding.ASCII.GetString(firstPointer));
                EnsureDirectory(generationPath);

                var first = ReadBundle(generationPath, requestedNetworkId.Span,
                    locatorHash.Span, generation);
                ValidateProtocolClosure(first, requestedNetworkId.Span, locatorHash.Span);
                var closure = EncodeClosure(first);

                var second = ReadBundle(generationPath, requestedNetworkId.Span,
                    locatorHash.Span, generation);
                first.RequireExact(second);
                var secondPointer = ReadExactFile(pointerPath, PointerBytes, PointerBytes);
                if (!Fixed(firstPointer, secondPointer))
                    throw new CryptographicException("The contact route closure publication changed during verification.");

                CheckAndAdvanceState(statePath, locatorHash.Span, generation,
                    SHA256.HashData(first.ManifestBytes));
                return closure;
            }
            catch (ContactRouteClosureNotFoundException)
            {
                throw;
            }
            catch (ContactRouteClosurePublicationRejectedException)
            {
                throw;
            }
            catch (Exception exception) when (exception is InvalidDataException or
                CryptographicException or FormatException or DirectoryNotFoundException or
                FileNotFoundException)
            {
                throw new ContactRouteClosurePublicationRejectedException(
                    "The locator publication was rejected.", exception);
            }
        }
        catch (ContactRouteClosureNotFoundException)
        {
            throw;
        }
        catch (ContactRouteClosurePublicationRejectedException)
        {
            throw;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or
            CryptographicException or InvalidDataException)
        {
            throw new ContactRouteClosureSourceUnavailableException();
        }
        finally
        {
            gate.Release();
        }
    }

    private void EnsureGlobalReadOnlyTree()
    {
        try
        {
            EnsureDirectory(rootPath);
            EnsureDirectory(publicationsPath);
            EnsureDirectory(networkPublicationsPath);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or
            InvalidDataException)
        {
            throw new ContactRouteClosureSourceUnavailableException();
        }
    }

    private string ResolvePublicationRoot(string locatorHex)
    {
        var first = Child(networkPublicationsPath, locatorHex[..2]);
        if (!Directory.Exists(first))
            throw new ContactRouteClosureNotFoundException();
        EnsureDirectory(first);
        var second = Child(first, locatorHex.Substring(2, 2));
        if (!Directory.Exists(second))
            throw new ContactRouteClosureNotFoundException();
        EnsureDirectory(second);
        return Child(second, locatorHex);
    }

    private string EnsureStatePath(string locatorHex)
    {
        CreateStateDirectory(stateRoot);
        CreateStateDirectory(networkStateRoot);
        var first = Child(networkStateRoot, locatorHex[..2]);
        CreateStateDirectory(first);
        var second = Child(first, locatorHex.Substring(2, 2));
        CreateStateDirectory(second);
        return Child(second, $"{locatorHex}.state");
    }

    private static void CreateStateDirectory(string path)
    {
        if (!Directory.Exists(path)) Directory.CreateDirectory(path);
        RejectReparseAncestors(path);
        EnsureDirectory(path);
    }

    private static ulong DecodePointer(ReadOnlySpan<byte> value)
    {
        if (value.Length != PointerBytes ||
            value.IndexOfAnyExceptInRange((byte)'0', (byte)'9') >= 0 ||
            !ulong.TryParse(Encoding.ASCII.GetString(value), out var generation) ||
            !Encoding.ASCII.GetBytes(generation.ToString("D20")).AsSpan().SequenceEqual(value))
            throw new InvalidDataException("The contact route closure current pointer is not canonical.");
        return generation;
    }

    private ArtifactBundle ReadBundle(
        string generationPath,
        ReadOnlySpan<byte> requestedNetwork,
        ReadOnlySpan<byte> locatorHash,
        ulong generation)
    {
        EnsureDirectory(generationPath);
        var manifestPath = Child(generationPath, "manifest.json");
        var manifestBytes = ReadExactFile(
            manifestPath, null, FileContactRouteClosureManifestCodec.MaximumManifestBytes);
        var manifest = FileContactRouteClosureManifestCodec.DecodeCanonical(manifestBytes);
        ValidateManifest(manifest, requestedNetwork, locatorHash, generation);

        var artifacts = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        foreach (var entry in manifest.Artifacts)
        {
            var definition = Definitions[entry.Role];
            var bytes = ReadExactFile(Child(generationPath, entry.FileName), entry.Length,
                definition.Maximum);
            if (!Fixed(SHA256.HashData(bytes), ParseLowerHex(entry.Sha256Hex, 32,
                    "artifact SHA-256")))
                throw new CryptographicException("An exact route artifact differs from its manifest hash.");
            artifacts.Add(entry.Role, bytes);
        }
        return new ArtifactBundle(manifestBytes, manifest, artifacts);
    }

    private void ValidateManifest(
        FileContactRouteClosureManifest manifest,
        ReadOnlySpan<byte> requestedNetwork,
        ReadOnlySpan<byte> locatorHash,
        ulong generation)
    {
        if (!StringComparer.Ordinal.Equals(manifest.Format,
                FileContactRouteClosureManifestCodec.CurrentFormat) ||
            manifest.PublicationGeneration != generation ||
            !Fixed(ParseLowerHex(manifest.NetworkIdHex, 16, "manifest network ID"), requestedNetwork) ||
            !Fixed(ParseLowerHex(manifest.LocatorHashHex, 32, "manifest locator hash"), locatorHash) ||
            manifest.Artifacts is null || manifest.Artifacts.Count != Roles.Length)
            throw new InvalidDataException("The contact route closure manifest header is invalid.");

        var names = new HashSet<string>(StringComparer.Ordinal);
        for (var index = 0; index < Roles.Length; index++)
        {
            var entry = manifest.Artifacts[index];
            var role = Roles[index];
            var definition = Definitions[role];
            if (entry is null || !StringComparer.Ordinal.Equals(entry.Role, role) ||
                !StringComparer.Ordinal.Equals(entry.FileName, $"{role}.bin") ||
                !names.Add(entry.FileName) ||
                entry.Length < definition.Minimum || entry.Length > definition.Maximum)
                throw new InvalidDataException("The contact route closure inventory is not exact and canonical.");
            _ = ParseLowerHex(entry.Sha256Hex, 32, "artifact SHA-256");
        }
    }

    private static void ValidateProtocolClosure(
        ArtifactBundle bundle,
        ReadOnlySpan<byte> network,
        ReadOnlySpan<byte> requestedLocator)
    {
        var records = new Dictionary<string, ContactRecord>(StringComparer.Ordinal);
        foreach (var role in Roles)
        {
            var definition = Definitions[role];
            var record = ContactCodec.Decode(definition.Magic, bundle.Artifact(role));
            if (!Fixed(record.Field(1).Span, network))
                throw new CryptographicException("A route artifact belongs to another network.");
            records.Add(role, record);
        }

        var resolver = new ExactResolver(records.Values);
        foreach (var record in records.Values)
            ContactCodec.VerifyContactOwnedClosure(record, resolver);

        var xir = records["xir1"];
        if (!Fixed(xir.Field(2).Span, requestedLocator))
            throw new CryptographicException(
                "The verified route closure belongs to another locator.");
        var xrr = records["xrr1"];
        var xra = records["xra1"];
        var xrc = records["xrc1"];
        var xss = records["xss1"];
        var pmt = records["pmt2"];
        var pms = records["pms2"];

        RequireReference(xir, 5, pmt);
        RequireReference(xir, 18, xra);
        RequireEqual(xir, 6, xra, 6);
        RequireEqual(xir, 7, xra, 10);
        RequireEqual(xir, 8, xra, 11);
        RequireEqual(xir, 12, xra, 9);
        RequireEqual(xir, 13, xra, 12);
        RequireEqual(xir, 14, xra, 13);
        RequireEqual(xir, 15, xra, 15);

        RequireReference(xra, 5, pmt);
        RequireReference(xrr, 5, xra);
        RequireReference(xrr, 6, xrc);
        RequireReference(xrr, 7, xss);
        RequireReference(xrr, 8, pmt);
        RequireHash(xrr, 9, pms);
        RequireEqual(pms, 3, xra, 6);
        if (U64(pms, 4) != U64(pmt, 6)) RejectGraph();

        RequireReference(xrc, 5, xra);
        RequireReference(xrc, 6, pmt);
        RequireHash(xrc, 7, pms);
        RequireEqual(xrc, 8, pmt, 5);
        RequireEqual(xrc, 19, pmt, 14);
        RequireEqual(xrc, 11, xra, 10);
        RequireEqual(xrc, 12, xra, 11);
        if (xrc.Field(14).Span[0] != pms.Field(5).Span[0]) RejectGraph();
        var replicas = xrc.Field(15).Span;
        var selected = pms.Field(6).Span;
        for (var index = 0; index < selected.Length / 32; index++)
            if (!Fixed(replicas.Slice(index * 64, 32), selected.Slice(index * 32, 32)))
                RejectGraph();

        RequireReference(xss, 5, xrc);
        RequireReference(xss, 6, xrc);
        RequireReference(xss, 7, pmt);
        RequireHash(xss, 9, pms);
        if (U64(xrc, 3) == ulong.MaxValue ||
            !Fixed(xss.Field(2).Span, xrc.Field(2).Span) ||
            U64(xss, 3) != U64(xrc, 3) + 1 ||
            !Fixed(xss.Field(4).Span, xrc.CoreHash.Span) ||
            !Fixed(xss.Field(8).Span, xrc.Field(8).Span))
            RejectGraph();

        RequireEqual(xrr, 11, xra, 9);
        RequireEqual(xrr, 18, xra, 15);
        if (U64(xrc, 17) < U64(xra, 12) || U64(xrc, 18) > U64(xra, 13) ||
            U64(xrc, 17) < U64(pmt, 11) || U64(xrc, 18) > U64(pmt, 12) ||
            U64(xrr, 16) < U64(xrc, 17) || U64(xrr, 17) > U64(xrc, 18))
            RejectGraph();
    }

    private static ReadOnlyMemory<byte> EncodeClosure(ArtifactBundle bundle)
    {
        var total = checked(1 + ResponseRoles.Sum(role => 4 + bundle.Artifact(role).Length));
        if (total is < ContactRouteClosureTransportCodec.MinimumClosureBytes or
            > ContactRouteClosureTransportCodec.MaximumClosureBytes)
            throw new InvalidDataException("The canonical contact route closure length is invalid.");
        var result = GC.AllocateUninitializedArray<byte>(total);
        result[0] = checked((byte)ResponseRoles.Length);
        var offset = 1;
        foreach (var role in ResponseRoles)
        {
            var artifact = bundle.Artifact(role);
            BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(offset), checked((uint)artifact.Length));
            offset += 4;
            artifact.CopyTo(result.AsSpan(offset));
            offset += artifact.Length;
        }
        return result;
    }

    private void CheckAndAdvanceState(
        string statePath,
        ReadOnlySpan<byte> locatorHash,
        ulong generation,
        ReadOnlySpan<byte> manifestHash)
    {
        var previous = ReadState(statePath, locatorHash);
        if (previous is { Forked: true })
            throw new ContactRouteClosurePublicationRejectedException(
                "The locator publication is latched on a prior fork.");
        if (previous is not null)
        {
            if (generation < previous.Generation)
                throw new ContactRouteClosurePublicationRejectedException(
                    "The locator publication rolled back.");
            if (generation == previous.Generation && !Fixed(manifestHash, previous.ManifestHash))
            {
                WriteState(statePath, locatorHash,
                    new SourceState(previous.Generation, previous.ManifestHash, true));
                throw new ContactRouteClosurePublicationRejectedException(
                    "The locator publication forked at the accepted generation.");
            }
            if (generation == previous.Generation) return;
        }
        WriteState(statePath, locatorHash,
            new SourceState(generation, manifestHash.ToArray(), false));
    }

    private SourceState? ReadState(string statePath, ReadOnlySpan<byte> locatorHash)
    {
        if (!File.Exists(statePath)) return null;
        RejectReparse(statePath);
        var encoded = DirectoryPublication.DirectoryPublicationProtectedFile.ReadBounded(
            statePath, StatePayloadBytes + 32);
        var payload = DirectoryPublication.DirectoryPublicationProtectedFile.Verify(encoded, integrityKey);
        if (payload.Length != StatePayloadBytes ||
            BinaryPrimitives.ReadUInt16BigEndian(payload) != 1 ||
            !Fixed(payload.Slice(2, 16), networkId) ||
            !Fixed(payload.Slice(18, 32), locatorHash) || payload[^1] > 1)
            throw new InvalidDataException("The protected route closure state is invalid.");
        return new SourceState(
            BinaryPrimitives.ReadUInt64BigEndian(payload.Slice(50, 8)),
            payload.Slice(58, 32).ToArray(), payload[90] == 1);
    }

    private void WriteState(string statePath, ReadOnlySpan<byte> locatorHash, SourceState state)
    {
        Span<byte> payload = stackalloc byte[StatePayloadBytes];
        BinaryPrimitives.WriteUInt16BigEndian(payload, 1);
        networkId.CopyTo(payload.Slice(2, 16));
        locatorHash.CopyTo(payload.Slice(18, 32));
        BinaryPrimitives.WriteUInt64BigEndian(payload.Slice(50, 8), state.Generation);
        state.ManifestHash.CopyTo(payload.Slice(58, 32));
        payload[90] = state.Forked ? (byte)1 : (byte)0;
        var protectedBytes = DirectoryPublication.DirectoryPublicationProtectedFile.Protect(
            payload, integrityKey);
        try
        {
            WriteStateAtomic(statePath, protectedBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(protectedBytes);
        }
    }

    private static byte[] ReadExactFile(string path, int? expectedLength, int maximumLength)
    {
        RejectReparse(path);
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read,
            16 * 1024, FileOptions.SequentialScan);
        if (stream.Length < 1 || stream.Length > maximumLength || stream.Length > int.MaxValue ||
            expectedLength is not null && stream.Length != expectedLength.Value)
            throw new InvalidDataException("A contact route closure file has an invalid length.");
        var value = GC.AllocateUninitializedArray<byte>(checked((int)stream.Length));
        stream.ReadExactly(value);
        if (stream.ReadByte() != -1 || expectedLength is not null && value.Length != expectedLength.Value)
            throw new InvalidDataException("A contact route closure file changed while it was read.");
        RejectReparse(path);
        return value;
    }

    private static IDisposable AcquireStateLease(string statePath, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var directory = Path.GetDirectoryName(statePath)
            ?? throw new InvalidDataException("The protected state path has no directory.");
        RejectReparseAncestors(directory);
        var lockPath = statePath + ".lock";
        try
        {
            return new FileStream(lockPath, FileMode.CreateNew, FileAccess.ReadWrite,
                FileShare.None, 1, FileOptions.WriteThrough | FileOptions.DeleteOnClose);
        }
        catch (IOException exception)
        {
            throw new InvalidDataException(
                "The protected route closure state lease is unavailable.", exception);
        }
    }

    private static void WriteStateAtomic(string statePath, ReadOnlySpan<byte> value)
    {
        var directory = Path.GetDirectoryName(statePath)
            ?? throw new InvalidDataException("The protected state path has no directory.");
        RejectReparseAncestors(directory);
        if (File.Exists(statePath)) RejectReparse(statePath);
        var writing = Path.Combine(directory,
            $".{Path.GetFileName(statePath)}.{Guid.NewGuid():N}.writing");
        try
        {
            using (var stream = new FileStream(writing, FileMode.CreateNew, FileAccess.Write,
                       FileShare.None, 4096, FileOptions.WriteThrough))
            {
                stream.Write(value);
                stream.Flush(true);
            }
            RejectReparse(writing);
            RejectReparseAncestors(directory);
            if (File.Exists(statePath)) RejectReparse(statePath);
            File.Move(writing, statePath, overwrite: true);
            RejectReparse(statePath);
        }
        finally
        {
            if (File.Exists(writing)) File.Delete(writing);
        }
    }

    private static string Child(string parent, string name)
    {
        if (string.IsNullOrWhiteSpace(name) || Path.IsPathRooted(name) ||
            name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 ||
            name.Contains(Path.DirectorySeparatorChar) ||
            name.Contains(Path.AltDirectorySeparatorChar) || name is "." or "..")
            throw new InvalidDataException("A contact route closure path component is invalid.");
        var child = Path.GetFullPath(Path.Combine(parent, name));
        if (!IsWithin(child, parent))
            throw new InvalidDataException("A contact route closure path escapes its configured root.");
        return child;
    }

    private static bool IsWithin(string candidate, string root)
    {
        var prefix = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root)) +
            Path.DirectorySeparatorChar;
        return Path.GetFullPath(candidate).StartsWith(prefix,
            OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);
    }

    private static StringComparer StringComparerForPaths => OperatingSystem.IsWindows()
        ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;

    private static void EnsureDirectory(string path)
    {
        if (!Directory.Exists(path))
            throw new DirectoryNotFoundException("A contact route closure directory is unavailable.");
        RejectReparseAncestors(path);
        RejectReparse(path);
    }

    private static void RejectReparseAncestors(string path)
    {
        var current = Path.GetFullPath(path);
        while (!string.IsNullOrWhiteSpace(current))
        {
            if (Directory.Exists(current) || File.Exists(current)) RejectReparse(current);
            var parent = Directory.GetParent(current)?.FullName;
            if (string.IsNullOrWhiteSpace(parent) || StringComparerForPaths.Equals(parent, current))
                break;
            current = parent;
        }
    }

    private static void RejectReparse(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException("Reparse points are forbidden in contact route closure storage.");
    }

    private static byte[] ParseLowerHex(string? value, int expectedBytes, string name)
    {
        if (value is null || value.Length != expectedBytes * 2 ||
            value.Any(static character => character is not (>= '0' and <= '9') and
                not (>= 'a' and <= 'f')))
            throw new InvalidDataException(
                $"The {name} must be exactly {expectedBytes * 2} lowercase hexadecimal characters.");
        var result = Convert.FromHexString(value);
        if (result.AsSpan().IndexOfAnyExcept((byte)0) < 0)
            throw new InvalidDataException($"The {name} cannot be all-zero.");
        return result;
    }

    private static string LowerHex(ReadOnlySpan<byte> value) =>
        Convert.ToHexString(value).ToLowerInvariant();

    private static void RequireReference(ContactRecord owner, int tag, ContactRecord target)
    {
        var expected = ContactCodec.ArtifactReference(target.Magic, target).CanonicalBytes;
        if (!Fixed(owner.Field(tag).Span, expected.Span)) RejectGraph();
    }

    private static void RequireHash(ContactRecord owner, int tag, ContactRecord target)
    {
        if (!Fixed(owner.Field(tag).Span, target.ArtifactHash.Span)) RejectGraph();
    }

    private static void RequireEqual(ContactRecord left, int leftTag, ContactRecord right, int rightTag)
    {
        if (!Fixed(left.Field(leftTag).Span, right.Field(rightTag).Span)) RejectGraph();
    }

    private static ulong U64(ContactRecord record, int tag) =>
        BinaryPrimitives.ReadUInt64BigEndian(record.Field(tag).Span);

    private static void RejectGraph() =>
        throw new CryptographicException("The exact XIR/route transport graph is inconsistent.");

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(integrityKey);
        gate.Dispose();
    }

    private sealed class ExactResolver(IEnumerable<ContactRecord> records) : IContactRecordResolver
    {
        private readonly ContactRecord[] values = records.ToArray();

        public ContactRecord? Resolve(ContactArtifactReference reference) => values.SingleOrDefault(
            value => StringComparer.Ordinal.Equals(value.Magic, reference.Magic) &&
                Fixed(value.ArtifactHash.Span, reference.Hash.Span));
    }

    private sealed class ArtifactBundle
    {
        private readonly Dictionary<string, byte[]> artifacts;

        internal ArtifactBundle(
            byte[] manifestBytes,
            FileContactRouteClosureManifest manifest,
            Dictionary<string, byte[]> artifacts)
        {
            ManifestBytes = manifestBytes;
            Manifest = manifest;
            this.artifacts = artifacts;
        }

        internal byte[] ManifestBytes { get; }
        internal FileContactRouteClosureManifest Manifest { get; }
        internal ReadOnlySpan<byte> Artifact(string role) => artifacts[role];

        internal void RequireExact(ArtifactBundle other)
        {
            if (!Fixed(ManifestBytes, other.ManifestBytes) || artifacts.Count != other.artifacts.Count)
                throw new CryptographicException("The route closure manifest changed during verification.");
            foreach (var (role, bytes) in artifacts)
                if (!other.artifacts.TryGetValue(role, out var second) || !Fixed(bytes, second))
                    throw new CryptographicException("An exact route artifact changed during verification.");
        }
    }

    private sealed record SourceState(ulong Generation, byte[] ManifestHash, bool Forked);
}
#endif
