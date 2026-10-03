#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.XPointNetworkV1;
using Microsoft.AspNetCore.Mvc;

namespace Deep.Registry.Api.DirectoryPublication;

internal sealed class DeepIdV2MailboxGrantOptions
{
    public bool Enabled { get; set; }
    public string ObserverCredentialPath { get; set; } = string.Empty;
    public string DepositSignerSocketPath { get; set; } = string.Empty;
    public string RetrieveSignerSocketPath { get; set; } = string.Empty;
}

internal sealed class DeepIdV2ExternalMailboxGrantCustody : IDeepIdV2MailboxGrantSignerCustody
{
    private readonly string deposit, retrieve;
    internal DeepIdV2ExternalMailboxGrantCustody(DeepIdV2MailboxGrantOptions options)
    {
        deposit = RequireSocket(options.DepositSignerSocketPath); retrieve = RequireSocket(options.RetrieveSignerSocketPath);
        if (string.Equals(deposit, retrieve, StringComparison.Ordinal)) throw new InvalidOperationException("Mailbox roles require independent signer sockets.");
    }
    public IMailboxGrantIssuerSigner Resolve(VerifiedMailboxAuthorityV2 authority, MailboxCapabilityDomain domain) =>
        new ExternalSigner(authority.ResolveIssuer(domain).PublicKey, new UnixSocketEd25519ExternalSigner(
            RequireSocket(domain == MailboxCapabilityDomain.Deposit ? deposit : retrieve), TimeSpan.FromSeconds(5)));
    private static string RequireSocket(string path)
    {
        if (OperatingSystem.IsWindows() || !Path.IsPathFullyQualified(path) || !File.Exists(path))
            throw new InvalidOperationException("Private mailbox issuance requires protected external signer sockets.");
        path = Path.GetFullPath(path);
        var info = new FileInfo(path);
        if (!string.IsNullOrEmpty(info.LinkTarget) || (info.Attributes & FileAttributes.ReparsePoint) != 0 ||
            (File.GetUnixFileMode(path) & (UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute)) != 0)
            throw new InvalidOperationException("Mailbox signer socket is not protected.");
        return path;
    }
    private sealed class ExternalSigner(ReadOnlyMemory<byte> publicKey, IEd25519ExternalSigner signer) : IMailboxGrantIssuerSigner
    {
        public ReadOnlyMemory<byte> Ed25519PublicKey => publicKey.ToArray();
        public async ValueTask<ReadOnlyMemory<byte>> SignAsync(ReadOnlyMemory<byte> signingBytes, CancellationToken ct) =>
            await signer.SignAsync(signingBytes, ct).ConfigureAwait(false);
    }
}

internal sealed class DeepIdV2MailboxGrantAdmission
{
    private readonly SemaphoreSlim gate = new(1, 1);
    internal bool TryEnter() => gate.Wait(0);
    internal void Exit() => gate.Release();
}

internal static class DeepIdV2MailboxGrantHosting
{
    internal const string EndpointPath = "/api/production-mailbox/internal/contact-grants";
    internal const string ResponseMediaType = "application/vnd.deep.mailbox-contact-grant-result.v1+octet-stream";
    internal const int MaximumBodyBytes = 48 * 1_024;

    internal static bool AddDeepIdV2MailboxGrants(this IServiceCollection services, IConfiguration configuration)
    {
        RetiredMailboxConfiguration.RequireAbsent(configuration);
        var options = configuration.GetSection("DeepIdV2MailboxGrantAuthority").Get<DeepIdV2MailboxGrantOptions>() ?? new();
        if (!options.Enabled) return false;
        var did2 = configuration.GetSection("DeepIdV2DirectoryAuthority").Get<DeepIdV2DirectoryAuthorityOptions>() ?? new();
        if (!did2.Enabled || !did2.ProofEnabled ||
            !configuration.GetValue<bool>("XPointNetworkClosureDistribution:Enabled") ||
            string.IsNullOrWhiteSpace(did2.LatestHeadFloorPostgreSqlConnectionString) || did2.NetworkIdHex.Length != 32 ||
            !Path.IsPathFullyQualified(options.ObserverCredentialPath))
            throw new InvalidOperationException("Private DID2 grant issuance requires current proof/floor/bundle and no retired mailbox authority.");
        var network = Convert.FromHexString(did2.NetworkIdHex);
        if (network.AsSpan().IndexOfAnyExcept((byte)0) < 0) throw new InvalidOperationException("Private grant network is zero.");
        var file = new FileInfo(options.ObserverCredentialPath);
        if (!file.Exists || file.Length != DeepIdV2Codec.Did2Length || !string.IsNullOrEmpty(file.LinkTarget) ||
            (file.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException("Private grant public observer credential is not an exact regular DID2 file.");
        using var stream = new FileStream(file.FullName, FileMode.Open, FileAccess.Read, FileShare.Read);
        var bytes = new byte[DeepIdV2Codec.Did2Length]; stream.ReadExactly(bytes);
        if (stream.ReadByte() != -1) throw new InvalidDataException("Private observer credential grew while reading.");
        var observer = DeepIdV2Codec.DecodeDid2(bytes);
        services.AddSingleton<IDeepIdV2MailboxGrantJournal>(_ => new DeepIdV2PostgreSqlMailboxGrantJournal(did2.LatestHeadFloorPostgreSqlConnectionString, network));
        services.AddSingleton<IDeepIdV2MailboxGrantSignerCustody>(_ => new DeepIdV2ExternalMailboxGrantCustody(options));
        services.AddSingleton<DeepIdV2MailboxGrantReplayGuard>(); services.AddSingleton<DeepIdV2MailboxGrantAdmission>();
        services.AddSingleton(provider => new DeepIdV2MailboxGrantIssuer(provider.GetRequiredService<DeepIdV2DirectoryProofIssuer>(),
            provider.GetRequiredService<DeepIdV2XPointAuthoritySource>(), provider.GetRequiredService<XPointNetworkClosureDistribution>(),
            provider.GetRequiredService<IContactResolveTrustedTimeContextSource>(), provider.GetRequiredService<IDeepIdV2MailboxGrantJournal>(),
            provider.GetRequiredService<IDeepIdV2MailboxGrantSignerCustody>(), provider.GetRequiredService<DeepIdV2MailboxGrantReplayGuard>(), observer));
        return true;
    }

    internal static void MapDeepIdV2MailboxGrants(this WebApplication app, bool enabled)
    {
        if (!enabled) return;
        _ = app.Services.GetRequiredService<DeepIdV2MailboxGrantIssuer>();
        app.MapPost(EndpointPath, HandleAsync).WithMetadata(new RequestSizeLimitAttribute(MaximumBodyBytes));
    }

    private static async Task<IResult> HandleAsync(HttpContext context, DeepIdV2MailboxGrantIssuer issuer, DeepIdV2MailboxGrantAdmission admission)
    {
        if (!context.Request.IsHttps) return Results.StatusCode(403);
        if (context.Request.Path.Value != EndpointPath || context.Request.QueryString.HasValue) return Results.BadRequest();
        if (context.Request.ContentType != "application/json" || context.Request.Headers.ContentEncoding.Count != 0) return Results.StatusCode(415);
        if (context.Request.ContentLength is null) return Results.StatusCode(411);
        if (context.Request.ContentLength is < 1 or > MaximumBodyBytes) return Results.StatusCode(413);
        if (!admission.TryEnter()) return Results.StatusCode(429);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(context.RequestAborted);
        timeout.CancelAfter(TimeSpan.FromSeconds(30));
        var body = new byte[checked((int)context.Request.ContentLength.Value)];
        try
        {
            await context.Request.Body.ReadExactlyAsync(body, timeout.Token).ConfigureAwait(false);
            var trailing = new byte[1];
            if (await context.Request.Body.ReadAsync(trailing, timeout.Token).ConfigureAwait(false) != 0) return Results.BadRequest();
            var input = DecodeRequest(body);
            var exact = await issuer.IssueAsync(input, timeout.Token).ConfigureAwait(false);
            context.Response.Headers.CacheControl = "no-store"; context.Response.Headers.XContentTypeOptions = "nosniff";
            context.Response.StatusCode = 200; context.Response.ContentType = ResponseMediaType; context.Response.ContentLength = exact.Length;
            await context.Response.Body.WriteAsync(exact, timeout.Token).ConfigureAwait(false); return Results.Empty;
        }
        catch (UnauthorizedAccessException) when (!context.Response.HasStarted) { return Results.Unauthorized(); }
        catch (Exception error) when (!context.Response.HasStarted && error is JsonException or ArgumentException or FormatException or OverflowException or CryptographicException or EndOfStreamException)
        { return Results.BadRequest(); }
        catch (Exception error) when (!context.Response.HasStarted && error is IOException or InvalidOperationException or OperationCanceledException or
            Npgsql.NpgsqlException or Deep.Protocol.DeepExtension.PrivacyRouting.OnionBoundaryException)
        { return Results.StatusCode(503); }
        finally { CryptographicOperations.ZeroMemory(body); admission.Exit(); }
    }

    internal static DeepIdV2MailboxGrantInput DecodeRequest(ReadOnlyMemory<byte> body)
    {
        try { return DecodeRequestCore(body); }
        catch (InvalidOperationException) { throw new JsonException("Private grant field has an invalid JSON kind."); }
    }

    private static DeepIdV2MailboxGrantInput DecodeRequestCore(ReadOnlyMemory<byte> body)
    {
        if (body.Length is < 1 or > MaximumBodyBytes) throw new JsonException("Private grant body exceeds bounds.");
        using var document = JsonDocument.Parse(body, new JsonDocumentOptions { MaxDepth = 8 });
        var root = document.RootElement;
        RequireFields(root, ["exactXmg1", "resultCode", "exactRouteClosure", "routeDisposition", "routeEffectiveExpiresAtUnixSeconds",
            "resultExpiresAtUnixSeconds", "nodeId", "issuedAtUnixSeconds", "nonce", "signature", "replicaEvidence"]);
        if (root.GetProperty("resultCode").GetUInt16() != 1 || root.GetProperty("routeDisposition").GetUInt16() != 1)
            throw new JsonException("Only current-route issuance is supported.");
        var request = Base64(root.GetProperty("exactXmg1").GetString(), 435, 435);
        var route = Base64(root.GetProperty("exactRouteClosure").GetString(), 4_143, 23_295);
        var replicas = root.GetProperty("replicaEvidence");
        if (replicas.ValueKind != JsonValueKind.Array || replicas.GetArrayLength() != 2) throw new JsonException("Two-store evidence is required.");
        var evidence = replicas.EnumerateArray().Select(item =>
        {
            RequireFields(item, ["replicaId", "signature"]);
            return new DeepIdV2MailboxGrantReplicaEvidence(Hex(item.GetProperty("replicaId").GetString()), Base64(item.GetProperty("signature").GetString(), 64, 64));
        }).ToArray();
        // Stable envelope deadline is signed by the forwarding node and journalled implicitly by XMG hash.
        if (root.GetProperty("resultExpiresAtUnixSeconds").GetUInt64() !=
            BinaryPrimitives.ReadUInt64BigEndian(Deep.Protocol.ContactV1.ContactCodec.Decode("XMG1", request).Field(10).Span))
            throw new JsonException("Private result deadline differs from the original request.");
        return new(request, route, root.GetProperty("routeEffectiveExpiresAtUnixSeconds").GetUInt64(), evidence,
            Hex(root.GetProperty("nodeId").GetString()), root.GetProperty("issuedAtUnixSeconds").GetUInt64(),
            Base64(root.GetProperty("nonce").GetString(), 32, 32), Base64(root.GetProperty("signature").GetString(), 64, 64));
    }
    private static void RequireFields(JsonElement value, string[] fields)
    {
        if (value.ValueKind != JsonValueKind.Object) throw new JsonException("Private grant object required.");
        var found = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in value.EnumerateObject())
            if (!fields.Contains(property.Name, StringComparer.Ordinal) || !found.Add(property.Name)) throw new JsonException("Unknown or duplicate private grant field.");
        if (found.Count != fields.Length) throw new JsonException("Private grant field is missing.");
    }
    private static byte[] Base64(string? text, int minimum, int maximum)
    {
        if (text is null || text.Length < (minimum * 8 + 5) / 6 || text.Length > (maximum * 8 + 5) / 6 ||
            text.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '-' or '_')))
            throw new JsonException("Private binary field exceeds its encoded bounds.");
        var normalized = text.Replace('-', '+').Replace('_', '/');
        var bytes = Convert.FromBase64String(normalized.PadRight((normalized.Length + 3) / 4 * 4, '='));
        if (bytes.Length < minimum || bytes.Length > maximum ||
            Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_') != text)
            throw new JsonException("Private binary field is not canonical.");
        return bytes;
    }
    private static byte[] Hex(string? text)
    {
        if (text is null || text.Length != 64 || text.Any(c => !(c is >= '0' and <= '9' or >= 'a' and <= 'f')))
            throw new JsonException("Private node ID must be canonical lowercase hex.");
        return Convert.FromHexString(text);
    }
}
#endif
