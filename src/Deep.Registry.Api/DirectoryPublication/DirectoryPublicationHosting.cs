using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Deep.Registry.Api.DirectoryPublication;

internal sealed class DirectoryPublicationOptions
{
    public bool MirrorEnabled { get; set; }
    public bool WriteEnabled { get; set; }
    public string StatePath { get; set; } = string.Empty;
    public string NetworkIdHex { get; set; } = string.Empty;
    public string AuthorityGenerationZeroCoreHashHex { get; set; } = string.Empty;
    public string ChallengeLedgerPath { get; set; } = string.Empty;
    public string ChallengeLedgerIntegrityKeyPath { get; set; } = string.Empty;
    public string MonotonicStatePath { get; set; } = string.Empty;
    public string ProtectedNetworkLkgPath { get; set; } = string.Empty;
    public string ProtectedNetworkLkgIntegrityKeyPath { get; set; } = string.Empty;
    public string PublisherClientCertificateSha256 { get; set; } = string.Empty;
}

internal readonly record struct DirectoryPublicationHostingState(
    bool MirrorEnabled,
    bool WriteEnabled)
{
    internal static DirectoryPublicationHostingState Disabled => default;
}

internal interface IDirectoryPublicationPublisherAuthorizer
{
    ValueTask<bool> IsAuthorizedAsync(HttpContext context, CancellationToken cancellationToken);
}

internal sealed class CertificateDirectoryPublicationPublisherAuthorizer(
    IOptions<DirectoryPublicationOptions> options) : IDirectoryPublicationPublisherAuthorizer
{
    public ValueTask<bool> IsAuthorizedAsync(HttpContext context, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var certificate = context.Connection.ClientCertificate;
        if (certificate is null)
        {
            return ValueTask.FromResult(false);
        }

        try
        {
            var expected = DirectoryPublicationHostingExtensions.Hex(
                options.Value.PublisherClientCertificateSha256,
                32,
                "publisher client-certificate SHA-256");
            return ValueTask.FromResult(CryptographicOperations.FixedTimeEquals(
                SHA256.HashData(certificate.RawData),
                expected));
        }
        catch (InvalidOperationException)
        {
            return ValueTask.FromResult(false);
        }
    }
}

internal static class DirectoryPublicationHostingExtensions
{
    private const string ManifestMediaType =
        "application/vnd.deep.directory-catalog-manifest.v2+octet-stream";
    private const string GenerationMediaType =
        "application/vnd.deep.directory-catalog-generation.v2+octet-stream";
    private const string HeadMediaType =
        "application/vnd.deep.xpoint-network-head.v1+octet-stream";

    internal static DirectoryPublicationHostingState AddDirectoryPublication(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        var section = configuration.GetSection("DirectoryPublication");
        var configured = section.Get<DirectoryPublicationOptions>() ?? new DirectoryPublicationOptions();
        services.Configure<DirectoryPublicationOptions>(section);
        if (!configured.MirrorEnabled)
        {
            if (configured.WriteEnabled)
            {
                throw new InvalidOperationException(
                    "Directory publication writes cannot be enabled while the mirror is disabled.");
            }
            return DirectoryPublicationHostingState.Disabled;
        }

        if (string.IsNullOrWhiteSpace(configured.StatePath))
        {
            throw new InvalidOperationException("DirectoryPublication:StatePath is required.");
        }
        var networkId = Hex(configured.NetworkIdHex, 16, "XPoint network ID");

        if (!configured.WriteEnabled)
        {
            services.AddSingleton<IDirectoryCanonicalPublicationVerifier,
                UnavailableDirectoryCanonicalPublicationVerifier>();
        }
        else
        {
            if (!ProductionDirectoryCanonicalPublicationVerifier.HasRequiredProtocolSurface)
            {
                throw new InvalidOperationException(
                    "Directory publication writes require the current DIRECTORY-01 Deep.Protocol surface; the pinned production package is fail-closed.");
            }

            ValidateWriteOptions(configured);
            var authorityHash = Hex(
                configured.AuthorityGenerationZeroCoreHashHex,
                32,
                "generation-zero XNA1 core hash");
            var challengeKey = DirectoryPublicationProtectedFile.ReadKey(
                configured.ChallengeLedgerIntegrityKeyPath);
            var lkgKey = DirectoryPublicationProtectedFile.ReadKey(
                configured.ProtectedNetworkLkgIntegrityKeyPath);

            services.AddSingleton(new DirectoryPublicationTrustAnchor(networkId, 0, authorityHash));
            services.AddSingleton<IDirectoryPublicationMonotonicClock>(
                new DurableDirectoryPublicationMonotonicClock(
                    configured.MonotonicStatePath,
                    challengeKey));
            services.AddSingleton<DurableDirectoryPublicationChallengeLedger>(sp => new(
                configured.ChallengeLedgerPath,
                networkId,
                challengeKey,
                sp.GetRequiredService<IDirectoryPublicationMonotonicClock>()));
            services.AddSingleton<IDirectoryPublicationChallengeIssuer>(sp =>
                sp.GetRequiredService<DurableDirectoryPublicationChallengeLedger>());
            services.AddSingleton<IDirectoryPublicationLiveChallengeAuthority>(sp =>
                sp.GetRequiredService<DurableDirectoryPublicationChallengeLedger>());
            services.AddSingleton<IDirectoryPublicationProtectedNetworkLkgSource>(
                new ProtectedFileDirectoryPublicationNetworkLkgSource(
                    configured.ProtectedNetworkLkgPath,
                    lkgKey));
            services.TryAddSingleton<IDirectoryPublicationPublisherAuthorizer,
                CertificateDirectoryPublicationPublisherAuthorizer>();
            services.AddSingleton<IDirectoryCanonicalPublicationVerifier>(sp =>
                new ProductionDirectoryCanonicalPublicationVerifier(
                    sp.GetRequiredService<DirectoryPublicationTrustAnchor>(),
                    sp.GetRequiredService<IDirectoryPublicationMonotonicClock>(),
                    sp.GetRequiredService<IDirectoryPublicationLiveChallengeAuthority>(),
                    sp.GetRequiredService<IDirectoryPublicationProtectedNetworkLkgSource>()));
        }

        services.AddSingleton(sp => new DirectoryPublicationCatalog(
            configured.StatePath,
            networkId,
            sp.GetRequiredService<IDirectoryCanonicalPublicationVerifier>()));
        return new DirectoryPublicationHostingState(true, configured.WriteEnabled);
    }

    internal static void MapDirectoryPublicationEndpoints(
        this WebApplication app,
        DirectoryPublicationHostingState state)
    {
        if (!state.MirrorEnabled) return;

        var group = app.MapGroup("/api/v1/directory");
        group.MapGet("/manifest", (HttpRequest request, HttpResponse response,
            DirectoryPublicationCatalog catalog) => MirrorResult(
                request, response, () => catalog.GetManifestArtifact(), ManifestMediaType,
                "private,no-store,max-age=0,must-revalidate"));
        group.MapGet("/head", (HttpRequest request, HttpResponse response,
            DirectoryPublicationCatalog catalog) => MirrorResult(
                request, response, catalog.GetCurrentHeadArtifact, HeadMediaType,
                "private,no-store,max-age=0,must-revalidate"));
        group.MapGet("/generations/{generation}", (
            string generation,
            HttpRequest request,
            HttpResponse response,
            DirectoryPublicationCatalog catalog) =>
        {
            if (!ulong.TryParse(generation, NumberStyles.None, CultureInfo.InvariantCulture, out var value))
            {
                return Results.NotFound();
            }
            return MirrorResult(
                request, response, () => catalog.GetGenerationArtifact(value), GenerationMediaType,
                "public,max-age=31536000,immutable");
        });

        if (!state.WriteEnabled) return;

        group.MapPost("/publication-challenges", IssueChallengeAsync);
        group.MapPost("/publications", PublishAsync)
            .WithMetadata(new Microsoft.AspNetCore.Mvc.RequestSizeLimitAttribute(
                DirectoryPublicationWriteEnvelopeCodec.MaximumEnvelopeBytes));
    }

    private static async Task<IResult> IssueChallengeAsync(
        HttpContext context,
        IDirectoryPublicationPublisherAuthorizer authorizer,
        IDirectoryPublicationChallengeIssuer issuer,
        CancellationToken cancellationToken)
    {
        if (!context.Request.IsHttps && !context.RequestServices
                .GetRequiredService<IHostEnvironment>().IsDevelopment())
        {
            return Failure(StatusCodes.Status400BadRequest, "https-required");
        }
        if (!await authorizer.IsAuthorizedAsync(context, cancellationToken).ConfigureAwait(false))
        {
            return Results.Unauthorized();
        }

        try
        {
            var challenge = await issuer.IssueAsync(cancellationToken).ConfigureAwait(false);
            return Results.Json(new DirectoryPublicationChallengeResponse(
                "challenge-issued",
                Convert.ToBase64String(challenge.Nonce.Span),
                Convert.ToBase64String(challenge.BootId.Span),
                challenge.CreatedAtMonotonicSeconds));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (IsUnavailable(exception))
        {
            return Failure(StatusCodes.Status503ServiceUnavailable, "challenge-ledger-unavailable");
        }
    }

    private static async Task<IResult> PublishAsync(
        HttpContext context,
        IDirectoryPublicationPublisherAuthorizer authorizer,
        IDirectoryPublicationMonotonicClock clock,
        DirectoryPublicationCatalog catalog,
        CancellationToken cancellationToken)
    {
        if (!context.Request.IsHttps && !context.RequestServices
                .GetRequiredService<IHostEnvironment>().IsDevelopment())
        {
            return Failure(StatusCodes.Status400BadRequest, "https-required");
        }
        if (!await authorizer.IsAuthorizedAsync(context, cancellationToken).ConfigureAwait(false))
        {
            return Results.Unauthorized();
        }
        if (!string.Equals(
            context.Request.ContentType,
            DirectoryPublicationWriteEnvelopeCodec.MediaType,
            StringComparison.OrdinalIgnoreCase))
        {
            return Failure(StatusCodes.Status415UnsupportedMediaType, "unsupported-publication-media-type");
        }

        try
        {
            var submission = await DirectoryPublicationWriteEnvelopeCodec.DecodeAsync(
                context.Request,
                cancellationToken).ConfigureAwait(false);
            var received = await clock.ReadAsync(cancellationToken).ConfigureAwait(false);
            if (!CryptographicOperations.FixedTimeEquals(
                    received.BootId.Span,
                    submission.ChallengeBootId))
            {
                return Failure(StatusCodes.Status409Conflict, "publication-challenge-rejected");
            }

            var candidate = submission.CreateCandidate(received.SampleSeconds);
            var result = await catalog.PublishAsync(
                candidate,
                submission.ExpectedAnchor,
                cancellationToken).ConfigureAwait(false);
            var response = new DirectoryPublicationWriteResponse(
                result.Status == DirectoryCatalogPublishStatus.Published
                    ? "published"
                    : "exact-replay",
                result.CurrentAnchor.Generation,
                Convert.ToHexString(result.CurrentAnchor.PublicationHash.Span).ToLowerInvariant());
            return Results.Json(
                response,
                statusCode: result.Status == DirectoryCatalogPublishStatus.Published
                    ? StatusCodes.Status201Created
                    : StatusCodes.Status200OK);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (DirectoryPublicationEnvelopeException exception)
        {
            return Failure(
                exception.TooLarge ? StatusCodes.Status413PayloadTooLarge : StatusCodes.Status400BadRequest,
                exception.TooLarge ? "publication-bounds-exceeded" : "malformed-publication");
        }
        catch (DirectoryCatalogException exception)
        {
            return exception.Error switch
            {
                DirectoryCatalogError.BoundsExceeded =>
                    Failure(StatusCodes.Status413PayloadTooLarge, "publication-bounds-exceeded"),
                DirectoryCatalogError.CompareExchangeMismatch or DirectoryCatalogError.GenerationGap or
                    DirectoryCatalogError.Rollback =>
                    Failure(StatusCodes.Status409Conflict, "publication-conflict"),
                DirectoryCatalogError.CanonicalVerificationFailed or
                    DirectoryCatalogError.VerificationMismatch or DirectoryCatalogError.WrongNetwork =>
                    Failure(StatusCodes.Status422UnprocessableEntity, "canonical-publication-rejected"),
                _ => Failure(StatusCodes.Status503ServiceUnavailable, "directory-publication-unavailable")
            };
        }
        catch (Exception exception) when (exception is ArgumentException or FormatException)
        {
            return Failure(StatusCodes.Status400BadRequest, "malformed-publication");
        }
        catch (Exception exception) when (IsUnavailable(exception))
        {
            return Failure(StatusCodes.Status503ServiceUnavailable, "directory-publication-unavailable");
        }
    }

    private static IResult MirrorResult(
        HttpRequest request,
        HttpResponse response,
        Func<DirectoryMirrorArtifact?> read,
        string mediaType,
        string cacheControl)
    {
        try
        {
            var artifact = read();
            if (artifact is null) return Results.NotFound();
            var etag = $"\"sha256-{Convert.ToHexString(artifact.Sha256.Span).ToLowerInvariant()}\"";
            response.Headers.ETag = etag;
            response.Headers.CacheControl = cacheControl;
            response.Headers["X-Content-Type-Options"] = "nosniff";
            if (MatchesIfNoneMatch(request.Headers.IfNoneMatch, etag))
            {
                return Results.StatusCode(StatusCodes.Status304NotModified);
            }
            return Results.Bytes(artifact.Bytes.ToArray(), mediaType, enableRangeProcessing: false);
        }
        catch (Exception exception) when (
            exception is DirectoryCatalogException or IOException or CryptographicException)
        {
            return Failure(StatusCodes.Status503ServiceUnavailable, "directory-mirror-unavailable");
        }
    }

    private static bool MatchesIfNoneMatch(IEnumerable<string> values, string etag)
    {
        foreach (var value in values)
        {
            foreach (var item in value.Split(','))
            {
                var candidate = item.Trim();
                if (candidate == "*") return true;
                if (candidate.StartsWith("W/", StringComparison.OrdinalIgnoreCase))
                    candidate = candidate[2..].TrimStart();
                if (StringComparer.Ordinal.Equals(candidate, etag)) return true;
            }
        }
        return false;
    }

    private static IResult Failure(int statusCode, string code) =>
        Results.Json(new DirectoryPublicationFailureResponse(code), statusCode: statusCode);

    private static bool IsUnavailable(Exception exception) =>
        exception is IOException or CryptographicException or InvalidDataException or InvalidOperationException;

    private static void ValidateWriteOptions(DirectoryPublicationOptions options)
    {
        var required = new Dictionary<string, string>
        {
            [nameof(options.ChallengeLedgerPath)] = options.ChallengeLedgerPath,
            [nameof(options.ChallengeLedgerIntegrityKeyPath)] = options.ChallengeLedgerIntegrityKeyPath,
            [nameof(options.MonotonicStatePath)] = options.MonotonicStatePath,
            [nameof(options.ProtectedNetworkLkgPath)] = options.ProtectedNetworkLkgPath,
            [nameof(options.ProtectedNetworkLkgIntegrityKeyPath)] = options.ProtectedNetworkLkgIntegrityKeyPath,
            [nameof(options.PublisherClientCertificateSha256)] = options.PublisherClientCertificateSha256,
            [nameof(options.AuthorityGenerationZeroCoreHashHex)] = options.AuthorityGenerationZeroCoreHashHex
        };
        var missing = required.FirstOrDefault(value => string.IsNullOrWhiteSpace(value.Value));
        if (missing.Key is not null)
        {
            throw new InvalidOperationException($"DirectoryPublication:{missing.Key} is required for writes.");
        }
        if (StringComparer.OrdinalIgnoreCase.Equals(
            Path.GetFullPath(options.ChallengeLedgerIntegrityKeyPath),
            Path.GetFullPath(options.ProtectedNetworkLkgIntegrityKeyPath)))
        {
            throw new InvalidOperationException(
                "The challenge ledger and protected network LKG require independent integrity keys.");
        }
        _ = Hex(options.PublisherClientCertificateSha256, 32, "publisher client-certificate SHA-256");
    }

    internal static byte[] Hex(string value, int length, string label)
    {
        try
        {
            var decoded = Convert.FromHexString(value);
            if (decoded.Length != length || decoded.AsSpan().IndexOfAnyExcept((byte)0) < 0)
                throw new FormatException();
            return decoded;
        }
        catch (FormatException exception)
        {
            throw new InvalidOperationException($"The configured {label} is invalid.", exception);
        }
    }

    private sealed class UnavailableDirectoryCanonicalPublicationVerifier :
        IDirectoryCanonicalPublicationVerifier
    {
        public ValueTask<VerifiedDirectoryPublication> VerifyAsync(
            FrozenDirectoryPublicationCandidate candidate,
            CancellationToken cancellationToken) =>
            ValueTask.FromException<VerifiedDirectoryPublication>(
                new DirectoryCanonicalVerificationException(
                    DirectoryCanonicalVerificationError.ProtocolSurfaceUnavailable,
                    "Directory publication writes are disabled."));
    }
}

internal sealed record DirectoryPublicationChallengeResponse(
    string Code,
    string NonceBase64,
    string BootIdBase64,
    ulong CreatedAtMonotonicSeconds);

internal sealed record DirectoryPublicationWriteResponse(
    string Code,
    ulong Generation,
    string PublicationSha256);

internal sealed record DirectoryPublicationFailureResponse(string Code);

internal sealed class DirectoryPublicationEnvelopeException(string message, bool tooLarge = false)
    : Exception(message)
{
    internal bool TooLarge { get; } = tooLarge;
}

internal sealed class DirectoryPublicationHttpSubmission
{
    internal required DirectoryCatalogAnchor ExpectedAnchor { get; init; }
    internal required byte[] ChallengeNonce { get; init; }
    internal required byte[] ChallengeBootId { get; init; }
    internal required ulong ChallengeCreatedAt { get; init; }
    internal required ushort SupportedReader { get; init; }
    internal required byte[] QueriedDirectoryLeafKey { get; init; }
    internal required IReadOnlyList<ReadOnlyMemory<byte>> AuthorityChain { get; init; }
    internal required IReadOnlyList<ReadOnlyMemory<byte>> TimePolicyChain { get; init; }
    internal required IReadOnlyList<ReadOnlyMemory<byte>> NetworkPolicyChain { get; init; }
    internal required IReadOnlyList<ReadOnlyMemory<byte>> NetworkViewChain { get; init; }
    internal required IReadOnlyList<ReadOnlyMemory<byte>> NetworkHeadChain { get; init; }
    internal required IReadOnlyList<ReadOnlyMemory<byte>> ActiveNodeDescriptors { get; init; }
    internal required IReadOnlyList<ReadOnlyMemory<byte>> MailboxTopologyChain { get; init; }
    internal required IReadOnlyList<ReadOnlyMemory<byte>> ResetAuthorityChain { get; init; }
    internal required IReadOnlyList<ReadOnlyMemory<byte>> ForwardCheckpointChain { get; init; }
    internal required byte[] ExactDirectoryHead { get; init; }
    internal required byte[] ExactLiveTimeAttestation { get; init; }
    internal required byte[] ExactDirectoryProof { get; init; }
    internal required byte[] CurrentNetworkView { get; init; }
    internal required byte[] CurrentNetworkHead { get; init; }
    internal required byte[] CurrentMailboxTopology { get; init; }
    internal required byte[] NetworkForwardCheckpoint { get; init; }
    internal required byte[] NetworkForwardProof { get; init; }

    internal DirectoryPublicationCandidate CreateCandidate(ulong responseReceivedAt)
    {
        var closure = new DirectoryPublicationVerificationClosure(
            AuthorityChain,
            TimePolicyChain,
            NetworkPolicyChain,
            NetworkViewChain,
            NetworkHeadChain,
            ActiveNodeDescriptors,
            MailboxTopologyChain,
            ExactDirectoryHead,
            ExactLiveTimeAttestation,
            ExactDirectoryProof,
            ChallengeNonce,
            QueriedDirectoryLeafKey,
            ChallengeBootId,
            ChallengeCreatedAt,
            responseReceivedAt,
            responseReceivedAt,
            SupportedReader,
            ResetAuthorityChain,
            ForwardCheckpointChain);
        return new DirectoryPublicationCandidate(
            CurrentNetworkView,
            CurrentNetworkHead,
            CurrentMailboxTopology,
            closure,
            NetworkForwardCheckpoint,
            NetworkForwardProof);
    }
}

internal static class DirectoryPublicationWriteEnvelopeCodec
{
    internal const string MediaType =
        "application/vnd.deep.directory-publication-write.v1+octet-stream";
    internal const long MaximumEnvelopeBytes =
        DirectoryPublicationVerificationClosure.MaximumTotalClosureBytes +
        (6L * DirectoryCatalogLimits.AbsoluteMaximumArtifactBytes) + 256 * 1024;
    private static readonly byte[] Magic = "DPW1"u8.ToArray();

    internal static async ValueTask<DirectoryPublicationHttpSubmission> DecodeAsync(
        HttpRequest request,
        CancellationToken cancellationToken)
    {
        if (request.ContentLength is > MaximumEnvelopeBytes)
            throw new DirectoryPublicationEnvelopeException("The publication envelope is too large.", true);
        using var stream = new MemoryStream();
        var buffer = new byte[64 * 1024];
        while (true)
        {
            var read = await request.Body.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0) break;
            if (stream.Length + read > MaximumEnvelopeBytes)
                throw new DirectoryPublicationEnvelopeException("The publication envelope is too large.", true);
            stream.Write(buffer, 0, read);
        }
        return Decode(stream.ToArray());
    }

    internal static DirectoryPublicationHttpSubmission Decode(ReadOnlySpan<byte> encoded)
    {
        try
        {
            var reader = new Reader(encoded);
            if (!reader.ReadBytes(4).SequenceEqual(Magic) || reader.ReadUInt16() != 1)
                throw Malformed();
            var hasAnchor = reader.ReadByte();
            if (hasAnchor > 1) throw Malformed();
            var anchor = hasAnchor == 0
                ? DirectoryCatalogAnchor.Empty
                : new DirectoryCatalogAnchor(reader.ReadUInt64(), reader.ReadBytes(32));
            var nonce = reader.ReadBytes(32).ToArray();
            var boot = reader.ReadBytes(16).ToArray();
            var created = reader.ReadUInt64();
            var supportedReader = reader.ReadUInt16();
            var queriedKey = reader.ReadBytes(32).ToArray();
            var authority = reader.ReadChain(DirectoryPublicationVerificationClosure.MaximumAuthorityChainEntries);
            var timePolicy = reader.ReadChain(DirectoryPublicationVerificationClosure.MaximumAuthorityChainEntries);
            var networkPolicy = reader.ReadChain(DirectoryPublicationVerificationClosure.MaximumSuccessorChainEntries);
            var networkViews = reader.ReadChain(DirectoryPublicationVerificationClosure.MaximumSuccessorChainEntries);
            var networkHeads = reader.ReadChain(DirectoryPublicationVerificationClosure.MaximumSuccessorChainEntries);
            var nodes = reader.ReadChain(DirectoryPublicationVerificationClosure.MaximumNodeDescriptors);
            var mailbox = reader.ReadChain(DirectoryPublicationVerificationClosure.MaximumSuccessorChainEntries);
            var resetAuthority = reader.ReadChain(DirectoryPublicationVerificationClosure.MaximumAuthorityChainEntries);
            var forward = reader.ReadChain(DirectoryPublicationVerificationClosure.MaximumForwardCheckpointEntries);
            var adh = reader.ReadArtifact(false);
            var dtt = reader.ReadArtifact(false);
            var adp = reader.ReadArtifact(false);
            var currentView = reader.ReadArtifact(false);
            var currentHead = reader.ReadArtifact(false);
            var currentMailbox = reader.ReadArtifact(false);
            var xnf = reader.ReadArtifact(true);
            var nfp = reader.ReadArtifact(true);
            if (!reader.AtEnd || xnf.Length == 0 != (nfp.Length == 0)) throw Malformed();
            return new DirectoryPublicationHttpSubmission
            {
                ExpectedAnchor = anchor,
                ChallengeNonce = nonce,
                ChallengeBootId = boot,
                ChallengeCreatedAt = created,
                SupportedReader = supportedReader,
                QueriedDirectoryLeafKey = queriedKey,
                AuthorityChain = authority,
                TimePolicyChain = timePolicy,
                NetworkPolicyChain = networkPolicy,
                NetworkViewChain = networkViews,
                NetworkHeadChain = networkHeads,
                ActiveNodeDescriptors = nodes,
                MailboxTopologyChain = mailbox,
                ResetAuthorityChain = resetAuthority,
                ForwardCheckpointChain = forward,
                ExactDirectoryHead = adh,
                ExactLiveTimeAttestation = dtt,
                ExactDirectoryProof = adp,
                CurrentNetworkView = currentView,
                CurrentNetworkHead = currentHead,
                CurrentMailboxTopology = currentMailbox,
                NetworkForwardCheckpoint = xnf,
                NetworkForwardProof = nfp
            };
        }
        catch (DirectoryPublicationEnvelopeException) { throw; }
        catch (Exception exception) when (
            exception is ArgumentException or OverflowException or EndOfStreamException)
        {
            throw new DirectoryPublicationEnvelopeException("The publication envelope is malformed.");
        }
    }

    private static DirectoryPublicationEnvelopeException Malformed() =>
        new("The publication envelope is malformed.");

    private ref struct Reader(ReadOnlySpan<byte> source)
    {
        private readonly ReadOnlySpan<byte> source = source;
        private int offset;
        internal bool AtEnd => offset == source.Length;
        internal byte ReadByte() => ReadBytes(1)[0];
        internal ushort ReadUInt16() => BinaryPrimitives.ReadUInt16BigEndian(ReadBytes(2));
        internal ulong ReadUInt64() => BinaryPrimitives.ReadUInt64BigEndian(ReadBytes(8));
        internal ReadOnlySpan<byte> ReadBytes(int count)
        {
            if (count < 0 || count > source.Length - offset) throw new EndOfStreamException();
            var value = source.Slice(offset, count);
            offset += count;
            return value;
        }
        internal byte[] ReadArtifact(bool optional)
        {
            var length = BinaryPrimitives.ReadUInt32BigEndian(ReadBytes(4));
            if (length > DirectoryCatalogLimits.AbsoluteMaximumArtifactBytes || (!optional && length == 0))
                throw new DirectoryPublicationEnvelopeException(
                    "A publication artifact exceeds its absolute bound.",
                    length > DirectoryCatalogLimits.AbsoluteMaximumArtifactBytes);
            return ReadBytes(checked((int)length)).ToArray();
        }
        internal IReadOnlyList<ReadOnlyMemory<byte>> ReadChain(int maximumCount)
        {
            var count = ReadUInt16();
            if (count > maximumCount) throw new DirectoryPublicationEnvelopeException("A publication chain exceeds its absolute bound.", true);
            var result = new ReadOnlyMemory<byte>[count];
            for (var index = 0; index < count; index++) result[index] = ReadArtifact(false);
            return result;
        }
    }
}
