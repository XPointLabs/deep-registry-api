#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Globalization;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Mvc;

namespace Deep.Registry.Api.DirectoryPublication;

internal sealed class MailboxRevocationDistributionAdmission
{
    private readonly SemaphoreSlim gate = new(1, 1);
    internal bool TryEnter() => gate.Wait(0);
    internal void Exit() => gate.Release();
}

// Raw identity-neutral signed control only. No observer issuance or signing in a read.
internal static class MailboxRevocationDistributionHosting
{
    internal const string Prefix = "/api/v1/node-control/mailbox-revocations";
    internal const string MediaType = "application/vnd.deep.mailbox-grant-revocation.v1+octet-stream";
    internal static void MapMailboxRevocationDistribution(this WebApplication app, bool enabled)
    {
        if (!enabled) return;
        app.MapGet(Prefix + "/{network}/{policy}/{role}/{generation}", HandleAsync)
            .WithMetadata(new RequestSizeLimitAttribute(0));
    }

    private static async Task<IResult> HandleAsync(HttpContext context, string network, string policy, string role, string generation,
        MailboxRevocationAuthority authority, MailboxRevocationDistributionAdmission admission)
    {
        context.Response.Headers.CacheControl = "no-store";
        context.Response.Headers.XContentTypeOptions = "nosniff";
        if (!context.Request.IsHttps) return Results.StatusCode(403);
        if (!HttpMethods.IsGet(context.Request.Method)) return Results.StatusCode(405);
        var path = Prefix + "/" + network + "/" + policy + "/" + role + "/" + generation;
        var rawTarget = context.Features.Get<IHttpRequestFeature>()?.RawTarget;
        if (context.Request.QueryString.HasValue || context.Request.Path.Value != path ||
            rawTarget != path || !ValidHex(network, 32) || !ValidHex(policy, 64) ||
            role is not ("1" or "2") || context.Request.ContentLength is > 0 ||
            context.Request.ContentType is not null || context.Request.Headers.ContentEncoding.Count != 0 ||
            context.Request.Headers.TransferEncoding.Count != 0 ||
            context.Request.Headers.Accept.Count != 1 || context.Request.Headers.Accept[0] != MediaType)
            return Results.BadRequest();
        ulong? step = null;
        if (generation != "latest")
        {
            if (!ulong.TryParse(generation, NumberStyles.None, CultureInfo.InvariantCulture, out var value) ||
                value is 0 or > 1_048_576 || value.ToString(CultureInfo.InvariantCulture) != generation)
                return Results.BadRequest();
            step = value;
        }
        if (!admission.TryEnter()) return Results.StatusCode(429);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(context.RequestAborted);
        deadline.CancelAfter(TimeSpan.FromSeconds(5));
        try
        {
            if (await context.Request.Body.ReadAsync(new byte[1], deadline.Token).ConfigureAwait(false) != 0)
                return Results.BadRequest();
            var bytes = await authority.ReadForDistributionAsync(Convert.FromHexString(network), Convert.FromHexString(policy),
                role == "1" ? MailboxCapabilityDomain.Deposit : MailboxCapabilityDomain.Retrieve, step, deadline.Token).ConfigureAwait(false);
            deadline.Token.ThrowIfCancellationRequested();
            context.Response.ContentType = MediaType; context.Response.ContentLength = bytes.Length;
            await context.Response.Body.WriteAsync(bytes, deadline.Token).ConfigureAwait(false);
            return Results.Empty;
        }
        catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested) { throw; }
        catch (Exception error) when (!context.Response.HasStarted && error is IOException or InvalidDataException or CryptographicException or
            InvalidOperationException or UnauthorizedAccessException or ArgumentException or FormatException or OverflowException or
            OnionBoundaryException or Npgsql.NpgsqlException or OperationCanceledException or TimeoutException)
        { return Results.StatusCode(503); }
        finally { admission.Exit(); }
    }
    private static bool ValidHex(string value, int width) => value.Length == width &&
        value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f') && value.Any(c => c != '0');
}
#endif
