#if DEEP_PROTOCOL_DIRECTORY_V1
using System.Security.Cryptography;
using System.Net;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.XPointNetworkV1;
using Deep.Registry.Api.DirectoryPublication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using Sodium;

namespace Deep.Registry.Api.Tests;

// Reuses the real Registry DID2 admission/ADA2/floor/witness/network ceremony.
// The early-return mailbox fact is separate; the three route cases retain
// every original assertion. No replacement source/host capability constructor.
public sealed partial class DeepIdV2RouteThresholdIssuerTests
{
    [Fact]
    public Task ActualMailboxRenewalRecoversExactIntentAndRetainedCumulativeWinners() =>
        ExerciseRegistryCeremonyAsync(crashMode: 0, mailboxLifecycle: true);

    private static async Task ExerciseMailboxLifecycleAsync(DeepIdV2DurableGenesisAuthority admission, DeepIdV2DirectoryProofIssuer proofs,
        DeepIdV2XPointAuthoritySource roots, XPointNetworkClosureDistribution distribution, Clock clock,
        NpgsqlConnection db, string scoped, byte[] network, ReadOnlyMemory<byte> observer,
        ReadOnlyMemory<byte> exactPma, string bundlePath, string directory)
    {
        await using (var ddl = new NpgsqlCommand(await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory,
            "Fixtures", "mailbox-revocation-journal.sql")), db)) await ddl.ExecuteNonQueryAsync();
        var pma = ContactCodec.Decode("PMA2", exactPma.Span);
        var reference = new byte[] { (byte)'P', (byte)'M', (byte)'A', (byte)'2', 0, 1 }.Concat(pma.CoreHash.ToArray()).ToArray();
        using var custody = new MailboxTestCustody();
        foreach (var role in new[] { MailboxCapabilityDomain.Deposit, MailboxCapabilityDomain.Retrieve })
        {
            await using var provision = new NpgsqlCommand("INSERT INTO deep_mailbox_revocation_scope VALUES ($1,$2,$3,$4,0,0,80,$5)", db);
            foreach (var value in new object[] { network, reference, (short)role, custody.For(role).Ed25519PublicKey.ToArray(), Array.Empty<byte>() })
                provision.Parameters.Add(new() { Value = value });
            await provision.ExecuteNonQueryAsync();
        }
        var contexts = new DeepIdV2MailboxAuthorityContextSource(proofs, roots, distribution, clock, DeepIdV2Codec.DecodeDid2(observer.Span));
        var authority = new MailboxRevocationAuthority(contexts, custody, scoped, network);
        await Assert.ThrowsAsync<IOException>(() => authority.RequireReadyAsync(default).AsTask());
        custody.Deposit.BeforeSign = (_, _) => throw new IOException("Interrupted role custody after reservation.");
        await Assert.ThrowsAsync<IOException>(() => authority.RefreshAsync(default).AsTask());
        var intent = Assert.Single(custody.Deposit.Inputs); Assert.Empty(custody.Retrieve.Inputs);
        await Assert.ThrowsAsync<IOException>(() => authority.RequireReadyAsync(default).AsTask());
        custody.Deposit.BeforeSign = null;
        // Old reserved genesis expired; complete current root/PMA2/PMT2 still valid.
        clock.UnixTime = 1_410; clock.Sample = 410;
        var reopened = new MailboxRevocationAuthority(contexts, custody, scoped, network);
        var builder = WebApplication.CreateBuilder(); builder.WebHost.UseTestServer();
        builder.Services.AddSingleton(admission); builder.Services.AddSingleton(proofs); builder.Services.AddSingleton(reopened);
        builder.Services.AddSingleton<IDeepIdV2GenesisAuthority>(admission);
        builder.Services.AddSingleton<DeepIdV2IssuanceAdmissionGate>();
        await using var app = builder.Build();
        app.MapDeepIdV2DirectoryAuthorityEndpoint(new(Enabled: true, ProofEnabled: true)); await app.StartAsync();
        using var http = app.GetTestClient();
        async Task RequireHttpReadinessAsync(bool ready)
        {
            using var response = await http.GetAsync(DeepIdV2DirectoryAuthorityHostingExtensions.ReadinessEndpointPath);
            Assert.Equal(ready ? HttpStatusCode.OK : HttpStatusCode.ServiceUnavailable, response.StatusCode);
        }
        await RequireHttpReadinessAsync(false); // Cold context is not authority.
        await reopened.RefreshAsync(default);
        Assert.Equal(3, custody.Deposit.Inputs.Count); Assert.Equal(intent, custody.Deposit.Inputs[1]);
        Assert.Single(custody.Retrieve.Inputs);
        var historical = await reopened.ReadRetainedAsync(MailboxCapabilityDomain.Deposit, 1, default);
        Assert.Equal(intent, MailboxGrantRevocationV1Codec.Decode(historical.Span).SignatureInput.ToArray());
        var deposit = await reopened.ReadRetainedAsync(MailboxCapabilityDomain.Deposit, 2, default);
        var retrieve = await reopened.ReadRetainedAsync(MailboxCapabilityDomain.Retrieve, 1, default);
        await contexts.WithCurrentAsync(async (context, ct) =>
        {
            await Assert.ThrowsAsync<CryptographicException>(() => MailboxGrantRevocationV1Verifier.PlanInitialEnrollmentAsync(context.Host, historical, ct).AsTask());
            _ = await MailboxGrantRevocationV1Verifier.PlanAdvanceAsync(context.Host, historical, deposit, ct);
            _ = await MailboxGrantRevocationV1Verifier.PlanInitialEnrollmentAsync(context.Host, retrieve, ct); return true;
        }, default);
        var requestsRoot = Path.Combine(directory, "proof-nonces");
        var nonceCount = Directory.EnumerateFiles(requestsRoot, "*.request", SearchOption.AllDirectories).Count();
        for (var check = 0; check < 5; check++)
        { await reopened.RequireReadyAsync(default); await RequireHttpReadinessAsync(true); }
        Assert.Equal(nonceCount, Directory.EnumerateFiles(requestsRoot, "*.request", SearchOption.AllDirectories).Count());
        Assert.Equal(3, custody.Deposit.Inputs.Count); Assert.Single(custody.Retrieve.Inputs);
        await reopened.RefreshAsync(default); // Fresh unchanged ledger: no extra generation/signature.
        Assert.Equal(3, custody.Deposit.Inputs.Count); Assert.Single(custody.Retrieve.Inputs);

        // New cumulative revocation plus a source change during signing: exact
        // intent survives, but changed authority cannot release/commit a winner.
        var frame = await File.ReadAllBytesAsync(bundlePath);
        custody.Deposit.BeforeSign = async (_, ct) =>
        { var changed = frame.ToArray(); changed[^1] ^= 1; await File.WriteAllBytesAsync(bundlePath, changed, ct); };
        await contexts.WithCurrentAsync(async (context, ct) =>
        {
            var current = await context.ReadIntervalAsync(ct);
            using var journal = new MailboxRevocationJournal(scoped, network, reference, MailboxCapabilityDomain.Deposit,
                custody.Deposit.Ed25519PublicKey.Span);
            await Assert.ThrowsAsync<CryptographicException>(() => journal.GetOrIssueNextAsync(context.Host,
                [Bytes(16, 0x51)], context.GuardSigner(custody.Resolve(current.Policy, MailboxCapabilityDomain.Deposit)), ct).AsTask());
            // Restore the same valid test-owned bundle, not a new authority.
            await File.WriteAllBytesAsync(bundlePath, frame, ct); return true;
        }, default);
        var pending = custody.Deposit.Inputs[^1];
        await Assert.ThrowsAsync<IOException>(() => reopened.RequireReadyAsync(default).AsTask());
        await RequireHttpReadinessAsync(false);
        custody.Deposit.BeforeSign = null;
        await reopened.RefreshAsync(default);
        Assert.Equal(pending, custody.Deposit.Inputs[^1]);
        var revoked = MailboxGrantRevocationV1Codec.Decode((await reopened.ReadRetainedAsync(MailboxCapabilityDomain.Deposit, 3, default)).Span);
        Assert.Equal(Bytes(16, 0x51), revoked.Field(11).ToArray());
        await reopened.RequireReadyAsync(default);

        // Actual BackgroundService start/observe/stop, not a fake renewal loop.
        var requestsBeforeWorker = Directory.EnumerateFiles(requestsRoot, "*.request", SearchOption.AllDirectories).Count();
        using (var worker = new MailboxRevocationRenewalWorker(reopened, NullLogger<MailboxRevocationRenewalWorker>.Instance))
        {
            await worker.StartAsync(default);
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            while (Directory.EnumerateFiles(requestsRoot, "*.request", SearchOption.AllDirectories).Count() == requestsBeforeWorker)
                await Task.Delay(25, deadline.Token);
            // Wait for the same single-flight refresh to release its owner.
            while (true)
            {
                try { await reopened.RequireReadyAsync(deadline.Token); break; }
                catch (IOException) { await Task.Delay(25, deadline.Token); }
            }
            await worker.StopAsync(deadline.Token);
        }
        await Assert.ThrowsAsync<IOException>(() => reopened.RequireReadyAsync(default).AsTask());
        await RequireHttpReadinessAsync(false);
        var afterStop = custody.Deposit.Inputs.Count + custody.Retrieve.Inputs.Count;
        await Assert.ThrowsAsync<IOException>(() => reopened.RefreshAsync(default).AsTask());
        Assert.Equal(afterStop, custody.Deposit.Inputs.Count + custody.Retrieve.Inputs.Count);
        var restarted = new MailboxRevocationAuthority(contexts, custody, scoped, network);
        await restarted.RefreshAsync(default); await restarted.RequireReadyAsync(default);
        Assert.Equal(afterStop, custody.Deposit.Inputs.Count + custody.Retrieve.Inputs.Count);
        Assert.Equal(revoked.CanonicalBytes.ToArray(), (await restarted.ReadRetainedAsync(MailboxCapabilityDomain.Deposit, 3, default)).ToArray());

        await using (var corrupt = new NpgsqlCommand("UPDATE deep_mailbox_revocation_snapshot SET exact_snapshot = " +
            "set_byte(exact_snapshot, octet_length(exact_snapshot)-1, get_byte(exact_snapshot, octet_length(exact_snapshot)-1) # 1) " +
            "WHERE role = 1 AND generation = 3", db)) await corrupt.ExecuteNonQueryAsync();
        await Assert.ThrowsAsync<CryptographicException>(() => restarted.RequireReadyAsync(default).AsTask());
        await Assert.ThrowsAsync<CryptographicException>(() => restarted.RefreshAsync(default).AsTask());
        Assert.Equal(afterStop, custody.Deposit.Inputs.Count + custody.Retrieve.Inputs.Count);
    }

    private sealed class MailboxTestCustody : IDeepIdV2MailboxGrantSignerCustody, IDisposable
    {
        internal readonly MailboxTestSigner Deposit = new(0x31), Retrieve = new(0x32);
        internal MailboxTestSigner For(MailboxCapabilityDomain role) => role == MailboxCapabilityDomain.Deposit ? Deposit : Retrieve;
        public IMailboxGrantIssuerSigner Resolve(VerifiedMailboxAuthorityV2 authority, MailboxCapabilityDomain role)
        {
            var signer = For(role); Assert.Equal(authority.ResolveIssuer(role).PublicKey.ToArray(), signer.Ed25519PublicKey.ToArray()); return signer;
        }
        public void Dispose() { Deposit.Dispose(); Retrieve.Dispose(); }
    }
    private sealed class MailboxTestSigner(byte marker) : IMailboxGrantIssuerSigner, IDisposable
    {
        private readonly KeyPair key = PublicKeyAuth.GenerateKeyPair(Bytes(32, marker));
        internal readonly List<byte[]> Inputs = [];
        internal Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask>? BeforeSign;
        public ReadOnlyMemory<byte> Ed25519PublicKey => key.PublicKey.ToArray();
        public async ValueTask<ReadOnlyMemory<byte>> SignAsync(ReadOnlyMemory<byte> bytes, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested(); Inputs.Add(bytes.ToArray());
            if (BeforeSign is { } action) await action(bytes, ct); ct.ThrowIfCancellationRequested();
            return PublicKeyAuth.SignDetached(bytes.ToArray(), key.PrivateKey);
        }
        public void Dispose() => CryptographicOperations.ZeroMemory(key.PrivateKey);
    }
}
#endif
