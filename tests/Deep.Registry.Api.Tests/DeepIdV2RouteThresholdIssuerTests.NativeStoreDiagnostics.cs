#if DEEP_PROTOCOL_DIRECTORY_V1
extern alias xnode;
using System.Diagnostics;
using System.Runtime.ExceptionServices;
using XNode.Core.Mailbox;
using Xunit.Abstractions;

namespace Deep.Registry.Api.Tests;

public sealed partial class DeepIdV2RouteThresholdIssuerTests
{
    private readonly ITestOutputHelper output;
    public DeepIdV2RouteThresholdIssuerTests(ITestOutputHelper output) => this.output = output;

    // Transparent observers of actual configured owners. Arguments, values,
    // cancellation, durability and exceptions pass through unchanged.
    private sealed class ObservedNativeSource(xnode::XNode.IDeepIdV2ContactStoreAuthoritySource inner)
        : xnode::XNode.IDeepIdV2ContactStoreAuthoritySource
    {
        private long calls, elapsed;
        internal string Summary => $"calls={Interlocked.Read(ref calls)},ms={Interlocked.Read(ref elapsed) * 1000 / Stopwatch.Frequency}";
        internal void Reset() { Interlocked.Exchange(ref calls, 0); Interlocked.Exchange(ref elapsed, 0); }
        public async ValueTask<xnode::XNode.DeepIdV2ContactStoreAuthority> ReadPublicationAuthorityAsync(CancellationToken ct)
        {
            Interlocked.Increment(ref calls); var watch = Stopwatch.StartNew();
            try { return await inner.ReadPublicationAuthorityAsync(ct); }
            finally { Interlocked.Add(ref elapsed, watch.ElapsedTicks); }
        }
    }

    private sealed class ObservedNativeDurability : IMailboxDurabilityBarrier
    {
        private readonly IMailboxDurabilityBarrier inner = new MailboxDurabilityBarrier();
        private long calls, elapsed;
        internal string Summary => $"calls={Interlocked.Read(ref calls)},ms={Interlocked.Read(ref elapsed) * 1000 / Stopwatch.Frequency}";
        internal void Reset() { Interlocked.Exchange(ref calls, 0); Interlocked.Exchange(ref elapsed, 0); }
        private void Observe(Action action)
        {
            Interlocked.Increment(ref calls); var watch = Stopwatch.StartNew();
            try { action(); } finally { Interlocked.Add(ref elapsed, watch.ElapsedTicks); }
        }
        public void FlushFileAndParentDirectory(string path) => Observe(() => inner.FlushFileAndParentDirectory(path));
        public void FlushParentDirectory(string path) => Observe(() => inner.FlushParentDirectory(path));
        public void ReplaceFile(string temporary, string final) => Observe(() => inner.ReplaceFile(temporary, final));
        public void DeleteFile(string path) => Observe(() => inner.DeleteFile(path));
        public void DeleteDirectory(string path) => Observe(() => inner.DeleteDirectory(path));
    }

    private sealed class ObservedNativeSecurity : IMailboxStorageSecurity
    {
        private readonly IMailboxStorageSecurity inner = new MailboxStorageSecurity();
        private long calls, elapsed;
        internal string Summary => $"calls={Interlocked.Read(ref calls)},ms={Interlocked.Read(ref elapsed) * 1000 / Stopwatch.Frequency}";
        internal void Reset() { Interlocked.Exchange(ref calls, 0); Interlocked.Exchange(ref elapsed, 0); }
        private void Observe(Action action)
        {
            Interlocked.Increment(ref calls); var watch = Stopwatch.StartNew();
            try { action(); } finally { Interlocked.Add(ref elapsed, watch.ElapsedTicks); }
        }
        public void SecureDirectory(string path) => Observe(() => inner.SecureDirectory(path));
        public void SecureFile(string path) => Observe(() => inner.SecureFile(path));
        public void ValidateSecureFile(string path) => Observe(() => inner.ValidateSecureFile(path));
    }

    // The ambient scope selects only this caller's async execution, not other
    // tests or Kestrel requests. Bounded code-owner/type names only: never an
    // exception message, file/URL, request, capability or identifier.
    private sealed class NativeStoreExceptions : IDisposable
    {
        private static readonly AsyncLocal<NativeStoreExceptions?> current = new();
        private readonly NativeStoreExceptions? previous;
        private readonly List<string> observations = [];
        private bool disposed;
        internal NativeStoreExceptions()
        {
            previous = current.Value; current.Value = this;
            AppDomain.CurrentDomain.FirstChanceException += Observe;
        }
        private void Observe(object? sender, FirstChanceExceptionEventArgs args)
        {
            if (!ReferenceEquals(current.Value, this)) return;
            lock (observations)
            {
                if (observations.Count == 16) return;
                var owner = new StackTrace(args.Exception, false).GetFrames()?.Select(frame => frame.GetMethod())
                    .FirstOrDefault(method => method?.DeclaringType?.Namespace?.StartsWith("XNode", StringComparison.Ordinal) == true);
                observations.Add($"{args.Exception.GetType().Name}/{args.Exception.HResult}/{owner?.DeclaringType?.Name}.{owner?.Name}");
            }
        }
        internal string Summary { get { lock (observations) return string.Join(',', observations); } }
        public void Dispose()
        {
            if (disposed) return; disposed = true;
            AppDomain.CurrentDomain.FirstChanceException -= Observe;
            current.Value = previous;
        }
    }
}
#endif
