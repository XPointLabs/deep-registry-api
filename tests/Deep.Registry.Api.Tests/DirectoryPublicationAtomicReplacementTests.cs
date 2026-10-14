using Deep.Registry.Api.DirectoryPublication;

namespace Deep.Registry.Api.Tests;

public sealed class DirectoryPublicationAtomicReplacementTests
{
    [Fact]
    public async Task PersistentDeleteSharingBlockKeepsOldStateAndPreparedCandidate()
    {
        if (!OperatingSystem.IsWindows()) return;
        var directory = Path.Combine(Path.GetTempPath(), "deep-atomic-held-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "state");
        try
        {
            var original = new byte[] { 1, 2, 3 }; var candidate = new byte[] { 4, 5, 6 };
            await File.WriteAllBytesAsync(path, original);
            using var reader = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            var error = Record.Exception(() => DirectoryPublicationProtectedFile.WriteAtomic(path, candidate));
            Assert.NotNull(error);
            Assert.True(error is IOException or UnauthorizedAccessException);
            Assert.True((error.HResult & 0xffff) is 5 or 32 or 33);
            Assert.Equal(original, await File.ReadAllBytesAsync(path));
            Assert.Equal(candidate, await File.ReadAllBytesAsync(path + ".writing"));
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    [Fact]
    public async Task ActualDeleteSharingBlockReleasesWithoutChangingPreparedBytes()
    {
        if (!OperatingSystem.IsWindows()) return;
        var directory = Path.Combine(Path.GetTempPath(), "deep-atomic-share-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "state");
        try
        {
            var original = new byte[] { 1, 2, 3 }; var candidate = new byte[] { 4, 5, 6 };
            await File.WriteAllBytesAsync(path, original);
            using var reader = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            var write = Task.Run(() => DirectoryPublicationProtectedFile.WriteAtomic(path, candidate));
            using var budget = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            while (!File.Exists(path + ".writing")) await Task.Delay(5, budget.Token);
            await Task.Delay(100, budget.Token);
            Assert.False(write.IsCompleted); Assert.Equal(original, await File.ReadAllBytesAsync(path));
            reader.Dispose(); await write.WaitAsync(budget.Token);
            Assert.Equal(candidate, await File.ReadAllBytesAsync(path)); Assert.False(File.Exists(path + ".writing"));
        }
        finally { Directory.Delete(directory, recursive: true); }
    }
}
