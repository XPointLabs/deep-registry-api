using Microsoft.Extensions.Options;

namespace Deep.Registry.Api;

public sealed class MembershipProjectionWorker : BackgroundService
{
    private readonly MembershipProjectionOptions _options;
    private readonly MembershipProjectionService _service;
    private readonly IReadOnlyList<IMembershipArtifactSource> _sources;

    public MembershipProjectionWorker(
        IOptions<MembershipProjectionOptions> options,
        MembershipProjectionService service,
        IEnumerable<IMembershipArtifactSource> sources)
    {
        _options = options.Value;
        _service = service;
        _sources = sources.ToArray();
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_options.Enabled || !_options.FixtureSourceWorkerEnabled || _sources.Count != 1)
        {
            return;
        }

        try
        {
            await _sources[0].PollAsync(_service, stoppingToken);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
        catch
        {
            _service.RecordSourceFailure();
        }
    }
}
