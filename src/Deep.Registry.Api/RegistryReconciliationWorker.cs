using Microsoft.Extensions.Options;

namespace Deep.Registry.Api;

public sealed class RegistryReconciliationWorker : BackgroundService
{
    private readonly NodeRegistry _registry;
    private readonly IOptions<RegistryOptions> _options;
    private readonly ILogger<RegistryReconciliationWorker> _logger;

    public RegistryReconciliationWorker(
        NodeRegistry registry,
        IOptions<RegistryOptions> options,
        ILogger<RegistryReconciliationWorker> logger)
    {
        _registry = registry;
        _options = options;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_options.Value.ReconciliationJobEnabled)
        {
            _logger.LogInformation("Registry reconciliation background job is disabled by configuration.");
            return;
        }

        var intervalSeconds = Math.Max(1, _options.Value.ReconciliationIntervalSeconds);
        var interval = TimeSpan.FromSeconds(intervalSeconds);

        while (!stoppingToken.IsCancellationRequested)
        {
            var report = _registry.RunReconciliationJob();
            if (report.Issues.Count > 0)
            {
                _logger.LogWarning(
                    "Registry reconciliation found {IssueCount} issue(s) across {NodeCount} node(s).",
                    report.Issues.Count,
                    report.TotalNodes);
            }
            else
            {
                _logger.LogInformation(
                    "Registry reconciliation completed with no issues across {NodeCount} node(s).",
                    report.TotalNodes);
            }

            await Task.Delay(interval, stoppingToken);
        }
    }
}
