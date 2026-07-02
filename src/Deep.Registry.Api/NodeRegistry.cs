using System.Collections.Concurrent;
using System.Globalization;
using System.Numerics;
using System.Text.Json;
using Microsoft.Extensions.Options;

namespace Deep.Registry.Api;

public sealed class NodeRegistry
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true
    };

    private readonly object _gate = new();
    private readonly ConcurrentDictionary<string, RegisteredNode> _nodes = new(StringComparer.OrdinalIgnoreCase);
    private readonly RegistryOptions _options;
    private readonly string? _statePath;
    private long _corruptedStateRecoveries;
    private ReconciliationReport? _lastReconciliationReport;
    private ReconciliationJobStatus _reconciliationJobStatus = new(null, 0, 0, 0);

    public NodeRegistry(IOptions<RegistryOptions> options)
    {
        _options = options.Value;
        _statePath = string.IsNullOrWhiteSpace(_options.StatePath)
            ? Path.Combine(AppContext.BaseDirectory, "artifacts", "registry-state.json")
            : _options.StatePath;

        LoadState();
    }

    public RegistryResult<RegisteredNode> Register(RegisterNodeRequest request)
    {
        var validationError = ValidateRegistration(request);
        if (validationError is not null)
        {
            return RegistryResult<RegisteredNode>.Fail(validationError);
        }

        var now = DateTimeOffset.UtcNow;
        var key = NormalizeKey(request.NodeId);
        var next = _nodes.AddOrUpdate(
            key,
            _ => ToRegisteredNode(request, now, now, 1, null),
            (_, existing) => ToRegisteredNode(request, existing.CreatedAt, now, existing.Revision + 1, existing));

        PersistState();

        return RegistryResult<RegisteredNode>.Ok(next);
    }

    public RegistryResult<TransportProfile> UpdateTransport(string nodeId, TransportBundle bundle)
    {
        var validationError = ValidateTransport(bundle);
        if (validationError is not null)
        {
            return RegistryResult<TransportProfile>.Fail(validationError);
        }

        var key = NormalizeKey(nodeId);
        if (!_nodes.TryGetValue(key, out var existing))
        {
            return RegistryResult<TransportProfile>.Fail("node not found");
        }

        var updated = existing with
        {
            Transport = NormalizeTransport(bundle),
            UpdatedAt = DateTimeOffset.UtcNow,
            Revision = existing.Revision + 1
        };

        _nodes[key] = updated;
        PersistState();
        return RegistryResult<TransportProfile>.Ok(ToTransportProfile(updated)!);
    }

    public RegisteredNode? GetNode(string nodeId)
    {
        return _nodes.TryGetValue(NormalizeKey(nodeId), out var node) ? node : null;
    }

    public IReadOnlyCollection<RegisteredNode> GetNodes()
    {
        return _nodes.Values.OrderBy(node => node.NodeId, StringComparer.OrdinalIgnoreCase).ToArray();
    }

    public IReadOnlyCollection<PublicNode> GetPublicNodes()
    {
        return GetNodes().Select(ToPublicNode).ToArray();
    }

    public PublicNode? GetPublicNode(string nodeId)
    {
        var node = GetNode(nodeId);
        return node is null ? null : ToPublicNode(node);
    }

    public IReadOnlyCollection<RegistryControlNode> GetControlNodes()
    {
        return GetNodes().Select(ToControlNode).ToArray();
    }

    public IReadOnlyCollection<RelayContactDocument> GetRelayContacts()
    {
        return _nodes.Values
            .Where(node => IsTransportHealthy(node.TransportStatus))
            .Select(node => node.RelayContact)
            .Where(contact => contact is not null)
            .Cast<RelayContactDocument>()
            .OrderBy(contact => contact.RouterId, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    public RegistryRuntimeStats GetRuntimeStats()
    {
        return new RegistryRuntimeStats(_nodes.Count, Interlocked.Read(ref _corruptedStateRecoveries));
    }

    public TransportProfile? GetTransportProfile(string nodeId)
    {
        var node = GetNode(nodeId);
        return node is null ? null : ToTransportProfile(node);
    }

    public StakeState? GetStakeState(string nodeId)
    {
        var node = GetNode(nodeId);
        if (node is null)
        {
            return null;
        }

        return new StakeState(
            node.NodeId,
            "XPoint",
            "XPNT",
            9,
            _options.StakingRequirementAtomic,
            node.StakeAtomic,
            node.OperatorFeeBps,
            node.OperatorAddress,
            node.RewardsAddress,
            node.Contributors,
            node.StakeAtomic >= _options.StakingRequirementAtomic ? "registered" : "awaiting-contribution");
    }

    public RegistrationRewardState GetRewards(string address)
    {
        return new RegistrationRewardState(
            NormalizeKey(address),
            "XPNT",
            9,
            0,
            0,
            0);
    }

    public RewardsStakeState? GetRewardsStakeState(string nodeId)
    {
        var stake = GetStakeState(nodeId);
        if (stake is null)
        {
            return null;
        }

        return new RewardsStakeState(nodeId, stake, GetRewards(stake.RewardsAddress));
    }

    public ReconciliationReport GetReconciliationReport()
    {
        var nodes = GetNodes();
        var issues = new List<ReconciliationIssue>();

        foreach (var node in nodes)
        {
            var contributorTotal = node.Contributors.Sum(item => item.AmountAtomic);
            if (contributorTotal != node.StakeAtomic)
            {
                issues.Add(new ReconciliationIssue(
                    node.NodeId,
                    "stake-contributor-mismatch",
                    $"Contributor total {contributorTotal} does not match stakeAtomic {node.StakeAtomic}."));
            }

            if (node.StakeAtomic < _options.StakingRequirementAtomic)
            {
                issues.Add(new ReconciliationIssue(
                    node.NodeId,
                    "stake-below-requirement",
                    $"Stake {node.StakeAtomic} is below requirement {_options.StakingRequirementAtomic}."));
            }

            if (node.Transport is null)
            {
                issues.Add(new ReconciliationIssue(
                    node.NodeId,
                    "transport-missing",
                    "Transport profile is not configured."));
            }

            if (node.TransportStatus is null)
            {
                issues.Add(new ReconciliationIssue(
                    node.NodeId,
                    "transport-status-missing",
                    "Transport runtime heartbeat status is not published."));
            }
            else
            {
                if (node.TransportStatus.Mocked)
                {
                    issues.Add(new ReconciliationIssue(
                        node.NodeId,
                        "transport-mocked",
                        "Transport runtime is using a mocked process."));
                }

                if (node.TransportStatus.Enabled && !node.TransportStatus.Running)
                {
                    issues.Add(new ReconciliationIssue(
                        node.NodeId,
                        "transport-not-running",
                        $"Transport runtime is enabled but not running (mode: {node.TransportStatus.Mode})."));
                }

                if (node.TransportStatus.Degraded)
                {
                    issues.Add(new ReconciliationIssue(
                        node.NodeId,
                        "transport-degraded",
                        $"Transport runtime is degraded after {node.TransportStatus.ConsecutiveFailures} consecutive failure(s)."));
                }
            }

            if (string.IsNullOrWhiteSpace(node.SigningEndpoint))
            {
                issues.Add(new ReconciliationIssue(
                    node.NodeId,
                    "signing-endpoint-missing",
                    "BLS quorum signing endpoint is not configured."));
            }
        }

        return new ReconciliationReport(DateTimeOffset.UtcNow, nodes.Count, issues);
    }

    public ReconciliationReport RunReconciliationJob()
    {
        var report = GetReconciliationReport();

        lock (_gate)
        {
            _lastReconciliationReport = report;
            _reconciliationJobStatus = _reconciliationJobStatus with
            {
                LastRunAt = report.GeneratedAt,
                LastTotalNodes = report.TotalNodes,
                LastIssueCount = report.Issues.Count,
                Runs = _reconciliationJobStatus.Runs + 1
            };
        }

        return report;
    }

    public ReconciliationJobStatus GetReconciliationJobStatus()
    {
        lock (_gate)
        {
            return _reconciliationJobStatus;
        }
    }

    public ReconciliationReport? GetLastReconciliationReport()
    {
        lock (_gate)
        {
            return _lastReconciliationReport;
        }
    }

    private static RegisteredNode ToRegisteredNode(
        RegisterNodeRequest request,
        DateTimeOffset createdAt,
        DateTimeOffset updatedAt,
        long revision,
        RegisteredNode? existing)
    {
        var contributors = request.Contributors.Count > 0
            ? request.Contributors
            : new[]
            {
                new ContributorStake
                {
                    Address = request.OperatorAddress,
                    Beneficiary = string.IsNullOrWhiteSpace(request.RewardsAddress) ? request.OperatorAddress : request.RewardsAddress,
                    AmountAtomic = request.StakeAtomic
                }
            };
        var transportStatus = request.TransportStatus is null ? null : NormalizeTransportStatus(request.TransportStatus);
        var transportHealthy = IsTransportHealthy(transportStatus);
        var existingTransportHealthy = IsTransportHealthy(existing?.TransportStatus);

        return new RegisteredNode
        {
            NodeId = NormalizeKey(request.NodeId),
            OperatorAddress = request.OperatorAddress,
            RewardsAddress = string.IsNullOrWhiteSpace(request.RewardsAddress) ? request.OperatorAddress : request.RewardsAddress,
            BlsPublicKey = NormalizeBlsPublicKey(request.BlsPublicKey),
            BlsSignature = NormalizeHex(request.BlsSignature, 256),
            Ed25519PublicKey = request.Ed25519PublicKey,
            Ed25519Signature1 = request.Ed25519Signature1,
            Ed25519Signature2 = request.Ed25519Signature2,
            OperatorFeeBps = request.OperatorFeeBps,
            StakeAtomic = request.StakeAtomic,
            Contributors = contributors.ToArray(),
            Transport = request.Transport is null ? null : NormalizeTransport(request.Transport),
            TransportStatus = transportStatus,
            TransportHealthySince = transportHealthy
                ? existingTransportHealthy ? existing?.TransportHealthySince ?? updatedAt : updatedAt
                : null,
            TransportUnhealthySince = transportHealthy
                ? null
                : existingTransportHealthy ? updatedAt : existing?.TransportUnhealthySince ?? updatedAt,
            SigningEndpoint = NormalizeSigningEndpoint(request.SigningEndpoint),
            RelayContact = request.RelayContact is null ? null : NormalizeRelayContact(request.RelayContact),
            CreatedAt = createdAt,
            UpdatedAt = updatedAt,
            Revision = revision
        };
    }

    private static TransportProfile? ToTransportProfile(RegisteredNode node)
    {
        if (node.Transport is null)
        {
            return null;
        }

        var bundle = node.Transport;
        return new TransportProfile(
            node.NodeId,
            bundle.Protocol,
            $"{bundle.Host}:{bundle.Port}",
            bundle,
            node.UpdatedAt);
    }

    private static string? ValidateRegistration(RegisterNodeRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.NodeId))
        {
            return "nodeId is required";
        }

        if (string.IsNullOrWhiteSpace(request.OperatorAddress))
        {
            return "operatorAddress is required";
        }

        if (request.OperatorFeeBps is < 0 or > 10_000)
        {
            return "operatorFeeBps must be between 0 and 10000";
        }

        if (request.StakeAtomic < 0)
        {
            return "stakeAtomic cannot be negative";
        }

        var blsError = ValidateBlsPublicKey(request.BlsPublicKey);
        if (blsError is not null)
        {
            return blsError;
        }

        if (!string.IsNullOrWhiteSpace(request.BlsSignature)
            && !IsFixedHex(request.BlsSignature, 256))
        {
            return "blsSignature must be a 256-byte hex value";
        }

        var transportError = request.Transport is null ? null : ValidateTransport(request.Transport);
        if (transportError is not null)
        {
            return transportError;
        }

        var transportStatusError = request.TransportStatus is null ? null : ValidateTransportStatus(request.TransportStatus);
        if (transportStatusError is not null)
        {
            return transportStatusError;
        }

        var relayContactError = request.RelayContact is null
            ? null
            : ValidateRelayContact(request.NodeId, request.RelayContact);
        if (relayContactError is not null)
        {
            return relayContactError;
        }

        return ValidateSigningEndpoint(request.SigningEndpoint);
    }

    private static string? ValidateBlsPublicKey(BlsPublicKey key)
    {
        if (!string.IsNullOrWhiteSpace(key.Data))
        {
            return IsFixedHex(key.Data, 128)
                ? null
                : "blsPublicKey.data must be a 128-byte hex value";
        }

        if (string.IsNullOrWhiteSpace(key.X) || string.IsNullOrWhiteSpace(key.Y))
        {
            return "blsPublicKey.data or blsPublicKey.x/y are required";
        }

        if (!IsUint256(key.X) || !IsUint256(key.Y))
        {
            return "blsPublicKey.x and blsPublicKey.y must be uint256 hex or decimal values";
        }

        return null;
    }

    private static BlsPublicKey NormalizeBlsPublicKey(BlsPublicKey key)
    {
        if (!string.IsNullOrWhiteSpace(key.Data))
        {
            return key with { Data = NormalizeHex(key.Data, 128), X = "", Y = "" };
        }

        var x = FormatUint256Hex(key.X);
        var y = FormatUint256Hex(key.Y);
        return new BlsPublicKey
        {
            Data = x.PadLeft(128, '0') + y.PadLeft(128, '0'),
            X = x,
            Y = y
        };
    }

    private static string? ValidateTransport(TransportBundle bundle)
    {
        if (!string.Equals(bundle.Protocol, "vless", StringComparison.OrdinalIgnoreCase))
        {
            return "only vless transport bundles are supported";
        }

        if (string.IsNullOrWhiteSpace(bundle.Host))
        {
            return "transport host is required";
        }

        if (bundle.Port is <= 0 or > 65_535)
        {
            return "transport port must be between 1 and 65535";
        }

        if (string.IsNullOrWhiteSpace(bundle.Uuid))
        {
            return "transport uuid is required";
        }

        return null;
    }

    private static TransportBundle NormalizeTransport(TransportBundle bundle)
    {
        return bundle with { Protocol = "vless" };
    }

    private static string? ValidateTransportStatus(TransportStatus status)
    {
        if (status.RestartCount < 0)
        {
            return "transportStatus.restartCount cannot be negative";
        }

        if (status.ConsecutiveFailures < 0)
        {
            return "transportStatus.consecutiveFailures cannot be negative";
        }

        return null;
    }

    private static TransportStatus NormalizeTransportStatus(TransportStatus status)
    {
        return status with
        {
            Mode = string.IsNullOrWhiteSpace(status.Mode)
                ? (status.Enabled ? "unknown" : "disabled")
                : status.Mode.Trim().ToLowerInvariant()
        };
    }

    private static string? ValidateRelayContact(string nodeId, RelayContactDocument contact)
    {
        if (!string.Equals(NormalizeKey(nodeId), NormalizeKey(contact.RouterId), StringComparison.OrdinalIgnoreCase))
        {
            return "relayContact.routerId must match nodeId";
        }

        if (string.IsNullOrWhiteSpace(contact.PublicHost))
        {
            return "relayContact.publicHost is required";
        }

        if (contact.PublicPort is <= 0 or > 65_535)
        {
            return "relayContact.publicPort must be between 1 and 65535";
        }

        if (!IsFixedHex(contact.X25519PublicKey, 32))
        {
            return "relayContact.x25519PublicKey must be a 32-byte hex value";
        }

        if (string.IsNullOrWhiteSpace(contact.RpcEndpoint)
            || ValidateSigningEndpoint(contact.RpcEndpoint) is not null)
        {
            return "relayContact.rpcEndpoint must be an absolute http(s) URL";
        }

        if (contact.ExpiresAt <= contact.SignedAt)
        {
            return "relayContact.expiresAt must be later than signedAt";
        }

        if (!string.Equals(contact.SignatureAlgorithm, "ed25519", StringComparison.OrdinalIgnoreCase))
        {
            return "relayContact.signatureAlgorithm must be ed25519";
        }

        if (!IsFixedHex(contact.Signature, 64))
        {
            return "relayContact.signature must be a 64-byte hex value";
        }

        if (!RelayContactDocumentVerifier.Verify(contact, DateTimeOffset.UtcNow))
        {
            return "relayContact signature is invalid or expired";
        }

        return null;
    }

    private static RelayContactDocument NormalizeRelayContact(RelayContactDocument contact)
    {
        return contact with
        {
            RouterId = NormalizeKey(contact.RouterId),
            PublicHost = contact.PublicHost.Trim(),
            PublicIp = string.IsNullOrWhiteSpace(contact.PublicIp) ? null : contact.PublicIp.Trim(),
            X25519PublicKey = NormalizeHex(contact.X25519PublicKey, 32),
            RpcEndpoint = NormalizeSigningEndpoint(contact.RpcEndpoint),
            SignatureAlgorithm = "ed25519",
            Signature = NormalizeHex(contact.Signature, 64),
            Capabilities = contact.Capabilities
                .Where(static value => !string.IsNullOrWhiteSpace(value))
                .Select(static value => value.Trim())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Order(StringComparer.OrdinalIgnoreCase)
                .ToArray()
        };
    }

    private static PublicNode ToPublicNode(RegisteredNode node)
    {
        return new PublicNode
        {
            NodeId = node.NodeId,
            OperatorAddress = node.OperatorAddress,
            RewardsAddress = node.RewardsAddress,
            BlsPublicKey = node.BlsPublicKey,
            Ed25519PublicKey = node.Ed25519PublicKey,
            OperatorFeeBps = node.OperatorFeeBps,
            StakeAtomic = node.StakeAtomic,
            Contributors = node.Contributors,
            TransportStatus = node.TransportStatus,
            TransportHealthySince = node.TransportHealthySince,
            TransportUnhealthySince = node.TransportUnhealthySince,
            CreatedAt = node.CreatedAt,
            UpdatedAt = node.UpdatedAt,
            Revision = node.Revision
        };
    }

    private static RegistryControlNode ToControlNode(RegisteredNode node)
    {
        return new RegistryControlNode
        {
            NodeId = node.NodeId,
            OperatorAddress = node.OperatorAddress,
            RewardsAddress = node.RewardsAddress,
            BlsPublicKey = node.BlsPublicKey,
            BlsSignature = node.BlsSignature,
            Ed25519PublicKey = node.Ed25519PublicKey,
            Ed25519Signature1 = node.Ed25519Signature1,
            Ed25519Signature2 = node.Ed25519Signature2,
            SigningEndpoint = node.SigningEndpoint,
            Contributors = node.Contributors,
            TransportStatus = node.TransportStatus,
            TransportHealthySince = node.TransportHealthySince,
            TransportUnhealthySince = node.TransportUnhealthySince,
            UpdatedAt = node.UpdatedAt
        };
    }

    private static bool IsTransportHealthy(TransportStatus? status)
    {
        return status is { Enabled: true, Running: true, Degraded: false, Mocked: false };
    }

    private static string? ValidateSigningEndpoint(string? endpoint)
    {
        if (string.IsNullOrWhiteSpace(endpoint))
        {
            return null;
        }

        return Uri.TryCreate(endpoint.Trim(), UriKind.Absolute, out var uri)
               && (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps)
            ? null
            : "signingEndpoint must be an absolute http(s) URL";
    }

    private static string NormalizeSigningEndpoint(string? endpoint)
    {
        if (string.IsNullOrWhiteSpace(endpoint))
        {
            return "";
        }

        return endpoint.Trim().TrimEnd('/');
    }

    private void LoadState()
    {
        if (_statePath is null || !File.Exists(_statePath))
        {
            return;
        }

        try
        {
            var json = File.ReadAllText(_statePath);
            var snapshot = JsonSerializer.Deserialize<RegistrySnapshot>(json, SerializerOptions);
            if (snapshot?.Nodes is null)
            {
                RecoverCorruptedStateFile();
                return;
            }

            foreach (var node in snapshot.Nodes)
            {
                _nodes[node.NodeId] = node;
            }
        }
        catch (JsonException)
        {
            RecoverCorruptedStateFile();
        }
        catch (IOException)
        {
            RecoverCorruptedStateFile();
        }
    }

    private void RecoverCorruptedStateFile()
    {
        if (_statePath is null || !File.Exists(_statePath))
        {
            return;
        }

        try
        {
            var backupPath = $"{_statePath}.corrupt-{DateTimeOffset.UtcNow:yyyyMMddHHmmssfff}.bak";
            File.Move(_statePath, backupPath, true);
            Interlocked.Increment(ref _corruptedStateRecoveries);
        }
        catch
        {
            // Best effort: startup should continue even if recovery backup fails.
        }
    }

    private void PersistState()
    {
        if (_statePath is null)
        {
            return;
        }

        lock (_gate)
        {
            var directory = Path.GetDirectoryName(_statePath);
            if (!string.IsNullOrWhiteSpace(directory))
            {
                Directory.CreateDirectory(directory);
            }

            var snapshot = new RegistrySnapshot(GetNodes());
            File.WriteAllText(_statePath, JsonSerializer.Serialize(snapshot, SerializerOptions));
        }
    }

    private static string NormalizeKey(string value)
    {
        return value.Trim().ToLowerInvariant();
    }

    private static string NormalizeHex(string value, int expectedBytes)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "";
        }

        var normalized = value.Trim();
        if (normalized.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            normalized = normalized[2..];
        }

        return normalized.Length == expectedBytes * 2 && normalized.All(Uri.IsHexDigit)
            ? normalized.ToLowerInvariant()
            : normalized.ToLowerInvariant();
    }

    private static bool IsFixedHex(string value, int expectedBytes)
    {
        var normalized = value.Trim();
        if (normalized.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            normalized = normalized[2..];
        }

        return normalized.Length == expectedBytes * 2 && normalized.All(Uri.IsHexDigit);
    }

    private static string FormatUint256Hex(string value)
    {
        var trimmed = value.Trim();
        if (trimmed.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            return trimmed[2..].PadLeft(64, '0').ToLowerInvariant();
        }

        return BigInteger.TryParse(trimmed, NumberStyles.None, CultureInfo.InvariantCulture, out var number)
            ? number.ToString("x", CultureInfo.InvariantCulture).PadLeft(64, '0').ToLowerInvariant()
            : trimmed.ToLowerInvariant();
    }

    private static bool IsUint256(string value)
    {
        var trimmed = value.Trim();
        if (trimmed.Length == 0)
        {
            return false;
        }

        if (trimmed.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            var hex = trimmed[2..];
            return hex.Length is > 0 and <= 64 && hex.All(Uri.IsHexDigit);
        }

        return BigInteger.TryParse(trimmed, NumberStyles.None, CultureInfo.InvariantCulture, out var number)
            && number >= BigInteger.Zero
            && number < (BigInteger.One << 256);
    }

    private sealed record RegistrySnapshot(IReadOnlyCollection<RegisteredNode> Nodes);
}
