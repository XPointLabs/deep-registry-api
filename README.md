# Deep Registry API

ASP.NET Core cache/bootstrap API for Deep node registration and VLESS
transport metadata. XPoint stake/reward semantics and active node membership
remain delegated to the staking contracts/backend; this service stores
registration extension fields that are not part of the Session contracts.

## Agent Specs

- Start with [`AGENTS.md`](AGENTS.md) before changing registry lifecycle, projections, reconciliation, or API shape.
- Use [`docs/SESSION_PORTING.md`](docs/SESSION_PORTING.md) for Session service-node registration and staking projection migration rules.
- Keep staking semantics delegated to `xpoint-staking-backend` and contracts.
- Keep remediation out of registry: divergence is reported through reconciliation endpoints, not centrally fixed here.

## Endpoints

- `POST /api/nodes/register`
- `PUT /api/nodes/{nodeId}/transport`
- `GET /api/nodes/{nodeId}/stake-state`
- `GET /api/nodes/{nodeId}/rewards-stake-state`
- `GET /api/rewards/{address}`
- `GET /api/nodes/{nodeId}`
- `GET /api/nodes` (public node status; transport credentials, registration proofs, and signer endpoints are omitted)
- `GET /api/internal/nodes` (Docker control-plane catalog; never expose through the public reverse proxy)
- `GET /api/relay-contacts` (registered-node Ed25519 authentication required)
- `GET /api/nodes/runtime`
- `GET /api/nodes/reconciliation`
- `GET /api/nodes/reconciliation/projections`
- `GET /api/v1/checkpoints/status`
- `GET /api/v1/checkpoints/bridge` (dormant P04 signed bytes; returns `503`
  unless the fixture projection is explicitly enabled and current)
- `GET /health/ready`

The static admin demo is served at `/`.

## Dormant P04 checkpoint projection

P06 is a default-disabled fixture projection. It is separate from
`NodeRegistry`; registered nodes, staking state and relay self-signatures are
never treated as P04 membership authority.

The application assembly contains no P04 signature implementation. Local tests
inject a deterministic verifier from the test assembly. Production activation
is blocked until the signature profile, trusted genesis, authority/mirror
ownership, live artifact source and external review are approved.

Configuration:

```json
{
  "MembershipProjection": {
    "Enabled": false,
    "ContractIdentifier": "Deep.Protocol/P04-canonical-v1",
    "PackageVersion": "0.3.0-p04.b887fa0",
    "StatePath": "artifacts/membership-projection-state.json",
    "ExpectedNetworkIdHex": "",
    "ExpectedGenesisSha256Hex": "",
    "MaximumArtifactBytes": 131072,
    "MaximumStateBytes": 524288,
    "AllowedClockSkewSeconds": 30,
    "ClientProtocol": 2,
    "FixtureSourceWorkerEnabled": false
  }
}
```

There is no checkpoint mutation, membership or inclusion-proof endpoint.
When enabled without a verifier, exactly one external
`IMembershipProjectionMonotonicAnchor`, trusted genesis pins or a current
bridge, readiness and bridge fetch return a sanitized `503`. This repository
intentionally ships no production monotonic-anchor or signature-verifier
implementation, so configuration alone cannot activate the projection. The
only accepted local package status is `fixture-go-runtime-blocked`.

Checkpoint state is read with the exact configured size ceiling before
deserialization, and invalid/hard-cap-exceeding limits prevent any persisted
read. Updates run under an interprocess file lease with bounded retry. A busy
lease or typed transient anchor failure reports a bounded non-ready state and
is revalidated on the next operation; it is not promoted to a permanent
rollback conflict.

Each durable generation is bound to the external monotonic anchor. A missing
file, stale generation or changed hash stops publication without quarantining
rollback evidence. The anchor also carries an irreversible terminal-unsafe
fork poison. Before attempting that anchor update, the service tries to
atomically write an independent compact terminal marker containing the
verified evidence hash, domain and sequence. The marker is checked before
every state load/read, so a detected fork remains non-servable after restart
even when every poison CAS attempt is pre-commit or ambiguous and writing the
detailed main state fails.

The compact marker and external terminal CAS are independent durable sinks:
failure or overflow in one does not suppress the other attempt. Full signed
candidate evidence is written separately on a best-effort basis and remains
bounded; detailed main-state persistence is attempted only after terminal
durability is established.
Once a terminal journal is present, startup does not read or interpret a
prepared transition; malformed or oversized lower-priority state cannot mask
the terminal `fork-detected` condition.

Normal state changes use a separate prepared-transition journal before the
N+1 state file is replaced. After CAS, the service rereads the anchor: the exact
intended N+1 value is success, the exact expected N value is retried or remains
transient, and any third value is a conflict. Startup and later operations
reconcile the same journal, including commit-then-throw outcomes. Stateful
`Apply` calls perform this recovery directly; callers do not need to probe a
status/read endpoint first.

Structurally or cryptographically corrupt state is quarantined. Its lifetime
recovery counter does not disable future continuity checks, and a
human-authorized reset/reseed can establish fresh state.

Authority changes immediately stop an older bridge until a bridge bound to the
current delegation is accepted. Valid fork candidates and their canonical
evidence are retained, and a fork latch cannot be cleared by changing only the
state boolean.

Successful bridge responses use `private, no-store, max-age=0,
must-revalidate` and support wildcard, list and weak `If-None-Match`
comparison. Status exposes bridge freshness and bounded counters, but no
membership sequence/hash or topology.

State persistence behavior:

- Registry snapshot is stored at `Registry:StatePath` (defaults to `artifacts/registry-state.json` under app base directory).
- If the snapshot file is corrupted/invalid, startup quarantines it to `*.corrupt-<timestamp>.bak` and continues with empty in-memory state.
- `GET /api/nodes/runtime` exposes operational counters (`totalNodes`, `corruptedStateRecoveries`).

## Recovery (devnet/non-production)

1. Stop registry API.
2. Move or delete the current `Registry:StatePath` snapshot.
3. Start registry API.
4. Replay node registration and transport updates through `/api/nodes/register` and `/api/nodes/{nodeId}/transport`.
5. Verify `/api/nodes/runtime`, `/api/nodes`, and `/api/nodes/reconciliation`.

Do not repair production divergence by editing registry state. Re-submit signed
node heartbeat/contact data or fix the staking/indexer source of truth, then let
registry refresh its cache.

Run locally:

```bash
Registry__StakingRequirementAtomic=25000000000000 \
dotnet run --project src/Deep.Registry.Api
dotnet test
```

Use `Registry__StakingRequirementAtomic` from the contract deployment manifest
(`parameters.stakingRequirement`) for local devnet runs. Production defaults to
`25,000 XPNT` in atomic units.
