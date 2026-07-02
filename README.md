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

The static admin demo is served at `/`.

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
