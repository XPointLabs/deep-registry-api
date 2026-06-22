# Agent Specification - Deep Registry API

Last updated: 2026-06-10.

## Mission

`deep-registry-api` owns a cache of Deep node registration state, transport metadata, staking projection lookup, reconciliation status, and client/router-facing registry APIs.

It is the registry bridge between new XNode transport metadata and Session-style service-node availability semantics.

## Source Of Truth

- Workspace entry point: `../prompts/00_Agent_Entry_Point.md`.
- Porting rules: `docs/SESSION_PORTING.md`.
- Router heartbeat payloads: `../xnode/AGENTS.md`.
- Staking projection backend: `../xpoint-staking-backend/AGENTS.md`.
- DevOps registry recovery drill: `../deep-devops/AGENTS.md`.

## Ownership Boundaries

Owned here:

- node registration cache API,
- transport profile storage,
- stake/reward projection API surface,
- registry snapshot persistence and corruption quarantine,
- reconciliation worker/status,
- static admin demo only as a diagnostic aid.

Not owned here:

- contract event indexing,
- contract reward/stake rules,
- chain-active service-node membership authority,
- router path selection,
- client UI behavior.

## New Deep Solution Rules

Registry changes must preserve:

- deterministic state snapshot behavior,
- explicit runtime counters,
- graceful corrupted-state recovery with diagnostics,
- compatibility with router heartbeat payloads,
- clear readiness semantics for DevOps gates.

Transport metadata may include Deep-specific fields, but clients must be able to distinguish missing/unsupported fields from valid disabled features.

## Session Compatibility Rules

Preserve Session-visible service-node concepts:

- node identity and registration lifecycle,
- stake requirement and stake state projection,
- reward address projection,
- transport profile lookup for client bootstrap.

Do not move staking rules into registry. Registry consumes staking projections.

Do not add registry mutation/remediation endpoints that rewrite contributors, operator addresses, transport bundles, signing endpoints, or stake values. Those values must come from chain/indexer state or signed node heartbeats/manifests.

## Required Verification

```powershell
dotnet test Deep.Registry.Api.slnx
```

For recovery/reconciliation changes, also run the DevOps registry recovery drill or the release evidence workflow equivalent.

## Acceptance Gates

A registry change is complete only when:

- API tests cover status codes and state changes,
- runtime counters expose new operational states,
- snapshot persistence and corruption behavior remain tested,
- router/staking/e2e consumers are updated for payload changes,
- docs list any new endpoint/config key.

## Stop-The-Line Conditions

- Corrupted state can crash startup without quarantine or diagnostic.
- Registry returns healthy while reconciliation is failing silently.
- Stake requirement defaults diverge from configured contract deployment.
- Transport profile payload changes without router/client coverage.
- Node registration can bypass required identity/stake checks.
- Registry can centrally rewrite node state instead of reporting divergence.

## Agent Workflow

1. Read this file and `docs/SESSION_PORTING.md`.
2. Inspect `RegistryApiTests.cs` and current endpoint behavior.
3. Add tests for new registration/projection/recovery behavior.
4. Run solution tests.
5. Update README/docs and DevOps evidence requirements if endpoints/artifacts change.
