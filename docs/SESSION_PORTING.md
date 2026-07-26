# Session Porting Spec - Registry API

Last updated: 2026-06-10.

## Scope

This document defines how Session service-node registration and staking availability semantics map into the Deep registry API.

## Porting Model

Deep separates responsibilities:

- router publishes signed transport metadata and runtime identity,
- registry caches node registration/transport profiles for bootstrap and diagnostics,
- staking backend/contracts determine stake/reward state and active node membership,
- DevOps verifies recovery and reconciliation evidence.

## Reference Sources

Use local upstream Session service-node/client references when available under `../source`. When unavailable, use router/e2e fixtures and existing registry tests as the current baseline.

## Required Semantics

- Registration must produce stable node lookup.
- Transport profile updates must be explicit and retrievable.
- Stake state endpoints must reflect staking backend projections.
- Runtime endpoint must expose enough counters for readiness gates.
- Corrupted state must be quarantined and counted.
- Reconciliation failures must be observable.
- Reconciliation is diagnostic only; registry must not mutate contributor, operator, stake, transport, or signing endpoint state as remediation.

## Accepted Deviations

- Registry stores Deep VLESS transport metadata, which is not an upstream Session transport.
- Staking is projected from XPNT contracts/backend rather than upstream OXEN runtime.
- Static admin UI is diagnostic only.
- Registry is an optional cache/bootstrap aid, not the Session network authority. Active membership comes from chain/indexer state and signed node contact manifests.
- Registry may publish an opaque, externally generated membership-route artifact, but does not
  parse, sign, synthesize or mutate it. Missing configuration fails closed. A registry response is
  not authoritative until the client quorum-verifies the P04 envelope, monotonic LKG and all MRL1
  inclusion proofs.

## Evidence Checklist

- API test for endpoint behavior,
- persistence/recovery test for stateful changes,
- router heartbeat compatibility when payloads change,
- DevOps recovery drill evidence for release-impacting changes,
- e2e client/router coverage when public response shapes change.

## Stop-The-Line Conditions

- Registry can lose all node state without backup/quarantine diagnostics.
- Runtime stats omit recovery/reconciliation counters needed by gates.
- Stake projection behavior is implemented locally instead of delegated.
- Registry exposes mutation/remediation endpoints that can override chain or signed node state.
- Transport profile response shape changes without consumer updates.
