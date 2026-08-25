# Deep Registry API agent rules

The workspace rules in `../AGENTS.md` apply. This file contains only registry-specific deltas.

## Owns

- Authenticated node registration, transport profiles and membership/catalog projections.
- Durable signed mailbox authority/control/history state and reconciliation.
- Production call signaling, inbox and signed ICE/TURN credential issuance.
- Snapshot persistence, corruption quarantine, runtime counters and readiness.

Contract event indexing belongs in `xpoint-staking-backend`; node heartbeat creation belongs in
`xnode`; deployment and coturn/ingress topology belong in `deep-devops`.

## Repository rules

- Registry reports signed/authoritative state; it must not invent or centrally rewrite node,
  stake, contributor, operator or mailbox-owner facts.
- Protocol-level signatures remain mandatory independently of TLS validation.
- Registry TLS uses its own standard trust configuration and never reads file-service TLS options.
- Call/ICE endpoints authenticate participants, bound lifetimes and replay state; TURN secrets are
  configuration inputs and never appear in responses, logs or snapshots.
- Persistence is deterministic; corrupted state is quarantined with diagnostics, never accepted.
- Readiness fails closed while reconciliation or required authority inputs are unhealthy.
- Update xnode/client/devops/e2e consumers and operator docs for payload, endpoint or config changes.

## Verify

```powershell
dotnet test Deep.Registry.Api.slnx
```

For persistence, reconciliation, call or ICE changes, also run the corresponding DevOps recovery
or physical UAT lane and retain sanitized evidence.
