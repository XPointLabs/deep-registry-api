# Deep Registry API agent rules

The workspace rules in `../AGENTS.md` apply. This file contains only registry-specific deltas.

## Owns

- Authenticated node registration, membership projections and byte-identical
  signed network/directory/carrier/media catalog distribution.
- Witness coordination and deterministic publication; no per-client route choice.
- Pre-cutover mailbox/call state only until destructive reset; target call
  signaling is ratcheted messaging and target allocation is owned by CallRelay.
- Snapshot persistence, corruption quarantine, runtime counters and readiness.

Contract event indexing belongs in `xpoint-staking-backend`; node heartbeat creation belongs in
`xnode`; deployment and coturn/ingress topology belong in `deep-devops`.

## Repository rules

- Registry reports signed/authoritative state; it must not invent or centrally rewrite node,
  stake, contributor, operator or mailbox-owner facts.
- Protocol-level signatures remain mandatory independently of TLS validation.
- Registry TLS uses its own standard trust configuration and never reads file-service TLS options.
- Do not add a target contact resolver, call inbox, ICE endpoint or call-allocation
  authority. Legacy endpoints are removal inputs, never a fallback.
- Persistence is deterministic; corrupted state is quarantined with diagnostics, never accepted.
- Readiness fails closed while reconciliation or required authority inputs are unhealthy.
- Update xnode/client/devops/e2e consumers and operator docs for payload, endpoint or config changes.

## Verify

```powershell
dotnet test Deep.Registry.Api.slnx
```

For persistence, reconciliation, call or ICE changes, also run the corresponding DevOps recovery
or physical UAT lane and retain sanitized evidence.
