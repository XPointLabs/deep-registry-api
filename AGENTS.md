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

Full local source qualification runs through
`../deep-devops/scripts/test-registry-postgres.ps1 -GateReferencePaths <array>`
and the root canonical runner. Pass a fresh `-GateRunDirectory` and explicitly
declared Windows skip names; the provider restores the environment and removes
only its labelled tmpfs database. Run from Windows PowerShell5.1.
`FixturePreflight=true` actually opens the loopback `deep_s00` provider and
the actual ML-DSA provider before full. Missing crypto/DB inputs fail, never skip
or return a successful-shaped default. Filtered diagnostics are not full gates.
Do not require unrelated ML-KEM activation for Registry's signing/provider lane.
