# ADR 0001: dormant P06 checkpoint projection

Status: fixture implementation; runtime blocked.

Date: 2026-07-19.

Human owner: Mr. X.

## Decision

The registry consumes the accepted
`Deep.Protocol/P04-canonical-v1` contract only through a separate,
default-disabled projection. The projection is not part of `NodeRegistry` and
does not derive authority from mutable registration, staking, relay-contact,
DNS or TLS state.

The local P06 slice:

- vendors the accepted `0.3.0-p04.b887fa0` packages with exact SHA-256 pins and
  locked restore;
- accepts only bounded raw canonical fixture bytes through an internal service;
- requires exactly one injected `IMembershipSignatureVerifier`;
- ships no verifier implementation or test key in the application assembly;
- persists exact accepted envelopes with same-directory flush/replace before
  publishing memory;
- requires exactly one external monotonic generation/hash anchor and ships no
  production implementation;
- serializes transitions with an interprocess file lease and rejects a whole
  file rollback before serving;
- quarantines corrupt state and fails readiness;
- keeps independent authority, bridge and membership LKG chains;
- exposes only the exact signed public bridge envelope;
- contains no checkpoint mutation endpoint or live source adapter.

The application stays usable when the feature is disabled. When it is enabled
without trusted state or a verifier, `/health/ready` and the public bridge
endpoint fail closed.

## Domain LKG interpretation

P04 defines distinct signature domains and domain-specific fork-evidence
builders. This consumer therefore keeps:

1. an authority delegation/revocation LKG;
2. a bridge-snapshot LKG;
3. a membership-commitment LKG.

A hash from one content domain can never advance the other. This is a
provisional consumer decision, not production protocol approval. The P04
owner must confirm it before runtime activation.

## Persistence and fork behavior

Every transition verifies against the expected predecessor while holding a
single-process gate and an interprocess file lease. Durable state is flushed
and atomically replaced before an external generation/hash anchor is advanced
with compare/exchange and before the in-memory reference changes. An anchor
mismatch, missing file behind a non-empty anchor, stale generation or changed
file hash permanently stops publication for that service instance. Rollback
evidence is not quarantined as corruption.

Lease contention and typed transient external-anchor errors are distinct from
rollback conflicts. They use a bounded retry, report sanitized non-ready state,
and revalidate on later reads or transitions. Stateful transitions invoke that
recovery directly, without requiring a separate status/read request. A
successful revalidation clears only the transient condition. Invalid configured
limits are rejected before any persisted read.

Before replacing a normal N+1 state file, P06 writes an atomic local prepared
transition containing the exact expected and intended anchors. CAS completion
always rereads the external anchor. Exact intended N+1 means success, exact
expected N means retry/transient, and a third value means conflict. The same
rules reconcile pre-commit failure and commit-then-throw during startup or a
later operation. A failed main-state write rolls back a prepared record only
when both the file and anchor still exactly match the expected generation.

An identical artifact is idempotent. A different valid same-sequence successor
sets an in-memory unsafe latch and atomically writes an independent local
terminal journal containing the verified fork evidence. That journal is checked
before every main/prepared state read. P06 then compare/exchanges a
terminal-unsafe poison into the external anchor before the main state write.
The journal keeps restart fail-closed even if all poison CAS attempts fail
pre-commit or become ambiguous. Both signed candidates, their canonical
statements and hashes are then preserved in detailed state when possible; they
do not replace the accepted LKG and publication/readiness stop. Persisted
evidence is reverified at startup, so clearing only `forkDetected` cannot
recover. P06 never selects a winning fork.

A present terminal journal has strict precedence: after it latches unsafe,
startup returns without reading main or prepared transition state. Therefore an
oversized or malformed prepared file cannot throw past startup or weaken the
terminal result.

Each content envelope retains the exact delegation and authority LKG under
which it was accepted. This permits historical verification after a later
revocation while readiness immediately stops serving the old bridge. Persisted
bytes are size-bounded before allocation/deserialization and cryptographically
reverified at startup. Structurally or cryptographically corrupt state is
quarantined, including parseable JSON with null/malformed nested records.
Corruption counters are diagnostic rather than a lifetime continuity bypass;
after explicit anchor reset and reseed, checks resume normally. Expired state
is retained as stale evidence but is not served.

## Public disclosure

`GET /api/v1/checkpoints/bridge` returns the accepted signed P04 envelope
byte-for-byte with:

`application/vnd.deep.p04.signed-bridge.v1+octet-stream`.

The status surface exposes bounded state codes, bridge hash/sequence/freshness
and counters only. It does not expose membership hash/sequence, contacts,
contact history, signer/node IDs, operator/reward addresses, source URLs,
paths or exceptions. Bridge responses are private and non-storable with
zero max-age and ETag revalidation.

The membership commitment is verified only for local state-machine evidence.
There is no membership or inclusion-proof endpoint. P04 currently defines an
inclusion-proof codec but no normative member-leaf schema or Merkle verifier.

## Production blockers

- DR-0002 authority and mirror ownership remains NOT APPROVED.
- There is no approved signature algorithm/profile or production verifier.
- There is no production genesis pin, ceremony bundle or live delegation.
- There is no approved P04B/P04C artifact source.
- There is no production external monotonic-anchor implementation or recovery
  ceremony.
- Domain LKG interpretation and membership disclosure require approval.
- Cross-language crypto vectors, integrated P04B–P07 evidence, external
  security review and recovery drills are absent.

No Docker/network service, deployment, key/seed access, package publication or
Git push is authorized by this ADR.

Required package status: `fixture-go-runtime-blocked`.
