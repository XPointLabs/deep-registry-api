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
single process gate. Durable state is flushed and atomically replaced before
the in-memory reference changes. A failed write leaves both the prior durable
and in-memory LKG unchanged.

An identical artifact is idempotent. A different valid same-sequence successor
is preserved as a fork condition; it does not replace the accepted LKG and
publication/readiness stop. P06 never selects a winning fork.

Persisted bytes are decoded, re-encoded and cryptographically reverified at
startup. Corrupt or mismatched state is quarantined. Expired state is retained
as stale evidence but is not served.

## Public disclosure

`GET /api/v1/checkpoints/bridge` returns the accepted signed P04 envelope
byte-for-byte with:

`application/vnd.deep.p04.signed-bridge.v1+octet-stream`.

The status surface exposes bounded state codes, hashes, sequences and counters
only. It does not expose contacts, contact history, signer/node IDs,
operator/reward addresses, source URLs, paths or exceptions.

The membership commitment is verified only for local state-machine evidence.
There is no membership or inclusion-proof endpoint. P04 currently defines an
inclusion-proof codec but no normative member-leaf schema or Merkle verifier.

## Production blockers

- DR-0002 authority and mirror ownership remains NOT APPROVED.
- There is no approved signature algorithm/profile or production verifier.
- There is no production genesis pin, ceremony bundle or live delegation.
- There is no approved P04B/P04C artifact source.
- Domain LKG interpretation and membership disclosure require approval.
- Cross-language crypto vectors, integrated P04B–P07 evidence, external
  security review and recovery drills are absent.

No Docker/network service, deployment, key/seed access, package publication or
Git push is authorized by this ADR.

Required package status: `fixture-go-runtime-blocked`.
