# Production mailbox coordinator

This component is disabled by default. It issues only official-cloud mailbox selections and
capability grants. Direct P2P and self-hosted node networks do not call this API and remain free.

## Security boundary

- Mr. X signs `PMA1` offline. The Registry process receives only the public artifact and a pinned
  SHA-256 hash of the Mr. X public key.
- The mailbox issuer private key is held by a separate signer process. Production Registry talks
  to it over an absolute Unix-domain socket using the fixed `PMES` request frame and verifies every
  returned Ed25519 signature against `PMA1`.
- A software-held issuer seed is accepted only in the Development environment. Production requires
  PostgreSQL and rejects in-memory state and software signing.
- The stable mailbox-owner Ed25519 key is a dedicated, unlinkable mailbox key. It must not reuse a
  global account or profile identity key. An active holder may rotate without changing the route.
- Anonymous challenges are one-use, expire, are globally bounded per time window, and carry a
configurable proof-of-work cost. The service records no request payloads, keys, routes, tokens,
entitlement blobs, or challenge values in its own metrics.

Proof of work is used only for enrollment or holder rotation, never polling. Configuration is
restricted to 8–22 leading zero bits (default 18) to bound mobile battery and latency cost.

## Public HTTP contract

All binary strings in JSON are canonical unpadded base64url. Enum values are JSON numbers:
`intent` is `1` (`LocalOwner`) or `2` (`PeerDeposit`); `platform` is `1` (Android) or `2`
(Windows).

1. `POST /api/production-mailbox/challenges` with an empty body returns `challengeId` (16 bytes),
   `challenge` (32 bytes), `leadingZeroBits`, `expiresAtUnixSeconds`, and the exact inline immutable
   PMA1/PMR1/PMT1 closure. The durable challenge row binds the three artifact hashes; issuance on a
   different closure fails closed instead of silently changing the signed PHP1 inputs.
2. The client solves `SHA-256(UTF8("Deep/production-mailbox/pow/v1") || challengeId || challenge
   || nonceBE64)` and requires the advertised number of leading zero bits.
3. `POST /api/production-mailbox/credentials` receives:

```json
{
  "holderEd25519PublicKey": "base64url-32",
  "mailboxOwnerEd25519PublicKey": "base64url-32",
  "intent": 1,
  "platform": 1,
  "signingCertificateSha256": "base64url-32",
  "buildArtifactSha256": "base64url-32",
  "idempotencyKey": "base64url-32",
  "entitlementCommitment": "base64url-32",
  "blindedMailboxId": "",
  "blindedPlacementId": "",
  "selectionInputCommitment": "",
  "challengeId": "base64url-16",
  "challenge": "base64url-32",
  "proofOfWorkNonce": 0,
  "holderProofSignature": "base64url-64",
  "ownerProofSignature": "base64url-64",
  "opaqueEntitlement": null,
  "routeAdvertisement": null
}
```

For `LocalOwner`, all three route strings are empty and both the active holder and stable owner sign
the exact protocol `PHP1` transcript. The coordinator derives a stable network/owner route and
returns an issuer-signed `PRC1`. The owner publishes an exact owner-signed `PRA1` only inside an
authenticated E2E contact channel. `PeerDeposit` requires that PRA1 plus its three exact nonzero
route fields, enforces authority/network/owner/route binding and durable sequence/hash replay state,
and issues deposit grants only; retrieve grants remain exclusive to `LocalOwner`.

`signingCertificateSha256` and `buildArtifactSha256` are holder-signed cohort metadata, not remote
attestation and not an authorization decision. Public approved hashes can be copied by an altered
client. A future admission policy must use platform-verifiable, privacy-preserving attestation.

This version issues only the free baseline. `entitlementCommitment` must be 32 zero bytes and
`opaqueEntitlement` must be null. Any paid/upgraded claim is rejected until a canonical quota
authorization is signed into a node-verifiable grant and enforced by XNode. JSON limits are never
treated as authoritative paid entitlement.

The canonical idempotency key is:

```text
SHA-256(
  UTF8("Deep/production-mailbox/issuance-idempotency/v1") ||
  authoritySha256 || revocationSha256 || topologySha256 ||
  holderKey || ownerKey || blindedMailboxId || blindedPlacementId ||
  selectionInputCommitment || intentByte || platformByte ||
  signingCertificateSha256 || buildArtifactSha256 || entitlementCommitment)
```

Every hash/key/route/commitment is exactly 32 bytes. LocalOwner uses three all-zero route fields.
The client includes this key in `PHP1`; the server independently recomputes it before issuance.
Retries obtain a byte-identical stored credential response while its current-epoch validity remains.

The response contains exact canonical Rendezvous-SHA256-v2 `PMS1` selections and exact `MCG2`
grants for both current and next epochs. On direct old-next/new-current promotion, Registry replays
the exact stored old-next MCG2 bytes for the same holder and emits a verifiable dual-signed `PSS1`;
after two or more missed rotations it emits current-issuer-signed `OfflineCheckpoint` PSS1. Each
selection contains exactly two ordered replicas. Clients send to the first replica
and fail over to the second only after a definitely pre-acceptance transport failure or an explicit
non-accepting response. An ambiguous post-dispatch timeout is retried with the exact same operation
identity so node-side duplicate handling remains authoritative.

Every response embeds the exact canonical authority, revocation, and topology bytes in the
corresponding artifact reference as `canonicalBase64Url`. Its `contentPath` is content-addressed;
verified historical snapshots remain in the running catalog across reload, and the inline closure
keeps an already stored response independently verifiable after restart. Public immutable artifacts
support ETags:

- `GET /api/production-mailbox/artifacts/{sha256}/authority.pma1`
- `GET /api/production-mailbox/artifacts/{sha256}/revocations.pmr1`
- `GET /api/production-mailbox/artifacts/{sha256}/topology.pmt1`

Catalog entries are retained through the credential/current-epoch expiry plus clock skew. Each
entry durably owns PMA1/PMR1/PMT1 and the exact bounded current+next MIP1 proof closure; every proof
is checked against its topology membership root, storage role and full epoch validity before the
entry can be staged. Canonical manifests and the active pointer are domain-separated HMAC-bound by
the protected route-state key. The PostgreSQL published-closure row is the rollback floor: startup
rejects a signed old-pointer replay, while a completed sweep whose pointer flip committed before its
database marker is reconciled before the server accepts traffic. Reads use one no-follow stable
handle and reject reparse/path-swap races. Expired entries are removed through durable tombstones
and bounded restart reconciliation. Reload is rejected before memory or persisted entries can
exceed `MaximumRetainedArtifactClosures` (default 16, maximum 64), so a rapid administrative reload
cannot silently evict a still-valid content address or grow memory/disk metadata without bound.

Artifact reload is a staged promotion, not an immediate pointer swap. PostgreSQL records one active
promotion with an immutable owner-sequence watermark and a resumable cursor. New enrollment and
credential issuance are fenced while it is active. The coordinator scans the durable LocalOwner
cohort in bounded pages, creates an exact new owner bundle/PSS1, updates the latest predecessor and
inserts immutable PMC1 publication targets in the same serializable transaction. PMP1 timestamp,
nonce and signature are renewable attempts; ACK binds the immutable target and PMC1 hash plus the
latest attempt hash. A background drainer can resume after process or network failure. The active
PMA1/PMR1/PMT1 pointer changes only after every cohort publication is acknowledged; a crash after
provider cutover but before the final database marker remains fail-closed and idempotently
reconcilable.

This sweep/ACK implementation is not yet the node-capacity reservation gate. Until XNode exposes an
authenticated bounded cohort reservation for exact count/bytes/expiry, a rotation can safely stop
as a resumable unpublished partial sweep when a node rejects capacity, but cannot claim a
production-wide preflight reservation. Survival Beta remains blocked on that separate API and its
capacity-pressure E2E; partial progress is never reported as a published artifact generation.

Internal reload, holder revocation, and sanitized runtime counters are under
`/api/internal/production-mailbox`. They fail closed unless the connection has the configured
authentication type and the exact pinned client-certificate SHA-256.

## Production configuration

Set `ProductionMailbox:Enabled=true` and provide all artifact paths, membership-proof directory,
an absolute `ProductionMailbox:RouteStateHmacKeyPath` to a protected, non-reparse 32-byte
secret used only for privacy-preserving durable route-state keys,
pinned Mr. X/network/last-known-good generations and hashes, absolute external signer socket,
bounded external signer timeout (1–30 seconds), PostgreSQL connection string, and internal
client-certificate pin. Mount artifacts and membership
proofs read-only. Do not put Mr. X or issuer private material in configuration or environment
variables. `UseDevelopmentInMemoryState` and `DevelopmentSoftwareSignerSeedPath` must remain unset.

The exact local protocol closure is recorded in `vendor/pma/package-manifest.json`; it is built
reproducibly from protocol commit `20249077913abfd9ad69f957aa07e57ff55b5e24` and is not published.
