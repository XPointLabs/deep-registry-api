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

> **Route-activation NO-GO:** the capacity and publication machinery below is infrastructure only.
> The current owner sweep must not be enabled for a production cutover: copying an old PRC1/PRA1
> into a new PMA closure is cryptographically invalid, and PSS1 does not authorize or extend that
> route. Production promotion remains blocked until the independently reviewed RCD1/RDA1/RCR1/
> RCH1/RTC1/RCA1/PRA2/PSS2 continuity contract and atomic high-level verifier are integrated.

The first clean-break V2 persistence slice is deliberately narrower than route activation. A
separate `production_mailbox_route_continuity_v2` state keeps the exact canonical ROL1, tagged
authorization hash/sequence, PRC1, authorization, RTC1, optional RCH1, PSS2 transcript, and the
latest accepted RCD1/RDA1 pair. All unsigned counters are stored as canonical eight-byte
big-endian values rather than PostgreSQL `bigint`, so the database cannot create a lower terminal
counter than the protocol. Both InMemory and PostgreSQL mutations use the same predecessor rules,
freeze the opaque route-state key before waiting, and accept only non-forgeable protocol outputs:
`VerifiedProductionMailboxRouteSelectionTransition` or
`ProductionMailboxRouteContinuityEnrollmentCommitPlan`. The PostgreSQL mutation is serialized by
the opaque route-state-key advisory lock and commits the entire successor row atomically.

The second state-only slice activates those reserved RCR1 and RHB1/RHC1 columns without opening a
wire or coordinator path. Owner revocation mutation accepts only the sealed
`VerifiedProductionMailboxRouteContinuityRevocation` returned by the protocol's owner-signature
verifier. History mutation accepts only a sealed expected cursor plus a verified batch commit plan;
Registry repeats protocol verification and exact protected-restore-context comparison before it
waits on storage. A bounded raw RHB1 is accepted only by a read-only lost-response replay check:
the current sequence and exact SHA-256 return the durable state, the same sequence with different
bytes is a fork, and older/future sequences are rejected without mutation. PostgreSQL serializes
all three operations on the opaque route advisory lock and stores the complete RHC1 protected
restore tuple atomically. Endpoints, coordinator activation, RCR/RHB ingestion, and XNode
publication remain deliberately absent until the later reviewed integration slices.

The third isolated slice adds only the V2 XNode cache-publication barrier; it still does not
activate a route or expose an owner endpoint. Registry freezes PMA1/PMR1/PMT1 and current/next
PMS1 from one internal control-plane snapshot, then replaces every route-specific field from one
durable route-state snapshot and invokes the protocol's cache-only verifier. The verifier output
is bound to a domain-separated fingerprint of the complete ROL/authorization/RCR/RHC transition
state. The store compares that fingerprint both when the activation is created and again in the
same transaction that marks publication complete.

Only after the verified plan is accepted does the state transaction generate and persist the
one nonzero random PMC2 salt, exact canonical envelope, cache transcript, hard expiry, lineage,
cohort and ordered target set. Exact retry returns those stored bytes; it never generates a new
salt. The same transaction writes a domain-separated Prepared-V2 HMAC over the entire bounded
materialized activation using the existing protected route-state integrity key. Every reload
verifies that MAC before returning an owned Prepared snapshot to the external signer. Missing,
wrong-key or corrupted prepared state fails closed. The HMAC format is clean-break v1: operators
must drain or explicitly discard all V2 activation rows before rotating that key; old and
new keys are never accepted concurrently. Publication then uses a separate Prepared-to-Attested
CAS: the publisher signs the exact
persisted salt, lineage commitment, envelope hash and length together with the verified source,
every exact artifact, cache transcript and complete ordered target/endpoint/pin set. A crash before
or after signing resumes the same prepared bytes, and a lost response after the attestation write
is an exact replay. An unattested row cannot enter the work queue, reserve capacity, create an
attempt, accept an ACK or finalize. PostgreSQL reload revalidates the attestation before any
capacity, signer or network callback. Database length constraints and
bounded target reads reject oversized or excess stored rows before materialization. Target
identities, HTTPS endpoints and pin pairs are derived only from the verified PSS2 old/current
selection and PMT1 closure; a disjoint next-only replica is not a publication target. Publisher-
signed PMP2 attempts freeze a signer result once, are locally reverified, and are durably recorded
before the constant-path peer POST. A delayed ACK is accepted only for the current exact attempt
hash.
The final store primitive locks the route, activation, target and capacity rows in canonical order
and, using authoritative transaction time, requires an unchanged source fingerprint, an unexpired
PMC2, every exact PMP2 ACK and every current node-signed PMB2 reservation receipt through the safe
renewal margin. It repeats the source/time/capacity predicate at the final write boundary.
An independent phase-integrity HMAC covers the exact persisted attestation signature, ordered
attempt bytes/hashes/timestamps/ACK flags and Published bit. Every read verifies both HMACs and,
for Attested/Published state, the exact Ed25519 attestation before interpreting a phase. Attempt,
ACK and final publication transactions lock and verify the full old phase, then update the row and
phase HMAC atomically; a stored phase-bit or coherent attempt/ACK rewrite is never authority.
The store admits at most two live cache commitments for one exact selection/old-PMS lineage under
the same cross-process lock used for creation; authenticated expired rows are pruned before a new
admission. Publication checks the immutable cache expiry and safety margin before capacity and
again before every attempt, so a hard-expired activation performs no signer, transport or capacity
work and is boundedly reclaimed. A best-effort source-current check also precedes those side
effects. If the source changes while an already-issued network request is in flight, the final
source CAS still prevents activation; the resulting undiscoverable XNode cache is bounded by its
signed hard expiry.

Node-visible PMC2/PMP2 records contain no RCD1, RDA1, RCR1, RHB1, RHC1, ROL1, route-state key,
token or entitlement data. There is no PMQ endpoint, owner signing, V1 fallback or public raw V2
mutation API in this slice. Capacity release remains the existing durable post-publication cohort
cleanup. Route activation remains blocked by the explicit NO-GO above until the continuity
coordinator and high-level client verifier are integrated.

Artifact reload infrastructure stages a promotion rather than immediately swapping the pointer.
PostgreSQL records one active
promotion with an immutable owner-sequence watermark and a resumable cursor. New enrollment and
credential issuance are fenced while it is active. The coordinator scans the durable LocalOwner
cohort in bounded pages, prepares an exact publication target, updates the latest predecessor and
inserts immutable PMC1 publication targets in the same serializable transaction. PMP1 timestamp,
nonce and signature are renewable attempts; ACK binds the immutable target and PMC1 hash plus the
latest attempt hash. A background drainer can resume after process or network failure. The active
PMA1/PMR1/PMT1 pointer is designed to change only after every cohort publication is acknowledged;
a crash after provider cutover but before the final database marker remains fail-closed and
idempotently reconcilable. This ordering does not waive the route-activation gate above.

Before the owner cursor can advance, a separate durable planning cursor scans the complete frozen
owner watermark and aggregates a conservative per-XNode reservation: one closure count per owner
ticket and the canonical PMC1 bytes plus PCS1 framing and configured filesystem-accounting
overhead. Registry signs exact PMB1 reserve/renew/release commands; every required XNode returns a
node-signed PMB2 receipt binding the cohort, target, command hash, revision, count, bytes and expiry.
Commands are stored before the HTTP attempt and replayed byte-for-byte after a lost response.
Registry verifies the receipt signature and commits it only against that pending command.

The owner update/outbox transaction independently evaluates `clock_timestamp()` plus
`CapacityReservationRenewalMarginSeconds` both before mutation and in the final cursor CAS, and
refuses to advance unless every target receipt is still live, exact, not released and has no
ambiguous pending attempt. PostgreSQL statement, lock and idle-transaction timeouts are strictly
shorter than the renewal margin. A partial reserve or renewal failure therefore freezes the
unpublished promotion before the next owner commit. Only after the artifact-provider cutover and
the authoritative database publication marker are durable does Registry enter its persisted
capacity-release cleanup phase. It sends revision-successor releases without ever returning to
Reserve; after a crash each already released target is skipped and each pending exact Release is
retried. XNode releases only unused headroom, while already written schedules remain charged as
actual storage. Registry persists revisions as PostgreSQL `bigint`: Reserve/Renew is therefore
bounded to `long.MaxValue - 1`, leaving exact `long.MaxValue` for the terminal Release; receipts or
attempts outside that storage domain fail before conversion. The defaults are a
3600-second reservation lifetime, 300-second safe-renewal margin and 1024-byte per-schedule
filesystem allowance; the filesystem allowance must equal the XNode setting.

If a terminal XNode capacity floor has already passed its bounded retention window, Registry does
not mark cleanup complete locally. It sends a fresh publisher-signed PMB3 reconciliation command
containing the exact last node-signed PMB2 receipt and its command/receipt hashes. PMB3 is capped at
300 seconds. Under its store and process locks the XNode returns a node-signed PMB4
`AbsentTerminal` receipt only when no live floor or transfer exists and its complete schedule scan
matches authoritative accounting. PMB4 is read-only: it cannot release, reserve or resurrect
capacity. Registry atomically binds PMB4 to the durable predecessor and pending Release command,
retains it for audit, marks only that target released, and can then finish cleanup and admit the
next promotion. A PostgreSQL/real-XNode test advances beyond floor retention, restarts both sides,
reconciles every target and proves the next promotion is no longer blocked.

This capacity barrier does not by itself promise an unlimited control-plane outage. The usable
Registry-offline horizon is the configured XNode multi-version schedule horizon (each live
selection/route activation is at
most 24 hours), not the 365-day historical-anchor age. Survival Beta additionally requires the
client/XNode +25-hour outage E2E and the owner-authenticated fresh-checkpoint lane for a client whose
exact durable old PMS predates the retained live node schedule. Expired PSS1 is never accepted and
retired issuer keys are never retained for refresh.

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

Set `CapacityReservationLifetimeSeconds`, `CapacityReservationRenewalMarginSeconds`,
`ClosureScheduleAccountingOverheadBytes`, and `MaximumCapacityPlanTargets` consistently with the
XNode fleet. A configuration mismatch fails closed during reservation; it must not be handled by
lowering the signed reservation after planning.

The exact local protocol closure is recorded in `vendor/pma/package-manifest.json`; it is built
reproducibly from protocol commit `cc39defbf9c24bf7d99f6346a86c7602379b62ea` and is not published.
