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
   `challenge` (32 bytes), `leadingZeroBits`, and `expiresAtUnixSeconds`.
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
  "opaqueEntitlement": null
}
```

For `LocalOwner`, all three route strings are empty and both the active holder and stable owner sign
the exact protocol `PHP1` transcript. The coordinator derives the stable route with the external
issuer. `PeerDeposit` currently fails closed with HTTP 409 and
`{"error":"route-advertisement-required"}`. It must not be exposed in production UI until the
protocol defines and the client verifies an owner-signed, authority/network-bound public route
advertisement. Dormant issuance logic will later require its three exact nonzero route fields and
will issue deposit grants only; retrieve grants remain exclusive to `LocalOwner`.

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

The response contains exact canonical `PMS1` selections and exact `MCG2` grants for both current and
next epochs. Each selection contains exactly two ordered replicas. Clients send to the first replica
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

Catalog entries are retained through the credential/current-epoch expiry plus clock skew. Reload is
rejected before memory can exceed `MaximumRetainedArtifactClosures` (default 16, maximum 64), so a
rapid administrative reload cannot silently evict a still-valid content address or grow memory
without bound.

Internal reload, holder revocation, and sanitized runtime counters are under
`/api/internal/production-mailbox`. They fail closed unless the connection has the configured
authentication type and the exact pinned client-certificate SHA-256.

## Production configuration

Set `ProductionMailbox:Enabled=true` and provide all artifact paths, membership-proof directory,
pinned Mr. X/network/last-known-good generations and hashes, absolute external signer socket,
bounded external signer timeout (1–30 seconds), PostgreSQL connection string, and internal
client-certificate pin. Mount artifacts and membership
proofs read-only. Do not put Mr. X or issuer private material in configuration or environment
variables. `UseDevelopmentInMemoryState` and `DevelopmentSoftwareSignerSeedPath` must remain unset.

The exact local protocol closure is recorded in `vendor/pma/package-manifest.json`; it is built from
protocol commit `eacaeb831905d6508fa118ca80c78b4a22a987e6` and is not published.
