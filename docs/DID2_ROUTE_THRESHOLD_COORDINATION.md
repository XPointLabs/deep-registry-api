# DID2 route threshold coordination candidate

Normative owner: [DR-0036](../../docs/survival-program/decisions/DR-0036-did2-route-threshold-coordination.md)
and [ContactResolver 3.1](../../docs/architecture/CONTACT-RESOLVER-V1.md).

The internal terminal is `/api/v2/contact-route-authority` over HTTPS with exact
request V3 and response V3 under [DR77](../../docs/survival-program/decisions/DR-0077-did2-route-successor-coordination.md).
`/api/v1/contact-route-authority` is removed. It is a private
witness-coordination boundary, not a steady-state contact resolver or public
mailbox-grant endpoint. Shipping clients still require XPoint/OHTTP coordination;
no public direct HTTP fallback is activated by this candidate.

Private calling-node access follows
[DR-0048](../../docs/survival-program/decisions/DR-0048-private-contact-coordination-peer-authentication.md).
When enabling either coordination terminal, provision
`ContactCoordinationIngress:AllowedNodePublicKeysHex` with the intended registered
nodes' canonical public Ed25519 keys. Missing/invalid access configuration prevents
startup; there is no authentication bypass. Preserve existing node private keys;
never copy them into Registry configuration. This access list does not establish
signed network membership, placement, publisher authorization or witness custody.

Enabling `ContactRouteAuthority:Enabled` requires DID2 admission/proofs in the
same network, configured witness custody, signed current NCP2 distribution and
`DeepIdV2DirectoryAuthority:LatestHeadFloorPostgreSqlConnectionString`. The
issuer reuses that independent restore-authority database for its permanent
route journal. Missing configuration, schema, network row, current floor,
authority/time or signed closure fails closed.

Before enabling, the operator executes
[`sql/did2-route-threshold-journal.sql`](sql/did2-route-threshold-journal.sql)
with a provisioning role and inserts exactly one intended network row with
`entry_count=0` and an explicit `maximum_entries` in 1..1,048,576. Runtime needs
SELECT and UPDATE(entry_count) on the network table, SELECT/INSERT and
UPDATE(exact_response) on the journal; request/network/nonce/capacity columns
must be immutable to the runtime role;
never grant DDL, DELETE or TRUNCATE. Do not recreate an empty row after loss.

For an existing DR36 journal, first stop coordination dispatch and back up its
exact tables together with the independent latest-head floor. A provisioning
role runs [`sql/did2-route-threshold-issued-head-upgrade.sql`](sql/did2-route-threshold-issued-head-upgrade.sql)
once, before activating matched Registry/XNode/client artifacts. The transaction
retains every old row, reservation, capacity and exact byte; it does not reset
floors or node keys. Old response envelopes remain audit-only and fail current
decoding. Runtime cannot perform DDL and rejects missing generation provision
before signing. Do not rerun this once-only script or replace a retired winner
under the same nonce. Rollback binaries and database evidence must be paired;
never manufacture a newer signed head for an older winner.

Keep journal and independently maintained latest-head floor in the same
restoration policy. Back up exact durable winners and reservations; do not
restore an older journal while preserving a newer issued state elsewhere.
Reservations consume capacity permanently even if signing is interrupted.
Exhaustion is an operator action, not a timed cleanup. A same-nonce changed
request conflicts; a valid replay returns identical committed threshold bytes.
Stale/expired winners reject and are not renewed under their old nonce.

Per-generation fencing follows
[DR-0072](../../docs/survival-program/decisions/DR-0072-did2-route-renewal-lineage.md).
The canonical request's account lookup, stable XRA1 ID and unsigned generation
select one permanent exact reservation, independently of the coordination nonce.
Another nonce or changed request for that generation rejects before signing and
without increasing capacity, including after a signing failure or restart. This
does not itself authorize a nonzero-generation request: the issuer independently
authenticates the exact predecessor and current successor before reservation.

Existing DR75 journals require the once-only provisioning transaction
[`sql/did2-route-threshold-generation-fence.sql`](sql/did2-route-threshold-generation-fence.sql)
before using the matched runtime. Stop dispatch and back up the exact journal
and latest-head floor first. The unique expression index includes all existing
request bytes, including audit-only response rows, without decoding old responses
or rewriting history. Competing existing generation reservations abort the
transaction: investigate and decide explicitly; do not delete rows or silently
choose one. Only successful provisioning installs `generation_fence_version=1`;
runtime rejects its absence before any signing callback and performs no DDL.
Existing provision then requires the once-only
[`sql/did2-route-threshold-successor-request.sql`](sql/did2-route-threshold-successor-request.sql)
transaction for DR77 request bounds and the mandatory request marker. Preserve
all exact history, counts and floors; old requests remain opaque audit-only.
Runtime rejects an absent marker before callbacks. Fresh installations use the
updated base schema, not the once-only upgrade scripts.

The Shared consumer retains the entire original request before dispatch under
[DR-0073](../../docs/survival-program/decisions/DR-0073-did2-exact-route-request-custody.md).
Its connected exchange forwards that retained request, never rebuilding the
minimum from a newer proof. DR75 retains the actual signed issuance head inside
the server winner and protected client custody. DR74 authenticates it separately
from independently current proof/network/time before completion and publication.
The current client journal requires explicit reset of incompatible disposable
QA state at activation, not production floor or registered-key reset. Source
integration tests do not establish matched production/device activation.
The connected local renewal lane expires a genuinely signed route, verifies
its history under fresh same-account authority, issues the successor over
TestServer HTTP and completes exact retained issuance after a lost response.
It rejects a forged predecessor before reservation/custody and another nonce
for the same generation before signing. Protected successor adoption is still
required separately; this lane does not establish physical recovery.
The real-account fixture uses DR70's pending signed network view, independent
ADA2-backed DID2 proof and subsequent topology completion; it no longer calls
the removed legacy one-stage operational author.

Fast isolated lane (does not replace the full Registry/Protocol/recovery gates):

```powershell
# DEEP_TEST_DID2_ROUTE_POSTGRES must identify an isolated test database.
dotnet test tests/Deep.Registry.Api.Tests/Deep.Registry.Api.Tests.csproj `
  -m:1 `
  -p:DeepProtocolLocalCutover=true -p:DirectoryVerifierFocused=true `
  -p:RouteThresholdFocused=true `
  --filter 'FullyQualifiedName~ContactRouteAuthorityHttpTests|FullyQualifiedName~DeepIdV2RouteThreshold'
```

Tests create/drop only uniquely named test schemas. Pipeline records are
structural test values, not authority. The real-issuer lane uses an actual PQ
account, native verifier, SQLCipher, authenticated ADA2, PostgreSQL floor and
route journal, signed network closure and file-backed witness custody; its HTTP
uses TestServer and its clock is explicitly controlled. It is not socket TLS,
production deployment, grants, UI or physical device E2E evidence. DR38 extends
this same real-account lane with publication coordination; see
[DID2_PUBLICATION_COORDINATION.md](DID2_PUBLICATION_COORDINATION.md).
