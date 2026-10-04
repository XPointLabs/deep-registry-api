# DID2 publication coordination candidate

The 2026-10-02 focused route/publication slice passed 33 tests with no skips,
using a real isolated PostgreSQL database and PQ/SQLCipher custody. The
shared production admission limit is unchanged: route plus publication use
the source budget; an immediate lost-response retry returns empty 429 with
bounded `Retry-After`. The test advances only its scheduling clock before
replaying the unchanged durable request. It does not advance signed authority
time or bypass admission. This is TestServer evidence, not physical delivery.

Normative owner: [DR-0089](../../docs/survival-program/decisions/DR-0089-did2-one-time-publication-coordination.md),
superseding DR79's envelope and permanent-only reservation scope.
Private terminal: HTTPS `/api/v2/contact-publication-authority`, exact V4 media
and envelopes only. Older readers are absent. No public direct HTTP
shipping fallback, replica commit, grants, UI or physical delivery is activated.

The independent node-authenticated private ingress and shared public-key access
configuration follow [DR-0048](../../docs/survival-program/decisions/DR-0048-private-contact-coordination-peer-authentication.md)
and the [route coordination operator notes](DID2_ROUTE_THRESHOLD_COORDINATION.md).
Both real-issuer TestServer exchanges now authenticate the calling node; that
does not replace publisher or witness verification.

Enable `ContactPublicationAuthority:Enabled` only with current DID2 authority
and proofs in the same network, file-backed witness custody, signed current
NCP2 distribution and the existing independently maintained latest-head floor.
The journal uses `DeepIdV2DirectoryAuthority:LatestHeadFloorPostgreSqlConnectionString`.
Missing schema/network row/floor/custody/current time fails closed.

For a genuinely new authority domain, provision [sql/did2-publication-journal.sql](sql/did2-publication-journal.sql)
using an operator role and insert one intended network row with `entry_count=0`
and explicit `maximum_entries` in 1..1,048,576. Runtime needs SELECT and
UPDATE(entry_count) on the network table, SELECT/INSERT and
UPDATE(exact_response) on the publication journal. Request/network/nonce and
capacity are immutable to runtime; never grant DDL, DELETE or TRUNCATE.
Never recreate an empty root after loss. Preserve exact pending reservations
and committed responses with the independent latest-head floor across recovery.
Capacity is permanent and exhaustion requires operator intervention.
For an existing DR79/V3 journal run the explicit operator
[one-time-scope provision](sql/did2-publication-one-time-scope.sql) instead.
A pre-DR79 authority requires its already documented
[successor-fence provision](sql/did2-publication-successor-fence.sql) first;
never recreate a network or erase audit rows. The provision preserves opaque
old request/response bytes and counts without parsing or backfilling them.
Retired projected permanent reservations still fence the same leaf/generation
without decoding the retired request. They do not occupy independent one-time
locator scopes. Runtime requires network markers envelope4/fence2 and checks
kind/locator projections against the canonical V4 request before callbacks.
Those retired rows are not usable runtime lineage. Match all private peers/clients and
grant INSERT for the immutable new projections, not UPDATE on them or markers.

Before reserving, independently verify current DID2/DCA, all DCR support and
prekey signatures, exact route/XIR, exact current head minimum, the whole-envelope
publisher signature, validity and placement. Reservation commits before signing;
the network lock serializes exact-winner signing/commit behind the immutable
network/leaf/kind/locator/unsigned-generation fence, followed by separate read-back
and full verification. Independent one-time genesis invitations can coexist
with the reusable publication for the same account; changing bytes or nonce
for one invitation cannot free its reservation. One-time successors reject.
Reusable nonzero generation first reads the completed predecessor in that exact
kind/locator scope at generation-1, then checks its signed publisher/XPA/history
and the publisher-bound two-node receipts. The issuer fact is NOT client object
decryption evidence. A second nonce/body for one generation conflicts even after
an interrupted signing attempt; pending reservations are never freed. Expired winners
reject without reminting. Sources/time are reread and fenced before commit and
after read-back. No resolver read capability or plaintext-decryption key is
sent to this authority. Opaque encryption correctness is owned by DR37 custody.

The reusable account-owned protected route journal follows DR89's current-only
journal9 and request bounds. It does not provide one-time secret custody.
It retains exact
request before the coordination callback and exact verified response before
return, with a 1 MiB slot bound and maximum-complete-entry reservation. Old QA
roots require explicit reset, no silent repair. One callback has a 30-second
deadline. A response lost after server commit retries the exact request; stale
retained requests reject instead of silently changing publisher intent.

The isolated real-account lane extends `DeepIdV2RouteThresholdIssuerTests`:
PQ/native account + SQLCipher + authenticated ADA2 + PostgreSQL floor/journals
+ real signed network/witness custody + signed in-process replica receipts
+ TestServer HTTP + controlled test clock. It covers expired committed history,
successor issuance, hostile receipts before reservation, pending-generation
conflict, lost-response replay, independent restart, canonical projection and
mandatory-marker corruption. The V4 extension checks two real independently
authored one-time invitations, signed pending-scope conflicts, authenticated HTTP
lost response, independent restart and exact concurrent provider replay. The
separate provisioning test checks opaque audit preservation, unsigned SQL fence,
disjoint scopes and malformed scope rejection. These are not device results.
It does not attest platform secure storage, socket TLS, ONION, production
deployment, dual-replica commit, mailbox delivery or physical device E2E.
Full gates and protocol/API/vector repin remain the final business-batch gate.
