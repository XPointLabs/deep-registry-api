# DID2 publication coordination candidate

The 2026-10-02 focused route/publication slice passed 33 tests with no skips,
using a real isolated PostgreSQL database and PQ/SQLCipher custody. The
shared production admission limit is unchanged: route plus publication use
the source budget; an immediate lost-response retry returns empty 429 with
bounded `Retry-After`. The test advances only its scheduling clock before
replaying the unchanged durable request. It does not advance signed authority
time or bypass admission. This is TestServer evidence, not physical delivery.

Normative owner: [DR-0079](../../docs/survival-program/decisions/DR-0079-did2-publication-issuer-successor.md),
superseding DR38's envelope and genesis-only issuer limit.
Private terminal: HTTPS `/api/v2/contact-publication-authority`, exact V3 media
and envelopes only. V1/V2 readers are absent. No public direct HTTP
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
For an existing pre-DR79 journal run the explicit one-time operator
[successor-fence provision](sql/did2-publication-successor-fence.sql) instead;
never recreate a network or erase audit rows. The provision preserves opaque
old request/response bytes and counts without parsing or backfilling them.
Those rows are not usable runtime lineage. Match all private peers/clients and
grant INSERT for the immutable new projections, not UPDATE on them or markers.

Before reserving, independently verify current DID2/DCA, all DCR support and
prekey signatures, exact route/XIR, exact current head minimum, the whole-envelope
publisher signature, validity and placement. Reservation commits before signing;
the network lock serializes exact-winner signing/commit behind the permanent
unsigned-generation fence, followed by separate read-back and full verification.
Nonzero generation first reads the completed predecessor by directory leaf and
exact generation-1, then independently checks its signed publisher/XPA/history
and the publisher-bound two-node receipts. The issuer fact is NOT client object
decryption evidence. A second nonce/body for one generation conflicts even after
an interrupted signing attempt; pending reservations are never freed. Expired winners
reject without reminting. Sources/time are reread and fenced before commit and
after read-back. No resolver read capability or plaintext-decryption key is
sent to this authority. Opaque encryption correctness is owned by DR37 custody.

The account-owned protected route journal follows DR79's current-only generation.
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
mandatory-marker corruption. The separate provisioning test checks opaque audit
preservation and the unsigned SQL fence. These are not full release-gate results.
It does not attest platform secure storage, socket TLS, ONION, production
deployment, dual-replica commit, mailbox delivery or physical device E2E.
Full gates and protocol/API/vector repin remain the final business-batch gate.
