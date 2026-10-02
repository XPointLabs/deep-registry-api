# DID2 publication coordination candidate

The 2026-10-02 focused route/publication slice passed 33 tests with no skips,
using a real isolated PostgreSQL database and PQ/SQLCipher custody. The
shared production admission limit is unchanged: route plus publication use
the source budget; an immediate lost-response retry returns empty 429 with
bounded `Retry-After`. The test advances only its scheduling clock before
replaying the unchanged durable request. It does not advance signed authority
time or bypass admission. This is TestServer evidence, not physical delivery.

Normative owner: [DR-0038](../../docs/survival-program/decisions/DR-0038-did2-publication-coordination.md).
Private terminal: HTTPS `/api/v2/contact-publication-authority`, exact V2 media
and envelopes only. V1 terminal and issuer are removed. No public direct HTTP
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

Before enabling, provision [sql/did2-publication-journal.sql](sql/did2-publication-journal.sql)
using an operator role and insert one intended network row with `entry_count=0`
and explicit `maximum_entries` in 1..1,048,576. Runtime needs SELECT and
UPDATE(entry_count) on the network table, SELECT/INSERT and
UPDATE(exact_response) on the publication journal. Request/network/nonce and
capacity are immutable to runtime; never grant DDL, DELETE or TRUNCATE.
Never recreate an empty root after loss. Preserve exact pending reservations
and committed responses with the independent latest-head floor across recovery.
Capacity is permanent and exhaustion requires operator intervention.

Before reserving, independently verify current DID2/DCA, all DCR support and
prekey signatures, exact route/XIR, exact current head minimum, the whole-envelope
publisher signature, validity and placement. Reservation commits before signing;
the network lock serializes exact-winner signing/commit, followed by a separate
read-back and full verification. A changed nonce body conflicts; expired winners
reject without reminting. Sources/time are reread and fenced before commit and
after read-back. No resolver read capability or plaintext-decryption key is
sent to this authority. Opaque encryption correctness is owned by DR37 custody.

The account-owned protected route journal is version 3 only. It retains exact
request before the coordination callback and exact verified response before
return, with a 1 MiB slot bound and maximum-complete-entry reservation. Old QA
roots require explicit reset, no silent repair. One callback has a 30-second
deadline. A response lost after server commit retries the exact request; stale
retained requests reject instead of silently changing publisher intent.

The isolated real-account lane extends `DeepIdV2RouteThresholdIssuerTests`:
PQ/native account + SQLCipher + authenticated ADA2 + PostgreSQL floor/journals
+ real signed network/witness custody + TestServer HTTP + controlled test clock.
It does not attest platform secure storage, socket TLS, ONION, production
deployment, dual-replica commit, mailbox delivery or physical device E2E.
Full gates and protocol/API/vector repin remain the final business-batch gate.
