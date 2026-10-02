# DID2 route threshold coordination candidate

Normative owner: [DR-0036](../../docs/survival-program/decisions/DR-0036-did2-route-threshold-coordination.md)
and [ContactResolver 3.1](../../docs/architecture/CONTACT-RESOLVER-V1.md).

The internal terminal is `/api/v2/contact-route-authority` over HTTPS with exact
V2 binary envelopes. `/api/v1/contact-route-authority` is removed. It is a private
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

Keep journal and independently maintained latest-head floor in the same
restoration policy. Back up exact durable winners and reservations; do not
restore an older journal while preserving a newer issued state elsewhere.
Reservations consume capacity permanently even if signing is interrupted.
Exhaustion is an operator action, not a timed cleanup. A same-nonce changed
request conflicts; a valid replay returns identical committed threshold bytes.
Stale/expired winners reject and are not renewed under their old nonce.

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
