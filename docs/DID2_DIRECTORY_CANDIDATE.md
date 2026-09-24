# DID2 Registry admission candidate

This is a development/UAT path, not a production release approval. The
`/api/v2/account-directory/genesis-admissions` route is disabled by default.
It accepts only DGA1 V2, verifies the exact DID2/DAB2 ML-DSA and classical
closure, and appends to separately provisioned ADA2 state. The legacy V1
admission and the V2 admission cannot be enabled together.

The `DeepIdV2DirectoryAuthority` configuration requires:

| Setting | Value |
|---|---|
| `NetworkIdHex` | Exact 16-byte network ID, matching `ContactResolveProductionAuthority` |
| `GenesisAuthorityCoreHashHex` | Independently pinned SHA-256 core hash of generation-zero XNA1 |
| `ExactAuthorityPaths` / `ExactTimePolicyPaths` | Ordered, positionally paired exact XNA1/DTS1 files |
| `GenesisHeadPath` / `GenesisHeadCoreHashHex` | Exact signed empty V2 ADH1 and its independently pinned core hash |
| `StatePath` / `IntegrityKeyPath` | Separate absolute paths for ADA2 and its nonzero 32-byte HMAC key |
| `DeploymentProfileId` | Nonzero DID2 deployment profile; currently 1 |
| `HeadValiditySeconds` | 300–86400 seconds; default 3600 |
| `ProofEnabled` | Optional UAT `DPQ2` proof endpoint; required for production; default `false` |
| `ProductionCutoverAttested` | Operator attestation after independent floor topology, restore drill and client E2E; default `false` |
| `CurrentXnv1Path` | Exact signed current XNV1 supplied by the authority owner |
| `ProofRequestLedgerRootPath` / `ProofRequestLedgerIntegrityKeyPath` | Separate V2 one-use nonce ledger root and nonzero 32-byte HMAC key; neither may alias V1 custody paths |

First configure protected trusted time and threshold witness custody under
`ContactResolveProductionAuthority`, and verify their network and key files.
Use only a newly signed V2 empty head (`minimumReader >= 2`, V2 empty-map
root); never copy ADA1 into ADA2. With the exact XNA1/DTS1 genesis paths and
independent XNA1 core-hash pin configured, V1 admission disabled, and an empty
absolute `GenesisHeadPath`, author the head once using the configured
threshold witness custody. The two numeric arguments are operator-approved
Unix-second bounds inside the verified XNA1 validity interval (at most 24h):

```text
dotnet Deep.Registry.Api.dll did2-directory author-genesis-head <validFromUnix> <validUntilUnix>
```

The command creates only the public signed ADH1, self-verifies its V2 empty
roots and witness threshold, prints its core hash, and refuses a pre-existing
head, interrupted authoring file, missing/insufficient custody, cross-network
keys, overlapping paths or a stale configured head pin. It never emits seeds.
Review and independently pin that printed hash as
`GenesisHeadCoreHashHex`; the command does not set the pin for you. With the
exact signed head present, the following read-only command re-verifies the
pinned XNA1/DTS1 lineage, threshold signatures and V2 empty-map genesis,
then prints the ADH1 core hash without reading witness seeds or writing state:

```text
dotnet Deep.Registry.Api.dll did2-directory verify-genesis-head
```

If `GenesisHeadCoreHashHex` is already configured, a mismatch fails closed.
Review the output against the authoring record and store the approved pin in
protected deployment configuration; the head file itself is not an independent
pin. With the V2 state/key settings supplied, initialize ADA2 once from inside the Registry
runtime:

```text
dotnet Deep.Registry.Api.dll did2-directory provision-state
```

This command re-verifies XNA1/DTS1 from the pinned genesis, verifies the
signed empty head, writes an HMAC-protected ADA2 file under an exclusive
lease, prints only its SHA-256, and refuses any existing state or interrupted
write. It does not enable the HTTP route. In production the admission endpoint
requires `ProductionCutoverAttested=true`, `ProofEnabled=true` and one remote
PostgreSQL floor endpoint configured with `SSL Mode=VerifyFull` and an absolute
local root-certificate path. This flag is an operator attestation, not proof
of independent backup/restore topology or the physical client gate. Before
mapping any production HTTP route, startup also verifies trusted time, the
signed authority chain, the complete ADA2 journal and its exact external
floor, and constructs the proof issuer with its protected nonce ledger; an
outage or mismatch aborts startup. UAT may explicitly set
`DeepIdV2DirectoryAuthority:Enabled=true` and keep
`AccountDirectoryAuthority:Enabled=false`.

Do not enable this candidate in production yet. A PostgreSQL latest-head
floor provider is implemented but has not been provisioned in an independently
operated and restored production database or exercised through a production
recovery drill. V2 current proof publication, client cutover and physical
Android↔Windows E2E are also open gates. The client must never trust the
admission receipt alone as a fresh directory or contact proof.

The ADA2 store's external floor dependency is threaded through both genesis
admission and proof issuance. Set
`DeepIdV2DirectoryAuthority:LatestHeadFloorPostgreSqlConnectionString` via a
secret environment variable to register the PostgreSQL provider in isolated
UAT. It performs an exact-head, network-bound atomic compare/exchange; missing
rows, stale heads, duplicate genesis provisioning and unavailable PostgreSQL
fail closed. Neither startup nor request handling creates tables or rows.
The schema is [did2-latest-head-floor.sql](sql/did2-latest-head-floor.sql).
Its database, snapshot schedule and restore authority MUST be independent of
the ADA2 filesystem. A local container, same-host volume or database restored
from the same snapshot is not a production rollback floor. Production cutover
must wait until independent topology, recovery and client verification have
been demonstrated. Authenticate the PostgreSQL server
with `SSL Mode=VerifyFull` and a pinned private CA/root certificate, and keep
the provisioning and runtime database roles separate. This is internal service
authentication, not a requirement for users to own public certificates.

Provisioning order for isolated UAT: create the schema with a DBA role; verify
the signed empty ADH1; provision ADA2 from that exact head; set the floor
connection using a provisioning role and run `did2-directory provision-floor`
exactly once; switch the runtime DSN to a role with only `SELECT`/`UPDATE` on
the floor table; enable DID2 admission/proof. A repeated provisioning command
must fail. Keep the DSN and credentials out of the repository. If the floor
has advanced but ADA2 replacement failed, restore the matching or newer
verified ADA2 from independent backups; never move the floor backwards or
reinitialize it from the older file. If the external floor itself is missing
or rolled back, keep endpoints closed and reconcile against independently
retained signed heads and audit evidence before any operator repair. Test a
stale-file restore and a floor outage before production approval.

The DID2-only proof issuer derives current/non-membership
material directly from the fully restored ADA2 journal under its exclusive
lease. It consumes a durable nonce before accessing witness custody, reads a
signed exact XNV1, and issues and self-verifies a live DTT1/ADP1 V2 using the
PQ verifier. Its nonce ledger must use a separate path/key from V1 if it is
ever composed for a deployed service. In UAT, an explicitly enabled
`POST /api/v2/account-directory/proofs` accepts only the exact bounded `DPQ2`
frame and returns `DPP2`; it shares the bounded admission gate but uses its
own durable one-use nonce ledger. The public route remains disabled by default
and cannot start in production without the attested floor gate. An arbitrary 32-byte leaf query is
not accepted: the leaf is derived from the exact DID2 carried by the frame.
The independent rollback floor, DAB2-bound client verification and physical
E2E remain production gates.

The issuer now sets DTT1 `issued-at` to the authenticated observation and
allows at most 30 seconds until `expires-at`, clipped by the issuance epoch,
XNA1/DTS1 policy and current ADH1 validity. If the complete uncertainty
interval leaves no post-observation lifetime, it refuses to issue. The former
`expires-at = observed + uncertainty` made any subsequent client monotonic
second fail. A Registry↔client-shared TestServer integration now creates a
real DID2 account, admits it, verifies live DTT1/ADP1 V2 and durably commits
the SQLCipher floor. This is local contract evidence, not physical E2E.

The internal issuer also accepts the candidate `DPQ2` frame: exact ADL1 V2
plus exact DID2, nonce, boot ID and monotonic sample. It derives the leaf,
matches the ADL1 lookup, resolves the caller's generation/hash floor only
against the restored ADA2 head history, and encodes a `DPP2` response with
exact ADH1/DTT1/ADP1 V2. Framing and cross-links are shape checks only;
production freshness still requires the public DID2 verifier and an
independently verified XPoint authority on the client.
