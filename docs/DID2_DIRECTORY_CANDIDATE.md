# DID2 Registry admission candidate

## Automatic time and historical distribution (2026-09-29)

The candidate Registry Dockerfile packages the reviewed DevOps NTS observer
at `/usr/local/bin/deep-nts-observer` for the actual `TARGETARCH` (amd64 or
arm64), using the pinned Go builder, locked modules and observer unit tests.
Build with both named contexts, `deep_protocol` and `deep_devops`, and record
both exact revisions in `DEEP_PROTOCOL_REVISION`/`DEEP_DEVOPS_REVISION` labels.
The candidate publishers do this from their checked-out source graph; no
prebuilt local helper is copied. The helper is an operational process, not a
new dependency in Protocol's exact-three .NET assembly graph.

Image presence does not activate automatic time, create an NTS floor or
restore proof readiness. Upgrading an existing manual-anchor deployment must
preserve its authority, ADA2, independent head floor, nonce ledger and custody.
Do not rerun `provision-state` on initialized ADA2 to obtain a missing NTS
floor, and do not change signed policy or trust OS/HTTP time to pass readiness.

The explicit existing-directory transition is defined by
[DR-0068](../../docs/survival-program/decisions/DR-0068-manual-to-nts-protected-floor-upgrade.md).
Stage the intended automatic-time configuration, including an absolute,
distinct `NtsLowerFloorPath`, and run the candidate operator command once:

```text
dotnet Deep.Registry.Api.dll did2-directory provision-nts-floor <retainedManualAnchorSha256>
```

The caller must retain the exact independently obtained protected manual-anchor
hash; no server-reported value is accepted as operator approval. The command
keeps that anchor unchanged and creates the separate floor, pending stage and
one-time fence. Interrupted pre-activation execution can resume with the same
hash and exact authenticated stage. Existing floors, corrupt/conflicting stages
and a completed fence with missing floor reject. Preserve the fence alongside
the current floor during backup/restore; do not delete it to retry provisioning.
The runtime is unavailable until new authenticated source acquisition succeeds.
The command does not reset initialized ADA2 or the external head floor, renew
signed authority/operational views, or assert production/device readiness.

`ContactResolveProductionAuthority:AutomaticTrustedTimeEnabled` selects the
owned persistent NTS observer, whose absolute executable path is supplied by
`NtsObserverExecutablePath`. `NtsLowerFloorPath` is a separate durable,
integrity-protected lower rollback floor,
explicitly provisioned file: `did2-directory provision-state` creates its
initial signed-policy lower bound with CreateNew, alongside first-time ADA2
custody. That lower bound is not current time. Missing or corrupt floor on
startup/acquisition rejects, never resets; restore the retained file rather
than rerunning provisioning on an initialized directory. Signed DTS1 sources, TLS/SPKI,
authenticated NTP packets, independent source-family quorum and bounded
monotonic age must all verify. Every process boot reacquires upper time;
retained lower state is not a freshness anchor. Acquisition/floor failures
make proof readiness unavailable without resetting state. Missing/corrupt
startup custody is a fatal configuration error, not a transient network failure.

Startup reacquisition and transient independent-floor/time unavailability are
logged as warnings and still return readiness/proof 503. Invalid cryptographic,
custody or configuration state remains Error severity. The head-renewal worker
logs recovery after the next successful protected-authority check. Known transient
NTS/floor loss retries after 5/10/20/40 seconds, capped at the configured maintenance
interval; successful checks restore the normal cadence. Invalid crypto/custody/
configuration keeps the regular cadence. This avoids waiting the full normal
interval after startup dependencies return; every retry still verifies fresh time,
the complete journal, signatures and the independent floor before renewal.
Logs expose the exception type and a closed static reason code (otherwise
`unclassified`), never arbitrary messages, source identifiers or custody paths.
Diagnostic labels do not change authority checks or HTTP status codes.

The read-only production check on 2026-10-02 confirmed readiness 503 and the
source-whitelisted `manual-time-anchor-stale` failure in the deployed manual
time composition. Automatic NTS was not enabled. These are live diagnostic
findings, not evidence of a repaired deployment. The stale-anchor and monotonic
reset labels remain Error severity and expose neither the anchor nor paths.
Enabling a helper alone does not provision a missing floor or repair expired
signed network/directory authority.

`/api/v2/account-directory/history` distributes source-bound DHQ2/DHR2 pages
from the authenticated journal under the independent PostgreSQL floor. It is
read-only and is never a freshness capability. Unknown historical sources
return 409; dependency unavailability returns 503 with bounded scheduling
metadata. See the single normative owner
[DR-0014](../../docs/survival-program/decisions/DR-0014-directory-historical-catchup.md).
The real development topology and required explicit first-time floor
provisioning are in [Deep DEV](../../deep-devops/docs/DEEP_DEV.md).

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
| `HeadRenewalEnabled` | Optional protected-time head renewal; default `false`; requires admission, proof and external floor |
| `HeadRenewalLeadSeconds` / `HeadRenewalIntervalSeconds` | Default 300/60 seconds; the poll interval must be less than half the lead |
| `ProofEnabled` | Optional UAT `DPQ2` proof endpoint; required for production; default `false` |
| `ProductionCutoverAttested` | Operator attestation after independent floor topology, restore drill and client E2E; default `false` |
| `CurrentXnv1Path` | Exact signed current XNV1 supplied by the authority owner |
| `ProofRequestLedgerRootPath` / `ProofRequestLedgerIntegrityKeyPath` | Separate V2 one-use nonce ledger root and nonzero 32-byte HMAC key; neither may alias V1 custody paths |

First configure protected trusted time and threshold witness custody under
`ContactResolveProductionAuthority`, and verify their network and key files.
An operator's uncertainty must fit the signed XNA1 maximum and leave a usable
nonce-proof lifetime; a ready head alone does not prove this. After independently
checking UTC and confirming no host reboot, `contact-resolve-authority provision-time`
can narrow an existing anchor with `--refine-current-interval true`,
`--expected-state-sha256` and the usual observed/valid-until/uncertainty options.
Unknown flag values reject. The command retains authenticated generation and
predecessor custody and refuses a backwards monotonic sample, equal/wider
uncertainty, observations outside the advanced interval and stale CAS before
mutation. It never resets ADA2, floors or nonce ledgers. The bounded rule and its
reboot non-claim are owned by
[the trusted-time specification](../../docs/architecture/ACCOUNT-DIRECTORY-TRANSPARENCY-V1.md).
Do not reduce uncertainty merely to pass readiness or infer time from a request.

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
of independent backup/restore topology or the physical client gate. Startup
validates configuration and constructs authority/proof custody, but a transient
external-floor outage or unavailable time does not terminate the host before
its recovery worker starts. `/health/live` may return 200 while DID2 readiness
returns 503. Readiness verifies trusted time, signed authority, the complete
ADA2 journal, its exact external floor and (when proof issuance is enabled)
the canonical signed current XNV1 and its complete issuance-time window using
the Protocol authoring boundary. It never consumes a nonce or writes state.
Actual admission and proof requests independently perform their required
checks; readiness is not authorization. Corruption, rollback and forks remain
closed, not repaired by retry. UAT may explicitly set
`DeepIdV2DirectoryAuthority:Enabled=true` and keep
`AccountDirectoryAuthority:Enabled=false`.

When explicitly enabled, head renewal re-reads the protected monotonic
trusted-time anchor, the complete ADA2 journal and independent PostgreSQL
floor before signing a content-preserving successor. The hosted worker attempts
renewal on activation and then checks at the bounded interval, including after
dependency outages, timeouts and dependency-owned cancellation while the host
token is not canceled. Host shutdown still cancels promptly. Readiness treats
that dependency-owned cancellation as unavailable, not a fresh capability.
A successful renewal preserves tree size and both map/log roots and advances
the external floor before replacing local ADA2. Missing,
stale or reset trusted time, insufficient witness custody, expired network
authority and floor failures all remain fail-closed. This feature does not
provision or rotate a trusted-time anchor, and must not be presented as a
substitute for the required independent time-source and recovery evidence.
On Linux, startup rejects repeated raw `DeepIdV2DirectoryAuthority__*`
environment names even when their values are identical: .NET configuration
would otherwise hide which override won. Compose one effective value per
setting before starting a new container; do not rely on duplicate `-e` flags.
Docker can normalize repeated `Config.Env` names before creating the process,
so this startup guard alone cannot detect duplicates in the container
definition. Before promotion, inspect the exact candidate with the
`deep-devops/scripts/check-did2-registry-container-env.mjs` host-side
preflight; it checks Docker `Config.Env` without reporting values.

Do not enable this candidate in production yet. The PostgreSQL latest-head
floor is deployed separately from Registry ADA2 and contains the exact signed
empty head. Its logical dump restored that row byte-for-byte in a temporary
isolated database. Host/DI regression tests cover repeated floor outages and
process recreation with exact retained ADA2; they substitute the database
transport and are not real PostgreSQL/TLS or Docker recovery evidence.
Old-ADA2 rejection and complete real-topology role recovery remain separate
gates. V2 current proof publication, client
cutover and physical Android↔Windows E2E are also open gates. The client must
never trust the admission receipt alone as a fresh directory or contact proof.

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
