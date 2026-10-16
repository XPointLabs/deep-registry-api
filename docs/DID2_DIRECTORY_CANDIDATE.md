# DID2 Registry admission candidate

Private grant composition and external signer prerequisites are documented
in [DID2 private mailbox grants](DID2_PRIVATE_MAILBOX_GRANTS.md); admission
readiness alone does not prove mailbox grants or physical delivery.

## Automatic time and historical distribution (2026-09-29)

### Network catalog source cutover (2026-10-02)

Network catalog writes now require the current DID2 admission/proof authority
and `DirectoryPublication:RequestedDid2Path`, an absolute path to the exact
public DID2 credential used by the catalog publisher's proof query. Never
supply a recovery phrase, private key or resolver read capability at this path.
The verifier derives the exact query locally and reads the current authenticated
ADA2 head under the independent external latest-head floor. It accepts only
reader version two and ADP1 V2, rechecks the head before release and projects
retention time using the actual protected monotonic elapsed interval. The
existing write envelope is not extended or interpreted as identity authority.
Missing current authority/context stays closed; mirror-only byte distribution
does not assert freshness. Update staged configuration with the matched source
graph before rollout; do not reset ADA2, nonce markers or floors to make it start.
Positive joined/native catalog, full linked consumer and live/device gates
remain pending. See the single normative source
[DR-0069](../../docs/survival-program/decisions/DR-0069-did2-retired-identity-surface-removal.md).

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

`did2-directory inspect-authority-window` reads and verifies only the pinned
XNA1/DTS1 lineage, then reports a closed schema of its validity bounds with
`currentTimeEvidence=false`. It opens no time key, floor, account or journal.
Those signed bounds are constraints, not observations; do not use the report
as DTT1, an NTS measurement or readiness approval.

After explicit floor activation, `did2-directory observe-trusted-time` starts
the packaged observer against the verified signed policy, waits at most 30
seconds for fresh authenticated quorum and persists its lower floor before
reporting the observed interval. It neither reads the stale manual anchor nor
falls back to it. The closed report contains only schema, observed Unix seconds,
uncertainty and `reusableFreshnessEvidence=false`; it is an operator observation,
not DTT1, a transferable freshness capability or readiness/device approval.
No account, head or nonce ledger is mutated. `refresh-current-head` selects
this same automatic owner when enabled; manual configuration retains its
existing protected monotonic owner. Automatic acquisition failures remain
closed, including timeout, source loss and invalid custody.

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

An acquired NTS response can wait while readers advance the protected lower
floor. The acceptance path now projects both source and prior-anchor intervals
to the actual monotonic acceptance sample before intersecting the current floor.
Its remaining sample age subtracts that queue delay: the original deadline does
not restart. Stale/rolled-back samples, clock reset, missing/corrupt floors and
policy expiry still reject without resetting or rewriting custody. No signed
policy, source, key, wire, floor format or lifetime is changed.
The deterministic queued-response regression originally failed with a false
floor-rollback (`nts-queued-observation-red-01`). Matching focused
`nts-queued-observation-03` passed37/0/0,
native0, including the original freshness boundary and three queued invalid
cases. `nts-queued-observation-02` retained3 fixture-setup failures because the new negative cases
advanced beyond that fixture's original sample-age bound before testing the
denial; their setup was corrected, not the production bound. These receipts are
under artifacts/s05-current-publication-20261015/ and are not full PG/runtime or
physical qualification. A deployed floor-rollback label alone does not identify
this particular cause; retained runtime recovery must still be observed.

Private NTS diagnostics distinguish the closed `policy-scope`, `acquisition-age`
and `observation-quorum` failures instead of the former combined label. The same
initial predicates still reject before floor mutation; no source/process output
or identifiers enter logs. Focused `nts-acquisition-diagnostics-04` passed40/0/0,
native0, including the prior37 cases and distinct missing-quorum/stale-acquisition
refusals with unchanged floor bytes. This is not full or deployed evidence.

The internal time-source owner separately exposes its actual boot/monotonic
sample, without UTC, source freshness or floor authority. Mailbox context's
`IOnionMonotonicClock` now uses that reading to advance an already verified
nonce-bound freshness proof, instead of reacquiring an NTS interval for every
pure Protocol clock check. Initial proof acquisition, actual UTC interval reads,
current source/floor checks, signer guards, journal callbacks and final release
checks are unchanged. Manual protected-anchor custody retains its authenticated
boot reader; there is no wall-clock, cached-current flag or alternate authority.
Other contact issuers retain their former clock adapters in this bounded slice.

Focused `owned-monotonic-clock-07` passed44/0/0/native0 through the supported
disposable PostgreSQL provider:42 NTS cases and the actual mailbox renewal and
TLS-proof/node-consumer cases. The new negatives prove monotonic sampling alone
cannot supply trusted time, renew freshness, write/repair a missing floor or
ignore cancellation. The broader unactivated candidate06 retained51PASS/5FAIL
(mailbox readiness, PostgreSQL timeouts and native grant-cycle); candidate05
retained42PASS/14 prerequisite FAIL because it lacked the required disposable DB.
Neither earlier run is reclassified, nor does the focused44 qualify the full
source/runtime/release. Runtime performance and retained physical clients remain
to be observed on this narrower source.

Signed MGR byte distribution now has its own single non-queuing reader, separate
from readiness/renewal exclusion. A slow read-only health probe cannot deny that
unrelated control read merely by holding the readiness owner. Actual journal
transactions still serialize exact signed winner/history selection against
independent issuers; unsigned pending inputs are never responses. Scope,
signature/host/source verification, before/after callbacks and the original
five-second read budget remain. HTTP control admission still allows one request.
`control-readiness-red-08` reproduced503 at the new concurrent-health assertion;
matching `control-readiness-09` passed44/0/0/native0, including retained writers,
pending/changed sources, stop/cancellation and TLS consumers. Its provider TRX is
under `artifacts/s00/owned-monotonic-clock-07-8d1a76cecbb64142a8c065083027f390/`
(the outer09 envelope names the exact native path; the provider lane label was
not changed). This is focused provider evidence, not full or physical acceptance.

Startup reacquisition and transient independent-floor/time unavailability are
logged as warnings and still return readiness/proof 503. Invalid cryptographic,
custody or configuration state remains Error severity. The head-renewal worker
logs recovery after the next successful protected-authority check. Known transient
NTS/floor loss retries after 5/10/20/40 seconds, capped at the configured maintenance
interval; the worker adds 0–2 seconds of jitter, capped by the existing
300-second polling ceiling and strictly below half the renewal lead.
Successful checks restore the normal cadence. Invalid crypto/custody/
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
closure, and appends to separately provisioned ADA2 state. The V1 admission,
proof-package and targeted-current-value hosts have been removed by
[DR-0069](../../docs/survival-program/decisions/DR-0069-did2-retired-identity-surface-removal.md).
The retired `AccountDirectoryAuthority`, `ContactResolveDirectoryArtifacts`
and `TargetedCurrentValueDirectoryPackages` configuration sections must be
absent, even when disabled or containing only unknown fields. This source
cutover does not delete deployed custody, journals, floors or registered keys.

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
`DeepIdV2DirectoryAuthority:Enabled=true`; omit all retired sections entirely.

When explicitly enabled, head renewal re-reads the protected monotonic
trusted-time anchor, the complete ADA2 journal and independent PostgreSQL
floor before signing a content-preserving successor. The hosted worker attempts
renewal on activation and then checks at the bounded interval, including after
dependency outages, timeouts and dependency-owned cancellation while the host
token is not canceled. One linked 30-second cancellation budget covers waiting
for the authority gate, time acquisition, signing and durable completion;
individual dependencies do not receive a fresh independent worker deadline.
A timed-out flight leaves retained intent/floor recovery to the existing owner,
never resets or provisions authority. Cancellation requires dependencies to
honor their token; this is not forced process termination. Host shutdown still
cancels promptly. Readiness treats
that dependency-owned cancellation as unavailable, not a fresh capability.
A successful renewal preserves tree size and both map/log roots and advances
the external floor before replacing local ADA2. A
changed current XNA1/witness-policy binding requires immediate head renewal,
even when the historical head has not reached its expiry lead. Readiness remains
unavailable until the existing threshold author commits a current-authority
successor. Full verified ancestor history still authenticates retained heads;
old heads are not rewritten, re-signed in place or accepted as current proof
authority. Cold restart restores the same current head/floor without another
generation. The diagnostic reason is `head-authority-renewal`, with no custody
values in logs. Missing,
stale or reset trusted time, insufficient witness custody, expired network
authority and floor failures all remain fail-closed. This feature does not
provision or rotate a trusted-time anchor, and must not be presented as a
substitute for the required independent time-source and recovery evidence.

The protected-file writer retries only the same flushed atomic rename after
Windows access/sharing/lock errors5/32/33, at most five delays totaling1550ms.
It never copies over or deletes the old file, alters permissions, regenerates a
signed candidate or accepts a partial write. Persistent failure still throws
and leaves the prepared `.writing` file. This bounded retry is not permission
to reset either restore domain. The ADA2 mutation owner additionally persists
the exact verified candidate at `StatePath + ".pending"` before external CAS,
then replaces primary ADA2 and clears pending custody. Preserve this file with
primary ADA2 in quiescent backups; the PostgreSQL floor remains in its independent
restore domain. Never delete a pending file to restore readiness or overwrite it
with a newly generated head/admission.

On the next admission/renewal flight, that owner reauthenticates the complete
primary and pending ADA2 from the original genesis, checks their exact prefix and
single successor, and queries the actual external floor. Only an exact candidate
match or exact predecessor CAS can complete the same commit. A completed local
replacement with unfinished cleanup requires byte-identical files and a matching
floor. No callback signs another head merely to finish that intent. An expired
prepared head completes as history, then ordinary current-authority renewal must
independently supply freshness. Missing/corrupt primary or pending custody,
unavailable/lost/unrelated floor and invalid lineage all remain fail-closed.
Readiness/history/proof reads refuse an unfinished pending commit and never
complete CAS or change files. The hosted renewal worker owns bounded recovery;
when it is disabled, a normal authorized admission retry can complete its retained
intent. This does not assert process/power-loss recovery without matching evidence.
The sole contract is [DR-0115](../../docs/survival-program/decisions/DR-0115-did2-prepared-directory-commit.md).
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
PQ verifier. Retain its separately provisioned path/key and protected nonce
markers on upgrades; the removed V1 issuer is not an available fallback. In UAT, an explicitly enabled
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

## DID2 proof resource budget

The DID2 host uses a separate process-local admission budget: 32 requests per
source per 10-second window and a global burst of 64, refilling at most 16 each
10 seconds (unused credit never exceeds 64), shared by its genesis/proof/history
routes. The contact issuer's independent budget is unchanged. These are local
resource defaults, not protocol freshness or a cluster-wide availability claim.
The actual DID2 proof ledger is explicitly provisioned for 200,000 retained
markers: `64 + (86400 / 10 + 1) * 16 = 138320` public admissions plus at most
`(86400 / 10 + 1) * 6 = 51846` private route/publication proof requests behind
the existing shared contact admission gate, leaving 9,834 entries of finite
boundary/crash headroom. Each private issuer obtains one fresh proof before
route/publication signing or replay verification. Enabling them must not count
that shared-ledger demand as unused crash margin. The ledger format, epoch and key/path
are unchanged; upgrading the capacity never deletes existing markers or reopens
a nonce. Corruption, rollback, a full ledger and excess requests still fail closed.
Repeated process restarts can consume that finite margin; monitor storage and
keep one active issuance owner. Do not present this arithmetic as protection
against unbounded restarts or a sustained-throughput guarantee.

Reserve disk space and inodes for the full marker bound before rollout; a marker
uses a separate durable file, not only its payload size. Retain the exact existing
ledger path/key, directory state, independent floor and signer custody on upgrade.
The focused burst test models client preparation, both replicas' fragments/final
proofs and three background refreshers. It is local admission evidence, not native
publication or physical message delivery; the guarded device retry remains required.

## Private DID2 contact coordination deployment

Private route and current reusable-publication issuance may wait for the existing shared
distribution/renewal owner instead of immediately failing on contention. There
is still at most one active operation and at most one queued private issuer
per process. A further issuer rejects without proof or journal/signing work.
Public closure fetches now have one separate admission waiter: a busy private
owner need not cause all eight bounded client read attempts to fail with429.
Further public requests still reject without reading/buffering another frame;
background renewal remains non-queuing. There is no parallel signer/frame
execution, per-caller cache or larger payload allowance. Waiting uses
the same original 30-second whole-operation deadline, with cancellation removing
the waiter without releasing another owner's permit. After admission the full
current proof, time, original-intent and permanent-winner checks still run;
waiting never renews a signed resource or changes unknown completion to noncommit.
This bounded scheduling change is not throughput or physical-delivery evidence.
The retained Android29 attempt reached the route backend and received503;
the matching Registry log identifies `Admission/busy`. Route issuance now uses
the same single private waiter as current publication, not an additional queue.
No command is resubmitted and no proof, permanent winner or resource is renewed
by waiting. The focused cancellation regression first failed on the old
immediate-rejection path (`s05-route-admission-20261016/red-01`, native1/1FAIL).
The corrected route HTTP/admission/distribution scope passed43/0/0/native0
under Windows PowerShell5.1 / SDK10.0.301 (`green-02`). This is admission and
TestServer evidence, not PostgreSQL issuance, deployed recovery or device E2E;
the mandatory full source qualification and retained physical retest remain.
The original deadline starts before public admission and covers both waiting
and the existing complete response write. Cancelling a public waiter cannot
release the active owner or the independent issuer waiter. Focused
`public-read-admission-focused-01` passed15/0/0/native0 on Windows PowerShell5.1;
these are actual TestServer/admission/file tests with shape-only public bundles,
not signed authority, PostgreSQL, deployed throughput or device-delivery proof.

The current route/publication terminals require the existing production witness
custody, trusted time, DID2 proof issuer, complete signed network bundle and
independent floor connection. Provision the exact permanent schemas in that same
independent restore domain using
[did2-route-threshold-journal.sql](sql/did2-route-threshold-journal.sql) and
[did2-publication-journal.sql](sql/did2-publication-journal.sql), then explicitly
insert each network capacity row. Runtime never creates them. Keep the runtime
role distinct from the DBA: SELECT on all four tables, UPDATE(entry_count) only
on capacity rows, INSERT and UPDATE(exact_response) only on request journals;
no schema CREATE, DELETE/TRUNCATE or updates to retained request/capacity columns.
Retain logical backups with the external floor; never recreate an empty journal
after a lost-response or observation failure.

Enable both contact authority sections together with the DR48 registered-node
access list. The reverse proxy adds only their two exact V2 coordination paths
on the existing listener/security include. A route or a registered-node signature
is not proof of publisher, witness, placement or current account authority.
The coordinated XNode candidate is prepared/staged by the supported DevOps and
installer workflow, with the retired ContactService runtime still disabled.
An empty unauthenticated 401 verifies access gating, not successful issuance;
actual three-hop device publication/claim and message delivery remain required.
The owning contracts are
[DR36](../../docs/survival-program/decisions/DR-0036-did2-route-threshold-coordination.md),
[DR38](../../docs/survival-program/decisions/DR-0038-did2-publication-coordination.md)
and [DR48](../../docs/survival-program/decisions/DR-0048-private-contact-coordination-peer-authentication.md).

Operator provisioning evidence (2026-10-02): all four previously absent tables
and two explicit 4,096-entry capacity rows committed in the independently hosted
floor database. Effective runtime column permissions and empty initial journals
read back correctly. Before/after logical dumps were retained and copied to local
private backup custody with matching hashes. Existing floor rows and credentials
were not written by provisioning. This is not an issuance, restore drill or
device-delivery claim; full recovery gates remain open.

Contact activation follow-up (2026-10-02): the same `1c1a6cb` image now runs with
route/publication enabled and the three existing registered nodes in the DR48
access list. Only those five environment entries changed; the previous owner is
stopped and retained. Both readiness routes passed, all seven checked custody
files and 2,987 retained proof nonce markers matched, and a fresh quiescent backup
was retained. The two exact proxy routes were added with the existing upstream
and security include after nginx validation. Public unauthenticated POSTs returned
401; this proves access gating, not witness issuance. Public and origin-local
HTTPS closure responses both returned the full 19,670 bytes with the same retained
SHA-256. The supported `7d918c6` installer activated the closed contact profile on
all three nodes, preserving registered Ed25519/BLS keys and named state volumes.
Read-only checks found coordination/resolver/claim enabled, retired contact/group
runtimes disabled and readiness 200. Mailbox authority readiness remains false.
A guarded Android retry with VPN still hit route authenticated-time coverage
rejection; its particular artifact and failure direction are not yet established.
Contact delivery, grants, messages, attachments and groups remain open physical gates.

## Earlier production proof-budget rollout evidence

Production follow-up (2026-10-02): the Linux AMD64 `1c1a6cb` image was installed
with the previous environment, mounts and loopback listener unchanged. The old
owner is stopped; both readiness routes returned 200. The directory/proof keys
and all 1,785 retained nonce markers matched before/after, and a private quiescent
state/time-floor backup was retained. Public Registry/DID2/staking requests returned
200; the complete network closure still matched the retained export. No proxy,
certificate, signer or independent-floor reset was performed.

The first guarded Android action after upgrade still failed at pre-key publication.
After current host readiness recovered, one exact protected retry advanced to
`ContactPublication (TransportIo)`: the preceding account-owned pre-key operation
returned its authenticated pair and recorded/revalidated protected completion.
This does not distinguish first dispatch from exact replay or prove present
replica availability. Contact composition and full physical message/asset/group
delivery remain open; no GitHub release or main merge was performed.
