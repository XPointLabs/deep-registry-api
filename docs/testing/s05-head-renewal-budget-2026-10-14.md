# S05: bounded directory-head renewal

Owner: Mr. X. Status: focused source check passed; S05 remains open.

The actual hosted DID2 directory-head worker now applies one linked 30-second
cancellation budget to the existing authority operation, including its gate,
trusted-time acquisition, signing and durable completion. Dependencies must
honor cancellation; the worker does not forcibly terminate them. Retained
signing intent and independent floor recovery remain owned by the existing
authority. No wire, identity, key, lifetime, assertion or persistence format changed.

Polling adds 0–2 seconds of jitter without exceeding the existing 300-second
ceiling or half the configured renewal lead. Existing failure classification
and exponential backoff are unchanged. Operator behavior belongs to
[the DID2 guide](../DID2_DIRECTORY_CANDIDATE.md).

The first diagnostic build stopped before tests with CS2012/MSB3026 while
parallel source-reference builds contested the same ProfileCarrier DLL.
Its native exit was1; it is not a product test failure or a passing receipt.
The disposable provider was removed. The existing DevOps filtered provider
lane now builds serially with shared compilation/node reuse disabled;
the canonical full branch remains unchanged.

The repeated matching scope compiled the whole Registry test graph and passed
**31/0/0**, native exit0. It includes the actual PQ admission/renewal authority,
caller cancellation, the real 30-second worker timeout with no caller deadline,
unchanged ADA2 bytes/floor advances, subsequent ready operation, four existing
host floor-outage recovery cases and diagnostic/jitter bounds. The blocked time
source is test-owned; production TLS, external signer failure and cancellation
during an actual durable commit are not proved by this added timeout case.

```powershell
& ../deep-devops/scripts/test-registry-postgres.ps1 -Lane s05-head-renewal-budget-serial -Filter 'FullyQualifiedName~DirectoryPublicationDiagnosticsTests|FullyQualifiedName~DeepIdV2DurableGenesisAuthorityTests|FullyQualifiedName~DeepIdV2DirectoryAuthorityHttpTests.ProductionHostSurvivesFloorOutageAndRecoversReadinessWithoutReset'
```

Receipt under Registry:
`artifacts/s00/s05-head-renewal-budget-serial-778beea2e6504c678e83e5fea75d0459/nikit_SURFACE-LT_2026-10-14_08_48_03_net10.0.trx`.
SHA256: `732BB4524FCC6674D5888CDAF736B127FFD39538A75DF2BE524C7AF90E16887B`.
The common TestGate reader checked31 exact case/definition/execution mappings.
Windows PowerShell5.1.26100.9457, SDK10.0.301. The owned loopback PostgreSQL
container and tmpfs were removed; no production connection/volume was used.

Separate serial whole-solution Release source-cutover build with warnings as
errors and no restore passed0, **zero warnings/errors**. Common native runner
interval:2026-10-14T03:49:50.6380195Z–2026-10-14T03:49:54.4384366Z;
log:`release-build.log` beside the receipt. Dependency configurations remain
those selected by the existing project graph; this is not a shipping matrix.

No unfiltered full, deployment, device result, Release/main mutation or S05
acceptance is claimed. Finish provisioning/rotation/catch-up and the remaining
[S05 criteria](../../../docs/architecture/IMPLEMENTATION-PLAN-V1.md#s05--current-issuer-и-автоматический-lifecycle-управляющего-контура)
before its final integrated gates. S06 is not opened; physical contacts/messages/
files/groups remain0/4.

## Immediate authority handover

Current Registry renewal now treats a changed terminal XNA1/witness-policy
binding as due, independently of head expiry. Readiness refuses the old head
until a new threshold-signed, content-preserving successor commits through the
existing external floor/local ADA2 path. No signature, time, floor or journal
validation is removed; historical heads authenticate under their own ancestor.

The actual nonempty PQ admission/ADA2 test now appends a genuinely root-signed
same-key XNA1/DTS1 renewal and a witness-signed predecessor-linked view. Cold
Registry restores original history with that complete authority chain. Before
renewal readiness/proof issuance readiness reject without changing ADA2/floor;
renewal occurs while the old head is still valid, advances the floor once, and
preserves its single admission/transition. Next warm/cold checks do not author
another head. Independent DID2 current-proof verification succeeds under the
new authority and the actual protected-store/floor head passed in the request.
The proof response is not used to self-pin a caller floor.

Matching run04 passed **29/0/0**, native0. Common receipt reader checked29 exact
case/definition/execution mappings. It compiles the whole Registry test graph;
this remains a filtered source scenario, not the full S05 gate, real HTTP/TLS,
changed-witness/root custody, PostgreSQL process crash or physical device proof.
Owned loopback provider/tmpfs were removed; no production connection was opened.

Receipt under Registry:
`artifacts/s00/s05-authority-head-transition-04-3ff33fb12f89444c9ece33fa30443a46/nikit_SURFACE-LT_2026-10-14_10_22_00_net10.0.trx`.
SHA256: `CCE14A47DE95B7AD86C8B9EE520AA238E1467F6B965260D310725258DE55784B`.
Windows PowerShell5.1.26100.9457 / SDK10.0.301. Separate whole-solution Release
build with warnings as errors passed0/zero warnings/errors, using the common
native runner:2026-10-14T05:24:35.5585742Z–2026-10-14T05:24:39.0444229Z;
log:`release-build.log` beside the receipt.

Run01 stopped before tests because the added fixture call was initially placed
before local declarations; it was moved after the existing renewal cycle.
Run03 retained28/1/0: independent verification correctly rejected a proof whose
test request omitted the supplied caller floor. The request now passes the actual
protected-store floor; no ADP1 assertion/guard was weakened. Those failed runs
remain separate, not counted as acceptance. S05 remains open.

The additional matching HTTP consumer recovery scope passed **4/0/0**, native0.
The common reader checked the four existing `failureKind: 0..3` theory cases,
including their unique case/definition/execution mappings. This uses the actual
ASP.NET Core test host and disposable PostgreSQL provider, not physical devices
or a deployed TLS endpoint. No new HTTP test case was added for this handover.
Receipt under Registry:
`artifacts/s00/s05-authority-http-consumer-508cae3e47114777a0fc28131edd09fd/nikit_SURFACE-LT_2026-10-14_10_28_34_net10.0.trx`.
SHA256: `54BEB6C655231E18EE9E651CF0A6BCBF2303967BB6FC36C0968EB4235EB53A85`.
The owned provider/tmpfs were removed. A follow-up diagnostic incorrectly
expected three cases; the source and exact receipt both contain four. That
diagnostic expectation was corrected without rerunning or changing the tests.

## Changed root and witness keys

The connected nonempty ADA2 scenario additionally follows the same-key renewal
with a genuinely signed root/witness-key rotation. XNA1 authenticates under its
predecessor root and DTS1 under the new root; the unchanged genesis pin verifies
the complete three-pair chain. The new predecessor-linked view uses the new
witness keys. Old file custody fails before ADA2 or the independent floor changes.
New file custody advances exactly one content-preserving head, and warm/cold
readiness, no-op renewal and independent current-proof verification succeed.
Historic heads remain under their own original authority; the admission and
transition are not re-created. Generated private fixture material is test-owned
and cleared/deleted with the existing fixture cleanup. This is not an operational
changed-key ceremony, deployment, live signer outage or physical device result.

Matching source scope passed **29/0/0**, native0, with29 exact mappings checked
by the common reader:
`artifacts/s00/s05-authority-key-handover-01-01e52059b13b461c882b71707efb29b2/nikit_SURFACE-LT_2026-10-14_10_37_55_net10.0.trx`.
SHA256: `98084EFF5831F92D60234145095FA0EAE5FA34AEF11896F98D86C73E6E139424`.
No new top-level test count is claimed: the rotation extends the existing real
PQ admission fact. The owned PostgreSQL provider/tmpfs were removed. Only local
test-source indentation changed after this receipt; no full byte-identical input
claim is made. S05 remains open, including supported changed-key provisioning,
retained-volume author/node recovery and bounded client catch-up.

Separate matching whole-solution **source-cutover** Release build passed0,
zero warnings/errors, through the common native runner with the repository's
`DeepProtocolLocalCutover=true` and `DeepProtocolSourceCutover=true` flags.
Interval:2026-10-14T05:40:08.1954276Z–2026-10-14T05:40:21.7405068Z;
log:`release-source-build.log` beside the receipt. The first diagnostic build
omitted those flags while using the existing source-cutover restore graph and
failed with21 unresolved package-type errors. Its native1/log remain separate;
the source-cutover build is not exact-package/shipping acceptance.

## Current issuer/CAS and socket consumer regression

The matching focused scope of five existing cases passed **5/0/0**, native0:
actual TLS proof acquisition and signed control delivery to configured node
consumers; interrupted mailbox renewal with exact retained intent/winners;
independent concurrent PostgreSQL grant writers, cold winner replay, conflict,
capacity and corruption; operator constraint cutover; and concurrent cumulative
revocation generations. No test assertion or fixture was changed for this scope.
The common reader confirmed all five exact case/definition/execution mappings.

Receipt under Registry:
`artifacts/s00/s05-current-issuer-cas-tls-01-e514337532d24fa5a36a552eb2e3bae0/nikit_SURFACE-LT_2026-10-14_10_41_34_net10.0.trx`.
SHA256: `AD913E759255EB81464476600CB5B3961857E222B22305CA9549EFDB630AA79E`.
Owned loopback PostgreSQL/tmpfs cleanup completed; no production connection or
volume was used. The socket case uses test-owned TLS custody and actual node
consumers, not physical clients, deployed three-hop routing or the changed-key
handover scenario above. These receipts cannot be combined into that unrun
end-to-end scenario or an unfiltered full/S05 acceptance.

## Two-page native consumer catch-up

A new connected source case provisions the real PostgreSQL latest-head floor,
admits one real PQ account through Registry and initializes both the account's
SQLCipher directory floor and the configured XNode native protected-head runtime.
The actual Registry renewal method authors69 signed content-preserving successors
using test-owned authenticated-time readings, taking head1 to70. A newly signed
current view covers the final observation; no signed lifetime or identity is
widened/replaced. These are fixture time steps, not an elapsed production run.

The client receives the actual first64-head history page; an injected503 on the
second request leaves only authenticated head65 committed and returns no fresh
proof. A reopened account/store keeps the same identity and head65, then fetches
the remaining five heads and a newly verified current proof. The actual configured
XNode runtime independently fetches pages64+5 from its retained head1, verifies
the current proof and keeps exact head70 after native cold reopen, without
another history request. No caller-supplied capability or in-memory floor replaces
either consumer's owned store. ASP.NET Core TestServer provides HTTP routing;
this case does not prove socket TLS, masked three-hop transport, Docker-volume
process restart or physical Windows/Android UX.

Run01 failed on fixture ownership: disposing the proof client also disposed its
owned HttpClient, incorrectly shared with the node. The fixture now gives each
owned transport a distinct client. Run02 reached actual renewal but stopped on
Windows atomic-rename denial. The protected writer now retries only that exact
flushed rename for Windows errors5/32/33, with five bounded delays totaling1550ms;
it changes no ACL, source bytes or destination contents on persistent failure.
Two added actual delete-sharing cases check successful release and persistent
rejection, retaining respectively the exact committed or old/prepared bytes.
No product assertion was removed. Failed receipts are retained separately.

Matching run04 passed **3/0/0**, native0, three exact mappings through the common
reader. Receipt under Registry:
`artifacts/s00/s05-two-page-native-catchup-04-b72de0aab5f248b0a5eb53597afec7ba/nikit_SURFACE-LT_2026-10-14_10_54_12_net10.0.trx`.
SHA256: `99B088602FDD33E251389E3FDE312CB6E17A5187526052C06AFEA5ECC864C7CE`.
Windows PowerShell5.1.26100.9457 / SDK10.0.301. Common native whole-solution
source-cutover Release build passed0/zero warnings/errors:
2026-10-14T05:55:44.5364262Z–2026-10-14T05:55:47.8661247Z;
log:`release-build.log` beside the receipt. Owned local provider/tmpfs cleanup
completed, without a production connection or named volume.

Persistent failure after external floor advance still leaves old ADA2 fail-closed.
This bounded retry does not implement interrupted floor/local commit recovery;
that S05 boundary remains open. No canonical full, stage acceptance, deployment,
commit/push, Release/main or physical claim follows from this diagnostic.

## Exact prepared directory commit recovery

The mutation owner now retains a complete authenticated ADA2 candidate before
external CAS. It recovers only that exact intent under its existing gate/time
budget/file lease and independent floor, then clears pending custody. Primary
corruption or a lost floor still cannot be repaired from pending bytes.
Readiness/proof/history reads stay read-only and refuse incomplete commits.
The sole lifecycle contract is
[DR-0115](../../../docs/survival-program/decisions/DR-0115-did2-prepared-directory-commit.md);
configuration/backup behavior is in the Registry operator guide.

First matching recovery scope passed13/0/0, native0, common exact mappings:
`artifacts/s00/s05-prepared-directory-commit-02-3ef5310ac4014b1bbff256e9d31db41a/nikit_SURFACE-LT_2026-10-14_11_10_37_net10.0.trx`.
SHA256: `47EC2BEFB4A05F852668BB5CB1C566207B72595E9A404AFD34FFCF3C1F50D77E`.
It uses actual owned PostgreSQL CAS, PQ admissions, signatures and file custody.
Injected boundaries cover pre-CAS interruption, lost successful CAS response,
persistent Windows rename denial and local-complete/pending-cleanup interruption.
Exact receipt replay, expired intent followed by new current renewal, six cold
authors, read outage, corrupt primary/pending, valid-HMAC predecessor substitution,
invalid prefix and actual deletion of the owned floor row are exercised.
The cleanup-interruption case recreates the exact observed pending snapshot;
these are controlled source fixtures, not an OS process/power-loss drill.

The expanded connected scope includes actual hosted worker start/retry/stop,
unchanged readiness while the floor times out, completion after it returns,
prepared history across genuinely signed root/witness rotation, original
route/grant consumers, immediate head handover, the30-second worker budget,
two-page actual client/node catch-up and actual Windows atomic replacement.
Run01 retained48/1/0 because the new host fixture omitted endpoint DI services.
Run02 retained49/1/0 because it incorrectly expected short transient recovery
from an unclassified IOException, whose existing policy uses the normal60-second
cadence. The fixture now uses an actual TimeoutException for that short-retry
scenario. Product severity/backoff policy and assertions were not weakened.

Matching run03 passed **51/0/0**, native0, with51 exact mappings:
`artifacts/s00/s05-directory-lifecycle-connected-03-dce0606605854009be766024c4dd801e/nikit_SURFACE-LT_2026-10-14_11_21_42_net10.0.trx`.
SHA256: `9F2CA297F931388A2618F678A588EB3802213268DA8C9BB77E7CDA5CDE1B44E6`.
Owned PostgreSQL/tmpfs cleanup completed. The standalone hosted-worker case is
an ASP.NET Core TestServer composition check, not full production TLS/DI or
retained-container restart. No source-stage or physical acceptance is inferred.
Required unfiltered full/review, process/volume/power-loss recovery and the
remaining operational S05 criteria stay separate.

## Required full: retained failures

Canonical Registry full01 completed **393/2/7**,402 exact result mappings.
Build/preflight0, native/qualification1, FullAccepted=false;2832 inputs captured.
Receipt:
`artifacts/test-gate-20261014/s05-directory-lifecycle-full-01/full/nikit_SURFACE-LT_2026-10-14_11_27_26_net10.0.trx`.
SHA256: `088EADE8267DF624133BC58A8828E2E7280798C7B63404D23CC686C8613FBAD2`.
Both failures were actual private-issuer/native-mailbox cycles, not directory
recovery: initial Store timeout/unknown outcome and ACK unknown outcome.
The seven exact original Windows skips require the Linux Unix-socket signer lane;
no new allowed failure or skip was added. Terminal native1 is not waived.

The matching native pair after bounded observation-context reuse passed2/0/0;
the node observation scope passed27/0/0. Those scopes do not replace full.
Canonical full02 still completed **394/1/7**,402 mappings, native/qualification1,
FullAccepted=false;2833 inputs captured. Receipt:
`artifacts/test-gate-20261014/s05-directory-lifecycle-full-02/full/nikit_SURFACE-LT_2026-10-14_11_50_38_net10.0.trx`.
Its remaining current private-issuer/native cycle failed at initial Store with
status504/OutcomeUnknownAfterForward under full load. No deadline/assertion is
widened, and no source acceptance/commit follows. Scoped phase measurement is
the next diagnostic. Final unchanged-input acceptance is not claimed for either
failed qualification. Owned loopback providers/tmpfs were removed.

Full02 SHA256: `E5C815F0B531FC48AFA073BFCEFEAD55DE1DFE06EBF1ADE4C6D6C61A89E2936C`.
The actual scoped phase observer then ran the native pair,2/0/0/native0:
`artifacts/s00/s05-native-mailbox-profile-01-e329ac92b1b34526b8244cbfa80b0ac6/nikit_SURFACE-LT_2026-10-14_12_19_38_net10.0.trx`.
SHA256: `BEB4F07A4C22530C24C94D381A78F31E93487E34E6B29E175B8BEB3D9B2B68BE`.
It passes arguments/results/cancellation through unchanged, observing only
closed phase counts/durations with caller-local AsyncLocal scope; no payload,
identifier, key, path or outgoing trace header is captured. Total initial Store
elapsed was9961ms/10480ms. The busiest source had175/176 calls and3343ms/3335ms
of source time, with only18ms of full network verification after reuse,975ms/
982ms of proof-observe and386ms/415ms of network-floor read. This demonstrates
reuse is active but does not establish the remaining bottleneck or full-load
deadline closure. Inspect the entire native lease/storage/peer callback path
next, retaining the original deadline and exact assertions. Do not launch another
unchanged full or relabel this isolated PASS as remediation acceptance.

The subsequent custody-walk diagnostic produced1/1/0:
`artifacts/s00/s05-native-store-custody-walk-01-f2ff3e8196db48d3bee0bb4ae9e68dee/nikit_SURFACE-LT_2026-10-14_12_41_36_net10.0.trx`.
Its original native terminal handle was lost; no native qualification is inferred
from the TRX alone. The failed initial Store reached15030ms despite a peer200
response in3994ms, identifying the total ingress deadline as the boundary.

The matching Node custody/observation scope then passed89/0/0, native0;
the [node checkpoint](../../../xnode/docs/testing/s05-observation-context-reuse-2026-10-14.md#subsequent-custody-path-remediation)
owns its exact scope and Windows path-read change. The new Registry native pair
passed2/0/0, native/wrapper0 and owned tmpfs provider cleanup:
`artifacts/s00/s05-native-store-attribute-query-01-53189587167940b88b644452c13c63e9/nikit_SURFACE-LT_2026-10-14_12_49_57_net10.0.trx`.
SHA256: `866BADFB7B7D6F5FF7A7816F7491D4F9895E0333D1306B58A5F6CC481173777E`.
Initial Store elapsed10309ms/9175ms; closed phase observations are inclusive,
isolated aggregates, not full-suite per-request performance evidence.
No assertion, peer/ingress deadline or authority lifetime was widened.
Canonical full03 is the next required check; no source/stage acceptance is inferred.

Full03 completed394/1/7,402 exact mappings, build/preflight0, native/qualification1,
2832 captured inputs, FullAccepted=false:
`artifacts/test-gate-20261014/s05-directory-lifecycle-full-03/full/nikit_SURFACE-LT_2026-10-14_12_54_19_net10.0.trx`.
SHA256: `1AFEAFBC944FD3CB26D5040957AA4B8A425D3E6A2677552559C704AF50EFE596`.
Both original private-issuer/native cycles passed. The different failure is
`ActualTlsProofAcquisitionAndSignedControlReachNodeConsumers`: a background
same-floor refresh could incorrectly latch intact custody when the Program
scenario rolls back its protected clock. This is not a timeout or native rename
denial. The [node exact-replay checkpoint](../../../xnode/docs/testing/s05-observation-context-reuse-2026-10-14.md#exact-replay-is-not-an-uncertain-write)
owns deterministic0/4 reproduction and110/0 matching remediation evidence.
Full04 will check the real Program scenario alongside all original cases;
no native FAIL is allowed. Full03 final unchanged-input acceptance is not claimed.

Full04 qualified395/0/7,402 mappings, build/preflight/native/qualification0,
2833 unchanged inputs, FullAccepted=true:
`artifacts/test-gate-20261014/s05-directory-lifecycle-full-04/full/nikit_SURFACE-LT_2026-10-14_13_02_01_net10.0.trx`.
SHA256: `F9DD60A0AD404B061DB5EC9AC74E4DF57CF0203CEBF9DC2231A35714FB29DBAC`.
The real Program rollback and both native mailbox cycles passed. The original
seven Windows Unix-socket signer skips remain separate Linux obligations.
This qualification belongs to the exact captured intermediate source.
Final review withdrew an experimental Windows attribute-sentinel optimization
to preserve device-not-ready rejection; the node checkpoint owns that correction
and final109/0/0/native0 evidence. Full05 requalifies the final stricter source;
Node full/transport/rehearsal and remaining S05 operational criteria remain open.

Final stricter full05 completed394/1/7,402 exact mappings; build/preflight0,
native/qualification1,2833 captured inputs, FullAccepted=false:
`artifacts/test-gate-20261014/s05-directory-lifecycle-full-05/full/nikit_SURFACE-LT_2026-10-14_13_09_12_net10.0.trx`.
SHA256: `3F488B2557717586F04C8497483F544602FD5C7799A18E422D9F6DD702EF9CB8`.
The Program rollback case passed. The current native Store again exceeded the
unchanged5-second peer budget (5005ms, overall13978ms). No final unchanged-input
acceptance is inferred from a failed qualification; full04 cannot qualify these
different final inputs. The provider cleanup completed.

Review also found the whole-process diagnostic listener was enabled
unconditionally despite its isolated-only interpretation. It is now opt-in via
`DEEP_TEST_NATIVE_PHASE_TRACE=1`; ordinary/full tests leave it disabled. This
is harness isolation, not proof of a runtime performance fix, and does not alter
sources, crypto, custody, deadlines or assertions. Run the matching Program/
native-issuer scope before any new full. Node full/rehearsal is not yet launched.

Matching Program/current/retained native scope passed3/0/0, native/wrapper0:
`artifacts/s00/s05-native-store-no-phase-listener-01-33200031f5b245ce8dfd9e8e5ecd81e0/nikit_SURFACE-LT_2026-10-14_13_16_16_net10.0.trx`.
SHA256: `6AA133D11139936634D243B425D28F73CE133CCF0C8603B142A5F7B4C4E8CEAB`.
The actual output confirms `aggregate-phases=disabled`; initial Store timings
were10994ms/9540ms. This does not prove full-load5-second peer-budget closure.
The supported provider wrapper now accepts `-NativePhaseTrace` only with a
filtered diagnostic, rejecting full before provider creation and restoring the
ambient environment. Its real-script orchestration contracts passed14/0,
native0; no real Docker/DB/TLS evidence is inferred from command doubles.
Do not launch another unchanged full merely because this isolated scope passed:
inspect the repeated authority/floor/recovery work inside the native peer budget
and assemble a coherent bounded remediation before final gates/review/commit.

The [coherent node batch](../../../xnode/docs/testing/s05-observation-context-reuse-2026-10-14.md#coherent-pathfloornative-replacement-batch)
then passed139/0/0/native0 and the actual Program/current/retained TLS-native
scope3/0/0/native-wrapper0:
`artifacts/s00/s05-path-floor-native-connected-01-efd77ad46e504951969e94b66a719a5f/nikit_SURFACE-LT_2026-10-14_13_36_09_net10.0.trx`.
SHA256:`115629C82CA0F628140CAA3083984E1EC192607D3BE5083A81069F0B4F6BAF98`.
Isolated Store elapsed6791ms/8348ms with all original lease/role checks and
peer/ingress timeouts. Windows proof-floor link handling and native replacement
resource behavior are owned by the node checkpoint/operator guide, not a
Registry protocol amendment. Canonical full06 requalifies the complete package;
profiling is forbidden there. No stage/production/device acceptance is inferred.

Full06 retained394/1/7,402 mappings, build/preflight0, native/qualification1,
2833 captured inputs, FullAccepted=false:
`artifacts/test-gate-20261014/s05-directory-lifecycle-full-06/full/nikit_SURFACE-LT_2026-10-14_13_41_51_net10.0.trx`.
SHA256:`EEB3572F3FE8B891D7E41BAF6DD9CBCF326613628EB30ED1B72B6159D0F30B3D`.
The current Store reached15031ms despite a peer200 in4768ms; the retained case
passed. Exact TRX inspection shows363 result intervals overlap the failed test's
whole32.58-second interval, and nine other executions overlap its final16 seconds
(an approximation, not a captured Store-span timestamp). These include a34.78s
2049-generation catalog write and a31.83s real-PQ/CAS ceremony, on12 reported
logical processors. This is unrelated fixture competition, not controlled
same-service production load.

The native issuer class now uses xUnit's explicit nonparallel collection; other
ordinary collections remain parallel. All test cases, deadlines, assertions,
real TLS/crypto/native stores and concurrent operations inside the scenarios
remain unchanged. See [xUnit collection isolation](https://xunit.net/docs/running-tests-in-parallel.html#opting-a-test-collection-out-of-parallelism).
Source full qualification under this harness is not sustained/load acceptance;
S09 still owns production-shaped concurrent traffic, retention and recovery.
Full07 must qualify the unchanged402-case matrix and inspect actual intervals
to confirm the isolation took effect. Full06 final unchanged-input acceptance
is not claimed. Node full/rehearsal and the rest of S05 remain open.

Canonical full07 qualified395/0/7,402 exact mappings, all native stages0,
2834 unchanged inputs, FullAccepted=true:
`artifacts/test-gate-20261014/s05-directory-lifecycle-full-07/full/nikit_SURFACE-LT_2026-10-14_13_50_10_net10.0.trx`.
SHA256:`52813945CDAF4816CE1D9D43A927DE5C86D5BB527487219281098CB56DA9A036`.
Native interval:2026-10-14T08:49:38.5641562Z–2026-10-14T08:56:03.0769397Z.
Independent interval inspection found seven native issuer executions with zero
overlaps against other collections. Their scenario-driven concurrency is still
executed. Actual output confirms phase profiling disabled. Store elapsed14930ms/
9610ms: the first has only70ms nominal margin below the original15s ingress
deadline. This source gate PASS is not stable-performance or S09 load acceptance;
the small cold-path margin remains an explicit risk. Original seven Unix-socket
skips require their Linux lane. The matching
[Node full](../../../xnode/docs/testing/s05-observation-context-reuse-2026-10-14.md)
has since qualified1499/0/0 with unchanged inputs. Smoke/rehearsal, operational
rotation/retained volumes and physical acceptance remain open; S05 is not closed.
