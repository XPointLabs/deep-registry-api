# S00 Registry baseline — 2026-10-03

Status: reproducible source-cutover component baseline, not release or physical
E2E qualification. Execution follows [S00](../../../docs/architecture/IMPLEMENTATION-PLAN-V1.md#s00--воспроизводимая-исходная-точка).
Source baseline: Registry `5c79cb07620915769f673fd4b92624d774ad709e`;
Protocol `17a7c8be2b222eb0855d381b5040864dc14b4c9e`;
XNode `68405afadd369540bb7f54957909012db3c24bed`.
Only test fixtures changed in Registry; crypto/verifier/runtime/DDL unchanged.

## Reproduction

From the Registry checkout with local Docker and .NET 10:

```powershell
../deep-devops/scripts/test-registry-postgres.ps1 -Lane s00
dotnet test Deep.Registry.Api.slnx -c Release -p:DeepProtocolLocalCutover=true -p:DeepProtocolSourceCutover=true --filter 'FullyQualifiedName~DirectoryPublicationCatalogTests|FullyQualifiedName~DirectoryPublicationHttpTests'
docker build --target mailbox-signer-tests --build-context deep_protocol=../deep-protocol --build-context deep_devops=../deep-devops --tag deep-s00/registry-signer-tests:local .
```

The [disposable DB runbook](../../../deep-devops/docs/S00_REGISTRY_POSTGRES.md)
owns environment isolation, PostgreSQL image pin, cleanup and guard tests.
Both source-cutover flags are required; this does not verify the published
NuGet/package graph. The full default test project was used, not a focused
compile whitelist. Linux signer build uses the existing signer-only target.

## Checkpoints and boundaries

| Run | Passed | Failed | Windows platform skips | Total | Exit |
| --- | ---: | ---: | ---: | ---: | ---: |
| A: immutable historical handoff | 292 | 31 | 6 | 329 | 1 |
| B: fresh source baseline, isolated PostgreSQL, before reader fixture repair | 301 | 22 | 6 | 329 | 1 |
| C: full source after reader repair and 8 new boundary cases | 331 | 0 | 6 | 337 | 0 |
| C repeated with final lane guards | 331 | 0 | 6 | 337 | 0 |
| Linux actual Unix socket target, same source | 6 | 0 | 0 | 6 | 0 |

Runs are repetitions/subsets, not additive unique coverage. The six Linux cases
are precisely the Windows-only skips, not six new cases. No build warnings
appeared. C includes all 329 previous cases plus eight new reject controls.

The catalog and HTTP fixtures now use **supported reader 2**. DPW1 framing
version stays **1**: reader and framing version are not interchangeable.
Reader 0/1/3/65535 reject at closure construction and HTTP decoding. HTTP
rejects call no verifier, write no catalog record and do not consume a valid
challenge; the same challenge then commits with reader 2. Existing corruption,
retention, compare-exchange, exact replay, copy/bound and sanitation assertions
remain. The oversize request now reaches 413 rather than the earlier reader
400, so that test finally exercises its intended boundary.

Synthetic canonical verifiers in catalog/HTTP tests deliberately isolate
persistence and endpoint behavior. They are **not signed protocol authority
or real socket TLS evidence**. The real PostgreSQL issuer cases use their
existing PQ/native/SQLCipher/ADA2 fixtures and in-process TestServer, not
physical clients, production replicas or socket TLS.

## Every historical failure

A lists all 31 failures in the immutable
[handoff](../../../docs/RELEASE-STABILIZATION-HANDOFF-2026-10-03.md#full-registry-failure-inventory).
B reproduces 22 reader failures; nine provider cases pass with all three
isolated DB inputs configured. Source inspection confirms their non-empty
environment prerequisites. C reruns every listed case without deletion/skip
or weakened assertions. The classification below is not a claim that every
other architecture defect was repaired.

| Case | Cause and checkpoint evidence | Retest |
| --- | --- | --- |
| `DirectoryPublicationCatalogTests.InputsOutputsAndAnchorsAreDefensiveCopies` | Reader 1 fixture; B failed before desired branch | C: passed |
| `DirectoryPublicationCatalogTests.MaximumSizedFiveArtifactClosureFitsOneBoundedSegment` | Reader 1 fixture; B failed before desired branch | C: passed |
| `DirectoryPublicationCatalogTests.CorruptHistoricalSegmentQuarantinesOnlyWhenLazyReadTouchesIt` | Reader 1 fixture; B failed before desired branch | C: passed |
| `DirectoryPublicationCatalogTests.CrashRecoveryIsAtomicAtEveryCommitStage(failpointValue: 0, successorMustRecover: False)` | Reader 1 fixture; B failed before desired branch | C: passed |
| `DirectoryPublicationCatalogTests.CrashRecoveryIsAtomicAtEveryCommitStage(failpointValue: 1, successorMustRecover: True)` | Reader 1 fixture; B failed before desired branch | C: passed |
| `DirectoryPublicationCatalogTests.CrashRecoveryIsAtomicAtEveryCommitStage(failpointValue: 2, successorMustRecover: True)` | Reader 1 fixture; B failed before desired branch | C: passed |
| `DirectoryPublicationCatalogTests.CorruptManifestIsPersistentlyQuarantined` | Reader 1 fixture; B failed before desired branch | C: passed |
| `DirectoryPublicationCatalogTests.ConfiguredArtifactBoundRejectsBeforeVerifierAndMutation` | Reader 1 fixture; B failed before desired branch | C: passed |
| `DirectoryPublicationCatalogTests.DefaultRetentionAccepts2047_2048_And2049ContiguousGenerations` | Reader 1 fixture; B failed before desired branch | C: passed |
| `DirectoryPublicationCatalogTests.SameGenerationDifferentCanonicalBytesLatchesForkAcrossRestart` | Reader 1 fixture; B failed before desired branch | C: passed |
| `DirectoryPublicationCatalogTests.TypedVerifierCannotSubstituteDifferentCanonicalBytes` | Reader 1 fixture; B failed before desired branch | C: passed |
| `DirectoryPublicationCatalogTests.WrongNetworkRejectsWithoutPersistenceMutation` | Reader 1 fixture; B failed before desired branch | C: passed |
| `DirectoryPublicationCatalogTests.SecondInstanceReadsHeadPublishedAfterItsInMemorySnapshot` | Reader 1 fixture; B failed before desired branch | C: passed |
| `DirectoryPublicationCatalogTests.OpenAndCommitReadOnlyBoundedMetadataAndHeadSegment` | Reader 1 fixture; B failed before desired branch | C: passed |
| `DirectoryPublicationCatalogTests.RestartPreservesExactBytesHashesAndExactReplay` | Reader 1 fixture; B failed before desired branch | C: passed |
| `DirectoryPublicationCatalogTests.Configured2048GenerationCapacityRejectsOnlyThe2049thAppend` | Reader 1 fixture; B failed before desired branch | C: passed |
| `DirectoryPublicationCatalogTests.GenerationCompareExchangeIsAtomicAcrossCatalogInstances` | Reader 1 fixture; B failed before desired branch | C: passed |
| `DirectoryPublicationCatalogTests.AbsoluteArtifactMaxPlusOneAndResetCardinalityRejectBeforeCopy` | Reader 1 fixture; B failed before desired branch | C: passed |
| `DirectoryPublicationHttpTests.Concurrent_same_challenge_publish_has_one_commit_and_one_fail_closed_replay` | Reader 1 fixture; B failed before desired branch | C: passed |
| `DeepIdV2RouteThresholdJournalTests.PermanentJournalSurvivesCallbackFailureConcurrentRetryRestartAndCapacity(upgradeExisting: False)` | Missing isolated DB input; B passed with disposable provider | C: passed |
| `DeepIdV2RouteThresholdJournalTests.PermanentJournalSurvivesCallbackFailureConcurrentRetryRestartAndCapacity(upgradeExisting: True)` | Missing isolated DB input; B passed with disposable provider | C: passed |
| `DeepIdV2RouteThresholdJournalTests.OperatorFenceAbortsOnExistingCompetingNoncesWithoutChangingEvidence` | Missing isolated DB input; B passed with disposable provider | C: passed |
| `DeepIdV2MailboxGrantJournalTests.OperatorConstraintCutoverRejectsIncompatibleWinnerWithoutRepairOrReissuance` | Missing isolated DB input; B passed with disposable provider | C: passed |
| `DeepIdV2MailboxGrantJournalTests.HashOnlyReservationConcurrentWinnerRestartConflictCapacityAndCorruption` | Missing isolated DB input; B passed with disposable provider | C: passed |
| `DirectoryPublicationHttpTests.Malformed_and_max_plus_one_artifacts_fail_before_verifier_or_commit` | Reader 1 fixture; B failed before desired branch | C: passed |
| `DeepIdV2RouteThresholdIssuerTests.ActualPqAccountAda2FloorWitnessCustodyAndJournalCloseOwnedRouteOverHttp(crashMode: 2)` | Missing isolated DB input; B passed with disposable provider | C: passed |
| `DeepIdV2RouteThresholdIssuerTests.ActualPqAccountAda2FloorWitnessCustodyAndJournalCloseOwnedRouteOverHttp(crashMode: 0)` | Missing isolated DB input; B passed with disposable provider | C: passed |
| `DeepIdV2RouteThresholdIssuerTests.ActualPqAccountAda2FloorWitnessCustodyAndJournalCloseOwnedRouteOverHttp(crashMode: 1)` | Missing isolated DB input; B passed with disposable provider | C: passed |
| `DeepIdV2PublicationJournalTests.PublicationSuccessorProvisionPreservesOpaqueAuditAndUnsignedPermanentFence` | Missing isolated DB input; B passed with disposable provider | C: passed |
| `DirectoryPublicationHttpTests.Verifier_rejection_occurs_before_catalog_commit_and_is_sanitized` | Reader 1 fixture; B failed before desired branch | C: passed |
| `DirectoryPublicationHttpTests.Mirror_returns_byte_identical_immutable_generation_manifest_and_head_with_cache_contracts` | Reader 1 fixture; B failed before desired branch | C: passed |

## Local raw evidence hashes

Raw TRX stays ignored: it contains machine paths. Only counts, test names and
SHA-256 digests are retained here; no private paths, node addresses or secrets.

| Run | SHA-256 of raw TRX |
| --- | --- |
| B | `c884df358bfa000ab8dc0aba1aea4c128290d753ba57ee115e22d6b4b9fa9967` |
| C | `f3abfd25bce17d19f518e0b8fd0458ebae3eeffb7b1e11f98b034c414bac2846` |
| C final repeat | `ab78ba9336cd4650f0993344437af98346b5e70972a20b40893e06077fc978b9` |
| Linux signer | `d8e2680e8b736477166c7408fa5380d2c605d04d797441aa12198b20d85a87fb` |

All three disposable PostgreSQL instances and the unstarted signer artifact-export
container were removed after exact ownership verification. No named DB volume
was created. The local signer test image/cache remains; it is not published.

## Checkpoint C remaining work (historical)

Registry's reader/isolated-provider baseline is closed, **S00 as a whole is not**.
XNode has a current signed one-time-invite prerequisite gap; current XPP fixture
migration and root governance drift remain. This checkpoint makes no claim about
revocation source/floor, current mailbox node admission/peer proof, shipping
Release composition, contact/message device E2E, remote files or groups.
No production deployment, device install/reset or Release publication ran.

## Current source baseline — 2026-10-05

Inputs: Registry `f47ca7510dcf04ff59235387ccce66662c19f620`, Protocol
`ed7153e12cc0749e875a047705566bf0a99338b9`. The source-cutover solution build
finishes terminal0 with zero warnings/errors. External Protocol builds in Debug
under this existing solution graph; this is not a uniform Release package matrix.
The first provider invocation did not start tests because the local Docker engine
was unavailable. After the local engine was ready, the existing disposable tmpfs
PostgreSQL lane completes **348 passed / 0 failed / 7 skipped**, terminal0.
All **31** historical failures in the table above match exact Passed results in
this fresh full receipt, including each theory argument; no case was omitted.

The existing actual Linux signer target completes **7 passed / 0 failed /
0 skipped**, terminal0. Comparing exact case names gives no difference between
these seven passes and the seven Windows platform skips. They are alternate
platform execution of the same cases, not additive unique coverage. Socket
framing with synthetic signatures is not cryptographic issuance qualification.
Both the owned temporary PostgreSQL container and never-started signer artifact
export container were removed after ownership checks. No production resources
or registered keys were read or modified.

| Ignored current receipt | SHA-256 |
| --- | --- |
| Windows full348/0/7 | `e8a8fca096c8f31ec2dff6710d8790d24bcecbd4c3109b1c8c3d98ec4b38bec8` |
| Linux signer7/0/0 | `7970108072c2c2fa1feeff7fe30eab2a6b1de7c2c80d29cf565329fa2c8145ab` |

The Windows receipt is under `artifacts/s00/s00-final-source-28141ffc04bd4a8db866c2ba7610bb08`;
Linux under `artifacts/s00/s00-final-source-linux-ed7153e`. Both remain ignored.
Linux test image: `sha256:94daf442a95937ff911a68926b7f1f18654a19c49f427903eaff3087d81a11c1`.
Commands remain the supported lane and signer target described above; the
isolated lane's current full invocation uses both source-cutover flags.

This closes the Registry component baseline only. The old checkpoint's one-time
producer gap was subsequently addressed in the
[signed publication checkpoint](s00-one-time-publication-2026-10-04.md);
it is not a new task to reimplement. Overall S00 acceptance and remaining work
are owned solely by [NEXT-SPRINT](../../../docs/NEXT-SPRINT.md). No shipping
composition, deployed issuer renewal, physical contact/message path or Release
qualification is inferred from this component receipt.
