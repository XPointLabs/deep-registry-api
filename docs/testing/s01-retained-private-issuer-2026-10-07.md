# S01 retained-read private Registry / Node boundary

Date: 2026-10-07. Sole semantics:
[CONTACT-RESOLVER §3.7.3](../../../docs/architecture/CONTACT-RESOLVER-V1.md#373-current-retained-retrieve-issuance),
[DR-0104](../../../docs/survival-program/decisions/DR-0104-current-retained-retrieve-issuance.md).
This is a source candidate within the unfinished S01 batch. It is not a green
full gate, shipping activation, elapsed-route or physical-device acceptance.

## Implemented boundary and limitations

The node-private JSON requires an explicit evidence kind and retained horizon.
Current evidence retains its existing purpose; retained evidence requires
Retrieve, independent signatures over the exact 136-byte tuple, zero current
effective expiry, and the separate forwarding purpose. Unknown, missing or
cross-fed fields reject without a default or compatibility path. The actual
current Registry host verifies retained issuance before replay admission,
permanent reservation and external signing. Current source/time and issuance
are rechecked around signing, durable winner read-back and response release.

The permanent winner scope binds the exact request/evidence, kind, horizon,
current PMA2/root/time-policy references and protected network history. A
different scope cannot rewrite a reservation or remint a winner. Exact retry
with a new forwarding nonce re-verifies the same current winner after reopening
the SQL journal, without another signature. No schema generation, implicit DDL,
floor/key reset, public endpoint or new protocol allocation was added.

The connected fixture uses actual current Registry context/observer proof,
PostgreSQL, role signing, Kestrel HTTPS and the actual Node HTTPS client. Both
store signatures in this fixture are synthetic key-backed inputs, not native
protected retained read-back. It covers current/retained cross-feed, conflicting
permanent kind/horizon scope, a lost real TLS reply after durable commit, exact
retry and cold journal read-back. The subsequent native Store/Retrieve/ACK cycle
still uses current-route grants. Public Node acquisition remains current-only;
held Shared ownership/installation and genuinely elapsed-route delivery are
not joined or accepted by this candidate.

## Source and focused evidence

Release source-cutover solution build completed terminal0, zero warnings/errors.
Final PostgreSQL focused lane completed terminal0: **29 Passed / 0 Failed /
0 Skipped**. Fourteen new closed-JSON cases and one connected retained exchange
extend the prior full matrix by exactly fifteen executions.

The final lane uses the frozen local disposable-provider wrapper, exact
`deep_s00` database and approved PostgreSQL image; external test origins are
disabled. It restores its environment and removes only its own labelled tmpfs
container. It is not PostgreSQL production TLS/process-crash evidence.

Earlier evidence remains separate: initial test compilation failed on a missing
namespace; initial JSON focused26/2/0 used invalid all-zero fixture signatures.
Only fixture bytes were corrected, not the nonzero guard. The first connected
focused28/1/0 tried to resend an already-sent HttpRequestMessage through another
HttpClient. Its test handler now creates a fresh message with exact body/headers
for the real TLS hop; no product assertion or TLS guard was weakened.

## Original full FAIL — not superseded by a repeat

Original frozen full completed **terminal1: 363 Passed / 1 Failed / 7 Skipped**.
The failed existing case is
`ActualPrivateIssuerHttpsForwarderClientVerifierAndConfiguredNativeMailboxCycle`:
its first configured native Store returned `OutcomeUnknownAfterForward` instead
of `Completed` at `DeepIdV2RouteThresholdIssuerTests.GrantNative.cs:146`.
The reason is unresolved. A bounded repeat of that exact case on the same
binaries/provider passed1/0/0, terminal0; it does not establish a cause or fix
and does not replace the full FAIL. The seven original Windows skips are
Linux-only Unix-socket signer tests, not passing evidence.

Original prelaunch manifest:3703 source/normative/fixture/test-binary inputs,
captured `2026-10-07T18:33:21.6441375+05:00`, SHA256
`093A66A54320EEF80D6EC72207873F4EA56DC8BFAFD2A70F16B04907DC9F649D`.
Separate `verify-original-matrix.ps1` confirms the exact union of356 prior
executions plus15 new, all29 required focused cases Passed in the original full,
the same seven exact platform skips, complete unique result/definition/execution
mappings and all3703 original inputs unchanged. It reports `FullAccepted=false`
and exits1, preserving the actual full failure. Its first counter check failed
because xUnit TRX has seven NotExecuted rows but a zero notExecuted counter;
the check now verifies exact rows, total/executed and passed/failed counters.
No manifest, test input or original receipt was recaptured or changed.
Verifier SHA256:
`5EA63019EFB2EFDE6101BC5762CE98FE8A571A303D6D0B84B2DAD6B4411DC0DD`
(finalized after Node terminal to pin its original three receipts too).

Paths below are relative to this repository.

| Original receipt | SHA256 |
| --- | --- |
| artifacts/s00/s01-retained-private-issuer-focused-final-360d3a7285ad45679c35e10bd6746b06/nikit_SURFACE-LT_2026-10-07_18_28_54_net10.0.trx | `89422EA9D01D29A9489558B406C39D498D6CC601F3E5743AAE38C3A573BD5980` |
| artifacts/s00/s01-retained-private-issuer-full-f9a24424b9bf4c849d47b2a1074309ac/nikit_SURFACE-LT_2026-10-07_18_34_53_net10.0.trx | `FD6B5C0C308FE074AAECBD16E6E538E79A08A4837C34B10078AE6FD1F3EE4591` |
| artifacts/s00/s01-retained-private-existing-native-triage-2f64a0f5808243aea68818dde132b91c/nikit_SURFACE-LT_2026-10-07_18_43_16_net10.0.trx | `7B0FF0E1CDD4ABADC748266505E4894BB6EA7EBBF40EDA6BEF61007777E668AE` |

Node focused/full and mandatory Docker evidence are owned by the
[matched Node receipt](../../../xnode/docs/testing/s01-retained-private-forwarding-2026-10-07.md).
No production deploy/reset, registered identity change, device E2E, Release
publication or main merge was performed. Source-cutover builds do not qualify
the pinned shipping package graph. S01 acceptance remains open.
Selected changed source/fresh evidence secret scan passed16 files. Root
documentation174 checks, contact-machine consistency and governance30/0/0
passed; these checks do not supersede the Registry full failure.
