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

## Matching horizon full and native Store diagnosis — 2026-10-08

Matching source versions: Protocol `e48484c`, Shared `a5c6d7d`, Node `2804023`,
root `bedac26`. Registry source-cutover Release solution build completed0,
zero warnings/errors. A fresh isolated PostgreSQL full completed actual test1/
qualification1: **363 Passed/1 Failed/7 Skipped**, exact371 original case/method
mappings and all3715 prelaunch inputs unchanged. The same first configured
native Store returned `OutcomeUnknownAfterForward`, not `Completed`. This
reproduces the open data-path failure; it does not prove a timeout/TLS/authority
cause. The original protected nonce-ledger case and all three crash modes passed
in this run; that does not establish a cause or fix for its earlier failure.

Manifest SHA256:
`27E377FDE26E1C3C990987512420740F4F65F063AE5EF745246120F5F75E6861`.
Receipt:
`artifacts/s00/s01-object-horizon-full-4182e4553b5b45afa776198106053ea3/nikit_SURFACE-LT_2026-10-08_13_18_32_net10.0.trx`,
SHA256 `BA050C70502E93DDD161A99C40E2040249E1B1BA5BC4A34F5A796B42CA2D0587`.
The actual terminal and standalone verifier preserve source acceptance=false;
the temporary labelled tmpfs database was removed by its provider wrapper.

The test now observes the existing descriptor-pinned peer client, without
replacing transport, adding retries or changing deadlines/authority. The failed
assertion reports only types/HResult, counts, elapsed time, cancellation, HTTP
status and byte lengths; never exception messages, URLs, identities, grants,
payloads or private paths. A rebuilt single-case diagnostic run passed1/0/0,
actual0, but does not supersede the full failure or establish its cause.
Receipt:
`artifacts/s00/s01-native-store-diagnostic-b98b883e1e3742fe8d317a0fbcd19bbc/nikit_SURFACE-LT_2026-10-08_13_25_19_net10.0.trx`.
The separate diagnostic full completed actual test1/qualification1:
363/1/7, exact371 cases and3715 immutable inputs unchanged. Receipt:
`artifacts/s00/s01-native-store-diagnostic-full-1e92556eaf3342acacc3a64a22535166/nikit_SURFACE-LT_2026-10-08_13_27_10_net10.0.trx`,
SHA256 `074AFE992BA880A4E80C27DC8FFABC964DADB00EA74FA6EF0F17B0876F3B2ABA`.
Manifest SHA256:
`BCA429BC851D23B30E085B507638D576AA10257F6F3D38134CD34213FB68EACA`.

The failing Store reports504/unknown after15027ms. The actual pinned peer call
took4506ms and returned296 bytes, uncancelled, with server200. Thus the client
received the expected transport framing; it was not a missing peer HTTP response.
This does not prove quorum-signature acceptance, durable recipient settlement or
the exact swallowed exception. The elapsed time closely matches the unchanged
15-second Store ingress deadline, making local verification/persistence or budget
exhaustion the next investigation boundary, not a proven causal fix. No timeout,
assertion, product guard, shipping activation or production/reset action changed.

## Native Store path optimization and matching full — 2026-10-08

The bounded phase observers now wrap the actual configured network source,
storage security and durability owners, retaining their arguments, cancellation,
exceptions and effects. Timing sums use Stopwatch ticks. Caller-scoped,
bounded first-chance observations expose only type/HResult/code-owner names;
no exception messages or private values. The original failed receipts above
remain immutable.

A local sampled-thread profile identified repeated native MGR1 ancestor
`LinkTarget` resolution as a hot path. The
[Node change and negative checks](../../../xnode/docs/testing/s01-native-store-path-safety-2026-10-08.md)
replace that Windows overhead with uncached entry-attribute checks. No TLS,
authority, revocation, protected read-back, quorum, retry, expiry or deadline
guard was removed. There is no wire/state-generation change.

Post-change focused native cycle passed1/0/0 with initial Store7402ms. The fresh
full source-cutover solution build finished0, zero warnings/errors; full
PostgreSQL/native gate completed **364 Passed/0 Failed/7 Skipped**, actual test0
and qualification0. All371 original case/method/execution mappings and3718
prelaunch inputs were accounted for and unchanged at terminal. Started
`2026-10-08T08:56:41.4657261Z`, finished `2026-10-08T09:01:54.8299116Z`.

The previously failing configured-native cycle Passed. Initial Store11017ms
completed under the unchanged15-second budget. The cycle still asserts the
two-node verified quorum, byte-identical exact retry, Retrieve, ACK and cold
reopen; HTTP200 alone cannot satisfy it. Four expected missing-entry exceptions
were observed during the successful Store. The original nonce-ledger case and
all three crash modes passed again; its historical exclusive cause remains
unproven, not retrospectively waived.

Receipt:
`artifacts/s00/s01-native-store-path-fix-full-4e94e3adb2cd423dac7aa1f2d38fea50/nikit_SURFACE-LT_2026-10-08_13_57_54_net10.0.trx`,
SHA256 `021BB4A2136E72E2DF4062E8DD4195D00FF2D0074EB1CDD9D08F0CE7F11189C6`.
Manifest: `artifacts/s01-native-store-path-fix-full/inputs.json`, SHA256
`C894704A0BF02A01DFA235BCDC93A51659F24B4B874B4BCF953E061C385D133C`.
`terminal.json` records actual build/capture/test/qualification exits0 and
`CurrentWindowsSourceAccepted=true`; historical exclusive-cause proof and
release acceptance remain false. The provider cleaned only its labelled
temporary container/tmpfs database; no named volume or production state changed.

This accepts the current Windows Registry source matrix, not Linux provider,
shipping packages, selected-entry/ONION, an owned two-client path or devices.
Matching full Node subsequently passed1363/0/0, build/test/qualification0,
all2191 captured inputs unchanged; required external/no-mock smoke and multi-node
both completed0. The exact joined source/infrastructure evidence belongs to the
[Node checkpoint](../../../xnode/docs/testing/s01-native-store-path-safety-2026-10-08.md#matching-full-and-docker-terminal).
This permits the next S01 known-floor/dependency contract batch, not release
acceptance. S01 is not closed.
