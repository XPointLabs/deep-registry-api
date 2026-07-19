# P06 dormant fixture evidence

Status: corrective green #4 awaiting final repeat independent review.

Human owner: Mr. X.

## Exact commits

- base: `fb7ebac6404e7a53241af08bb2f80d8a81022be8`;
- red: `70395d5903b078bd57c50db94e8744620bd01bfd`;
- initial green source:
  `59a7ae1b0bfe931c02a637f0e131d42e44b369de`;
- corrective red:
  `387e85807229c353e917c975e9a3b93c0eac1660`;
- corrective green source:
  `79bf87b6f7e42916a94125f665d4a2c053f5d922`;
- corrective #2 red:
  `acc270f7db896104f6d32bba383d35cf9a9af620`;
- corrective #2 green source:
  `107a7d68eb2104a94e97b486d5bfe902567f6ab0`;
- corrective #3 red:
  `fb26a0d4132e934241cae1620242c06a43a86f0e`;
- corrective #3 green source:
  `a801106f9201ea382ac0568a8a1eba943731970d`;
- corrective #4 red:
  `23d03267c6aa6d80127a7d38b7f3619a93b53195`;
- corrective #4 green source:
  `17d2b0aece401023f536394f736d0cc01abe23b6`.

## Prerequisite evidence

- W1/W2 final evidence:
  `1c01e24e24647a46b4f37622f3934dc2cc1284ef`;
- compatibility carrier:
  `524c5796aa868fa3d057fbf7eaa13cfea2e0d19c`;
- detached manifest SHA-256:
  `920b24bb5bcfcc8b4f91aef56ed210127246ec9fd2d49178ed9856c8555d0b93`;
- strict local gate: PASS, 17 immutable producer artifacts;
- independent verdict: GO, P0/P1/P2/P3 = 0/0/0/0.

## Supply-chain evidence

The repository contains exactly three accepted P04 packages, the accepted
manifest and the accepted vector file. The pre-restore and test hash gate
passed 5/5.

| Artifact | SHA-256 |
| --- | --- |
| `Deep.Protocol.0.3.0-p04.b887fa0.nupkg` | `8ef4e70ad0b6c1cc0087f25c0313d6ab6a5387d16246679e4c10a3c00898a442` |
| `Deep.Protocol.Abstractions.0.3.0-p04.b887fa0.nupkg` | `fc1212a6765f5778188fcb3866ef923023c2253c3ead299a542271f4cc4f844f` |
| `Deep.Protocol.Protobuf.0.3.0-p04.b887fa0.nupkg` | `755a027c58be670151456cc0bca4764731f7c493932d9eedd00c02e704baf818` |
| `package-manifest.json` | `fd3ef27bf0b9272570d6c6e680a3c99e581f6220799d13ee3afbd86ea0e99298` |
| `membership-contract-v1.json` | `758707e4705c0499f546ce1e1e5201df253ef70822225c5fd3086c43d8d9bf45` |

`Deep.Protocol` is requested as the exact NuGet range
`[0.3.0-p04.b887fa0]`. Both lock files resolve the accepted protocol,
abstractions and protobuf versions. The nupkg metadata pins source
`b887fa088f486390be182cac4cbcb59b60ce8931`.

Locked restore completed with public network access unavailable through the
test process proxy. Dependencies resolved from the repository vendor source
and existing local package cache.
The corrective #4 rerun set `NuGetAudit=false` because the deliberate
network-deny proxy cannot reach the advisory endpoint; exact vendor hashes,
source mapping and both lock files remained independently enforced.

## Verification

Environment: Windows ARM64 host, .NET SDK `10.0.301`, target `net10.0`,
Release.

| Gate | Result |
| --- | --- |
| P04 hash gate | PASS, 5/5 exact files |
| locked restore | PASS |
| Release build | PASS, 0 warnings, 0 errors |
| focused P06/package tests | PASS, 52/52, 0 skipped |
| full registry suite | PASS, 75/75, 0 skipped |
| format verification | PASS |
| line coverage | 2,403/2,967, 80.99% |
| branch coverage | 754/1,195, 63.09% |

Machine-readable result SHA-256:

- focused TRX:
  `1493a01f89d5078222fe1047d69fa3a9d5fb7a9f8f5b306f83b52c825b2c3711`;
- full TRX:
  `e09466da00dfc35252af1246c0be0b83d43672ec1c198b0961c659b5a7d3cd41`;
- Cobertura:
  `356e19829f64b816daf4b7d4c334f28dba5540e96e1ff6b6e69f2d3d17509d17`.

## Prior review findings and disposition

The first independent review inspected evidence commit
`d6608812fc7a108c305a2ad7d408a9949b657102`. Architecture/recovery returned
P0/P1/P2/P3 = 0/2/1/1 and security/privacy returned 0/4/6/2. The corrective
source pin for repeat review is
`79bf87b6f7e42916a94125f665d4a2c053f5d922`.

Disposition:

- historical content now retains and reverifies its accepted authority LKG and
  delegation; revocation immediately stops serving the old bridge without
  misclassifying valid historical state as corruption;
- unsafe fork state is latched before persistence, and both signed candidates,
  canonical statements and hashes are durably stored and reverified for
  authority, bridge and membership domains;
- enabled mode requires exactly one external monotonic generation/hash anchor;
  there is deliberately no production implementation, so missing authority
  fails closed;
- state transitions and reads use an interprocess lease plus generation/hash
  comparison; whole-file rollback is detected at startup and before serving;
- configured artifact/state limits are exact, persisted size is checked before
  allocation/deserialization, and timestamps are bounded to the
  `DateTimeOffset` range;
- persisted active delegation/revocation invariants are cryptographically
  revalidated;
- bridge responses are private/non-storable, conditional requests implement
  wildcard/list/weak ETag semantics, and public status no longer exposes
  membership sequence/hash;
- NuGet source mapping no longer permits the public wildcard source to resolve
  `Deep.Protocol*`; documentation and evidence now describe the actual
  fail-closed activation boundary.

## Corrective #2 disposition

The repeat reviews inspected evidence commit
`eaa99802a3fe8914b006784ce50ae99da81c6e2f` and source
`79bf87b6f7e42916a94125f665d4a2c053f5d922`. The read-only
`/root/p06_arch_recovery_review` verdict was NO-GO with P0/P1/P2/P3 =
0/1/2/0. The read-only `/root/p06_security_privacy_review` verdict was NO-GO
with P0/P1/P2/P3 = 0/4/3/0. Neither reviewer created a commit. Their remaining
P0/P1/P2 union is addressed by source
`107a7d68eb2104a94e97b486d5bfe902567f6ab0`:

- valid fork detection compare/exchanges terminal-unsafe poison into the
  external anchor before detailed state persistence; restart remains
  fail-closed when the main state write fails;
- lease sharing violations are typed, retried within a fixed bound and exposed
  as recoverable `continuity-busy`; a real two-instance file-contention test
  proves the same service instance recovers after lease release;
- typed transient anchor read/CAS failures are retried, reported separately
  from monotonic conflict and revalidated on later operations;
- corruption uses a current-state flag rather than the lifetime recovery
  counter, so explicit anchor reset/reseed resumes continuity checks;
- configuration and hard-cap validation occurs before every startup persisted
  read, raw artifact lengths are rejected before `ToArray`, and oversized
  persisted files are rejected before deserialization;
- parseable JSON with null authority, content or fork-record structures is
  quarantined without escaping startup;
- new transient/busy/conflict counters preserve bounded operational
  diagnostics without exposing topology.

## Corrective #3 disposition

The next read-only reviews inspected evidence
`28e20b61a9a215b85f00f5e990f5d1a94cd75d6b` and source
`107a7d68eb2104a94e97b486d5bfe902567f6ab0`.
`/root/p06_arch_recovery_review` returned P0/P1/P2/P3 = 0/1/1/1 and
`/root/p06_security_privacy_review` returned 0/1/2/1. Their P0/P1/P2 union is
addressed by source `a801106f9201ea382ac0568a8a1eba943731970d`:

- verified fork evidence is atomically written to an independent terminal
  journal before external poison CAS; the journal is checked before every
  main/prepared state read, so restart remains terminal unsafe when every
  poison attempt fails pre-commit or is ambiguous;
- every normal N+1 transition has an atomic prepared record containing exact
  expected/intended anchors before the main state replacement;
- CAS reconciliation rereads the anchor, accepts only the exact intended next,
  retries or remains transient for the exact expected value, and treats only a
  third value as conflict;
- startup and later operations reconcile both pre-commit failure and
  commit-then-throw, while a main-write failure clears prepared state only when
  the old file and expected anchor still match exactly;
- stateful `Apply` invokes deferred lease/anchor/prepared recovery directly and
  succeeds idempotently without a preceding status/read probe.

## Corrective #4 disposition

The final security pass on evidence
`fff9773d79701ebd62e54ba3bff1007d81d3c13f` and source
`a801106f9201ea382ac0568a8a1eba943731970d` had two read-only verdicts:
`/root/p06_final_arch_review` returned GO with P0/P1/P2/P3 = 0/0/0/0, while
`/root/p06_final_security_review` returned NO-GO with 0/1/0/0. Its independent
rerun recorded MembershipProjection 48/48, full Registry 74/74, format and
diff-check PASS, and a clean worktree. Source
`17d2b0aece401023f536394f736d0cc01abe23b6` addresses the sole remaining
security finding by giving a present valid terminal journal strict startup
precedence: after latching `fork-detected`, `LoadState` returns without reading
prepared state. The regression fixture combines a valid terminal journal with
a prepared file of `MaximumStateBytes + 1` and proves constructor success,
`Ready=false`, `State=fork-detected` and no bridge publication.

## Acceptance evidence

- feature defaults to disabled;
- application assembly contains no P04 signature-verifier implementation or
  deterministic key material;
- only bounded raw internal fixture ingress exists;
- no checkpoint POST/PUT/upload, live source or production file watcher exists;
- P06 store is isolated from `NodeRegistry`;
- authority, bridge and membership LKG chains are separate;
- persistence completes before memory publication;
- an external monotonic generation/hash anchor is mandatory for enabled mode;
- fork terminal-unsafe poison is durable in that anchor before main state
  persistence;
- independent local terminal evidence preserves fail-closed restart when
  external poison CAS is unavailable or ambiguous;
- terminal evidence suppresses lower-priority main/prepared reads, including
  oversized or malformed prepared state;
- the repository ships no production anchor implementation;
- exact configured size ceilings are enforced before persisted-state
  deserialization;
- interprocess serialization and compare/exchange reject whole-file rollback
  both at startup and before serving;
- typed lease contention and transient anchor failures are bounded,
  distinguishable and recoverable;
- prepared N+1 state and ambiguous CAS are reconciled against exact
  expected/intended anchors;
- rollback, gap, invalid signature, fork, expiry and corruption fail closed;
- valid fork candidates and canonical evidence survive restart and a cleared
  boolean;
- a write failure cannot clear the in-memory fork latch;
- a main-state write failure after fork detection cannot clear the external
  terminal-unsafe poison;
- revocation immediately stops an older bridge while its historical authority
  binding remains verifiable without false quarantine;
- a current cache survives source failure;
- stale state is retained but not served;
- explicit reset/reseed resumes continuity despite lifetime corruption
  counters;
- stateful retries recover transient continuity directly without a separate
  health/status request;
- public bridge bytes are exact and versioned;
- public bridge caching is private/non-storable and ETag matching accepts
  wildcard, list and weak validators;
- status/problem responses are sanitized;
- public status omits membership sequence/hash;
- no membership or inclusion-proof endpoint exists;
- all prior registry tests remain green.

## Non-actions

- no Docker or application network service;
- no live artifact source, signer or mirror;
- no key, seed phrase, mnemonic, credential, HSM/KMS or UAT identity access;
- no production genesis or deployment;
- no package publication;
- no Git push or pull request.

The permitted final status remains `fixture-go-runtime-blocked`. It may be
recorded as final only after architecture/recovery and security/privacy reviews
return P0/P1/P2 = 0.
