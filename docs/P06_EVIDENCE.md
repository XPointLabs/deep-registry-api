# P06 dormant fixture evidence

Status: corrective green awaiting repeat independent review.

Human owner: Mr. X.

## Exact commits

- base: `fb7ebac6404e7a53241af08bb2f80d8a81022be8`;
- red: `70395d5903b078bd57c50db94e8744620bd01bfd`;
- initial green source:
  `59a7ae1b0bfe931c02a637f0e131d42e44b369de`;
- corrective red:
  `387e85807229c353e917c975e9a3b93c0eac1660`;
- corrective green source:
  `79bf87b6f7e42916a94125f665d4a2c053f5d922`.

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

## Verification

Environment: Windows ARM64 host, .NET SDK `10.0.301`, target `net10.0`,
Release.

| Gate | Result |
| --- | --- |
| P04 hash gate | PASS, 5/5 exact files |
| locked restore | PASS |
| Release build | PASS, 0 warnings, 0 errors |
| focused P06/package tests | PASS, 35/35, 0 skipped |
| full registry suite | PASS, 58/58, 0 skipped |
| format verification | PASS |
| line coverage | 2,172/2,569, 84.54% |
| branch coverage | 631/973, 64.85% |

Machine-readable result SHA-256:

- focused TRX:
  `3b9d8c7a283789b32a97a2171406bea41f71ef73628e3c628ad669a88f039227`;
- full TRX:
  `2dc31138942a235d8a7e0fbd5d3e4853c5765536f70a26b8dd9243569a98fa29`;
- Cobertura:
  `a8fccb4a144ac74628b08efa3ed48be3b37718a1255dd4d30c1b13e12139b81d`.

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
- the repository ships no production anchor implementation;
- exact configured size ceilings are enforced before persisted-state
  deserialization;
- interprocess serialization and compare/exchange reject whole-file rollback
  both at startup and before serving;
- rollback, gap, invalid signature, fork, expiry and corruption fail closed;
- valid fork candidates and canonical evidence survive restart and a cleared
  boolean;
- a write failure cannot clear the in-memory fork latch;
- revocation immediately stops an older bridge while its historical authority
  binding remains verifiable without false quarantine;
- a current cache survives source failure;
- stale state is retained but not served;
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
