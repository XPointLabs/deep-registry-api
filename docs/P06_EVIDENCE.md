# P06 dormant fixture evidence

Status: green implementation awaiting independent review.

Human owner: Mr. X.

## Exact commits

- base: `fb7ebac6404e7a53241af08bb2f80d8a81022be8`;
- red: `70395d5903b078bd57c50db94e8744620bd01bfd`;
- green source: `59a7ae1b0bfe931c02a637f0e131d42e44b369de`.

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
| focused P06/package tests | PASS, 23/23, 0 skipped |
| full registry suite | PASS, 46/46, 0 skipped |
| format verification | PASS |
| line coverage | 1,662/2,001, 83.05% |
| branch coverage | 487/783, 62.19% |

Machine-readable result SHA-256:

- focused TRX:
  `066212da44f478564ee44323ceb380a255a665a82ac4f309163e17b24e37fb29`;
- full TRX:
  `f6428ab7b7628e9f38cb4bbd0baf7307361f1ade7a56a952980fe30eb2e34c0c`;
- Cobertura:
  `9889d3ec82dc2a2ad92e089b1ee289d24deb4a806a697822897ab13600ba9ea6`.

## Acceptance evidence

- feature defaults to disabled;
- application assembly contains no P04 signature-verifier implementation or
  deterministic key material;
- only bounded raw internal fixture ingress exists;
- no checkpoint POST/PUT/upload, live source or production file watcher exists;
- P06 store is isolated from `NodeRegistry`;
- authority, bridge and membership LKG chains are separate;
- persistence completes before memory publication;
- rollback, gap, invalid signature, fork, expiry and corruption fail closed;
- a current cache survives source failure;
- stale state is retained but not served;
- public bridge bytes are exact and versioned;
- status/problem responses are sanitized;
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
