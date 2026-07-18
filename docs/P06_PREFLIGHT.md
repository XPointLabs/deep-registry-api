# P06 dormant fixture preflight

Status: red phase. Human owner: Mr. X.

## Accepted inputs

- `deep-registry-api` base:
  `fb7ebac6404e7a53241af08bb2f80d8a81022be8`.
- W1/W2 final evidence:
  `1c01e24e24647a46b4f37622f3934dc2cc1284ef`.
- W1/W2 contract carrier:
  `524c5796aa868fa3d057fbf7eaa13cfea2e0d19c`.
- Detached W1/W2 manifest SHA-256:
  `920b24bb5bcfcc8b4f91aef56ed210127246ec9fd2d49178ed9856c8555d0b93`.
- Strict dependency closure gate: PASS, 17 immutable producer artifacts.
- Independent W1/W2 review: GO, P0/P1/P2/P3 = 0/0/0/0.
- P04 source:
  `b887fa088f486390be182cac4cbcb59b60ce8931`.
- P04 final GO evidence:
  `db58937d4070eb057642c00d10a64d2f738f6e41`.
- P04 contract and package:
  `Deep.Protocol/P04-canonical-v1`,
  `0.3.0-p04.b887fa0`.

The three package SHA-256 values and the package-manifest SHA-256 are enforced
by `P04PackagePinTests`.

## Boundary

This slice is dormant, fixture-driven and default-disabled. It must not use
`NodeRegistry` as membership authority. It contains no production signature
adapter, live source, checkpoint mutation endpoint, Docker/network action,
key/seed access, package publication or Git push.

The only permitted final status is `fixture-go-runtime-blocked`.
