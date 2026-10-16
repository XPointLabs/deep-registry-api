# S05 — private grant endpoint failure classification

Date: 2026-10-16. This diagnostic candidate changes no grant authority, endpoint
result, admission limit, timeout, journal, signer, wire or trust requirement.

The existing private grant endpoint now emits bounded failure metadata for
body/decode/issue/write phases: existing HTTP result, fixed category and first
approved code-owned method/IL offset. No exception object/message, request data,
identifier, endpoint/origin, key or capability enters the sink. One fixed bucket
per phase is limited to one event per10s; diagnostic exceptions cannot replace
the original HTTP outcome. Early request-size/type/TLS/admission checks remain.

`artifacts/s05-private-grant-hop-20261016/registry-01` passed33 cases, no failure/
skip/native/compiler error or warning, under Windows PowerShell5.1/SDK10.0.301.
Includes existing private JSON/admission/refusal cases and exact closed-field,
suppression and throwing-sink tests. This is not full source, PostgreSQL issuer,
deployed issuance or physical business qualification. Local activation and the
retained Android retry must identify the actual issuer boundary before a fix is
chosen; a503/504 response alone never authorizes a replacement request.

The original device/server observations and node HTTP-hop mapping are in the
[Node checkpoint](../../../xnode/docs/testing/s05-private-grant-hop-2026-10-16.md).
