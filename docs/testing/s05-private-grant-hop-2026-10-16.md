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

## Confirmed admission defect and candidate correction

Supported local `build-02`/`up-03`/`smoke-04` activated the diagnostic source;
readiness recovered in21s. All9 desired images match. The original raw mount
comparison failed for5 bind representations; a separate finite Windows-drive /
Docker-Desktop representation proof matches every original hash and read/write
flag across all54 mounts (29 volumes/25 binds). Both reports are retained. No
operator reset or production update occurred.

Android Refresh103 -> independent Inspect104 still failed. New closed metadata
records private-hop503 and Registry Issue/io at `WithCurrentAsync` IL126. DLL and
portable PDB copied from the actual running Registry image have matching CodeView
identity; that offset maps to source line26, the immediate `TryEnter` busy throw.
Module SHA256 `d154392e83143aff328f5140f0d557d42b7138ad9beb32029f83d3b4573569af`.
This establishes the contention defect; it is not a TLS or signature exemption.

The one current context method now requires an explicit internal scheduling
mode. Private grant issuance shares the existing one-waiter route/publication
admission within its original30s deadline. Background revocation refresh remains
non-queuing. All proof/network/time/issuer/SQL/signature/release checks still run
after acquisition; only an acquired permit is released. No overload, caller
clock/trust flag, wire, journal, queue bound or timeout increase.

Further native receipts under the same artifact prefix:

- `registry-admission-red-06`:0PASS/1FAIL/native1, proving the original immediate
  busy completion instead of cancellable waiting. Admission-only null dependencies
  are intentionally unreachable, not surrogate proof or signing evidence.
- `registry-admission-07`:compile/native1, no TRX; four test-only callers had not
  selected the new explicit mode. They now choose their real foreground/background
  purpose; no compatibility overload was added.
- `registry-admission-08`:80PASS, no failures/skips/compiler warnings/errors,
  native0. Includes private/shared-queue cancellation and ownership, background
  non-queuing, unknown mode, existing route/publication and distribution admission.
- `provider-09`:2PASS, no failures/skips, native0 through the supported disposable
  PostgreSQL provider. Real signed Registry context, private HTTPS grant exchange,
  exact winner retry after lost reply and background revocation recovery pass.
  Replica attestations are fixture-owned; this is not ONION/device acceptance.

Matching supported local `build-10`/`up-11`/`smoke-12` exited0 with no compiler
diagnostics. All9 desired images run. Raw mount comparison failed for7 bind
representations; its original report remains unchanged, and the separate finite
representation proof matches all54 originals with their read/write flags.
Readiness recovered in68s; no account, key or volume reset occurred.

Retained APK37 Refresh106 -> independent Inspect110 now reports completed
incoming synchronization with no messaging error. Matching Windows build20
also retained account/recovery, verified registration and completed its one
incoming refresh without error. These are empty-mailbox read observations,
not message/contact delivery or sustained acceptance. Every old unknown request
remains owned; request expiry is not manual remint authority. Captured-page/ACK
continuation and physical business/full/package gates remain open.

The original device/server observations and node HTTP-hop mapping are in the
[Node checkpoint](../../../xnode/docs/testing/s05-private-grant-hop-2026-10-16.md).
