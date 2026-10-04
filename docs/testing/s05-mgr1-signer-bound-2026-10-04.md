# S05 current MGR1 external signer input boundary

Product source: `dac2c5fd180ac03400a381ccfa7c320d326065c6`.
Protocol source: `8989ad6a787cdc8194106a5130fcfa832608e252`.
This is a necessary signer-transport fix, not MGR1 issuer activation, cumulative
renewal, production provisioning or physical delivery evidence.

## Defect and connected regression

The actual Unix socket adapter rejected signing input above65,536 bytes. A
canonical current MGR1 with4096 serials requires65,824 signing bytes: its exact
65,863-byte record minus the72-byte signature field plus the33-byte SIGINPUT
prefix. The new test constructs that maximum through the current Protocol codec
with canonical sorted serials and passes it through an actual Linux Unix socket.
The response remains synthetic public framing bytes, not a verified role
signature. No private/operator key or production socket is used.

Before the product change, the existing Linux Docker target reproduces **6 pass /
1 fail /0 skip**, exit1. The new maximum case fails with argument-range rejection
in the adapter before opening the socket. The failed Docker RUN has no exported
image/TRX; its terminal output is the reproduction evidence, not a claimed receipt.

The I/O ceiling now matches that exact maximum. Empty/max+1 still reject before
socket connection. PMES/v1 header, one original deadline,64-byte signature,
truncated/trailing/late-byte rejection and mandatory EOF remain unchanged. This
adapter transports bytes; it grants no policy, role, signing or node authority.
The sole operator behavior is in
[DID2_PRIVATE_MAILBOX_GRANTS](../DID2_PRIVATE_MAILBOX_GRANTS.md#external-signer-response-lifecycle).

The first green Linux run7/0/0 exposed xUnit2000 argument-order warning. The final
source swaps expected/actual without changing their equality; final Docker
compilation emits no warning and the seven socket cases pass again.

## Full Registry fixture failures and closure

An initial bare full run is unqualified: **322 pass /9 fail /7 Windows skips**,
exit1, and the same analyzer warning-as-error. Its nine provider cases have no
required isolated PostgreSQL inputs. The supported disposable lane supplies all
three synthetic DB inputs without any ambient production connection. Its next
full run is **329 pass /2 fail /7 Windows skips**, exit1. Both crash-mode route
issuer cases expect obsolete protected generation9 while the actual current
Shared owner writes10. No product signature, request, replay or time assertion
fails at that point.

The fixture now checks the actual owner's declared version, retaining exact
pending/threshold state-byte checks, original request/response equality, one
signer call, independent ADA2/floor advance, cold retry and permanent PostgreSQL
winner assertions. It introduces no old-state reader or migration. The focused
three crash-mode cases pass3/0/0,1m20s, in a fresh isolated DB. The unfiltered final
solution passes **331 /0 /7**,338 total, exit0,1m12s. Full test source compiles;
no focused compile whitelist or filter is used for this Windows full run.

The seven Windows skips are exactly the seven actual Linux socket tests, executed
separately in the existing signer-only Docker target: **7 /0 /0**,725ms. They are
overlapping platform evidence, not seven additional tests or a full Linux suite.
That focused target intentionally compiles only its existing signer-test graph;
it does not qualify the rest of Registry. A separate final source-cutover full
solution build under warnings-as-errors finishes **zero warnings /zero errors**.
External dependency references map to Debug while Registry is Release; this is
not a uniformly Release package/installed-artifact matrix.

```powershell
docker build --target mailbox-signer-tests --build-context deep_protocol=../deep-protocol -t deep-registry-mailbox-signer-tests:local .
../deep-devops/scripts/test-registry-postgres.ps1 -Lane s05-mgr1-signer-final
dotnet build Deep.Registry.Api.slnx -c Release --no-restore -m:1 -p:DeepProtocolLocalCutover=true -p:DeepProtocolSourceCutover=true -warnaserror
```

Each DB lane cleans its owned container/tmpfs database and restores environment
inputs; there is no named volume, operator connection, production mutation or
TLS qualification. The Linux receipt is copied from a never-started, network-none
temporary container, then that container is removed. Retained final image ID:
`sha256:fb997a075687f8db81f82187b18a6199c66be7a8e49fc3f1eec7b3f0a7281c20`.
This image's focused signer graph predates the separate route-fixture-only edit;
the signer product/test bytes are identical. The full Windows receipt covers
the complete final fixture matrix.

| Local receipt | SHA-256 |
| --- | --- |
| Initial unconfigured full `artifacts/s05-mgr1-signer-bound/full-final/nikit_SURFACE-LT_2026-10-04_21_52_45_net10.0.trx` | `d6dc08a7c4625ab9bce5e506577c100a72645009b8705edb64d8ad63e65be6bd` |
| Isolated stale-fixture full `artifacts/s00/s05-mgr1-signer-bound-183889a5ce604bb69fb34b780412f4f0/nikit_SURFACE-LT_2026-10-04_21_54_34_net10.0.trx` | `6239f3fb8f1559c03ca6b976146367fc71055ad73270fd435efd01ad7db5a66c` |
| Focused route3 `artifacts/s00/s05-mgr1-source-fixture-cb3d9d4549f84f7cb189096dfab5f2f6/nikit_SURFACE-LT_2026-10-04_21_58_38_net10.0.trx` | `5412610bd4a6031cce46738af60fef8df7cb0e6f6e48ec687f565b39095e0ad5` |
| Final full331/0/7 `artifacts/s00/s05-mgr1-signer-final-ca92dc685e8b4287a6ed901c54ce3afe/nikit_SURFACE-LT_2026-10-04_22_02_18_net10.0.trx` | `c6abad1a3eb15e63e5c5b5713b35e29ff57b95ee3327bc50687c60d8af54198d` |
| Final Linux7/0/0 `artifacts/s05-mgr1-signer-bound/linux-final/_buildkitsandbox_2026-10-04_16_54_47_net10.0.trx` | `c4053953fceec590e71caba83a9f2b44eb0cd01605e6c265a78620866432d86d` |

## Unqualified boundaries

No MGR1 producer/renewal/distributor is added by this adapter fix. Actual issuer
lineage/custody, current node-control activation, shipping composition, Protocol
package cleanup and Windows/Android physical contacts/messages/attachments/groups
remain open. Physical qualification is0/4. Work follows the single
[implementation plan](../../../docs/architecture/IMPLEMENTATION-PLAN-V1.md),
not another isolated release claim or a parallel backlog.
