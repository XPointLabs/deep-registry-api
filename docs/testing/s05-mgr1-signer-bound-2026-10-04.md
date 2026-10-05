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

## Connected private grant exchange (2026-10-05)

The existing real PQ account/ADA2/protected floor/witness route ceremony now
feeds the actual `DeepIdV2MailboxGrantIssuer`, permanent PostgreSQL journal and
mapped private HTTP endpoint over real Kestrel HTTPS. The compiled XNode
`HttpsMailboxGrantAuthorityClient` constructs and signs the actual forwarding
request; the independent client Protocol verifier authenticates its exact winner
under the original verified route and PMA2. Exact XMG1 retry returns the same
winner with one role signature and one permanent reservation.

Untrusted TLS and corrupt two-store evidence reject without signing or reserving;
a changed returned grant fails independent client verification. No permissive
TLS callback, production signer/key, new wire or public client endpoint is added.
The fixture uses owned PKI/time, synthetic holder/role custody and synthetic
signed resolver attestations. Its prior route/proof transport is TestServer.
It does **not** qualify actual resolver storage, native mailbox admission/data,
protected Shared grant installation, selected ONION transport or physical E2E.
The three original route crash cases retain their assertions unchanged.

An initial compile failed on the missing ApplicationCore namespace import;
correcting that fixture import produced focused1/0/0, terminal0. After adding
the untrusted TLS and zero-reservation assertions, the normal whole Registry
Release build passed with0 warnings/errors and the approved unfiltered provider
lane passed **348/0/7**, terminal0,1m43s. Seven Windows platform skips remain
skips. Each owned tmpfs PostgreSQL database was removed. Product source is
unchanged; this test-only continuation does not transfer old full-gate evidence
to changed runtime bodies or close S05. Stage0/14, physical0/4 remain.

| Receipt under `artifacts/s00/` | Outcome | SHA-256 |
| --- | --- | --- |
| `s05-connected-grant-7fb09e3a4f474c1e944877abe335a819/nikit_SURFACE-LT_2026-10-05_05_59_38_net10.0.trx` | 1/0/0 before final negative assertions | `3d6e6b50e51f6ce65343a9865181cd5d3d54e84fd0f1e4bc90c13e285c8cba3a` |
| `s05-connected-grant-full-614835f9a7c54170831be973891656aa/nikit_SURFACE-LT_2026-10-05_06_00_39_net10.0.trx` | final348/0/7 | `a96b07c67054dc5a10a4362851c9001cdac88d319b28fd6f80f4b2df5028a5e6` |

### Continuation: configured native Store/Retrieve/ACK and cold reopen

The same fact now connects both actual issuer role winners to three independently
configured native XNode owner graphs. Signed descriptors carry the owned listeners'
real origins/SPKI; the existing peer client/endpoint uses real TLS/H2. Every node
uses actual configured proof/network acquisition from the real Registry HTTPS
endpoint, protected head/network floors, explicit native MGR1 enrollment and
registered native receiver/coordinator. No fixture publication-authority source,
peer client or native endpoint is substituted. Real MGR1 roots are explicitly
provisioned in the disposable DB and signed by a separate test-owned custody.

Store produces the selected two-node quorum; Retrieve returns the exact original
ciphertext; ACK leaves both native stores empty. Exactly one Store peer RPC and
one tombstone peer RPC occur. All three hosts then reopen the same data/custody/key
rings without explicit reprovisioning or enrollment. Cold startup rejects before
fresh observation; explicit acquisition restores the graph. Exact Store/ACK retry
returns the same saved bytes with no additional peer RPC. Both stores remain empty:
the acknowledged object is not resurrected.

Three first0/1 attempts were fixture defects, not bypassed runtime checks:
artifact reference instead of the required PMA2 core reference in the provisioned
MGR1 scope; missing TimeProvider for the actual proof endpoint's admission DI;
and comparing canonical MQR3 byte-ID order with PMS2 writer ranking. The exact
scope, required DI and expected canonical pair were corrected. The three original
route crash cases still execute unchanged. Focused native Store, complete native
cycle and cold reopen pass independently. With final peer-RPC assertions, the
whole Release build has0 warnings/errors and the approved unfiltered Registry
suite is **348/0/7**, terminal0,2m38s. Owned tmpfs databases are removed.

This extends the same contact/text vertical, not a new delivery implementation.
Product runtime source is unchanged. These hosts use minimal Kestrel plus actual
registered XNode services, not the complete Program/ONION/Xray pipeline. Holder,
ciphertext and resolver attestations are test-owned; the account route/proof
preparation still uses TestServer. Actual resolver authorization, protected Shared
grant installation/E2EE dispatch, masked selected-entry transport, application
receipts and physical Windows/Android remain unqualified. No production, identity,
operator key, Release publication or main merge changed. S05 remains open;
stage0/14 and physical0/4 are not replaced by these local results.

| Receipt under `artifacts/s00/` | Outcome / scope | SHA-256 |
| --- | --- | --- |
| `s05-grant-native-ecf8c7952dfe4ad48294dbc0133f8aec/nikit_SURFACE-LT_2026-10-05_06_11_54_net10.0.trx` | 0/1/0, scope input | `daaa842f3212004d2c2e6a723d6d87270185ca1da07ae977209f3d2eebcd4c31` |
| `s05-grant-native-a351138dd4534c7a962d488280792cb7/nikit_SURFACE-LT_2026-10-05_06_12_49_net10.0.trx` | 0/1/0, proof DI | `264049cccbdd64ea2d05d995873dcff2b107af244bba35d5c1ca6e7b445b8925` |
| `s05-grant-native-478ddfe8b7d44322bc855bf746891eb9/nikit_SURFACE-LT_2026-10-05_06_14_13_net10.0.trx` | 0/1/0, receipt order | `2c89ef9f727c0d096cf7bd132910c80a7fa3d3daa63dda128de43346614d6bce` |
| `s05-grant-native-bc4e95dbb8224aa7abafaabdb69013cc/nikit_SURFACE-LT_2026-10-05_06_15_43_net10.0.trx` | 1/0/0, Store only | `7bd881b7381901763356a3485a18bb632aef0d60e993e56804a5c03e3c08c4e6` |
| `s05-grant-native-cycle-ae4b10bce33f4277b5cc66fe29a38abc/nikit_SURFACE-LT_2026-10-05_06_18_55_net10.0.trx` | 1/0/0, native cycle | `6d0cbd4cfe06031da395d4f81d500d3903fb8c6b96b58b20c8b58e77018f341c` |
| `s05-grant-native-cold-64796b14d10b47aebf342fd371cc4967/nikit_SURFACE-LT_2026-10-05_06_21_08_net10.0.trx` | 1/0/0, cold reopen before final peer-count assertions | `81297b63ea8ebbc90dd5469f38179e6c4ff9f5f0ac3cee39a7f625a1480e84c4` |
| `s05-grant-native-cycle-full-98493fdc54d44633a7d2542c462ca3a8/nikit_SURFACE-LT_2026-10-05_06_22_14_net10.0.trx` | final348/0/7 | `8df7ae06a94452a244d480cfed7331c3332cde027bb0cdcfea3238897b918d1a` |
