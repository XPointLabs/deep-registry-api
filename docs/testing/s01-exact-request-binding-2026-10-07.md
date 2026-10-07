# S01 exact acquisition request binding — Registry source gate

Date: 2026-10-07. Normative request owner:
[DR-0102](../../../docs/survival-program/decisions/DR-0102-exact-mailbox-request-route-binding.md).
Private HTTP ingress accepts the closed current request property only. Actual
issuer verification rejects a correctly holder-signed wrong route intent even
with both genuine replica signatures bound to its request digest, before any
SQL reservation or external role-signer callback. Journal/result framing and
existing role keys are unchanged; no retained issuer is activated.
[Matched-rollout consequences](../DID2_PRIVATE_MAILBOX_GRANTS.md).

Release source-cutover solution build0, zero warnings/errors. Final focused
17/0/0, terminal0, including the private ingress/issuer/immutable winner path.
The first complete native run is retained as **335/14/7, terminal1**. Its14
failures were the unchanged isolated PostgreSQL guard: supplied `route_test`
instead of required `deep_s00`. No guard/assertion was weakened. That existing
isolated container was returned to its original stopped state; data retained.

The repeat used the official DevOps `test-registry-postgres.ps1` provider,
with only no-build/no-restore and fresh results-directory changes in a private
copy, preserving loopback Docker endpoint checks, unique UUID label, tmpfs,
synthetic user/database and environment restoration. Its own temporary
container/database was cleaned up, not production or existing dev state.
Original native terminal0: **349/0/7**,356 executions. Seven existing Linux
Unix-socket skips remain skips, not passed production signer evidence.

Post-terminal qualification0 preserves all355 prior exact case/outcomes,
with two explicit current XMG case renames. Original prelaunch manifest2146
entries/hash `73548617B85B7F3EA3D130D6AF2CE00C02521BE13F0E49A26A96D9303ACA96EC`
was not replaced. All2145 immutable source/normative/executed-binary inputs are
unchanged. One overcaptured `bin/Release/net10.0/artifacts/registry-state.json`
is mutable test persistence: NodeRegistry loads and writes it. Its changed
hash is reported separately, not declared immutable or isolated-state evidence.
Only that exact path is classified separately; all other JSON/dependency files
remain hash checked. The xUnit metadata/multiset correction is described in the
[Protocol gate](../../../deep-protocol/docs/testing/s01-exact-request-binding-2026-10-07.md).
Post-terminal validator SHA256:
`807E0B11BED41FC0114E5B7693B262D36697CACF1CBC181101AAB3A7BDF19DCD`.

| Receipt under artifacts/s01-exact-request-binding | SHA256 |
| --- | --- |
| focused-final/focused-final.trx | `F1B6979B24863415123AAEF44C5108CBB86CE277F08E6592D17D04ED9FF7379D` |
| full/nikit_SURFACE-LT_2026-10-07_13_00_06_net10.0.trx | `BC289D68574BF6ED3657583DAEBB78DC3E8E09A27403C033D043CB9E1DB20312` |
| full-corrected-provider/nikit_SURFACE-LT_2026-10-07_13_05_18_net10.0.trx | `2C0DDE67260DC71CD52B17938D5EE1B7C7CA9F05D08555308EAE94ACAEC9EA61` |

This qualifies the bounded source change, not actual deployed HTTPS/external
custody, retained route availability, process-crash PostgreSQL protection,
renewed retained issuance or device delivery. No deployment/reset, registered
key/genesis change, GitHub Release or main merge was performed. S01 stays open.

## Matched CI provider configuration

Inspection before push found the same isolation mismatch in both existing
workflows: `registry-api.yml` and `publish-image.yml` provisioned `deep_ci`,
while the unchanged native test guard requires `deep_s00`. Both now use the
already-qualified loopback synthetic database/user in the service, health probe
and all three provider variables. The existing CI-only password, PostgreSQL
image, schema isolation and product/test assertions are unchanged. The selected
scanner initially flagged the old inline synthetic password in six connection
strings; that failed report is preserved. Those strings no longer contain a
password. Npgsql's documented [PGPASSWORD channel](https://www.npgsql.org/doc/connection-string-parameters#environment-variables)
supplies only the same disposable CI credential, not production key material.
Environment credentials are not the recommended production secret mechanism;
this exception is scoped to synthetic, short-lived CI authentication. No new
dependency, endpoint, workflow trigger or production deployment is added.

Bounded scalar checks plus the framework connection-string parser passed both
service/health scopes and all six provider strings. This is not general YAML
validation or executed GitHub CI. No product/test/binary input was rebuilt or
edited: the native349/0/7 provider gate above remains the source evidence.
The authorized exact-HEAD Linux CI run
[37599715974](https://github.com/XPointLabs/deep-registry-api/actions/runs/37599715974)
for `e694282127fce2e612919492d1f1751813d49404` restored and built successfully,
then completed **352/4/0, terminal1**. All four failures occur while generating
initial client prekeys: no release-approved ML-KEM asset exists for the Linux
process RID. They are the three crash modes of the actual route ceremony and
`ActualPrivateIssuerHttpsForwarderClientVerifierAndConfiguredNativeMailboxCycle`.
This is a platform/approved-asset qualification gap, not the Windows file-write
failure below or an accepted pass. No tests are filtered/skipped and no candidate
provider is substituted to hide it. Candidate image publication was skipped
because tests failed. The Windows native source receipt above does not qualify
these Linux crypto paths.
An additional frozen-binary full run with explicit host SCRAM authentication
and PGPASSWORD completed **348/1/7, terminal1**. PostgreSQL authentication worked;
the new failure is `ActualPqAccountAda2FloorWitnessCustodyAndJournalCloseOwnedRouteOverHttp(crashMode: 1)`:
`UnauthorizedAccessException` at protected one-use ledger `WriteState` during
publication issuer replay. It is not reclassified as an accepted baseline,
proof of a password-provider fault, or a fixed product defect. Cause remains
under investigation; no retry/ACL/crypto guard was weakened.
Receipt `full-ci-provider/nikit_SURFACE-LT_2026-10-07_14_04_35_net10.0.trx`, SHA256
`0CD32DA52B290CD92C8BC41EA26B573D51179D847BFD7E3179AB66F4BF6E409B`.
One bounded repeat of all three crash modes on the same frozen binaries and
SCRAM provider completed **3/0/0, terminal0**. The file-write failure did not
reproduce; this does not establish its cause or fix and does not supersede the
failed full run. No product, fixture, retry budget or permissions changed.
Receipt `ci-provider-file-triage/nikit_SURFACE-LT_2026-10-07_14_14_23_net10.0.trx`, SHA256
`4BC15592143EACF42AD3B66DD884F70ADD53265B4042D7F06736A08545ED5131`.
Regular CI may publish its existing immutable candidate image after successful
tests; it does not deploy production or create a GitHub Release. The separate
image publication workflow remains manual.
