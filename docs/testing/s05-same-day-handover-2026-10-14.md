# S05: same-day retained issuer handover

Date:2026-10-14. Owner: Mr. X. Contract:
[DR-0119](../../../docs/survival-program/decisions/DR-0119-dtt1-same-day-authority-handover.md).
The earlier failure/readiness receipt remains in
[epoch readiness](s05-epoch-readiness-2026-10-14.md).

The current issuer ledger accepts a same-day stored namespace only from the
protocol-minted exact verified paired ancestry. Before reservation it probes
every authenticated namespace's unchanged HMAC nonce path under the existing
exclusive lease. Any existing marker rejects reuse, even after a boot/sample or
authority change. Quota spans the whole day; compaction retains all same-day
ancestor markers. Unknown/sibling/future namespaces and older-authority rollback
still reject. No CRL1/CRS1 generation, encoding, raw allowlist or compatibility
reader changed. Readiness performs no reserve/compaction/deletion. Recovery scans
reuse one defensive namespace snapshot instead of allocating it per marker.

Actual PostgreSQL-provider focused01:84/0/0/native0:
`artifacts/s00/s05-same-day-handover-01-647e9211ccd24a27addb81ee8f0dd3f0/nikit_SURFACE-LT_2026-10-14_19_57_40_net10.0.trx`.
SHA256:`A40250391A2987ABCB577D2D7E9CA80159C517D70FCAE785C14946985418A7C6`.
Final focused03:57/0/0/native0:
`artifacts/s00/s05-same-day-handover-03-122829b70dc84047aadb6418663f5f8d/nikit_SURFACE-LT_2026-10-14_20_09_02_net10.0.trx`.
SHA256:`958DF5D72731B9067064494554899A46DFB227DEED173785B6CC9D12EEE4751D`.
Scope includes real signed paired renewal, warm/cold readiness, nonce reuse after
handover, aggregate quota, competing cold writers, partial ancestor marker,
sibling fork, authority rollback and read-only next-day recovery. Existing
head/floor/currentness cases were not weakened or retired.

Canonical full01:401/0/7,408 exact mappings,2842 unchanged inputs,
all native stages0, FullAccepted=true, zero build warnings/errors;
Windows PowerShell5.1/SDK10.0.301:
`artifacts/test-gate-20261014/s05-same-day-handover-full-01/full/nikit_SURFACE-LT_2026-10-14_20_11_38_net10.0.trx`.
SHA256:`4A01AC90C163BDF8E2893C1002819829F88E49EBEE43752283B0F3F2AE6A8E03`.
Interval2026-10-14T15:10:13.4726356Z–15:16:24.0154119Z. Seven original Unix-socket
skips still require their Linux lane. Protocol's independent package witness
retains its original S08 failure; this Registry full cannot waive it.

Actual current-dev Registry was updated against retained state/floor and current
role/TLS/traffic custody: proof/three independent ONION capabilities recovered21s,
then retained scoped restart passed20s offline/18s recovery/30s stable with the
same custody/mounts. Exact runtime evidence is owned by the
[DevOps checkpoint](../../../deep-devops/docs/S05-AUTHORITY-HISTORY-2026-10-14.md#same-day-lineage-aware-recovery).
The observed epoch collision is resolved. Protected grant sockets/journals,
remaining S05 lifecycle/issuer/node/client gates, physical messaging and release
readiness are not thereby accepted. No production write, marker reset or
registered identity replacement occurred.
