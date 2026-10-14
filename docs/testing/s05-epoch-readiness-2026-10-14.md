# S05: retained issuance-epoch readiness

Date:2026-10-14. Owner: Mr. X. Source/runtime claims are separate.

The current dev operational successor exposed a same-UTC-day root/DTS handover
failure: signed policy/head renewal and ordinary TLS/NTS can work while retained
nonce custody rejects the changed DTT1 epoch ID at the same day number. This is
required fork rejection under the normative
[directory contract](../../../docs/architecture/ACCOUNT-DIRECTORY-TRANSPARENCY-V1.md),
not permission to reset quota/nonce markers or accept another same-number ID.
Operational ceremony coordination remains an S05 blocker.

`IContactResolveOneUseRequestLedger.RequireReadyAsync` now validates protected
quota/epoch/capacity before proof readiness succeeds, under the existing ledger
lease. Bounded recovery scans authenticate markers, honor cancellation, and do
not consume a nonce, delete markers, compact persisted state or advance its
revision. Same-day policy replacement is rejected with the closed reason
`issuance-epoch-rollback-or-fork`; arbitrary exception suffixes remain unclassified.
No wire, signature domain, state generation, legacy reader or fork waiver changed.

The new real-signature test checks same namespace, same-day successor rejection,
cold rejection, and next-day read-only readiness with identical quota/marker
bytes. The source build passed with zero warnings/errors. First focused attempt
ran65/16/0 because16 provider cases were launched without PostgreSQL; it remains
under `artifacts/s05-epoch-readiness-20261014/01`, not accepted.

Supported PostgreSQL wrapper focused02:81/0/0/native0:
`artifacts/s00/s05-epoch-readiness-02-96f1c205184844b8acf22b63cd7840e7/nikit_SURFACE-LT_2026-10-14_19_04_12_net10.0.trx`.
SHA256:`909E4A605B16F50ED6053C1294495B2324FD554AA3BE31496E04147947DF8AEB`.
Final ledger/diagnostics focused03:54/0/0/native0:
`artifacts/s00/s05-epoch-readiness-03-2c169b1ad1154786bccf737da6867e7f/nikit_SURFACE-LT_2026-10-14_19_06_49_net10.0.trx`.
SHA256:`3FB8DF2025FDAF80CC9618F64246A07B8E4A6AF6000025F1C55F47ECF45252B1`.

Canonical full01:398/0/7,405 exact mappings,2839 unchanged inputs,
all native stages0, FullAccepted=true; Windows PowerShell5.1/SDK10.0.301:
`artifacts/test-gate-20261014/s05-epoch-readiness-full-01/full/nikit_SURFACE-LT_2026-10-14_19_10_34_net10.0.trx`.
SHA256:`FC0EE47A44A3DBF1FE9CE6C4D205230DDC1D143DC770811231DDE69B080CC546`.
Interval2026-10-14T14:09:04.9796644Z–14:15:29.1710914Z. Seven original Unix-socket
skips still require Linux qualification; this source gate is not physical or GA.

The new Linux ARM64 dev Registry image was started against retained state/floor.
Actual HTTPS readiness now returns503 with the epoch-fork reason; all three ONION
capabilities remain unavailable. Diagnostic receipt:
`deep-devops/artifacts/s05-dev-operational-activation-20261014/04/runtime-registry.log`
(workspace-relative), native curl22/HTTP503, SHA256
`F024E0660EA2735D7E67894F19055F223D554EE0ECC4A7A27D114B2B4634061D`.
Production was not changed. No complete activation, mailbox issuance, device
delivery or release readiness is claimed. The supported install/resume scope is
owned by the [DevOps checkpoint](../../../deep-devops/docs/S05-AUTHORITY-HISTORY-2026-10-14.md#coordinated-installation-and-failed-connected-acceptance).
