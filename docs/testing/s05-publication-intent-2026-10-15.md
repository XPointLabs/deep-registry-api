# S05 — original publication winner recovery prerequisite

Date: 2026-10-15. Source candidate only; no endpoint/deployment activation.

The single contract owner is
[CONTACT-RESOLVER](../../../docs/architecture/CONTACT-RESOLVER-V1.md), with
[DR-0123](../../../docs/survival-program/decisions/DR-0123-retained-publication-intent.md).
The private journal now reads a completed original winner under its existing
network lock, canonical row projections, exact request/response hash binding,
permanent generation fence and completed predecessor. No signer, reservation,
entry-count update, migration, new table or reset is involved. Returned bytes
are not current Protocol authority and cannot prove replica noncommit.

The disposable PostgreSQL provider in
`artifacts/s05-logical-assignment-20261015/retained-intent-01/provider.log`
completed native0, **2/0/0**. It checked genuine signed publication custody after
journal reopen, wrong nonce/leaf/hash, hostile bounds, cancellation, pending
winner and corrupt projection. The original row/response and count stayed
unchanged; pending did not mint a replacement and corruption was not repaired.
The isolated schema/container/tmpfs database were removed by their owners;
retained current-dev and production custody were untouched.

Protocol's separate owner/issuer intent results keep decryption claims distinct.
Fresh current mutation lease, exact original two-peer dispatch/reconciliation,
durable adoption and physical Windows/Android recovery are still open. These
source/provider tests are not an operational or release acceptance.
