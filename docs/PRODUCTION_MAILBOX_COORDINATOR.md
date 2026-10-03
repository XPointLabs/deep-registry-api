# Registry mailbox composition

The pre-cutover PMA1 coordinator, issuance endpoints, owner-control state and
software signer have been removed, not disabled or adapted. Their previous
configuration is rejected even when `Enabled=false`.

Use the [current private DID2 issuer runbook](DID2_PRIVATE_MAILBOX_GRANTS.md)
and the normative [DR-0081](../../docs/survival-program/decisions/DR-0081-did2-mailbox-selection-grant-clean-break.md).
This source retirement does not reset existing databases, registered keys or
protected floors, and does not prove live mailbox/device delivery.
