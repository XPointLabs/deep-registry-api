-- Explicit, atomic operator provisioning for DR75. Run once against the
-- existing independent restore-authority database, never inside runtime.
-- Keeps every existing opaque row, nonce, request, count, capacity and floor.
-- Retired response bytes remain audit-only: current runtime rejects them.
BEGIN;
LOCK TABLE deep_did2_route_journal_network, deep_did2_route_threshold_journal IN ACCESS EXCLUSIVE MODE;
ALTER TABLE deep_did2_route_threshold_journal
    DROP CONSTRAINT deep_did2_route_threshold_journal_exact_response_check;
ALTER TABLE deep_did2_route_threshold_journal
    ADD CONSTRAINT deep_did2_route_threshold_journal_exact_response_check
    CHECK (octet_length(exact_response) BETWEEN 2151 AND 15179);
ALTER TABLE deep_did2_route_journal_network
    ADD COLUMN response_envelope_version smallint NOT NULL DEFAULT 3
    CHECK (response_envelope_version = 3);
COMMIT;
