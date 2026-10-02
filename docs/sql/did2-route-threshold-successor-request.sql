-- Explicit operator-only DR77 provisioning, once after DR75 and lineage fencing.
-- Preserves opaque history, reservations/counts/capacity and independent floors.
-- Never run from runtime or repair/delete conflicting history automatically.
BEGIN;
LOCK TABLE deep_did2_route_journal_network, deep_did2_route_threshold_journal IN ACCESS EXCLUSIVE MODE;
ALTER TABLE deep_did2_route_threshold_journal
    DROP CONSTRAINT deep_did2_route_threshold_journal_exact_request_check;
ALTER TABLE deep_did2_route_threshold_journal
    ADD CONSTRAINT deep_did2_route_threshold_journal_exact_request_check
    CHECK (octet_length(exact_request) BETWEEN 1151 AND 25065);
ALTER TABLE deep_did2_route_journal_network
    ADD COLUMN request_envelope_version smallint NOT NULL DEFAULT 3 CHECK (request_envelope_version = 3);
COMMIT;
