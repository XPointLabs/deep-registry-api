-- Explicit once-only operator provisioning after DR75; never runtime DDL.
-- Stop coordination dispatch and back up both exact tables and latest-head floor.
-- Existing request bytes/reservations/winners/counts/capacity are unchanged.
-- A competing same-account/XRA-generation reservation aborts the transaction:
-- stop and investigate, never discard audit rows or select a winner implicitly.
BEGIN;
LOCK TABLE deep_did2_route_journal_network, deep_did2_route_threshold_journal IN ACCESS EXCLUSIVE MODE;
CREATE UNIQUE INDEX deep_did2_route_generation_winner ON deep_did2_route_threshold_journal
    (network_id, (substring(exact_request FROM 57 FOR 32)),
     (substring(exact_request FROM 646 FOR 32)), (substring(exact_request FROM 686 FOR 8)));
ALTER TABLE deep_did2_route_journal_network
    ADD COLUMN generation_fence_version smallint NOT NULL DEFAULT 1
    CHECK (generation_fence_version = 1);
COMMIT;
