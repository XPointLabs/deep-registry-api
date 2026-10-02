-- Explicit operator provisioning in the same independent restore-authority
-- domain as deep_did2_latest_head_floor. Never execute DDL in runtime.
CREATE TABLE deep_did2_route_journal_network (
    network_id bytea PRIMARY KEY CHECK (octet_length(network_id) = 16),
    entry_count bigint NOT NULL CHECK (entry_count >= 0),
    maximum_entries bigint NOT NULL CHECK (maximum_entries BETWEEN 1 AND 1048576),
    response_envelope_version smallint NOT NULL DEFAULT 3 CHECK (response_envelope_version = 3),
    generation_fence_version smallint NOT NULL DEFAULT 1 CHECK (generation_fence_version = 1),
    CHECK (entry_count <= maximum_entries)
);
CREATE TABLE deep_did2_route_threshold_journal (
    network_id bytea NOT NULL REFERENCES deep_did2_route_journal_network(network_id),
    request_nonce bytea NOT NULL CHECK (octet_length(request_nonce) = 32),
    exact_request bytea NOT NULL CHECK (octet_length(exact_request) = 1151),
    -- The lower storage bound preserves retired opaque audit rows; runtime
    -- accepts only current V3 responses, never an old V2 reader.
    exact_response bytea CHECK (octet_length(exact_response) BETWEEN 2151 AND 15179),
    PRIMARY KEY (network_id, request_nonce)
);
-- Canonical request V2: account lookup, XRA1 field 2 (stable advertisement ID),
-- field 3 (unsigned generation bytes). PostgreSQL bytea offsets are 1-based.
CREATE UNIQUE INDEX deep_did2_route_generation_winner ON deep_did2_route_threshold_journal
    (network_id, (substring(exact_request FROM 57 FOR 32)),
     (substring(exact_request FROM 646 FOR 32)), (substring(exact_request FROM 686 FOR 8)));
-- Operator inserts one network row with entry_count=0 and explicit capacity.
-- Runtime: SELECT and UPDATE(entry_count) on network table;
-- SELECT/INSERT and UPDATE(exact_response) on journal. Request bytes and
-- network/nonce/capacity columns are immutable to the runtime role.
-- Never grant DDL, DELETE, TRUNCATE or authority to recreate an empty network.
-- Preserve rows permanently, with the independent floor, across backups,
-- upgrade and recovery. Capacity exhaustion requires explicit operator work.
