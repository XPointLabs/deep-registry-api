-- Explicit operator provisioning in the independent DID2 restore-authority DB.
-- Runtime cannot create/repair this root or persist raw XMG capabilities.
CREATE TABLE deep_did2_grant_journal_network (
    network_id bytea PRIMARY KEY CHECK (octet_length(network_id) = 16),
    entry_count bigint NOT NULL CHECK (entry_count >= 0),
    maximum_entries bigint NOT NULL CHECK (maximum_entries BETWEEN 1 AND 1048576),
    CHECK (entry_count <= maximum_entries)
);
CREATE TABLE deep_did2_grant_journal (
    network_id bytea NOT NULL REFERENCES deep_did2_grant_journal_network(network_id),
    operation_id bytea NOT NULL CHECK (octet_length(operation_id) = 32),
    request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
    scope_hash bytea NOT NULL CHECK (octet_length(scope_hash) = 32),
    exact_response bytea CHECK (octet_length(exact_response) = 478),
    PRIMARY KEY (network_id, operation_id)
);
-- Operator inserts one network row with count=0 and explicit capacity.
-- Runtime: SELECT/UPDATE(entry_count) on network, SELECT/INSERT and
-- UPDATE(exact_response) on journal. No DDL, DELETE, TRUNCATE or updates to
-- immutable request/scope/network/operation/capacity columns. Preserve rows
-- with the independent floor across backup/upgrade/recovery; never evict.
