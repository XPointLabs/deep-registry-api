-- Explicit operator provisioning in the same independent restore-authority
-- domain as deep_did2_latest_head_floor. Never execute DDL in runtime.
CREATE TABLE deep_did2_publication_journal_network (
    network_id bytea PRIMARY KEY CHECK (octet_length(network_id) = 16),
    entry_count bigint NOT NULL CHECK (entry_count >= 0),
    maximum_entries bigint NOT NULL CHECK (maximum_entries BETWEEN 1 AND 1048576),
    request_envelope_version smallint NOT NULL DEFAULT 3 CONSTRAINT did2_publication_request_version_check CHECK (request_envelope_version = 3),
    generation_fence_version smallint NOT NULL DEFAULT 1 CONSTRAINT did2_publication_generation_version_check CHECK (generation_fence_version = 1),
    CHECK (entry_count <= maximum_entries)
);
CREATE TABLE deep_did2_publication_journal (
    network_id bytea NOT NULL REFERENCES deep_did2_publication_journal_network(network_id),
    request_nonce bytea NOT NULL CHECK (octet_length(request_nonce) = 32),
    -- The lower audit bound preserves opaque older rows during operator upgrades.
    -- Only projected V3 rows are usable by runtime; no history backfill/reader.
    exact_request bytea NOT NULL CHECK (octet_length(exact_request) BETWEEN 23302 AND 171598),
    exact_response bytea CHECK (octet_length(exact_response) BETWEEN 14682 AND 93092),
    directory_lookup_key bytea,
    request_generation bytea,
    predecessor_object_hash bytea,
    object_ciphertext_hash bytea,
    CONSTRAINT deep_did2_publication_journal_projection_check CHECK (
        (directory_lookup_key IS NULL AND request_generation IS NULL AND predecessor_object_hash IS NULL AND object_ciphertext_hash IS NULL)
        OR (directory_lookup_key IS NOT NULL AND request_generation IS NOT NULL AND predecessor_object_hash IS NOT NULL AND object_ciphertext_hash IS NOT NULL
            AND octet_length(directory_lookup_key) = 32 AND octet_length(request_generation) = 8
            AND octet_length(predecessor_object_hash) = 32 AND octet_length(object_ciphertext_hash) = 32
            AND octet_length(exact_request) >= 23306 AND substring(exact_request FROM 1 FOR 2) = decode('0003', 'hex'))),
    PRIMARY KEY (network_id, request_nonce)
);
CREATE UNIQUE INDEX deep_did2_publication_generation_fence
    ON deep_did2_publication_journal (network_id, directory_lookup_key, request_generation)
    WHERE directory_lookup_key IS NOT NULL;
-- Operator inserts one network row with entry_count=0 and explicit capacity.
-- Runtime: SELECT and UPDATE(entry_count) on network table;
-- SELECT/INSERT and UPDATE(exact_response) on journal. Request bytes and
-- network/nonce/capacity/markers/projections are immutable to the runtime role.
-- Never grant DDL, DELETE, TRUNCATE or authority to recreate an empty network.
-- Preserve rows permanently, with the independent floor, across backups,
-- upgrade and recovery. Capacity exhaustion requires explicit operator work.
