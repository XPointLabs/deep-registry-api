-- Run once in an independently operated PostgreSQL database, outside the
-- ADA2 file's snapshot/backup/restore domain. Runtime must not own DDL rights.
CREATE TABLE deep_did2_latest_head_floor (
    network_id bytea PRIMARY KEY CHECK (octet_length(network_id) = 16),
    exact_adh1 bytea NOT NULL CHECK (octet_length(exact_adh1) BETWEEN 1 AND 4096),
    core_hash bytea NOT NULL CHECK (octet_length(core_hash) = 32)
);

-- Grant only SELECT, INSERT (operator provisioning) and UPDATE (runtime CAS)
-- to narrowly scoped roles. Never grant DELETE or TRUNCATE to the runtime.
