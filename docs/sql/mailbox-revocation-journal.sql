-- Explicit operator provisioning in the independent restore-authority database.
-- No runtime DDL, auto-genesis, pruning, or reinitialization of a missing scope.
CREATE TABLE deep_mailbox_revocation_scope (
    network_id bytea NOT NULL CHECK (octet_length(network_id) = 16),
    policy_reference bytea NOT NULL CHECK (octet_length(policy_reference) = 38),
    role smallint NOT NULL CHECK (role IN (1, 2)),
    issuer_key bytea NOT NULL CHECK (octet_length(issuer_key) = 32),
    committed_generation bigint NOT NULL CHECK (committed_generation >= 0),
    entry_count bigint NOT NULL CHECK (entry_count >= 0),
    maximum_entries bigint NOT NULL CHECK (maximum_entries BETWEEN 1 AND 1048576),
    cumulative_serials bytea NOT NULL CHECK (
        octet_length(cumulative_serials) <= 65536 AND octet_length(cumulative_serials) % 16 = 0),
    PRIMARY KEY (network_id, policy_reference, role, issuer_key),
    CHECK (entry_count <= maximum_entries),
    CHECK (entry_count - committed_generation BETWEEN 0 AND 1)
);
CREATE TABLE deep_mailbox_revocation_snapshot (
    network_id bytea NOT NULL,
    policy_reference bytea NOT NULL,
    role smallint NOT NULL,
    issuer_key bytea NOT NULL,
    generation bigint NOT NULL CHECK (generation BETWEEN 1 AND 1048576),
    signing_input bytea NOT NULL CHECK (octet_length(signing_input) BETWEEN 288 AND 65824),
    exact_snapshot bytea CHECK (octet_length(exact_snapshot) BETWEEN 327 AND 65863),
    PRIMARY KEY (network_id, policy_reference, role, issuer_key, generation),
    FOREIGN KEY (network_id, policy_reference, role, issuer_key)
        REFERENCES deep_mailbox_revocation_scope(network_id, policy_reference, role, issuer_key)
);
-- Provision exactly one root per actual (network, PMA2 CoreRef, role, issuer key),
-- with committed_generation=entry_count=0, explicit capacity, empty bytea serials.
-- Runtime: SELECT; INSERT(snapshot); UPDATE(snapshot.exact_snapshot only);
-- UPDATE(scope.committed_generation, entry_count, cumulative_serials only).
-- Immutable signing_input must survive signer outage and an uncertain commit.
-- Preserve roots and all signed/pending rows together in independent custody.
-- No raw account/device identifiers, capabilities, signer secrets or node ID.
