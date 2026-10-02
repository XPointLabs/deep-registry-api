-- Explicit operator-only DR79 provisioning, once on the pre-DR79 journal.
-- Preserve opaque audit requests/responses, capacity/count and authority floors.
-- No runtime DDL, old-request decode, projection backfill, reset or deletion.
BEGIN;
LOCK TABLE deep_did2_publication_journal_network, deep_did2_publication_journal IN ACCESS EXCLUSIVE MODE;
ALTER TABLE deep_did2_publication_journal DROP CONSTRAINT deep_did2_publication_journal_exact_request_check;
ALTER TABLE deep_did2_publication_journal ADD CONSTRAINT deep_did2_publication_journal_exact_request_check
    CHECK (octet_length(exact_request) BETWEEN 23302 AND 171598);
ALTER TABLE deep_did2_publication_journal
    ADD COLUMN directory_lookup_key bytea,
    ADD COLUMN request_generation bytea,
    ADD COLUMN predecessor_object_hash bytea,
    ADD COLUMN object_ciphertext_hash bytea,
    ADD CONSTRAINT deep_did2_publication_journal_projection_check CHECK (
        (directory_lookup_key IS NULL AND request_generation IS NULL AND predecessor_object_hash IS NULL AND object_ciphertext_hash IS NULL)
        OR (directory_lookup_key IS NOT NULL AND request_generation IS NOT NULL AND predecessor_object_hash IS NOT NULL AND object_ciphertext_hash IS NOT NULL
            AND octet_length(directory_lookup_key) = 32 AND octet_length(request_generation) = 8
            AND octet_length(predecessor_object_hash) = 32 AND octet_length(object_ciphertext_hash) = 32
            AND octet_length(exact_request) >= 23306 AND substring(exact_request FROM 1 FOR 2) = decode('0003', 'hex')));
CREATE UNIQUE INDEX deep_did2_publication_generation_fence
    ON deep_did2_publication_journal (network_id, directory_lookup_key, request_generation)
    WHERE directory_lookup_key IS NOT NULL;
ALTER TABLE deep_did2_publication_journal_network
    ADD COLUMN request_envelope_version smallint NOT NULL DEFAULT 3 CONSTRAINT did2_publication_request_version_check CHECK (request_envelope_version = 3),
    ADD COLUMN generation_fence_version smallint NOT NULL DEFAULT 1 CONSTRAINT did2_publication_generation_version_check CHECK (generation_fence_version = 1);
COMMIT;
