-- Explicit operator-only DR89 provisioning, once on a DR79/V3 journal.
-- Keep opaque bytes, both previous fences, counts, capacity and authority floors.
-- No old-envelope decode/backfill and no runtime DDL/reset/deletion.
BEGIN;
LOCK TABLE deep_did2_publication_journal_network, deep_did2_publication_journal IN ACCESS EXCLUSIVE MODE;
ALTER TABLE deep_did2_publication_journal DROP CONSTRAINT deep_did2_publication_journal_exact_request_check;
ALTER TABLE deep_did2_publication_journal ADD CONSTRAINT deep_did2_publication_journal_exact_request_check
    CHECK (octet_length(exact_request) BETWEEN 23302 AND 171614);
ALTER TABLE deep_did2_publication_journal DROP CONSTRAINT deep_did2_publication_journal_projection_check;
ALTER TABLE deep_did2_publication_journal
    ADD COLUMN publication_kind smallint,
    ADD COLUMN locator_hash bytea,
    ADD CONSTRAINT deep_did2_publication_journal_projection_check CHECK (
        (directory_lookup_key IS NULL AND request_generation IS NULL AND predecessor_object_hash IS NULL AND object_ciphertext_hash IS NULL)
        OR (directory_lookup_key IS NOT NULL AND request_generation IS NOT NULL AND predecessor_object_hash IS NOT NULL AND object_ciphertext_hash IS NOT NULL
            AND octet_length(directory_lookup_key) = 32 AND octet_length(request_generation) = 8
            AND octet_length(predecessor_object_hash) = 32 AND octet_length(object_ciphertext_hash) = 32
            AND octet_length(exact_request) >= 23306 AND substring(exact_request FROM 1 FOR 2) IN (decode('0003','hex'),decode('0004','hex')))),
    ADD CONSTRAINT deep_did2_publication_journal_scope_check CHECK (
        (publication_kind IS NULL AND locator_hash IS NULL)
        OR (publication_kind IS NOT NULL AND publication_kind IN (1,2) AND locator_hash IS NOT NULL AND octet_length(locator_hash) = 32
            AND directory_lookup_key IS NOT NULL AND request_generation IS NOT NULL
            AND predecessor_object_hash IS NOT NULL AND object_ciphertext_hash IS NOT NULL
            AND octet_length(exact_request) >= 23322 AND substring(exact_request FROM 1 FOR 2) = decode('0004','hex')
            AND (publication_kind = 1 OR (request_generation = decode('0000000000000000','hex')
                AND predecessor_object_hash = decode(repeat('00',32),'hex')))));
DROP INDEX deep_did2_publication_generation_fence;
CREATE UNIQUE INDEX deep_did2_publication_generation_fence
    ON deep_did2_publication_journal (network_id, directory_lookup_key, request_generation)
    WHERE directory_lookup_key IS NOT NULL AND publication_kind IS NULL;
CREATE UNIQUE INDEX deep_did2_publication_scope_generation_fence
    ON deep_did2_publication_journal (network_id, directory_lookup_key, publication_kind, locator_hash, request_generation)
    WHERE publication_kind IS NOT NULL;
ALTER TABLE deep_did2_publication_journal_network DROP CONSTRAINT did2_publication_request_version_check;
ALTER TABLE deep_did2_publication_journal_network DROP CONSTRAINT did2_publication_generation_version_check;
UPDATE deep_did2_publication_journal_network SET request_envelope_version=4, generation_fence_version=2;
ALTER TABLE deep_did2_publication_journal_network
    ALTER COLUMN request_envelope_version SET DEFAULT 4,
    ALTER COLUMN generation_fence_version SET DEFAULT 2,
    ADD CONSTRAINT did2_publication_request_version_check CHECK (request_envelope_version=4),
    ADD CONSTRAINT did2_publication_generation_version_check CHECK (generation_fence_version=2);
COMMIT;
