-- Explicit operator-only DR81 constraint cutover in the restore-authority DB.
-- No winner conversion, deletion, request rewrite or capacity/floor reset.
BEGIN;
LOCK TABLE deep_did2_grant_journal IN ACCESS EXCLUSIVE MODE;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM deep_did2_grant_journal
               WHERE exact_response IS NOT NULL AND octet_length(exact_response) <> 510) THEN
        RAISE EXCEPTION 'Mailbox grant cutover requires review of incompatible retained winners; no conversion is allowed';
    END IF;
END $$;
ALTER TABLE deep_did2_grant_journal
    DROP CONSTRAINT deep_did2_grant_journal_exact_response_check;
ALTER TABLE deep_did2_grant_journal
    ADD CONSTRAINT deep_did2_grant_journal_exact_response_check
    CHECK (octet_length(exact_response) = 510);
COMMIT;
