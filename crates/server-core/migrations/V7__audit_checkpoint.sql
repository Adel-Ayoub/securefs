-- Signed tree head for the audit chain: a keyed attestation that the chain head
-- was (head_seq, head_hash) when sealed. The MAC key derives from the server
-- master (DATA_KEY), which is absent from the database, so an attacker with DB
-- write access can recompute the unkeyed chain but cannot forge this seal -
-- altering, back-dating, or truncating sealed history then fails verification.
-- One current row (the latest sealed head); the structured log carries the
-- historical sequence of heads as a separate witness.
CREATE TABLE IF NOT EXISTS audit_checkpoint (
    id        INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    head_seq  BIGINT NOT NULL,
    head_hash BYTEA NOT NULL,
    seal      BYTEA NOT NULL,
    sealed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
