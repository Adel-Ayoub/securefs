-- Tamper-evident audit log. Each row is chained to its predecessor by
-- entry_hash = BLAKE3(domain || prev_hash || seq || ts || fields). seq is a
-- gapless counter assigned under an advisory lock so appends form one linear
-- chain; any in-place edit, reorder, insert, or deletion then fails verification.
-- Columns are nullable so a database that predates the chain adopts cleanly: a
-- Rust backfill chains existing rows at boot (the path_digest backfill pattern),
-- since the hash is computed in application code, not SQL (no BLAKE3 in pgcrypto).
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS seq BIGINT;
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS prev_hash BYTEA;
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS entry_hash BYTEA;

-- One row per chain position. The column is nullable until backfilled, and a
-- unique index permits many NULLs while rejecting a duplicate seq once chained.
CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_log_seq ON audit_log(seq);
