-- Envelope encryption: each file is encrypted with a per-file data key
-- (DEK) that is itself wrapped by the key-encryption key and stored here. NULL
-- for directories and for legacy (v0/v1) files still encrypted under the global
-- key; those keep decrypting via the version byte in the blob.
ALTER TABLE fnode ADD COLUMN IF NOT EXISTS wrapped_dek BYTEA;
