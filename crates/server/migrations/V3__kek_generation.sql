-- Tracks the current KEK generation for envelope encryption. Key rotation
-- rewraps every file's wrapped DEK from one generation's KEK to the next, then
-- bumps this counter; new writes stamp their wrap with the current generation.
-- Single-row table: id is pinned to 1.
CREATE TABLE IF NOT EXISTS crypto_meta (
    id SMALLINT PRIMARY KEY DEFAULT 1,
    kek_generation SMALLINT NOT NULL DEFAULT 1,
    CONSTRAINT crypto_meta_singleton CHECK (id = 1)
);

INSERT INTO crypto_meta (id, kek_generation) VALUES (1, 1)
    ON CONFLICT (id) DO NOTHING;

-- Stamp existing wrapped DEKs with generation 1. Pre-rotation DEKs were stored
-- as nonce(12) || ciphertext(48) = 60 bytes with no generation prefix; prepend
-- the generation byte so every stored DEK is self-describing. Length-guarded so
-- it never double-prefixes an already-stamped value.
UPDATE fnode
SET wrapped_dek = '\x01'::bytea || wrapped_dek
WHERE wrapped_dek IS NOT NULL AND octet_length(wrapped_dek) = 60;
