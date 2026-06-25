-- Per-file Merkle root for the chunked at-rest format (v3): a BLAKE3 tree over
-- the plaintext chunks, used to verify whole-file integrity on read. NULL for
-- directories, symlinks, and legacy (v0/v1/v2) blobs, which carry their own
-- integrity (a single AEAD tag) and keep decrypting via the version byte.
ALTER TABLE fnode ADD COLUMN IF NOT EXISTS merkle_root VARCHAR;
