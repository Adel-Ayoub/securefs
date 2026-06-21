use std::sync::OnceLock;

use aes_gcm::aead::{Aead, AeadCore};
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroizing;

use securefs_keyring::{KeyProvider, LocalKeyProvider};
use securefs_server::dao;

// At-rest format versions (first byte of a blob):
//   0x00 = legacy: nonce(12) || ciphertext, no compression, global key
//   0x01 = zstd then AES-256-GCM under the global key: 0x01 || nonce || ct
//   0x02 = envelope: zstd then AES-256-GCM under a per-file DEK; the DEK is
//          wrapped by the KEK and stored as file metadata (fnode.wrapped_dek)
const FORMAT_V1_ZSTD: u8 = 0x01;
const FORMAT_V2_ENVELOPE: u8 = 0x02;
//   0x03 = chunked envelope: per-chunk zstd-then-AES-256-GCM under a per-file DEK
//          with STREAM nonces, plus a per-file Merkle root over the plaintext.
const FORMAT_V3_CHUNKED: u8 = 0x03;

// HKDF-SHA256 info labels. The DEK-wrapping label is fixed across generations:
// rotation changes the master, not the label, so the KEK for a generation is
// HKDF(master_for_that_generation, DEK_WRAP_INFO).
const DEK_WRAP_INFO: &[u8] = b"securefs-dek-wrap-v1";
const LEGACY_FILE_INFO: &[u8] = b"securefs-file-encryption-key-v1";

// Generation that new DEK wraps are stamped with. Set once at boot from the
// crypto_meta row; defaults to 1 (fresh DB / unit tests). Process-constant: it
// only changes across a restart following an offline KEK rotation.
static CURRENT_KEK_GENERATION: OnceLock<u8> = OnceLock::new();

fn current_generation() -> u8 {
    *CURRENT_KEK_GENERATION.get().unwrap_or(&1)
}

// Set the current KEK generation at boot from the crypto_meta row. Only the
// first call in a process takes effect; the value is process-constant and only
// changes across a restart following an offline rotation.
pub fn set_current_generation(generation: u8) {
    let _ = CURRENT_KEK_GENERATION.set(generation);
}

// Whether the current master's KEK can unwrap this stored DEK. Used at boot to
// fail fast on a wrong DATA_KEY or an incomplete rotation rather than surfacing
// the error on first file access.
pub fn can_unwrap(wrapped: &[u8]) -> bool {
    unwrap_dek(wrapped).is_ok()
}

// The currently configured master secret (env/file), zeroized on drop.
fn current_master() -> Zeroizing<Vec<u8>> {
    LocalKeyProvider::new(dao::get_data_key())
        .master_key()
        .expect("local key provider yields the configured secret")
}

// Derive a 32-byte subkey from an explicit master for a given HKDF label.
fn derive_from_master(master: &[u8], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let hkdf = Hkdf::<Sha256>::new(None, master);
    let mut okm = Zeroizing::new([0u8; 32]);
    hkdf.expand(info, okm.as_mut_slice())
        .expect("32 bytes is valid output length for HKDF-SHA256");
    okm
}

// Derive a subkey from the currently configured master.
fn derive_key(info: &[u8]) -> Zeroizing<[u8; 32]> {
    derive_from_master(&current_master(), info)
}

// Key-encryption key for a given generation's master. Exposed so rotation can
// derive the old and new KEKs side by side from their respective masters.
pub fn kek_from_master(master: &[u8]) -> Zeroizing<[u8; 32]> {
    derive_from_master(master, DEK_WRAP_INFO)
}

// Key-encryption key that wraps per-file DEKs under the current master.
fn dek_wrapping_key() -> Zeroizing<[u8; 32]> {
    kek_from_master(&current_master())
}

// Global key for legacy (v0/v1) files written before envelope encryption.
fn legacy_file_key() -> Zeroizing<[u8; 32]> {
    derive_key(LEGACY_FILE_INFO)
}

// Wrap a DEK under the current KEK, stamping the current generation.
fn wrap_dek(dek: &[u8]) -> Vec<u8> {
    wrap_dek_with(&dek_wrapping_key(), current_generation(), dek)
}

// Wrap a DEK under an explicit KEK: generation(1) || nonce(12) || ciphertext.
fn wrap_dek_with(kek: &[u8; 32], generation: u8, dek: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(kek.as_slice()));
    let nonce = Aes256Gcm::generate_nonce(OsRng);
    let ct = cipher
        .encrypt(&nonce, dek)
        .expect("AES-GCM wrap should not fail with valid inputs");
    let mut out = Vec::with_capacity(1 + 12 + ct.len());
    out.push(generation);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

// A DEK wrapped under AES-256-GCM is nonce(12) || ciphertext(dek 32 + tag 16).
const WRAPPED_BODY_LEN: usize = 12 + 32 + 16;

// Split a stored wrapped DEK into (generation, body = nonce || ciphertext).
// Values of exactly WRAPPED_BODY_LEN predate the generation prefix and are
// generation 1; longer values carry the generation in the first byte.
fn split_wrapped(wrapped: &[u8]) -> Result<(u8, &[u8]), &'static str> {
    let n = wrapped.len();
    if n == WRAPPED_BODY_LEN {
        Ok((1, wrapped))
    } else if n == WRAPPED_BODY_LEN + 1 {
        Ok((wrapped[0], &wrapped[1..]))
    } else {
        Err("wrapped dek has unexpected length")
    }
}

// Unwrap a DEK using the current master's KEK (runtime path). The stored
// generation is informational here: post-rotation every DEK is at the current
// generation, so a mismatch surfaces as an authentication failure.
fn unwrap_dek(wrapped: &[u8]) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let (_generation, body) = split_wrapped(wrapped)?;
    unwrap_dek_with(&dek_wrapping_key(), body)
}

// Unwrap a DEK body (nonce || ciphertext) under an explicit KEK.
fn unwrap_dek_with(kek: &[u8; 32], body: &[u8]) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    if body.len() < 12 + 16 {
        return Err("wrapped dek too short");
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(kek.as_slice()));
    let nonce = Nonce::from_slice(&body[..12]);
    let dek = cipher
        .decrypt(nonce, &body[12..])
        .map_err(|_| "dek unwrap failed")?;
    Ok(Zeroizing::new(dek))
}

// The generation a stored wrapped DEK was wrapped under.
pub fn wrapped_generation(wrapped: &[u8]) -> Result<u8, &'static str> {
    Ok(split_wrapped(wrapped)?.0)
}

// Unwrap a stored DEK under a specific master's KEK; None if that master does
// not authenticate it. Used by rotation to validate the old key and to verify
// rewraps - never on the hot path.
pub fn unwrap_with_master(wrapped: &[u8], master: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let (_generation, body) = split_wrapped(wrapped).ok()?;
    unwrap_dek_with(&kek_from_master(master), body).ok()
}

// Rewrap a DEK from the old KEK to the new KEK, stamping `new_generation`. The
// DEK itself (and therefore the file body) is unchanged.
pub fn rewrap_dek(
    wrapped: &[u8],
    old_kek: &[u8; 32],
    new_kek: &[u8; 32],
    new_generation: u8,
) -> Result<Vec<u8>, &'static str> {
    let (_generation, body) = split_wrapped(wrapped)?;
    let dek = unwrap_dek_with(old_kek, body)?;
    Ok(wrap_dek_with(new_kek, new_generation, &dek))
}

// Decrypt a zstd-then-AEAD body (the bytes after the version byte: nonce || ct).
fn open_zstd(key: &Key<Aes256Gcm>, body: &[u8]) -> Result<Vec<u8>, &'static str> {
    if body.len() < 12 + 16 {
        return Err("encrypted data too short");
    }
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&body[..12]);
    let compressed = cipher
        .decrypt(nonce, &body[12..])
        .map_err(|_| "decryption failed")?;
    zstd::decode_all(compressed.as_slice()).map_err(|_| "decompression failed")
}

/// Encrypt content as a single whole-file AEAD envelope (`0x02`). Superseded for
/// new writes by [`encrypt_file_chunked`]; kept to build test vectors so the
/// older decode path keeps regression coverage (those blobs still exist on disk).
#[cfg(test)]
pub fn encrypt_file_content(content: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let compressed = zstd::encode_all(content, 3).expect("zstd compression should not fail");
    let dek = Aes256Gcm::generate_key(OsRng);
    let cipher = Aes256Gcm::new(&dek);
    let nonce = Aes256Gcm::generate_nonce(OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, compressed.as_ref())
        .expect("AES-GCM encryption should not fail with valid inputs");
    let mut blob = Vec::with_capacity(1 + 12 + ciphertext.len());
    blob.push(FORMAT_V2_ENVELOPE);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    let wrapped = wrap_dek(dek.as_slice());
    (blob, wrapped)
}

/// Decrypt file content. v2 (envelope) requires the file's wrapped DEK; v1 and
/// legacy blobs decrypt under the global key.
pub fn decrypt_file_content(
    encrypted: &[u8],
    wrapped_dek: Option<&[u8]>,
) -> Result<Vec<u8>, &'static str> {
    if encrypted.is_empty() {
        return Err("encrypted data too short");
    }

    match encrypted[0] {
        FORMAT_V3_CHUNKED => {
            let wrapped = wrapped_dek.ok_or("missing wrapped dek for chunked file")?;
            decrypt_file_chunked(encrypted, wrapped).map(|(content, _root)| content)
        }
        FORMAT_V2_ENVELOPE => {
            let wrapped = wrapped_dek.ok_or("missing wrapped dek for envelope file")?;
            let dek = unwrap_dek(wrapped)?;
            open_zstd(Key::<Aes256Gcm>::from_slice(&dek), &encrypted[1..])
        }
        FORMAT_V1_ZSTD => {
            let key = legacy_file_key();
            open_zstd(
                Key::<Aes256Gcm>::from_slice(key.as_slice()),
                &encrypted[1..],
            )
        }
        _ => {
            // Legacy: nonce(12) || ciphertext, no version byte, no compression.
            if encrypted.len() < 12 + 16 {
                return Err("encrypted data too short");
            }
            let key = legacy_file_key();
            let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_slice()));
            let nonce = Nonce::from_slice(&encrypted[..12]);
            cipher
                .decrypt(nonce, &encrypted[12..])
                .map_err(|_| "decryption failed")
        }
    }
}

/// Compute BLAKE3 hash of file content for integrity verification.
pub fn hash_content(content: &[u8]) -> String {
    hex::encode(blake3::hash(content).as_bytes())
}

// Chunked envelope (v3): zstd-then-AES-256-GCM per fixed-size plaintext chunk
// under the per-file DEK, framed as 0x03 || prefix(7) || (len32 || aead_chunk)*.
// Each chunk's nonce is a STREAM construction - a 7-byte per-file random prefix,
// a 4-byte big-endian chunk counter, and a 1-byte final flag - so chunks cannot
// be reordered, dropped, or truncated without an authentication failure.
const CHUNK_PLAINTEXT_SIZE: usize = 64 * 1024;
// Sanity bound on one framed ciphertext chunk; guards the decrypt-side framing.
const CHUNK_CIPHERTEXT_MAX: usize = CHUNK_PLAINTEXT_SIZE + 4096;

fn stream_nonce(prefix: &[u8; 7], counter: u32, is_final: bool) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..7].copy_from_slice(prefix);
    nonce[7..11].copy_from_slice(&counter.to_be_bytes());
    nonce[11] = u8::from(is_final);
    nonce
}

// Binary BLAKE3 Merkle root over chunk leaves; an odd node is promoted a level.
fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return *blake3::hash(&[]).as_bytes();
    }
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            if pair.len() == 2 {
                let mut hasher = blake3::Hasher::new();
                hasher.update(&pair[0]);
                hasher.update(&pair[1]);
                next.push(*hasher.finalize().as_bytes());
            } else {
                next.push(pair[0]);
            }
        }
        level = next;
    }
    level[0]
}

/// Encrypt content as the chunked envelope format (v3). Returns the on-disk blob,
/// the wrapped DEK, and the hex Merkle root over the plaintext chunks.
pub fn encrypt_file_chunked(content: &[u8]) -> (Vec<u8>, Vec<u8>, String) {
    let dek = Aes256Gcm::generate_key(OsRng);
    let cipher = Aes256Gcm::new(&dek);
    let mut prefix = [0u8; 7];
    OsRng.fill_bytes(&mut prefix);

    let pieces: Vec<&[u8]> = if content.is_empty() {
        vec![&[][..]]
    } else {
        content.chunks(CHUNK_PLAINTEXT_SIZE).collect()
    };
    let n = pieces.len();

    let mut blob = Vec::with_capacity(1 + 7 + content.len());
    blob.push(FORMAT_V3_CHUNKED);
    blob.extend_from_slice(&prefix);

    let mut leaves = Vec::with_capacity(n);
    for (i, piece) in pieces.iter().enumerate() {
        let nonce = stream_nonce(&prefix, i as u32, i == n - 1);
        let compressed = zstd::encode_all(*piece, 3).expect("zstd compression should not fail");
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce), compressed.as_ref())
            .expect("AES-GCM encryption should not fail with valid inputs");
        blob.extend_from_slice(&(ct.len() as u32).to_be_bytes());
        blob.extend_from_slice(&ct);
        leaves.push(*blake3::hash(piece).as_bytes());
    }

    let wrapped = wrap_dek(dek.as_slice());
    (blob, wrapped, hex::encode(merkle_root(&leaves)))
}

/// Decrypt a chunked envelope (v3) blob. Returns the plaintext and the hex Merkle
/// root recomputed from it, for the caller to check against the stored root.
pub fn decrypt_file_chunked(
    blob: &[u8],
    wrapped_dek: &[u8],
) -> Result<(Vec<u8>, String), &'static str> {
    if blob.len() < 8 || blob[0] != FORMAT_V3_CHUNKED {
        return Err("not a chunked (v3) blob");
    }
    let dek = unwrap_dek(wrapped_dek)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&dek));
    let prefix: [u8; 7] = blob[1..8].try_into().expect("7-byte prefix");

    // Parse framing first so the final-chunk flag is known before decrypting.
    let mut frames = Vec::new();
    let mut pos = 8;
    while pos < blob.len() {
        if pos + 4 > blob.len() {
            return Err("truncated chunk header");
        }
        let len = u32::from_be_bytes(blob[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        if !(16..=CHUNK_CIPHERTEXT_MAX).contains(&len) || pos + len > blob.len() {
            return Err("invalid chunk length");
        }
        frames.push((pos, len));
        pos += len;
    }
    let n = frames.len();
    if n == 0 {
        return Err("no chunks");
    }

    let mut out = Vec::new();
    let mut leaves = Vec::with_capacity(n);
    for (i, &(off, len)) in frames.iter().enumerate() {
        let nonce = stream_nonce(&prefix, i as u32, i == n - 1);
        let compressed = cipher
            .decrypt(Nonce::from_slice(&nonce), &blob[off..off + len])
            .map_err(|_| "chunk authentication failed")?;
        let piece = zstd::decode_all(compressed.as_slice()).map_err(|_| "decompression failed")?;
        leaves.push(*blake3::hash(&piece).as_bytes());
        out.extend_from_slice(&piece);
    }
    Ok((out, hex::encode(merkle_root(&leaves))))
}

/// Whether a blob is the chunked (v3) format.
pub fn is_chunked(blob: &[u8]) -> bool {
    blob.first() == Some(&FORMAT_V3_CHUNKED)
}

/// Decrypt any at-rest format, additionally checking a v3 file's recomputed
/// Merkle root against the stored one when one is provided.
pub fn decrypt_verified(
    blob: &[u8],
    wrapped_dek: Option<&[u8]>,
    expected_root: Option<&str>,
) -> Result<Vec<u8>, &'static str> {
    if is_chunked(blob) {
        let wrapped = wrapped_dek.ok_or("missing wrapped dek for chunked file")?;
        let (content, root) = decrypt_file_chunked(blob, wrapped)?;
        if let Some(expected) = expected_root {
            if expected != root {
                return Err("merkle root mismatch");
            }
        }
        Ok(content)
    } else {
        decrypt_file_content(blob, wrapped_dek)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set_key() {
        // SAFETY: tests in this module run single-threaded under one process.
        unsafe { std::env::set_var("DB_PASS", "crypto-test-secret") };
    }

    #[test]
    fn envelope_round_trip() {
        set_key();
        let (blob, wrapped) = encrypt_file_content(b"hello envelope");
        assert_eq!(blob[0], FORMAT_V2_ENVELOPE);
        let out = decrypt_file_content(&blob, Some(&wrapped)).unwrap();
        assert_eq!(out, b"hello envelope");
    }

    #[test]
    fn envelope_needs_its_wrapped_dek() {
        set_key();
        let (blob, _wrapped) = encrypt_file_content(b"secret");
        assert!(decrypt_file_content(&blob, None).is_err());
    }

    #[test]
    fn distinct_files_get_distinct_deks() {
        set_key();
        let (_b1, w1) = encrypt_file_content(b"a");
        let (_b2, w2) = encrypt_file_content(b"b");
        assert_ne!(w1, w2, "each file must get its own wrapped DEK");
    }

    #[test]
    fn legacy_v1_still_decrypts() {
        set_key();
        // Produce a v1 blob (global key) the way pre-envelope writes did.
        let compressed = zstd::encode_all(&b"old file"[..], 3).unwrap();
        let key = legacy_file_key();
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_slice()));
        let nonce = Aes256Gcm::generate_nonce(OsRng);
        let ct = cipher.encrypt(&nonce, compressed.as_ref()).unwrap();
        let mut blob = vec![FORMAT_V1_ZSTD];
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ct);
        // Decrypts with no wrapped DEK (global key path).
        assert_eq!(decrypt_file_content(&blob, None).unwrap(), b"old file");
    }

    #[test]
    fn wrapped_dek_carries_current_generation() {
        set_key();
        let (_blob, wrapped) = encrypt_file_content(b"x");
        // Default current generation is 1, stamped as the first byte.
        assert_eq!(wrapped.len(), WRAPPED_BODY_LEN + 1);
        assert_eq!(split_wrapped(&wrapped).unwrap().0, 1);
    }

    #[test]
    fn legacy_unprefixed_wrapped_dek_still_unwraps() {
        set_key();
        let (blob, wrapped) = encrypt_file_content(b"compat");
        // The 60-byte body is the pre-generation on-disk form; it must still open.
        let (_gen, body) = split_wrapped(&wrapped).unwrap();
        assert_eq!(body.len(), WRAPPED_BODY_LEN);
        assert_eq!(decrypt_file_content(&blob, Some(body)).unwrap(), b"compat");
    }

    #[test]
    fn rewrap_to_new_generation_under_new_kek() {
        let old_kek = kek_from_master(b"old-master");
        let new_kek = kek_from_master(b"new-master");
        let dek = [7u8; 32];

        let w1 = wrap_dek_with(&old_kek, 1, &dek);
        assert_eq!(split_wrapped(&w1).unwrap().0, 1);

        // Rewrap old -> new without changing the DEK itself.
        let (_g1, body1) = split_wrapped(&w1).unwrap();
        let unwrapped = unwrap_dek_with(&old_kek, body1).unwrap();
        let w2 = wrap_dek_with(&new_kek, 2, &unwrapped);

        assert_eq!(split_wrapped(&w2).unwrap().0, 2);
        let (_g2, body2) = split_wrapped(&w2).unwrap();
        assert_eq!(&**unwrap_dek_with(&new_kek, body2).unwrap(), &dek);
        // The old KEK can no longer open the rewrapped DEK.
        assert!(unwrap_dek_with(&old_kek, body2).is_err());
    }

    #[test]
    fn rewrap_dek_rebinds_through_public_api() {
        let old_kek = kek_from_master(b"old");
        let new_kek = kek_from_master(b"new");
        let dek = [9u8; 32];

        let w1 = wrap_dek_with(&old_kek, 1, &dek);
        let w2 = rewrap_dek(&w1, &old_kek, &new_kek, 2).unwrap();

        assert_eq!(wrapped_generation(&w2).unwrap(), 2);
        assert_eq!(&**unwrap_with_master(&w2, b"new").unwrap(), &dek);
        assert!(unwrap_with_master(&w2, b"old").is_none());
        // A wrong old key fails the rewrap rather than producing garbage.
        assert!(rewrap_dek(&w1, &new_kek, &new_kek, 2).is_err());
    }

    #[test]
    fn chunked_round_trip_multi_chunk() {
        set_key();
        // > 3 chunks of 64 KiB.
        let content: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let (blob, wrapped, root) = encrypt_file_chunked(&content);
        assert_eq!(blob[0], FORMAT_V3_CHUNKED);
        let (out, root2) = decrypt_file_chunked(&blob, &wrapped).unwrap();
        assert_eq!(out, content);
        assert_eq!(root, root2);
        // decrypt_file_content dispatches v3 by the version byte too.
        assert_eq!(
            decrypt_file_content(&blob, Some(&wrapped)).unwrap(),
            content
        );
    }

    #[test]
    fn chunked_empty_and_single_chunk() {
        set_key();
        for content in [Vec::new(), b"small file".to_vec()] {
            let (blob, wrapped, root) = encrypt_file_chunked(&content);
            let (out, root2) = decrypt_file_chunked(&blob, &wrapped).unwrap();
            assert_eq!(out, content);
            assert_eq!(root, root2);
        }
    }

    #[test]
    fn chunked_tamper_is_detected() {
        set_key();
        let content = vec![7u8; 100_000];
        let (mut blob, wrapped, _root) = encrypt_file_chunked(&content);
        // Flip a byte inside the first chunk's ciphertext.
        blob[20] ^= 0x01;
        assert!(decrypt_file_chunked(&blob, &wrapped).is_err());
    }

    #[test]
    fn chunked_truncation_is_detected() {
        set_key();
        let content = vec![3u8; 200_000]; // 4 plaintext chunks
        let (blob, wrapped, _root) = encrypt_file_chunked(&content);
        // Keep only the first chunk's frame. It was encrypted as non-final, so
        // decrypting it as the new final chunk fails authentication.
        let l0 = u32::from_be_bytes(blob[8..12].try_into().unwrap()) as usize;
        let truncated = &blob[..12 + l0];
        assert!(decrypt_file_chunked(truncated, &wrapped).is_err());
    }

    #[test]
    fn chunked_root_changes_with_content() {
        set_key();
        let (_b1, _w1, r1) = encrypt_file_chunked(b"alpha");
        let (_b2, _w2, r2) = encrypt_file_chunked(b"beta");
        assert_ne!(r1, r2);
    }

    #[test]
    fn decrypt_verified_checks_merkle_root() {
        set_key();
        let content = vec![5u8; 100_000];
        let (blob, wrapped, root) = encrypt_file_chunked(&content);
        // The stored root verifies.
        assert_eq!(
            decrypt_verified(&blob, Some(&wrapped), Some(&root)).unwrap(),
            content
        );
        // A wrong stored root is rejected even though every chunk authenticates.
        let bad = "0".repeat(64);
        assert!(decrypt_verified(&blob, Some(&wrapped), Some(&bad)).is_err());
        // No expected root skips the comparison (AEAD still authenticates).
        assert_eq!(
            decrypt_verified(&blob, Some(&wrapped), None).unwrap(),
            content
        );
    }

    #[test]
    fn decrypt_verified_passes_through_non_chunked() {
        set_key();
        let (blob, wrapped) = encrypt_file_content(b"plain file");
        // Non-chunked blobs ignore the root argument and decrypt as before.
        assert_eq!(
            decrypt_verified(&blob, Some(&wrapped), None).unwrap(),
            b"plain file"
        );
    }
}
