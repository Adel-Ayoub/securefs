use aes_gcm::aead::{Aead, AeadCore};
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use hkdf::Hkdf;
use rand_core::OsRng;
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

// Derive a 32-byte subkey from the master secret for a given HKDF info label.
fn derive_key(info: &[u8]) -> Zeroizing<[u8; 32]> {
    let provider = LocalKeyProvider::new(dao::get_data_key());
    let master = provider
        .master_key()
        .expect("local key provider yields the configured secret");
    let hkdf = Hkdf::<Sha256>::new(None, &master);
    let mut okm = Zeroizing::new([0u8; 32]);
    hkdf.expand(info, okm.as_mut_slice())
        .expect("32 bytes is valid output length for HKDF-SHA256");
    okm
}

// Key-encryption key that wraps per-file DEKs.
fn dek_wrapping_key() -> Zeroizing<[u8; 32]> {
    derive_key(b"securefs-dek-wrap-v1")
}

// Global key for legacy (v0/v1) files written before envelope encryption.
fn legacy_file_key() -> Zeroizing<[u8; 32]> {
    derive_key(b"securefs-file-encryption-key-v1")
}

// Wrap a DEK with the KEK: nonce(12) || ciphertext(dek + tag).
fn wrap_dek(dek: &[u8]) -> Vec<u8> {
    let wk = dek_wrapping_key();
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(wk.as_slice()));
    let nonce = Aes256Gcm::generate_nonce(OsRng);
    let ct = cipher
        .encrypt(&nonce, dek)
        .expect("AES-GCM wrap should not fail with valid inputs");
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

fn unwrap_dek(wrapped: &[u8]) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    if wrapped.len() < 12 + 16 {
        return Err("wrapped dek too short");
    }
    let wk = dek_wrapping_key();
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(wk.as_slice()));
    let nonce = Nonce::from_slice(&wrapped[..12]);
    let dek = cipher
        .decrypt(nonce, &wrapped[12..])
        .map_err(|_| "dek unwrap failed")?;
    Ok(Zeroizing::new(dek))
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

/// Encrypt file content with a fresh per-file DEK (zstd, then AES-256-GCM).
/// Returns the on-disk blob (`0x02 || nonce || ciphertext`) and the wrapped DEK
/// to persist as file metadata.
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
}
