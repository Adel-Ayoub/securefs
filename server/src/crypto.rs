use aes_gcm::aead::{Aead, AeadCore};
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use hkdf::Hkdf;
use rand_core::OsRng;
use securefs_model::protocol::AppMessage;
use sha2::Sha256;

use securefs_server::dao;

/// Encrypt an AppMessage using AES-256-GCM.
/// Returns a tuple of (ciphertext_hex, nonce_bytes).
pub fn encrypt_app_message(
    key: &Key<Aes256Gcm>,
    msg: &AppMessage,
) -> Result<(String, [u8; 12]), String> {
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(OsRng);
    let payload = serde_json::to_string(msg).map_err(|e| e.to_string())?;
    let ciphertext = cipher
        .encrypt(&nonce, payload.as_bytes())
        .map_err(|e| format!("encryption failed: {}", e))?;
    Ok((hex::encode(ciphertext), nonce.into()))
}

/// Decrypt a message using AES-256-GCM.
pub fn decrypt_app_message(
    key: &Key<Aes256Gcm>,
    msg_tuple: &(String, [u8; 12]),
) -> Result<AppMessage, String> {
    let (ciphertext_hex, nonce_bytes) = msg_tuple;
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);
    let ciphertext =
        hex::decode(ciphertext_hex).map_err(|_| "invalid ciphertext hex".to_string())?;
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|e| format!("decryption failed: {}", e))?;
    let plaintext_str = String::from_utf8(plaintext).map_err(|_| "invalid utf8".to_string())?;
    serde_json::from_str(&plaintext_str).map_err(|e| format!("json decode failed: {}", e))
}

/// Derive a key for file-at-rest encryption using HKDF.
/// Key is derived from DB_PASS to ensure persistence across server restarts.
fn get_file_encryption_key() -> Key<Aes256Gcm> {
    let db_pass = dao::get_db_pass();
    let hkdf = Hkdf::<Sha256>::new(None, db_pass.as_bytes());
    let mut okm = [0u8; 32];
    hkdf.expand(b"securefs-file-encryption-key-v1", &mut okm)
        .expect("32 bytes is valid output length for HKDF-SHA256");
    *Key::<Aes256Gcm>::from_slice(&okm)
}

/// Encrypt file content with AES-256-GCM for at-rest storage.
/// Returns: nonce (12 bytes) || ciphertext (content + 16 byte auth tag)
pub fn encrypt_file_content(content: &[u8]) -> Vec<u8> {
    let key = get_file_encryption_key();
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, content)
        .expect("AES-GCM encryption should not fail with valid inputs");
    let mut result = nonce.to_vec();
    result.extend_from_slice(&ciphertext);
    result
}

/// Decrypt file content that was encrypted with encrypt_file_content.
/// Input format: nonce (12 bytes) || ciphertext
pub fn decrypt_file_content(encrypted: &[u8]) -> Result<Vec<u8>, &'static str> {
    if encrypted.len() < 12 + 16 {
        return Err("encrypted data too short");
    }
    let key = get_file_encryption_key();
    let cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::from_slice(&encrypted[..12]);
    let ciphertext = &encrypted[12..];
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "decryption failed")
}

/// Compute BLAKE3 hash of file content for integrity verification.
pub fn hash_content(content: &[u8]) -> String {
    hex::encode(blake3::hash(content).as_bytes())
}
