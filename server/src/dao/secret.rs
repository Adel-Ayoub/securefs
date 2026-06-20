use std::env;
use std::sync::Once;

use aes_gcm::{Aes256Gcm, KeyInit};
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2,
};
use hmac::{Hmac, Mac};
use rand_core::OsRng;
use sha2::Sha256;

use super::DaoError;

static WARN_DEFAULT_PASS: Once = Once::new();

// Read a secret from env var `var`, or from the file named by `file_var`
// (contents trimmed). Lets deployments mount secrets as files instead of
// passing them through the environment. None if neither yields a value.
fn read_secret(var: &str, file_var: &str) -> Option<String> {
    if let Ok(v) = env::var(var) {
        if !v.is_empty() {
            return Some(v);
        }
    }
    if let Ok(path) = env::var(file_var) {
        if let Ok(contents) = std::fs::read_to_string(&path) {
            let trimmed = contents.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

// Database/pgcrypto secret, from DB_PASS or DB_PASS_FILE. Warns and uses an
// insecure default when unset; startup refuses this default outside dev.
pub fn get_db_pass() -> String {
    match read_secret("DB_PASS", "DB_PASS_FILE") {
        Some(pass) => pass,
        None => {
            WARN_DEFAULT_PASS.call_once(|| {
                eprintln!("[SECURITY WARNING] DB_PASS not set, using insecure default!");
                eprintln!("[SECURITY WARNING] Set DB_PASS environment variable for production.");
            });
            "TEMP".to_string()
        }
    }
}

// At-rest data-encryption secret if explicitly configured (DATA_KEY or
// DATA_KEY_FILE). No fallback to DB_PASS — production startup refuses to run
// without it.
pub fn data_key_secret() -> Option<String> {
    read_secret("DATA_KEY", "DATA_KEY_FILE")
}

// At-rest data-encryption key for runtime use. Prefers DATA_KEY; falls back to
// DB_PASS for development only (production requires DATA_KEY, checked at boot).
pub fn get_data_key() -> String {
    data_key_secret().unwrap_or_else(get_db_pass)
}

// Deterministic keyed digest of a plaintext path for indexed exact-match
// lookups. HMAC-SHA256 keyed by DB_PASS, so the digest reveals nothing about
// the path without the secret yet the same path always maps to the same value.
// Must match Postgres `hmac(path, db_pass, 'sha256')` so SQL-side maintenance
// (inserts, renames, backfill) and Rust-side lookups agree.
pub fn path_digest(path: &str) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(get_db_pass().as_bytes())
        .expect("HMAC accepts a key of any length");
    mac.update(path.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

/// Hash and salt a plaintext password using Argon2.
pub fn salt_pass(pass: String) -> Result<String, DaoError> {
    let b_pass = pass.as_bytes();
    let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
    let argon2 = Argon2::default();
    argon2
        .hash_password(b_pass, &salt)
        .map(|p| p.serialize().as_str().to_string())
        .map_err(|e| DaoError::ParseError(format!("argon2 hash failed: {}", e)))
}

/// Generate a random AES-256 key serialized to JSON for DB storage.
pub fn key_gen() -> Result<String, DaoError> {
    let key = Aes256Gcm::generate_key(&mut OsRng);
    let u8_32_arr: [u8; 32] = key.into();
    serde_json::to_string(&u8_32_arr)
        .map_err(|_| DaoError::ParseError("could not serialize symmetric key".into()))
}
