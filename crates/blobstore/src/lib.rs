#![forbid(unsafe_code)]

use std::path::PathBuf;

use async_trait::async_trait;
use thiserror::Error;
use tokio::fs;

#[cfg(feature = "s3")]
mod s3;
#[cfg(feature = "s3")]
pub use s3::S3Blobstore;

#[derive(Debug, Error)]
pub enum BlobError {
    #[error("blob not found")]
    NotFound,
    #[error("invalid blob key")]
    InvalidKey,
    #[error("blob io error: {0}")]
    Io(#[from] std::io::Error),
    #[cfg(feature = "s3")]
    #[error("blob backend error: {0}")]
    Backend(String),
    #[cfg(feature = "s3")]
    #[error("blob configuration error: {0}")]
    Config(String),
}

// Content store keyed by opaque tokens. Implementations know nothing about
// logical paths, encryption, or the /home policy; callers map a validated
// logical path to a key before reaching here.
#[async_trait]
pub trait Blobstore: Send + Sync {
    async fn put(&self, key: &str, bytes: &[u8]) -> Result<(), BlobError>;
    async fn get(&self, key: &str) -> Result<Vec<u8>, BlobError>;
    // Idempotent: removing an absent blob succeeds.
    async fn delete(&self, key: &str) -> Result<(), BlobError>;
    async fn rename(&self, from: &str, to: &str) -> Result<(), BlobError>;
    async fn copy(&self, from: &str, to: &str) -> Result<(), BlobError>;
    async fn exists(&self, key: &str) -> Result<bool, BlobError>;
    async fn size(&self, key: &str) -> Result<u64, BlobError>;
}

// A blobstore backed by a local directory. Keys fan out two levels
// (root/ab/cd/abcd...) to keep any single directory small.
pub struct LocalFs {
    root: PathBuf,
}

impl LocalFs {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        LocalFs { root: root.into() }
    }

    // Reject keys that aren't safe single-segment tokens so a malformed caller
    // can never traverse out of `root`. Valid keys (hex digests) always pass.
    fn path_for(&self, key: &str) -> Result<PathBuf, BlobError> {
        if !is_valid_key(key) {
            return Err(BlobError::InvalidKey);
        }
        Ok(self.root.join(&key[0..2]).join(&key[2..4]).join(key))
    }
}

pub(crate) fn is_valid_key(key: &str) -> bool {
    key.len() >= 4 && key.len() <= 128 && key.bytes().all(|b| b.is_ascii_alphanumeric())
}

fn classify(e: std::io::Error) -> BlobError {
    if e.kind() == std::io::ErrorKind::NotFound {
        BlobError::NotFound
    } else {
        BlobError::Io(e)
    }
}

#[async_trait]
impl Blobstore for LocalFs {
    async fn put(&self, key: &str, bytes: &[u8]) -> Result<(), BlobError> {
        let path = self.path_for(key)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await?;
        }
        fs::write(&path, bytes).await?;
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Vec<u8>, BlobError> {
        let path = self.path_for(key)?;
        fs::read(&path).await.map_err(classify)
    }

    async fn delete(&self, key: &str) -> Result<(), BlobError> {
        let path = self.path_for(key)?;
        match fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(BlobError::Io(e)),
        }
    }

    async fn rename(&self, from: &str, to: &str) -> Result<(), BlobError> {
        let from_path = self.path_for(from)?;
        let to_path = self.path_for(to)?;
        if let Some(parent) = to_path.parent() {
            fs::create_dir_all(parent).await?;
        }
        fs::rename(&from_path, &to_path).await.map_err(classify)
    }

    async fn copy(&self, from: &str, to: &str) -> Result<(), BlobError> {
        let from_path = self.path_for(from)?;
        let to_path = self.path_for(to)?;
        if let Some(parent) = to_path.parent() {
            fs::create_dir_all(parent).await?;
        }
        fs::copy(&from_path, &to_path).await.map_err(classify)?;
        Ok(())
    }

    async fn exists(&self, key: &str) -> Result<bool, BlobError> {
        let path = self.path_for(key)?;
        match fs::metadata(&path).await {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(BlobError::Io(e)),
        }
    }

    async fn size(&self, key: &str) -> Result<u64, BlobError> {
        let path = self.path_for(key)?;
        fs::metadata(&path).await.map(|m| m.len()).map_err(classify)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    const K1: &str = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
    const K2: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    fn temp_store() -> LocalFs {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir =
            std::env::temp_dir().join(format!("securefs-blobstore-{}-{}", std::process::id(), n));
        std::fs::create_dir_all(&dir).unwrap();
        LocalFs::new(dir)
    }

    #[tokio::test]
    async fn put_then_get_round_trips() {
        let s = temp_store();
        s.put(K1, b"hello world").await.unwrap();
        assert_eq!(s.get(K1).await.unwrap(), b"hello world");
    }

    #[tokio::test]
    async fn get_missing_is_not_found() {
        let s = temp_store();
        assert!(matches!(s.get(K2).await, Err(BlobError::NotFound)));
    }

    #[tokio::test]
    async fn keys_fan_out_two_levels() {
        let s = temp_store();
        s.put(K1, b"x").await.unwrap();
        let expected = s.root.join("aa").join("bb").join(K1);
        assert!(expected.exists(), "blob not at sharded path {expected:?}");
    }

    #[tokio::test]
    async fn delete_is_idempotent() {
        let s = temp_store();
        s.delete(K1).await.unwrap();
        s.put(K1, b"x").await.unwrap();
        s.delete(K1).await.unwrap();
        assert!(!s.exists(K1).await.unwrap());
    }

    #[tokio::test]
    async fn rename_moves_blob() {
        let s = temp_store();
        s.put(K1, b"payload").await.unwrap();
        s.rename(K1, K2).await.unwrap();
        assert_eq!(s.get(K2).await.unwrap(), b"payload");
        assert!(matches!(s.get(K1).await, Err(BlobError::NotFound)));
    }

    #[tokio::test]
    async fn rename_missing_is_not_found() {
        let s = temp_store();
        assert!(matches!(s.rename(K2, K1).await, Err(BlobError::NotFound)));
    }

    #[tokio::test]
    async fn copy_duplicates_blob() {
        let s = temp_store();
        s.put(K1, b"dup").await.unwrap();
        s.copy(K1, K2).await.unwrap();
        assert_eq!(s.get(K1).await.unwrap(), b"dup");
        assert_eq!(s.get(K2).await.unwrap(), b"dup");
    }

    #[tokio::test]
    async fn size_reports_byte_len() {
        let s = temp_store();
        s.put(K1, b"12345").await.unwrap();
        assert_eq!(s.size(K1).await.unwrap(), 5);
        assert!(matches!(s.size(K2).await, Err(BlobError::NotFound)));
    }

    #[tokio::test]
    async fn exists_tracks_presence() {
        let s = temp_store();
        assert!(!s.exists(K1).await.unwrap());
        s.put(K1, b"x").await.unwrap();
        assert!(s.exists(K1).await.unwrap());
    }

    #[tokio::test]
    async fn traversal_keys_are_rejected() {
        let s = temp_store();
        for bad in [
            "../../etc/passwd",
            "ab/cd",
            "..",
            "",
            "abc",
            "ab.cd",
            "abcd\0ef",
        ] {
            assert!(
                matches!(s.put(bad, b"x").await, Err(BlobError::InvalidKey)),
                "key {bad:?} should be rejected by put"
            );
            assert!(
                matches!(s.get(bad).await, Err(BlobError::InvalidKey)),
                "key {bad:?} should be rejected by get"
            );
        }
    }
}
