use std::sync::Arc;

use async_trait::async_trait;
use object_store::aws::AmazonS3Builder;
use object_store::path::Path as ObjectPath;
use object_store::{Error as OsError, ObjectStore, PutPayload};

use crate::{is_valid_key, BlobError, Blobstore};

// Blobstore backed by S3-compatible object storage (AWS S3, MinIO, ...) so any
// stateless instance can serve any file. Keys are the same opaque tokens LocalFs
// uses; an optional prefix namespaces them within the bucket. Encryption stays in
// the caller (crate::crypto) - this holds ciphertext, exactly like LocalFs.
pub struct S3Blobstore {
    store: Arc<dyn ObjectStore>,
    prefix: String,
}

impl S3Blobstore {
    // Low-level constructor; also used by tests with an in-memory ObjectStore.
    pub fn new(store: Arc<dyn ObjectStore>, prefix: impl Into<String>) -> Self {
        S3Blobstore {
            store,
            prefix: prefix.into(),
        }
    }

    // Build from the environment: S3_BUCKET (required), S3_REGION (default
    // us-east-1), S3_ENDPOINT (set for MinIO/custom; an http:// endpoint
    // auto-allows plaintext), AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY
    // (standard), S3_KEY_PREFIX (optional). Path-style addressing is the
    // object_store default with a custom endpoint, which is what MinIO needs.
    pub fn from_env() -> Result<Self, BlobError> {
        let bucket = std::env::var("S3_BUCKET")
            .map_err(|_| BlobError::Config("S3_BUCKET is required for the s3 backend".into()))?;
        let region = std::env::var("S3_REGION").unwrap_or_else(|_| "us-east-1".to_string());

        let mut builder = AmazonS3Builder::new()
            .with_bucket_name(bucket)
            .with_region(region);
        if let Ok(endpoint) = std::env::var("S3_ENDPOINT") {
            let allow_http = endpoint.starts_with("http://");
            builder = builder.with_endpoint(endpoint).with_allow_http(allow_http);
        }
        if let Ok(key) = std::env::var("AWS_ACCESS_KEY_ID") {
            builder = builder.with_access_key_id(key);
        }
        if let Ok(secret) = std::env::var("AWS_SECRET_ACCESS_KEY") {
            builder = builder.with_secret_access_key(secret);
        }

        let store = builder
            .build()
            .map_err(|e| BlobError::Config(format!("s3 backend init: {e}")))?;
        Ok(S3Blobstore {
            store: Arc::new(store),
            prefix: std::env::var("S3_KEY_PREFIX").unwrap_or_default(),
        })
    }

    // Reject keys that aren't safe single-segment tokens, identically to LocalFs,
    // so a malformed caller can never address unexpected objects.
    fn path_for(&self, key: &str) -> Result<ObjectPath, BlobError> {
        if !is_valid_key(key) {
            return Err(BlobError::InvalidKey);
        }
        Ok(ObjectPath::from(format!("{}{}", self.prefix, key)))
    }
}

fn classify(e: OsError) -> BlobError {
    match e {
        OsError::NotFound { .. } => BlobError::NotFound,
        other => BlobError::Backend(other.to_string()),
    }
}

#[async_trait]
impl Blobstore for S3Blobstore {
    async fn put(&self, key: &str, bytes: &[u8]) -> Result<(), BlobError> {
        let path = self.path_for(key)?;
        self.store
            .put(&path, PutPayload::from(bytes.to_vec()))
            .await
            .map(|_| ())
            .map_err(classify)
    }

    async fn get(&self, key: &str) -> Result<Vec<u8>, BlobError> {
        let path = self.path_for(key)?;
        let res = self.store.get(&path).await.map_err(classify)?;
        let bytes = res.bytes().await.map_err(classify)?;
        Ok(bytes.to_vec())
    }

    async fn delete(&self, key: &str) -> Result<(), BlobError> {
        let path = self.path_for(key)?;
        match self.store.delete(&path).await {
            Ok(()) => Ok(()),
            // Idempotent: removing an absent blob succeeds (S3 already behaves so;
            // the in-memory store and some backends return NotFound).
            Err(OsError::NotFound { .. }) => Ok(()),
            Err(e) => Err(classify(e)),
        }
    }

    async fn rename(&self, from: &str, to: &str) -> Result<(), BlobError> {
        let from_p = self.path_for(from)?;
        let to_p = self.path_for(to)?;
        // S3 has no native rename; object_store does copy-then-delete.
        self.store.rename(&from_p, &to_p).await.map_err(classify)
    }

    async fn copy(&self, from: &str, to: &str) -> Result<(), BlobError> {
        let from_p = self.path_for(from)?;
        let to_p = self.path_for(to)?;
        self.store.copy(&from_p, &to_p).await.map_err(classify)
    }

    async fn exists(&self, key: &str) -> Result<bool, BlobError> {
        let path = self.path_for(key)?;
        match self.store.head(&path).await {
            Ok(_) => Ok(true),
            Err(OsError::NotFound { .. }) => Ok(false),
            Err(e) => Err(classify(e)),
        }
    }

    async fn size(&self, key: &str) -> Result<u64, BlobError> {
        let path = self.path_for(key)?;
        let meta = self.store.head(&path).await.map_err(classify)?;
        Ok(meta.size as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use object_store::memory::InMemory;

    const K1: &str = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
    const K2: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    const K3: &str = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";

    // InMemory is a real ObjectStore, so these exercise the actual method/error
    // mapping (not a hand-rolled fake) in-process, with no network.
    fn mem_store() -> S3Blobstore {
        S3Blobstore::new(Arc::new(InMemory::new()), "")
    }

    #[tokio::test]
    async fn put_then_get_round_trips() {
        let s = mem_store();
        s.put(K1, b"hello world").await.unwrap();
        assert_eq!(s.get(K1).await.unwrap(), b"hello world");
    }

    #[tokio::test]
    async fn get_missing_is_not_found() {
        let s = mem_store();
        assert!(matches!(s.get(K2).await, Err(BlobError::NotFound)));
    }

    #[tokio::test]
    async fn delete_is_idempotent() {
        let s = mem_store();
        s.delete(K1).await.unwrap();
        s.put(K1, b"x").await.unwrap();
        s.delete(K1).await.unwrap();
        assert!(!s.exists(K1).await.unwrap());
    }

    #[tokio::test]
    async fn rename_moves_blob() {
        let s = mem_store();
        s.put(K1, b"payload").await.unwrap();
        s.rename(K1, K2).await.unwrap();
        assert_eq!(s.get(K2).await.unwrap(), b"payload");
        assert!(matches!(s.get(K1).await, Err(BlobError::NotFound)));
    }

    #[tokio::test]
    async fn rename_missing_is_not_found() {
        let s = mem_store();
        assert!(matches!(s.rename(K2, K1).await, Err(BlobError::NotFound)));
    }

    #[tokio::test]
    async fn copy_duplicates_blob() {
        let s = mem_store();
        s.put(K1, b"dup").await.unwrap();
        s.copy(K1, K2).await.unwrap();
        assert_eq!(s.get(K1).await.unwrap(), b"dup");
        assert_eq!(s.get(K2).await.unwrap(), b"dup");
    }

    #[tokio::test]
    async fn size_reports_byte_len() {
        let s = mem_store();
        s.put(K1, b"12345").await.unwrap();
        assert_eq!(s.size(K1).await.unwrap(), 5);
        assert!(matches!(s.size(K2).await, Err(BlobError::NotFound)));
    }

    #[tokio::test]
    async fn exists_tracks_presence() {
        let s = mem_store();
        assert!(!s.exists(K1).await.unwrap());
        s.put(K1, b"x").await.unwrap();
        assert!(s.exists(K1).await.unwrap());
    }

    #[tokio::test]
    async fn traversal_keys_are_rejected() {
        let s = mem_store();
        for bad in ["../../etc/passwd", "ab/cd", "..", "", "abc", "ab.cd"] {
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

    #[tokio::test]
    async fn prefix_namespaces_keys() {
        let inner = Arc::new(InMemory::new());
        let s = S3Blobstore::new(inner.clone(), "tenant-a/");
        s.put(K1, b"scoped").await.unwrap();
        // The object lands under the prefix, and a differently-prefixed store
        // does not see it.
        assert_eq!(s.get(K1).await.unwrap(), b"scoped");
        let other = S3Blobstore::new(inner, "tenant-b/");
        assert!(matches!(other.get(K1).await, Err(BlobError::NotFound)));
    }

    // Real round-trip against an S3-compatible server, run only when
    // SFX_S3_TEST_ENDPOINT is set (e.g. a local MinIO). Skipped otherwise, so the
    // default gate needs no object store. Requires SFX_S3_TEST_BUCKET and AWS
    // creds in the environment; the bucket must already exist.
    #[tokio::test]
    async fn live_s3_round_trip() {
        let endpoint = match std::env::var("SFX_S3_TEST_ENDPOINT") {
            Ok(e) => e,
            Err(_) => return,
        };
        let bucket = std::env::var("SFX_S3_TEST_BUCKET").unwrap_or_else(|_| "securefs-test".into());
        let mut builder = AmazonS3Builder::new()
            .with_bucket_name(bucket)
            .with_region(std::env::var("S3_REGION").unwrap_or_else(|_| "us-east-1".into()))
            .with_allow_http(endpoint.starts_with("http://"))
            .with_endpoint(endpoint);
        if let Ok(k) = std::env::var("AWS_ACCESS_KEY_ID") {
            builder = builder.with_access_key_id(k);
        }
        if let Ok(s) = std::env::var("AWS_SECRET_ACCESS_KEY") {
            builder = builder.with_secret_access_key(s);
        }
        let s = S3Blobstore::new(Arc::new(builder.build().expect("build s3")), "");

        s.delete(K1).await.unwrap();
        s.delete(K2).await.unwrap();
        assert!(!s.exists(K1).await.unwrap());

        s.put(K1, b"hello-minio").await.unwrap();
        assert_eq!(s.get(K1).await.unwrap(), b"hello-minio");
        assert!(s.exists(K1).await.unwrap());
        assert_eq!(s.size(K1).await.unwrap(), 11);

        s.copy(K1, K2).await.unwrap();
        assert_eq!(s.get(K2).await.unwrap(), b"hello-minio");

        s.rename(K2, K3).await.unwrap();
        assert_eq!(s.get(K3).await.unwrap(), b"hello-minio");
        assert!(matches!(s.get(K2).await, Err(BlobError::NotFound)));

        s.delete(K1).await.unwrap();
        s.delete(K3).await.unwrap();
        assert!(!s.exists(K1).await.unwrap());
    }
}
