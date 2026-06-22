use deadpool_postgres::Pool;
use securefs_blobstore::Blobstore;
use securefs_model::protocol::{AppMessage, Cmd};

use securefs_server::dao;
use securefs_server::storage::physical_key;

use crate::crypto;

pub mod nav;
pub mod read;
pub mod relocate;
pub mod transfer;
pub mod write;

pub use nav::*;
pub use read::*;
pub use relocate::*;
pub use transfer::*;
pub use write::*;

// Read and decrypt a file's content as raw bytes (binary-safe). Maps the logical
// path to its blob key through the validated chokepoint, then decrypts (envelope
// files need their wrapped DEK; legacy files ignore it).
async fn read_file_bytes(
    store: &dyn Blobstore,
    pool: &Pool,
    path: &str,
    wrapped_dek: Option<&[u8]>,
) -> Result<Vec<u8>, AppMessage> {
    let key = physical_key(path).map_err(|_| AppMessage {
        cmd: Cmd::Failure,
        data: vec!["invalid path".into()],
    })?;
    let encrypted = store.get(&key).await.map_err(|_| AppMessage {
        cmd: Cmd::Failure,
        data: vec!["file not found".into()],
    })?;
    // Chunked (v3) files carry a Merkle root; verify the recomputed root against
    // the stored one. Other formats authenticate via their single AEAD tag.
    let expected_root = if crypto::is_chunked(&encrypted) {
        dao::get_merkle_root(pool, path.to_string())
            .await
            .ok()
            .flatten()
    } else {
        None
    };
    crypto::decrypt_verified(&encrypted, wrapped_dek, expected_root.as_deref()).map_err(|e| {
        AppMessage {
            cmd: Cmd::Failure,
            data: vec![e.to_string()],
        }
    })
}

#[cfg(test)]
#[allow(unsafe_code)] // tests set DB_PASS via the unsafe std::env::set_var
mod tests {
    use super::*;
    use deadpool_postgres::{Config, ManagerConfig, RecyclingMethod, Runtime};
    use securefs_blobstore::LocalFs;
    use tokio_postgres::NoTls;

    fn test_pool() -> Pool {
        let mut cfg = Config::new();
        cfg.host = Some("localhost".into());
        cfg.dbname = Some("securefs".into());
        cfg.user = Some("securefs_user".into());
        cfg.password = Some("securefs_password".into());
        cfg.port = Some(5431);
        cfg.manager = Some(ManagerConfig {
            recycling_method: RecyclingMethod::Fast,
        });
        cfg.create_pool(Some(Runtime::Tokio1), NoTls).unwrap()
    }

    // End-to-end read path: store a real v3 blob via LocalFs, persist its DEK and
    // Merkle root, then read it back through the chokepoint and confirm a tampered
    // stored root is rejected.
    #[tokio::test]
    async fn read_file_bytes_verifies_merkle_root() {
        // SAFETY: single-threaded test.
        unsafe { std::env::set_var("DB_PASS", "securefs") };
        let pool = test_pool();
        dao::init_db(&pool).await.unwrap();

        let path = "/home/rfb_merkle_test";
        let digest = dao::path_digest(path);
        let client = pool.get().await.unwrap();
        client
            .execute("DELETE FROM fnode WHERE path_digest = $1", &[&digest])
            .await
            .unwrap();
        client
            .execute(
                "INSERT INTO fnode (dir, path_digest) VALUES (false, $1)",
                &[&digest],
            )
            .await
            .unwrap();
        drop(client);

        let content = vec![42u8; 150_000]; // multi-chunk
        let (blob, wrapped, root) = crypto::encrypt_file_chunked(&content);
        assert!(crypto::is_chunked(&blob));

        let dir = std::env::temp_dir().join("sfx_rfb_test");
        let store = LocalFs::new(dir.to_string_lossy().to_string());
        let key = physical_key(path).unwrap();
        store.put(&key, &blob).await.unwrap();
        dao::set_wrapped_dek(&pool, path.to_string(), &wrapped)
            .await
            .unwrap();
        dao::set_merkle_root(&pool, path.to_string(), &root)
            .await
            .unwrap();

        // Reads back and verifies the stored root.
        let got = read_file_bytes(&store, &pool, path, Some(&wrapped))
            .await
            .expect("read with correct root");
        assert_eq!(got, content);

        // A tampered stored root is rejected even though every chunk authenticates.
        dao::set_merkle_root(&pool, path.to_string(), "00")
            .await
            .unwrap();
        assert!(read_file_bytes(&store, &pool, path, Some(&wrapped))
            .await
            .is_err());

        let client = pool.get().await.unwrap();
        client
            .execute("DELETE FROM fnode WHERE path_digest = $1", &[&digest])
            .await
            .unwrap();
    }
}
