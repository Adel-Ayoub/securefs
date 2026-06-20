use securefs_blobstore::Blobstore;
use securefs_model::protocol::{AppMessage, Cmd};

use securefs_server::storage::physical_key;

use crate::crypto::decrypt_file_content;

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
// path to its blob key through the validated chokepoint, then decrypts.
async fn read_file_bytes(store: &dyn Blobstore, path: &str) -> Result<Vec<u8>, AppMessage> {
    let key = physical_key(path).map_err(|_| AppMessage {
        cmd: Cmd::Failure,
        data: vec!["invalid path".into()],
    })?;
    let encrypted = store.get(&key).await.map_err(|_| AppMessage {
        cmd: Cmd::Failure,
        data: vec!["file not found".into()],
    })?;
    decrypt_file_content(&encrypted).map_err(|e| AppMessage {
        cmd: Cmd::Failure,
        data: vec![e.to_string()],
    })
}
