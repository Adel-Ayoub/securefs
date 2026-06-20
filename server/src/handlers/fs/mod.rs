use securefs_model::protocol::{AppMessage, Cmd};
use tokio::fs;
use tokio::io::AsyncReadExt;

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

// Read and decrypt a file's content as raw bytes (binary-safe).
async fn read_file_bytes(file_path: &str) -> Result<Vec<u8>, AppMessage> {
    let mut f = fs::File::open(file_path).await.map_err(|_| AppMessage {
        cmd: Cmd::Failure,
        data: vec!["file not found".into()],
    })?;
    let mut encrypted = Vec::new();
    f.read_to_end(&mut encrypted)
        .await
        .map_err(|_| AppMessage {
            cmd: Cmd::Failure,
            data: vec!["read failed".into()],
        })?;
    decrypt_file_content(&encrypted).map_err(|e| AppMessage {
        cmd: Cmd::Failure,
        data: vec![e.to_string()],
    })
}
