use base64::Engine;
use deadpool_postgres::Pool;
use securefs_blobstore::Blobstore;
use securefs_model::protocol::{AppMessage, Cmd, FNode};

use securefs_server::dao;
use securefs_server::storage::physical_key;

use crate::crypto::{encrypt_file_content, hash_content};
use crate::session::{DownloadState, Session, UploadState};
use crate::util::*;

use super::read_file_bytes;

const CHUNK_SIZE: usize = 64 * 1024;

// Hard cap on a single chunked upload to bound server memory.
const MAX_UPLOAD_BYTES: usize = 100 * 1024 * 1024;

pub async fn upload_start(data: Vec<String>, session: &mut Session, pool: &Pool) -> AppMessage {
    if !session.authenticated {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["not authenticated".into()],
        };
    }

    let file_name = data.first().cloned().unwrap_or_default();
    if !is_valid_name(&file_name) {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["invalid file name".into()],
        };
    }

    // Check write permission on parent
    let has_perm = match dao::get_f_node(pool, session.current_path.clone()).await {
        Ok(Some(parent)) => {
            let owner_group =
                dao::get_file_group(pool, parent.owner.clone(), parent.file_group.clone())
                    .await
                    .unwrap_or(None);
            can_write_with_group(
                &parent,
                session.current_user.as_ref(),
                session.current_user_group.as_ref(),
                owner_group.as_ref(),
            )
        }
        _ => false,
    };
    if !has_perm {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["no write permission".into()],
        };
    }

    session.upload = Some(UploadState {
        file_name,
        chunks: Vec::new(),
        total: 0,
    });

    AppMessage {
        cmd: Cmd::UploadStart,
        data: vec!["ready".into()],
    }
}

pub fn upload_chunk(data: Vec<String>, session: &mut Session) -> AppMessage {
    if !session.authenticated {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["not authenticated".into()],
        };
    }

    let b64_chunk = data.first().cloned().unwrap_or_default();
    if session.upload.is_none() {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["no upload in progress".into()],
        };
    }

    let bytes = match base64::engine::general_purpose::STANDARD.decode(&b64_chunk) {
        Ok(b) => b,
        Err(_) => {
            return AppMessage {
                cmd: Cmd::Failure,
                data: vec!["invalid base64".into()],
            }
        }
    };

    let new_total = session.upload.as_ref().map(|u| u.total).unwrap_or(0) + bytes.len();
    if new_total > MAX_UPLOAD_BYTES {
        // Abort the transfer; freeing the buffer prevents a memory-exhaustion DoS.
        session.upload = None;
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["upload exceeds maximum size".into()],
        };
    }

    let upload = session.upload.as_mut().unwrap();
    upload.total = new_total;
    upload.chunks.push(bytes);
    AppMessage {
        cmd: Cmd::UploadChunk,
        data: vec!["ok".into()],
    }
}

pub async fn upload_end(session: &mut Session, pool: &Pool, store: &dyn Blobstore) -> AppMessage {
    if !session.authenticated {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["not authenticated".into()],
        };
    }

    let upload = match session.upload.take() {
        Some(u) => u,
        None => {
            return AppMessage {
                cmd: Cmd::Failure,
                data: vec!["no upload in progress".into()],
            }
        }
    };

    // Reassemble content from chunks
    let content: Vec<u8> = upload.chunks.into_iter().flatten().collect();
    let file_name = upload.file_name;

    // Re-check write permission on the *current* directory; it may have
    // changed via cd between upload_start and upload_end.
    let has_perm = match dao::get_f_node(pool, session.current_path.clone()).await {
        Ok(Some(parent)) => {
            let owner_group =
                dao::get_file_group(pool, parent.owner.clone(), parent.file_group.clone())
                    .await
                    .unwrap_or(None);
            can_write_with_group(
                &parent,
                session.current_user.as_ref(),
                session.current_user_group.as_ref(),
                owner_group.as_ref(),
            )
        }
        _ => false,
    };
    if !has_perm {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["no write permission".into()],
        };
    }

    // Encrypt (compress-then-encrypt handled by encrypt_file_content)
    let encrypted = encrypt_file_content(&content);
    let hash = hash_content(&content);

    let node_path = format!("{}/{}", session.current_path, file_name);
    let key = match physical_key(&node_path) {
        Ok(k) => k,
        Err(_) => {
            return AppMessage {
                cmd: Cmd::Failure,
                data: vec!["upload failed".into()],
            }
        }
    };
    if store.put(&key, &encrypted).await.is_err() {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["upload write failed".into()],
        };
    }

    // Create FNode if it doesn't exist (new file upload)
    if dao::get_f_node(pool, node_path.clone())
        .await
        .ok()
        .flatten()
        .is_none()
    {
        let owner = session.current_user.clone().unwrap_or_default();
        let now = current_timestamp();
        let new_file = FNode {
            id: -1,
            name: file_name.clone(),
            path: node_path.clone(),
            owner,
            hash: hash.clone(),
            parent: session.current_path.clone(),
            dir: false,
            u: 6,
            g: 6,
            o: 4,
            children: vec![],
            encrypted_name: file_name.clone(),
            size: content.len() as i64,
            created_at: now,
            modified_at: now,
            file_group: session.current_user_group.clone(),
            link_target: None,
        };
        let _ = dao::add_file(pool, new_file).await;
        let _ =
            dao::add_file_to_parent(pool, session.current_path.clone(), file_name.clone()).await;
    }

    // Use advisory lock for the hash update.
    if let Err(e) = dao::update_hash_locked(pool, node_path.clone(), hash.clone()).await {
        if matches!(e, dao::DaoError::Conflict(_)) {
            return AppMessage {
                cmd: Cmd::Failure,
                data: vec!["file is being modified, try again".into()],
            };
        }
        let _ = dao::update_hash(pool, node_path, file_name, hash).await;
    }
    AppMessage {
        cmd: Cmd::UploadEnd,
        data: vec![format!("{} bytes uploaded", content.len())],
    }
}

pub async fn download_start(
    data: Vec<String>,
    session: &mut Session,
    pool: &Pool,
    store: &dyn Blobstore,
) -> AppMessage {
    if !session.authenticated {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["not authenticated".into()],
        };
    }

    let file_name = data.first().cloned().unwrap_or_default();
    if !is_valid_name(&file_name) {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["invalid file name".into()],
        };
    }

    let node_path = format!("{}/{}", session.current_path, file_name);
    let node = match dao::get_f_node(pool, node_path.clone()).await {
        Ok(Some(n)) if !n.dir => n,
        _ => {
            return AppMessage {
                cmd: Cmd::Failure,
                data: vec!["file not found".into()],
            }
        }
    };

    let owner_group = dao::get_file_group(pool, node.owner.clone(), node.file_group.clone())
        .await
        .unwrap_or(None);
    if !can_read_with_group(
        &node,
        session.current_user.as_ref(),
        session.current_user_group.as_ref(),
        owner_group.as_ref(),
    ) {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["no read permission".into()],
        };
    }

    let content = match read_file_bytes(store, &node_path).await {
        Ok(c) => c,
        Err(e) => return e,
    };

    // Split into base64-encoded chunks
    let b64_engine = base64::engine::general_purpose::STANDARD;
    let chunks: Vec<String> = content
        .chunks(CHUNK_SIZE)
        .map(|chunk| b64_engine.encode(chunk))
        .collect();
    let total = chunks.len();

    session.download = Some(DownloadState { chunks });

    // Send the plaintext BLAKE3 hash so the client can verify integrity.
    AppMessage {
        cmd: Cmd::DownloadStart,
        data: vec![
            total.to_string(),
            content.len().to_string(),
            node.hash.clone(),
        ],
    }
}

pub fn download_chunk(data: Vec<String>, session: &Session) -> AppMessage {
    if !session.authenticated {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["not authenticated".into()],
        };
    }

    let idx: usize = data
        .first()
        .and_then(|s| s.parse().ok())
        .unwrap_or(usize::MAX);

    let download = match session.download.as_ref() {
        Some(d) => d,
        None => {
            return AppMessage {
                cmd: Cmd::Failure,
                data: vec!["no download in progress".into()],
            }
        }
    };

    match download.chunks.get(idx) {
        Some(chunk) => AppMessage {
            cmd: Cmd::DownloadChunk,
            data: vec![idx.to_string(), chunk.clone()],
        },
        None => AppMessage {
            cmd: Cmd::Failure,
            data: vec!["chunk index out of range".into()],
        },
    }
}

pub fn download_end(session: &mut Session) -> AppMessage {
    if !session.authenticated {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["not authenticated".into()],
        };
    }
    session.download = None;
    AppMessage {
        cmd: Cmd::DownloadEnd,
        data: vec!["ok".into()],
    }
}
