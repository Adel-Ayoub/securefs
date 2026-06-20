use deadpool_postgres::Pool;
use securefs_blobstore::Blobstore;
use securefs_model::protocol::{AppMessage, Cmd};

use securefs_server::dao;

use crate::session::Session;
use crate::util::*;

use super::read_file_bytes;

// Cap on total bytes grep will decrypt+scan in one request.
const MAX_GREP_SCAN_BYTES: usize = 64 * 1024 * 1024;

// Decrypt to UTF-8 text for the line-oriented commands (cat, head, tail, grep).
async fn read_file_content(
    store: &dyn Blobstore,
    path: &str,
    wrapped_dek: Option<&[u8]>,
) -> Result<String, AppMessage> {
    let bytes = read_file_bytes(store, path, wrapped_dek).await?;
    String::from_utf8(bytes).map_err(|_| AppMessage {
        cmd: Cmd::Failure,
        data: vec!["binary file; use download".into()],
    })
}

pub async fn cat(
    data: Vec<String>,
    session: &Session,
    pool: &Pool,
    store: &dyn Blobstore,
) -> AppMessage {
    if !session.authenticated {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["not authenticated".to_string()],
        };
    }

    let file_name = data.first().cloned().unwrap_or_default();
    if !is_valid_name(&file_name) {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["invalid file name".to_string()],
        };
    }

    let node_path = format!("{}/{}", session.current_path, file_name);

    match dao::get_f_node(pool, node_path.clone()).await {
        Ok(Some(node)) if node.dir => AppMessage {
            cmd: Cmd::Failure,
            data: vec!["cannot cat dir".into()],
        },
        Ok(Some(node)) => {
            // Follow symlink to resolve the actual file's logical path.
            let (resolved_node, resolved_path) = if let Some(ref target) = node.link_target {
                match dao::get_f_node(pool, target.clone()).await {
                    Ok(Some(tgt)) if !tgt.dir => {
                        let path = tgt.path.clone();
                        (tgt, path)
                    }
                    Ok(Some(_)) => {
                        return AppMessage {
                            cmd: Cmd::Failure,
                            data: vec!["cannot cat dir".into()],
                        }
                    }
                    _ => {
                        return AppMessage {
                            cmd: Cmd::Failure,
                            data: vec!["broken symlink".into()],
                        }
                    }
                }
            } else {
                (node, node_path.clone())
            };

            let owner_group = dao::get_file_group(
                pool,
                resolved_node.owner.clone(),
                resolved_node.file_group.clone(),
            )
            .await
            .unwrap_or(None);
            if can_read_with_group(
                &resolved_node,
                session.current_user.as_ref(),
                session.current_user_group.as_ref(),
                owner_group.as_ref(),
            ) {
                let wrapped = dao::get_wrapped_dek(pool, resolved_path.clone())
                    .await
                    .unwrap_or(None);
                match read_file_content(store, &resolved_path, wrapped.as_deref()).await {
                    Ok(content) => {
                        audit!(
                            pool,
                            "FILE_READ",
                            session.current_user.as_deref().unwrap_or("-"),
                            &resolved_path,
                            "ok"
                        );
                        AppMessage {
                            cmd: Cmd::Cat,
                            data: vec![content],
                        }
                    }
                    Err(e) => e,
                }
            } else {
                AppMessage {
                    cmd: Cmd::Failure,
                    data: vec!["no read permission".into()],
                }
            }
        }
        _ => AppMessage {
            cmd: Cmd::Failure,
            data: vec!["no read permission".into()],
        },
    }
}

pub async fn head(
    data: Vec<String>,
    session: &Session,
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
    let n: usize = data.get(1).and_then(|s| s.parse().ok()).unwrap_or(10);
    if !is_valid_name(&file_name) {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["invalid file name".into()],
        };
    }

    let node_path = format!("{}/{}", session.current_path, file_name);
    match dao::get_f_node(pool, node_path.clone()).await {
        Ok(Some(node)) if node.dir => AppMessage {
            cmd: Cmd::Failure,
            data: vec!["cannot read directory".into()],
        },
        Ok(Some(node)) => {
            let owner_group =
                dao::get_file_group(pool, node.owner.clone(), node.file_group.clone())
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
            let wrapped = dao::get_wrapped_dek(pool, node_path.clone())
                .await
                .unwrap_or(None);
            match read_file_content(store, &node_path, wrapped.as_deref()).await {
                Ok(content) => {
                    let lines: Vec<&str> = content.lines().take(n).collect();
                    AppMessage {
                        cmd: Cmd::Head,
                        data: vec![lines.join("\n")],
                    }
                }
                Err(e) => e,
            }
        }
        _ => AppMessage {
            cmd: Cmd::Failure,
            data: vec!["file not found".into()],
        },
    }
}

pub async fn tail(
    data: Vec<String>,
    session: &Session,
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
    let n: usize = data.get(1).and_then(|s| s.parse().ok()).unwrap_or(10);
    if !is_valid_name(&file_name) {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["invalid file name".into()],
        };
    }

    let node_path = format!("{}/{}", session.current_path, file_name);
    match dao::get_f_node(pool, node_path.clone()).await {
        Ok(Some(node)) if node.dir => AppMessage {
            cmd: Cmd::Failure,
            data: vec!["cannot read directory".into()],
        },
        Ok(Some(node)) => {
            let owner_group =
                dao::get_file_group(pool, node.owner.clone(), node.file_group.clone())
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
            let wrapped = dao::get_wrapped_dek(pool, node_path.clone())
                .await
                .unwrap_or(None);
            match read_file_content(store, &node_path, wrapped.as_deref()).await {
                Ok(content) => {
                    let all_lines: Vec<&str> = content.lines().collect();
                    let start = all_lines.len().saturating_sub(n);
                    let lines = &all_lines[start..];
                    AppMessage {
                        cmd: Cmd::Tail,
                        data: vec![lines.join("\n")],
                    }
                }
                Err(e) => e,
            }
        }
        _ => AppMessage {
            cmd: Cmd::Failure,
            data: vec!["file not found".into()],
        },
    }
}

pub async fn grep(
    data: Vec<String>,
    session: &Session,
    pool: &Pool,
    store: &dyn Blobstore,
) -> AppMessage {
    if !session.authenticated {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["not authenticated".to_string()],
        };
    }

    let pattern = data.first().cloned().unwrap_or_default();
    if pattern.is_empty() {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["missing pattern".into()],
        };
    }

    let nodes = match dao::get_subtree(pool, session.current_path.clone()).await {
        Ok(n) => n,
        Err(_) => {
            return AppMessage {
                cmd: Cmd::Failure,
                data: vec!["grep failed".into()],
            }
        }
    };

    let mut matches = Vec::new();
    let max_matches = 100;
    let mut scanned: usize = 0;

    for node in &nodes {
        if node.dir {
            continue;
        }
        if scanned >= MAX_GREP_SCAN_BYTES {
            break;
        }
        let owner_group = dao::get_file_group(pool, node.owner.clone(), node.file_group.clone())
            .await
            .unwrap_or(None);
        if !can_read_with_group(
            node,
            session.current_user.as_ref(),
            session.current_user_group.as_ref(),
            owner_group.as_ref(),
        ) {
            continue;
        }

        let wrapped = dao::get_wrapped_dek(pool, node.path.clone())
            .await
            .unwrap_or(None);
        if let Ok(content) = read_file_content(store, &node.path, wrapped.as_deref()).await {
            scanned += content.len();
            for (i, line) in content.lines().enumerate() {
                if line.contains(&pattern) {
                    let rel = node
                        .path
                        .strip_prefix(&session.current_path)
                        .unwrap_or(&node.path)
                        .trim_start_matches('/');
                    matches.push(format!("{}:{}:{}", rel, i + 1, line));
                    if matches.len() >= max_matches {
                        break;
                    }
                }
            }
        }
        if matches.len() >= max_matches {
            break;
        }
    }

    if matches.is_empty() {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["no matches".into()],
        };
    }

    AppMessage {
        cmd: Cmd::Grep,
        data: matches,
    }
}
