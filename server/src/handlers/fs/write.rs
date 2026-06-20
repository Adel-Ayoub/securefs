use deadpool_postgres::Pool;
use globset::GlobBuilder;
use securefs_model::protocol::{AppMessage, Cmd, FNode};
use std::fs as stdfs;
use std::path::Path;
use tokio::fs;
use tokio::io::AsyncWriteExt;

use securefs_server::dao;

use crate::crypto::{encrypt_file_content, hash_content};
use crate::session::Session;
use crate::util::*;

/// Check if a string contains glob metacharacters.
fn is_glob_pattern(s: &str) -> bool {
    s.contains('*') || s.contains('?')
}

/// Expand a glob pattern against children of a directory.
async fn expand_glob(pool: &Pool, parent_path: &str, pattern: &str) -> Result<Vec<String>, String> {
    let glob = GlobBuilder::new(pattern)
        .literal_separator(true)
        .build()
        .map_err(|e| format!("invalid glob: {}", e))?
        .compile_matcher();
    let children = dao::get_children(pool, parent_path.to_string())
        .await
        .map_err(|_| "failed to list children".to_string())?;
    Ok(children
        .iter()
        .filter(|c| glob.is_match(&c.name))
        .map(|c| c.name.clone())
        .collect())
}

pub async fn mkdir(data: Vec<String>, session: &Session, pool: &Pool) -> AppMessage {
    if !session.authenticated {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["not authenticated".to_string()],
        };
    }

    let dir_name = data.first().cloned().unwrap_or_default();
    if !is_valid_name(&dir_name) {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["invalid directory name".to_string()],
        };
    }

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

    let target_path = format!("{}/{}", session.current_path, dir_name);
    let exists = dao::get_f_node(pool, target_path.clone())
        .await
        .ok()
        .flatten()
        .is_some();
    if exists {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["directory already exists".to_string()],
        };
    }

    let owner = session.current_user.clone().unwrap_or_default();
    let now = current_timestamp();
    let new_dir = FNode {
        id: -1,
        name: dir_name.clone(),
        path: target_path.clone(),
        owner: owner.clone(),
        hash: "".to_string(),
        parent: session.current_path.clone(),
        dir: true,
        u: 7,
        g: 7,
        o: 7,
        children: vec![],
        encrypted_name: dir_name.clone(),
        size: 0,
        created_at: now,
        modified_at: now,
        file_group: session.current_user_group.clone(),
        link_target: None,
    };

    let res = dao::add_file(pool, new_dir).await;
    let parent_update = if res.is_ok() {
        dao::add_file_to_parent(pool, session.current_path.clone(), dir_name.clone()).await
    } else {
        Err(dao::DaoError::QueryFailed("parent not updated".into()))
    };

    match (res, parent_update) {
        (Ok(_), Ok(_)) => AppMessage {
            cmd: Cmd::Mkdir,
            data: vec!["ok".to_string()],
        },
        _ => AppMessage {
            cmd: Cmd::Failure,
            data: vec!["mkdir failed".to_string()],
        },
    }
}

pub async fn touch(data: Vec<String>, session: &Session, pool: &Pool) -> AppMessage {
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

    let target_path = format!("{}/{}", session.current_path, file_name);
    let exists = dao::get_f_node(pool, target_path.clone())
        .await
        .ok()
        .flatten()
        .is_some();
    if exists {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["file already exists".to_string()],
        };
    }

    let owner = session.current_user.clone().unwrap_or_default();
    let now = current_timestamp();
    let new_file = FNode {
        id: -1,
        name: file_name.clone(),
        path: target_path.clone(),
        owner: owner.clone(),
        hash: "".to_string(),
        parent: session.current_path.clone(),
        dir: false,
        u: 6,
        g: 6,
        o: 4,
        children: vec![],
        encrypted_name: file_name.clone(),
        size: 0,
        created_at: now,
        modified_at: now,
        file_group: session.current_user_group.clone(),
        link_target: None,
    };

    let res = dao::add_file(pool, new_file).await;
    let parent_update = if res.is_ok() {
        dao::add_file_to_parent(pool, session.current_path.clone(), file_name.clone()).await
    } else {
        Err(dao::DaoError::QueryFailed("parent not updated".into()))
    };

    match (res, parent_update) {
        (Ok(_), Ok(_)) => AppMessage {
            cmd: Cmd::Touch,
            data: vec!["ok".to_string()],
        },
        _ => AppMessage {
            cmd: Cmd::Failure,
            data: vec!["touch failed".to_string()],
        },
    }
}

pub async fn echo(data: Vec<String>, session: &Session, pool: &Pool) -> AppMessage {
    if !session.authenticated {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["not authenticated".to_string()],
        };
    }

    let file_name = data.first().cloned().unwrap_or_default();
    let content = data.get(1).cloned().unwrap_or_default();
    if !is_valid_name(&file_name) {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["invalid file name".to_string()],
        };
    }

    match dao::get_f_node(pool, session.current_path.clone()).await {
        Ok(Some(parent)) => {
            let owner_group =
                dao::get_file_group(pool, parent.owner.clone(), parent.file_group.clone())
                    .await
                    .unwrap_or(None);
            if can_write_with_group(
                &parent,
                session.current_user.as_ref(),
                session.current_user_group.as_ref(),
                owner_group.as_ref(),
            ) {
                let target_path = format!("storage{}", session.current_path);
                let file_path = format!("{}/{}", target_path, file_name);
                if fs::create_dir_all(&target_path).await.is_err() {
                    return AppMessage {
                        cmd: Cmd::Failure,
                        data: vec!["echo failed".to_string()],
                    };
                }
                match fs::File::create(&file_path).await {
                    Ok(mut f) => {
                        let encrypted = encrypt_file_content(content.as_bytes());
                        match f.write_all(&encrypted).await {
                            Ok(_) => {
                                let hash = hash_content(content.as_bytes());
                                let node_path = format!("{}/{}", session.current_path, file_name);
                                // Create the FNode if this is a new file; otherwise
                                // echo writes ciphertext to disk with no visible node.
                                if dao::get_f_node(pool, node_path.clone())
                                    .await
                                    .ok()
                                    .flatten()
                                    .is_none()
                                {
                                    let now = current_timestamp();
                                    let new_file = FNode {
                                        id: -1,
                                        name: file_name.clone(),
                                        path: node_path.clone(),
                                        owner: session.current_user.clone().unwrap_or_default(),
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
                                    let _ = dao::add_file_to_parent(
                                        pool,
                                        session.current_path.clone(),
                                        file_name.clone(),
                                    )
                                    .await;
                                }
                                // Use advisory lock for existing files
                                if let Err(e) =
                                    dao::update_hash_locked(pool, node_path.clone(), hash.clone())
                                        .await
                                {
                                    if matches!(e, dao::DaoError::Conflict(_)) {
                                        return AppMessage {
                                            cmd: Cmd::Failure,
                                            data: vec!["file is being modified, try again".into()],
                                        };
                                    }
                                    // File may not exist yet — fall back to regular update
                                    let _ =
                                        dao::update_hash(pool, node_path, file_name.clone(), hash)
                                            .await;
                                }
                                audit!(
                                    pool,
                                    "FILE_WRITE",
                                    session.current_user.as_deref().unwrap_or("-"),
                                    &file_path,
                                    "ok"
                                );
                                AppMessage {
                                    cmd: Cmd::Echo,
                                    data: vec!["ok".to_string()],
                                }
                            }
                            Err(_) => AppMessage {
                                cmd: Cmd::Failure,
                                data: vec!["echo failed".to_string()],
                            },
                        }
                    }
                    Err(_) => AppMessage {
                        cmd: Cmd::Failure,
                        data: vec!["echo failed".to_string()],
                    },
                }
            } else {
                AppMessage {
                    cmd: Cmd::Failure,
                    data: vec!["no write permission".into()],
                }
            }
        }
        _ => AppMessage {
            cmd: Cmd::Failure,
            data: vec!["no write permission".into()],
        },
    }
}

pub async fn delete(data: Vec<String>, session: &Session, pool: &Pool) -> AppMessage {
    if !session.authenticated {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["not authenticated".to_string()],
        };
    }

    let target = data.first().cloned().unwrap_or_default();

    // Check write permission on parent directory
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

    // Expand glob or use single target
    let targets = if is_glob_pattern(&target) {
        match expand_glob(pool, &session.current_path, &target).await {
            Ok(names) if names.is_empty() => {
                return AppMessage {
                    cmd: Cmd::Failure,
                    data: vec!["no matches".into()],
                }
            }
            Ok(names) => names,
            Err(e) => {
                return AppMessage {
                    cmd: Cmd::Failure,
                    data: vec![e],
                }
            }
        }
    } else {
        if !is_valid_name(&target) {
            return AppMessage {
                cmd: Cmd::Failure,
                data: vec!["invalid path".to_string()],
            };
        }
        vec![target]
    };

    let mut deleted = 0;
    let mut errors = Vec::new();
    for name in &targets {
        let path = format!("{}/{}", session.current_path, name);
        if let Ok(Some(node)) = dao::get_f_node(pool, path.clone()).await {
            if node.dir && !node.children.is_empty() {
                errors.push(format!("{}: directory not empty", name));
                continue;
            }
            match dao::delete_node(
                pool,
                session.current_path.clone(),
                name.clone(),
                path.clone(),
            )
            .await
            {
                Ok(_) => {
                    // Remove backing storage only after the DB change commits.
                    let storage_path = format!("storage{}", path);
                    if Path::new(&storage_path).exists() {
                        let _ = stdfs::remove_file(&storage_path)
                            .or_else(|_| stdfs::remove_dir_all(&storage_path));
                    }
                    deleted += 1;
                }
                Err(e) => {
                    log::warn!("delete failed: {}", e);
                    errors.push(format!("{}: delete failed", name));
                }
            }
        } else {
            errors.push(format!("{}: not found", name));
        }
    }

    if deleted > 0 && errors.is_empty() {
        AppMessage {
            cmd: Cmd::Delete,
            data: vec![format!("{} deleted", deleted)],
        }
    } else if deleted > 0 {
        AppMessage {
            cmd: Cmd::Delete,
            data: vec![format!(
                "{} deleted, errors: {}",
                deleted,
                errors.join("; ")
            )],
        }
    } else {
        AppMessage {
            cmd: Cmd::Failure,
            data: vec![errors.join("; ")],
        }
    }
}

pub async fn ln(data: Vec<String>, session: &Session, pool: &Pool) -> AppMessage {
    if !session.authenticated {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["not authenticated".to_string()],
        };
    }

    let target = data.first().cloned().unwrap_or_default();
    let link_name = data.get(1).cloned().unwrap_or_default();
    if target.is_empty() || link_name.is_empty() {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["usage: ln <target> <link_name>".into()],
        };
    }
    if !is_valid_name(&link_name) {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["invalid link name".into()],
        };
    }

    let target_path = if target.starts_with('/') {
        target.clone()
    } else {
        format!("{}/{}", session.current_path, target)
    };
    if !is_safe_path(&target_path) {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["invalid target path".into()],
        };
    }

    if dao::get_f_node(pool, target_path.clone())
        .await
        .ok()
        .flatten()
        .is_none()
    {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["target does not exist".into()],
        };
    }

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

    let link_path = format!("{}/{}", session.current_path, link_name);
    if dao::get_f_node(pool, link_path.clone())
        .await
        .ok()
        .flatten()
        .is_some()
    {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["name already exists".into()],
        };
    }

    let owner = session.current_user.clone().unwrap_or_default();
    let now = current_timestamp();
    let symlink_node = FNode {
        id: -1,
        name: link_name.clone(),
        path: link_path,
        owner,
        hash: "".to_string(),
        parent: session.current_path.clone(),
        dir: false,
        u: 7,
        g: 7,
        o: 7,
        children: vec![],
        encrypted_name: link_name.clone(),
        size: 0,
        created_at: now,
        modified_at: now,
        file_group: session.current_user_group.clone(),
        link_target: Some(target_path),
    };

    match dao::add_file(pool, symlink_node).await {
        Ok(_) => {
            let _ = dao::add_file_to_parent(pool, session.current_path.clone(), link_name.clone())
                .await;
            AppMessage {
                cmd: Cmd::Ln,
                data: vec!["ok".into()],
            }
        }
        Err(_) => AppMessage {
            cmd: Cmd::Failure,
            data: vec!["failed to create symlink".into()],
        },
    }
}
