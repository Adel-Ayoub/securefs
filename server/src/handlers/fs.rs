use deadpool_postgres::Pool;
use securefs_model::protocol::{AppMessage, Cmd, FNode};
use std::collections::HashSet;
use std::fs as stdfs;
use std::path::Path;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use securefs_server::dao;

use crate::crypto::{decrypt_file_content, encrypt_file_content, hash_content};
use crate::session::Session;
use crate::util::*;

// Helpers for reading and decrypting file content (shared by cat, head, tail)
async fn read_file_content(file_path: &str) -> Result<String, AppMessage> {
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
    let decrypted = decrypt_file_content(&encrypted).map_err(|e| AppMessage {
        cmd: Cmd::Failure,
        data: vec![e.to_string()],
    })?;
    String::from_utf8(decrypted).map_err(|_| AppMessage {
        cmd: Cmd::Failure,
        data: vec!["invalid utf-8".into()],
    })
}

pub fn pwd(session: &Session) -> AppMessage {
    if !session.authenticated {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["not authenticated".to_string()],
        };
    }
    AppMessage {
        cmd: Cmd::Pwd,
        data: vec![session.current_path.clone()],
    }
}

pub async fn cd(data: Vec<String>, session: &mut Session, pool: &Pool) -> AppMessage {
    if !session.authenticated {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["not authenticated".to_string()],
        };
    }

    let target = data.first().cloned().unwrap_or_default();
    let new_path = resolve_path(&session.current_path, &target);
    if !is_safe_path(&new_path) {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["path not allowed".to_string()],
        };
    }

    let mut guard = HashSet::new();
    if !guard.insert(new_path.clone()) {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["invalid path".to_string()],
        };
    }

    match dao::get_f_node(pool, new_path.clone()).await {
        Ok(Some(node)) if node.dir => {
            let owner_group =
                dao::get_file_group(pool, node.owner.clone(), node.file_group.clone())
                    .await
                    .unwrap_or(None);
            if can_read_with_group(
                &node,
                session.current_user.as_ref(),
                session.current_user_group.as_ref(),
                owner_group.as_ref(),
            ) {
                session.current_path = new_path.clone();
                AppMessage {
                    cmd: Cmd::Cd,
                    data: vec![new_path],
                }
            } else {
                AppMessage {
                    cmd: Cmd::Failure,
                    data: vec!["no read permission".to_string()],
                }
            }
        }
        _ => AppMessage {
            cmd: Cmd::Failure,
            data: vec!["invalid path".to_string()],
        },
    }
}

pub async fn ls(session: &Session, pool: &Pool) -> AppMessage {
    if !session.authenticated {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["not authenticated".to_string()],
        };
    }

    let children = match dao::get_f_node(pool, session.current_path.clone()).await {
        Ok(Some(fnode)) => {
            let owner_group =
                dao::get_file_group(pool, fnode.owner.clone(), fnode.file_group.clone())
                    .await
                    .unwrap_or(None);
            if can_read_with_group(
                &fnode,
                session.current_user.as_ref(),
                session.current_user_group.as_ref(),
                owner_group.as_ref(),
            ) {
                match dao::get_children(pool, session.current_path.clone()).await {
                    Ok(nodes) => nodes.iter().map(format_ls_entry).collect(),
                    Err(_) => vec![],
                }
            } else {
                vec![]
            }
        }
        _ => vec![],
    };
    AppMessage {
        cmd: Cmd::Ls,
        data: children,
    }
}

pub async fn find(data: Vec<String>, session: &Session, pool: &Pool) -> AppMessage {
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
            data: vec!["missing pattern".to_string()],
        };
    }

    match dao::get_subtree(pool, session.current_path.clone()).await {
        Ok(nodes) => {
            let results: Vec<String> = nodes
                .iter()
                .filter(|n| {
                    n.name.contains(&pattern)
                        && can_read_with_group(
                            n,
                            session.current_user.as_ref(),
                            session.current_user_group.as_ref(),
                            // NOTE: uses file_group directly, skipping owner lookup for perf
                            n.file_group.as_ref(),
                        )
                })
                .map(|n| n.path.clone())
                .collect();
            if results.is_empty() {
                AppMessage {
                    cmd: Cmd::Find,
                    data: vec!["no matches found".to_string()],
                }
            } else {
                AppMessage {
                    cmd: Cmd::Find,
                    data: results,
                }
            }
        }
        Err(_) => AppMessage {
            cmd: Cmd::Find,
            data: vec!["no matches found".to_string()],
        },
    }
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

pub async fn delete(data: Vec<String>, session: &Session, pool: &Pool) -> AppMessage {
    if !session.authenticated {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["not authenticated".to_string()],
        };
    }

    let target = data.first().cloned().unwrap_or_default();
    if !is_valid_name(&target) {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["invalid path".to_string()],
        };
    }

    let path = format!("{}/{}", session.current_path, target);
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

    if let Ok(Some(node)) = dao::get_f_node(pool, path.clone()).await {
        if node.dir && !node.children.is_empty() {
            return AppMessage {
                cmd: Cmd::Failure,
                data: vec!["directory not empty".into()],
            };
        }

        let storage_path = format!("storage{}", path);
        if Path::new(&storage_path).exists() {
            let _ =
                stdfs::remove_file(&storage_path).or_else(|_| stdfs::remove_dir_all(&storage_path));
        }

        let parent_remove =
            dao::remove_file_from_parent(pool, session.current_path.clone(), target.clone()).await;
        let del = dao::delete_path(pool, path.clone()).await;

        if parent_remove.is_ok() && del.is_ok() {
            AppMessage {
                cmd: Cmd::Delete,
                data: vec!["ok".to_string()],
            }
        } else {
            AppMessage {
                cmd: Cmd::Failure,
                data: vec!["delete failed".to_string()],
            }
        }
    } else {
        AppMessage {
            cmd: Cmd::Failure,
            data: vec!["delete failed".to_string()],
        }
    }
}

pub async fn mv(data: Vec<String>, session: &Session, pool: &Pool) -> AppMessage {
    if !session.authenticated {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["not authenticated".to_string()],
        };
    }

    let src = data.first().cloned().unwrap_or_default();
    let dst = data.get(1).cloned().unwrap_or_default();
    if !is_valid_name(&src) || !is_valid_name(&dst) {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["invalid name".to_string()],
        };
    }

    let old_path = format!("{}/{}", session.current_path, src);
    let new_path = format!("{}/{}", session.current_path, dst);

    let src_exists = dao::get_f_node(pool, old_path.clone())
        .await
        .ok()
        .flatten()
        .is_some();
    if !src_exists {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["source not found".to_string()],
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
                let res = dao::update_path(pool, old_path.clone(), new_path.clone()).await;
                let name_res = dao::update_fnode_name_if_path_is_already_updated(
                    pool,
                    new_path.clone(),
                    dst.clone(),
                )
                .await;
                let enc_res = dao::update_fnode_enc_name(pool, new_path.clone(), dst.clone()).await;
                let parent_remove =
                    dao::remove_file_from_parent(pool, session.current_path.clone(), src.clone())
                        .await;
                let parent_add =
                    dao::add_file_to_parent(pool, session.current_path.clone(), dst.clone()).await;
                if res.is_ok()
                    && name_res.is_ok()
                    && enc_res.is_ok()
                    && parent_remove.is_ok()
                    && parent_add.is_ok()
                {
                    AppMessage {
                        cmd: Cmd::Mv,
                        data: vec!["ok".to_string()],
                    }
                } else {
                    AppMessage {
                        cmd: Cmd::Failure,
                        data: vec!["mv failed".to_string()],
                    }
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

pub async fn cp(data: Vec<String>, session: &Session, pool: &Pool) -> AppMessage {
    if !session.authenticated {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["not authenticated".to_string()],
        };
    }

    let src = data.first().cloned().unwrap_or_default();
    let dst = data.get(1).cloned().unwrap_or_default();
    if !is_valid_name(&src) || !is_valid_name(&dst) {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["invalid name".to_string()],
        };
    }

    let src_path = format!("{}/{}", session.current_path, src);
    let dst_path_orig = format!("{}/{}", session.current_path, dst);

    match dao::get_f_node(pool, src_path.clone()).await {
        Ok(Some(src_node)) => {
            let src_owner_group =
                dao::get_file_group(pool, src_node.owner.clone(), src_node.file_group.clone())
                    .await
                    .unwrap_or(None);
            if can_read_with_group(
                &src_node,
                session.current_user.as_ref(),
                session.current_user_group.as_ref(),
                src_owner_group.as_ref(),
            ) {
                let (final_dst_path, valid_dst) = match dao::get_f_node(pool, dst_path_orig.clone())
                    .await
                {
                    Ok(Some(dst_node)) => {
                        if dst_node.dir {
                            match Path::new(&src_path).file_name().and_then(|n| n.to_str()) {
                                Some(src_name) => (format!("{}/{}", dst_path_orig, src_name), true),
                                None => (String::new(), false),
                            }
                        } else {
                            (String::new(), false)
                        }
                    }
                    Ok(None) => (dst_path_orig, true),
                    Err(_) => (String::new(), false),
                };

                if !valid_dst || final_dst_path.is_empty() {
                    return AppMessage {
                        cmd: Cmd::Failure,
                        data: vec!["destination exists as file or error".to_string()],
                    };
                }

                match dao::get_f_node(pool, final_dst_path.clone()).await {
                    Ok(Some(_)) => AppMessage {
                        cmd: Cmd::Failure,
                        data: vec!["destination already exists".to_string()],
                    },
                    _ => {
                        let path_obj = Path::new(&final_dst_path);
                        let parent_opt = path_obj.parent().map(|p| p.to_str().unwrap_or("/"));
                        let parent_str = match parent_opt {
                            Some("") | None => "/".to_string(),
                            Some(p) => p.to_string(),
                        };

                        match dao::get_f_node(pool, parent_str).await {
                            Ok(Some(parent_node)) => {
                                let parent_owner_group = dao::get_file_group(
                                    pool,
                                    parent_node.owner.clone(),
                                    parent_node.file_group.clone(),
                                )
                                .await
                                .unwrap_or(None);
                                if can_write_with_group(
                                    &parent_node,
                                    session.current_user.as_ref(),
                                    session.current_user_group.as_ref(),
                                    parent_owner_group.as_ref(),
                                ) {
                                    match dao::copy_recursive(
                                        pool,
                                        src_path,
                                        final_dst_path,
                                        session.current_user.clone().unwrap(),
                                    )
                                    .await
                                    {
                                        Ok(_) => AppMessage {
                                            cmd: Cmd::Cp,
                                            data: vec!["ok".to_string()],
                                        },
                                        Err(e) => AppMessage {
                                            cmd: Cmd::Failure,
                                            data: vec![e.to_string()],
                                        },
                                    }
                                } else {
                                    AppMessage {
                                        cmd: Cmd::Failure,
                                        data: vec![
                                            "no write permission on target directory".to_string()
                                        ],
                                    }
                                }
                            }
                            _ => AppMessage {
                                cmd: Cmd::Failure,
                                data: vec!["target directory not found".to_string()],
                            },
                        }
                    }
                }
            } else {
                AppMessage {
                    cmd: Cmd::Failure,
                    data: vec!["no read permission on source".to_string()],
                }
            }
        }
        _ => AppMessage {
            cmd: Cmd::Failure,
            data: vec!["source not found".to_string()],
        },
    }
}

pub async fn cat(data: Vec<String>, session: &Session, pool: &Pool) -> AppMessage {
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

    let target_path = format!("storage{}", session.current_path);
    let file_path = format!("{}/{}", target_path, file_name);

    match dao::get_f_node(pool, format!("{}/{}", session.current_path, file_name)).await {
        Ok(Some(node)) if node.dir => AppMessage {
            cmd: Cmd::Failure,
            data: vec!["cannot cat dir".into()],
        },
        Ok(Some(node)) => {
            let owner_group =
                dao::get_file_group(pool, node.owner.clone(), node.file_group.clone())
                    .await
                    .unwrap_or(None);
            if can_read_with_group(
                &node,
                session.current_user.as_ref(),
                session.current_user_group.as_ref(),
                owner_group.as_ref(),
            ) {
                match fs::File::open(&file_path).await {
                    Ok(mut f) => {
                        let mut encrypted = Vec::new();
                        match f.read_to_end(&mut encrypted).await {
                            Ok(_) => match decrypt_file_content(&encrypted) {
                                Ok(decrypted) => match String::from_utf8(decrypted) {
                                    Ok(content) => {
                                        audit!(
                                            "FILE_READ",
                                            session.current_user.as_deref().unwrap_or("-"),
                                            &file_path,
                                            "ok"
                                        );
                                        AppMessage {
                                            cmd: Cmd::Cat,
                                            data: vec![content],
                                        }
                                    }
                                    Err(_) => AppMessage {
                                        cmd: Cmd::Failure,
                                        data: vec!["invalid utf-8".to_string()],
                                    },
                                },
                                Err(e) => AppMessage {
                                    cmd: Cmd::Failure,
                                    data: vec![e.to_string()],
                                },
                            },
                            Err(_) => AppMessage {
                                cmd: Cmd::Failure,
                                data: vec!["cat failed".to_string()],
                            },
                        }
                    }
                    Err(_) => AppMessage {
                        cmd: Cmd::Failure,
                        data: vec!["cat failed".to_string()],
                    },
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
                                let _ = dao::update_hash(pool, node_path, file_name.clone(), hash)
                                    .await;
                                audit!(
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

pub async fn tree(session: &Session, pool: &Pool) -> AppMessage {
    if !session.authenticated {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["not authenticated".into()],
        };
    }

    match dao::get_subtree(pool, session.current_path.clone()).await {
        Ok(mut nodes) => {
            nodes.sort_by(|a, b| a.path.cmp(&b.path));
            let base_depth = session
                .current_path
                .split('/')
                .filter(|s| !s.is_empty())
                .count();
            let mut lines: Vec<String> = vec![".".into()];
            for node in &nodes {
                if !can_read_with_group(
                    node,
                    session.current_user.as_ref(),
                    session.current_user_group.as_ref(),
                    node.file_group.as_ref(),
                ) {
                    continue;
                }
                let depth = node.path.split('/').filter(|s| !s.is_empty()).count() - base_depth;
                if depth == 0 {
                    continue;
                }
                let indent = format!("{}-- ", "   ".repeat(depth - 1));
                let suffix = if node.dir { "/" } else { "" };
                lines.push(format!("{}{}{}", indent, node.name, suffix));
            }
            AppMessage {
                cmd: Cmd::Tree,
                data: lines,
            }
        }
        Err(_) => AppMessage {
            cmd: Cmd::Failure,
            data: vec!["tree failed".into()],
        },
    }
}

pub async fn stat(data: Vec<String>, session: &Session, pool: &Pool) -> AppMessage {
    if !session.authenticated {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["not authenticated".into()],
        };
    }

    let name = data.first().cloned().unwrap_or_default();
    if !is_valid_name(&name) {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["invalid name".into()],
        };
    }

    let path = format!("{}/{}", session.current_path, name);
    match dao::get_f_node(pool, path.clone()).await {
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

            let file_size = if !node.dir {
                let storage_path = format!("storage{}", path);
                tokio::fs::metadata(&storage_path)
                    .await
                    .map(|m| m.len() as i64)
                    .unwrap_or(0)
            } else {
                0
            };

            let kind = if node.dir { "directory" } else { "file" };
            let perms = format_permissions(node.u, node.g, node.o);
            let group = node.file_group.as_deref().unwrap_or("(none)");
            AppMessage {
                cmd: Cmd::Stat,
                data: vec![
                    format!("  Name: {}", node.name),
                    format!("  Path: {}", node.path),
                    format!("  Type: {}", kind),
                    format!(" Owner: {}", node.owner),
                    format!(" Group: {}", group),
                    format!(" Perms: {}", perms),
                    format!("  Size: {} bytes", file_size),
                    format!(
                        "  Hash: {}",
                        if node.hash.is_empty() {
                            "-"
                        } else {
                            &node.hash
                        }
                    ),
                    format!("  Created: {}", node.created_at),
                    format!(" Modified: {}", node.modified_at),
                ],
            }
        }
        _ => AppMessage {
            cmd: Cmd::Failure,
            data: vec!["not found".into()],
        },
    }
}

pub async fn du(session: &Session, pool: &Pool) -> AppMessage {
    if !session.authenticated {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["not authenticated".into()],
        };
    }

    match dao::get_subtree(pool, session.current_path.clone()).await {
        Ok(nodes) => {
            let mut total: u64 = 0;
            for node in &nodes {
                if node.dir {
                    continue;
                }
                let storage_path = format!("storage{}", node.path);
                if let Ok(meta) = tokio::fs::metadata(&storage_path).await {
                    total += meta.len();
                }
            }
            let human = if total >= 1_048_576 {
                format!("{:.1} MB", total as f64 / 1_048_576.0)
            } else if total >= 1024 {
                format!("{:.1} KB", total as f64 / 1024.0)
            } else {
                format!("{} B", total)
            };
            AppMessage {
                cmd: Cmd::Du,
                data: vec![format!("{} ({})", human, session.current_path)],
            }
        }
        Err(_) => AppMessage {
            cmd: Cmd::Failure,
            data: vec!["du failed".into()],
        },
    }
}

pub async fn head(data: Vec<String>, session: &Session, pool: &Pool) -> AppMessage {
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
    match dao::get_f_node(pool, node_path).await {
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
            let file_path = format!("storage{}/{}", session.current_path, file_name);
            match read_file_content(&file_path).await {
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

pub async fn tail(data: Vec<String>, session: &Session, pool: &Pool) -> AppMessage {
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
    match dao::get_f_node(pool, node_path).await {
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
            let file_path = format!("storage{}/{}", session.current_path, file_name);
            match read_file_content(&file_path).await {
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
