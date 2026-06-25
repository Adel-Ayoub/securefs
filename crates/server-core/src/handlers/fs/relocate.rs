use deadpool_postgres::Pool;
use securefs_blobstore::Blobstore;
use securefs_proto::protocol::{AppMessage, Cmd};
use std::path::Path;

use crate::dao;
use crate::storage::physical_key;

use crate::session::Session;
use crate::util::*;

pub async fn mv(
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
                // Snapshot blob paths before the DB rewrites descendant paths:
                // the node itself plus every descendant file. The key derives
                // from the full path, so each must move from key(old) to
                // key(new); directories and never-written files have no blob.
                let mut blob_paths = vec![old_path.clone()];
                if let Ok(sub) = dao::get_subtree(pool, old_path.clone()).await {
                    blob_paths.extend(sub.into_iter().filter(|n| !n.dir).map(|n| n.path));
                }
                match dao::rename_node(
                    pool,
                    session.current_path.clone(),
                    old_path.clone(),
                    new_path.clone(),
                    src.clone(),
                    dst.clone(),
                )
                .await
                {
                    Ok(_) => {
                        // Move each backing blob so file content follows the rename.
                        for old_file in &blob_paths {
                            let new_file = format!("{}{}", new_path, &old_file[old_path.len()..]);
                            if let (Ok(old_key), Ok(new_key)) =
                                (physical_key(old_file), physical_key(&new_file))
                            {
                                if store.exists(&old_key).await.unwrap_or(false) {
                                    if let Err(e) = store.rename(&old_key, &new_key).await {
                                        log::warn!("mv blob move failed: {}", e);
                                    }
                                }
                            }
                        }
                        AppMessage {
                            cmd: Cmd::Mv,
                            data: vec!["ok".to_string()],
                        }
                    }
                    Err(e) => {
                        log::warn!("mv failed: {}", e);
                        AppMessage {
                            cmd: Cmd::Failure,
                            data: vec!["mv failed".to_string()],
                        }
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

pub async fn cp(
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
                                        store,
                                    )
                                    .await
                                    {
                                        Ok(_) => AppMessage {
                                            cmd: Cmd::Cp,
                                            data: vec!["ok".to_string()],
                                        },
                                        Err(e) => {
                                            log::warn!("cp failed: {}", e);
                                            AppMessage {
                                                cmd: Cmd::Failure,
                                                data: vec!["copy failed".into()],
                                            }
                                        }
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
