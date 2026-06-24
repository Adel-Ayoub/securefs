use deadpool_postgres::Pool;
use securefs_blobstore::Blobstore;
use securefs_proto::protocol::{AppMessage, Cmd};
use std::collections::HashSet;

use securefs_server::dao;
use securefs_server::storage::physical_key;

use crate::session::Session;
use crate::util::*;

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
        Ok(Some(node)) => {
            // Follow symlink if target is a directory
            let (resolved_path, resolved_node) = if let Some(ref target) = node.link_target {
                match dao::get_f_node(pool, target.clone()).await {
                    Ok(Some(tgt)) if tgt.dir => (target.clone(), tgt),
                    _ => {
                        return AppMessage {
                            cmd: Cmd::Failure,
                            data: vec!["symlink target is not a directory".into()],
                        }
                    }
                }
            } else if node.dir {
                (new_path.clone(), node)
            } else {
                return AppMessage {
                    cmd: Cmd::Failure,
                    data: vec!["not a directory".into()],
                };
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
                session.current_path = resolved_path.clone();
                AppMessage {
                    cmd: Cmd::Cd,
                    data: vec![resolved_path],
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

pub async fn stat(
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
                match physical_key(&path) {
                    Ok(key) => store.size(&key).await.unwrap_or(0) as i64,
                    Err(_) => 0,
                }
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

pub async fn du(session: &Session, pool: &Pool, store: &dyn Blobstore) -> AppMessage {
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
                if let Ok(key) = physical_key(&node.path) {
                    if let Ok(sz) = store.size(&key).await {
                        total += sz;
                    }
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
