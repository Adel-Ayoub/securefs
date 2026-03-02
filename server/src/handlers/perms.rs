use deadpool_postgres::Pool;
use globset::GlobBuilder;
use log::info;
use securefs_model::protocol::{AppMessage, Cmd};
use tokio::fs;

use securefs_server::dao;

use crate::crypto::{decrypt_file_content, hash_content};
use crate::session::Session;
use crate::util::*;

pub async fn chmod(data: Vec<String>, session: &Session, pool: &Pool) -> AppMessage {
    if !session.authenticated {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["not authenticated".to_string()],
        };
    }

    let target = data.first().cloned().unwrap_or_default();
    let mode = data.get(1).cloned().unwrap_or_default();
    if mode.len() != 3 {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["invalid args".to_string()],
        };
    }

    let ugo: Vec<i16> = mode
        .chars()
        .filter_map(|c| c.to_digit(8))
        .map(|d| d as i16)
        .collect();
    if ugo.len() != 3 {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["invalid mode".to_string()],
        };
    }

    // Expand glob or use single target
    let is_glob = target.contains('*') || target.contains('?');
    let targets = if is_glob {
        let glob = match GlobBuilder::new(&target).literal_separator(true).build() {
            Ok(g) => g.compile_matcher(),
            Err(e) => {
                return AppMessage {
                    cmd: Cmd::Failure,
                    data: vec![format!("invalid glob: {}", e)],
                }
            }
        };
        let children = match dao::get_children(pool, session.current_path.clone()).await {
            Ok(c) => c,
            Err(_) => {
                return AppMessage {
                    cmd: Cmd::Failure,
                    data: vec!["failed to list children".into()],
                }
            }
        };
        let names: Vec<String> = children
            .iter()
            .filter(|c| glob.is_match(&c.name))
            .map(|c| c.name.clone())
            .collect();
        if names.is_empty() {
            return AppMessage {
                cmd: Cmd::Failure,
                data: vec!["no matches".into()],
            };
        }
        names
    } else {
        if !is_valid_name(&target) {
            return AppMessage {
                cmd: Cmd::Failure,
                data: vec!["invalid args".to_string()],
            };
        }
        vec![target]
    };

    let mut changed = 0;
    let mut errors = Vec::new();
    for name in &targets {
        let path = format!("{}/{}", session.current_path, name);
        match dao::get_f_node(pool, path.clone()).await {
            Ok(Some(node)) if is_owner(&node, session.current_user.as_ref()) => {
                match dao::change_file_perms(pool, path.clone(), ugo[0], ugo[1], ugo[2]).await {
                    Ok(_) => {
                        audit!(
                            pool,
                            "CHMOD",
                            session.current_user.as_deref().unwrap_or("-"),
                            &path,
                            &mode
                        );
                        changed += 1;
                    }
                    Err(_) => errors.push(format!("{}: chmod failed", name)),
                }
            }
            Ok(Some(_)) => errors.push(format!("{}: not owner", name)),
            _ => errors.push(format!("{}: not found", name)),
        }
    }

    if changed > 0 && errors.is_empty() {
        AppMessage {
            cmd: Cmd::Chmod,
            data: vec!["ok".to_string()],
        }
    } else if changed > 0 {
        AppMessage {
            cmd: Cmd::Chmod,
            data: vec![format!(
                "{} changed, errors: {}",
                changed,
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

pub async fn chown(data: Vec<String>, session: &Session, pool: &Pool) -> AppMessage {
    if !session.authenticated {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["not authenticated".to_string()],
        };
    }

    let target = data.first().cloned().unwrap_or_default();
    let new_owner = data.get(1).cloned().unwrap_or_default();

    if !is_valid_name(&target) {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["invalid target name".to_string()],
        };
    }
    if !is_valid_user_group_name(&new_owner) {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["invalid owner name".to_string()],
        };
    }

    match dao::get_user(pool, new_owner.clone()).await {
        Ok(None) => AppMessage {
            cmd: Cmd::Failure,
            data: vec!["user not found".to_string()],
        },
        Err(_) => AppMessage {
            cmd: Cmd::Failure,
            data: vec!["database error".to_string()],
        },
        Ok(Some(_)) => {
            let path = format!("{}/{}", session.current_path, target);
            match dao::get_f_node(pool, path.clone()).await {
                Ok(Some(node)) if is_owner(&node, session.current_user.as_ref()) => {
                    match dao::change_owner(pool, path, new_owner.clone()).await {
                        Ok(_) => AppMessage {
                            cmd: Cmd::Chown,
                            data: vec![format!("owner changed to {}", new_owner)],
                        },
                        Err(_) => AppMessage {
                            cmd: Cmd::Failure,
                            data: vec!["chown failed".to_string()],
                        },
                    }
                }
                Ok(Some(_)) => AppMessage {
                    cmd: Cmd::Failure,
                    data: vec!["not owner".to_string()],
                },
                _ => AppMessage {
                    cmd: Cmd::Failure,
                    data: vec!["file not found".to_string()],
                },
            }
        }
    }
}

pub async fn chgrp(data: Vec<String>, session: &Session, pool: &Pool) -> AppMessage {
    if !session.authenticated {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["not authenticated".to_string()],
        };
    }

    let target = data.first().cloned().unwrap_or_default();
    let new_group = data.get(1).cloned().unwrap_or_default();

    if !is_valid_name(&target) {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["invalid target name".to_string()],
        };
    }
    if !is_valid_user_group_name(&new_group) {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["invalid group name".to_string()],
        };
    }

    match dao::get_group(pool, new_group.clone()).await {
        Ok(None) => AppMessage {
            cmd: Cmd::Failure,
            data: vec!["group not found".to_string()],
        },
        Err(_) => AppMessage {
            cmd: Cmd::Failure,
            data: vec!["database error".to_string()],
        },
        Ok(Some(_)) => {
            let path = format!("{}/{}", session.current_path, target);
            match dao::get_f_node(pool, path.clone()).await {
                Ok(Some(node)) if is_owner(&node, session.current_user.as_ref()) => {
                    match dao::change_file_group(pool, path.clone(), new_group.clone()).await {
                        Ok(_) => {
                            info!("chgrp: {} -> {} for {}", node.owner, new_group, path);
                            AppMessage {
                                cmd: Cmd::Chgrp,
                                data: vec![format!("group changed to {}", new_group)],
                            }
                        }
                        Err(_) => AppMessage {
                            cmd: Cmd::Failure,
                            data: vec!["chgrp failed".to_string()],
                        },
                    }
                }
                Ok(Some(_)) => AppMessage {
                    cmd: Cmd::Failure,
                    data: vec!["not owner".to_string()],
                },
                _ => AppMessage {
                    cmd: Cmd::Failure,
                    data: vec!["file not found".to_string()],
                },
            }
        }
    }
}

pub async fn scan(data: Vec<String>, session: &Session, pool: &Pool) -> AppMessage {
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

    let file_path = format!("{}/{}", session.current_path, file_name);
    match dao::get_f_node(pool, file_path.clone()).await {
        Ok(Some(node)) if node.dir => AppMessage {
            cmd: Cmd::Failure,
            data: vec!["cannot scan directory".to_string()],
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
                let target_path = format!("storage{}/{}", session.current_path, file_name);
                match fs::read(&target_path).await {
                    Ok(encrypted) => match decrypt_file_content(&encrypted) {
                        Ok(content) => {
                            let new_hash = hash_content(&content);
                            if new_hash == node.hash {
                                AppMessage {
                                    cmd: Cmd::Scan,
                                    data: vec![format!("Ensured integrity of {}!", file_name)],
                                }
                            } else {
                                AppMessage {
                                    cmd: Cmd::Failure,
                                    data: vec![format!(
                                        "Integrity of file {} compromised!",
                                        file_name
                                    )],
                                }
                            }
                        }
                        Err(_) => AppMessage {
                            cmd: Cmd::Failure,
                            data: vec!["scan failed: decryption error".to_string()],
                        },
                    },
                    Err(_) => AppMessage {
                        cmd: Cmd::Failure,
                        data: vec!["scan failed: file not found".to_string()],
                    },
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
            data: vec!["no read permission".to_string()],
        },
    }
}

pub async fn get_encrypted_file(data: Vec<String>, session: &Session, pool: &Pool) -> AppMessage {
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

    let file_path = format!("{}/{}", session.current_path, file_name);
    match dao::get_f_node(pool, file_path).await {
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
                let path_parts: Vec<String> = session
                    .current_path
                    .split('/')
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .collect();
                let mut result = vec!["/".to_string()];
                result.extend(path_parts);
                result.push(node.encrypted_name);
                AppMessage {
                    cmd: Cmd::GetEncryptedFile,
                    data: result,
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
            data: vec!["file not found".to_string()],
        },
    }
}
