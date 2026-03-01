use deadpool_postgres::Pool;
use securefs_model::protocol::{AppMessage, Cmd, FNode};

use securefs_server::dao;

use crate::session::Session;
use crate::util::{current_timestamp, is_valid_password};

pub fn whoami(session: &Session) -> AppMessage {
    if !session.authenticated {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["not authenticated".into()],
        };
    }
    let user = session.current_user.clone().unwrap_or_default();
    let group = session
        .current_user_group
        .clone()
        .unwrap_or_else(|| "(none)".into());
    AppMessage {
        cmd: Cmd::Whoami,
        data: vec![user, group],
    }
}

pub async fn ls_users(session: &Session, pool: &Pool) -> AppMessage {
    if let Some(user) = &session.current_user {
        match dao::is_admin(pool, user.clone()).await {
            Ok(true) => match dao::get_all_users(pool).await {
                Ok(users) => AppMessage {
                    cmd: Cmd::LsUsers,
                    data: users,
                },
                Err(_) => AppMessage {
                    cmd: Cmd::Failure,
                    data: vec!["failed to list users".to_string()],
                },
            },
            _ => AppMessage {
                cmd: Cmd::Failure,
                data: vec!["admin privileges required".to_string()],
            },
        }
    } else {
        AppMessage {
            cmd: Cmd::Failure,
            data: vec!["not authenticated".to_string()],
        }
    }
}

pub async fn ls_groups(session: &Session, pool: &Pool) -> AppMessage {
    if let Some(user) = &session.current_user {
        match dao::is_admin(pool, user.clone()).await {
            Ok(true) => match dao::get_all_groups(pool).await {
                Ok(groups) => AppMessage {
                    cmd: Cmd::LsGroups,
                    data: groups,
                },
                Err(_) => AppMessage {
                    cmd: Cmd::Failure,
                    data: vec!["failed to list groups".to_string()],
                },
            },
            _ => AppMessage {
                cmd: Cmd::Failure,
                data: vec!["admin privileges required".to_string()],
            },
        }
    } else {
        AppMessage {
            cmd: Cmd::Failure,
            data: vec!["not authenticated".to_string()],
        }
    }
}

pub async fn new_user(data: Vec<String>, session: &Session, pool: &Pool) -> AppMessage {
    if !session.authenticated {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["not authenticated".to_string()],
        };
    }

    let user_name = data.first().cloned().unwrap_or_default();
    let pass = data.get(1).cloned().unwrap_or_default();
    let group = data.get(2).cloned().unwrap_or_default();

    if user_name.is_empty() || pass.is_empty() || group.is_empty() {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["missing user data".to_string()],
        };
    }
    if !is_valid_password(&pass) {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["password must be at least 8 characters".to_string()],
        };
    }

    let exists = dao::get_user(pool, user_name.clone())
        .await
        .ok()
        .flatten()
        .is_some();
    if exists {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["user already exists".to_string()],
        };
    }

    let group_exists = dao::get_group(pool, group.clone())
        .await
        .ok()
        .flatten()
        .is_some();
    if !group_exists {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["group does not exist".to_string()],
        };
    }

    match dao::create_user(pool, user_name.clone(), pass, Some(group.clone()), false).await {
        Ok(_) => {
            let user_home = format!("/home/{}", user_name);
            let now = current_timestamp();
            let new_dir = FNode {
                id: -1,
                name: user_name.clone(),
                path: user_home.clone(),
                owner: user_name.clone(),
                hash: "".to_string(),
                parent: "/home".to_string(),
                dir: true,
                u: 7,
                g: 7,
                o: 0,
                children: vec![],
                encrypted_name: user_name.clone(),
                size: 0,
                created_at: now,
                modified_at: now,
                file_group: Some(group.clone()),
            };
            let _ = dao::add_file(pool, new_dir).await;
            let _ = dao::add_file_to_parent(pool, "/home".to_string(), user_name.clone()).await;
            AppMessage {
                cmd: Cmd::NewUser,
                data: vec![user_home],
            }
        }
        Err(_) => AppMessage {
            cmd: Cmd::Failure,
            data: vec!["failed to create user".to_string()],
        },
    }
}

pub async fn new_group(data: Vec<String>, session: &Session, pool: &Pool) -> AppMessage {
    if !session.authenticated {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["not authenticated".to_string()],
        };
    }

    let group_name = data.first().cloned().unwrap_or_default();
    if group_name.is_empty() {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["missing group name".to_string()],
        };
    }

    let exists = dao::get_group(pool, group_name.clone())
        .await
        .ok()
        .flatten()
        .is_some();
    if exists {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["group already exists".to_string()],
        };
    }

    match dao::create_group(pool, group_name.clone()).await {
        Ok(_) => AppMessage {
            cmd: Cmd::NewGroup,
            data: vec![group_name],
        },
        Err(_) => AppMessage {
            cmd: Cmd::Failure,
            data: vec!["failed to create group".to_string()],
        },
    }
}

pub async fn add_user_to_group(data: Vec<String>, session: &Session, pool: &Pool) -> AppMessage {
    if let Some(user) = &session.current_user {
        match dao::is_admin(pool, user.clone()).await {
            Ok(true) => {
                let user_name = data.first().cloned().unwrap_or_default();
                let group_name = data.get(1).cloned().unwrap_or_default();
                if user_name.is_empty() || group_name.is_empty() {
                    AppMessage {
                        cmd: Cmd::Failure,
                        data: vec!["missing arguments".to_string()],
                    }
                } else {
                    match dao::add_user_to_group(pool, user_name.clone(), group_name.clone()).await
                    {
                        Ok(_) => AppMessage {
                            cmd: Cmd::AddUserToGroup,
                            data: vec![format!("User {} added to group {}", user_name, group_name)],
                        },
                        Err(e) => AppMessage {
                            cmd: Cmd::Failure,
                            data: vec![e.to_string()],
                        },
                    }
                }
            }
            _ => AppMessage {
                cmd: Cmd::Failure,
                data: vec!["admin privileges required".to_string()],
            },
        }
    } else {
        AppMessage {
            cmd: Cmd::Failure,
            data: vec!["not authenticated".to_string()],
        }
    }
}

pub async fn remove_user_from_group(
    data: Vec<String>,
    session: &Session,
    pool: &Pool,
) -> AppMessage {
    if let Some(user) = &session.current_user {
        match dao::is_admin(pool, user.clone()).await {
            Ok(true) => {
                let user_name = data.first().cloned().unwrap_or_default();
                let group_name = data.get(1).cloned().unwrap_or_default();
                if user_name.is_empty() || group_name.is_empty() {
                    AppMessage {
                        cmd: Cmd::Failure,
                        data: vec!["missing arguments".to_string()],
                    }
                } else {
                    match dao::remove_user_from_group(pool, user_name.clone(), group_name.clone())
                        .await
                    {
                        Ok(_) => AppMessage {
                            cmd: Cmd::RemoveUserFromGroup,
                            data: vec![format!(
                                "User {} removed from group {}",
                                user_name, group_name
                            )],
                        },
                        Err(e) => AppMessage {
                            cmd: Cmd::Failure,
                            data: vec![e.to_string()],
                        },
                    }
                }
            }
            _ => AppMessage {
                cmd: Cmd::Failure,
                data: vec!["admin privileges required".to_string()],
            },
        }
    } else {
        AppMessage {
            cmd: Cmd::Failure,
            data: vec!["not authenticated".to_string()],
        }
    }
}
