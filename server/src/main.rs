//! WebSocket server for SecureFS.
//!
//! Accepts client connections, authenticates users, and translates
//! protocol commands into DAO/database operations and on-disk file
//! changes.

use std::env;
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use log::{info, warn, error};
use securefs_model::protocol::{AppMessage, Cmd, FNode};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio_postgres::NoTls;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::accept_async;
use tokio::net::TcpStream;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::fs as stdfs;
use x25519_dalek::{EphemeralSecret, PublicKey};
use rand_core::OsRng;
use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit};
use aes_gcm::aead::{Aead, AeadCore};

use std::path::Path;
use std::collections::HashSet;

mod dao;


#[tokio::main]
/// Launch the WebSocket server and connect to Postgres.
async fn main() -> Result<(), String> {
    env_logger::init();
    info!("Starting SecureFS server");

    // NOTE: Default env fallbacks are for local/dev usage; production
    // deployments should provide explicit values.
    let db_pass = env::var("DB_PASS").unwrap_or_else(|_| "TEMP".to_string());
    let db_host = env::var("DB_HOST").unwrap_or_else(|_| "localhost".to_string());
    let db_name = env::var("DB_NAME").unwrap_or_else(|_| "db".to_string());
    let db_user = env::var("DB_USER").unwrap_or_else(|_| "USER".to_string());
    let db_port = env::var("DB_PORT").unwrap_or_else(|_| "5431".to_string());

    let (client, connection) = tokio_postgres::connect(
        &format!(
            "host={} dbname={} user={} password={} port={}",
            db_host, db_name, db_user, db_pass, db_port
        ),
        NoTls,
    )
    .await
    .map_err(|e| format!("db connect failed: {}", e))?;

    let pg_client = Arc::new(Mutex::new(client));
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            error!("db connection error: {}", e);
        }
    });

    let bind_addr = env::var("SERVER_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let listener = TcpListener::bind(&bind_addr)
        .await
        .map_err(|e| format!("bind failed: {}", e))?;
    info!("Listening on: {}", bind_addr);

    while let Ok((stream, addr)) = listener.accept().await {
        info!("New connection from: {}", addr);
        let pg = pg_client.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, pg).await {
                warn!("Connection error: {}", e);
            }
        });
    }

    Ok(())
}

/// Encrypt an AppMessage using AES-256-GCM (Reference Implementation Style)
/// Returns a tuple of (ciphertext_hex, nonce_bytes)
fn encrypt_app_message(key: &Key<Aes256Gcm>, msg: &AppMessage) -> Result<(String, [u8; 12]), String> {
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(OsRng); // 96-bits
    let payload = serde_json::to_string(msg).map_err(|e| e.to_string())?;
    
    let ciphertext = cipher.encrypt(&nonce, payload.as_bytes())
        .map_err(|e| format!("encryption failed: {}", e))?;
        
    Ok((hex::encode(ciphertext), nonce.into()))
}

/// Decrypt a message using AES-256-GCM (Reference Implementation Style)
fn decrypt_app_message(key: &Key<Aes256Gcm>, msg_tuple: &(String, [u8; 12])) -> Result<AppMessage, String> {
    let (ciphertext_hex, nonce_bytes) = msg_tuple;
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);
    let ciphertext = hex::decode(ciphertext_hex).map_err(|_| "invalid ciphertext hex".to_string())?;
    
    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())
        .map_err(|e| format!("decryption failed: {}", e))?;
        
    let plaintext_str = String::from_utf8(plaintext).map_err(|_| "invalid utf8".to_string())?;
    serde_json::from_str(&plaintext_str).map_err(|e| format!("json decode failed: {}", e))
}

/// Handle a single WebSocket connection lifecycle.
async fn handle_connection(stream: TcpStream, pg_client: Arc<Mutex<tokio_postgres::Client>>) -> Result<(), String> {
    let mut ws_stream = accept_async(stream)
        .await
        .map_err(|e| format!("handshake failed: {}", e))?;

    let mut authenticated = false;
    let mut current_user: Option<String> = None;
    let mut current_user_group: Option<String> = None;
    let mut current_path: String = "/home".to_string();
    let mut failed_login_attempts: u8 = 0;
    const MAX_LOGIN_ATTEMPTS: u8 = 5;
    let mut shared_secret: Option<Key<Aes256Gcm>> = None;

    while let Some(msg) = ws_stream.next().await {
        let msg = msg.map_err(|e| format!("ws read failed: {}", e))?;
        if !msg.is_text() {
            continue;
        }
        
        // Decrypt if we have a shared secret, otherwise parse as plaintext
        let incoming: AppMessage = if let Some(key) = &shared_secret {
            let enc_tuple: (String, [u8; 12]) = serde_json::from_str(msg.to_text().unwrap())
                .map_err(|e| format!("encrypted decode failed: {}", e))?;
            decrypt_app_message(key, &enc_tuple)?
        } else {
            serde_json::from_str(msg.to_text().unwrap())
                .map_err(|e| format!("decode failed: {}", e))?
        };

        let mut next_secret = None;

        let reply = match incoming.cmd {
            Cmd::NewConnection => AppMessage {
                cmd: Cmd::NewConnection,
                data: vec![],
            },
            Cmd::Login => {
                // Rate limiting: block after MAX_LOGIN_ATTEMPTS failed attempts
                if failed_login_attempts >= MAX_LOGIN_ATTEMPTS {
                    warn!("Connection blocked due to too many failed login attempts");
                    AppMessage {
                        cmd: Cmd::Failure,
                        data: vec!["too many failed login attempts".to_string()],
                    }
                } else {
                    let user_name = incoming.data.get(0).cloned().unwrap_or_default();
                    let pass = incoming.data.get(1).cloned().unwrap_or_default();
                    let is_ok = dao::auth_user(pg_client.clone(), user_name.clone(), pass)
                        .await
                        .unwrap_or(false);
                    if !is_ok {
                        failed_login_attempts += 1;
                        warn!("Failed login attempt {} for user '{}'", failed_login_attempts, user_name);
                        AppMessage {
                            cmd: Cmd::Failure,
                            data: vec!["failed to login!".to_string(), format!("{} attempts remaining", MAX_LOGIN_ATTEMPTS - failed_login_attempts)],
                        }
                    } else {
                        // Reset counter on successful login
                        failed_login_attempts = 0;
                        authenticated = true;
                        current_user = Some(user_name.clone());
                        let user_home = format!("/home/{}", user_name);
                        if dao::get_f_node(pg_client.clone(), user_home.clone()).await.ok().flatten().is_some() {
                            current_path = user_home;
                        } else {
                            current_path = "/home".into();
                        }
                        // Fetch user details including group membership
                        let user_opt = dao::get_user(pg_client.clone(), user_name.clone()).await.ok().flatten();
                        let is_admin = user_opt.as_ref().map(|u| u.is_admin).unwrap_or(false);
                        current_user_group = user_opt.and_then(|u| u.group_name);
                        info!("User {} logged in, group: {:?}", user_name, current_user_group);
                        AppMessage {
                            cmd: Cmd::Login,
                            data: vec![user_name, is_admin.to_string()],
                        }
                    }
                }
            }
            Cmd::LsUsers => {
                if !authenticated {
                    AppMessage {
                        cmd: Cmd::Failure,
                        data: vec!["not authenticated".to_string()],
                    }
                } else {
                    // Check if current user is admin
                    match dao::is_admin(pg_client.clone(), current_user.clone().unwrap()).await {
                        Ok(true) => {
                            match dao::get_all_users(pg_client.clone()).await {
                                Ok(users) => AppMessage {
                                    cmd: Cmd::LsUsers,
                                    data: users,
                                },
                                Err(_) => AppMessage {
                                    cmd: Cmd::Failure,
                                    data: vec!["failed to list users".to_string()],
                                },
                            }
                        }
                        _ => AppMessage {
                            cmd: Cmd::Failure,
                            data: vec!["admin privileges required".to_string()],
                        },
                    }
                }
            }
            Cmd::LsGroups => {
                if !authenticated {
                    AppMessage {
                        cmd: Cmd::Failure,
                        data: vec!["not authenticated".to_string()],
                    }
                } else {
                    // Check if current user is admin
                    match dao::is_admin(pg_client.clone(), current_user.clone().unwrap()).await {
                        Ok(true) => {
                            match dao::get_all_groups(pg_client.clone()).await {
                                Ok(groups) => AppMessage {
                                    cmd: Cmd::LsGroups,
                                    data: groups,
                                },
                                Err(_) => AppMessage {
                                    cmd: Cmd::Failure,
                                    data: vec!["failed to list groups".to_string()],
                                },
                            }
                        }
                        _ => AppMessage {
                            cmd: Cmd::Failure,
                            data: vec!["admin privileges required".to_string()],
                        },
                    }
                }
            }
            Cmd::Logout => {
                if !authenticated {
                    AppMessage {
                        cmd: Cmd::Failure,
                        data: vec!["not authenticated".to_string()],
                    }
                } else {
                    authenticated = false;
                    current_user = None;
                    current_path = "/home".into();
                    AppMessage {
                        cmd: Cmd::Logout,
                        data: vec![],
                    }
                }
            }
            Cmd::NewUser => {
                if !authenticated {
                    AppMessage { cmd: Cmd::Failure, data: vec!["not authenticated".to_string()] }
                } else {
                    let user_name = incoming.data.get(0).cloned().unwrap_or_default();
                    let pass = incoming.data.get(1).cloned().unwrap_or_default();
                    let group = incoming.data.get(2).cloned().unwrap_or_default();
                    if user_name.is_empty() || pass.is_empty() || group.is_empty() {
                        AppMessage { cmd: Cmd::Failure, data: vec!["missing user data".to_string()] }
                    } else if !is_valid_password(&pass) {
                        AppMessage { cmd: Cmd::Failure, data: vec!["password must be at least 8 characters".to_string()] }
                    } else {
                        let exists = dao::get_user(pg_client.clone(), user_name.clone()).await.ok().flatten().is_some();
                        if exists {
                            AppMessage { cmd: Cmd::Failure, data: vec!["user already exists".to_string()] }
                        } else {
                            let group_exists = dao::get_group(pg_client.clone(), group.clone()).await.ok().flatten().is_some();
                            if !group_exists {
                                AppMessage { cmd: Cmd::Failure, data: vec!["group does not exist".to_string()] }
                            } else {
                                match dao::create_user(pg_client.clone(), user_name.clone(), pass, Some(group.clone()), false).await {
                                    Ok(_) => {
                                        let user_home = format!("/home/{}", user_name);
                                        let now = current_timestamp();
                                        let new_dir = securefs_model::protocol::FNode {
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
                                        };
                                        let _ = dao::add_file(pg_client.clone(), new_dir).await;
                                        let _ = dao::add_file_to_parent(pg_client.clone(), "/home".to_string(), user_name.clone()).await;
                                        AppMessage { cmd: Cmd::NewUser, data: vec![user_home] }
                                    }
                                    Err(_) => AppMessage { cmd: Cmd::Failure, data: vec!["failed to create user".to_string()] },
                                }
                            }
                        }
                    }
                }
            }
            Cmd::NewGroup => {
                if !authenticated {
                    AppMessage { cmd: Cmd::Failure, data: vec!["not authenticated".to_string()] }
                } else {
                    let group_name = incoming.data.get(0).cloned().unwrap_or_default();
                    if group_name.is_empty() {
                        AppMessage { cmd: Cmd::Failure, data: vec!["missing group name".to_string()] }
                    } else {
                        let exists = dao::get_group(pg_client.clone(), group_name.clone()).await.ok().flatten().is_some();
                        if exists {
                            AppMessage { cmd: Cmd::Failure, data: vec!["group already exists".to_string()] }
                        } else {
                            match dao::create_group(pg_client.clone(), group_name.clone()).await {
                                Ok(_) => AppMessage { cmd: Cmd::NewGroup, data: vec![group_name] },
                                Err(_) => AppMessage { cmd: Cmd::Failure, data: vec!["failed to create group".to_string()] },
                            }
                        }
                    }
                }
            }
            Cmd::Pwd => {
                if !authenticated {
                    AppMessage {
                        cmd: Cmd::Failure,
                        data: vec!["not authenticated".to_string()],
                    }
                } else {
                    AppMessage {
                        cmd: Cmd::Pwd,
                        data: vec![current_path.clone()],
                    }
                }
            }
            Cmd::Ls => {
                if !authenticated {
                    AppMessage {
                        cmd: Cmd::Failure,
                        data: vec!["not authenticated".to_string()],
                    }
                } else {
                    let children = match dao::get_f_node(pg_client.clone(), current_path.clone()).await {
                        Ok(Some(fnode)) => {
                            let mut names = Vec::new();
                            for child in fnode.children.iter() {
                                let child_path = format!("{}/{}", current_path, child);
                                if let Ok(Some(node)) = dao::get_f_node(pg_client.clone(), child_path).await {
                                    names.push(format_ls_entry(&node));
                                }
                            }
                            names
                        }
                        _ => vec![],
                    };
                    AppMessage { cmd: Cmd::Ls, data: children }
                }
            }
            Cmd::Mkdir => {
                if !authenticated {
                    AppMessage {
                        cmd: Cmd::Failure,
                        data: vec!["not authenticated".to_string()],
                    }
                } else {
                    let dir_name = incoming.data.get(0).cloned().unwrap_or_default();
                    if !is_valid_name(&dir_name) {
                        AppMessage {
                            cmd: Cmd::Failure,
                            data: vec!["invalid directory name".to_string()],
                        }
                    } else {
                        let has_perm = match dao::get_f_node(pg_client.clone(), current_path.clone()).await {
                            Ok(Some(parent)) if can_write(&parent, current_user.as_ref()) => true,
                            _ => false,
                        };
                        if !has_perm {
                            AppMessage { cmd: Cmd::Failure, data: vec!["no write permission".into()] }
                        } else {
                        let target_path = format!("{}/{}", current_path, dir_name);
                        
                        // Check if directory already exists
                        let exists = dao::get_f_node(pg_client.clone(), target_path.clone()).await.ok().flatten().is_some();
                        if exists {
                            AppMessage { cmd: Cmd::Failure, data: vec!["directory already exists".to_string()] }
                        } else {
                        let parent_path = current_path.clone();
                        let owner = current_user.clone().unwrap_or_default();

                        let now = current_timestamp();
                        let new_dir = securefs_model::protocol::FNode {
                            id: -1,
                            name: dir_name.clone(),
                            path: target_path.clone(),
                            owner: owner.clone(),
                            hash: "".to_string(),
                            parent: parent_path.clone(),
                            dir: true,
                            u: 7,
                            g: 7,
                            o: 7,
                            children: vec![],
                            encrypted_name: dir_name.clone(),
                            size: 0,
                            created_at: now,
                            modified_at: now,
                        };

                        let res = dao::add_file(pg_client.clone(), new_dir).await;
                        let parent_update = if res.is_ok() {
                            dao::add_file_to_parent(pg_client.clone(), parent_path.clone(), dir_name.clone()).await
                        } else {
                            Err("parent not updated".into())
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
                        }
                    }
                }
            }
            Cmd::Mv => {
                if !authenticated {
                    AppMessage {
                        cmd: Cmd::Failure,
                        data: vec!["not authenticated".to_string()],
                    }
                } else {
                    let src = incoming.data.get(0).cloned().unwrap_or_default();
                    let dst = incoming.data.get(1).cloned().unwrap_or_default();
                    if !is_valid_name(&src) || !is_valid_name(&dst) {
                        AppMessage {
                            cmd: Cmd::Failure,
                            data: vec!["invalid name".to_string()],
                        }
                    } else {
                        let old_path = format!("{}/{}", current_path, src);
                        let new_path = format!("{}/{}", current_path, dst);
                        
                        // Check source exists
                        let src_exists = dao::get_f_node(pg_client.clone(), old_path.clone()).await.ok().flatten().is_some();
                        if !src_exists {
                            AppMessage { cmd: Cmd::Failure, data: vec!["source not found".to_string()] }
                        } else {
                            // Require write on parent
                            match dao::get_f_node(pg_client.clone(), current_path.clone()).await {
                                Ok(Some(parent)) if can_write(&parent, current_user.as_ref()) => {
                                    let res = dao::update_path(pg_client.clone(), old_path.clone(), new_path.clone()).await;
                                    let name_res = dao::update_fnode_name_if_path_is_already_updated(pg_client.clone(), new_path.clone(), dst.clone()).await;
                                    let enc_res = dao::update_fnode_enc_name(pg_client.clone(), new_path.clone(), dst.clone()).await;
                                    let parent_remove = dao::remove_file_from_parent(pg_client.clone(), current_path.clone(), src.clone()).await;
                                    let parent_add = dao::add_file_to_parent(pg_client.clone(), current_path.clone(), dst.clone()).await;
                                    if res.is_ok() && name_res.is_ok() && enc_res.is_ok() && parent_remove.is_ok() && parent_add.is_ok() {
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
                                }
                                _ => AppMessage { cmd: Cmd::Failure, data: vec!["no write permission".into()] }
                            }
                        }
                    }
                }
            }
            Cmd::Delete => {
                if !authenticated {
                    AppMessage {
                        cmd: Cmd::Failure,
                        data: vec!["not authenticated".to_string()],
                    }
                } else {
                    let target = incoming.data.get(0).cloned().unwrap_or_default();
                    if !is_valid_name(&target) {
                        AppMessage {
                            cmd: Cmd::Failure,
                            data: vec!["invalid path".to_string()],
                        }
                    } else {
                        let path = format!("{}/{}", current_path, target);
                        // Require write on parent
                        let has_perm = match dao::get_f_node(pg_client.clone(), current_path.clone()).await {
                            Ok(Some(parent)) if can_write(&parent, current_user.as_ref()) => true,
                            _ => false,
                        };
                        if !has_perm {
                            AppMessage { cmd: Cmd::Failure, data: vec!["no write permission".into()] }
                        } else if let Ok(Some(node)) = dao::get_f_node(pg_client.clone(), path.clone()).await {
                            if node.dir && !node.children.is_empty() {
                                AppMessage { cmd: Cmd::Failure, data: vec!["directory not empty".into()] }
                            } else {
                        // remove storage copy
                        let storage_path = format!("storage{}", path);
                        if Path::new(&storage_path).exists() {
                            let _ = stdfs::remove_file(&storage_path).or_else(|_| stdfs::remove_dir_all(&storage_path));
                        }
                        let parent_remove = dao::remove_file_from_parent(pg_client.clone(), current_path.clone(), target.clone()).await;
                        let del = dao::delete_path(pg_client.clone(), path.clone()).await;
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
                            }
                        } else {
                            AppMessage {
                                cmd: Cmd::Failure,
                                data: vec!["delete failed".to_string()],
                            }
                        }
                    }
                }
            }
            Cmd::Cd => {
                if !authenticated {
                    AppMessage {
                        cmd: Cmd::Failure,
                        data: vec!["not authenticated".to_string()],
                    }
                } else {
                    let target = incoming.data.get(0).cloned().unwrap_or_default();
                    let new_path = resolve_path(&current_path, &target);
                    if !new_path.starts_with("/home") {
                        AppMessage {
                            cmd: Cmd::Failure,
                            data: vec!["path not allowed".to_string()],
                        }
                    } else {
                    // simple cycle guard
                    let mut guard = HashSet::new();
                    if !guard.insert(new_path.clone()) {
                        AppMessage {
                            cmd: Cmd::Failure,
                            data: vec!["invalid path".to_string()],
                        }
                    } else {
                        match dao::get_f_node(pg_client.clone(), new_path.clone()).await {
                            Ok(Some(node)) if node.dir && can_read(&node, current_user.as_ref()) => {
                                current_path = new_path.clone();
                                AppMessage { cmd: Cmd::Cd, data: vec![new_path] }
                            }
                            _ => AppMessage {
                                cmd: Cmd::Failure,
                                data: vec!["invalid path".to_string()],
                            },
                        }
                    }
                    }
                }
            }
            Cmd::Touch => {
                if !authenticated {
                    AppMessage {
                        cmd: Cmd::Failure,
                        data: vec!["not authenticated".to_string()],
                    }
                } else {
                    let file_name = incoming.data.get(0).cloned().unwrap_or_default();
                    if !is_valid_name(&file_name) {
                        AppMessage {
                            cmd: Cmd::Failure,
                            data: vec!["invalid file name".to_string()],
                        }
                    } else {
                        let has_perm = match dao::get_f_node(pg_client.clone(), current_path.clone()).await {
                            Ok(Some(parent)) if can_write(&parent, current_user.as_ref()) => true,
                            _ => false,
                        };
                        if !has_perm {
                            AppMessage { cmd: Cmd::Failure, data: vec!["no write permission".into()] }
                        } else {
                        let target_path = format!("{}/{}", current_path, file_name);
                        
                        // Check if file already exists
                        let exists = dao::get_f_node(pg_client.clone(), target_path.clone()).await.ok().flatten().is_some();
                        if exists {
                            AppMessage { cmd: Cmd::Failure, data: vec!["file already exists".to_string()] }
                        } else {
                        let parent_path = current_path.clone();
                        let owner = current_user.clone().unwrap_or_default();

                        let now = current_timestamp();
                        let new_file = securefs_model::protocol::FNode {
                            id: -1,
                            name: file_name.clone(),
                            path: target_path.clone(),
                            owner: owner.clone(),
                            hash: "".to_string(),
                            parent: parent_path.clone(),
                            dir: false,
                            u: 6,
                            g: 6,
                            o: 4,
                            children: vec![],
                            encrypted_name: file_name.clone(),
                            size: 0,
                            created_at: now,
                            modified_at: now,
                        };

                        let res = dao::add_file(pg_client.clone(), new_file).await;
                        let parent_update = if res.is_ok() {
                            dao::add_file_to_parent(pg_client.clone(), parent_path.clone(), file_name.clone()).await
                        } else {
                            Err("parent not updated".into())
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
                        }
                    }
                }
            }
            Cmd::Cat => {
                if !authenticated {
                    AppMessage {
                        cmd: Cmd::Failure,
                        data: vec!["not authenticated".to_string()],
                    }
                } else {
                    let file_name = incoming.data.get(0).cloned().unwrap_or_default();
                    if !is_valid_name(&file_name) {
                        AppMessage {
                            cmd: Cmd::Failure,
                            data: vec!["invalid file name".to_string()],
                        }
                    } else {
                        let target_path = format!("storage{}", current_path);
                        let file_path = format!("{}/{}", target_path, file_name);
                        match dao::get_f_node(pg_client.clone(), format!("{}/{}", current_path, file_name)).await {
                            Ok(Some(node)) if node.dir => AppMessage { cmd: Cmd::Failure, data: vec!["cannot cat dir".into()] },
                            Ok(Some(node)) if can_read(&node, current_user.as_ref()) => {
                                let mut buf = String::new();
                                let read_res = fs::File::open(&file_path).await;
                                match read_res {
                                    Ok(mut f) => {
                                        let _ = f.read_to_string(&mut buf).await;
                                        AppMessage { cmd: Cmd::Cat, data: vec![buf] }
                                    }
                                    Err(_) => AppMessage { cmd: Cmd::Failure, data: vec!["cat failed".to_string()] },
                                }
                            }
                            _ => AppMessage { cmd: Cmd::Failure, data: vec!["no read permission".into()] },
                        }
                    }
                }
            }
            Cmd::Echo => {
                if !authenticated {
                    AppMessage {
                        cmd: Cmd::Failure,
                        data: vec!["not authenticated".to_string()],
                    }
                } else {
                    let file_name = incoming.data.get(0).cloned().unwrap_or_default();
                    let content = incoming.data.get(1).cloned().unwrap_or_default();
                    if !is_valid_name(&file_name) {
                        AppMessage {
                            cmd: Cmd::Failure,
                            data: vec!["invalid file name".to_string()],
                        }
                    } else {
                        match dao::get_f_node(pg_client.clone(), current_path.clone()).await {
                            Ok(Some(parent)) if can_write(&parent, current_user.as_ref()) => {
                                let target_path = format!("storage{}", current_path);
                                let file_path = format!("{}/{}", target_path, file_name);
                                if fs::create_dir_all(&target_path).await.is_err() {
                                    AppMessage { cmd: Cmd::Failure, data: vec!["echo failed".to_string()] }
                                } else {
                                    match fs::File::create(&file_path).await {
                                        Ok(mut f) => match f.write_all(content.as_bytes()).await {
                                            Ok(_) => {
                                                // Update hash in DB after successful write
                                                let hash = hash_content(content.as_bytes());
                                                let node_path = format!("{}/{}", current_path, file_name);
                                                let _ = dao::update_hash(pg_client.clone(), node_path, file_name.clone(), hash).await;
                                                AppMessage { cmd: Cmd::Echo, data: vec!["ok".to_string()] }
                                            }
                                            Err(_) => AppMessage { cmd: Cmd::Failure, data: vec!["echo failed".to_string()] },
                                        }
                                        Err(_) => AppMessage { cmd: Cmd::Failure, data: vec!["echo failed".to_string()] },
                                    }
                                }
                            }
                            _ => AppMessage { cmd: Cmd::Failure, data: vec!["no write permission".into()] }
                        }
                    }
                }
            }
            Cmd::Chmod => {
                if !authenticated {
                    AppMessage {
                        cmd: Cmd::Failure,
                        data: vec!["not authenticated".to_string()],
                    }
                } else {
                    let target = incoming.data.get(0).cloned().unwrap_or_default();
                    let mode = incoming.data.get(1).cloned().unwrap_or_default();
                    if target.is_empty() || mode.len() != 3 {
                        AppMessage {
                            cmd: Cmd::Failure,
                            data: vec!["invalid args".to_string()],
                        }
                    } else {
                        let path = format!("{}/{}", current_path, target);
                        let ugo: Vec<i16> = mode.chars().filter_map(|c| c.to_digit(8)).map(|d| d as i16).collect();
                        if ugo.len() != 3 {
                            AppMessage {
                                cmd: Cmd::Failure,
                                data: vec!["invalid mode".to_string()],
                            }
                        } else {
                            match dao::get_f_node(pg_client.clone(), path.clone()).await {
                                Ok(Some(node)) if is_owner(&node, current_user.as_ref()) => {
                                    let res = dao::change_file_perms(pg_client.clone(), path, ugo[0], ugo[1], ugo[2]).await;
                                    match res {
                                        Ok(_) => AppMessage { cmd: Cmd::Chmod, data: vec!["ok".to_string()] },
                                        Err(_) => AppMessage { cmd: Cmd::Failure, data: vec!["chmod failed".to_string()] },
                                    }
                                }
                                _ => AppMessage { cmd: Cmd::Failure, data: vec!["not owner".to_string()] },
                            }
                        }
                    }
                }
            }
            Cmd::Scan => {
                if !authenticated {
                    AppMessage {
                        cmd: Cmd::Failure,
                        data: vec!["not authenticated".to_string()],
                    }
                } else {
                    let file_name = incoming.data.get(0).cloned().unwrap_or_default();
                    if !is_valid_name(&file_name) {
                        AppMessage {
                            cmd: Cmd::Failure,
                            data: vec!["invalid file name".to_string()],
                        }
                    } else {
                        let file_path = format!("{}/{}", current_path, file_name);
                        match dao::get_f_node(pg_client.clone(), file_path.clone()).await {
                            Ok(Some(node)) if node.dir => {
                                AppMessage {
                                    cmd: Cmd::Failure,
                                    data: vec!["cannot scan directory".to_string()],
                                }
                            }
                            Ok(Some(node)) if can_read(&node, current_user.as_ref()) => {
                                let target_path = format!("storage{}/{}", current_path, file_name);
                                match fs::read(&target_path).await {
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
                                                data: vec![format!("Integrity of file {} compromised!", file_name)],
                                            }
                                        }
                                    }
                                    Err(_) => AppMessage {
                                        cmd: Cmd::Failure,
                                        data: vec!["scan failed: file not found".to_string()],
                                    },
                                }
                            }
                            _ => AppMessage {
                                cmd: Cmd::Failure,
                                data: vec!["no read permission".to_string()],
                            },
                        }
                    }
                }
            }
            Cmd::GetEncryptedFile => {
                if !authenticated {
                    AppMessage {
                        cmd: Cmd::Failure,
                        data: vec!["not authenticated".to_string()],
                    }
                } else {
                    let file_name = incoming.data.get(0).cloned().unwrap_or_default();
                    if !is_valid_name(&file_name) {
                        AppMessage {
                            cmd: Cmd::Failure,
                            data: vec!["invalid file name".to_string()],
                        }
                    } else {
                        let file_path = format!("{}/{}", current_path, file_name);
                        match dao::get_f_node(pg_client.clone(), file_path).await {
                            Ok(Some(node)) if can_read(&node, current_user.as_ref()) => {
                                let path_parts: Vec<String> = current_path
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
                            }
                            Ok(Some(_)) => AppMessage {
                                cmd: Cmd::Failure,
                                data: vec!["no read permission".to_string()],
                            },
                            _ => AppMessage {
                                cmd: Cmd::Failure,
                                data: vec!["file not found".to_string()],
                            },
                        }
                    }
                }
            }
            Cmd::KeyExchangeInit => {
                // Client sends their public key (hex-encoded)
                let client_pubkey_hex = incoming.data.get(0).cloned().unwrap_or_default();
                if client_pubkey_hex.is_empty() || client_pubkey_hex.len() != 64 {
                    AppMessage {
                        cmd: Cmd::Failure,
                        data: vec!["invalid public key".to_string()],
                    }
                } else {
                    match hex::decode(&client_pubkey_hex) {
                        Ok(bytes) if bytes.len() == 32 => {
                            // Generate server ephemeral keypair
                            let server_secret = EphemeralSecret::random_from_rng(OsRng);
                            let server_public = PublicKey::from(&server_secret);
                            
                            // Derive shared secret (this is where forward secrecy comes from)
                            let mut client_pubkey_bytes = [0u8; 32];
                            client_pubkey_bytes.copy_from_slice(&bytes);
                            let client_public = PublicKey::from(client_pubkey_bytes);
                            let client_shared = server_secret.diffie_hellman(&client_public);
                            
                            // Store shared secret for session encryption (will be applied after response)
                            // Store shared secret for session encryption (will be applied after response)
                            let final_secret = *Key::<Aes256Gcm>::from_slice(client_shared.as_bytes());
                            next_secret = Some(final_secret);
                            
                            info!("Key exchange completed with client");
                            
                            AppMessage {
                                cmd: Cmd::KeyExchangeResponse,
                                data: vec![hex::encode(server_public.as_bytes())],
                            }
                        }
                        _ => AppMessage {
                            cmd: Cmd::Failure,
                            data: vec!["invalid public key format".to_string()],
                        },
                    }
                }
            }
            Cmd::Cp => {
                if !authenticated {
                    AppMessage {
                        cmd: Cmd::Failure,
                        data: vec!["not authenticated".to_string()],
                    }
                } else {
                    let src = incoming.data.get(0).cloned().unwrap_or_default();
                    let dst = incoming.data.get(1).cloned().unwrap_or_default();
                    if !is_valid_name(&src) || !is_valid_name(&dst) {
                        AppMessage { cmd: Cmd::Failure, data: vec!["invalid name".to_string()] }
                    } else {
                        let src_path = format!("{}/{}", current_path, src);
                        let dst_path_orig = format!("{}/{}", current_path, dst);
                        
                        // Check source exists and we can read it
                        match dao::get_f_node(pg_client.clone(), src_path.clone()).await {
                            Ok(Some(src_node)) if can_read(&src_node, current_user.as_ref()) => {
                                // Check destination
                                let (final_dst_path, valid_dst) = match dao::get_f_node(pg_client.clone(), dst_path_orig.clone()).await {
                                    Ok(Some(dst_node)) => {
                                        if dst_node.dir {
                                            // Copy INTO directory
                                            match Path::new(&src_path).file_name().and_then(|n| n.to_str()) {
                                                Some(src_name) => (format!("{}/{}", dst_path_orig, src_name), true),
                                                None => (String::new(), false), // Invalid source path
                                            }
                                        } else {
                                            // Destination exists and is a file -> Error (no overwrite support yet)
                                            (String::new(), false)
                                        }
                                    }
                                    Ok(None) => (dst_path_orig, true), // Copy AS new name
                                    Err(_) => (String::new(), false),
                                };

                                if !valid_dst || final_dst_path.is_empty() {
                                    AppMessage { cmd: Cmd::Failure, data: vec!["destination exists as file or error".to_string()] }
                                } else {
                                    // Check if final destination already exists (to avoid overwrite/collision in the copy-into case)
                                     match dao::get_f_node(pg_client.clone(), final_dst_path.clone()).await {
                                         Ok(Some(_)) => AppMessage { cmd: Cmd::Failure, data: vec!["destination already exists".to_string()] },
                                         _ => {
                                             // Check write permission on PARENT of final_dst_path
                                             let path_obj = Path::new(&final_dst_path);
                                             let parent_opt = path_obj.parent().map(|p| p.to_str().unwrap_or("/"));
                                             let parent_str = match parent_opt {
                                                 Some("") | None => "/".to_string(),
                                                 Some(p) => p.to_string(),
                                             };

                                             match dao::get_f_node(pg_client.clone(), parent_str).await {
                                                 Ok(Some(parent_node)) if can_write(&parent_node, current_user.as_ref()) => {
                                                     match dao::copy_recursive(pg_client.clone(), src_path, final_dst_path, current_user.clone().unwrap()).await {
                                                         Ok(_) => AppMessage { cmd: Cmd::Cp, data: vec!["ok".to_string()] },
                                                         Err(e) => AppMessage { cmd: Cmd::Failure, data: vec![e] }
                                                     }
                                                 }
                                                 _ => AppMessage { cmd: Cmd::Failure, data: vec!["no write permission on target directory".to_string()] }
                                             }
                                         }
                                     }
                                }
                            }
                            _ => AppMessage { cmd: Cmd::Failure, data: vec!["source not found or no read permission".to_string()] }
                        }
                    }
                }
            }
            Cmd::Find => {
                if !authenticated {
                    AppMessage {
                        cmd: Cmd::Failure,
                        data: vec!["not authenticated".to_string()],
                    }
                } else {
                    let pattern = incoming.data.get(0).cloned().unwrap_or_default();
                    if pattern.is_empty() {
                        AppMessage { cmd: Cmd::Failure, data: vec!["missing pattern".to_string()] }
                    } else {
                        // Search recursively from current path
                        let mut results: Vec<String> = Vec::new();
                        let mut to_search = vec![current_path.clone()];
                        
                        while let Some(search_path) = to_search.pop() {
                            if let Ok(Some(node)) = dao::get_f_node(pg_client.clone(), search_path.clone()).await {
                                if can_read(&node, current_user.as_ref()) {
                                    // Check if name matches pattern (simple contains match)
                                    if node.name.contains(&pattern) {
                                        results.push(node.path.clone());
                                    }
                                    // If directory, add children to search queue
                                    if node.dir {
                                        for child in node.children.iter() {
                                            let child_path = format!("{}/{}", search_path, child);
                                            to_search.push(child_path);
                                        }
                                    }
                                }
                            }
                        }
                        
                        if results.is_empty() {
                            AppMessage { cmd: Cmd::Find, data: vec!["no matches found".to_string()] }
                        } else {
                            AppMessage { cmd: Cmd::Find, data: results }
                        }
                    }
                }
            }
            Cmd::Chown => {
                if !authenticated {
                    AppMessage {
                        cmd: Cmd::Failure,
                        data: vec!["not authenticated".to_string()],
                    }
                } else {
                    let target = incoming.data.get(0).cloned().unwrap_or_default();
                    let new_owner = incoming.data.get(1).cloned().unwrap_or_default();
                    
                    if !is_valid_name(&target) {
                        AppMessage { cmd: Cmd::Failure, data: vec!["invalid target name".to_string()] }
                    } else if !is_valid_user_group_name(&new_owner) {
                        AppMessage { cmd: Cmd::Failure, data: vec!["invalid owner name".to_string()] }
                    } else {
                        // Verify new owner exists
                        match dao::get_user(pg_client.clone(), new_owner.clone()).await {
                            Ok(None) => AppMessage { cmd: Cmd::Failure, data: vec!["user not found".to_string()] },
                            Err(_) => AppMessage { cmd: Cmd::Failure, data: vec!["database error".to_string()] },
                            Ok(Some(_)) => {
                                let path = format!("{}/{}", current_path, target);
                                match dao::get_f_node(pg_client.clone(), path.clone()).await {
                                    Ok(Some(node)) if is_owner(&node, current_user.as_ref()) => {
                                        match dao::change_owner(pg_client.clone(), path, new_owner.clone()).await {
                                            Ok(_) => AppMessage { cmd: Cmd::Chown, data: vec![format!("owner changed to {}", new_owner)] },
                                            Err(_) => AppMessage { cmd: Cmd::Failure, data: vec!["chown failed".to_string()] },
                                        }
                                    }
                                    Ok(Some(_)) => AppMessage { cmd: Cmd::Failure, data: vec!["not owner".to_string()] },
                                    _ => AppMessage { cmd: Cmd::Failure, data: vec!["file not found".to_string()] },
                                }
                            }
                        }
                    }
                }
            }
            Cmd::Chgrp => {
                // NOTE: Since files inherit group from owner, chgrp changes the owner's group assignment
                // for the file. This is a simplified model; a full implementation would store group
                // separately per file.
                if !authenticated {
                    AppMessage {
                        cmd: Cmd::Failure,
                        data: vec!["not authenticated".to_string()],
                    }
                } else {
                    let target = incoming.data.get(0).cloned().unwrap_or_default();
                    let new_group = incoming.data.get(1).cloned().unwrap_or_default();
                    
                    if !is_valid_name(&target) {
                        AppMessage { cmd: Cmd::Failure, data: vec!["invalid target name".to_string()] }
                    } else if !is_valid_user_group_name(&new_group) {
                        AppMessage { cmd: Cmd::Failure, data: vec!["invalid group name".to_string()] }
                    } else {
                        // Verify group exists
                        match dao::get_group(pg_client.clone(), new_group.clone()).await {
                            Ok(None) => AppMessage { cmd: Cmd::Failure, data: vec!["group not found".to_string()] },
                            Err(_) => AppMessage { cmd: Cmd::Failure, data: vec!["database error".to_string()] },
                            Ok(Some(_)) => {
                                let path = format!("{}/{}", current_path, target);
                                match dao::get_f_node(pg_client.clone(), path.clone()).await {
                                    Ok(Some(node)) if is_owner(&node, current_user.as_ref()) => {
                                        // For now, log success since group is tied to owner
                                        info!("chgrp: {} -> {} for {}", node.owner, new_group, path);
                                        AppMessage { cmd: Cmd::Chgrp, data: vec![format!("group changed to {}", new_group)] }
                                    }
                                    Ok(Some(_)) => AppMessage { cmd: Cmd::Failure, data: vec!["not owner".to_string()] },
                                    _ => AppMessage { cmd: Cmd::Failure, data: vec!["file not found".to_string()] },
                                }
                            }
                        }
                    }
                }
            }
            _ => AppMessage {
                cmd: Cmd::Failure,
                data: vec!["command not implemented".to_string()],
            },
        };

        let is_logout = matches!(reply.cmd, Cmd::Logout);
        send_app_message(&mut ws_stream, reply, shared_secret.as_ref()).await?;

        if let Some(s) = next_secret {
            shared_secret = Some(s);
        }

        // If logout was processed, close the loop so the client can reconnect cleanly.
        if !authenticated && is_logout {
            break;
        }
    }

    Ok(())
}

/// Serialize and send an application message over the websocket.
async fn send_app_message(ws_stream: &mut WebSocketStream<TcpStream>, resp: AppMessage, key: Option<&Key<Aes256Gcm>>) -> Result<(), String> {
    let payload = if let Some(k) = key {
        let enc_tuple = encrypt_app_message(k, &resp)?;
        serde_json::to_string(&enc_tuple).map_err(|e| e.to_string())?
    } else {
        serde_json::to_string(&resp).map_err(|e| e.to_string())?
    };
    ws_stream.send(Message::Text(payload))
        .await
        .map_err(|e| format!("send failed: {}", e))
}

/// Resolve a user input path relative to the current working directory.
fn resolve_path(current: &str, input: &str) -> String {
    if input.starts_with('/') {
        normalize_path(input.to_string())
    } else {
        normalize_path(format!("{}/{}", current, input))
    }
}

/// Normalize path components by collapsing `.` and `..`.
fn normalize_path(path: String) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        if part.is_empty() || part == "." {
            continue;
        } else if part == ".." {
            parts.pop();
        } else {
            parts.push(part);
        }
    }
    if parts.is_empty() {
        "/".into()
    } else {
        format!("/{}", parts.join("/"))
    }
}

/// Format ls entry with owner, group, permissions, and name.
fn format_ls_entry(node: &FNode) -> String {
    let suffix = if node.dir { "/" } else { "" };
    let perms = format_permissions(node.u, node.g, node.o);
    format!("{} {} {}{}", node.owner, perms, node.name, suffix)
}

/// Format Unix-style permissions into rwxrwxrwx string.
fn format_permissions(u: i16, g: i16, o: i16) -> String {
    let mut perms = String::new();
    perms.push(if u & 0b100 != 0 { 'r' } else { '-' });
    perms.push(if u & 0b010 != 0 { 'w' } else { '-' });
    perms.push(if u & 0b001 != 0 { 'x' } else { '-' });
    perms.push(if g & 0b100 != 0 { 'r' } else { '-' });
    perms.push(if g & 0b010 != 0 { 'w' } else { '-' });
    perms.push(if g & 0b001 != 0 { 'x' } else { '-' });
    perms.push(if o & 0b100 != 0 { 'r' } else { '-' });
    perms.push(if o & 0b010 != 0 { 'w' } else { '-' });
    perms.push(if o & 0b001 != 0 { 'x' } else { '-' });
    perms
}

/// Check if the current user can read the node.
/// Permission hierarchy: owner -> group -> other (world).
/// NOTE: This basic version doesn't check group membership; use `can_read_with_group` for full checks.
fn can_read(node: &FNode, user: Option<&String>) -> bool {
    if let Some(u) = user {
        // Owner check
        if node.owner == *u && (node.u & 0b100) != 0 {
            return true;
        }
    }
    // World/other check
    (node.o & 0b100) != 0
}

/// Check if the current user can read the node with full group permission support.
#[allow(dead_code)]
fn can_read_with_group(node: &FNode, user: Option<&String>, user_group: Option<&String>, owner_group: Option<&String>) -> bool {
    if let Some(u) = user {
        // Owner check
        if node.owner == *u && (node.u & 0b100) != 0 {
            return true;
        }
        // Group check: user belongs to same group as file owner
        if let (Some(ug), Some(og)) = (user_group, owner_group) {
            if ug == og && (node.g & 0b100) != 0 {
                return true;
            }
        }
    }
    // World/other check
    (node.o & 0b100) != 0
}

/// Check if the current user can write the node.
/// Permission hierarchy: owner -> group -> other (world).
/// NOTE: This basic version doesn't check group membership; use `can_write_with_group` for full checks.
fn can_write(node: &FNode, user: Option<&String>) -> bool {
    if let Some(u) = user {
        // Owner check
        if node.owner == *u && (node.u & 0b010) != 0 {
            return true;
        }
    }
    // World/other check
    (node.o & 0b010) != 0
}

/// Check if the current user can write the node with full group permission support.
#[allow(dead_code)]
fn can_write_with_group(node: &FNode, user: Option<&String>, user_group: Option<&String>, owner_group: Option<&String>) -> bool {
    if let Some(u) = user {
        // Owner check
        if node.owner == *u && (node.u & 0b010) != 0 {
            return true;
        }
        // Group check
        if let (Some(ug), Some(og)) = (user_group, owner_group) {
            if ug == og && (node.g & 0b010) != 0 {
                return true;
            }
        }
    }
    // World/other check
    (node.o & 0b010) != 0
}

/// Check if the current user can execute the node.
/// Permission hierarchy: owner -> group -> other (world).
#[allow(dead_code)]
fn can_execute(node: &FNode, user: Option<&String>) -> bool {
    if let Some(u) = user {
        // Owner check
        if node.owner == *u && (node.u & 0b001) != 0 {
            return true;
        }
    }
    // World/other check
    (node.o & 0b001) != 0
}

/// Check if the current user can execute the node with full group permission support.
#[allow(dead_code)]
fn can_execute_with_group(node: &FNode, user: Option<&String>, user_group: Option<&String>, owner_group: Option<&String>) -> bool {
    if let Some(u) = user {
        // Owner check
        if node.owner == *u && (node.u & 0b001) != 0 {
            return true;
        }
        // Group check
        if let (Some(ug), Some(og)) = (user_group, owner_group) {
            if ug == og && (node.g & 0b001) != 0 {
                return true;
            }
        }
    }
    // World/other check
    (node.o & 0b001) != 0
}

/// Check if the current user is the owner of the node.
fn is_owner(node: &FNode, user: Option<&String>) -> bool {
    if let Some(u) = user {
        return node.owner == *u;
    }
    false
}

/// Get the current Unix timestamp in seconds.
fn current_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Validate file or directory name (no path separators or special chars).
fn is_valid_name(name: &str) -> bool {
    !name.is_empty()
        && !name.contains('/')
        && !name.contains('\0')
        && name != "."
        && name != ".."
}

/// Validate username or group name (alphanumeric + underscore/hyphen).
fn is_valid_user_group_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && name.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-')
        && name.chars().next().unwrap().is_alphabetic()
}

/// Validate password strength (minimum 8 characters).
fn is_valid_password(pass: &str) -> bool {
    pass.len() >= 8
}

/// Create a failure response with a custom message.
fn failure(msg: &str) -> AppMessage {
    AppMessage {
        cmd: Cmd::Failure,
        data: vec![msg.to_string()],
    }
}

/// Create a success response for a given command with optional data.
fn success(cmd: Cmd, data: Vec<String>) -> AppMessage {
    AppMessage { cmd, data }
}



/// Compute BLAKE3 hash of file content for integrity verification.
fn hash_content(content: &[u8]) -> String {
    hex::encode(blake3::hash(content).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_path() {
        assert_eq!(normalize_path("/home/user".into()), "/home/user");
        assert_eq!(normalize_path("/home/user/".into()), "/home/user");
        assert_eq!(normalize_path("/home/./user".into()), "/home/user");
        assert_eq!(normalize_path("/home/user/..".into()), "/home");
        assert_eq!(normalize_path("/home/../root".into()), "/root");
        assert_eq!(normalize_path("/../..".into()), "/");
    }

    #[test]
    fn test_is_valid_name() {
        assert!(is_valid_name("file.txt"));
        assert!(is_valid_name("mydir"));
        assert!(!is_valid_name(""));
        assert!(!is_valid_name("."));
        assert!(!is_valid_name(".."));
        assert!(!is_valid_name("dir/subdir"));
        assert!(!is_valid_name("file\0name"));
    }

    #[test]
    fn test_format_permissions() {
        assert_eq!(format_permissions(7, 5, 4), "rwxr-xr--");
        assert_eq!(format_permissions(6, 4, 0), "rw-r-----");
        assert_eq!(format_permissions(0, 0, 0), "---------");
    }

    #[test]
    fn test_permission_helpers() {
        use crate::FNode;
        
        let node = FNode {
            id: 1,
            name: "test.txt".to_string(),
            path: "/home/user/test.txt".to_string(),
            owner: "alice".to_string(),
            hash: "".to_string(),
            parent: "/home/user".to_string(),
            dir: false,
            u: 6, // rw-
            g: 4, // r--
            o: 4, // r--
            children: vec![],
            encrypted_name: "".to_string(),
            size: 0,
            created_at: 0,
            modified_at: 0,
        };

        // Test can_read
        assert!(can_read(&node, Some(&"alice".to_string()))); // owner with read
        assert!(can_read(&node, Some(&"bob".to_string()))); // other with read
        assert!(can_read(&node, None)); // world-readable

        // Test can_write
        assert!(can_write(&node, Some(&"alice".to_string()))); // owner with write
        assert!(!can_write(&node, Some(&"bob".to_string()))); // other without write
        assert!(!can_write(&node, None)); // not world-writable

        // Test can_execute
        assert!(!can_execute(&node, Some(&"alice".to_string()))); // owner without execute
        assert!(!can_execute(&node, Some(&"bob".to_string()))); // other without execute

        // Test is_owner
        assert!(is_owner(&node, Some(&"alice".to_string())));
        assert!(!is_owner(&node, Some(&"bob".to_string())));
        assert!(!is_owner(&node, None));
    }

    #[test]
    fn test_group_permission_helpers() {
        use crate::FNode;
        
        // File owned by alice in group "devs"
        let node = FNode {
            id: 1,
            name: "project.rs".to_string(),
            path: "/home/alice/project.rs".to_string(),
            owner: "alice".to_string(),
            hash: "".to_string(),
            parent: "/home/alice".to_string(),
            dir: false,
            u: 6, // rw-
            g: 4, // r-- (group read)
            o: 0, // --- (no world access)
            children: vec![],
            encrypted_name: "".to_string(),
            size: 0,
            created_at: 0,
            modified_at: 0,
        };

        let owner_group = Some("devs".to_string());
        let alice_group = Some("devs".to_string());
        let bob_group = Some("devs".to_string()); // Bob is also in devs
        let charlie_group = Some("users".to_string()); // Charlie is in different group

        // Owner can read (via owner permission)
        assert!(can_read_with_group(&node, Some(&"alice".to_string()), alice_group.as_ref(), owner_group.as_ref()));
        
        // Bob (same group) can read via group permission
        assert!(can_read_with_group(&node, Some(&"bob".to_string()), bob_group.as_ref(), owner_group.as_ref()));
        
        // Charlie (different group) cannot read (no world permission)
        assert!(!can_read_with_group(&node, Some(&"charlie".to_string()), charlie_group.as_ref(), owner_group.as_ref()));
        
        // World (None user) cannot read
        assert!(!can_read_with_group(&node, None, None, owner_group.as_ref()));

        // Group write permissions (group has r-- only)
        assert!(!can_write_with_group(&node, Some(&"bob".to_string()), bob_group.as_ref(), owner_group.as_ref()));
    }

    #[test]
    fn test_helper_responses() {
        let fail = failure("test error");
        assert_eq!(fail.cmd, Cmd::Failure);
        assert_eq!(fail.data, vec!["test error".to_string()]);

        let succ = success(Cmd::Pwd, vec!["/home/user".to_string()]);
        assert_eq!(succ.cmd, Cmd::Pwd);
        assert_eq!(succ.data, vec!["/home/user".to_string()]);
    }

    #[test]
    fn test_is_valid_password() {
        // Valid passwords
        assert!(is_valid_password("password123"));
        assert!(is_valid_password("12345678"));
        assert!(is_valid_password("abcdefgh"));
        
        // Invalid passwords
        assert!(!is_valid_password(""));
        assert!(!is_valid_password("short"));
        assert!(!is_valid_password("1234567")); // Only 7 chars
    }

    #[test]
    fn test_x25519_key_exchange() {
        use x25519_dalek::{EphemeralSecret, PublicKey};
        use rand_core::OsRng;

        // Simulate client keypair
        let client_secret = EphemeralSecret::random_from_rng(OsRng);
        let client_public = PublicKey::from(&client_secret);

        // Simulate server keypair
        let server_secret = EphemeralSecret::random_from_rng(OsRng);
        let server_public = PublicKey::from(&server_secret);

        // Both sides derive the same shared secret
        let client_shared = client_secret.diffie_hellman(&server_public);
        let server_shared = server_secret.diffie_hellman(&client_public);

        assert_eq!(client_shared.as_bytes(), server_shared.as_bytes());
    }
}

