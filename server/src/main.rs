use std::env;
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use securefs_model::protocol::{AppMessage, Cmd};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio_postgres::NoTls;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::accept_async;
use tokio::net::TcpStream;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod dao;

#[tokio::main]
async fn main() -> Result<(), String> {
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
            eprintln!("db connection error: {}", e);
        }
    });

    let bind_addr = env::var("SERVER_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let listener = TcpListener::bind(&bind_addr)
        .await
        .map_err(|e| format!("bind failed: {}", e))?;
    println!("listening on: {}", bind_addr);

    while let Ok((stream, _)) = listener.accept().await {
        let pg = pg_client.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, pg).await {
                eprintln!("connection error: {}", e);
            }
        });
    }

    Ok(())
}

async fn handle_connection(stream: TcpStream, pg_client: Arc<Mutex<tokio_postgres::Client>>) -> Result<(), String> {
    let mut ws_stream = accept_async(stream)
        .await
        .map_err(|e| format!("handshake failed: {}", e))?;

    let mut authenticated = false;
    let mut current_user: Option<String> = None;
    let mut current_path: String = "/home".to_string();

    while let Some(msg) = ws_stream.next().await {
        let msg = msg.map_err(|e| format!("ws read failed: {}", e))?;
        if !msg.is_text() {
            continue;
        }
        let incoming: AppMessage = serde_json::from_str(msg.to_text().unwrap())
            .map_err(|e| format!("decode failed: {}", e))?;

        let reply = match incoming.cmd {
            Cmd::NewConnection => AppMessage {
                cmd: Cmd::NewConnection,
                data: vec![],
            },
            Cmd::Login => {
                let user_name = incoming.data.get(0).cloned().unwrap_or_default();
                let pass = incoming.data.get(1).cloned().unwrap_or_default();
                let is_ok = dao::auth_user(pg_client.clone(), user_name.clone(), pass)
                    .await
                    .unwrap_or(false);
                if !is_ok {
                    AppMessage {
                        cmd: Cmd::Failure,
                        data: vec!["failed to login!".to_string(), "".to_string()],
                    }
                } else {
                    authenticated = true;
                    current_user = Some(user_name.clone());
                    let user_home = format!("/home/{}", user_name);
                    if dao::get_f_node(pg_client.clone(), user_home.clone()).await.ok().flatten().is_some() {
                        current_path = user_home;
                    } else {
                        current_path = "/home".into();
                    }
                    let is_admin = dao::get_user(pg_client.clone(), user_name.clone())
                        .await
                        .ok()
                        .flatten()
                        .map(|u| u.is_admin)
                        .unwrap_or(false);
                    AppMessage {
                        cmd: Cmd::Login,
                        data: vec![user_name, is_admin.to_string()],
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
                                if let Ok(Some(node)) = dao::get_f_node(pg_client.clone(), child_path) {
                                    names.push(node.name);
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
                    if dir_name.is_empty() {
                        AppMessage {
                            cmd: Cmd::Failure,
                            data: vec!["missing directory name".to_string()],
                        }
                    } else {
                        let target_path = format!("{}/{}", current_path, dir_name);
                        let parent_path = current_path.clone();
                        let owner = current_user.clone().unwrap_or_default();

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
            Cmd::Mv => {
                if !authenticated {
                    AppMessage {
                        cmd: Cmd::Failure,
                        data: vec!["not authenticated".to_string()],
                    }
                } else {
                    let src = incoming.data.get(0).cloned().unwrap_or_default();
                    let dst = incoming.data.get(1).cloned().unwrap_or_default();
                    if src.is_empty() || dst.is_empty() {
                        AppMessage {
                            cmd: Cmd::Failure,
                            data: vec!["missing paths".to_string()],
                        }
                    } else {
                        let old_path = format!("{}/{}", current_path, src);
                        let new_path = format!("{}/{}", current_path, dst);
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
                    if target.is_empty() {
                        AppMessage {
                            cmd: Cmd::Failure,
                            data: vec!["missing path".to_string()],
                        }
                    } else {
                        let path = format!("{}/{}", current_path, target);
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
                    match dao::get_f_node(pg_client.clone(), new_path.clone()).await {
                        Ok(Some(node)) if node.dir => {
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
            Cmd::Touch => {
                if !authenticated {
                    AppMessage {
                        cmd: Cmd::Failure,
                        data: vec!["not authenticated".to_string()],
                    }
                } else {
                    let file_name = incoming.data.get(0).cloned().unwrap_or_default();
                    if file_name.is_empty() {
                        AppMessage {
                            cmd: Cmd::Failure,
                            data: vec!["missing file name".to_string()],
                        }
                    } else {
                        let target_path = format!("{}/{}", current_path, file_name);
                        let parent_path = current_path.clone();
                        let owner = current_user.clone().unwrap_or_default();

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
            Cmd::Cat => {
                if !authenticated {
                    AppMessage {
                        cmd: Cmd::Failure,
                        data: vec!["not authenticated".to_string()],
                    }
                } else {
                    let file_name = incoming.data.get(0).cloned().unwrap_or_default();
                    if file_name.is_empty() {
                        AppMessage {
                            cmd: Cmd::Failure,
                            data: vec!["missing file name".to_string()],
                        }
                    } else {
                        let target_path = format!("storage{}", current_path);
                        let file_path = format!("{}/{}", target_path, file_name);
                        let mut buf = String::new();
                        let read_res = fs::File::open(&file_path).await;
                        match read_res {
                            Ok(mut f) => {
                                let _ = f.read_to_string(&mut buf).await;
                                AppMessage { cmd: Cmd::Cat, data: vec![buf] }
                            }
                            Err(_) => AppMessage {
                                cmd: Cmd::Failure,
                                data: vec!["cat failed".to_string()],
                            },
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
                    if file_name.is_empty() {
                        AppMessage {
                            cmd: Cmd::Failure,
                            data: vec!["missing file name".to_string()],
                        }
                    } else {
                        let target_path = format!("storage{}", current_path);
                        let file_path = format!("{}/{}", target_path, file_name);
                        if fs::create_dir_all(&target_path).await.is_err() {
                            AppMessage {
                                cmd: Cmd::Failure,
                                data: vec!["echo failed".to_string()],
                            }
                        } else {
                            let write_res = fs::File::create(&file_path).await.and_then(|mut f| f.write_all(content.as_bytes()));
                            match write_res {
                                Ok(_) => AppMessage { cmd: Cmd::Echo, data: vec!["ok".to_string()] },
                                Err(_) => AppMessage { cmd: Cmd::Failure, data: vec!["echo failed".to_string()] },
                            }
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
                            let res = dao::change_file_perms(pg_client.clone(), path, ugo[0], ugo[1], ugo[2]).await;
                            match res {
                                Ok(_) => AppMessage { cmd: Cmd::Chmod, data: vec!["ok".to_string()] },
                                Err(_) => AppMessage { cmd: Cmd::Failure, data: vec!["chmod failed".to_string()] },
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

        send_app_message(&mut ws_stream, reply).await?;

        // if logout was processed, close the loop
        if !authenticated && matches!(reply.cmd, Cmd::Logout) {
            break;
        }
    }

    Ok(())
}

async fn send_app_message(ws_stream: &mut WebSocketStream<TcpStream>, resp: AppMessage) -> Result<(), String> {
    let serialized = serde_json::to_string(&resp).map_err(|e| format!("encode failed: {}", e))?;
    ws_stream
        .send(Message::text(serialized))
        .await
        .map_err(|e| format!("ws send failed: {}", e))
}

fn resolve_path(current: &str, input: &str) -> String {
    if input.starts_with('/') {
        normalize_path(input.to_string())
    } else {
        normalize_path(format!("{}/{}", current, input))
    }
}

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

