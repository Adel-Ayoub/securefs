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
                        data: vec!["/".to_string()],
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
                    AppMessage { cmd: Cmd::Ls, data: vec![] }
                }
            }
            Cmd::Mkdir => {
                if !authenticated {
                    AppMessage {
                        cmd: Cmd::Failure,
                        data: vec!["not authenticated".to_string()],
                    }
                } else {
                    AppMessage {
                        cmd: Cmd::Mkdir,
                        data: vec!["ok".to_string()],
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

