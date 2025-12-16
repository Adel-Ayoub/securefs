//! SecureFS command-line client
//!
//! This is the main entry point for the SecureFS CLI client,
//! providing a command-line interface to the SecureFS file system.

use std::env;
use std::io::{self, Write};

use futures_util::{SinkExt, StreamExt};
use securefs_model::cmd::{MapStr, NumArgs};
use securefs_model::protocol::{AppMessage, Cmd};
use tokio::runtime::Runtime;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

fn main() {
    let rt = Runtime::new().expect("runtime");
    if let Err(e) = rt.block_on(run()) {
        eprintln!("{}", e);
    }
}

async fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    let bind = "127.0.0.1:8080".to_string();
    let server_addr = args.get(1).cloned().unwrap_or(bind);
    let url = format!("ws://{}", server_addr);

    let (mut ws_stream, _) = connect_async(url)
        .await
        .map_err(|e| format!("connect failed: {}", e))?;

    println!("Connected. Login with: login <username> <password>");
    println!("Commands: login <u> <p>, logout, pwd, ls, cd <path>, mkdir <dir>, touch <file>, mv <src> <dst>, delete <name>, cat <file>, echo <data> <file>, chmod <mode> <name>");
    let stdin = io::stdin();
    loop {
        print!("> ");
        io::stdout().flush().map_err(|e| e.to_string())?;
        let mut line = String::new();
        stdin.read_line(&mut line).map_err(|e| e.to_string())?;
        if line.trim().is_empty() {
            continue;
        }
        let line = line.trim_end().to_string();
        let app_message = match command_parser(line.clone()) {
            Ok(msg) => msg,
            Err(err) => {
                println!("{}", err);
                continue;
            }
        };

        match app_message.cmd {
            Cmd::Login => {
                send(&mut ws_stream, &app_message).await?;
                let reply = recv(&mut ws_stream).await?;
                match reply.cmd {
                    Cmd::Login => {
                        let is_admin = reply.data.get(1).unwrap_or(&"false".into());
                        println!("login ok (is_admin: {})", is_admin);
                    }
                    Cmd::Failure => {
                        println!("{}", reply.data.get(0).unwrap_or(&"login failed".into()));
                    }
                    _ => println!("unexpected reply"),
                }
            }
            Cmd::Logout => {
                println!("bye");
                break;
            }
            Cmd::Cd => {
                send(&mut ws_stream, &app_message).await?;
                let reply = recv(&mut ws_stream).await?;
                match reply.cmd {
                    Cmd::Cd => println!("{}", reply.data.get(0).unwrap_or(&"/".into())),
                    Cmd::Failure => println!("{}", reply.data.get(0).unwrap_or(&"cd failed".into())),
                    _ => println!("unexpected reply"),
                }
            }
            Cmd::Pwd => {
                send(&mut ws_stream, &app_message).await?;
                let reply = recv(&mut ws_stream).await?;
                match reply.cmd {
                    Cmd::Pwd => {
                        let path = reply.data.get(0).unwrap_or(&"/".into());
                        println!("{}", path);
                    }
                    Cmd::Failure => {
                        println!("{}", reply.data.get(0).unwrap_or(&"pwd failed".into()));
                    }
                    _ => println!("unexpected reply"),
                }
            }
            Cmd::Ls => {
                send(&mut ws_stream, &app_message).await?;
                let reply = recv(&mut ws_stream).await?;
                match reply.cmd {
                    Cmd::Ls => {
                        if reply.data.is_empty() {
                            println!("");
                        } else {
                            reply.data.iter().for_each(|d| println!("{}", d));
                        }
                    }
                    Cmd::Failure => {
                        println!("{}", reply.data.get(0).unwrap_or(&"ls failed".into()));
                    }
                    _ => println!("unexpected reply"),
                }
            }
            Cmd::Mkdir => {
                send(&mut ws_stream, &app_message).await?;
                let reply = recv(&mut ws_stream).await?;
                match reply.cmd {
                    Cmd::Mkdir => println!("ok"),
                    Cmd::Failure => {
                        println!("{}", reply.data.get(0).unwrap_or(&"mkdir failed".into()));
                    }
                    _ => println!("unexpected reply"),
                }
            }
            Cmd::Touch => {
                send(&mut ws_stream, &app_message).await?;
                let reply = recv(&mut ws_stream).await?;
                match reply.cmd {
                    Cmd::Touch => println!("ok"),
                    Cmd::Failure => println!("{}", reply.data.get(0).unwrap_or(&"touch failed".into())),
                    _ => println!("unexpected reply"),
                }
            }
            Cmd::Mv => {
                send(&mut ws_stream, &app_message).await?;
                let reply = recv(&mut ws_stream).await?;
                match reply.cmd {
                    Cmd::Mv => println!("ok"),
                    Cmd::Failure => println!("{}", reply.data.get(0).unwrap_or(&"mv failed".into())),
                    _ => println!("unexpected reply"),
                }
            }
            Cmd::Delete => {
                send(&mut ws_stream, &app_message).await?;
                let reply = recv(&mut ws_stream).await?;
                match reply.cmd {
                    Cmd::Delete => println!("ok"),
                    Cmd::Failure => println!("{}", reply.data.get(0).unwrap_or(&"delete failed".into())),
                    _ => println!("unexpected reply"),
                }
            }
            Cmd::Cat => {
                send(&mut ws_stream, &app_message).await?;
                let reply = recv(&mut ws_stream).await?;
                match reply.cmd {
                    Cmd::Cat => println!("{}", reply.data.get(0).unwrap_or(&"".into())),
                    Cmd::Failure => println!("{}", reply.data.get(0).unwrap_or(&"cat failed".into())),
                    _ => println!("unexpected reply"),
                }
            }
            Cmd::Echo => {
                // echo "<data>" filename
                send(&mut ws_stream, &app_message).await?;
                let reply = recv(&mut ws_stream).await?;
                match reply.cmd {
                    Cmd::Echo => println!("ok"),
                    Cmd::Failure => println!("{}", reply.data.get(0).unwrap_or(&"echo failed".into())),
                    _ => println!("unexpected reply"),
                }
            }
            Cmd::Chmod => {
                send(&mut ws_stream, &app_message).await?;
                let reply = recv(&mut ws_stream).await?;
                match reply.cmd {
                    Cmd::Chmod => println!("ok"),
                    Cmd::Failure => println!("{}", reply.data.get(0).unwrap_or(&"chmod failed".into())),
                    _ => println!("unexpected reply"),
                }
            }
            _ => {
                println!("command not implemented");
            }
        }
    }

    Ok(())
}

fn command_parser(input: String) -> Result<AppMessage, String> {
    let mut parts = input
        .split_whitespace()
        .map(|s| s.to_string())
        .collect::<Vec<String>>();
    let cmd_str = match parts.get(0) {
        Some(c) => c.clone(),
        None => return Err("missing command".into()),
    };
    let num_args = Cmd::num_args(cmd_str.clone()).unwrap_or(usize::MAX);
    if num_args < usize::MAX && parts.len() != num_args {
        return Err("invalid number of args".into());
    }
    let args = parts.split_off(1);
    let cmd = Cmd::from_str(cmd_str).unwrap_or_default();
    Ok(AppMessage { cmd, data: args })
}

async fn send(ws: &mut tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>, msg: &AppMessage) -> Result<(), String> {
    let payload = serde_json::to_string(msg).map_err(|e| e.to_string())?;
    ws.send(Message::Text(payload))
        .await
        .map_err(|e| format!("send failed: {}", e))
}

async fn recv(ws: &mut tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>) -> Result<AppMessage, String> {
    let msg = ws.next().await.ok_or("connection closed")??;
    if !msg.is_text() {
        return Err("non-text message".into());
    }
    serde_json::from_str(msg.to_text().unwrap()).map_err(|e| format!("decode failed: {}", e))
}
