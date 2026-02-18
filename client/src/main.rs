//! SecureFS command-line client.
//!
//! Establishes a WebSocket connection to the server and forwards CLI
//! commands to protocol messages.

use std::env;

use futures_util::{SinkExt, StreamExt};
use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;
use securefs_model::cmd::{MapStr, NumArgs};
use securefs_model::protocol::{AppMessage, Cmd};
use tokio::runtime::Runtime;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;
use x25519_dalek::{EphemeralSecret, PublicKey};
use rand_core::OsRng;
use colored::Colorize;

/// Initialize a Tokio runtime and run the async client loop.
fn main() {
    let rt = Runtime::new().expect("runtime");
    if let Err(e) = rt.block_on(run()) {
        eprintln!("{}", e);
    }
}

/// Connect to the server and drive the interactive REPL.
async fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    
    // Check for help flag
    if args.len() > 1 && (args[1] == "-h" || args[1] == "--help") {
        print_help();
        return Ok(());
    }
    
    // Check for flags
    let mut verbose = false;
    let mut quiet = false;
    let mut server_addr_arg = None;

    for arg in args.iter().skip(1) {
        match arg.as_str() {
            "-v" | "--verbose" => verbose = true,
            "-q" | "--quiet" => quiet = true,
            s if !s.starts_with("-") => server_addr_arg = Some(s.to_string()),
            _ => {}
        }
    }

    let bind = env::var("SERVER_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let server_addr = server_addr_arg.unwrap_or(bind);
    let url = format!("ws://{}", server_addr);

    if verbose {
        println!("{}", format!("Connecting to {}", url).cyan());
    }

    // Initialize rustyline editor for command history and line editing
    let mut rl = DefaultEditor::new().map_err(|e| format!("failed to init readline: {}", e))?;
    
    let mut reconnect_delay = 1;
    let max_delay = 30;

    loop {
        // Connection loop
        match connect_and_run(&url, &mut rl, verbose, quiet).await {
            Ok(_) => {
                // Normal exit (logout)
                break;
            }
            Err(e) => {
                if !quiet {
                    eprintln!("Connection error: {}", e.red());
                    eprintln!("Reconnecting in {} seconds...", reconnect_delay);
                }
                tokio::time::sleep(tokio::time::Duration::from_secs(reconnect_delay)).await;
                reconnect_delay = std::cmp::min(reconnect_delay * 2, max_delay);
            }
        }
    }

    Ok(())
}

async fn connect_and_run(url: &str, rl: &mut DefaultEditor, verbose: bool, quiet: bool) -> Result<(), String> {
    let (mut ws_stream, _) = connect_async(url)
        .await
        .map_err(|e| format!("connect failed: {}", e))?;

    if verbose {
        println!("{}", "WebSocket connection established".green());
    }

    // Perform X25519 key exchange with server
    let client_secret = EphemeralSecret::random_from_rng(OsRng);
    let client_public = PublicKey::from(&client_secret);
    
    if verbose {
        println!("{}", "Initiating key exchange...".cyan());
    }

    // Send our public key to server
    let key_exchange_msg = AppMessage {
        cmd: Cmd::KeyExchangeInit,
        data: vec![hex::encode(client_public.as_bytes())],
    };
    send(&mut ws_stream, &key_exchange_msg, None).await?;
    
    // Receive server's public key
    let reply = recv(&mut ws_stream, None).await?;
    let _shared_secret = match reply.cmd {
        Cmd::KeyExchangeResponse => {
            let server_pubkey_hex = reply.data.get(0).cloned().unwrap_or_default();
            let server_bytes = hex::decode(&server_pubkey_hex)
                .map_err(|_| "invalid server public key")?;
            if server_bytes.len() != 32 {
                return Err("invalid server public key length".into());
            }
            let mut server_pubkey_bytes = [0u8; 32];
            server_pubkey_bytes.copy_from_slice(&server_bytes);
            let server_public = PublicKey::from(server_pubkey_bytes);
            let shared = client_secret.diffie_hellman(&server_public);
            if verbose {
                println!("{}", "Secure key exchange completed".green());
            }
            shared
        }
        Cmd::Failure => {
            let err = reply.data.get(0).cloned().unwrap_or_else(|| "key exchange failed".into());
            return Err(err);
        }
        _ => return Err("unexpected response to key exchange".into()),
    };
    
    // Derive session key using HKDF-SHA256 (must match server derivation)
    let hkdf = Hkdf::<Sha256>::new(None, _shared_secret.as_bytes());
    let mut okm = [0u8; 32];
    hkdf.expand(b"securefs-session-key-v1", &mut okm)
        .expect("32 bytes is valid output length for HKDF-SHA256");
    let shared_secret_key: Option<Key<Aes256Gcm>> = Some(*Key::<Aes256Gcm>::from_slice(&okm));

    if !quiet {
        // Use environment variable for server address in prompt or default
        let server_addr_display = env::var("SERVER_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
        println!("{} {}. Login with: login <username> <password>", "Connected to".cyan(), server_addr_display.cyan());
        println!("{}", "Commands: login, logout, pwd, ls, cd, mkdir, touch, mv, delete, cat, echo".yellow());
        println!("{}", "          chmod, chown, chgrp, cp, find, scan, get_encrypted_filename".yellow());
        println!("{}", "          new_user, new_group, lsusers, lsgroups, add_user_to_group, remove_user_from_group".yellow());
        println!("{}", "Use up/down arrows for command history. Ctrl+C or 'logout' to exit.".yellow());
    }
    
    loop {
        // REPL with command history support
        let prompt = if quiet { "".to_string() } else { format!("{} ", ">".bold()) };
        let readline = rl.readline(&prompt);
        let line = match readline {
            Ok(l) => l,
            Err(ReadlineError::Interrupted) => {
                if !quiet {
                    println!("{}", "Use 'logout' to exit".yellow());
                }
                continue;
            }
            Err(ReadlineError::Eof) => return Ok(()), // treat EOF as logout/exit
            Err(e) => return Err(format!("readline error: {}", e)),
        };
        
        if line.trim().is_empty() {
            continue;
        }
        
        // Add to history
        let _ = rl.add_history_entry(&line);
        
        let app_message = match command_parser(line.clone()) {
            Ok(msg) => msg,
            Err(err) => {
                println!("{}", err.red());
                continue;
            }
        };

        if verbose {
            println!("{}", format!("Sending command: {:?}", app_message.cmd).dimmed());
        }

        match app_message.cmd {
            Cmd::Login => {
                send(&mut ws_stream, &app_message, shared_secret_key.as_ref()).await?;
                let reply = recv(&mut ws_stream, shared_secret_key.as_ref()).await?;
                match reply.cmd {
                    Cmd::Login => {
                        let default_admin = "false".to_string();
                        let is_admin = reply.data.get(1).unwrap_or(&default_admin);
                        println!("{} (is_admin: {})", "login ok".green(), is_admin);
                    }
                    Cmd::Failure => {
                        println!("{}", reply.data.get(0).unwrap_or(&"login failed".into()).red());
                    }
                    _ => println!("{}", "unexpected reply".red()),
                }
            }
            Cmd::LsUsers => {
                send(&mut ws_stream, &app_message, shared_secret_key.as_ref()).await?;
                let reply = recv(&mut ws_stream, shared_secret_key.as_ref()).await?;
                match reply.cmd {
                    Cmd::LsUsers => {
                        if reply.data.is_empty() {
                            println!("no users found");
                        } else {
                            println!("users:");
                            for user in &reply.data {
                                println!("  {}", user.blue());
                            }
                        }
                    }
                    Cmd::Failure => println!("error: {}", reply.data.get(0).unwrap_or(&"lsusers failed".into()).red()),
                    _ => println!("{}", "unexpected reply".red()),
                }
            }
            Cmd::LsGroups => {
                send(&mut ws_stream, &app_message, shared_secret_key.as_ref()).await?;
                let reply = recv(&mut ws_stream, shared_secret_key.as_ref()).await?;
                match reply.cmd {
                    Cmd::LsGroups => {
                        if reply.data.is_empty() {
                            println!("no groups found");
                        } else {
                            println!("groups:");
                            for group in &reply.data {
                                println!("  {}", group.blue());
                            }
                        }
                    }
                    Cmd::Failure => println!("error: {}", reply.data.get(0).unwrap_or(&"lsgroups failed".into()).red()),
                    _ => println!("{}", "unexpected reply".red()),
                }
            }
            Cmd::Logout => {
                println!("bye");
                return Ok(());
            }
            Cmd::NewUser => {
                send(&mut ws_stream, &app_message, shared_secret_key.as_ref()).await?;
                let reply = recv(&mut ws_stream, shared_secret_key.as_ref()).await?;
                match reply.cmd {
                    Cmd::NewUser => println!("user created: {}", reply.data.get(0).unwrap_or(&"".into()).green()),
                    Cmd::Failure => println!("{}", reply.data.get(0).unwrap_or(&"newuser failed".into()).red()),
                    _ => println!("{}", "unexpected reply".red()),
                }
            }
            Cmd::NewGroup => {
                send(&mut ws_stream, &app_message, shared_secret_key.as_ref()).await?;
                let reply = recv(&mut ws_stream, shared_secret_key.as_ref()).await?;
                match reply.cmd {
                    Cmd::NewGroup => println!("group created: {}", reply.data.get(0).unwrap_or(&"".into()).green()),
                    Cmd::Failure => println!("{}", reply.data.get(0).unwrap_or(&"newgroup failed".into()).red()),
                    _ => println!("{}", "unexpected reply".red()),
                }
            }
            Cmd::Cd => {
                send(&mut ws_stream, &app_message, shared_secret_key.as_ref()).await?;
                let reply = recv(&mut ws_stream, shared_secret_key.as_ref()).await?;
                match reply.cmd {
                    Cmd::Cd => println!("{}", reply.data.get(0).unwrap_or(&"/".into()).blue()),
                    Cmd::Failure => println!("{}", reply.data.get(0).unwrap_or(&"cd failed".into()).red()),
                    _ => println!("{}", "unexpected reply".red()),
                }
            }
            Cmd::Pwd => {
                send(&mut ws_stream, &app_message, shared_secret_key.as_ref()).await?;
                let reply = recv(&mut ws_stream, shared_secret_key.as_ref()).await?;
                match reply.cmd {
                    Cmd::Pwd => {
                        let default_path = "/".to_string();
                        let path = reply.data.get(0).unwrap_or(&default_path);
                        println!("{}", path.blue());
                    }
                    Cmd::Failure => {
                        println!("{}", reply.data.get(0).unwrap_or(&"pwd failed".into()).red());
                    }
                    _ => println!("{}", "unexpected reply".red()),
                }
            }
            Cmd::Ls => {
                send(&mut ws_stream, &app_message, shared_secret_key.as_ref()).await?;
                let reply = recv(&mut ws_stream, shared_secret_key.as_ref()).await?;
                match reply.cmd {
                    Cmd::Ls => {
                        if reply.data.is_empty() {
                            println!("");
                        } else {
                            reply.data.iter().for_each(|d| println!("{}", d));
                        }
                    }
                    Cmd::Failure => {
                        println!("{}", reply.data.get(0).unwrap_or(&"ls failed".into()).red());
                    }
                    _ => println!("{}", "unexpected reply".red()),
                }
            }
            Cmd::Mkdir => {
                send(&mut ws_stream, &app_message, shared_secret_key.as_ref()).await?;
                let reply = recv(&mut ws_stream, shared_secret_key.as_ref()).await?;
                match reply.cmd {
                    Cmd::Mkdir => println!("{}", "ok".green()),
                    Cmd::Failure => {
                        println!("{}", reply.data.get(0).unwrap_or(&"mkdir failed".into()).red());
                    }
                    _ => println!("{}", "unexpected reply".red()),
                }
            }
            Cmd::Touch => {
                send(&mut ws_stream, &app_message, shared_secret_key.as_ref()).await?;
                let reply = recv(&mut ws_stream, shared_secret_key.as_ref()).await?;
                match reply.cmd {
                    Cmd::Touch => println!("{}", "ok".green()),
                    Cmd::Failure => println!("{}", reply.data.get(0).unwrap_or(&"touch failed".into()).red()),
                    _ => println!("{}", "unexpected reply".red()),
                }
            }
            Cmd::Mv => {
                send(&mut ws_stream, &app_message, shared_secret_key.as_ref()).await?;
                let reply = recv(&mut ws_stream, shared_secret_key.as_ref()).await?;
                match reply.cmd {
                    Cmd::Mv => println!("{}", "ok".green()),
                    Cmd::Failure => println!("{}", reply.data.get(0).unwrap_or(&"mv failed".into()).red()),
                    _ => println!("{}", "unexpected reply".red()),
                }
            }
            Cmd::Delete => {
                send(&mut ws_stream, &app_message, shared_secret_key.as_ref()).await?;
                let reply = recv(&mut ws_stream, shared_secret_key.as_ref()).await?;
                match reply.cmd {
                    Cmd::Delete => println!("{}", "ok".green()),
                    Cmd::Failure => println!("{}", reply.data.get(0).unwrap_or(&"delete failed".into()).red()),
                    _ => println!("{}", "unexpected reply".red()),
                }
            }
            Cmd::Cat => {
                send(&mut ws_stream, &app_message, shared_secret_key.as_ref()).await?;
                let reply = recv(&mut ws_stream, shared_secret_key.as_ref()).await?;
                match reply.cmd {
                    Cmd::Cat => println!("{}", reply.data.get(0).unwrap_or(&"".into())),
                    Cmd::Failure => println!("{}", reply.data.get(0).unwrap_or(&"cat failed".into()).red()),
                    _ => println!("{}", "unexpected reply".red()),
                }
            }
            Cmd::Echo => {
                // echo "<data>" filename
                send(&mut ws_stream, &app_message, shared_secret_key.as_ref()).await?;
                let reply = recv(&mut ws_stream, shared_secret_key.as_ref()).await?;
                match reply.cmd {
                    Cmd::Echo => println!("{}", "ok".green()),
                    Cmd::Failure => println!("{}", reply.data.get(0).unwrap_or(&"echo failed".into()).red()),
                    _ => println!("{}", "unexpected reply".red()),
                }
            }
            Cmd::Chmod => {
                send(&mut ws_stream, &app_message, shared_secret_key.as_ref()).await?;
                let reply = recv(&mut ws_stream, shared_secret_key.as_ref()).await?;
                match reply.cmd {
                    Cmd::Chmod => println!("{}", "ok".green()),
                    Cmd::Failure => println!("{}", reply.data.get(0).unwrap_or(&"chmod failed".into()).red()),
                    _ => println!("{}", "unexpected reply".red()),
                }
            }
            Cmd::Scan => {
                send(&mut ws_stream, &app_message, shared_secret_key.as_ref()).await?;
                let reply = recv(&mut ws_stream, shared_secret_key.as_ref()).await?;
                match reply.cmd {
                    Cmd::Scan => println!("{}", reply.data.get(0).unwrap_or(&"scan ok".into()).green()),
                    Cmd::Failure => println!("{}", reply.data.get(0).unwrap_or(&"scan failed".into()).red()),
                    _ => println!("{}", "unexpected reply".red()),
                }
            }
            Cmd::GetEncryptedFile => {
                send(&mut ws_stream, &app_message, shared_secret_key.as_ref()).await?;
                let reply = recv(&mut ws_stream, shared_secret_key.as_ref()).await?;
                match reply.cmd {
                    Cmd::GetEncryptedFile => {
                        println!("encrypted path: {}", reply.data.join("/").blue());
                    }
                    Cmd::Failure => println!("{}", reply.data.get(0).unwrap_or(&"failed to get encrypted file".into()).red()),
                    _ => println!("{}", "unexpected reply".red()),
                }
            }
            Cmd::Cp => {
                send(&mut ws_stream, &app_message, shared_secret_key.as_ref()).await?;
                let reply = recv(&mut ws_stream, shared_secret_key.as_ref()).await?;
                match reply.cmd {
                    Cmd::Cp => println!("{}", "ok".green()),
                    Cmd::Failure => println!("{}", reply.data.get(0).unwrap_or(&"cp failed".into()).red()),
                    _ => println!("{}", "unexpected reply".red()),
                }
            }
            Cmd::Find => {
                send(&mut ws_stream, &app_message, shared_secret_key.as_ref()).await?;
                let reply = recv(&mut ws_stream, shared_secret_key.as_ref()).await?;
                match reply.cmd {
                    Cmd::Find => {
                        for path in &reply.data {
                            println!("{}", path.blue());
                        }
                    }
                    Cmd::Failure => println!("{}", reply.data.get(0).unwrap_or(&"find failed".into()).red()),
                    _ => println!("{}", "unexpected reply".red()),
                }
            }
            Cmd::Chown => {
                send(&mut ws_stream, &app_message, shared_secret_key.as_ref()).await?;
                let reply = recv(&mut ws_stream, shared_secret_key.as_ref()).await?;
                match reply.cmd {
                    Cmd::Chown => println!("{}", reply.data.get(0).unwrap_or(&"ok".into()).green()),
                    Cmd::Failure => println!("{}", reply.data.get(0).unwrap_or(&"chown failed".into()).red()),
                    _ => println!("{}", "unexpected reply".red()),
                }
            }
            Cmd::Chgrp => {
                send(&mut ws_stream, &app_message, shared_secret_key.as_ref()).await?;
                let reply = recv(&mut ws_stream, shared_secret_key.as_ref()).await?;
                match reply.cmd {
                    Cmd::Chgrp => println!("{}", reply.data.get(0).unwrap_or(&"ok".into()).green()),
                    Cmd::Failure => println!("{}", reply.data.get(0).unwrap_or(&"chgrp failed".into()).red()),
                    _ => println!("{}", "unexpected reply".red()),
                }
            }
            Cmd::AddUserToGroup => {
                send(&mut ws_stream, &app_message, shared_secret_key.as_ref()).await?;
                let reply = recv(&mut ws_stream, shared_secret_key.as_ref()).await?;
                match reply.cmd {
                    Cmd::AddUserToGroup => println!("{}", reply.data.get(0).unwrap_or(&"ok".into()).green()),
                    Cmd::Failure => println!("{}", reply.data.get(0).unwrap_or(&"failed".into()).red()),
                    _ => println!("{}", "unexpected reply".red()),
                }
            }
            Cmd::RemoveUserFromGroup => {
                send(&mut ws_stream, &app_message, shared_secret_key.as_ref()).await?;
                let reply = recv(&mut ws_stream, shared_secret_key.as_ref()).await?;
                match reply.cmd {
                    Cmd::RemoveUserFromGroup => println!("{}", reply.data.get(0).unwrap_or(&"ok".into()).green()),
                    Cmd::Failure => println!("{}", reply.data.get(0).unwrap_or(&"failed".into()).red()),
                    _ => println!("{}", "unexpected reply".red()),
                }
            }
            _ => {
                println!("command not implemented");
            }
        }
    }
}

/// Parse user input into an `AppMessage` understood by the server.
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
        return Err(format!("expected {} args for '{}', got {}", num_args - 1, cmd_str, parts.len() - 1));
    }
    let args = parts.split_off(1);
    let cmd = Cmd::from_str(cmd_str.clone()).map_err(|_| format!("unknown command: {}", cmd_str))?;
    Ok(AppMessage { cmd, data: args })
}

use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit};
use aes_gcm::aead::{Aead, AeadCore};
use hkdf::Hkdf;
use sha2::Sha256;

/// Encrypt and send message
async fn send(ws: &mut tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>, msg: &AppMessage, key: Option<&Key<Aes256Gcm>>) -> Result<(), String> {
    let payload = if let Some(k) = key {
        let cipher = Aes256Gcm::new(k);
        let nonce = Aes256Gcm::generate_nonce(OsRng);
        let msg_str = serde_json::to_string(msg).map_err(|e| e.to_string())?;
        let ciphertext = cipher.encrypt(&nonce, msg_str.as_bytes())
            .map_err(|e| format!("encryption failed: {}", e))?;
        let tuple = (hex::encode(ciphertext), Into::<[u8; 12]>::into(nonce));
        serde_json::to_string(&tuple).map_err(|e| e.to_string())?
    } else {
        serde_json::to_string(msg).map_err(|e| e.to_string())?
    };
    ws.send(Message::Text(payload))
        .await
        .map_err(|e| format!("send failed: {}", e))
}

/// Receive and decrypt message
async fn recv(ws: &mut tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>, key: Option<&Key<Aes256Gcm>>) -> Result<AppMessage, String> {
    let msg = ws.next().await.ok_or("connection closed".to_string())?
        .map_err(|e| format!("recv failed: {}", e))?;
    if !msg.is_text() {
        return Err("non-text message".into());
    }
    let text = msg.to_text().unwrap();
    
    if let Some(k) = key {
        let (ciphertext_hex, nonce_bytes): (String, [u8; 12]) = serde_json::from_str(text)
            .map_err(|e| format!("encrypted decode failed: {}", e))?;
        let cipher = Aes256Gcm::new(k);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = hex::decode(ciphertext_hex).map_err(|_| "invalid ciphertext hex".to_string())?;
        let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())
            .map_err(|e| format!("decryption failed: {}", e))?;
        let plaintext_str = String::from_utf8(plaintext).map_err(|_| "invalid utf8".to_string())?;
        serde_json::from_str(&plaintext_str).map_err(|e| format!("json decode failed: {}", e))
    } else {
        serde_json::from_str(text).map_err(|e| format!("decode failed: {}", e))
    }
}

/// Print usage information.
fn print_help() {
    println!("SecureFS Client");
    println!();
    println!("USAGE:");
    println!("    securefs-client [OPTIONS] [SERVER_ADDRESS]");
    println!();
    println!("ARGS:");
    println!("    <SERVER_ADDRESS>    WebSocket server address (default: 127.0.0.1:8080)");
    println!();
    println!("OPTIONS:");
    println!("    -h, --help          Print help information");
    println!("    -v, --verbose       Enable verbose output");
    println!("    -q, --quiet         Suppress non-essential output");
    println!();
    println!("ENVIRONMENT:");
    println!("    SERVER_ADDR         Default server address");
}
