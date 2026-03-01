//! SecureFS command-line client.
//!
//! Establishes a WebSocket connection to the server and forwards CLI
//! commands to protocol messages.

use std::env;
use std::fs as stdfs;
use std::io::Write as _;

use base64::Engine;
use colored::Colorize;
use futures_util::{SinkExt, StreamExt};
use rand_core::OsRng;
use rustyline::completion::{Completer, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::{CompletionType, Config, Context, Editor, Helper};
use securefs_model::cmd::{MapStr, NumArgs};
use securefs_model::protocol::{AppMessage, Cmd};
use tokio::runtime::Runtime;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;
use x25519_dalek::{EphemeralSecret, PublicKey};

const COMMANDS: &[&str] = &[
    "cat",
    "cd",
    "chmod",
    "chown",
    "chgrp",
    "cp",
    "delete",
    "download",
    "du",
    "echo",
    "find",
    "get_encrypted_filename",
    "grep",
    "head",
    "ln",
    "login",
    "logout",
    "ls",
    "lsgroups",
    "lsusers",
    "mkdir",
    "mv",
    "new_group",
    "new_user",
    "pwd",
    "scan",
    "stat",
    "tail",
    "touch",
    "tree",
    "upload",
    "whoami",
    "add_user_to_group",
    "remove_user_from_group",
];

struct SecureFsHelper;

impl Completer for SecureFsHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        let line_up_to_pos = &line[..pos];
        // Only complete the first word (command name)
        if !line_up_to_pos.contains(' ') {
            let prefix = line_up_to_pos;
            let matches: Vec<Pair> = COMMANDS
                .iter()
                .filter(|cmd| cmd.starts_with(prefix))
                .map(|cmd| Pair {
                    display: cmd.to_string(),
                    replacement: cmd.to_string(),
                })
                .collect();
            Ok((0, matches))
        } else {
            Ok((pos, vec![]))
        }
    }
}

impl Hinter for SecureFsHelper {
    type Hint = String;
}

impl Highlighter for SecureFsHelper {}
impl Validator for SecureFsHelper {}
impl Helper for SecureFsHelper {}

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
    let mut use_tls = false;
    let mut server_addr_arg = None;

    for arg in args.iter().skip(1) {
        match arg.as_str() {
            "-v" | "--verbose" => verbose = true,
            "-q" | "--quiet" => quiet = true,
            "-t" | "--tls" => use_tls = true,
            s if !s.starts_with("-") => server_addr_arg = Some(s.to_string()),
            _ => {}
        }
    }

    // Check env var for TLS
    if env::var("USE_TLS")
        .map(|v| v == "1" || v.to_lowercase() == "true")
        .unwrap_or(false)
    {
        use_tls = true;
    }

    let bind = env::var("SERVER_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let server_addr = server_addr_arg.unwrap_or(bind);
    let scheme = if use_tls { "wss" } else { "ws" };
    let url = format!("{}://{}", scheme, server_addr);

    if verbose {
        println!("{}", format!("Connecting to {}", url).cyan());
    }

    let config = Config::builder()
        .completion_type(CompletionType::List)
        .build();
    let mut rl =
        Editor::with_config(config).map_err(|e| format!("failed to init readline: {}", e))?;
    rl.set_helper(Some(SecureFsHelper));

    // Load persistent history
    let history_path = dirs::home_dir().map(|h| h.join(".securefs_history"));
    if let Some(ref path) = history_path {
        let _ = rl.load_history(path);
    }

    let mut reconnect_delay = 1;
    let max_delay = 30;

    loop {
        match connect_and_run(&url, &mut rl, verbose, quiet).await {
            Ok(_) => break,
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

    // Save history on exit
    if let Some(ref path) = history_path {
        let _ = rl.save_history(path);
    }

    Ok(())
}

async fn connect_and_run(
    url: &str,
    rl: &mut Editor<SecureFsHelper, rustyline::history::DefaultHistory>,
    verbose: bool,
    quiet: bool,
) -> Result<(), String> {
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
            let server_pubkey_hex = reply.data.first().cloned().unwrap_or_default();
            let server_bytes =
                hex::decode(&server_pubkey_hex).map_err(|_| "invalid server public key")?;
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
            let err = reply
                .data
                .first()
                .cloned()
                .unwrap_or_else(|| "key exchange failed".into());
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
        let server_addr_display =
            env::var("SERVER_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
        println!(
            "{} {}. Login with: login <username> <password>",
            "Connected to".cyan(),
            server_addr_display.cyan()
        );
        println!(
            "{}",
            "Commands: login, logout, pwd, ls, cd, mkdir, touch, mv, delete, cat, echo".yellow()
        );
        println!(
            "{}",
            "          chmod, chown, chgrp, cp, find, scan, whoami, tree, stat, du".yellow()
        );
        println!(
            "{}",
            "          head, tail, grep, ln, upload, download".yellow()
        );
        println!(
            "{}",
            "          new_user, new_group, lsusers, lsgroups".yellow()
        );
        println!(
            "{}",
            "          add_user_to_group, remove_user_from_group, get_encrypted_filename".yellow()
        );
        println!(
            "{}",
            "Tab for completion. Up/down for history. Ctrl+C or 'logout' to exit.".yellow()
        );
    }

    loop {
        // REPL with command history support
        let prompt = if quiet {
            "".to_string()
        } else {
            format!("{} ", ">".bold())
        };
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
            println!(
                "{}",
                format!("Sending command: {:?}", app_message.cmd).dimmed()
            );
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
                        println!(
                            "{}",
                            reply.data.first().unwrap_or(&"login failed".into()).red()
                        );
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
                    Cmd::Failure => println!(
                        "error: {}",
                        reply.data.first().unwrap_or(&"lsusers failed".into()).red()
                    ),
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
                    Cmd::Failure => println!(
                        "error: {}",
                        reply
                            .data
                            .first()
                            .unwrap_or(&"lsgroups failed".into())
                            .red()
                    ),
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
                    Cmd::NewUser => println!(
                        "user created: {}",
                        reply.data.first().unwrap_or(&"".into()).green()
                    ),
                    Cmd::Failure => println!(
                        "{}",
                        reply.data.first().unwrap_or(&"newuser failed".into()).red()
                    ),
                    _ => println!("{}", "unexpected reply".red()),
                }
            }
            Cmd::NewGroup => {
                send(&mut ws_stream, &app_message, shared_secret_key.as_ref()).await?;
                let reply = recv(&mut ws_stream, shared_secret_key.as_ref()).await?;
                match reply.cmd {
                    Cmd::NewGroup => println!(
                        "group created: {}",
                        reply.data.first().unwrap_or(&"".into()).green()
                    ),
                    Cmd::Failure => println!(
                        "{}",
                        reply
                            .data
                            .first()
                            .unwrap_or(&"newgroup failed".into())
                            .red()
                    ),
                    _ => println!("{}", "unexpected reply".red()),
                }
            }
            Cmd::Cd => {
                send(&mut ws_stream, &app_message, shared_secret_key.as_ref()).await?;
                let reply = recv(&mut ws_stream, shared_secret_key.as_ref()).await?;
                match reply.cmd {
                    Cmd::Cd => println!("{}", reply.data.first().unwrap_or(&"/".into()).blue()),
                    Cmd::Failure => println!(
                        "{}",
                        reply.data.first().unwrap_or(&"cd failed".into()).red()
                    ),
                    _ => println!("{}", "unexpected reply".red()),
                }
            }
            Cmd::Pwd => {
                send(&mut ws_stream, &app_message, shared_secret_key.as_ref()).await?;
                let reply = recv(&mut ws_stream, shared_secret_key.as_ref()).await?;
                match reply.cmd {
                    Cmd::Pwd => {
                        let default_path = "/".to_string();
                        let path = reply.data.first().unwrap_or(&default_path);
                        println!("{}", path.blue());
                    }
                    Cmd::Failure => {
                        println!(
                            "{}",
                            reply.data.first().unwrap_or(&"pwd failed".into()).red()
                        );
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
                            println!();
                        } else {
                            for line in &reply.data {
                                if line.ends_with('/') {
                                    println!("{}", line.blue());
                                } else if line.contains(" -> ") {
                                    println!("{}", line.cyan());
                                } else {
                                    println!("{}", line);
                                }
                            }
                        }
                    }
                    Cmd::Failure => {
                        println!(
                            "{}",
                            reply.data.first().unwrap_or(&"ls failed".into()).red()
                        );
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
                        println!(
                            "{}",
                            reply.data.first().unwrap_or(&"mkdir failed".into()).red()
                        );
                    }
                    _ => println!("{}", "unexpected reply".red()),
                }
            }
            Cmd::Touch => {
                send(&mut ws_stream, &app_message, shared_secret_key.as_ref()).await?;
                let reply = recv(&mut ws_stream, shared_secret_key.as_ref()).await?;
                match reply.cmd {
                    Cmd::Touch => println!("{}", "ok".green()),
                    Cmd::Failure => println!(
                        "{}",
                        reply.data.first().unwrap_or(&"touch failed".into()).red()
                    ),
                    _ => println!("{}", "unexpected reply".red()),
                }
            }
            Cmd::Mv => {
                send(&mut ws_stream, &app_message, shared_secret_key.as_ref()).await?;
                let reply = recv(&mut ws_stream, shared_secret_key.as_ref()).await?;
                match reply.cmd {
                    Cmd::Mv => println!("{}", "ok".green()),
                    Cmd::Failure => println!(
                        "{}",
                        reply.data.first().unwrap_or(&"mv failed".into()).red()
                    ),
                    _ => println!("{}", "unexpected reply".red()),
                }
            }
            Cmd::Delete => {
                send(&mut ws_stream, &app_message, shared_secret_key.as_ref()).await?;
                let reply = recv(&mut ws_stream, shared_secret_key.as_ref()).await?;
                match reply.cmd {
                    Cmd::Delete => println!("{}", "ok".green()),
                    Cmd::Failure => println!(
                        "{}",
                        reply.data.first().unwrap_or(&"delete failed".into()).red()
                    ),
                    _ => println!("{}", "unexpected reply".red()),
                }
            }
            Cmd::Cat => {
                send(&mut ws_stream, &app_message, shared_secret_key.as_ref()).await?;
                let reply = recv(&mut ws_stream, shared_secret_key.as_ref()).await?;
                match reply.cmd {
                    Cmd::Cat => println!("{}", reply.data.first().unwrap_or(&"".into())),
                    Cmd::Failure => println!(
                        "{}",
                        reply.data.first().unwrap_or(&"cat failed".into()).red()
                    ),
                    _ => println!("{}", "unexpected reply".red()),
                }
            }
            Cmd::Echo => {
                // echo "<data>" filename
                send(&mut ws_stream, &app_message, shared_secret_key.as_ref()).await?;
                let reply = recv(&mut ws_stream, shared_secret_key.as_ref()).await?;
                match reply.cmd {
                    Cmd::Echo => println!("{}", "ok".green()),
                    Cmd::Failure => println!(
                        "{}",
                        reply.data.first().unwrap_or(&"echo failed".into()).red()
                    ),
                    _ => println!("{}", "unexpected reply".red()),
                }
            }
            Cmd::Chmod => {
                send(&mut ws_stream, &app_message, shared_secret_key.as_ref()).await?;
                let reply = recv(&mut ws_stream, shared_secret_key.as_ref()).await?;
                match reply.cmd {
                    Cmd::Chmod => println!("{}", "ok".green()),
                    Cmd::Failure => println!(
                        "{}",
                        reply.data.first().unwrap_or(&"chmod failed".into()).red()
                    ),
                    _ => println!("{}", "unexpected reply".red()),
                }
            }
            Cmd::Scan => {
                send(&mut ws_stream, &app_message, shared_secret_key.as_ref()).await?;
                let reply = recv(&mut ws_stream, shared_secret_key.as_ref()).await?;
                match reply.cmd {
                    Cmd::Scan => println!(
                        "{}",
                        reply.data.first().unwrap_or(&"scan ok".into()).green()
                    ),
                    Cmd::Failure => println!(
                        "{}",
                        reply.data.first().unwrap_or(&"scan failed".into()).red()
                    ),
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
                    Cmd::Failure => println!(
                        "{}",
                        reply
                            .data
                            .first()
                            .unwrap_or(&"failed to get encrypted file".into())
                            .red()
                    ),
                    _ => println!("{}", "unexpected reply".red()),
                }
            }
            Cmd::Cp => {
                send(&mut ws_stream, &app_message, shared_secret_key.as_ref()).await?;
                let reply = recv(&mut ws_stream, shared_secret_key.as_ref()).await?;
                match reply.cmd {
                    Cmd::Cp => println!("{}", "ok".green()),
                    Cmd::Failure => println!(
                        "{}",
                        reply.data.first().unwrap_or(&"cp failed".into()).red()
                    ),
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
                    Cmd::Failure => println!(
                        "{}",
                        reply.data.first().unwrap_or(&"find failed".into()).red()
                    ),
                    _ => println!("{}", "unexpected reply".red()),
                }
            }
            Cmd::Chown => {
                send(&mut ws_stream, &app_message, shared_secret_key.as_ref()).await?;
                let reply = recv(&mut ws_stream, shared_secret_key.as_ref()).await?;
                match reply.cmd {
                    Cmd::Chown => {
                        println!("{}", reply.data.first().unwrap_or(&"ok".into()).green())
                    }
                    Cmd::Failure => println!(
                        "{}",
                        reply.data.first().unwrap_or(&"chown failed".into()).red()
                    ),
                    _ => println!("{}", "unexpected reply".red()),
                }
            }
            Cmd::Chgrp => {
                send(&mut ws_stream, &app_message, shared_secret_key.as_ref()).await?;
                let reply = recv(&mut ws_stream, shared_secret_key.as_ref()).await?;
                match reply.cmd {
                    Cmd::Chgrp => {
                        println!("{}", reply.data.first().unwrap_or(&"ok".into()).green())
                    }
                    Cmd::Failure => println!(
                        "{}",
                        reply.data.first().unwrap_or(&"chgrp failed".into()).red()
                    ),
                    _ => println!("{}", "unexpected reply".red()),
                }
            }
            Cmd::AddUserToGroup => {
                send(&mut ws_stream, &app_message, shared_secret_key.as_ref()).await?;
                let reply = recv(&mut ws_stream, shared_secret_key.as_ref()).await?;
                match reply.cmd {
                    Cmd::AddUserToGroup => {
                        println!("{}", reply.data.first().unwrap_or(&"ok".into()).green())
                    }
                    Cmd::Failure => {
                        println!("{}", reply.data.first().unwrap_or(&"failed".into()).red())
                    }
                    _ => println!("{}", "unexpected reply".red()),
                }
            }
            Cmd::RemoveUserFromGroup => {
                send(&mut ws_stream, &app_message, shared_secret_key.as_ref()).await?;
                let reply = recv(&mut ws_stream, shared_secret_key.as_ref()).await?;
                match reply.cmd {
                    Cmd::RemoveUserFromGroup => {
                        println!("{}", reply.data.first().unwrap_or(&"ok".into()).green())
                    }
                    Cmd::Failure => {
                        println!("{}", reply.data.first().unwrap_or(&"failed".into()).red())
                    }
                    _ => println!("{}", "unexpected reply".red()),
                }
            }
            Cmd::Whoami => {
                send(&mut ws_stream, &app_message, shared_secret_key.as_ref()).await?;
                let reply = recv(&mut ws_stream, shared_secret_key.as_ref()).await?;
                match reply.cmd {
                    Cmd::Whoami => {
                        let user = reply.data.first().cloned().unwrap_or_default();
                        let group = reply.data.get(1).cloned().unwrap_or_default();
                        println!("user: {}  group: {}", user.green(), group.blue());
                    }
                    Cmd::Failure => println!(
                        "{}",
                        reply.data.first().unwrap_or(&"whoami failed".into()).red()
                    ),
                    _ => println!("{}", "unexpected reply".red()),
                }
            }
            Cmd::Tree => {
                send(&mut ws_stream, &app_message, shared_secret_key.as_ref()).await?;
                let reply = recv(&mut ws_stream, shared_secret_key.as_ref()).await?;
                match reply.cmd {
                    Cmd::Tree => {
                        for line in &reply.data {
                            println!("{}", line);
                        }
                    }
                    Cmd::Failure => println!(
                        "{}",
                        reply.data.first().unwrap_or(&"tree failed".into()).red()
                    ),
                    _ => println!("{}", "unexpected reply".red()),
                }
            }
            Cmd::Stat => {
                send(&mut ws_stream, &app_message, shared_secret_key.as_ref()).await?;
                let reply = recv(&mut ws_stream, shared_secret_key.as_ref()).await?;
                match reply.cmd {
                    Cmd::Stat => {
                        for line in &reply.data {
                            println!("{}", line);
                        }
                    }
                    Cmd::Failure => println!(
                        "{}",
                        reply.data.first().unwrap_or(&"stat failed".into()).red()
                    ),
                    _ => println!("{}", "unexpected reply".red()),
                }
            }
            Cmd::Du => {
                send(&mut ws_stream, &app_message, shared_secret_key.as_ref()).await?;
                let reply = recv(&mut ws_stream, shared_secret_key.as_ref()).await?;
                match reply.cmd {
                    Cmd::Du => println!("{}", reply.data.first().unwrap_or(&"0 B".into())),
                    Cmd::Failure => println!(
                        "{}",
                        reply.data.first().unwrap_or(&"du failed".into()).red()
                    ),
                    _ => println!("{}", "unexpected reply".red()),
                }
            }
            Cmd::Head => {
                send(&mut ws_stream, &app_message, shared_secret_key.as_ref()).await?;
                let reply = recv(&mut ws_stream, shared_secret_key.as_ref()).await?;
                match reply.cmd {
                    Cmd::Head => println!("{}", reply.data.first().unwrap_or(&"".into())),
                    Cmd::Failure => println!(
                        "{}",
                        reply.data.first().unwrap_or(&"head failed".into()).red()
                    ),
                    _ => println!("{}", "unexpected reply".red()),
                }
            }
            Cmd::Tail => {
                send(&mut ws_stream, &app_message, shared_secret_key.as_ref()).await?;
                let reply = recv(&mut ws_stream, shared_secret_key.as_ref()).await?;
                match reply.cmd {
                    Cmd::Tail => println!("{}", reply.data.first().unwrap_or(&"".into())),
                    Cmd::Failure => println!(
                        "{}",
                        reply.data.first().unwrap_or(&"tail failed".into()).red()
                    ),
                    _ => println!("{}", "unexpected reply".red()),
                }
            }
            Cmd::Grep => {
                send(&mut ws_stream, &app_message, shared_secret_key.as_ref()).await?;
                let reply = recv(&mut ws_stream, shared_secret_key.as_ref()).await?;
                match reply.cmd {
                    Cmd::Grep => {
                        for line in &reply.data {
                            println!("{}", line);
                        }
                    }
                    Cmd::Failure => println!(
                        "{}",
                        reply.data.first().unwrap_or(&"grep failed".into()).red()
                    ),
                    _ => println!("{}", "unexpected reply".red()),
                }
            }
            Cmd::Ln => {
                send(&mut ws_stream, &app_message, shared_secret_key.as_ref()).await?;
                let reply = recv(&mut ws_stream, shared_secret_key.as_ref()).await?;
                match reply.cmd {
                    Cmd::Ln => println!("{}", "ok".green()),
                    Cmd::Failure => println!(
                        "{}",
                        reply.data.first().unwrap_or(&"ln failed".into()).red()
                    ),
                    _ => println!("{}", "unexpected reply".red()),
                }
            }
            Cmd::UploadStart => {
                // upload <remote_name> — reads from stdin-like flow
                // Client must have provided: upload <filename>
                // We read the local file with same name from cwd
                let file_name = app_message.data.first().cloned().unwrap_or_default();
                let local_data = match stdfs::read(&file_name) {
                    Ok(d) => d,
                    Err(e) => {
                        println!("{}", format!("cannot read local file: {}", e).red());
                        continue;
                    }
                };

                // Send UploadStart
                send(&mut ws_stream, &app_message, shared_secret_key.as_ref()).await?;
                let reply = recv(&mut ws_stream, shared_secret_key.as_ref()).await?;
                if reply.cmd != Cmd::UploadStart {
                    println!(
                        "{}",
                        reply
                            .data
                            .first()
                            .unwrap_or(&"upload start failed".into())
                            .red()
                    );
                    continue;
                }

                // Send chunks
                let b64 = base64::engine::general_purpose::STANDARD;
                let chunk_size = 64 * 1024;
                let total_chunks = local_data.len().div_ceil(chunk_size);
                for (i, chunk) in local_data.chunks(chunk_size).enumerate() {
                    let chunk_msg = AppMessage {
                        cmd: Cmd::UploadChunk,
                        data: vec![b64.encode(chunk)],
                    };
                    send(&mut ws_stream, &chunk_msg, shared_secret_key.as_ref()).await?;
                    let cr = recv(&mut ws_stream, shared_secret_key.as_ref()).await?;
                    if cr.cmd != Cmd::UploadChunk {
                        println!("{}", format!("chunk {} failed: {:?}", i, cr.data).red());
                        break;
                    }
                    if !quiet {
                        print!(
                            "\r{}",
                            format!("uploading {}/{}", i + 1, total_chunks).dimmed()
                        );
                        let _ = std::io::stdout().flush();
                    }
                }
                if !quiet {
                    println!();
                }

                // Send UploadEnd
                let end_msg = AppMessage {
                    cmd: Cmd::UploadEnd,
                    data: vec![],
                };
                send(&mut ws_stream, &end_msg, shared_secret_key.as_ref()).await?;
                let end_reply = recv(&mut ws_stream, shared_secret_key.as_ref()).await?;
                match end_reply.cmd {
                    Cmd::UploadEnd => {
                        println!("{}", end_reply.data.first().unwrap_or(&"ok".into()).green())
                    }
                    Cmd::Failure => println!(
                        "{}",
                        end_reply
                            .data
                            .first()
                            .unwrap_or(&"upload failed".into())
                            .red()
                    ),
                    _ => println!("{}", "unexpected reply".red()),
                }
            }
            Cmd::DownloadStart => {
                let file_name = app_message.data.first().cloned().unwrap_or_default();

                // Send DownloadStart
                send(&mut ws_stream, &app_message, shared_secret_key.as_ref()).await?;
                let reply = recv(&mut ws_stream, shared_secret_key.as_ref()).await?;
                if reply.cmd != Cmd::DownloadStart {
                    println!(
                        "{}",
                        reply
                            .data
                            .first()
                            .unwrap_or(&"download failed".into())
                            .red()
                    );
                    continue;
                }

                let total_chunks: usize =
                    reply.data.first().and_then(|s| s.parse().ok()).unwrap_or(0);
                let total_bytes: usize =
                    reply.data.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);

                // Fetch each chunk
                let b64 = base64::engine::general_purpose::STANDARD;
                let mut content = Vec::with_capacity(total_bytes);
                for i in 0..total_chunks {
                    let chunk_msg = AppMessage {
                        cmd: Cmd::DownloadChunk,
                        data: vec![i.to_string()],
                    };
                    send(&mut ws_stream, &chunk_msg, shared_secret_key.as_ref()).await?;
                    let cr = recv(&mut ws_stream, shared_secret_key.as_ref()).await?;
                    if cr.cmd != Cmd::DownloadChunk {
                        println!("{}", format!("chunk {} failed: {:?}", i, cr.data).red());
                        break;
                    }
                    if let Some(b64_data) = cr.data.get(1) {
                        if let Ok(bytes) = b64.decode(b64_data) {
                            content.extend_from_slice(&bytes);
                        }
                    }
                    if !quiet {
                        print!(
                            "\r{}",
                            format!("downloading {}/{}", i + 1, total_chunks).dimmed()
                        );
                        let _ = std::io::stdout().flush();
                    }
                }
                if !quiet {
                    println!();
                }

                // Send DownloadEnd
                let end_msg = AppMessage {
                    cmd: Cmd::DownloadEnd,
                    data: vec![],
                };
                send(&mut ws_stream, &end_msg, shared_secret_key.as_ref()).await?;
                let _ = recv(&mut ws_stream, shared_secret_key.as_ref()).await?;

                // Write to local file
                match stdfs::write(&file_name, &content) {
                    Ok(_) => println!(
                        "{}",
                        format!("{} bytes saved to {}", content.len(), file_name).green()
                    ),
                    Err(e) => println!("{}", format!("write failed: {}", e).red()),
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
    let cmd_str = match parts.first() {
        Some(c) => c.clone(),
        None => return Err("missing command".into()),
    };
    let num_args = Cmd::num_args(cmd_str.clone()).unwrap_or(usize::MAX);
    if num_args < usize::MAX && parts.len() != num_args {
        return Err(format!(
            "expected {} args for '{}', got {}",
            num_args - 1,
            cmd_str,
            parts.len() - 1
        ));
    }
    let args = parts.split_off(1);
    let cmd =
        Cmd::from_str(cmd_str.clone()).map_err(|_| format!("unknown command: {}", cmd_str))?;
    Ok(AppMessage { cmd, data: args })
}

use aes_gcm::aead::{Aead, AeadCore};
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

/// Encrypt and send message
async fn send(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    msg: &AppMessage,
    key: Option<&Key<Aes256Gcm>>,
) -> Result<(), String> {
    let payload = if let Some(k) = key {
        let cipher = Aes256Gcm::new(k);
        let nonce = Aes256Gcm::generate_nonce(OsRng);
        let msg_str = serde_json::to_string(msg).map_err(|e| e.to_string())?;
        let ciphertext = cipher
            .encrypt(&nonce, msg_str.as_bytes())
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
async fn recv(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    key: Option<&Key<Aes256Gcm>>,
) -> Result<AppMessage, String> {
    let msg = ws
        .next()
        .await
        .ok_or("connection closed".to_string())?
        .map_err(|e| format!("recv failed: {}", e))?;
    if !msg.is_text() {
        return Err("non-text message".into());
    }
    let text = msg.to_text().unwrap();

    if let Some(k) = key {
        let (ciphertext_hex, nonce_bytes): (String, [u8; 12]) =
            serde_json::from_str(text).map_err(|e| format!("encrypted decode failed: {}", e))?;
        let cipher = Aes256Gcm::new(k);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext =
            hex::decode(ciphertext_hex).map_err(|_| "invalid ciphertext hex".to_string())?;
        let plaintext = cipher
            .decrypt(nonce, ciphertext.as_ref())
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
    println!("    -t, --tls           Use TLS (wss://) connection");
    println!();
    println!("ENVIRONMENT:");
    println!("    SERVER_ADDR         Default server address");
    println!("    USE_TLS             Enable TLS (set to 1 or true)");
}
