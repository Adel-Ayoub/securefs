use std::env;

use colored::Colorize;
use rand_core::OsRng;
use rustyline::error::ReadlineError;
use rustyline::Editor;
use securefs_proto::protocol::{AppMessage, Cmd};
use securefs_channel::secure_channel::{Role, SecureChannel, PROTOCOL_VERSION};
use tokio_tungstenite::connect_async;
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::cli::SecureFsHelper;
use crate::commands;
use crate::parse::{command_parser, read_credential_command};
use crate::transport::{recv, send};

pub async fn connect_and_run(
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

    // Send our public key and protocol version to the server
    let key_exchange_msg = AppMessage {
        cmd: Cmd::KeyExchangeInit,
        data: vec![
            hex::encode(client_public.as_bytes()),
            PROTOCOL_VERSION.to_string(),
        ],
    };
    send(&mut ws_stream, &key_exchange_msg, None).await?;

    // Receive server's public key and version
    let reply = recv(&mut ws_stream, None).await?;
    let shared_secret = match reply.cmd {
        Cmd::KeyExchangeResponse => {
            if reply.data.get(1).and_then(|v| v.parse::<u8>().ok()) != Some(PROTOCOL_VERSION) {
                return Err("server uses an incompatible protocol version".into());
            }
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

    let mut channel: Option<SecureChannel> =
        Some(SecureChannel::new(shared_secret.as_bytes(), Role::Client));

    if !quiet {
        // Use environment variable for server address in prompt or default
        let server_addr_display =
            env::var("SERVER_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
        println!(
            "{} {}. Login with: login <username>",
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
            "          totp_setup, totp_verify, audit_log, list_sessions, force_logout".yellow()
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

        // Credential commands prompt for the secret with masking and are never
        // written to history; everything else parses normally and is recorded.
        let cmd_word = line.split_whitespace().next().unwrap_or("").to_lowercase();
        let app_message = if cmd_word == "login" || cmd_word == "new_user" {
            match read_credential_command(&line) {
                Ok(msg) => msg,
                Err(err) => {
                    println!("{}", err.red());
                    continue;
                }
            }
        } else {
            let _ = rl.add_history_entry(&line);
            match command_parser(line.clone()) {
                Ok(msg) => msg,
                Err(err) => {
                    println!("{}", err.red());
                    continue;
                }
            }
        };

        if verbose {
            println!(
                "{}",
                format!("Sending command: {:?}", app_message.cmd).dimmed()
            );
        }

        match app_message.cmd {
            Cmd::Logout => {
                println!("bye");
                return Ok(());
            }
            Cmd::Cd
            | Cmd::Pwd
            | Cmd::Ls
            | Cmd::Mkdir
            | Cmd::Touch
            | Cmd::Mv
            | Cmd::Delete
            | Cmd::Cat
            | Cmd::Echo
            | Cmd::Chmod
            | Cmd::Scan
            | Cmd::GetEncryptedFile
            | Cmd::Cp
            | Cmd::Find
            | Cmd::Chown
            | Cmd::Chgrp
            | Cmd::Tree
            | Cmd::Stat
            | Cmd::Du
            | Cmd::Head
            | Cmd::Tail
            | Cmd::Grep
            | Cmd::Ln => commands::fs::handle(&mut ws_stream, &mut channel, &app_message).await?,
            Cmd::Login
            | Cmd::LsUsers
            | Cmd::LsGroups
            | Cmd::NewUser
            | Cmd::NewGroup
            | Cmd::AddUserToGroup
            | Cmd::RemoveUserFromGroup
            | Cmd::Whoami
            | Cmd::AuditLog
            | Cmd::TotpSetup
            | Cmd::TotpVerify
            | Cmd::ListSessions
            | Cmd::ForceLogout => {
                commands::admin::handle(&mut ws_stream, &mut channel, &app_message).await?
            }
            Cmd::UploadStart => {
                commands::transfer::upload(&mut ws_stream, &mut channel, &app_message, quiet)
                    .await?
            }
            Cmd::DownloadStart => {
                commands::transfer::download(&mut ws_stream, &mut channel, &app_message, quiet)
                    .await?
            }
            _ => println!("command not implemented"),
        }
    }
}
