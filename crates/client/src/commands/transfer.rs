use std::fs as stdfs;
use std::io::Write as _;

use base64::Engine;
use colored::Colorize;
use securefs_model::protocol::{AppMessage, Cmd};
use securefs_model::secure_channel::SecureChannel;

use crate::transport::{recv, send, Ws};

pub async fn upload(
    ws: &mut Ws,
    channel: &mut Option<SecureChannel>,
    app_message: &AppMessage,
    quiet: bool,
) -> Result<(), String> {
    // upload <remote_name> — reads from stdin-like flow
    // Client must have provided: upload <filename>
    // We read the local file with same name from cwd
    let file_name = app_message.data.first().cloned().unwrap_or_default();
    let local_data = match stdfs::read(&file_name) {
        Ok(d) => d,
        Err(e) => {
            println!("{}", format!("cannot read local file: {}", e).red());
            return Ok(());
        }
    };

    // Send UploadStart
    send(ws, app_message, channel.as_mut()).await?;
    let reply = recv(ws, channel.as_mut()).await?;
    if reply.cmd != Cmd::UploadStart {
        println!(
            "{}",
            reply
                .data
                .first()
                .unwrap_or(&"upload start failed".into())
                .red()
        );
        return Ok(());
    }

    // Send chunks
    let b64 = base64::engine::general_purpose::STANDARD;
    let chunk_size = 64 * 1024;
    let total_chunks = local_data.len().div_ceil(chunk_size);
    let mut complete = true;
    for (i, chunk) in local_data.chunks(chunk_size).enumerate() {
        let chunk_msg = AppMessage {
            cmd: Cmd::UploadChunk,
            data: vec![b64.encode(chunk)],
        };
        send(ws, &chunk_msg, channel.as_mut()).await?;
        let cr = recv(ws, channel.as_mut()).await?;
        if cr.cmd != Cmd::UploadChunk {
            println!("{}", format!("chunk {} failed: {:?}", i, cr.data).red());
            complete = false;
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

    if !complete {
        // Never finalize a truncated upload; the server discards the
        // partial buffer when the session ends.
        println!("{}", "upload aborted; file not saved".red());
        return Ok(());
    }

    // Send UploadEnd
    let end_msg = AppMessage {
        cmd: Cmd::UploadEnd,
        data: vec![],
    };
    send(ws, &end_msg, channel.as_mut()).await?;
    let end_reply = recv(ws, channel.as_mut()).await?;
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
    Ok(())
}

pub async fn download(
    ws: &mut Ws,
    channel: &mut Option<SecureChannel>,
    app_message: &AppMessage,
    quiet: bool,
) -> Result<(), String> {
    let file_name = app_message.data.first().cloned().unwrap_or_default();

    // Send DownloadStart
    send(ws, app_message, channel.as_mut()).await?;
    let reply = recv(ws, channel.as_mut()).await?;
    if reply.cmd != Cmd::DownloadStart {
        println!(
            "{}",
            reply
                .data
                .first()
                .unwrap_or(&"download failed".into())
                .red()
        );
        return Ok(());
    }

    let total_chunks: usize = reply.data.first().and_then(|s| s.parse().ok()).unwrap_or(0);
    let total_bytes: usize = reply.data.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let expected_hash = reply.data.get(2).cloned();

    // Fetch each chunk
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut content = Vec::with_capacity(total_bytes);
    let mut complete = true;
    for i in 0..total_chunks {
        let chunk_msg = AppMessage {
            cmd: Cmd::DownloadChunk,
            data: vec![i.to_string()],
        };
        send(ws, &chunk_msg, channel.as_mut()).await?;
        let cr = recv(ws, channel.as_mut()).await?;
        if cr.cmd != Cmd::DownloadChunk {
            println!("{}", format!("chunk {} failed: {:?}", i, cr.data).red());
            complete = false;
            break;
        }
        match cr.data.get(1).and_then(|d| b64.decode(d).ok()) {
            Some(bytes) => content.extend_from_slice(&bytes),
            None => {
                println!("{}", format!("chunk {} decode failed", i).red());
                complete = false;
                break;
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

    // Always release the server's download buffer.
    let end_msg = AppMessage {
        cmd: Cmd::DownloadEnd,
        data: vec![],
    };
    send(ws, &end_msg, channel.as_mut()).await?;
    let _ = recv(ws, channel.as_mut()).await?;

    // Only persist a fully received, integrity-verified file.
    let hash_ok = match &expected_hash {
        Some(h) if !h.is_empty() => hex::encode(blake3::hash(&content).as_bytes()) == *h,
        _ => true,
    };
    if !complete || content.len() != total_bytes {
        println!("{}", "download incomplete; file not saved".red());
    } else if !hash_ok {
        println!("{}", "integrity check failed; file not saved".red());
    } else {
        match stdfs::write(&file_name, &content) {
            Ok(_) => println!(
                "{}",
                format!("{} bytes saved to {}", content.len(), file_name).green()
            ),
            Err(e) => println!("{}", format!("write failed: {}", e).red()),
        }
    }
    Ok(())
}
