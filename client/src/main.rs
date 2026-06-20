//! SecureFS command-line client.
//!
//! Establishes a WebSocket connection to the server and forwards CLI
//! commands to protocol messages.

use std::env;

use colored::Colorize;
use rustyline::{CompletionType, Config, Editor};
use tokio::runtime::Runtime;

mod cli;
mod commands;
mod parse;
mod repl;
mod transport;

use cli::{print_help, SecureFsHelper};
use repl::connect_and_run;

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
    let mut use_tls = true;
    let mut server_addr_arg = None;

    for arg in args.iter().skip(1) {
        match arg.as_str() {
            "-v" | "--verbose" => verbose = true,
            "-q" | "--quiet" => quiet = true,
            "-t" | "--tls" => use_tls = true,
            "-k" | "--insecure" | "--no-tls" => use_tls = false,
            s if !s.starts_with("-") => server_addr_arg = Some(s.to_string()),
            _ => {}
        }
    }

    // Env overrides: USE_TLS forces TLS on; ALLOW_INSECURE/INSECURE forces it off.
    if env::var("USE_TLS")
        .map(|v| v == "1" || v.to_lowercase() == "true")
        .unwrap_or(false)
    {
        use_tls = true;
    }
    if env::var("ALLOW_INSECURE")
        .or_else(|_| env::var("INSECURE"))
        .map(|v| v == "1" || v.to_lowercase() == "true")
        .unwrap_or(false)
    {
        use_tls = false;
    }

    let bind = env::var("SERVER_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let server_addr = server_addr_arg.unwrap_or(bind);
    let scheme = if use_tls { "wss" } else { "ws" };
    let url = format!("{}://{}", scheme, server_addr);

    if !use_tls {
        eprintln!(
            "{}",
            "[WARNING] plaintext ws:// — traffic is not encrypted in transit; use TLS (default) \
             in production, --insecure for local dev only."
                .yellow()
        );
    }

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
