use rustyline::completion::{Completer, Pair};
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::{Context, Helper};

const COMMANDS: &[&str] = &[
    "audit_log",
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
    "force_logout",
    "get_encrypted_filename",
    "grep",
    "head",
    "list_sessions",
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
    "totp_setup",
    "totp_verify",
    "touch",
    "tree",
    "upload",
    "whoami",
    "add_user_to_group",
    "remove_user_from_group",
];

pub struct SecureFsHelper;

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

/// Print usage information.
pub fn print_help() {
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
    println!("    -t, --tls           Force TLS (wss://) — on by default");
    println!("    -k, --insecure      Use plaintext ws:// (local dev only)");
    println!();
    println!("ENVIRONMENT:");
    println!("    SERVER_ADDR         Default server address");
    println!("    USE_TLS             Force TLS (set to 1 or true)");
    println!("    ALLOW_INSECURE      Use plaintext ws:// (set to 1 or true)");
}
