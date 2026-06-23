use securefs_model::cmd::{MapStr, NumArgs};
use securefs_model::protocol::{AppMessage, Cmd};

/// Parse user input into an `AppMessage` understood by the server.
pub fn command_parser(input: String) -> Result<AppMessage, String> {
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

/// Build a login/new_user message, prompting for the password with masking so
/// it never appears on screen or in shell history.
pub fn read_credential_command(line: &str) -> Result<AppMessage, String> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    match parts.first().map(|s| s.to_lowercase()).as_deref() {
        Some("login") => {
            let user = parts.get(1).ok_or("usage: login <username>")?.to_string();
            let pass = match parts.get(2) {
                Some(p) => p.to_string(),
                None => rpassword::prompt_password("password: ")
                    .map_err(|e| format!("password read failed: {}", e))?,
            };
            Ok(AppMessage {
                cmd: Cmd::Login,
                data: vec![user, pass],
            })
        }
        Some("new_user") => {
            let name = parts
                .get(1)
                .ok_or("usage: new_user <username> <group>")?
                .to_string();
            let group = parts
                .get(2)
                .ok_or("usage: new_user <username> <group>")?
                .to_string();
            let pass = rpassword::prompt_password("password: ")
                .map_err(|e| format!("password read failed: {}", e))?;
            Ok(AppMessage {
                cmd: Cmd::NewUser,
                data: vec![name, pass, group],
            })
        }
        _ => Err("unknown credential command".into()),
    }
}
