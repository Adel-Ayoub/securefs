use colored::Colorize;
use securefs_proto::protocol::{AppMessage, Cmd};
use securefs_channel::secure_channel::SecureChannel;

use crate::transport::{recv, send, Ws};

pub async fn handle(
    ws: &mut Ws,
    channel: &mut Option<SecureChannel>,
    app_message: &AppMessage,
) -> Result<(), String> {
    match app_message.cmd {
        Cmd::Login => {
            send(ws, app_message, channel.as_mut()).await?;
            let reply = recv(ws, channel.as_mut()).await?;
            match reply.cmd {
                Cmd::Login => {
                    let default_admin = "false".to_string();
                    let is_admin = reply.data.get(1).unwrap_or(&default_admin);
                    // TOTP second factor required
                    if reply.data.get(2).map(|s| s.as_str()) == Some("totp_required") {
                        println!("{}", "totp verification required".yellow());
                        print!("enter 6-digit code: ");
                        std::io::Write::flush(&mut std::io::stdout()).ok();
                        let mut code = String::new();
                        std::io::stdin().read_line(&mut code).ok();
                        let totp_msg = AppMessage {
                            cmd: Cmd::TotpVerify,
                            data: vec![code.trim().to_string()],
                        };
                        send(ws, &totp_msg, channel.as_mut()).await?;
                        let totp_reply = recv(ws, channel.as_mut()).await?;
                        match totp_reply.cmd {
                            Cmd::TotpVerify => {
                                println!("{} (is_admin: {})", "login ok".green(), is_admin);
                            }
                            Cmd::Failure => {
                                println!(
                                    "{}",
                                    totp_reply
                                        .data
                                        .first()
                                        .unwrap_or(&"totp failed".into())
                                        .red()
                                );
                            }
                            _ => println!("{}", "unexpected totp reply".red()),
                        }
                    } else {
                        println!("{} (is_admin: {})", "login ok".green(), is_admin);
                    }
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
            send(ws, app_message, channel.as_mut()).await?;
            let reply = recv(ws, channel.as_mut()).await?;
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
            send(ws, app_message, channel.as_mut()).await?;
            let reply = recv(ws, channel.as_mut()).await?;
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
        Cmd::NewUser => {
            send(ws, app_message, channel.as_mut()).await?;
            let reply = recv(ws, channel.as_mut()).await?;
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
            send(ws, app_message, channel.as_mut()).await?;
            let reply = recv(ws, channel.as_mut()).await?;
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
        Cmd::AddUserToGroup => {
            send(ws, app_message, channel.as_mut()).await?;
            let reply = recv(ws, channel.as_mut()).await?;
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
            send(ws, app_message, channel.as_mut()).await?;
            let reply = recv(ws, channel.as_mut()).await?;
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
            send(ws, app_message, channel.as_mut()).await?;
            let reply = recv(ws, channel.as_mut()).await?;
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
        Cmd::AuditLog => {
            send(ws, app_message, channel.as_mut()).await?;
            let reply = recv(ws, channel.as_mut()).await?;
            match reply.cmd {
                Cmd::AuditLog => {
                    for line in &reply.data {
                        println!("{}", line);
                    }
                }
                Cmd::Failure => println!(
                    "{}",
                    reply
                        .data
                        .first()
                        .unwrap_or(&"audit_log failed".into())
                        .red()
                ),
                _ => println!("{}", "unexpected reply".red()),
            }
        }
        Cmd::TotpSetup => {
            send(ws, app_message, channel.as_mut()).await?;
            let reply = recv(ws, channel.as_mut()).await?;
            match reply.cmd {
                Cmd::TotpSetup => {
                    println!("{}", "TOTP setup successful".green());
                    if let Some(uri) = reply.data.first() {
                        println!("  URI: {}", uri);
                    }
                    if let Some(secret) = reply.data.get(1) {
                        println!("  Secret: {}", secret.yellow());
                    }
                    println!("{}", "  Verify with: totp_verify <code>".yellow());
                }
                Cmd::Failure => println!(
                    "{}",
                    reply
                        .data
                        .first()
                        .unwrap_or(&"totp_setup failed".into())
                        .red()
                ),
                _ => println!("{}", "unexpected reply".red()),
            }
        }
        Cmd::TotpVerify => {
            send(ws, app_message, channel.as_mut()).await?;
            let reply = recv(ws, channel.as_mut()).await?;
            match reply.cmd {
                Cmd::TotpVerify => println!("{}", "TOTP verified".green()),
                Cmd::Failure => println!(
                    "{}",
                    reply
                        .data
                        .first()
                        .unwrap_or(&"totp_verify failed".into())
                        .red()
                ),
                _ => println!("{}", "unexpected reply".red()),
            }
        }
        Cmd::ListSessions => {
            send(ws, app_message, channel.as_mut()).await?;
            let reply = recv(ws, channel.as_mut()).await?;
            match reply.cmd {
                Cmd::ListSessions => {
                    for line in &reply.data {
                        println!("{}", line);
                    }
                }
                Cmd::Failure => println!(
                    "{}",
                    reply
                        .data
                        .first()
                        .unwrap_or(&"list_sessions failed".into())
                        .red()
                ),
                _ => println!("{}", "unexpected reply".red()),
            }
        }
        Cmd::ForceLogout => {
            send(ws, app_message, channel.as_mut()).await?;
            let reply = recv(ws, channel.as_mut()).await?;
            match reply.cmd {
                Cmd::ForceLogout => {
                    println!("{}", reply.data.first().unwrap_or(&"ok".into()).green())
                }
                Cmd::Failure => println!(
                    "{}",
                    reply
                        .data
                        .first()
                        .unwrap_or(&"force_logout failed".into())
                        .red()
                ),
                _ => println!("{}", "unexpected reply".red()),
            }
        }
        _ => unreachable!("admin::handle received non-admin command"),
    }
    Ok(())
}
