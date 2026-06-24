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
        Cmd::Cd => {
            send(ws, app_message, channel.as_mut()).await?;
            let reply = recv(ws, channel.as_mut()).await?;
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
            send(ws, app_message, channel.as_mut()).await?;
            let reply = recv(ws, channel.as_mut()).await?;
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
            send(ws, app_message, channel.as_mut()).await?;
            let reply = recv(ws, channel.as_mut()).await?;
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
            send(ws, app_message, channel.as_mut()).await?;
            let reply = recv(ws, channel.as_mut()).await?;
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
            send(ws, app_message, channel.as_mut()).await?;
            let reply = recv(ws, channel.as_mut()).await?;
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
            send(ws, app_message, channel.as_mut()).await?;
            let reply = recv(ws, channel.as_mut()).await?;
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
            send(ws, app_message, channel.as_mut()).await?;
            let reply = recv(ws, channel.as_mut()).await?;
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
            send(ws, app_message, channel.as_mut()).await?;
            let reply = recv(ws, channel.as_mut()).await?;
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
            send(ws, app_message, channel.as_mut()).await?;
            let reply = recv(ws, channel.as_mut()).await?;
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
            send(ws, app_message, channel.as_mut()).await?;
            let reply = recv(ws, channel.as_mut()).await?;
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
            send(ws, app_message, channel.as_mut()).await?;
            let reply = recv(ws, channel.as_mut()).await?;
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
            send(ws, app_message, channel.as_mut()).await?;
            let reply = recv(ws, channel.as_mut()).await?;
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
            send(ws, app_message, channel.as_mut()).await?;
            let reply = recv(ws, channel.as_mut()).await?;
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
            send(ws, app_message, channel.as_mut()).await?;
            let reply = recv(ws, channel.as_mut()).await?;
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
            send(ws, app_message, channel.as_mut()).await?;
            let reply = recv(ws, channel.as_mut()).await?;
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
            send(ws, app_message, channel.as_mut()).await?;
            let reply = recv(ws, channel.as_mut()).await?;
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
        Cmd::Tree => {
            send(ws, app_message, channel.as_mut()).await?;
            let reply = recv(ws, channel.as_mut()).await?;
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
            send(ws, app_message, channel.as_mut()).await?;
            let reply = recv(ws, channel.as_mut()).await?;
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
            send(ws, app_message, channel.as_mut()).await?;
            let reply = recv(ws, channel.as_mut()).await?;
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
            send(ws, app_message, channel.as_mut()).await?;
            let reply = recv(ws, channel.as_mut()).await?;
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
            send(ws, app_message, channel.as_mut()).await?;
            let reply = recv(ws, channel.as_mut()).await?;
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
            send(ws, app_message, channel.as_mut()).await?;
            let reply = recv(ws, channel.as_mut()).await?;
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
            send(ws, app_message, channel.as_mut()).await?;
            let reply = recv(ws, channel.as_mut()).await?;
            match reply.cmd {
                Cmd::Ln => println!("{}", "ok".green()),
                Cmd::Failure => println!(
                    "{}",
                    reply.data.first().unwrap_or(&"ln failed".into()).red()
                ),
                _ => println!("{}", "unexpected reply".red()),
            }
        }
        _ => unreachable!("fs::handle received non-fs command"),
    }
    Ok(())
}
