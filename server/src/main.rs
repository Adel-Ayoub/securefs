//! WebSocket server for SecureFS.
//!
//! Accepts client connections, authenticates users, and translates
//! protocol commands into DAO/database operations and on-disk file
//! changes.

use std::env;
use std::sync::Arc;

use deadpool_postgres::{Config, ManagerConfig, Pool, RecyclingMethod, Runtime};
use futures_util::{SinkExt, StreamExt};
use log::{info, warn};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use securefs_model::protocol::{AppMessage, Cmd};
use securefs_model::secure_channel::SecureChannel;
use std::collections::HashMap;
use std::net::IpAddr;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Semaphore};
use tokio_postgres::NoTls;
use tokio_rustls::rustls;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::accept_async_with_config;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

use securefs_server::dao;
use securefs_server::health;
use securefs_server::logging;

mod crypto;
mod session;
mod util;

/// Audit log for security-relevant events.
/// Logs to stdout AND persists to the audit_log DB table.
#[macro_export]
macro_rules! audit {
    ($pool:expr, $event:expr, $user:expr, $resource:expr, $result:expr) => {{
        log::info!(
            "[AUDIT] {} | {} | {} | {}",
            $event,
            $user,
            $resource,
            $result
        );
        let pool_ref = $pool.clone();
        let ev = $event.to_string();
        let us = $user.to_string();
        let re = $resource.to_string();
        let rs = $result.to_string();
        tokio::spawn(async move {
            if let Err(e) =
                securefs_server::dao::insert_audit_log(&pool_ref, &ev, &us, &re, &rs, None).await
            {
                log::warn!("audit persist failed: {}", e);
            }
        });
    }};
}

mod handlers;

use session::{RateLimiter, Session, SessionInfo, SessionRegistry};

// DoS limits.
const MAX_MESSAGE_SIZE: usize = 1 << 20; // 1 MiB cap per WebSocket message/frame
const MAX_CONNECTIONS: usize = 1024; // concurrent connections accepted at once
const CONNECTION_IDLE_TIMEOUT_SECS: u64 = 1800; // close a connection idle this long
const SHUTDOWN_GRACE_SECS: u64 = 10; // drain window for in-flight connections

// WebSocket config bounding message/frame size to limit per-connection memory.
fn ws_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(MAX_MESSAGE_SIZE))
        .max_frame_size(Some(MAX_MESSAGE_SIZE))
}

// Resolves when the process receives SIGINT (Ctrl-C) or, on Unix, SIGTERM.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
}

/// Load TLS configuration from certificate and key files.
fn load_tls_config(cert_path: &str, key_path: &str) -> Result<TlsAcceptor, String> {
    let certs = CertificateDer::pem_file_iter(cert_path)
        .map_err(|e| format!("failed to read cert file: {}", e))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("failed to parse certs: {}", e))?;
    if certs.is_empty() {
        return Err("no certificates found in cert file".to_string());
    }

    let key = PrivateKeyDer::from_pem_file(key_path)
        .map_err(|e| format!("failed to read private key: {}", e))?;

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("invalid TLS config: {}", e))?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

#[tokio::main]
/// Launch the WebSocket server and connect to Postgres.
async fn main() -> Result<(), String> {
    // Subcommand used by the container HEALTHCHECK; probes /health and exits.
    if std::env::args().nth(1).as_deref() == Some("healthcheck") {
        let addr = env::var("HEALTH_ADDR").unwrap_or_else(|_| "127.0.0.1:8081".to_string());
        return health::run_healthcheck(&addr).await;
    }

    logging::init();
    info!("Starting SecureFS server");

    // NOTE: Default env fallbacks are for local/dev usage; production
    // deployments should provide explicit values.
    let allow_insecure = env::var("ALLOW_INSECURE").unwrap_or_default() == "1";

    let db_pass = dao::get_db_pass();
    if db_pass == "TEMP" && !allow_insecure {
        return Err(
            "refusing to start with the default DB_PASS; set a strong DB_PASS (or ALLOW_INSECURE=1 for development)"
                .into(),
        );
    }

    // At-rest file encryption uses its own secret; never silently reuse DB_PASS.
    match dao::data_key_secret() {
        Some(k) if k == "TEMP" && !allow_insecure => {
            return Err(
                "refusing to start with a default DATA_KEY; set a strong DATA_KEY (or ALLOW_INSECURE=1 for development)"
                    .into(),
            );
        }
        None if !allow_insecure => {
            return Err(
                "refusing to start without DATA_KEY; set DATA_KEY or DATA_KEY_FILE to a strong secret (or ALLOW_INSECURE=1 for development)"
                    .into(),
            );
        }
        _ => {}
    }
    let db_host = env::var("DB_HOST").unwrap_or_else(|_| "localhost".to_string());
    let db_name = env::var("DB_NAME").unwrap_or_else(|_| "db".to_string());
    let db_user = env::var("DB_USER").unwrap_or_else(|_| "USER".to_string());
    let db_port = env::var("DB_PORT").unwrap_or_else(|_| "5431".to_string());
    // The Postgres connection password can differ from DB_PASS (the pgcrypto
    // data key); fall back to DB_PASS when not set.
    let db_conn_pass = env::var("DB_CONN_PASSWORD").unwrap_or_else(|_| db_pass.clone());

    let mut pool_cfg = Config::new();
    pool_cfg.host = Some(db_host);
    pool_cfg.dbname = Some(db_name);
    pool_cfg.user = Some(db_user);
    pool_cfg.password = Some(db_conn_pass);
    pool_cfg.port = Some(db_port.parse().unwrap_or(5431));
    pool_cfg.manager = Some(ManagerConfig {
        recycling_method: RecyclingMethod::Fast,
    });
    let pool = pool_cfg
        .create_pool(Some(Runtime::Tokio1), NoTls)
        .map_err(|e| format!("pool creation failed: {}", e))?;

    dao::init_db(&pool)
        .await
        .map_err(|e| format!("database init failed: {}", e))?;

    let bind_addr = env::var("SERVER_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let listener = TcpListener::bind(&bind_addr)
        .await
        .map_err(|e| format!("bind failed: {}", e))?;

    // TLS configuration — required unless ALLOW_INSECURE=1 is set
    let tls_acceptor: Option<TlsAcceptor> = match (env::var("TLS_CERT"), env::var("TLS_KEY")) {
        (Ok(cert_path), Ok(key_path)) => {
            let acceptor = load_tls_config(&cert_path, &key_path)?;
            info!("TLS enabled (wss://)");
            Some(acceptor)
        }
        _ if allow_insecure => {
            eprintln!("============================================================");
            eprintln!("[SECURITY WARNING] ALLOW_INSECURE=1 — TLS is DISABLED.");
            eprintln!("[SECURITY WARNING] Traffic is UNENCRYPTED in transit.");
            eprintln!("[SECURITY WARNING] For local development ONLY — never in production.");
            eprintln!("============================================================");
            None
        }
        _ => {
            return Err(
                "TLS_CERT and TLS_KEY are required. Set ALLOW_INSECURE=1 to bypass for development."
                    .into(),
            );
        }
    };

    info!("Listening on: {}", bind_addr);

    // Shared rate limiter for IP-based tracking
    let rate_limiter: RateLimiter = Arc::new(Mutex::new(HashMap::new()));

    // Periodic cleanup of expired rate limiter entries
    {
        let rl = rate_limiter.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                session::cleanup_rate_limiter(&rl).await;
            }
        });
    }

    // Plaintext liveness/readiness endpoint on its own port.
    {
        let health_addr = env::var("HEALTH_ADDR").unwrap_or_else(|_| "127.0.0.1:8081".to_string());
        let pool = pool.clone();
        tokio::spawn(health::serve(pool, health_addr));
    }

    let session_registry: SessionRegistry = Arc::new(Mutex::new(HashMap::new()));
    let conn_limit = Arc::new(Semaphore::new(MAX_CONNECTIONS));

    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);

    loop {
        let (stream, addr) = tokio::select! {
            biased;
            _ = &mut shutdown => {
                info!("Shutdown signal received; no longer accepting connections");
                break;
            }
            accepted = listener.accept() => match accepted {
                Ok(pair) => pair,
                Err(e) => {
                    warn!("accept failed: {}", e);
                    continue;
                }
            },
        };

        // Bound concurrent connections; refuse (and close) when at capacity.
        let permit = match conn_limit.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                warn!(
                    "connection limit ({}) reached; refusing {}",
                    MAX_CONNECTIONS, addr
                );
                continue;
            }
        };

        info!("New connection from: {}", addr);
        let pg = pool.clone();
        let rl = rate_limiter.clone();
        let sr = session_registry.clone();
        let ip = addr.ip();
        let tls = tls_acceptor.clone();
        tokio::spawn(async move {
            let _permit = permit; // released when the connection ends
            let result = if let Some(acceptor) = tls {
                match acceptor.accept(stream).await {
                    Ok(tls_stream) => handle_tls_connection(tls_stream, pg, rl, sr, ip).await,
                    Err(e) => Err(format!("TLS handshake failed: {}", e)),
                }
            } else {
                handle_connection(stream, pg, rl, sr, ip).await
            };
            if let Err(e) = result {
                warn!("Connection error: {}", e);
            }
        });
    }

    // Best-effort graceful drain: wait for in-flight connections to finish.
    let in_flight = MAX_CONNECTIONS - conn_limit.available_permits();
    if in_flight > 0 {
        info!("Draining {} in-flight connection(s)...", in_flight);
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(SHUTDOWN_GRACE_SECS),
            conn_limit.acquire_many(MAX_CONNECTIONS as u32),
        )
        .await;
    }
    info!("Shutdown complete");
    Ok(())
}

/// Handle a TLS WebSocket connection lifecycle.
async fn handle_tls_connection(
    stream: tokio_rustls::server::TlsStream<TcpStream>,
    pool: Pool,
    rate_limiter: RateLimiter,
    session_registry: SessionRegistry,
    client_ip: IpAddr,
) -> Result<(), String> {
    let ws_stream = accept_async_with_config(stream, Some(ws_config()))
        .await
        .map_err(|e| format!("TLS handshake failed: {}", e))?;
    handle_ws_stream(ws_stream, pool, rate_limiter, session_registry, client_ip).await
}

/// Handle a plain TCP WebSocket connection lifecycle.
async fn handle_connection(
    stream: TcpStream,
    pool: Pool,
    rate_limiter: RateLimiter,
    session_registry: SessionRegistry,
    client_ip: IpAddr,
) -> Result<(), String> {
    let ws_stream = accept_async_with_config(stream, Some(ws_config()))
        .await
        .map_err(|e| format!("handshake failed: {}", e))?;
    handle_ws_stream(ws_stream, pool, rate_limiter, session_registry, client_ip).await
}

/// Serialize and send an application message over the websocket.
async fn send_app_message<S>(
    ws_stream: &mut WebSocketStream<S>,
    resp: AppMessage,
    channel: Option<&mut SecureChannel>,
) -> Result<(), String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let payload = match channel {
        Some(ch) => ch.seal(&resp)?,
        None => serde_json::to_string(&resp).map_err(|e| e.to_string())?,
    };
    ws_stream
        .send(Message::Text(payload.into()))
        .await
        .map_err(|e| format!("send failed: {}", e))
}

const SESSION_TIMEOUT_SECS: u64 = 1800;

/// Handle WebSocket stream logic (shared between TLS and plain TCP).
async fn handle_ws_stream<S>(
    mut ws_stream: WebSocketStream<S>,
    pool: Pool,
    rate_limiter: RateLimiter,
    session_registry: SessionRegistry,
    client_ip: IpAddr,
) -> Result<(), String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut session = Session::new();
    let mut channel: Option<SecureChannel> = None;
    let mut last_activity = std::time::Instant::now();
    let session_id = uuid::Uuid::new_v4().to_string();

    loop {
        let msg = match tokio::time::timeout(
            std::time::Duration::from_secs(CONNECTION_IDLE_TIMEOUT_SECS),
            ws_stream.next(),
        )
        .await
        {
            Ok(Some(m)) => m.map_err(|e| format!("ws read failed: {}", e))?,
            Ok(None) => break,
            Err(_) => {
                warn!(
                    "connection idle timeout ({}s)",
                    CONNECTION_IDLE_TIMEOUT_SECS
                );
                break;
            }
        };
        if !msg.is_text() {
            continue;
        }

        // Decrypt over the secure channel once established, else parse plaintext
        let text = msg
            .to_text()
            .map_err(|e| format!("ws message error: {}", e))?;
        let incoming: AppMessage = if let Some(ch) = channel.as_mut() {
            ch.open(text)?
        } else {
            serde_json::from_str(text).map_err(|e| format!("decode failed: {}", e))?
        };

        // Check session timeout for authenticated sessions
        if session.authenticated && last_activity.elapsed().as_secs() > SESSION_TIMEOUT_SECS {
            warn!(
                "Session expired for user {:?} after {} seconds of inactivity",
                session.current_user,
                last_activity.elapsed().as_secs()
            );
            session_registry.lock().await.remove(&session_id);
            session.reset();
        }

        last_activity = std::time::Instant::now();

        // Check if admin flagged this session for forced logout
        {
            let reg = session_registry.lock().await;
            if let Some(info) = reg.get(&session_id) {
                if info.force_logout {
                    drop(reg);
                    session_registry.lock().await.remove(&session_id);
                    session.reset();
                    let reply = AppMessage {
                        cmd: Cmd::Logout,
                        data: vec!["session terminated by admin".into()],
                    };
                    send_app_message(&mut ws_stream, reply, channel.as_mut()).await?;
                    break;
                }
            }
        }

        // Update last_activity in registry
        if session.authenticated {
            if let Some(info) = session_registry.lock().await.get_mut(&session_id) {
                info.last_activity = std::time::Instant::now();
            }
        }

        // Require an established secure channel before anything but the
        // handshake — credentials must never travel over plaintext.
        if channel.is_none() && !matches!(incoming.cmd, Cmd::NewConnection | Cmd::KeyExchangeInit) {
            let reply = AppMessage {
                cmd: Cmd::Failure,
                data: vec!["secure channel required: perform key exchange first".into()],
            };
            send_app_message(&mut ws_stream, reply, None).await?;
            continue;
        }

        // Block all commands except TotpVerify/Logout while TOTP is pending
        if session.totp_required && !matches!(incoming.cmd, Cmd::TotpVerify | Cmd::Logout) {
            let reply = AppMessage {
                cmd: Cmd::Failure,
                data: vec!["totp verification required".into()],
            };
            send_app_message(&mut ws_stream, reply, channel.as_mut()).await?;
            continue;
        }

        // Dispatch command to appropriate handler module
        let (reply, new_secret) = match incoming.cmd {
            Cmd::NewConnection => (handlers::auth::new_connection(), None),
            Cmd::Login => (
                handlers::auth::login(incoming.data, &mut session, &pool, &rate_limiter, client_ip)
                    .await,
                None,
            ),
            Cmd::Logout => (handlers::auth::logout(&mut session), None),
            Cmd::KeyExchangeInit => handlers::auth::key_exchange(incoming.data),
            Cmd::LsUsers => (handlers::user::ls_users(&session, &pool).await, None),
            Cmd::LsGroups => (handlers::user::ls_groups(&session, &pool).await, None),
            Cmd::NewUser => (
                handlers::user::new_user(incoming.data, &session, &pool).await,
                None,
            ),
            Cmd::NewGroup => (
                handlers::user::new_group(incoming.data, &session, &pool).await,
                None,
            ),
            Cmd::AddUserToGroup => (
                handlers::user::add_user_to_group(incoming.data, &session, &pool).await,
                None,
            ),
            Cmd::RemoveUserFromGroup => (
                handlers::user::remove_user_from_group(incoming.data, &session, &pool).await,
                None,
            ),
            Cmd::Pwd => (handlers::fs::pwd(&session), None),
            Cmd::Cd => (
                handlers::fs::cd(incoming.data, &mut session, &pool).await,
                None,
            ),
            Cmd::Ls => (handlers::fs::ls(&session, &pool).await, None),
            Cmd::Find => (
                handlers::fs::find(incoming.data, &session, &pool).await,
                None,
            ),
            Cmd::Mkdir => (
                handlers::fs::mkdir(incoming.data, &session, &pool).await,
                None,
            ),
            Cmd::Touch => (
                handlers::fs::touch(incoming.data, &session, &pool).await,
                None,
            ),
            Cmd::Delete => (
                handlers::fs::delete(incoming.data, &session, &pool).await,
                None,
            ),
            Cmd::Mv => (handlers::fs::mv(incoming.data, &session, &pool).await, None),
            Cmd::Cp => (handlers::fs::cp(incoming.data, &session, &pool).await, None),
            Cmd::Cat => (
                handlers::fs::cat(incoming.data, &session, &pool).await,
                None,
            ),
            Cmd::Echo => (
                handlers::fs::echo(incoming.data, &session, &pool).await,
                None,
            ),
            Cmd::Chmod => (
                handlers::perms::chmod(incoming.data, &session, &pool).await,
                None,
            ),
            Cmd::Chown => (
                handlers::perms::chown(incoming.data, &session, &pool).await,
                None,
            ),
            Cmd::Chgrp => (
                handlers::perms::chgrp(incoming.data, &session, &pool).await,
                None,
            ),
            Cmd::Scan => (
                handlers::perms::scan(incoming.data, &session, &pool).await,
                None,
            ),
            Cmd::GetEncryptedFile => (
                handlers::perms::get_encrypted_file(incoming.data, &session, &pool).await,
                None,
            ),
            Cmd::Whoami => (handlers::user::whoami(&session), None),
            Cmd::Tree => (handlers::fs::tree(&session, &pool).await, None),
            Cmd::Stat => (
                handlers::fs::stat(incoming.data, &session, &pool).await,
                None,
            ),
            Cmd::Du => (handlers::fs::du(&session, &pool).await, None),
            Cmd::Head => (
                handlers::fs::head(incoming.data, &session, &pool).await,
                None,
            ),
            Cmd::Tail => (
                handlers::fs::tail(incoming.data, &session, &pool).await,
                None,
            ),
            Cmd::Grep => (
                handlers::fs::grep(incoming.data, &session, &pool).await,
                None,
            ),
            Cmd::Ln => (handlers::fs::ln(incoming.data, &session, &pool).await, None),
            Cmd::UploadStart => (
                handlers::fs::upload_start(incoming.data, &mut session, &pool).await,
                None,
            ),
            Cmd::UploadChunk => (
                handlers::fs::upload_chunk(incoming.data, &mut session),
                None,
            ),
            Cmd::UploadEnd => (handlers::fs::upload_end(&mut session, &pool).await, None),
            Cmd::DownloadStart => (
                handlers::fs::download_start(incoming.data, &mut session, &pool).await,
                None,
            ),
            Cmd::DownloadChunk => (handlers::fs::download_chunk(incoming.data, &session), None),
            Cmd::DownloadEnd => (handlers::fs::download_end(&mut session), None),
            Cmd::AuditLog => (
                handlers::audit::audit_log(incoming.data, &session, &pool).await,
                None,
            ),
            Cmd::TotpSetup => (handlers::auth::totp_setup(&session, &pool).await, None),
            Cmd::TotpVerify => (
                handlers::auth::totp_verify(
                    incoming.data,
                    &mut session,
                    &pool,
                    &rate_limiter,
                    client_ip,
                )
                .await,
                None,
            ),
            Cmd::ListSessions => (
                handlers::sessions::list_sessions(&session, &pool, &session_registry).await,
                None,
            ),
            Cmd::ForceLogout => (
                handlers::sessions::force_logout(incoming.data, &session, &pool, &session_registry)
                    .await,
                None,
            ),
            _ => (
                AppMessage {
                    cmd: Cmd::Failure,
                    data: vec!["command not implemented".to_string()],
                },
                None,
            ),
        };

        // Register session in registry on successful login
        if matches!(reply.cmd, Cmd::Login) && session.authenticated {
            let now = std::time::Instant::now();
            session_registry.lock().await.insert(
                session_id.clone(),
                SessionInfo {
                    session_id: session_id.clone(),
                    username: session.current_user.clone().unwrap_or_default(),
                    client_ip,
                    connected_at: now,
                    last_activity: now,
                    force_logout: false,
                },
            );
        }

        let is_logout = matches!(reply.cmd, Cmd::Logout);
        send_app_message(&mut ws_stream, reply, channel.as_mut()).await?;

        if let Some(s) = new_secret {
            channel = Some(s);
        }

        if !session.authenticated && is_logout {
            session_registry.lock().await.remove(&session_id);
            break;
        }
    }

    // Deregister on disconnect
    session_registry.lock().await.remove(&session_id);
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::util::*;
    use securefs_model::protocol::FNode;

    #[test]
    fn test_normalize_path() {
        assert_eq!(normalize_path("/home/user".into()), "/home/user");
        assert_eq!(normalize_path("/home/user/".into()), "/home/user");
        assert_eq!(normalize_path("/home/./user".into()), "/home/user");
        assert_eq!(normalize_path("/home/user/..".into()), "/home");
        assert_eq!(normalize_path("/home/../root".into()), "/root");
        assert_eq!(normalize_path("/../..".into()), "/");
    }

    #[test]
    fn test_is_valid_name() {
        assert!(is_valid_name("file.txt"));
        assert!(is_valid_name("mydir"));
        assert!(!is_valid_name(""));
        assert!(!is_valid_name("."));
        assert!(!is_valid_name(".."));
        assert!(!is_valid_name("dir/subdir"));
        assert!(!is_valid_name("file\0name"));
    }

    #[test]
    fn test_format_permissions() {
        assert_eq!(format_permissions(7, 5, 4), "rwxr-xr--");
        assert_eq!(format_permissions(6, 4, 0), "rw-r-----");
        assert_eq!(format_permissions(0, 0, 0), "---------");
    }

    #[test]
    fn test_permission_helpers() {
        let node = FNode {
            id: 1,
            name: "test.txt".to_string(),
            path: "/home/user/test.txt".to_string(),
            owner: "alice".to_string(),
            hash: "".to_string(),
            parent: "/home/user".to_string(),
            dir: false,
            u: 6,
            g: 4,
            o: 4,
            children: vec![],
            encrypted_name: "".to_string(),
            size: 0,
            created_at: 0,
            modified_at: 0,
            file_group: None,
            link_target: None,
        };

        assert!(can_read(&node, Some(&"alice".to_string())));
        assert!(can_read(&node, Some(&"bob".to_string())));
        assert!(can_read(&node, None));

        assert!(can_write(&node, Some(&"alice".to_string())));
        assert!(!can_write(&node, Some(&"bob".to_string())));
        assert!(!can_write(&node, None));

        assert!(!can_execute(&node, Some(&"alice".to_string())));
        assert!(!can_execute(&node, Some(&"bob".to_string())));

        assert!(is_owner(&node, Some(&"alice".to_string())));
        assert!(!is_owner(&node, Some(&"bob".to_string())));
        assert!(!is_owner(&node, None));
    }

    #[test]
    fn test_group_permission_helpers() {
        let node = FNode {
            id: 1,
            name: "project.rs".to_string(),
            path: "/home/alice/project.rs".to_string(),
            owner: "alice".to_string(),
            hash: "".to_string(),
            parent: "/home/alice".to_string(),
            dir: false,
            u: 6,
            g: 4,
            o: 0,
            children: vec![],
            encrypted_name: "".to_string(),
            size: 0,
            created_at: 0,
            modified_at: 0,
            file_group: Some("devs".to_string()),
            link_target: None,
        };

        let owner_group = Some("devs".to_string());
        let alice_group = Some("devs".to_string());
        let bob_group = Some("devs".to_string());
        let charlie_group = Some("users".to_string());

        assert!(can_read_with_group(
            &node,
            Some(&"alice".to_string()),
            alice_group.as_ref(),
            owner_group.as_ref()
        ));
        assert!(can_read_with_group(
            &node,
            Some(&"bob".to_string()),
            bob_group.as_ref(),
            owner_group.as_ref()
        ));
        assert!(!can_read_with_group(
            &node,
            Some(&"charlie".to_string()),
            charlie_group.as_ref(),
            owner_group.as_ref()
        ));
        assert!(!can_read_with_group(
            &node,
            None,
            None,
            owner_group.as_ref()
        ));
        assert!(!can_write_with_group(
            &node,
            Some(&"bob".to_string()),
            bob_group.as_ref(),
            owner_group.as_ref()
        ));
    }

    #[test]
    fn test_is_valid_password() {
        assert!(is_valid_password("password123"));
        assert!(is_valid_password("12345678"));
        assert!(is_valid_password("abcdefgh"));
        assert!(!is_valid_password(""));
        assert!(!is_valid_password("short"));
        assert!(!is_valid_password("1234567"));
    }

    #[test]
    fn test_x25519_key_exchange() {
        use rand_core::OsRng;
        use x25519_dalek::{EphemeralSecret, PublicKey};

        let client_secret = EphemeralSecret::random_from_rng(OsRng);
        let client_public = PublicKey::from(&client_secret);

        let server_secret = EphemeralSecret::random_from_rng(OsRng);
        let server_public = PublicKey::from(&server_secret);

        let client_shared = client_secret.diffie_hellman(&server_public);
        let server_shared = server_secret.diffie_hellman(&client_public);

        assert_eq!(client_shared.as_bytes(), server_shared.as_bytes());
    }

    #[test]
    fn test_is_safe_path() {
        assert!(is_safe_path("/home"));
        assert!(is_safe_path("/home/user"));
        assert!(is_safe_path("/home/user/docs"));
        assert!(is_safe_path("/home/user/a/b/c"));

        assert!(!is_safe_path("/homeevil"));
        assert!(!is_safe_path("/homedir"));

        assert!(!is_safe_path("/"));
        assert!(!is_safe_path("/etc/passwd"));
        assert!(!is_safe_path("/root"));
        assert!(!is_safe_path("/tmp"));
        assert!(!is_safe_path(""));

        assert!(!is_safe_path("/home/user\0"));
        assert!(!is_safe_path("/home/\0evil"));

        let deep_ok = format!(
            "/home/{}",
            (0..62)
                .map(|i| format!("d{}", i))
                .collect::<Vec<_>>()
                .join("/")
        );
        assert!(is_safe_path(&deep_ok));
        let deep_bad = format!(
            "/home/{}",
            (0..64)
                .map(|i| format!("d{}", i))
                .collect::<Vec<_>>()
                .join("/")
        );
        assert!(!is_safe_path(&deep_bad));
    }

    #[test]
    fn test_path_traversal_attacks() {
        let attack1 = normalize_path("/home/user/../../etc/passwd".into());
        assert!(!is_safe_path(&attack1));

        let attack2 = normalize_path("/home/../root".into());
        assert!(!is_safe_path(&attack2));

        let attack3 = normalize_path("/home/user/../../../".into());
        assert!(!is_safe_path(&attack3));

        let safe1 = normalize_path("/home/user/../user2".into());
        assert!(is_safe_path(&safe1));

        let safe2 = normalize_path("/home/user/./docs".into());
        assert!(is_safe_path(&safe2));
    }
}
