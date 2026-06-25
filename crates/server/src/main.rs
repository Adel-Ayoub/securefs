//! WebSocket server for SecureFS.
//!
//! Accepts client connections, authenticates users, and translates
//! protocol commands into DAO/database operations and on-disk file
//! changes.

#![deny(unsafe_code)]

use std::env;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use deadpool_postgres::Pool;
use futures_util::{SinkExt, StreamExt};
use log::{info, warn};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use securefs_channel::secure_channel::{decode_frame, encode_frame, SecureChannel};
use securefs_proto::protocol::{AppMessage, Cmd};
use std::net::IpAddr;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_rustls::rustls;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::accept_async_with_config;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

#[cfg(feature = "s3")]
use securefs_blobstore::S3Blobstore;
use securefs_blobstore::{Blobstore, LocalFs};
use securefs_server_core::config::NetConfig;
use securefs_server_core::metrics::{Metrics, SharedMetrics};
use securefs_server_core::pool::{build_pool, build_read_pool};
use securefs_server_core::session::Session;
use securefs_server_core::{audit_verify, crypto, dao, handlers, health, logging, rotate};

use securefs_server_core::rate_limiter::{
    InProcessRateLimiter, PgRateLimiter, RateLimiter, MAX_LOGIN_ATTEMPTS, RATE_LIMIT_WINDOW_SECS,
};
use securefs_server_core::session_store::{InProcessSessionStore, PgSessionStore, SessionStore};

// DoS limits.
const MAX_MESSAGE_SIZE: usize = 1 << 20; // 1 MiB cap per WebSocket message/frame
const CONNECTION_IDLE_TIMEOUT_SECS: u64 = 1800; // close a connection idle this long

// Defaults for env-tunable MAX_CONNECTIONS and SHUTDOWN_GRACE_SECS: a deployment
// sizes pods and aligns the drain with the orchestrator's termination grace period.
const DEFAULT_MAX_CONNECTIONS: usize = 1024;
const DEFAULT_SHUTDOWN_GRACE_SECS: u64 = 10;

// RAII guard for the active-connections gauge: increment on creation, decrement
// on drop, so the count stays correct even if a connection task panics.
struct ActiveGuard(SharedMetrics);

impl ActiveGuard {
    fn new(metrics: SharedMetrics) -> Self {
        metrics.connections_active.fetch_add(1, Ordering::Relaxed);
        Self(metrics)
    }
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.connections_active.fetch_sub(1, Ordering::Relaxed);
    }
}

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

// Parse a numeric setting (raw env value or None), falling back to `default`;
// a malformed value fails loudly. Split from env access so it is unit-testable.
fn parse_num_or<T: std::str::FromStr>(
    raw: Option<String>,
    var: &str,
    default: T,
) -> Result<T, String> {
    match raw {
        Some(v) if !v.is_empty() => v
            .parse::<T>()
            .map_err(|_| format!("{} must be a number, got '{}'", var, v)),
        _ => Ok(default),
    }
}

// Numeric setting from env var `var`, or `default` when unset.
fn env_num<T: std::str::FromStr>(var: &str, default: T) -> Result<T, String> {
    parse_num_or(env::var(var).ok(), var, default)
}

// Build the S3/MinIO-backed blob store from the environment (S3_BUCKET etc.).
#[cfg(feature = "s3")]
fn make_s3_store() -> Result<Arc<dyn Blobstore>, String> {
    info!("storage backend: s3");
    let store = S3Blobstore::from_env().map_err(|e| format!("s3 storage init: {}", e))?;
    Ok(Arc::new(store))
}

// Without the s3 feature, selecting it is a clear startup error rather than a
// silent fallback to local disk (which would not be shared across instances).
#[cfg(not(feature = "s3"))]
fn make_s3_store() -> Result<Arc<dyn Blobstore>, String> {
    Err(
        "STORAGE_BACKEND=s3 but this build lacks the 's3' feature; rebuild with --features s3"
            .into(),
    )
}

#[tokio::main]
/// Launch the WebSocket server and connect to Postgres.
async fn main() -> Result<(), String> {
    // The s3 backend links a second rustls CryptoProvider (ring, via reqwest), so
    // pin the process default to aws_lc_rs: this disambiguates the server's TLS
    // config builder and gives reqwest's no-provider S3 client a provider to use.
    #[cfg(feature = "s3")]
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    // Subcommand used by the container HEALTHCHECK; probes /health and exits.
    if std::env::args().nth(1).as_deref() == Some("healthcheck") {
        let addr = env::var("HEALTH_ADDR").unwrap_or_else(|_| "127.0.0.1:8081".to_string());
        return health::run_healthcheck(&addr)
            .await
            .map_err(|e| e.to_string());
    }

    // Offline KEK rotation: rewrap every file's DEK from DATA_KEY to DATA_KEY_NEW
    // without touching file bodies, then exit. Run with the server stopped.
    if std::env::args().nth(1).as_deref() == Some("rotate-kek") {
        logging::init();
        return rotate::run().await;
    }

    // Offline audit-chain verification: walk the chain, validate the signed head,
    // and exit non-zero if it was tampered with. Run against the live database.
    if std::env::args().nth(1).as_deref() == Some("verify-audit") {
        logging::init();
        return audit_verify::run().await;
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

    // Inject the at-rest master DOWN into the crypto layer from the configured
    // secret, so derivation routes through the held provider instead of reaching
    // up into the DAO on each call.
    crypto::install_env_key_provider();

    let net = NetConfig::from_env().map_err(|e| e.to_string())?;

    let pool = build_pool(&net, &db_pass)?;
    let read_pool = build_read_pool(&net, &db_pass, &pool)?;

    dao::init_db(&pool)
        .await
        .map_err(|e| format!("database init failed: {}", e))?;

    // Load the current at-rest KEK generation new writes wrap under, and fail
    // fast if the configured DATA_KEY cannot open an existing DEK (wrong key or
    // an incomplete rotation) rather than surfacing it on first file access.
    let kek_generation = dao::get_kek_generation(&pool)
        .await
        .map_err(|e| format!("read KEK generation: {}", e))?;
    crypto::set_current_generation(kek_generation);
    info!("at-rest KEK generation {}", kek_generation);
    if let Some(sample) = dao::sample_wrapped_dek(&pool)
        .await
        .map_err(|e| format!("sample wrapped DEK: {}", e))?
    {
        if !crypto::can_unwrap(&sample) {
            return Err(format!(
                "configured DATA_KEY cannot unwrap stored DEKs (KEK generation {}): wrong key or an incomplete rotation",
                kek_generation
            ));
        }
    }

    // Seal the audit-chain head now so there is always a checkpoint under the
    // current master right after boot (and so a post-rotation restart re-anchors
    // under the new key). The maintenance task re-seals periodically.
    let audit_seal_key = crypto::audit_seal_key();
    if let Err(e) = dao::seal_audit_head(&pool, &audit_seal_key).await {
        warn!("audit checkpoint seal at startup failed: {}", e);
    }

    // Single blob backend for the process. STORAGE_BACKEND=s3 uses S3-compatible
    // object storage (so any instance serves any file); otherwise a local
    // directory rooted at STORAGE_DIR (default "storage"). Either way logical
    // paths map to opaque keys at the chokepoint, so the backend only ever sees
    // ciphertext under opaque names.
    let store: Arc<dyn Blobstore> = if env::var("STORAGE_BACKEND").as_deref() == Ok("s3") {
        make_s3_store()?
    } else {
        let storage_root = env::var("STORAGE_DIR").unwrap_or_else(|_| "storage".to_string());
        info!("storage backend: local ({})", storage_root);
        Arc::new(LocalFs::new(storage_root))
    };

    let listener = TcpListener::bind(net.server_addr)
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

    info!("Listening on: {}", net.server_addr);

    // Shared session + rate-limit state. SHARED_STATE=postgres backs both with
    // Postgres so multiple stateless instances coordinate; otherwise both are
    // in-process (single instance / dev), preserving the previous behavior.
    let window = std::time::Duration::from_secs(RATE_LIMIT_WINDOW_SECS);
    let (session_store, rate_limiter): (Arc<dyn SessionStore>, Arc<dyn RateLimiter>) =
        if env::var("SHARED_STATE").as_deref() == Ok("postgres") {
            info!("shared state: postgres (scale-out)");
            (
                Arc::new(PgSessionStore::new(pool.clone())),
                Arc::new(PgRateLimiter::new(pool.clone(), MAX_LOGIN_ATTEMPTS, window)),
            )
        } else {
            info!("shared state: in-process (single instance)");
            (
                Arc::new(InProcessSessionStore::new()),
                Arc::new(InProcessRateLimiter::new(MAX_LOGIN_ATTEMPTS, window)),
            )
        };

    // Periodic maintenance: drop expired rate-limit entries, reap sessions left
    // behind by an instance that died mid-session, and re-seal the audit head.
    {
        let rl = rate_limiter.clone();
        let ss = session_store.clone();
        let maint_pool = pool.clone();
        let seal_key = audit_seal_key;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                if let Err(e) = rl.cleanup().await {
                    warn!("rate limiter cleanup failed: {}", e);
                }
                if let Err(e) = ss.reap_expired(SESSION_TIMEOUT_SECS).await {
                    warn!("session reap failed: {}", e);
                }
                if let Err(e) = dao::seal_audit_head(&maint_pool, &seal_key).await {
                    warn!("audit checkpoint seal failed: {}", e);
                }
            }
        });
    }

    let metrics: SharedMetrics = Arc::new(Metrics::default());

    // Plaintext liveness/readiness/metrics endpoint on its own port.
    {
        let health_addr = net.health_addr.to_string();
        let pool = pool.clone();
        let metrics = metrics.clone();
        tokio::spawn(health::serve(pool, health_addr, metrics));
    }

    let max_connections = env_num("MAX_CONNECTIONS", DEFAULT_MAX_CONNECTIONS)?;
    let shutdown_grace_secs = env_num("SHUTDOWN_GRACE_SECS", DEFAULT_SHUTDOWN_GRACE_SECS)?;
    let conn_limit = Arc::new(Semaphore::new(max_connections));

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
                metrics
                    .connections_rejected_total
                    .fetch_add(1, Ordering::Relaxed);
                warn!(
                    "connection limit ({}) reached; refusing {}",
                    max_connections, addr
                );
                continue;
            }
        };

        info!("New connection from: {}", addr);
        metrics.connections_total.fetch_add(1, Ordering::Relaxed);
        let active = ActiveGuard::new(metrics.clone());
        let pg = pool.clone();
        let rp = read_pool.clone();
        let rl = rate_limiter.clone();
        let ss = session_store.clone();
        let ip = addr.ip();
        let tls = tls_acceptor.clone();
        let st = store.clone();
        tokio::spawn(async move {
            let _permit = permit; // released when the connection ends
            let _active = active; // decrements the active gauge on drop
            let result = if let Some(acceptor) = tls {
                match acceptor.accept(stream).await {
                    Ok(tls_stream) => {
                        handle_tls_connection(tls_stream, pg, rp, rl, ss, ip, st).await
                    }
                    Err(e) => Err(format!("TLS handshake failed: {}", e)),
                }
            } else {
                handle_connection(stream, pg, rp, rl, ss, ip, st).await
            };
            if let Err(e) = result {
                warn!("Connection error: {}", e);
            }
        });
    }

    // Best-effort graceful drain: wait for in-flight connections to finish.
    let in_flight = max_connections - conn_limit.available_permits();
    if in_flight > 0 {
        info!("Draining {} in-flight connection(s)...", in_flight);
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(shutdown_grace_secs),
            conn_limit.acquire_many(max_connections as u32),
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
    read_pool: Pool,
    rate_limiter: Arc<dyn RateLimiter>,
    session_store: Arc<dyn SessionStore>,
    client_ip: IpAddr,
    store: Arc<dyn Blobstore>,
) -> Result<(), String> {
    let ws_stream = accept_async_with_config(stream, Some(ws_config()))
        .await
        .map_err(|e| format!("TLS handshake failed: {}", e))?;
    handle_ws_stream(
        ws_stream,
        pool,
        read_pool,
        rate_limiter,
        session_store,
        client_ip,
        store,
    )
    .await
}

/// Handle a plain TCP WebSocket connection lifecycle.
async fn handle_connection(
    stream: TcpStream,
    pool: Pool,
    read_pool: Pool,
    rate_limiter: Arc<dyn RateLimiter>,
    session_store: Arc<dyn SessionStore>,
    client_ip: IpAddr,
    store: Arc<dyn Blobstore>,
) -> Result<(), String> {
    let ws_stream = accept_async_with_config(stream, Some(ws_config()))
        .await
        .map_err(|e| format!("handshake failed: {}", e))?;
    handle_ws_stream(
        ws_stream,
        pool,
        read_pool,
        rate_limiter,
        session_store,
        client_ip,
        store,
    )
    .await
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
    let payload = encode_frame(channel, &resp).map_err(|e| e.to_string())?;
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
    read_pool: Pool,
    rate_limiter: Arc<dyn RateLimiter>,
    session_store: Arc<dyn SessionStore>,
    client_ip: IpAddr,
    store: Arc<dyn Blobstore>,
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
        let incoming: AppMessage =
            decode_frame(channel.as_mut(), text).map_err(|e| e.to_string())?;

        // Check session timeout for authenticated sessions
        if session.authenticated && last_activity.elapsed().as_secs() > SESSION_TIMEOUT_SECS {
            warn!(
                "Session expired for user {:?} after {} seconds of inactivity",
                session.current_user,
                last_activity.elapsed().as_secs()
            );
            let _ = session_store.remove(&session_id).await;
            session.reset();
        }

        last_activity = std::time::Instant::now();

        // One round-trip: bump last activity and learn whether an admin (here or
        // on another instance) flagged this session for forced logout.
        if session.authenticated {
            match session_store.heartbeat(&session_id).await {
                Ok(true) => {
                    let _ = session_store.remove(&session_id).await;
                    session.reset();
                    let reply = AppMessage {
                        cmd: Cmd::Logout,
                        data: vec!["session terminated by admin".into()],
                    };
                    send_app_message(&mut ws_stream, reply, channel.as_mut()).await?;
                    break;
                }
                Ok(false) => {}
                Err(e) => warn!("session heartbeat failed: {}", e),
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
                handlers::auth::login(
                    incoming.data,
                    &mut session,
                    &pool,
                    rate_limiter.as_ref(),
                    client_ip,
                )
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
            Cmd::Ls => (handlers::fs::ls(&session, &read_pool).await, None),
            Cmd::Find => (
                handlers::fs::find(incoming.data, &session, &read_pool).await,
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
                handlers::fs::delete(incoming.data, &session, &pool, &*store).await,
                None,
            ),
            Cmd::Mv => (
                handlers::fs::mv(incoming.data, &session, &pool, &*store).await,
                None,
            ),
            Cmd::Cp => (
                handlers::fs::cp(incoming.data, &session, &pool, &*store).await,
                None,
            ),
            Cmd::Cat => (
                handlers::fs::cat(incoming.data, &session, &pool, &*store).await,
                None,
            ),
            Cmd::Echo => (
                handlers::fs::echo(incoming.data, &session, &pool, &*store).await,
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
                handlers::perms::scan(incoming.data, &session, &pool, &*store).await,
                None,
            ),
            Cmd::GetEncryptedFile => (
                handlers::perms::get_encrypted_file(incoming.data, &session, &pool).await,
                None,
            ),
            Cmd::Whoami => (handlers::user::whoami(&session), None),
            Cmd::Tree => (handlers::fs::tree(&session, &read_pool).await, None),
            Cmd::Stat => (
                handlers::fs::stat(incoming.data, &session, &pool, &*store).await,
                None,
            ),
            Cmd::Du => (handlers::fs::du(&session, &pool, &*store).await, None),
            Cmd::Head => (
                handlers::fs::head(incoming.data, &session, &pool, &*store).await,
                None,
            ),
            Cmd::Tail => (
                handlers::fs::tail(incoming.data, &session, &pool, &*store).await,
                None,
            ),
            Cmd::Grep => (
                handlers::fs::grep(incoming.data, &session, &pool, &*store).await,
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
            Cmd::UploadEnd => (
                handlers::fs::upload_end(&mut session, &pool, &*store).await,
                None,
            ),
            Cmd::DownloadStart => (
                handlers::fs::download_start(incoming.data, &mut session, &pool, &*store).await,
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
                    rate_limiter.as_ref(),
                    client_ip,
                )
                .await,
                None,
            ),
            Cmd::ListSessions => (
                handlers::sessions::list_sessions(&session, &pool, session_store.as_ref()).await,
                None,
            ),
            Cmd::ForceLogout => (
                handlers::sessions::force_logout(
                    incoming.data,
                    &session,
                    &pool,
                    session_store.as_ref(),
                )
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

        // Register session in the shared store on successful login.
        if matches!(reply.cmd, Cmd::Login) && session.authenticated {
            let username = session.current_user.clone().unwrap_or_default();
            if let Err(e) = session_store
                .register(&session_id, &username, client_ip)
                .await
            {
                warn!("session register failed: {}", e);
            }
        }

        let is_logout = matches!(reply.cmd, Cmd::Logout);
        send_app_message(&mut ws_stream, reply, channel.as_mut()).await?;

        if let Some(s) = new_secret {
            channel = Some(s);
        }

        if !session.authenticated && is_logout {
            let _ = session_store.remove(&session_id).await;
            break;
        }
    }

    // Deregister on disconnect
    let _ = session_store.remove(&session_id).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::parse_num_or;

    #[test]
    fn numeric_settings_parse_with_fallback() {
        assert_eq!(parse_num_or(Some("42".into()), "X", 7usize).unwrap(), 42);
        assert_eq!(parse_num_or(None, "X", 7usize).unwrap(), 7);
        assert_eq!(parse_num_or(Some("".into()), "X", 7usize).unwrap(), 7);
        assert_eq!(parse_num_or(Some("9".into()), "X", 1u64).unwrap(), 9);
        assert!(parse_num_or(Some("nope".into()), "X", 0usize).is_err());
    }
}
