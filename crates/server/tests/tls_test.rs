//! End-to-end test over a real TLS (wss://) connection.
//!
//! Spawns the server with a generated certificate and TLS mandatory
//! (ALLOW_INSECURE unset), connects with a client that trusts only that
//! certificate, and runs the encrypted handshake + login + pwd flow. This
//! covers the TLS-serving path that the plain-ws e2e test cannot.

use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use deadpool_postgres::{Config, ManagerConfig, Pool, RecyclingMethod, Runtime};
use futures_util::{SinkExt, StreamExt};
use rcgen::CertifiedKey;
use securefs_channel::handshake::ClientHandshake;
use securefs_channel::secure_channel::SecureChannel;
use securefs_proto::protocol::{AppMessage, Cmd};
use securefs_server_core::dao;
use tokio_postgres::NoTls;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{
    connect_async_tls_with_config, Connector, MaybeTlsStream, WebSocketStream,
};
use uuid::Uuid;

type Ws = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

fn test_pool() -> Pool {
    let mut cfg = Config::new();
    cfg.host = Some("localhost".into());
    cfg.dbname = Some("securefs".into());
    cfg.user = Some("securefs_user".into());
    cfg.password = Some("securefs_password".into());
    cfg.port = Some(5431);
    cfg.manager = Some(ManagerConfig {
        recycling_method: RecyclingMethod::Fast,
    });
    cfg.create_pool(Some(Runtime::Tokio1), NoTls).unwrap()
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct ServerGuard(Child);
impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn send_plain(ws: &mut Ws, msg: &AppMessage) -> Result<(), String> {
    let s = serde_json::to_string(msg).map_err(|e| e.to_string())?;
    ws.send(Message::Text(s.into()))
        .await
        .map_err(|e| e.to_string())
}

async fn recv_plain(ws: &mut Ws) -> Result<AppMessage, String> {
    let msg = ws
        .next()
        .await
        .ok_or("connection closed")?
        .map_err(|e| e.to_string())?;
    let text = msg.into_text().map_err(|e| e.to_string())?;
    serde_json::from_str(&text).map_err(|e| e.to_string())
}

async fn send_sealed(ws: &mut Ws, ch: &mut SecureChannel, msg: &AppMessage) -> Result<(), String> {
    ws.send(Message::Text(
        ch.seal(msg).map_err(|e| e.to_string())?.into(),
    ))
    .await
    .map_err(|e| e.to_string())
}

async fn recv_opened(ws: &mut Ws, ch: &mut SecureChannel) -> Result<AppMessage, String> {
    let msg = ws
        .next()
        .await
        .ok_or("connection closed")?
        .map_err(|e| e.to_string())?;
    let text = msg.into_text().map_err(|e| e.to_string())?;
    ch.open(&text).map_err(|e| e.to_string())
}

// Connect over wss (retrying until the server binds), perform the handshake,
// log in over the encrypted channel, and return the result of `pwd`.
async fn tls_flow(
    wss_url: &str,
    user: &str,
    pass: &str,
    connector: Connector,
) -> Result<String, String> {
    let mut ws: Ws = {
        let mut last = String::new();
        let mut connected = None;
        for _ in 0..100 {
            match connect_async_tls_with_config(wss_url, None, false, Some(connector.clone())).await
            {
                Ok((s, _)) => {
                    connected = Some(s);
                    break;
                }
                Err(e) => {
                    last = e.to_string();
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
        connected.ok_or_else(|| format!("could not connect over tls: {}", last))?
    };

    let (handshake, init) = ClientHandshake::initiate();
    send_plain(&mut ws, &init).await?;
    let reply = recv_plain(&mut ws).await?;
    if reply.cmd != Cmd::KeyExchangeResponse {
        return Err(format!("unexpected handshake reply: {:?}", reply.cmd));
    }
    let mut ch = handshake.complete(&reply.data).map_err(|e| e.to_string())?;

    send_sealed(
        &mut ws,
        &mut ch,
        &AppMessage {
            cmd: Cmd::Login,
            data: vec![user.into(), pass.into()],
        },
    )
    .await?;
    let login = recv_opened(&mut ws, &mut ch).await?;
    if login.cmd != Cmd::Login {
        return Err(format!("login failed: {:?} {:?}", login.cmd, login.data));
    }

    send_sealed(
        &mut ws,
        &mut ch,
        &AppMessage {
            cmd: Cmd::Pwd,
            data: vec![],
        },
    )
    .await?;
    let pwd = recv_opened(&mut ws, &mut ch).await?;
    if pwd.cmd != Cmd::Pwd {
        return Err(format!("pwd failed: {:?}", pwd.cmd));
    }
    Ok(pwd.data.first().cloned().unwrap_or_default())
}

#[tokio::test]
async fn test_login_over_tls() {
    // SAFETY: single-threaded test — no concurrent env access
    unsafe { std::env::set_var("DB_PASS", "securefs") };
    let pool = test_pool();
    dao::init_db(&pool).await.expect("init_db");

    let tag = Uuid::new_v4().simple().to_string();
    let user = format!("tls{}", tag);
    let pass = "password123";
    dao::create_user(&pool, user.clone(), pass.to_string(), None, false)
        .await
        .expect("create user");

    // Self-signed cert for "localhost"; write the PEM files the server reads.
    let CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("generate cert");
    let dir = std::env::temp_dir();
    let cert_path = dir.join(format!("securefs-{}-cert.pem", tag));
    let key_path = dir.join(format!("securefs-{}-key.pem", tag));
    std::fs::write(&cert_path, cert.pem()).expect("write cert");
    std::fs::write(&key_path, signing_key.serialize_pem()).expect("write key");

    let port = free_port();
    let addr = format!("127.0.0.1:{}", port);
    let server = ServerGuard(
        Command::new(env!("CARGO_BIN_EXE_securefs-server"))
            .env("SERVER_ADDR", &addr)
            .env("TLS_CERT", &cert_path)
            .env("TLS_KEY", &key_path)
            .env("DB_HOST", "localhost")
            .env("DB_PORT", "5431")
            .env("DB_NAME", "securefs")
            .env("DB_USER", "securefs_user")
            .env("DB_CONN_PASSWORD", "securefs_password")
            .env("DB_PASS", "securefs")
            .env("DATA_KEY", "tls-test-data-key")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn server"),
    );

    // Trust only the generated certificate.
    let mut roots = RootCertStore::empty();
    roots.add(cert.der().clone()).expect("add root cert");
    let client_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = Connector::Rustls(Arc::new(client_config));

    let wss_url = format!("wss://localhost:{}", port);
    let result = tokio::time::timeout(
        Duration::from_secs(20),
        tls_flow(&wss_url, &user, pass, connector),
    )
    .await;

    drop(server);
    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);
    let _ = pool
        .get()
        .await
        .unwrap()
        .execute("DELETE FROM users WHERE user_name=$1", &[&user])
        .await;

    let pwd = result.expect("tls e2e timed out").expect("tls flow failed");
    assert_eq!(
        pwd, "/home",
        "pwd after login over TLS should default to /home"
    );
}
