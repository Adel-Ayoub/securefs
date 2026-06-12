use std::process::{Child, Command, Stdio};
use std::time::Duration;

use aes_gcm::aead::{Aead, AeadCore};
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use deadpool_postgres::{Config, ManagerConfig, Pool, RecyclingMethod, Runtime};
use futures_util::{SinkExt, StreamExt};
use hkdf::Hkdf;
use rand_core::OsRng;
use securefs_model::protocol::{AppMessage, Cmd};
use securefs_server::dao;
use sha2::Sha256;
use tokio_postgres::NoTls;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};
use uuid::Uuid;
use x25519_dalek::{EphemeralSecret, PublicKey};

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

async fn send_plain(ws: &mut Ws, msg: &AppMessage) -> Result<(), String> {
    let s = serde_json::to_string(msg).map_err(|e| e.to_string())?;
    ws.send(Message::Text(s)).await.map_err(|e| e.to_string())
}

async fn send_enc(ws: &mut Ws, key: &Key<Aes256Gcm>, msg: &AppMessage) -> Result<(), String> {
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(OsRng);
    let pt = serde_json::to_string(msg).map_err(|e| e.to_string())?;
    let ct = cipher
        .encrypt(&nonce, pt.as_bytes())
        .map_err(|e| e.to_string())?;
    let tuple = (hex::encode(ct), Into::<[u8; 12]>::into(nonce));
    let s = serde_json::to_string(&tuple).map_err(|e| e.to_string())?;
    ws.send(Message::Text(s)).await.map_err(|e| e.to_string())
}

async fn recv_msg(ws: &mut Ws, key: Option<&Key<Aes256Gcm>>) -> Result<AppMessage, String> {
    let msg = ws
        .next()
        .await
        .ok_or("connection closed")?
        .map_err(|e| e.to_string())?;
    let text = msg.into_text().map_err(|e| e.to_string())?;
    match key {
        Some(k) => {
            let (ct_hex, nonce): (String, [u8; 12]) =
                serde_json::from_str(&text).map_err(|e| e.to_string())?;
            let cipher = Aes256Gcm::new(k);
            let ct = hex::decode(&ct_hex).map_err(|e| e.to_string())?;
            let pt = cipher
                .decrypt(Nonce::from_slice(&nonce), ct.as_ref())
                .map_err(|e| e.to_string())?;
            serde_json::from_slice(&pt).map_err(|e| e.to_string())
        }
        None => serde_json::from_str(&text).map_err(|e| e.to_string()),
    }
}

// Connect (retrying until the server binds), perform the X25519/HKDF handshake,
// log in over the encrypted channel, and return the result of `pwd`.
async fn e2e_flow(addr: &str, user: &str, pass: &str) -> Result<String, String> {
    let url = format!("ws://{}", addr);
    let mut ws: Ws = {
        let mut last = String::new();
        let mut connected = None;
        for _ in 0..50 {
            match connect_async(url.as_str()).await {
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
        connected.ok_or_else(|| format!("could not connect: {}", last))?
    };

    let secret = EphemeralSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    send_plain(
        &mut ws,
        &AppMessage {
            cmd: Cmd::KeyExchangeInit,
            data: vec![hex::encode(public.as_bytes())],
        },
    )
    .await?;
    let reply = recv_msg(&mut ws, None).await?;
    if reply.cmd != Cmd::KeyExchangeResponse {
        return Err(format!("unexpected handshake reply: {:?}", reply.cmd));
    }
    let server_bytes =
        hex::decode(reply.data.first().cloned().unwrap_or_default()).map_err(|e| e.to_string())?;
    if server_bytes.len() != 32 {
        return Err("bad server pubkey length".into());
    }
    let mut sb = [0u8; 32];
    sb.copy_from_slice(&server_bytes);
    let shared = secret.diffie_hellman(&PublicKey::from(sb));
    let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(b"securefs-session-key-v1", &mut okm)
        .map_err(|e| e.to_string())?;
    let key = *Key::<Aes256Gcm>::from_slice(&okm);

    send_enc(
        &mut ws,
        &key,
        &AppMessage {
            cmd: Cmd::Login,
            data: vec![user.into(), pass.into()],
        },
    )
    .await?;
    let login = recv_msg(&mut ws, Some(&key)).await?;
    if login.cmd != Cmd::Login {
        return Err(format!("login failed: {:?} {:?}", login.cmd, login.data));
    }

    send_enc(
        &mut ws,
        &key,
        &AppMessage {
            cmd: Cmd::Pwd,
            data: vec![],
        },
    )
    .await?;
    let pwd = recv_msg(&mut ws, Some(&key)).await?;
    if pwd.cmd != Cmd::Pwd {
        return Err(format!("pwd failed: {:?}", pwd.cmd));
    }
    Ok(pwd.data.first().cloned().unwrap_or_default())
}

struct ServerGuard(Child);
impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
async fn test_login_e2e() {
    // SAFETY: single-threaded test — no concurrent env access
    unsafe { std::env::set_var("DB_PASS", "securefs") };
    let pool = test_pool();
    dao::init_db(&pool).await.expect("init_db");

    let tag = Uuid::new_v4().simple().to_string();
    let user = format!("e2e{}", tag);
    let pass = "password123";
    dao::create_user(&pool, user.clone(), pass.to_string(), None, false)
        .await
        .expect("create user");

    let port = free_port();
    let addr = format!("127.0.0.1:{}", port);
    let server = ServerGuard(
        Command::new(env!("CARGO_BIN_EXE_securefs-server"))
            .env("ALLOW_INSECURE", "1")
            .env("SERVER_ADDR", &addr)
            .env("DB_PASS", "securefs")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn server"),
    );

    let result = tokio::time::timeout(Duration::from_secs(20), e2e_flow(&addr, &user, pass)).await;

    drop(server);

    let pwd = result.expect("e2e timed out").expect("e2e flow failed");
    assert_eq!(pwd, "/home", "pwd after login should default to /home");

    let _ = pool
        .get()
        .await
        .unwrap()
        .execute("DELETE FROM users WHERE user_name=$1", &[&user])
        .await;
}
