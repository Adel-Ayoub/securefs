use std::process::{Child, Command, Stdio};
use std::time::Duration;

use deadpool_postgres::{Config, ManagerConfig, Pool, RecyclingMethod, Runtime};
use futures_util::{SinkExt, StreamExt};
use securefs_channel::handshake::ClientHandshake;
use securefs_channel::secure_channel::SecureChannel;
use securefs_proto::protocol::{AppMessage, Cmd};
use securefs_server::dao;
use tokio_postgres::NoTls;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};
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

// Connect (retrying until the server binds), perform the X25519/HKDF handshake,
// log in over the encrypted channel, and return the result of `pwd`.
async fn e2e_flow(addr: &str, user: &str, pass: &str) -> Result<String, String> {
    let url = format!("ws://{}", addr);
    let mut ws: Ws = {
        let mut last = String::new();
        let mut connected = None;
        for _ in 0..100 {
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
            .env("DB_HOST", "localhost")
            .env("DB_PORT", "5431")
            .env("DB_NAME", "securefs")
            .env("DB_USER", "securefs_user")
            .env("DB_CONN_PASSWORD", "securefs_password")
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
