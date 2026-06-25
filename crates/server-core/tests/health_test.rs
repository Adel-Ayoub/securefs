// The plaintext health server answers liveness (/health), readiness (/ready,
// which checks the database), /metrics, 404s anything else, and the healthcheck
// subcommand client accepts a 200.

use deadpool_postgres::{Config, ManagerConfig, Pool, RecyclingMethod, Runtime};
use securefs_server_core::health;
use securefs_server_core::metrics::Metrics;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_postgres::NoTls;

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

async fn get(addr: &str, path: &str) -> String {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        path
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.unwrap();
    String::from_utf8_lossy(&buf).into_owned()
}

#[tokio::test]
async fn health_ready_metrics_and_404() {
    let pool = test_pool();
    // Bind first so queued connections are accepted with no startup race.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(health::serve_on(
        listener,
        pool,
        Arc::new(Metrics::default()),
    ));

    let h = get(&addr, "/health").await;
    assert!(
        h.starts_with("HTTP/1.1 200"),
        "health status: {}",
        h.lines().next().unwrap_or("")
    );
    assert!(h.trim_end().ends_with("ok"), "health body: {}", h);

    let r = get(&addr, "/ready").await;
    assert!(
        r.starts_with("HTTP/1.1 200"),
        "ready status: {}",
        r.lines().next().unwrap_or("")
    );

    let m = get(&addr, "/metrics").await;
    assert!(
        m.starts_with("HTTP/1.1 200"),
        "metrics status: {}",
        m.lines().next().unwrap_or("")
    );
    assert!(
        m.contains("securefs_connections_total"),
        "metrics body missing counter: {}",
        m
    );

    let nf = get(&addr, "/nope").await;
    assert!(
        nf.starts_with("HTTP/1.1 404"),
        "404 status: {}",
        nf.lines().next().unwrap_or("")
    );

    health::run_healthcheck(&addr)
        .await
        .expect("healthcheck subcommand should accept a 200");
}
