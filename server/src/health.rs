use crate::metrics::SharedMetrics;
use deadpool_postgres::Pool;
use log::{info, warn};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

// Minimal, dependency-free HTTP/1.1 server on its own plaintext port, separate
// from the TLS WebSocket port. GET /health is liveness; GET /ready checks the
// database; GET /metrics exposes Prometheus counters.
pub async fn serve(pool: Pool, addr: String, metrics: SharedMetrics) {
    match TcpListener::bind(&addr).await {
        Ok(listener) => {
            info!("Health endpoint on http://{}/health", addr);
            serve_on(listener, pool, metrics).await;
        }
        Err(e) => warn!("health server bind failed on {}: {}", addr, e),
    }
}

pub async fn serve_on(listener: TcpListener, pool: Pool, metrics: SharedMetrics) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let pool = pool.clone();
                let metrics = metrics.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle(stream, pool, metrics).await {
                        warn!("health request failed: {}", e);
                    }
                });
            }
            Err(e) => warn!("health accept failed: {}", e),
        }
    }
}

async fn handle(mut stream: TcpStream, pool: Pool, metrics: SharedMetrics) -> std::io::Result<()> {
    let mut buf = [0u8; 1024];
    let n = match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await {
        Ok(Ok(n)) => n,
        _ => return Ok(()),
    };
    let path = std::str::from_utf8(&buf[..n])
        .ok()
        .and_then(|req| req.lines().next())
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("");

    let (status, ctype, body) = match path {
        "/health" => ("200 OK", "text/plain", "ok".to_string()),
        "/ready" => {
            if db_ok(&pool).await {
                ("200 OK", "text/plain", "ready".to_string())
            } else {
                (
                    "503 Service Unavailable",
                    "text/plain",
                    "not ready".to_string(),
                )
            }
        }
        "/metrics" => ("200 OK", "text/plain; version=0.0.4", metrics.render()),
        _ => ("404 Not Found", "text/plain", "not found".to_string()),
    };

    let resp = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status,
        ctype,
        body.len(),
        body
    );
    stream.write_all(resp.as_bytes()).await?;
    stream.flush().await
}

async fn db_ok(pool: &Pool) -> bool {
    match pool.get().await {
        Ok(client) => client.simple_query("SELECT 1").await.is_ok(),
        Err(_) => false,
    }
}

// Client side of the container HEALTHCHECK: probe our own /health and map a 200
// to exit 0, so the runtime image needs no curl/wget.
pub async fn run_healthcheck(addr: &str) -> Result<(), String> {
    let mut stream = TcpStream::connect(addr)
        .await
        .map_err(|e| format!("health connect failed: {}", e))?;
    stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .map_err(|e| format!("health write failed: {}", e))?;
    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .await
        .map_err(|e| format!("health read failed: {}", e))?;
    let head = String::from_utf8_lossy(&buf);
    if head.starts_with("HTTP/1.1 200") {
        Ok(())
    } else {
        Err(format!(
            "health check failed: {}",
            head.lines().next().unwrap_or("no response")
        ))
    }
}
