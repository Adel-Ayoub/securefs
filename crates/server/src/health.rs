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

// Parse the request-target (path) out of a raw HTTP request head: the second
// whitespace-separated token of the first line ("METHOD <target> VERSION").
// Returns "" for non-UTF-8 or otherwise malformed input. Pure and panic-free,
// so it is safe to run on unauthenticated bytes straight off the socket (and is
// exercised continuously by the `health_parse` fuzz target).
pub fn parse_request_target(buf: &[u8]) -> &str {
    std::str::from_utf8(buf)
        .ok()
        .and_then(|req| req.lines().next())
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("")
}

async fn handle(mut stream: TcpStream, pool: Pool, metrics: SharedMetrics) -> std::io::Result<()> {
    let mut buf = [0u8; 1024];
    let n = match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await {
        Ok(Ok(n)) => n,
        _ => return Ok(()),
    };
    let path = parse_request_target(&buf[..n]);

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

/// Error from the client-side container health probe.
#[derive(Debug, thiserror::Error)]
pub enum HealthCheckError {
    #[error("health connect failed: {0}")]
    Connect(std::io::Error),
    #[error("health write failed: {0}")]
    Write(std::io::Error),
    #[error("health read failed: {0}")]
    Read(std::io::Error),
    #[error("health check failed: {0}")]
    BadStatus(String),
}

// Client side of the container HEALTHCHECK: probe our own /health and map a 200
// to exit 0, so the runtime image needs no curl/wget.
pub async fn run_healthcheck(addr: &str) -> Result<(), HealthCheckError> {
    let mut stream = TcpStream::connect(addr)
        .await
        .map_err(HealthCheckError::Connect)?;
    stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .map_err(HealthCheckError::Write)?;
    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .await
        .map_err(HealthCheckError::Read)?;
    let head = String::from_utf8_lossy(&buf);
    if head.starts_with("HTTP/1.1 200") {
        Ok(())
    } else {
        Err(HealthCheckError::BadStatus(
            head.lines().next().unwrap_or("no response").to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::parse_request_target;

    #[test]
    fn parses_common_request_targets() {
        assert_eq!(
            parse_request_target(b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n"),
            "/health"
        );
        assert_eq!(
            parse_request_target(b"GET /ready HTTP/1.1\r\n\r\n"),
            "/ready"
        );
        assert_eq!(
            parse_request_target(b"POST /metrics HTTP/1.0\n"),
            "/metrics"
        );
    }

    #[test]
    fn empty_on_malformed_or_non_utf8() {
        assert_eq!(parse_request_target(b""), "");
        assert_eq!(parse_request_target(b"GET"), "");
        assert_eq!(parse_request_target(b"   \r\n"), "");
        assert_eq!(parse_request_target(b"\xff\xfe not utf8"), "");
    }

    #[test]
    fn never_panics_on_odd_shapes() {
        for raw in [
            &b"GET "[..],
            b"\n\n\n",
            b"G E T",
            b"GET  /x  y",
            b"\0\0 /y z",
        ] {
            let target = parse_request_target(raw);
            assert!(target.len() <= raw.len());
        }
    }
}
