use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use deadpool_postgres::Pool;
use tokio::sync::Mutex;

use crate::dao::{self, DaoError};

// Failed-auth window and threshold defaults; impls take them at construction.
pub const RATE_LIMIT_WINDOW_SECS: u64 = 900;
pub const MAX_LOGIN_ATTEMPTS: u32 = 5;
// Hard cap on distinct IPs the in-process limiter tracks, to bound memory.
const MAX_RATE_LIMITER_ENTRIES: usize = 10_000;

// Per-IP failed-auth rate limiting, shared across instances by the Postgres impl
// so an attacker can't reset their budget by reconnecting to a different one.
#[async_trait]
pub trait RateLimiter: Send + Sync {
    async fn is_blocked(&self, ip: IpAddr) -> Result<bool, DaoError>;
    // Record one failed attempt; returns the running failure count in the window.
    async fn record_failure(&self, ip: IpAddr) -> Result<u32, DaoError>;
    async fn clear(&self, ip: IpAddr) -> Result<(), DaoError>;
    // Drop entries whose window has elapsed; returns the number removed.
    async fn cleanup(&self) -> Result<u64, DaoError>;
    fn max_attempts(&self) -> u32;
}

// Single-instance limiter; counters live in this process only.
pub struct InProcessRateLimiter {
    max_attempts: u32,
    window: Duration,
    entries: Mutex<HashMap<IpAddr, (u32, Instant)>>,
}

impl InProcessRateLimiter {
    pub fn new(max_attempts: u32, window: Duration) -> Self {
        Self {
            max_attempts,
            window,
            entries: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl RateLimiter for InProcessRateLimiter {
    async fn is_blocked(&self, ip: IpAddr) -> Result<bool, DaoError> {
        let map = self.entries.lock().await;
        Ok(match map.get(&ip) {
            Some((count, first)) => first.elapsed() <= self.window && *count >= self.max_attempts,
            None => false,
        })
    }

    async fn record_failure(&self, ip: IpAddr) -> Result<u32, DaoError> {
        let mut map = self.entries.lock().await;
        let now = Instant::now();
        let entry = map.entry(ip).or_insert((0, now));
        if entry.1.elapsed() > self.window {
            *entry = (0, now);
        }
        entry.0 = entry.0.saturating_add(1);
        Ok(entry.0)
    }

    async fn clear(&self, ip: IpAddr) -> Result<(), DaoError> {
        self.entries.lock().await.remove(&ip);
        Ok(())
    }

    async fn cleanup(&self) -> Result<u64, DaoError> {
        let mut map = self.entries.lock().await;
        let before = map.len();
        map.retain(|_, (_count, first)| first.elapsed() <= self.window);
        if map.len() > MAX_RATE_LIMITER_ENTRIES {
            let mut entries: Vec<(IpAddr, Instant)> =
                map.iter().map(|(ip, (_c, t))| (*ip, *t)).collect();
            entries.sort_by_key(|(_ip, t)| *t);
            let to_remove = map.len() - MAX_RATE_LIMITER_ENTRIES;
            for (ip, _) in entries.into_iter().take(to_remove) {
                map.remove(&ip);
            }
        }
        Ok(before.saturating_sub(map.len()) as u64)
    }

    fn max_attempts(&self) -> u32 {
        self.max_attempts
    }
}

// Limiter backed by Postgres and shared by all server instances.
pub struct PgRateLimiter {
    pool: Pool,
    max_attempts: u32,
    window_secs: i64,
}

impl PgRateLimiter {
    pub fn new(pool: Pool, max_attempts: u32, window: Duration) -> Self {
        Self {
            pool,
            max_attempts,
            window_secs: window.as_secs() as i64,
        }
    }
}

#[async_trait]
impl RateLimiter for PgRateLimiter {
    async fn is_blocked(&self, ip: IpAddr) -> Result<bool, DaoError> {
        dao::is_ip_blocked(
            &self.pool,
            &ip.to_string(),
            self.max_attempts as i32,
            self.window_secs,
        )
        .await
    }

    async fn record_failure(&self, ip: IpAddr) -> Result<u32, DaoError> {
        dao::record_login_failure(&self.pool, &ip.to_string(), self.window_secs).await
    }

    async fn clear(&self, ip: IpAddr) -> Result<(), DaoError> {
        dao::clear_login_attempts(&self.pool, &ip.to_string()).await
    }

    async fn cleanup(&self) -> Result<u64, DaoError> {
        dao::cleanup_login_attempts(&self.pool, self.window_secs).await
    }

    fn max_attempts(&self) -> u32 {
        self.max_attempts
    }
}
