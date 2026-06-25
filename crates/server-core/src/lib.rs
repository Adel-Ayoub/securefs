//! SecureFS domain and security core.
//!
//! The whole server domain lives here as a library: at-rest crypto, request
//! handlers and authorization, sessions, the data-access layer, and the
//! supporting infrastructure. The `securefs-server` binary is a thin wrapper
//! that wires TLS/WebSocket transport, the connection pool, and signals over
//! this crate. Keeping the core in a library makes it reachable from the
//! integration tests and the fuzzer.

#![forbid(unsafe_code)]

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
            match $crate::dao::append_audit_log(&pool_ref, &ev, &us, &re, &rs, None).await {
                // The chained head doubles as a witness: the structured log is a
                // separate sink, so a DB-side rewrite still has to match the logs.
                Ok(entry) => log::info!(
                    "[AUDIT] chained seq={} head={}",
                    entry.seq,
                    hex::encode(entry.entry_hash)
                ),
                Err(e) => log::warn!("audit persist failed: {}", e),
            }
        });
    }};
}

pub mod audit_verify;
pub mod config;
pub mod crypto;
pub mod dao;
pub mod handlers;
pub mod health;
pub mod logging;
pub mod metrics;
pub mod pool;
pub mod rate_limiter;
pub mod rotate;
pub mod session;
pub mod session_store;
pub mod storage;
pub mod util;
