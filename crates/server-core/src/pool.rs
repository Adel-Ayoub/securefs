//! Postgres connection-pool construction from the environment. Shared by the
//! server binary's startup and the offline `rotate-kek` / `verify-audit`
//! subcommands, so the pool wiring lives in the library rather than the bin.

use std::env;

use deadpool_postgres::{Config, ManagerConfig, Pool, PoolConfig, RecyclingMethod, Runtime};
use log::info;
use tokio_postgres::NoTls;

use crate::config::NetConfig;

// Lowest-level pool builder: explicit connection params, optional connection
// cap. Takes no env, so it is unit-testable. max_size None keeps the deadpool
// default (cpu count * 4).
fn build_pool_to(
    host: String,
    port: u16,
    dbname: String,
    user: String,
    password: String,
    max_size: Option<usize>,
) -> Result<Pool, String> {
    let mut pool_cfg = Config::new();
    pool_cfg.host = Some(host);
    pool_cfg.dbname = Some(dbname);
    pool_cfg.user = Some(user);
    pool_cfg.password = Some(password);
    pool_cfg.port = Some(port);
    pool_cfg.manager = Some(ManagerConfig {
        recycling_method: RecyclingMethod::Fast,
    });
    if let Some(n) = max_size {
        pool_cfg.pool = Some(PoolConfig::new(n));
    }
    pool_cfg
        .create_pool(Some(Runtime::Tokio1), NoTls)
        .map_err(|e| format!("pool creation failed: {}", e))
}

// Optional positive connection cap read from `var`; a non-positive or malformed
// value fails loudly at startup rather than silently falling back.
fn pool_max_size(var: &str) -> Result<Option<usize>, String> {
    match env::var(var) {
        Ok(v) if !v.is_empty() => match v.parse::<usize>() {
            Ok(n) if n > 0 => Ok(Some(n)),
            _ => Err(format!("{} must be a positive integer, got '{}'", var, v)),
        },
        _ => Ok(None),
    }
}

// Build the primary Postgres pool from env. Shared by the server and the
// rotate-kek subcommand. The connection password (DB_CONN_PASSWORD) can differ
// from DB_PASS (the pgcrypto / data key); it falls back to DB_PASS when unset.
// DB_POOL_MAX_SIZE caps per-instance connections so many instances don't
// exhaust the database's connection limit.
pub fn build_pool(net: &NetConfig, db_pass: &str) -> Result<Pool, String> {
    build_pool_to(
        env::var("DB_HOST").unwrap_or_else(|_| "localhost".to_string()),
        net.db_port,
        env::var("DB_NAME").unwrap_or_else(|_| "db".to_string()),
        env::var("DB_USER").unwrap_or_else(|_| "USER".to_string()),
        env::var("DB_CONN_PASSWORD").unwrap_or_else(|_| db_pass.to_string()),
        pool_max_size("DB_POOL_MAX_SIZE")?,
    )
}

// Optional read-replica pool for read-only queries. When DB_REPLICA_HOST is set,
// builds a separate pool to the replica (own DB_REPLICA_PORT / DB_REPLICA_POOL_MAX_SIZE,
// reusing the primary's dbname/user/password); otherwise reads share the primary
// pool. Replicas lag, so only staleness-tolerant listing reads are routed here -
// writes and content reads stay on the primary.
pub fn build_read_pool(net: &NetConfig, db_pass: &str, primary: &Pool) -> Result<Pool, String> {
    match env::var("DB_REPLICA_HOST") {
        Ok(host) if !host.is_empty() => {
            let port = match env::var("DB_REPLICA_PORT") {
                Ok(p) if !p.is_empty() => p
                    .parse::<u16>()
                    .map_err(|_| format!("DB_REPLICA_PORT must be a port number, got '{}'", p))?,
                _ => net.db_port,
            };
            info!("read-replica pool enabled -> {}:{}", host, port);
            build_pool_to(
                host,
                port,
                env::var("DB_NAME").unwrap_or_else(|_| "db".to_string()),
                env::var("DB_USER").unwrap_or_else(|_| "USER".to_string()),
                env::var("DB_CONN_PASSWORD").unwrap_or_else(|_| db_pass.to_string()),
                pool_max_size("DB_REPLICA_POOL_MAX_SIZE")?,
            )
        }
        _ => Ok(primary.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_size_cap_is_applied() {
        // An explicit cap is honored; None keeps deadpool's (nonzero) default.
        let capped = build_pool_to(
            "localhost".into(),
            5432,
            "db".into(),
            "u".into(),
            "p".into(),
            Some(3),
        )
        .unwrap();
        assert_eq!(capped.status().max_size, 3);
        let default = build_pool_to(
            "localhost".into(),
            5432,
            "db".into(),
            "u".into(),
            "p".into(),
            None,
        )
        .unwrap();
        assert!(default.status().max_size >= 1);
    }
}
