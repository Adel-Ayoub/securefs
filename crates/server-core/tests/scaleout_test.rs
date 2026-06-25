// Exercises the shared SessionStore and RateLimiter against a real database:
// state is visible to any instance, the rate-limit window is database-
// authoritative, and a session flagged on one "instance" is observed by the
// owner at its next heartbeat. The in-process impls are covered for parity.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use deadpool_postgres::{Config, ManagerConfig, Pool, RecyclingMethod, Runtime};
use securefs_server_core::dao;
use securefs_server_core::rate_limiter::{InProcessRateLimiter, PgRateLimiter, RateLimiter};
use securefs_server_core::session_store::{InProcessSessionStore, PgSessionStore, SessionStore};
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

async fn ready_pool() -> Pool {
    // SAFETY: single-threaded tests — no concurrent env access.
    unsafe { std::env::set_var("DB_PASS", "securefs") };
    let pool = test_pool();
    dao::init_db(&pool).await.expect("init_db");
    pool
}

fn ip(last: u8) -> IpAddr {
    // TEST-NET-3 (203.0.113.0/24), reserved for documentation/testing.
    IpAddr::V4(Ipv4Addr::new(203, 0, 113, last))
}

#[tokio::test]
async fn pg_session_store_shares_and_force_logs_out() {
    let pool = ready_pool().await;
    let sid = "scaleout-test-session-1";

    let store = PgSessionStore::new(pool.clone());
    store.remove(sid).await.unwrap();

    store.register(sid, "alice", ip(1)).await.expect("register");

    let found = store
        .list()
        .await
        .unwrap()
        .into_iter()
        .find(|v| v.session_id == sid)
        .expect("registered session is listed");
    assert_eq!(found.username, "alice");
    assert_eq!(found.client_ip, "203.0.113.1");
    assert!(found.uptime_secs >= 0 && found.idle_secs >= 0);

    // Not flagged yet: heartbeat reports false and the row survives.
    assert!(!store.heartbeat(sid).await.unwrap());

    // A different instance (own connection pool, same database) flags it.
    let other_instance = PgSessionStore::new(pool.clone());
    assert!(other_instance.flag_force_logout(sid).await.unwrap());
    assert!(
        !other_instance
            .flag_force_logout("no-such-session")
            .await
            .unwrap(),
        "flagging an unknown session reports not-found"
    );

    // The owning instance observes the flag on its next heartbeat.
    assert!(store.heartbeat(sid).await.unwrap());

    store.remove(sid).await.unwrap();
    assert!(
        store
            .list()
            .await
            .unwrap()
            .iter()
            .all(|v| v.session_id != sid),
        "removed session no longer listed"
    );
}

#[tokio::test]
async fn pg_session_store_reaps_idle_rows() {
    let pool = ready_pool().await;
    let sid = "scaleout-test-session-reap";

    let store = PgSessionStore::new(pool.clone());
    store.remove(sid).await.unwrap();
    store.register(sid, "bob", ip(2)).await.unwrap();

    // Backdate activity to simulate an instance that died mid-session.
    let client = pool.get().await.unwrap();
    client
        .execute(
            "UPDATE sessions SET last_activity = now() - interval '1 hour' WHERE session_id = $1",
            &[&sid],
        )
        .await
        .unwrap();

    let reaped = store.reap_expired(60).await.unwrap();
    assert!(reaped >= 1, "the idle session is reaped");
    assert!(
        store
            .list()
            .await
            .unwrap()
            .iter()
            .all(|v| v.session_id != sid),
        "reaped session no longer listed"
    );
}

#[tokio::test]
async fn pg_rate_limiter_blocks_after_max_and_clears() {
    let pool = ready_pool().await;
    let rl = PgRateLimiter::new(pool, 3, Duration::from_secs(900));
    let addr = ip(10);

    rl.clear(addr).await.unwrap();
    assert!(!rl.is_blocked(addr).await.unwrap());

    assert_eq!(rl.record_failure(addr).await.unwrap(), 1);
    assert_eq!(rl.record_failure(addr).await.unwrap(), 2);
    assert_eq!(rl.record_failure(addr).await.unwrap(), 3);
    assert!(rl.is_blocked(addr).await.unwrap(), "blocked at the cap");

    rl.clear(addr).await.unwrap();
    assert!(!rl.is_blocked(addr).await.unwrap(), "clear resets the IP");
    assert_eq!(
        rl.record_failure(addr).await.unwrap(),
        1,
        "count restarts after clear"
    );
    rl.clear(addr).await.unwrap();
}

#[tokio::test]
async fn pg_rate_limiter_window_resets_and_cleans_up() {
    let pool = ready_pool().await;
    let rl = PgRateLimiter::new(pool.clone(), 5, Duration::from_secs(900));
    let addr = ip(11);
    let key = "203.0.113.11";

    rl.clear(addr).await.unwrap();
    assert_eq!(rl.record_failure(addr).await.unwrap(), 1);

    // Push the window anchor into the past; the next failure must reset to 1.
    let client = pool.get().await.unwrap();
    client
        .execute(
            "UPDATE login_attempts SET first_attempt = now() - interval '1 hour' WHERE client_ip = $1",
            &[&key],
        )
        .await
        .unwrap();
    assert_eq!(
        rl.record_failure(addr).await.unwrap(),
        1,
        "a failure past the window starts a fresh count"
    );

    // Backdate again and prove cleanup deletes the expired row.
    client
        .execute(
            "UPDATE login_attempts SET first_attempt = now() - interval '1 hour' WHERE client_ip = $1",
            &[&key],
        )
        .await
        .unwrap();
    assert!(
        rl.cleanup().await.unwrap() >= 1,
        "expired row is cleaned up"
    );
    let remaining: i64 = client
        .query_one(
            "SELECT count(*)::bigint FROM login_attempts WHERE client_ip = $1",
            &[&key],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(remaining, 0, "cleaned-up IP has no row");
}

#[tokio::test]
async fn in_process_rate_limiter_parity() {
    let rl = InProcessRateLimiter::new(2, Duration::from_secs(900));
    let addr = ip(20);

    assert_eq!(rl.max_attempts(), 2);
    assert!(!rl.is_blocked(addr).await.unwrap());
    assert_eq!(rl.record_failure(addr).await.unwrap(), 1);
    assert_eq!(rl.record_failure(addr).await.unwrap(), 2);
    assert!(rl.is_blocked(addr).await.unwrap());
    rl.clear(addr).await.unwrap();
    assert!(!rl.is_blocked(addr).await.unwrap());
    assert_eq!(rl.record_failure(addr).await.unwrap(), 1);
}

#[tokio::test]
async fn in_process_session_store_parity() {
    let store = InProcessSessionStore::new();
    let sid = "in-proc-session";

    store.register(sid, "carol", ip(21)).await.unwrap();
    assert_eq!(store.list().await.unwrap().len(), 1);
    assert!(!store.heartbeat(sid).await.unwrap());

    assert!(store.flag_force_logout(sid).await.unwrap());
    assert!(!store.flag_force_logout("missing").await.unwrap());
    assert!(store.heartbeat(sid).await.unwrap(), "flag is observed");

    store.remove(sid).await.unwrap();
    assert!(store.list().await.unwrap().is_empty());
}
