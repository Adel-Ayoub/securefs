//! One-time TOTP enforcement: a time-step can be consumed once, and only
//! strictly-newer steps are accepted afterward. This is the cross-connection
//! replay protection - a captured code cannot be reused on a fresh connection
//! within its validity window.

use deadpool_postgres::{Config, ManagerConfig, Pool, RecyclingMethod, Runtime};
use securefs_server_core::dao;
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

#[tokio::test]
async fn totp_step_consumed_once_and_monotonic() {
    let pool = test_pool();
    let client = pool.get().await.unwrap();
    let user = "__totp_replay_test_user__";

    // Self-provision the column: the test harness applies schema.sql only, while
    // this column is normally created by the server's init_db migration.
    client
        .execute(
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_last_step BIGINT",
            &[],
        )
        .await
        .unwrap();
    client
        .execute("DELETE FROM users WHERE user_name = $1", &[&user])
        .await
        .unwrap();
    client
        .execute("INSERT INTO users (user_name) VALUES ($1)", &[&user])
        .await
        .unwrap();

    // First use of a step succeeds; replaying the same step fails.
    assert!(dao::consume_totp_step(&pool, user, 100).await.unwrap());
    assert!(!dao::consume_totp_step(&pool, user, 100).await.unwrap());

    // A newer step is accepted exactly once.
    assert!(dao::consume_totp_step(&pool, user, 101).await.unwrap());
    assert!(!dao::consume_totp_step(&pool, user, 101).await.unwrap());

    // Older or equal steps can never be replayed once a newer one was used.
    assert!(!dao::consume_totp_step(&pool, user, 100).await.unwrap());
    assert!(!dao::consume_totp_step(&pool, user, 99).await.unwrap());

    // An unknown user consumes nothing.
    assert!(!dao::consume_totp_step(&pool, "__no_such_user__", 100)
        .await
        .unwrap());

    client
        .execute("DELETE FROM users WHERE user_name = $1", &[&user])
        .await
        .unwrap();
}
