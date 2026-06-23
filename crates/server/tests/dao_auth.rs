use deadpool_postgres::{Config, ManagerConfig, Pool, RecyclingMethod, Runtime};
use securefs_server::dao;
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

// Basic smoke test for auth flow: create user then auth succeeds.
#[tokio::test]
async fn auth_user_roundtrip() {
    // Matches schema.sql encryption key
    // SAFETY: single-threaded test — no concurrent env access
    unsafe { std::env::set_var("DB_PASS", "securefs") };

    let pool = test_pool();

    // Clean up potentially stale data with wrong encryption keys
    let client = pool.get().await.unwrap();
    client.execute("DELETE FROM fnode", &[]).await.unwrap();
    client.execute("DELETE FROM users", &[]).await.unwrap();
    drop(client);

    // Ensure base init is present.
    dao::init_db(&pool).await.expect("init_db");

    let user_name = format!("user_{}", uuid::Uuid::new_v4());
    let pass = "pass123".to_string();

    let _key = dao::create_user(&pool, user_name.clone(), pass.clone(), None, false)
        .await
        .expect("create user");

    let ok = dao::auth_user(&pool, user_name.clone(), pass.clone())
        .await
        .expect("auth user");
    assert!(ok, "auth should succeed for created user");
}
