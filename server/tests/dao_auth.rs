use std::sync::Arc;

use securefs_server::dao;
use tokio::sync::Mutex;
use tokio_postgres::NoTls;

// Basic smoke test for auth flow: create user then auth succeeds.
#[tokio::test]
async fn auth_user_roundtrip() {
    // These env vars should point to a running test database (e.g., docker-compose).
    let db_pass = std::env::var("DB_PASS").unwrap_or_else(|_| "TEMP".into());
    let db_host = std::env::var("DB_HOST").unwrap_or_else(|_| "localhost".into());
    let db_name = std::env::var("DB_NAME").unwrap_or_else(|_| "db".into());
    let db_user = std::env::var("DB_USER").unwrap_or_else(|_| "USER".into());
    let db_port = std::env::var("DB_PORT").unwrap_or_else(|_| "5431".into());

    let (client, connection) = tokio_postgres::connect(
        &format!(
            "host={} dbname={} user={} password={} port={}",
            db_host, db_name, db_user, db_pass, db_port
        ),
        NoTls,
    )
    .await
    .expect("db connect");
    let pg_client = Arc::new(Mutex::new(client));
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("db connection error: {}", e);
        }
    });

    // Ensure base init is present.
    dao::init_db(pg_client.clone()).await.ok();

    let user_name = format!("user_{}", uuid::Uuid::new_v4());
    let pass = "pass123".to_string();

    let _key = dao::create_user(pg_client.clone(), user_name.clone(), pass.clone(), None, false)
        .await
        .expect("create user");

    let ok = dao::auth_user(pg_client.clone(), user_name.clone(), pass.clone())
        .await
        .expect("auth user");
    assert!(ok, "auth should succeed for created user");
}

