use securefs_server::dao;
use securefs_model::protocol::{User, Group};
use tokio_postgres::NoTls;
use std::sync::Arc;
use tokio::sync::Mutex;
use std::env;

#[tokio::test]
async fn test_group_membership() {
    // Setup DB connection
    let db_pass = env::var("DB_PASS").unwrap_or_else(|_| "securefs_password".to_string());
    let db_host = env::var("DB_HOST").unwrap_or_else(|_| "localhost".to_string());
    let (client, connection) = tokio_postgres::connect(
        &format!("host={} user=securefs_user password={} dbname=securefs port=5431", db_host, db_pass),
        NoTls,
    )
    .await
    .expect("Failed to connect to DB");

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("connection error: {}", e);
        }
    });

    let pg_client = Arc::new(Mutex::new(client));

    // Cleanup previous run
    let _ = pg_client.lock().await.execute("DELETE FROM groups WHERE g_name = 'test_group_mem'", &[]).await;
    let _ = pg_client.lock().await.execute("DELETE FROM users WHERE user_name = 'test_user_mem'", &[]).await;

    // Create user and group
    let _ = dao::create_user(pg_client.clone(), "test_user_mem".to_string(), "pass".to_string(), None, false).await.expect("create user failed");
    let _ = dao::create_group(pg_client.clone(), "test_group_mem".to_string()).await.expect("create group failed");

    // Verify initially not in group (secondary)
    let in_group = dao::user_in_group(pg_client.clone(), "test_user_mem".to_string(), "test_group_mem".to_string()).await.expect("check failed");
    assert!(!in_group, "User should not be in group yet");

    // Add user to group
    dao::add_user_to_group(pg_client.clone(), "test_user_mem".to_string(), "test_group_mem".to_string()).await.expect("add failed");

    // Verify now in group
    let in_group = dao::user_in_group(pg_client.clone(), "test_user_mem".to_string(), "test_group_mem".to_string()).await.expect("check failed");
    assert!(in_group, "User should be in group");

    // Remove user from group
    dao::remove_user_from_group(pg_client.clone(), "test_user_mem".to_string(), "test_group_mem".to_string()).await.expect("remove failed");

    // Verify removed
    let in_group = dao::user_in_group(pg_client.clone(), "test_user_mem".to_string(), "test_group_mem".to_string()).await.expect("check failed");
    assert!(!in_group, "User should be removed from group");

    // Cleanup
    let _ = pg_client.lock().await.execute("DELETE FROM groups WHERE g_name = 'test_group_mem'", &[]).await;
    let _ = pg_client.lock().await.execute("DELETE FROM users WHERE user_name = 'test_user_mem'", &[]).await;
}

