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

#[tokio::test]
async fn test_group_membership() {
    let pool = test_pool();

    // Cleanup previous run
    let client = pool.get().await.unwrap();
    let _ = client
        .execute("DELETE FROM groups WHERE g_name = 'test_group_mem'", &[])
        .await;
    let _ = client
        .execute("DELETE FROM users WHERE user_name = 'test_user_mem'", &[])
        .await;
    drop(client);

    // Create user and group
    let _ = dao::create_user(
        &pool,
        "test_user_mem".to_string(),
        "pass".to_string(),
        None,
        false,
    )
    .await
    .expect("create user failed");
    let _ = dao::create_group(&pool, "test_group_mem".to_string())
        .await
        .expect("create group failed");

    // Verify initially not in group (secondary)
    let in_group = dao::user_in_group(
        &pool,
        "test_user_mem".to_string(),
        "test_group_mem".to_string(),
    )
    .await
    .expect("check failed");
    assert!(!in_group, "User should not be in group yet");

    // Add user to group
    dao::add_user_to_group(
        &pool,
        "test_user_mem".to_string(),
        "test_group_mem".to_string(),
    )
    .await
    .expect("add failed");

    // Verify now in group
    let in_group = dao::user_in_group(
        &pool,
        "test_user_mem".to_string(),
        "test_group_mem".to_string(),
    )
    .await
    .expect("check failed");
    assert!(in_group, "User should be in group");

    // Remove user from group
    dao::remove_user_from_group(
        &pool,
        "test_user_mem".to_string(),
        "test_group_mem".to_string(),
    )
    .await
    .expect("remove failed");

    // Verify removed
    let in_group = dao::user_in_group(
        &pool,
        "test_user_mem".to_string(),
        "test_group_mem".to_string(),
    )
    .await
    .expect("check failed");
    assert!(!in_group, "User should be removed from group");

    // Cleanup
    let client = pool.get().await.unwrap();
    let _ = client
        .execute("DELETE FROM groups WHERE g_name = 'test_group_mem'", &[])
        .await;
    let _ = client
        .execute("DELETE FROM users WHERE user_name = 'test_user_mem'", &[])
        .await;
}
