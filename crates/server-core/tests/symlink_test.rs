use deadpool_postgres::{Config, ManagerConfig, Pool, RecyclingMethod, Runtime};
use securefs_server_core::dao;
use securefs_server_core::dao::records::FNode;
use tokio_postgres::NoTls;
use uuid::Uuid;

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

// Regression: link_target, size, timestamps and file_group must survive a
// round trip through the DB. Before the schema fix these were dropped on
// insert and always read back as None/0, leaving symlinks non-functional.
#[tokio::test]
async fn test_metadata_roundtrip() {
    // SAFETY: single-threaded test — no concurrent env access
    unsafe { std::env::set_var("DB_PASS", "securefs") };
    let pool = test_pool();
    dao::init_db(&pool).await.expect("init_db");

    let tag = Uuid::new_v4().simple().to_string();
    let link_path = format!("/home/link{}", tag);
    let target = format!("/home/target{}", tag);

    let link = FNode {
        id: -1,
        name: format!("link{}", tag),
        path: link_path.clone(),
        owner: "admin".into(),
        hash: "".into(),
        parent: "/home".into(),
        dir: false,
        u: 7,
        g: 7,
        o: 7,
        children: vec![],
        encrypted_name: format!("link{}", tag),
        size: 4096,
        created_at: 111,
        modified_at: 222,
        file_group: Some("devs".into()),
        link_target: Some(target.clone()),
    };
    dao::add_file(&pool, link).await.expect("add symlink");

    let got = dao::get_f_node(&pool, link_path.clone())
        .await
        .expect("query")
        .expect("node exists");

    assert_eq!(got.link_target, Some(target), "link_target must persist");
    assert_eq!(got.size, 4096, "size_bytes must persist");
    assert_eq!(got.created_at, 111, "created_at must persist");
    assert_eq!(got.modified_at, 222, "modified_at must persist");
    assert_eq!(
        got.file_group,
        Some("devs".to_string()),
        "create-time file_group must persist"
    );

    dao::delete_path(&pool, link_path).await.ok();
}
