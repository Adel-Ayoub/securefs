use deadpool_postgres::{Config, ManagerConfig, Pool, RecyclingMethod, Runtime};
use securefs_model::protocol::FNode;
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
async fn test_scan_command() {
    // SAFETY: single-threaded test — no concurrent env access
    unsafe { std::env::set_var("DB_PASS", "securefs") };

    let pool = test_pool();

    // Clean DB
    pool.get()
        .await
        .unwrap()
        .execute("DELETE FROM fnode", &[])
        .await
        .ok();
    dao::init_db(&pool).await.expect("init_db");

    // Create a file
    let file_name = "test_scan.txt";
    let file_content = "integrity check content";
    let file_hash = blake3::hash(file_content.as_bytes()).to_hex().to_string();

    let file_node = FNode {
        id: -1,
        name: file_name.into(),
        path: format!("/home/{}", file_name),
        owner: "admin".into(),
        hash: file_hash.clone(),
        parent: "/home".into(),
        dir: false,
        u: 7,
        g: 7,
        o: 7,
        children: vec![],
        encrypted_name: file_name.into(),
        size: 0,
        created_at: 0,
        modified_at: 0,
        file_group: None,
    };

    dao::add_file(&pool, file_node).await.expect("create file");
    dao::add_file_to_parent(&pool, "/home".into(), file_name.into())
        .await
        .expect("link file");

    // Create physical file
    let storage_root = "storage";
    tokio::fs::create_dir_all(format!("{}/home", storage_root))
        .await
        .expect("mkdir home");
    let phys_path = format!("{}/home/{}", storage_root, file_name);
    tokio::fs::write(&phys_path, file_content)
        .await
        .expect("write file");

    // Case 1: Integrity OK
    let node = dao::get_f_node(&pool, format!("/home/{}", file_name))
        .await
        .unwrap()
        .unwrap();
    let read_content = tokio::fs::read(&phys_path).await.expect("read phys");
    let calc_hash = blake3::hash(&read_content).to_hex().to_string();
    assert_eq!(node.hash, calc_hash, "Hash mismatch in valid case");

    // Case 2: Integrity Compromised
    tokio::fs::write(&phys_path, "corrupted content")
        .await
        .expect("corrupt file");
    let read_content_corrupt = tokio::fs::read(&phys_path)
        .await
        .expect("read phys corrupt");
    let calc_hash_corrupt = blake3::hash(&read_content_corrupt).to_hex().to_string();
    assert_ne!(
        node.hash, calc_hash_corrupt,
        "Hash should NOT match in corrupted case"
    );

    // cleanup
    let _ = tokio::fs::remove_file(phys_path).await;
}
