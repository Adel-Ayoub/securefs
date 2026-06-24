use deadpool_postgres::{Config, ManagerConfig, Pool, RecyclingMethod, Runtime};
use securefs_blobstore::{Blobstore, LocalFs};
use securefs_server::dao;
use securefs_server::dao::records::FNode;
use securefs_server::storage::physical_key;
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

#[tokio::test]
async fn test_recursive_copy() {
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

    // Setup:
    // /home/src_dir
    // /home/src_dir/file1
    // /home/src_dir/subdir
    // /home/src_dir/subdir/file2

    let src_dir_name = format!("src_{}", Uuid::new_v4());
    let src_dir_path = format!("/home/{}", src_dir_name);

    // Create src_dir
    let dir_node = FNode {
        id: -1,
        name: src_dir_name.clone(),
        path: src_dir_path.clone(),
        owner: "admin".into(),
        hash: "".into(),
        parent: "/home".into(),
        dir: true,
        u: 7,
        g: 7,
        o: 7,
        children: vec![],
        encrypted_name: src_dir_name.clone(),
        size: 0,
        created_at: 0,
        modified_at: 0,
        file_group: None,
        link_target: None,
    };
    dao::add_file(&pool, dir_node)
        .await
        .expect("create src dir");
    dao::add_file_to_parent(&pool, "/home".into(), src_dir_name.clone())
        .await
        .expect("link src dir");

    // Create file1
    let file1_node = FNode {
        id: -1,
        name: "file1".into(),
        path: format!("{}/file1", src_dir_path),
        owner: "admin".into(),
        hash: "data1".into(),
        parent: src_dir_path.clone(),
        dir: false,
        u: 7,
        g: 7,
        o: 6,
        children: vec![],
        encrypted_name: "file1".into(),
        size: 0,
        created_at: 0,
        modified_at: 0,
        file_group: None,
        link_target: None,
    };
    dao::add_file(&pool, file1_node)
        .await
        .expect("create file1");
    dao::add_file_to_parent(&pool, src_dir_path.clone(), "file1".into())
        .await
        .expect("link file1");

    // Seed the source blob at its opaque key (copy_recursive copies bytes as-is).
    let store = LocalFs::new("storage");
    let file1_path = format!("{}/file1", src_dir_path);
    let src_key = physical_key(&file1_path).expect("src key");
    store
        .put(&src_key, b"data1")
        .await
        .expect("write file1 blob");

    // Copy src_dir to dst_dir
    let dst_dir_name = format!("dst_{}", Uuid::new_v4());
    let dst_dir_path = format!("/home/{}", dst_dir_name);

    dao::copy_recursive(
        &pool,
        src_dir_path.clone(),
        dst_dir_path.clone(),
        "admin".to_string(),
        &store,
    )
    .await
    .expect("copy_recursive failed");

    // Verify Destination exists in DB
    let dst_node = dao::get_f_node(&pool, dst_dir_path.clone()).await.unwrap();
    assert!(dst_node.is_some(), "Destination dir not found in DB");

    // Verify Child exists in DB
    let dst_file1_path = format!("{}/file1", dst_dir_path);
    let dst_file1_node = dao::get_f_node(&pool, dst_file1_path.clone())
        .await
        .unwrap();
    assert!(
        dst_file1_node.is_some(),
        "Destination file1 not found in DB"
    );

    // Verify the destination blob exists at its opaque key.
    let dst_key = physical_key(&dst_file1_path).expect("dst key");
    assert!(
        store.exists(&dst_key).await.expect("exists check"),
        "destination blob not copied"
    );

    // Clean up blobs.
    let _ = store.delete(&src_key).await;
    let _ = store.delete(&dst_key).await;
}
