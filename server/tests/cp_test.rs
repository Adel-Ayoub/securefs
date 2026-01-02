use std::sync::Arc;
use securefs_server::dao;
use securefs_model::protocol::FNode;
use tokio::sync::Mutex;
use tokio_postgres::NoTls;
use uuid::Uuid;

#[tokio::test]
async fn test_recursive_copy() {
    let db_pass = "securefs"; // Matches schema
    std::env::set_var("DB_PASS", db_pass);
    
    // Connect to DB
    let db_host = std::env::var("DB_HOST").unwrap_or_else(|_| "localhost".into());
    let (client, connection) = tokio_postgres::connect(
        &format!("host={} dbname=securefs user=securefs_user password=securefs_password port=5431", db_host),
        NoTls,
    ).await.expect("db connect");
    
    let pg_client = Arc::new(Mutex::new(client));
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("db connection error: {}", e);
        }
    });

    // Clean DB (careful!)
    // For safety, maybe we just work with unique paths?
    // But we need a clean slate to be sure. 
    // Let's rely on unique paths to avoid nuking the DB if other tests are running (though we play mostly sequentially).
    // Actually, dao_auth nukes the DB. Let's do the same for consistency.
    pg_client.lock().await.execute("DELETE FROM fnode", &[]).await.ok();
    dao::init_db(pg_client.clone()).await.expect("init_db");

    // Setup:
    // /home/src_dir
    // /home/src_dir/file1
    // /home/src_dir/subdir
    // /home/src_dir/subdir/file2
    
    let src_dir_name = format!("src_{}", Uuid::new_v4());
    let src_dir_path = format!("/home/{}", src_dir_name);
    
    // Create src_dir
    let dir_node = FNode {
        id: -1, name: src_dir_name.clone(), path: src_dir_path.clone(), owner: "admin".into(),
        hash: "".into(), parent: "/home".into(), dir: true, u: 7, g: 7, o: 7, children: vec![], encrypted_name: src_dir_name.clone(),
        size: 0, created_at: 0, modified_at: 0
    };
    dao::add_file(pg_client.clone(), dir_node).await.expect("create src dir");
    dao::add_file_to_parent(pg_client.clone(), "/home".into(), src_dir_name.clone()).await.expect("link src dir");

    // Create file1
    let file1_node = FNode {
        id: -1, name: "file1".into(), path: format!("{}/file1", src_dir_path), owner: "admin".into(),
        hash: "data1".into(), parent: src_dir_path.clone(), dir: false, u: 7, g: 7, o: 6, children: vec![], encrypted_name: "file1".into(),
        size: 0, created_at: 0, modified_at: 0
    };
    dao::add_file(pg_client.clone(), file1_node).await.expect("create file1");
    // We should technically update parent children, but for copy_recursive test we mainly need the nodes to exist in DB
    // copy_recursive gets children from the DB node. So if we don't link them, it won't find them?
    // Yes, dao::get_f_node fetches children.
    dao::add_file_to_parent(pg_client.clone(), src_dir_path.clone(), "file1".into()).await.expect("link file1");

    // Create physical files
    let storage_root = "storage";
    let src_phys_path = format!("{}{}", storage_root, src_dir_path);
    tokio::fs::create_dir_all(&src_phys_path).await.expect("create src phys dir");
    tokio::fs::write(format!("{}/file1", src_phys_path), "data1").await.expect("write file1");
    // Also ensuring parent path exists for consistency if not already there
    
    // Copy src_dir to dst_dir
    let dst_dir_name = format!("dst_{}", Uuid::new_v4());
    let dst_dir_path = format!("/home/{}", dst_dir_name);

    dao::copy_recursive(pg_client.clone(), src_dir_path.clone(), dst_dir_path.clone(), "admin".to_string())
        .await
        .expect("copy_recursive failed");

    // Verify Destination exists in DB
    let dst_node = dao::get_f_node(pg_client.clone(), dst_dir_path.clone()).await.unwrap();
    assert!(dst_node.is_some(), "Destination dir not found in DB");
    
    // Verify Child exists in DB
    let dst_file1_path = format!("{}/file1", dst_dir_path);
    let dst_file1_node = dao::get_f_node(pg_client.clone(), dst_file1_path.clone()).await.unwrap();
    assert!(dst_file1_node.is_some(), "Destination file1 not found in DB");

    // Verify Physical File exists
    let dst_phys_path = format!("{}{}/file1", storage_root, dst_dir_path);
    assert!(std::path::Path::new(&dst_phys_path).exists(), "Physical file not copied");
    
    // Clean up physical
    let _ = tokio::fs::remove_dir_all(src_phys_path).await;
    let _ = tokio::fs::remove_dir_all(format!("{}{}", storage_root, dst_dir_path)).await;
}
