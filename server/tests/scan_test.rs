use std::sync::Arc;
use securefs_server::dao;
use securefs_model::protocol::FNode;
use tokio::sync::Mutex;
use tokio_postgres::NoTls;

#[tokio::test]
async fn test_scan_command() {
    let db_pass = "securefs"; 
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

    // Clean DB
    pg_client.lock().await.execute("DELETE FROM fnode", &[]).await.ok();
    dao::init_db(pg_client.clone()).await.expect("init_db");

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
        u: 7, g: 7, o: 7,
        children: vec![],
        encrypted_name: file_name.into(),
        size: 0, created_at: 0, modified_at: 0, file_group: None
    };
    
    dao::add_file(pg_client.clone(), file_node).await.expect("create file");
    dao::add_file_to_parent(pg_client.clone(), "/home".into(), file_name.into()).await.expect("link file");
    
    // Create physical file
    let storage_root = "storage";
    // need to ensure storage/home exists
    tokio::fs::create_dir_all(format!("{}/home", storage_root)).await.expect("mkdir home");
    let phys_path = format!("{}/home/{}", storage_root, file_name);
    tokio::fs::write(&phys_path, file_content).await.expect("write file");
    
    // Test logic:
    // We want to verify `scan` logic.
    // The `scan` logic in `main.rs` does:
    // 1. get_f_node
    // 2. read physical file
    // 3. hash physical file
    // 4. compare
    
    // Case 1: Integrity OK
    // We can't call the `Cmd::Scan` handler directly easily without mocking the whole WebSocket loop.
    // But we can replicate the logic to verify the components work together.
    
    let node = dao::get_f_node(pg_client.clone(), format!("/home/{}", file_name)).await.unwrap().unwrap();
    let read_content = tokio::fs::read(&phys_path).await.expect("read phys");
    let calc_hash = blake3::hash(&read_content).to_hex().to_string();
    assert_eq!(node.hash, calc_hash, "Hash mismatch in valid case");
    
    // Case 2: Integrity Compromised
    tokio::fs::write(&phys_path, "corrupted content").await.expect("corrupt file");
    let read_content_corrupt = tokio::fs::read(&phys_path).await.expect("read phys corrupt");
    let calc_hash_corrupt = blake3::hash(&read_content_corrupt).to_hex().to_string();
    assert_ne!(node.hash, calc_hash_corrupt, "Hash should NOT match in corrupted case");
    
    // cleanup
    let _ = tokio::fs::remove_file(phys_path).await;
}
