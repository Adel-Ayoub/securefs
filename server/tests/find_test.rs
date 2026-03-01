use deadpool_postgres::{Config, ManagerConfig, RecyclingMethod, Runtime, Pool};
use securefs_server::dao;
use securefs_model::protocol::FNode;
use tokio_postgres::NoTls;

fn test_pool() -> Pool {
    let mut cfg = Config::new();
    cfg.host = Some("localhost".into());
    cfg.dbname = Some("securefs".into());
    cfg.user = Some("securefs_user".into());
    cfg.password = Some("securefs_password".into());
    cfg.port = Some(5431);
    cfg.manager = Some(ManagerConfig { recycling_method: RecyclingMethod::Fast });
    cfg.create_pool(Some(Runtime::Tokio1), NoTls).unwrap()
}

#[tokio::test]
async fn test_find_command() {
    // SAFETY: single-threaded test — no concurrent env access
    unsafe { std::env::set_var("DB_PASS", "securefs") };

    let pool = test_pool();

    // Clean DB
    pool.get().await.unwrap().execute("DELETE FROM fnode", &[]).await.ok();
    dao::init_db(&pool).await.expect("init_db");

    // Setup structure:
    // /home
    //   /home/dir1
    //     /home/dir1/match_target.txt
    //     /home/dir1/other.txt
    //   /home/dir2
    //     /home/dir2/match_nested.txt

    let dir1 = FNode {
        id: -1, name: "dir1".into(), path: "/home/dir1".into(), owner: "admin".into(),
        hash: "".into(), parent: "/home".into(), dir: true, u: 7, g: 7, o: 7, children: vec![], encrypted_name: "dir1".into(),
        size: 0, created_at: 0, modified_at: 0, file_group: None
    };
    dao::add_file(&pool, dir1).await.expect("create dir1");
    dao::add_file_to_parent(&pool, "/home".into(), "dir1".into()).await.expect("link dir1");

    let match_target = FNode {
        id: -1, name: "match_target.txt".into(), path: "/home/dir1/match_target.txt".into(), owner: "admin".into(),
        hash: "".into(), parent: "/home/dir1".into(), dir: false, u: 7, g: 7, o: 7, children: vec![], encrypted_name: "match_target.txt".into(),
        size: 0, created_at: 0, modified_at: 0, file_group: None
    };
    dao::add_file(&pool, match_target).await.expect("create match_target");
    dao::add_file_to_parent(&pool, "/home/dir1".into(), "match_target.txt".into()).await.expect("link match_target");

    let other = FNode {
        id: -1, name: "other.txt".into(), path: "/home/dir1/other.txt".into(), owner: "admin".into(),
        hash: "".into(), parent: "/home/dir1".into(), dir: false, u: 7, g: 7, o: 7, children: vec![], encrypted_name: "other.txt".into(),
        size: 0, created_at: 0, modified_at: 0, file_group: None
    };
    dao::add_file(&pool, other).await.expect("create other");
    dao::add_file_to_parent(&pool, "/home/dir1".into(), "other.txt".into()).await.expect("link other");

    let pattern = "match";
    let current_path = "/home";

    let mut results: Vec<String> = Vec::new();
    let mut to_search = vec![current_path.to_string()];

    while let Some(search_path) = to_search.pop() {
        if let Ok(Some(node)) = dao::get_f_node(&pool, search_path.clone()).await {
             if node.name.contains(pattern) {
                 results.push(node.path.clone());
             }
             if node.dir {
                 for child in node.children {
                     let child_path = if search_path == "/" { format!("/{}", child) } else { format!("{}/{}", search_path, child) };
                     to_search.push(child_path);
                 }
             }
        }
    }

    assert!(results.contains(&"/home/dir1/match_target.txt".to_string()));
    assert!(!results.contains(&"/home/dir1/other.txt".to_string()));
}
