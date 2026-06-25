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

fn node(path: &str, name: &str, parent: &str, dir: bool) -> FNode {
    FNode {
        id: -1,
        name: name.into(),
        path: path.into(),
        owner: "admin".into(),
        hash: "".into(),
        parent: parent.into(),
        dir,
        u: 7,
        g: 7,
        o: 7,
        children: vec![],
        encrypted_name: name.into(),
        size: 0,
        created_at: 0,
        modified_at: 0,
        file_group: None,
        link_target: None,
    }
}

// Regression: deleting `<base>/doc` must remove it and its subtree, but must
// NOT touch the prefix-sibling `<base>/document`.
#[tokio::test]
async fn test_delete_path_no_prefix_overmatch() {
    // SAFETY: single-threaded test — no concurrent env access
    unsafe { std::env::set_var("DB_PASS", "securefs") };
    let pool = test_pool();
    pool.get()
        .await
        .unwrap()
        .execute("DELETE FROM fnode", &[])
        .await
        .ok();
    dao::init_db(&pool).await.expect("init_db");

    let tag = Uuid::new_v4().simple().to_string();
    let base = format!("/home/del{}", tag);
    let doc = format!("{}/doc", base);
    let inner = format!("{}/doc/inner", base);
    let sibling = format!("{}/document", base);

    dao::add_file(&pool, node(&base, "del", "/home", true))
        .await
        .unwrap();
    dao::add_file(&pool, node(&doc, "doc", &base, true))
        .await
        .unwrap();
    dao::add_file(&pool, node(&inner, "inner", &doc, false))
        .await
        .unwrap();
    dao::add_file(&pool, node(&sibling, "document", &base, false))
        .await
        .unwrap();

    dao::delete_path(&pool, doc.clone()).await.expect("delete");

    assert!(
        dao::get_f_node(&pool, doc).await.unwrap().is_none(),
        "target node should be deleted"
    );
    assert!(
        dao::get_f_node(&pool, inner).await.unwrap().is_none(),
        "descendant should be deleted with the subtree"
    );
    assert!(
        dao::get_f_node(&pool, sibling).await.unwrap().is_some(),
        "prefix-sibling /document must survive deletion of /doc"
    );

    pool.get()
        .await
        .unwrap()
        .execute("DELETE FROM fnode", &[])
        .await
        .ok();
}
