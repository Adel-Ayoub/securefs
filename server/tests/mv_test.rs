use deadpool_postgres::{Config, ManagerConfig, Pool, RecyclingMethod, Runtime};
use securefs_model::protocol::FNode;
use securefs_server::dao;
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

// Moving a non-empty directory must rewrite every descendant's path and parent
// pointer, swap the entry in the parent's children array, and leave a
// prefix-sibling untouched — all atomically.
#[tokio::test]
async fn test_rename_nonempty_directory() {
    // SAFETY: single-threaded test — no concurrent env access
    unsafe { std::env::set_var("DB_PASS", "securefs") };
    let pool = test_pool();
    dao::init_db(&pool).await.expect("init_db");

    let tag = Uuid::new_v4().simple().to_string();
    let src = format!("/home/mv{}", tag);
    let dst = format!("/home/renamed{}", tag);
    let sub = format!("{}/sub", src);
    let file = format!("{}/sub/f", src);
    let sibling = format!("{}sibling", src); // shares src as a string prefix

    for (n, p, par, dir) in [
        (format!("mv{}", tag), src.clone(), "/home".to_string(), true),
        ("sub".to_string(), sub.clone(), src.clone(), true),
        ("f".to_string(), file.clone(), sub.clone(), false),
        (
            format!("mv{}sibling", tag),
            sibling.clone(),
            "/home".to_string(),
            true,
        ),
    ] {
        dao::add_file(&pool, node(&p, &n, &par, dir))
            .await
            .expect("add");
        dao::add_file_to_parent(&pool, par, n).await.expect("link");
    }

    dao::rename_node(
        &pool,
        "/home".to_string(),
        src.clone(),
        dst.clone(),
        format!("mv{}", tag),
        format!("renamed{}", tag),
    )
    .await
    .expect("rename");

    // Old paths gone, new paths present.
    assert!(dao::get_f_node(&pool, src.clone()).await.unwrap().is_none());
    assert!(dao::get_f_node(&pool, dst.clone()).await.unwrap().is_some());

    let moved_sub = dao::get_f_node(&pool, format!("{}/sub", dst))
        .await
        .unwrap()
        .expect("sub moved");
    assert_eq!(moved_sub.parent, dst, "descendant parent must be rewritten");

    let moved_file = dao::get_f_node(&pool, format!("{}/sub/f", dst))
        .await
        .unwrap()
        .expect("file moved");
    assert_eq!(moved_file.parent, format!("{}/sub", dst));

    // Prefix-sibling must be untouched.
    assert!(
        dao::get_f_node(&pool, sibling.clone())
            .await
            .unwrap()
            .is_some(),
        "prefix-sibling must survive the rename"
    );

    // Parent's children array swapped old name for new.
    let home = dao::get_f_node(&pool, "/home".to_string())
        .await
        .unwrap()
        .expect("home");
    assert!(home.children.contains(&format!("renamed{}", tag)));
    assert!(!home.children.contains(&format!("mv{}", tag)));

    dao::delete_path(&pool, dst).await.ok();
    dao::delete_path(&pool, sibling).await.ok();
}
