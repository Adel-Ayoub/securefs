// Listing a directory resolves children via the keyed parent_digest index, and
// returns exactly the nodes whose parent matches, never a sibling's children.

use deadpool_postgres::{Config, ManagerConfig, Pool, RecyclingMethod, Runtime};
use securefs_server::dao::records::FNode;
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

fn node(name: &str, path: &str, parent: &str, dir: bool) -> FNode {
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

#[tokio::test]
async fn get_children_uses_parent_digest_index() {
    // SAFETY: single-threaded test, no concurrent env access
    unsafe { std::env::set_var("DB_PASS", "securefs") };
    let pool = test_pool();
    dao::init_db(&pool).await.expect("init_db");

    let tag = Uuid::new_v4();
    let dir_path = format!("/home/d_{}", tag);
    let other_path = format!("/home/o_{}", tag);

    dao::add_file(&pool, node(&format!("d_{}", tag), &dir_path, "/home", true))
        .await
        .expect("dir");
    dao::add_file(
        &pool,
        node(&format!("o_{}", tag), &other_path, "/home", true),
    )
    .await
    .expect("other dir");
    dao::add_file(
        &pool,
        node("a", &format!("{}/a", dir_path), &dir_path, false),
    )
    .await
    .expect("a");
    dao::add_file(
        &pool,
        node("b", &format!("{}/b", dir_path), &dir_path, false),
    )
    .await
    .expect("b");
    dao::add_file(
        &pool,
        node("c", &format!("{}/c", other_path), &other_path, false),
    )
    .await
    .expect("c");

    let mut names: Vec<String> = dao::get_children(&pool, dir_path.clone())
        .await
        .expect("get_children")
        .into_iter()
        .map(|n| n.name)
        .collect();
    names.sort();
    assert_eq!(names, vec!["a".to_string(), "b".to_string()]);

    // A sibling directory's child must not leak into this listing.
    let other: Vec<String> = dao::get_children(&pool, other_path.clone())
        .await
        .expect("get_children other")
        .into_iter()
        .map(|n| n.name)
        .collect();
    assert_eq!(other, vec!["c".to_string()]);

    let client = pool.get().await.unwrap();
    for p in [&dir_path, &other_path] {
        client
            .execute(
                "DELETE FROM fnode
                 WHERE pgp_sym_decrypt(path::bytea, $2::text) = $1
                    OR left(pgp_sym_decrypt(path::bytea, $2::text), length($1) + 1) = $1 || '/'",
                &[p, &"securefs"],
            )
            .await
            .ok();
    }
}
