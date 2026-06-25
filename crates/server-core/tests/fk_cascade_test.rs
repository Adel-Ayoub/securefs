// The user->group reference is enforced and has explicit, safe cascade rules:
// deleting a group nulls its members' group_name (never deletes the user), and
// a user cannot reference a group that does not exist.

use deadpool_postgres::{Config, ManagerConfig, Pool, RecyclingMethod, Runtime};
use securefs_server_core::dao;
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
async fn user_group_fk_set_null_on_delete_and_enforced() {
    // SAFETY: single-threaded test, no concurrent env access
    unsafe { std::env::set_var("DB_PASS", "securefs") };
    let pool = test_pool();
    dao::init_db(&pool).await.expect("init_db");
    let client = pool.get().await.unwrap();

    let tag = Uuid::new_v4().simple().to_string();
    let grp = format!("g_{}", tag);
    let usr = format!("u_{}", tag);
    client
        .execute("DELETE FROM users WHERE user_name = $1", &[&usr])
        .await
        .ok();
    client
        .execute("DELETE FROM groups WHERE g_name = $1", &[&grp])
        .await
        .ok();

    // The FK carries ON DELETE SET NULL (n) and ON UPDATE CASCADE (c).
    let row = client
        .query_one(
            "SELECT confdeltype::text AS d, confupdtype::text AS u
             FROM pg_constraint
             WHERE conrelid = 'users'::regclass AND conname = 'users_group_name_fkey'",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(
        row.get::<_, String>("d"),
        "n",
        "on delete should be SET NULL"
    );
    assert_eq!(
        row.get::<_, String>("u"),
        "c",
        "on update should be CASCADE"
    );

    client
        .execute(
            "INSERT INTO groups (g_name, users) VALUES ($1, ARRAY[]::varchar[])",
            &[&grp],
        )
        .await
        .unwrap();

    // A user cannot reference a non-existent group.
    let bogus = client
        .execute(
            "INSERT INTO users (user_name, group_name, is_admin) VALUES ($1, $2, false)",
            &[&usr, &format!("nope_{}", tag)],
        )
        .await;
    assert!(bogus.is_err(), "FK should reject a non-existent group");

    // user_name is NOT NULL.
    let null_name = client
        .execute(
            "INSERT INTO users (user_name, is_admin) VALUES (NULL, false)",
            &[],
        )
        .await;
    assert!(null_name.is_err(), "user_name NOT NULL should be enforced");

    // Valid membership, then deleting the group nulls the member but keeps the user.
    client
        .execute(
            "INSERT INTO users (user_name, group_name, is_admin) VALUES ($1, $2, false)",
            &[&usr, &grp],
        )
        .await
        .unwrap();
    client
        .execute("DELETE FROM groups WHERE g_name = $1", &[&grp])
        .await
        .unwrap();

    let after = client
        .query_one("SELECT group_name FROM users WHERE user_name = $1", &[&usr])
        .await
        .expect("user must still exist after its group is deleted");
    assert!(
        after.get::<_, Option<String>>(0).is_none(),
        "member's group_name should be NULL after the group is deleted"
    );

    client
        .execute("DELETE FROM users WHERE user_name = $1", &[&usr])
        .await
        .ok();
}
