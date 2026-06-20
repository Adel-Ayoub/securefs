// Drift sentinel: schema is owned by refinery migrations run from
// init_db. Verifies the baseline is idempotent (re-running applies nothing new)
// and that it actually built the schema, not just recorded a history row.

use deadpool_postgres::{Config, ManagerConfig, Pool, RecyclingMethod, Runtime};
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
async fn migrations_are_idempotent_and_build_schema() {
    // SAFETY: single-threaded test — no concurrent env access.
    unsafe { std::env::set_var("DB_PASS", "securefs") };

    let pool = test_pool();

    // init_db runs migrations; running it twice must succeed without drift.
    dao::init_db(&pool).await.expect("init_db first run");
    dao::init_db(&pool)
        .await
        .expect("init_db second run (idempotent)");

    let client = pool.get().await.unwrap();

    // The baseline is recorded in refinery's history.
    let applied: i64 = client
        .query_one(
            "SELECT count(*)::bigint FROM refinery_schema_history WHERE version >= 1",
            &[],
        )
        .await
        .expect("query refinery history")
        .get(0);
    assert!(applied >= 1, "baseline migration must be recorded");

    // The migration actually built the schema (a column added post-base-table).
    let has_parent_digest: bool = client
        .query_one(
            "SELECT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'fnode' AND column_name = 'parent_digest'
            )",
            &[],
        )
        .await
        .expect("introspect schema")
        .get(0);
    assert!(
        has_parent_digest,
        "baseline must create fnode.parent_digest"
    );
}
