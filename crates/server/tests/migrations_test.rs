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

#[tokio::test]
async fn crypto_meta_seeded_and_dek_backfill() {
    // SAFETY: single-threaded test — no concurrent env access.
    unsafe { std::env::set_var("DB_PASS", "securefs") };

    let pool = test_pool();
    dao::init_db(&pool).await.expect("init_db");

    // crypto_meta is seeded to generation 1 by migration V3.
    assert_eq!(
        dao::get_kek_generation(&pool)
            .await
            .expect("read generation"),
        1
    );

    // The generation-prefix backfill (same statement V3 runs) turns a legacy
    // 60-byte DEK into a 61-byte value whose first byte is generation 1.
    let client = pool.get().await.unwrap();
    let legacy = vec![0u8; 60];
    let prefixed: Vec<u8> = client
        .query_one(
            "SELECT CASE WHEN octet_length($1::bytea) = 60
                         THEN '\\x01'::bytea || $1::bytea ELSE $1::bytea END",
            &[&legacy],
        )
        .await
        .expect("backfill statement")
        .get(0);
    assert_eq!(prefixed.len(), 61);
    assert_eq!(prefixed[0], 1);
}

#[tokio::test]
async fn merkle_root_column_round_trips() {
    // SAFETY: single-threaded test - no concurrent env access.
    unsafe { std::env::set_var("DB_PASS", "securefs") };

    let pool = test_pool();
    dao::init_db(&pool).await.expect("init_db");

    // V4 adds fnode.merkle_root; the DAO persists and reads it by path digest.
    let path = "/home/merkle_root_test_file";
    let digest = dao::path_digest(path);
    let client = pool.get().await.unwrap();
    client
        .execute("DELETE FROM fnode WHERE path_digest = $1", &[&digest])
        .await
        .unwrap();
    client
        .execute(
            "INSERT INTO fnode (dir, path_digest) VALUES (false, $1)",
            &[&digest],
        )
        .await
        .unwrap();

    assert!(dao::get_merkle_root(&pool, path.to_string())
        .await
        .unwrap()
        .is_none());
    dao::set_merkle_root(&pool, path.to_string(), "deadbeef")
        .await
        .unwrap();
    assert_eq!(
        dao::get_merkle_root(&pool, path.to_string())
            .await
            .unwrap()
            .as_deref(),
        Some("deadbeef")
    );

    client
        .execute("DELETE FROM fnode WHERE path_digest = $1", &[&digest])
        .await
        .unwrap();
}
