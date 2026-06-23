//! Verifies the Rust-side `path_digest` (used for lookups) produces the exact
//! same bytes as Postgres `hmac(path, db_pass, 'sha256')` (used by inserts,
//! renames, and the backfill). If these ever diverge, lookups silently stop
//! matching stored rows, so this invariant must hold.

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
async fn rust_and_pg_path_digests_match() {
    // SAFETY: single-threaded test, no concurrent env access
    unsafe { std::env::set_var("DB_PASS", "securefs") };
    let pool = test_pool();
    let client = pool.get().await.unwrap();

    for path in ["/", "/home", "/home/alice", "/home/alice/notes.txt"] {
        let rust = dao::path_digest(path);
        let row = client
            .query_one(
                "SELECT hmac($1 ::text, $2 ::text, 'sha256') AS d",
                &[&path, &"securefs"],
            )
            .await
            .unwrap();
        let pg: Vec<u8> = row.get("d");
        assert_eq!(rust, pg, "digest mismatch for {}", path);
    }
}
