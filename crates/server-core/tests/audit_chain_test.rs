// Proves the audit log is tamper-evident against a real database: appended
// entries chain, the chain verifies, an in-place edit (what a DBA covering
// tracks would do) is pinpointed at the altered row, and restoring the row
// re-validates. The chain is global and this suite shares one database, so the
// test is robust to pre-existing entries and leaves the chain pristine.

use deadpool_postgres::{Config, ManagerConfig, Pool, RecyclingMethod, Runtime};
use securefs_server_core::crypto;
use securefs_server_core::dao::{self, ChainStatus};
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

async fn ready_pool() -> Pool {
    // SAFETY: single-threaded tests — no concurrent env access.
    unsafe { std::env::set_var("DB_PASS", "securefs") };
    let pool = test_pool();
    dao::init_db(&pool).await.expect("init_db");
    pool
}

#[tokio::test]
async fn appends_chain_verify_and_detect_tampering() {
    let pool = ready_pool().await;

    // init_db backfills any pre-chain rows, so the chain starts intact.
    let (base_entries, base_head) = match dao::verify_audit_chain(&pool, None).await.unwrap() {
        ChainStatus::Intact {
            entries, head_seq, ..
        } => (entries, head_seq),
        ChainStatus::Broken { seq, reason } => {
            panic!("precondition: chain already broken at {}: {}", seq, reason)
        }
    };

    let e1 = dao::append_audit_log(
        &pool,
        "TEST_EVENT",
        "alice",
        "/r1",
        "ok",
        Some("203.0.113.7"),
    )
    .await
    .unwrap();
    let _e2 = dao::append_audit_log(&pool, "TEST_EVENT", "bob", "/r2", "denied", None)
        .await
        .unwrap();
    let e3 = dao::append_audit_log(&pool, "TEST_EVENT", "carol", "/r3", "ok", None)
        .await
        .unwrap();

    assert_eq!(e1.seq, base_head + 1, "seq continues from the head");
    assert_eq!(e3.seq, base_head + 3, "seq is gapless");

    match dao::verify_audit_chain(&pool, None).await.unwrap() {
        ChainStatus::Intact {
            entries,
            head_seq,
            head_hash,
        } => {
            assert_eq!(entries, base_entries + 3);
            assert_eq!(head_seq, e3.seq);
            assert_eq!(head_hash, e3.entry_hash, "verify reproduces the head hash");
        }
        ChainStatus::Broken { seq, reason } => {
            panic!("chain should be intact, broke at {}: {}", seq, reason)
        }
    }

    // Tamper in place: rewrite a logged result without touching the hash.
    let client = pool.get().await.unwrap();
    let original: String = client
        .query_one("SELECT result FROM audit_log WHERE seq = $1", &[&e1.seq])
        .await
        .unwrap()
        .get(0);
    client
        .execute(
            "UPDATE audit_log SET result = 'tampered' WHERE seq = $1",
            &[&e1.seq],
        )
        .await
        .unwrap();

    match dao::verify_audit_chain(&pool, None).await.unwrap() {
        ChainStatus::Broken { seq, .. } => {
            assert_eq!(seq, e1.seq, "verify pinpoints the altered row")
        }
        ChainStatus::Intact { .. } => panic!("a tampered chain must not verify"),
    }

    // Restore so later serial tests still see an intact chain.
    client
        .execute(
            "UPDATE audit_log SET result = $1 WHERE seq = $2",
            &[&original, &e1.seq],
        )
        .await
        .unwrap();
    match dao::verify_audit_chain(&pool, None).await.unwrap() {
        ChainStatus::Intact { .. } => {}
        ChainStatus::Broken { seq, reason } => {
            panic!(
                "restoring the row should re-validate, broke at {}: {}",
                seq, reason
            )
        }
    }
}

#[tokio::test]
async fn signed_head_anchors_and_detects_truncation() {
    let pool = ready_pool().await;
    // The real derived seal key (the production seam), not a fabricated constant;
    // a different key must still be rejected below.
    let key = crypto::audit_seal_key();
    let wrong_key = [9u8; 32];

    dao::append_audit_log(&pool, "TEST_SEAL", "alice", "/s1", "ok", None)
        .await
        .unwrap();
    let b = dao::append_audit_log(&pool, "TEST_SEAL", "bob", "/s2", "ok", None)
        .await
        .unwrap();

    let (sealed_seq, sealed_hash) = dao::seal_audit_head(&pool, &key)
        .await
        .unwrap()
        .expect("chain is non-empty");
    assert_eq!(sealed_seq, b.seq);
    assert_eq!(sealed_hash, b.entry_hash);

    // The signed head validates under the key.
    match dao::verify_audit_chain(&pool, Some(&key)).await.unwrap() {
        ChainStatus::Intact { head_seq, .. } => assert_eq!(head_seq, b.seq),
        ChainStatus::Broken { seq, reason } => {
            panic!("sealed chain should verify, broke at {}: {}", seq, reason)
        }
    }

    // A wrong key cannot validate the seal (key-binding / forgery resistance).
    match dao::verify_audit_chain(&pool, Some(&wrong_key))
        .await
        .unwrap()
    {
        ChainStatus::Broken { .. } => {}
        ChainStatus::Intact { .. } => panic!("a checkpoint must not validate under the wrong key"),
    }

    // Truncation below the signed head: delete the sealed tail row. The unkeyed
    // walk alone would accept the shorter chain; the seal catches the missing head.
    let client = pool.get().await.unwrap();
    let row = client
        .query_one(
            "SELECT ts, event, username, resource, result, ip, prev_hash, entry_hash
             FROM audit_log WHERE seq = $1",
            &[&b.seq],
        )
        .await
        .unwrap();
    let ts: i64 = row.get(0);
    let event: String = row.get(1);
    let username: String = row.get(2);
    let resource: String = row.get(3);
    let result: String = row.get(4);
    let ip: Option<String> = row.get(5);
    let prev_hash: Vec<u8> = row.get(6);
    let entry_hash: Vec<u8> = row.get(7);

    client
        .execute("DELETE FROM audit_log WHERE seq = $1", &[&b.seq])
        .await
        .unwrap();

    match dao::verify_audit_chain(&pool, Some(&key)).await.unwrap() {
        ChainStatus::Broken { seq, .. } => {
            assert_eq!(seq, b.seq, "verify flags the truncated sealed head")
        }
        ChainStatus::Intact { .. } => panic!("truncation below the signed head must be detected"),
    }

    // Restore the row exactly so the shared chain is left pristine.
    client
        .execute(
            "INSERT INTO audit_log
                (ts, event, username, resource, result, ip, seq, prev_hash, entry_hash)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
            &[
                &ts,
                &event,
                &username,
                &resource,
                &result,
                &ip,
                &b.seq,
                &prev_hash,
                &entry_hash,
            ],
        )
        .await
        .unwrap();
    match dao::verify_audit_chain(&pool, Some(&key)).await.unwrap() {
        ChainStatus::Intact { .. } => {}
        ChainStatus::Broken { seq, reason } => {
            panic!("restore should re-validate, broke at {}: {}", seq, reason)
        }
    }
}
