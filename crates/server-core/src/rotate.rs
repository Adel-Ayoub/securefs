//! Offline KEK rotation. Rewraps every file's wrapped DEK from the current
//! generation's master to a new one without touching file bodies, then records
//! the new generation. Run with the server stopped:
//!
//!   DATA_KEY=<current> DATA_KEY_NEW=<target> securefs-server rotate-kek
//!
//! Afterward set DATA_KEY to the new master and restart. The generation byte on
//! each wrapped DEK makes a run idempotent: a re-run after an interruption skips
//! DEKs already rewrapped and finishes the rest.

use std::env;

use deadpool_postgres::Pool;
use log::info;

use crate::config::NetConfig;
use crate::dao;

use crate::crypto;
use crate::pool::build_pool;

// Rewrap at most this many DEKs per page; bounds memory on large stores.
const PAGE: i64 = 256;

#[derive(Debug, Default)]
struct RotationStats {
    rewrapped: u64,
    already_current: u64,
}

pub async fn run() -> Result<(), String> {
    // Both masters must be present: DATA_KEY is the current one, DATA_KEY_NEW
    // the target. DATA_KEY has no DB_PASS fallback here - rotation is explicit.
    let old_master =
        dao::data_key_secret().ok_or("rotate-kek requires DATA_KEY (the current master)")?;
    let new_master = env::var("DATA_KEY_NEW")
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or("rotate-kek requires DATA_KEY_NEW (the target master)")?;
    if new_master == old_master {
        return Err("DATA_KEY_NEW must differ from DATA_KEY".into());
    }

    let net = NetConfig::from_env().map_err(|e| e.to_string())?;
    let db_pass = dao::get_db_pass();
    let pool = build_pool(&net, &db_pass)?;

    let stats = rotate(&pool, old_master.as_bytes(), new_master.as_bytes()).await?;

    // Re-seal the audit head under the new master so the signed tree head is
    // valid immediately, before the server restarts with the new DATA_KEY.
    let seal_key = crypto::audit_seal_key_from_master(new_master.as_bytes());
    if let Err(e) = dao::seal_audit_head(&pool, &seal_key).await {
        log::warn!("audit checkpoint re-seal after rotation failed: {}", e);
    }

    let new_gen = dao::get_kek_generation(&pool)
        .await
        .map_err(|e| e.to_string())?;
    println!(
        "KEK rotation complete: {} DEK(s) rewrapped, {} already current, now at generation {}.",
        stats.rewrapped, stats.already_current, new_gen
    );
    println!("Set DATA_KEY to the new master and restart the server.");
    Ok(())
}

// Core rotation, separated from env/IO so it is testable against a pool.
async fn rotate(
    pool: &Pool,
    old_master: &[u8],
    new_master: &[u8],
) -> Result<RotationStats, String> {
    let current_gen = dao::get_kek_generation(pool)
        .await
        .map_err(|e| e.to_string())?;
    let new_gen = current_gen
        .checked_add(1)
        .ok_or("KEK generation overflow")?;

    // Guard against silent data loss: refuse while any legacy non-envelope file
    // exists, since rotating the master would make it unreadable.
    let legacy = dao::count_legacy_unwrapped_files(pool)
        .await
        .map_err(|e| e.to_string())?;
    if legacy > 0 {
        return Err(format!(
            "{} legacy (non-envelope) file(s) present; rotation would make them unreadable - convert them to envelope format first",
            legacy
        ));
    }

    let old_kek = crypto::kek_from_master(old_master);
    let new_kek = crypto::kek_from_master(new_master);

    // Pre-flight: the current master must actually open an existing DEK, so a
    // wrong DATA_KEY fails before anything is written.
    if let Some(sample) = dao::sample_wrapped_dek(pool)
        .await
        .map_err(|e| e.to_string())?
    {
        let gen = crypto::wrapped_generation(&sample).map_err(|e| e.to_string())?;
        if gen == current_gen && crypto::unwrap_with_master(&sample, old_master).is_none() {
            return Err("DATA_KEY does not match the stored DEKs (wrong current master)".into());
        }
    }

    info!("rotating KEK generation {} -> {}", current_gen, new_gen);

    let mut stats = RotationStats::default();
    let mut after_id = 0i64;
    loop {
        let page = dao::wrapped_deks_after(pool, after_id, PAGE)
            .await
            .map_err(|e| e.to_string())?;
        if page.is_empty() {
            break;
        }
        for (id, wrapped) in &page {
            after_id = *id;
            let gen = crypto::wrapped_generation(wrapped)
                .map_err(|e| format!("file id {}: {}", id, e))?;
            if gen == new_gen {
                stats.already_current += 1; // resumed run: already rewrapped
                continue;
            }
            if gen != current_gen {
                return Err(format!(
                    "file id {} has unexpected KEK generation {} (expected {} or {})",
                    id, gen, current_gen, new_gen
                ));
            }
            let rewrapped = crypto::rewrap_dek(wrapped, &old_kek, &new_kek, new_gen)
                .map_err(|e| format!("file id {}: rewrap failed: {}", id, e))?;
            dao::update_wrapped_dek_by_id(pool, *id, &rewrapped)
                .await
                .map_err(|e| e.to_string())?;
            stats.rewrapped += 1;
        }
    }

    // Every DEK is now at the new generation; record it so new writes wrap there
    // once the server restarts with the new master.
    dao::set_kek_generation(pool, new_gen)
        .await
        .map_err(|e| e.to_string())?;
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use deadpool_postgres::{Config, ManagerConfig, RecyclingMethod, Runtime};
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

    // Clear all files (keep directories) so each test starts from a known set.
    async fn reset(pool: &Pool) {
        dao::init_db(pool).await.unwrap();
        let client = pool.get().await.unwrap();
        client
            .execute("DELETE FROM fnode WHERE dir = false", &[])
            .await
            .unwrap();
        dao::set_kek_generation(pool, 1).await.unwrap();
    }

    async fn insert_envelope_file(pool: &Pool, digest: &[u8], content: &[u8]) -> Vec<u8> {
        let (_blob, wrapped) = crypto::encrypt_file_content(content);
        let client = pool.get().await.unwrap();
        client
            .execute(
                "INSERT INTO fnode (dir, wrapped_dek, path_digest) VALUES (false, $1, $2)",
                &[&wrapped, &digest],
            )
            .await
            .unwrap();
        wrapped
    }

    async fn fetch_wrapped(pool: &Pool, digest: &[u8]) -> Vec<u8> {
        let client = pool.get().await.unwrap();
        client
            .query_one(
                "SELECT wrapped_dek FROM fnode WHERE path_digest = $1",
                &[&digest],
            )
            .await
            .unwrap()
            .get::<_, Vec<u8>>(0)
    }

    #[tokio::test]
    async fn rotation_rewraps_deks_and_preserves_them() {
        let pool = test_pool();
        reset(&pool).await;

        let d1 = vec![1u8; 32];
        let d2 = vec![2u8; 32];
        let w1 = insert_envelope_file(&pool, &d1, b"file one").await;
        let w2 = insert_envelope_file(&pool, &d2, b"file two").await;
        assert_eq!(crypto::wrapped_generation(&w1).unwrap(), 1);

        let stats = rotate(&pool, b"securefs", b"new-master").await.unwrap();
        assert_eq!(stats.rewrapped, 2);
        assert_eq!(dao::get_kek_generation(&pool).await.unwrap(), 2);

        // Each DEK is now generation 2, opens under the new master only, and the
        // underlying DEK is unchanged so the file body still decrypts.
        for (digest, original) in [(&d1, &w1), (&d2, &w2)] {
            let now = fetch_wrapped(&pool, digest).await;
            assert_eq!(crypto::wrapped_generation(&now).unwrap(), 2);
            let before = crypto::unwrap_with_master(original, b"securefs").unwrap();
            let after = crypto::unwrap_with_master(&now, b"new-master").unwrap();
            assert_eq!(&**before, &**after, "DEK must survive rotation");
            assert!(crypto::unwrap_with_master(&now, b"securefs").is_none());
        }

        // Idempotent: re-running with the new master as current rewraps nothing.
        let again = rotate(&pool, b"new-master", b"newer-master").await.unwrap();
        assert_eq!(again.rewrapped, 2); // 2 -> 3
        let third = rotate(&pool, b"new-master", b"newer-master").await;
        // current is now 3; old master "new-master" no longer matches -> refused.
        assert!(third.is_err());

        let client = pool.get().await.unwrap();
        client
            .execute("DELETE FROM fnode WHERE dir = false", &[])
            .await
            .unwrap();
        dao::set_kek_generation(&pool, 1).await.unwrap();
    }

    async fn fetch_id(pool: &Pool, digest: &[u8]) -> i64 {
        let client = pool.get().await.unwrap();
        client
            .query_one("SELECT id FROM fnode WHERE path_digest = $1", &[&digest])
            .await
            .unwrap()
            .get::<_, i64>(0)
    }

    #[tokio::test]
    async fn rotation_resumes_and_skips_already_rewrapped() {
        let pool = test_pool();
        reset(&pool).await;

        let d1 = vec![3u8; 32];
        let d2 = vec![4u8; 32];
        let w1 = insert_envelope_file(&pool, &d1, b"a").await;
        let _w2 = insert_envelope_file(&pool, &d2, b"b").await;

        // Simulate a crash mid-rotation: file 1's DEK is already rewrapped to
        // generation 2 under the new master, but crypto_meta still says 1.
        let old_kek = crypto::kek_from_master(b"securefs");
        let new_kek = crypto::kek_from_master(b"new-master");
        let pre = crypto::rewrap_dek(&w1, &old_kek, &new_kek, 2).unwrap();
        let id1 = fetch_id(&pool, &d1).await;
        dao::update_wrapped_dek_by_id(&pool, id1, &pre)
            .await
            .unwrap();

        // Resuming skips file 1 (already generation 2) and rewraps file 2.
        let stats = rotate(&pool, b"securefs", b"new-master").await.unwrap();
        assert_eq!(stats.already_current, 1);
        assert_eq!(stats.rewrapped, 1);
        assert_eq!(dao::get_kek_generation(&pool).await.unwrap(), 2);

        let client = pool.get().await.unwrap();
        client
            .execute("DELETE FROM fnode WHERE dir = false", &[])
            .await
            .unwrap();
        dao::set_kek_generation(&pool, 1).await.unwrap();
    }

    #[tokio::test]
    async fn rotation_aborts_on_legacy_blob() {
        let pool = test_pool();
        reset(&pool).await;

        // A non-directory file with no wrapped DEK is a legacy v0/v1 blob.
        let client = pool.get().await.unwrap();
        client
            .execute(
                "INSERT INTO fnode (dir, wrapped_dek, link_target, path_digest)
                 VALUES (false, NULL, NULL, $1)",
                &[&vec![9u8; 32]],
            )
            .await
            .unwrap();

        let err = rotate(&pool, b"securefs", b"new-master").await.unwrap_err();
        assert!(
            err.contains("legacy"),
            "expected legacy guard, got: {}",
            err
        );

        client
            .execute("DELETE FROM fnode WHERE dir = false", &[])
            .await
            .unwrap();
    }
}
