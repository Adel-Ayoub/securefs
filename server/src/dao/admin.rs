use std::env;

use aes_gcm::{Aes256Gcm, KeyInit};
use deadpool_postgres::Pool;
use rand_core::OsRng;

use super::{conn, get_db_pass, key_gen, salt_pass, DaoError};

mod embedded {
    refinery::embed_migrations!("migrations");
}

// Arbitrary fixed key so concurrent server starts serialize on the same
// advisory lock while bootstrapping the admin account.
const ADMIN_BOOTSTRAP_LOCK: i64 = 776_655_001;

// Separate fixed key serializing schema migrations across concurrent starts.
const MIGRATION_LOCK: i64 = 776_655_002;

// Generate a strong random password as 32 hex-encoded random bytes.
fn generate_admin_password() -> String {
    let key = Aes256Gcm::generate_key(&mut OsRng);
    let bytes: [u8; 32] = key.into();
    hex::encode(bytes)
}

// Seed the admin group, the /home root, and the admin user on first boot,
// keyed by the live secret. The admin password comes from ADMIN_PASSWORD or is
// randomly generated and printed once. An advisory lock plus existence checks
// keep it idempotent and safe against concurrent starts.
async fn bootstrap(pool: &Pool) -> Result<(), DaoError> {
    let mut client = conn(pool).await?;
    let tx = client
        .transaction()
        .await
        .map_err(|e| DaoError::QueryFailed(format!("begin tx: {}", e)))?;

    tx.execute("SELECT pg_advisory_xact_lock($1)", &[&ADMIN_BOOTSTRAP_LOCK])
        .await
        .map_err(|e| DaoError::QueryFailed(format!("bootstrap lock: {}", e)))?;

    let db_pass = get_db_pass();

    let has_group = tx
        .query_opt("SELECT 1 FROM groups WHERE g_name = 'admin_group'", &[])
        .await
        .map_err(|e| DaoError::QueryFailed(format!("check admin group: {}", e)))?
        .is_some();
    if !has_group {
        tx.execute(
            "INSERT INTO groups (g_name, users) VALUES ('admin_group', $1)",
            &[&Vec::<String>::new()],
        )
        .await
        .map_err(|e| DaoError::QueryFailed(format!("create admin group: {}", e)))?;
    }

    // /home root directory; idempotent on the unique path digest.
    tx.execute(
        "INSERT INTO fnode
            (name, path, owner, hash, parent, dir, u, g, o, children,
             encrypted_name, size_bytes, created_at, modified_at, path_digest,
             parent_digest)
         SELECT pgp_sym_encrypt('home', $1::text), pgp_sym_encrypt('/home', $1::text),
                pgp_sym_encrypt('', $1::text), '', pgp_sym_encrypt('', $1::text), true,
                pgp_sym_encrypt('4', $1::text), pgp_sym_encrypt('4', $1::text),
                pgp_sym_encrypt('4', $1::text), ARRAY[]::VARCHAR[], '', 0, 0, 0,
                hmac('/home', $1::text, 'sha256'),
                hmac('', $1::text, 'sha256')
         WHERE NOT EXISTS (
             SELECT 1 FROM fnode WHERE path_digest = hmac('/home', $1::text, 'sha256'))",
        &[&db_pass],
    )
    .await
    .map_err(|e| DaoError::QueryFailed(format!("seed home: {}", e)))?;

    let has_admin = tx
        .query_opt("SELECT 1 FROM users WHERE user_name = 'admin'", &[])
        .await
        .map_err(|e| DaoError::QueryFailed(format!("check admin user: {}", e)))?
        .is_some();
    if !has_admin {
        let pass = match env::var("ADMIN_PASSWORD") {
            Ok(p) if !p.is_empty() => p,
            _ => {
                let generated = generate_admin_password();
                eprintln!(
                    "[SECUREFS] No ADMIN_PASSWORD set — generated an initial admin password."
                );
                eprintln!("[SECUREFS] Log in as  admin  with password:  {}", generated);
                eprintln!(
                    "[SECUREFS] Save it now and change it after first login; shown only once."
                );
                generated
            }
        };
        let salt = salt_pass(pass)?;
        let key = key_gen()?;
        tx.execute(
            "INSERT INTO users (user_name, group_name, salt, key, is_admin)
             VALUES ('admin', 'admin_group', $1, pgp_sym_encrypt($2 ::text, $3 ::text), true)",
            &[&salt, &key, &db_pass],
        )
        .await
        .map_err(|e| DaoError::QueryFailed(format!("create admin: {}", e)))?;
    }

    tx.commit()
        .await
        .map_err(|e| DaoError::QueryFailed(format!("commit: {}", e)))
}

/// Apply schema migrations, then runtime backfills and seed data.
pub async fn init_db(pool: &Pool) -> Result<(), DaoError> {
    // Schema is owned by forward-only migrations under server/migrations. The
    // baseline is idempotent, so this also adopts a database created by the
    // pre-migration init path.
    {
        let mut client = conn(pool).await?;
        // Serialize migrations across concurrent starts (parallel tests, and
        // later multiple server instances) so refinery never races to apply the
        // baseline. Session-level lock, released before the pooled connection
        // is reused.
        client
            .execute("SELECT pg_advisory_lock($1)", &[&MIGRATION_LOCK])
            .await
            .map_err(|e| DaoError::QueryFailed(format!("migration lock: {}", e)))?;
        let migrated = embedded::migrations::runner()
            .run_async(&mut **client)
            .await;
        let _ = client
            .execute("SELECT pg_advisory_unlock($1)", &[&MIGRATION_LOCK])
            .await;
        migrated.map_err(|e| DaoError::QueryFailed(format!("run migrations: {}", e)))?;
    }

    // Backfill keyed digests for rows that predate those columns. These use the
    // live DB_PASS secret, so they stay in Rust rather than in static SQL. A
    // genuinely duplicate path (corruption) trips the unique index and fails loud.
    let client = conn(pool).await?;
    let db_pass = get_db_pass();
    client
        .execute(
            "UPDATE fnode
             SET path_digest = hmac(pgp_sym_decrypt(path ::bytea, $1 ::text), $1 ::text, 'sha256')
             WHERE path_digest IS NULL",
            &[&db_pass],
        )
        .await
        .map_err(|e| DaoError::QueryFailed(format!("backfill path_digest: {}", e)))?;
    client
        .execute(
            "UPDATE fnode
             SET parent_digest = hmac(pgp_sym_decrypt(parent ::bytea, $1 ::text), $1 ::text, 'sha256')
             WHERE parent_digest IS NULL AND parent IS NOT NULL",
            &[&db_pass],
        )
        .await
        .map_err(|e| DaoError::QueryFailed(format!("backfill parent_digest: {}", e)))?;
    drop(client);

    // Adopt any pre-chain audit rows into the tamper-evident hash chain. The
    // hash is computed in application code, so this backfill stays in Rust like
    // the digest backfills above; it is a cheap no-op once everything is chained.
    let chained = super::backfill_audit_chain(pool).await?;
    if chained > 0 {
        log::info!("audit chain: backfilled {} pre-existing entries", chained);
    }

    bootstrap(pool).await?;
    Ok(())
}
