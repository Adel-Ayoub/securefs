use std::env;

use aes_gcm::{Aes256Gcm, KeyInit};
use deadpool_postgres::Pool;
use rand_core::OsRng;

use super::{conn, get_db_pass, key_gen, salt_pass, DaoError};

// Arbitrary fixed key so concurrent server starts serialize on the same
// advisory lock while bootstrapping the admin account.
const ADMIN_BOOTSTRAP_LOCK: i64 = 776_655_001;

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
        let key = key_gen()
            .map_err(|_| DaoError::ParseError("could not serialize symmetric key".into()))?;
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

/// Ensure required seed data and tables exist.
pub async fn init_db(pool: &Pool) -> Result<(), DaoError> {
    let client = conn(pool).await?;

    // Create audit_log table if it doesn't exist
    client
        .execute(
            "CREATE TABLE IF NOT EXISTS audit_log (
                id BIGSERIAL PRIMARY KEY,
                ts BIGINT NOT NULL,
                event VARCHAR(64) NOT NULL,
                username VARCHAR(64) NOT NULL,
                resource VARCHAR(512) NOT NULL,
                result VARCHAR(256) NOT NULL,
                ip VARCHAR(45)
            )",
            &[],
        )
        .await
        .map_err(|e| DaoError::QueryFailed(format!("create audit_log: {}", e)))?;
    let _ = client
        .execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_log_ts ON audit_log(ts DESC)",
            &[],
        )
        .await;

    // Add TOTP columns to users table (idempotent)
    let _ = client
        .execute(
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret VARCHAR DEFAULT NULL",
            &[],
        )
        .await;
    let _ = client
        .execute(
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_last_step BIGINT",
            &[],
        )
        .await;

    // Persist FNode metadata that older schemas lacked (idempotent).
    for ddl in [
        "ALTER TABLE fnode ADD COLUMN IF NOT EXISTS size_bytes BIGINT DEFAULT 0",
        "ALTER TABLE fnode ADD COLUMN IF NOT EXISTS created_at BIGINT DEFAULT 0",
        "ALTER TABLE fnode ADD COLUMN IF NOT EXISTS modified_at BIGINT DEFAULT 0",
        "ALTER TABLE fnode ADD COLUMN IF NOT EXISTS link_target VARCHAR",
        "ALTER TABLE fnode ADD COLUMN IF NOT EXISTS path_digest BYTEA",
        "ALTER TABLE fnode ADD COLUMN IF NOT EXISTS parent_digest BYTEA",
    ] {
        let _ = client.execute(ddl, &[]).await;
    }

    // Backfill the keyed path digest for rows that predate the column, then
    // enforce uniqueness on it and on user names. A collision here means
    // genuinely duplicate paths/users (corruption) and fails the build loudly.
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
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_fnode_path_digest ON fnode(path_digest)",
            &[],
        )
        .await
        .map_err(|e| DaoError::QueryFailed(format!("create path_digest index: {}", e)))?;
    // Keyed digest of each node's parent path, so listing a directory's children
    // is an indexed lookup instead of a full-table decrypt scan. Not unique:
    // siblings share a parent.
    client
        .execute(
            "UPDATE fnode
             SET parent_digest = hmac(pgp_sym_decrypt(parent ::bytea, $1 ::text), $1 ::text, 'sha256')
             WHERE parent_digest IS NULL AND parent IS NOT NULL",
            &[&db_pass],
        )
        .await
        .map_err(|e| DaoError::QueryFailed(format!("backfill parent_digest: {}", e)))?;
    client
        .execute(
            "CREATE INDEX IF NOT EXISTS idx_fnode_parent_digest ON fnode(parent_digest)",
            &[],
        )
        .await
        .map_err(|e| DaoError::QueryFailed(format!("create parent_digest index: {}", e)))?;
    client
        .execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_user_name ON users(user_name)",
            &[],
        )
        .await
        .map_err(|e| DaoError::QueryFailed(format!("create user_name index: {}", e)))?;

    // Identity columns must never be null.
    client
        .execute("ALTER TABLE users ALTER COLUMN user_name SET NOT NULL", &[])
        .await
        .map_err(|e| DaoError::QueryFailed(format!("user_name not null: {}", e)))?;
    client
        .execute("ALTER TABLE groups ALTER COLUMN g_name SET NOT NULL", &[])
        .await
        .map_err(|e| DaoError::QueryFailed(format!("g_name not null: {}", e)))?;

    // Make the user->group reference explicit and safe: deleting a group nulls
    // its members' group_name rather than cascading into user deletion, and a
    // rename propagates. DROP+ADD inside one DO block is a single transaction,
    // so it stays idempotent and safe even if two instances boot at once.
    client
        .execute(
            "DO $$ BEGIN
                ALTER TABLE users DROP CONSTRAINT IF EXISTS users_group_name_fkey;
                ALTER TABLE users ADD CONSTRAINT users_group_name_fkey
                    FOREIGN KEY (group_name) REFERENCES groups(g_name)
                    ON UPDATE CASCADE ON DELETE SET NULL;
            END $$;",
            &[],
        )
        .await
        .map_err(|e| DaoError::QueryFailed(format!("tighten group_name fk: {}", e)))?;

    drop(client);

    bootstrap(pool).await?;
    Ok(())
}
