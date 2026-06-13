//! Data-access helpers for SecureFS.
//!
//! Handles authentication, key material generation, and CRUD helpers
//! that persist `FNode`, `User`, and `Group` records. Queries are kept
//! thin here so the server loop can stay focused on protocol flow.

use std::sync::Once;
use std::{env, fmt};

use aes_gcm::{Aes256Gcm, Key, KeyInit};
use argon2::{
    password_hash::{Encoding, PasswordHashString, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use deadpool_postgres::Pool;
use hmac::{Hmac, Mac};
use rand_core::OsRng;
use securefs_model::protocol::{FNode, User};
use serde_json;
use sha2::Sha256;

/// Typed error for all DAO operations.
#[derive(Debug)]
pub enum DaoError {
    /// Row not found when one was expected.
    NotFound,
    /// Query or execute failed at the database level.
    QueryFailed(String),
    /// Data could not be parsed (hash, key, JSON, etc.).
    ParseError(String),
    /// A constraint was violated (duplicate, FK, etc.).
    Conflict(String),
}

impl fmt::Display for DaoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DaoError::NotFound => write!(f, "not found"),
            DaoError::QueryFailed(msg) => write!(f, "query failed: {}", msg),
            DaoError::ParseError(msg) => write!(f, "parse error: {}", msg),
            DaoError::Conflict(msg) => write!(f, "conflict: {}", msg),
        }
    }
}

/// Get a connection from the pool, mapping errors to DaoError.
async fn conn(pool: &Pool) -> Result<deadpool_postgres::Object, DaoError> {
    pool.get()
        .await
        .map_err(|e| DaoError::QueryFailed(format!("pool: {}", e)))
}

static WARN_DEFAULT_PASS: Once = Once::new();

// Read a secret from env var `var`, or from the file named by `file_var`
// (contents trimmed). Lets deployments mount secrets as files instead of
// passing them through the environment. None if neither yields a value.
fn read_secret(var: &str, file_var: &str) -> Option<String> {
    if let Ok(v) = env::var(var) {
        if !v.is_empty() {
            return Some(v);
        }
    }
    if let Ok(path) = env::var(file_var) {
        if let Ok(contents) = std::fs::read_to_string(&path) {
            let trimmed = contents.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

// Database/pgcrypto secret, from DB_PASS or DB_PASS_FILE. Warns and uses an
// insecure default when unset; startup refuses this default outside dev.
pub fn get_db_pass() -> String {
    match read_secret("DB_PASS", "DB_PASS_FILE") {
        Some(pass) => pass,
        None => {
            WARN_DEFAULT_PASS.call_once(|| {
                eprintln!("[SECURITY WARNING] DB_PASS not set, using insecure default!");
                eprintln!("[SECURITY WARNING] Set DB_PASS environment variable for production.");
            });
            "TEMP".to_string()
        }
    }
}

// At-rest data-encryption secret if explicitly configured (DATA_KEY or
// DATA_KEY_FILE). No fallback to DB_PASS — production startup refuses to run
// without it.
pub fn data_key_secret() -> Option<String> {
    read_secret("DATA_KEY", "DATA_KEY_FILE")
}

// At-rest data-encryption key for runtime use. Prefers DATA_KEY; falls back to
// DB_PASS for development only (production requires DATA_KEY, checked at boot).
pub fn get_data_key() -> String {
    data_key_secret().unwrap_or_else(get_db_pass)
}

// Deterministic keyed digest of a plaintext path for indexed exact-match
// lookups. HMAC-SHA256 keyed by DB_PASS, so the digest reveals nothing about
// the path without the secret yet the same path always maps to the same value.
// Must match Postgres `hmac(path, db_pass, 'sha256')` so SQL-side maintenance
// (inserts, renames, backfill) and Rust-side lookups agree.
pub fn path_digest(path: &str) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(get_db_pass().as_bytes())
        .expect("HMAC accepts a key of any length");
    mac.update(path.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

/// Hash and salt a plaintext password using Argon2.
pub fn salt_pass(pass: String) -> Result<String, DaoError> {
    let b_pass = pass.as_bytes();
    let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
    let argon2 = Argon2::default();
    argon2
        .hash_password(b_pass, &salt)
        .map(|p| p.serialize().as_str().to_string())
        .map_err(|e| DaoError::ParseError(format!("argon2 hash failed: {}", e)))
}

/// Generate a random AES-256 key serialized to JSON for DB storage.
#[allow(clippy::result_unit_err)]
pub fn key_gen() -> Result<String, ()> {
    let key = Aes256Gcm::generate_key(&mut OsRng);
    let u8_32_arr: [u8; 32] = key.into();
    match serde_json::to_string(&u8_32_arr) {
        Ok(s) => Ok(s),
        Err(_) => Err(()),
    }
}

/// Verify a user's password against the stored Argon2 hash.
pub async fn auth_user(pool: &Pool, user_name: String, pass: String) -> Result<bool, DaoError> {
    let client = conn(pool).await?;
    let e = client
        .query_one(
            "SELECT u.salt FROM users u WHERE u.user_name=$1",
            &[&user_name],
        )
        .await;
    let res = match e {
        Ok(row) => row,
        Err(_) => return Ok(false),
    };
    let hash: String = res.get("salt");
    let hash_str: PasswordHashString = PasswordHashString::parse(hash.as_str(), Encoding::B64)
        .map_err(|_| DaoError::ParseError("invalid hash format".into()))?;
    let true_hash = hash_str.password_hash();
    match Argon2::default().verify_password(pass.as_bytes(), &true_hash) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Create a new user row and return the decrypted symmetric key for the caller.
pub async fn create_user(
    pool: &Pool,
    user_name: String,
    pass: String,
    group: Option<String>,
    is_admin: bool,
) -> Result<Key<Aes256Gcm>, DaoError> {
    let client = conn(pool).await?;
    let db_pass = get_db_pass();
    let salt = salt_pass(pass)?;
    let key =
        key_gen().map_err(|_| DaoError::ParseError("could not serialize symmetric key".into()))?;
    let e = match group {
        Some(_) => client.execute("INSERT INTO users (user_name, group_name, salt, key, is_admin) VALUES ($1, $2, $3, pgp_sym_encrypt($4 ::text, $6 ::text), $5)",
    &[&user_name, &group, &salt, &key, &is_admin, &db_pass]).await,
        None => client.execute("INSERT INTO users (user_name, salt, key, is_admin) VALUES ($1, $2, pgp_sym_encrypt($3 ::text, $5 ::text), $4)",
    &[&user_name, &salt, &key, &is_admin, &db_pass]).await,
    };
    match e {
        Ok(_) => {
            let arr: [u8; 32] = serde_json::from_str(&key)
                .map_err(|e| DaoError::ParseError(format!("key parse: {}", e)))?;
            Ok(arr.into())
        }
        Err(e) => Err(DaoError::QueryFailed(format!("create user: {}", e))),
    }
}

/// Insert a new group into the database.
pub async fn create_group(pool: &Pool, group_name: String) -> Result<String, DaoError> {
    let client = conn(pool).await?;
    client
        .execute(
            "INSERT INTO groups (g_name, users) VALUES ($1, $2)",
            &[&group_name, &Vec::<String>::new()],
        )
        .await
        .map(|_| group_name)
        .map_err(|e| DaoError::Conflict(format!("create group: {}", e)))
}

/// Persist a file or directory node.
pub async fn add_file(pool: &Pool, file: FNode) -> Result<String, DaoError> {
    let client = conn(pool).await?;
    let db_pass = get_db_pass();
    client
        .execute(
            "INSERT INTO fnode
    (name, path, owner, hash, parent, dir, u, g, o, children, encrypted_name,
     file_group, size_bytes, created_at, modified_at, link_target, path_digest)
    VALUES (
        pgp_sym_encrypt($1 ::text, $12 ::text),
        pgp_sym_encrypt($2 ::text, $12 ::text),
        pgp_sym_encrypt($3 ::text, $12 ::text),
        $4,
        pgp_sym_encrypt($5 ::text, $12 ::text),
        $6,
        pgp_sym_encrypt($7 ::text, $12 ::text),
        pgp_sym_encrypt($8 ::text, $12 ::text),
        pgp_sym_encrypt($9 ::text, $12 ::text),
        $10,
        $11,
        $13, $14, $15, $16, $17,
        hmac($2 ::text, $12 ::text, 'sha256'))",
            &[
                &file.name,
                &file.path,
                &file.owner,
                &file.hash,
                &file.parent,
                &file.dir,
                &file.u.to_string(),
                &file.g.to_string(),
                &file.o.to_string(),
                &file.children,
                &file.encrypted_name,
                &db_pass,
                &file.file_group,
                &file.size,
                &file.created_at,
                &file.modified_at,
                &file.link_target,
            ],
        )
        .await
        .map(|_| file.name)
        .map_err(|e| DaoError::QueryFailed(format!("add file: {}", e)))
}

/// Update the stored hash for a file at `path`.
pub async fn update_hash(
    pool: &Pool,
    path: String,
    _file_name: String,
    hash: String,
) -> Result<String, DaoError> {
    let client = conn(pool).await?;
    let digest = path_digest(&path);
    client
        .execute(
            "UPDATE fnode SET hash = $1 WHERE path_digest = $2",
            &[&hash, &digest],
        )
        .await
        .map(|_| path)
        .map_err(|e| DaoError::QueryFailed(format!("update hash: {}", e)))
}

/// Update a file's hash inside a transaction with an advisory lock.
/// Prevents concurrent writes to the same file.
pub async fn update_hash_locked(pool: &Pool, path: String, hash: String) -> Result<(), DaoError> {
    let mut client = conn(pool).await?;
    let digest = path_digest(&path);
    let tx = client
        .transaction()
        .await
        .map_err(|e| DaoError::QueryFailed(format!("begin tx: {}", e)))?;
    // Look up fnode id for the advisory lock key
    let row = tx
        .query_opt("SELECT id FROM fnode WHERE path_digest = $1", &[&digest])
        .await
        .map_err(|e| DaoError::QueryFailed(format!("lock lookup: {}", e)))?;
    let id: i64 = match row {
        Some(r) => r.get("id"),
        None => return Err(DaoError::NotFound),
    };
    // Non-blocking advisory lock scoped to this transaction
    let lock_row = tx
        .query_one("SELECT pg_try_advisory_xact_lock($1) AS acquired", &[&id])
        .await
        .map_err(|e| DaoError::QueryFailed(format!("advisory lock: {}", e)))?;
    let acquired: bool = lock_row.get("acquired");
    if !acquired {
        return Err(DaoError::Conflict(
            "file is being written by another session".into(),
        ));
    }
    tx.execute(
        "UPDATE fnode SET hash = $1 WHERE path_digest = $2",
        &[&hash, &digest],
    )
    .await
    .map_err(|e| DaoError::QueryFailed(format!("update hash: {}", e)))?;
    tx.commit()
        .await
        .map_err(|e| DaoError::QueryFailed(format!("commit: {}", e)))?;
    Ok(())
}

/// Append a child entry to the parent's `children` array.
pub async fn add_file_to_parent(
    pool: &Pool,
    parent_path: String,
    new_f_node_name: String,
) -> Result<(), DaoError> {
    let client = conn(pool).await?;
    let db_pass = get_db_pass();
    let digest = path_digest(&parent_path);
    client
        .execute(
            "UPDATE fnode SET children =
        ARRAY_APPEND(children,
            pgp_sym_encrypt($1 ::text, $3 ::text)::text
        )
        WHERE path_digest = $2",
            &[&new_f_node_name, &digest, &db_pass],
        )
        .await
        .map(|_| ())
        .map_err(|e| DaoError::QueryFailed(format!("add to parent: {}", e)))
}

/// Fetch a decrypted `FNode` by path.
pub async fn get_f_node(pool: &Pool, path: String) -> Result<Option<FNode>, DaoError> {
    let client = conn(pool).await?;
    let db_pass = get_db_pass();
    let digest = path_digest(&path);
    let e = client.query_opt("SELECT
        id,
        pgp_sym_decrypt(name ::bytea, $2 ::text) AS name,
        pgp_sym_decrypt(path ::bytea, $2 ::text) AS path,
        pgp_sym_decrypt(owner ::bytea, $2 ::text) AS owner,
        hash,
        pgp_sym_decrypt(parent ::bytea, $2 ::text) AS parent,
        dir,
        CAST (pgp_sym_decrypt(u ::bytea, $2 ::text) AS SMALLINT) AS u,
        CAST (pgp_sym_decrypt(g ::bytea, $2 ::text) AS SMALLINT) AS g,
        CAST (pgp_sym_decrypt(o ::bytea, $2 ::text) AS SMALLINT) AS o,
        (SELECT array_agg(pgp_sym_decrypt(child ::bytea, $2::text)) FROM unnest(children) AS child) AS children,
        encrypted_name,
        file_group,
        size_bytes,
        created_at,
        modified_at,
        link_target
    FROM fnode WHERE path_digest = $1",
        &[&digest, &db_pass]).await;
    match e {
        Ok(Some(row)) => {
            let fnode = FNode {
                id: row.get(0),
                name: row.get(1),
                path: row.get(2),
                owner: row.try_get(3).unwrap_or("".to_string()),
                hash: row.get(4),
                parent: row.get(5),
                dir: row.get(6),
                u: row.get(7),
                g: row.get(8),
                o: row.get(9),
                children: row.try_get(10).unwrap_or(vec![]),
                encrypted_name: row.get(11),
                size: row.try_get("size_bytes").unwrap_or(0),
                created_at: row.try_get("created_at").unwrap_or(0),
                modified_at: row.try_get("modified_at").unwrap_or(0),
                file_group: row.try_get("file_group").unwrap_or(None),
                link_target: row.try_get("link_target").unwrap_or(None),
            };
            Ok(Some(fnode))
        }
        Ok(None) => Ok(None),
        Err(e) => Err(DaoError::QueryFailed(format!("get fnode: {}", e))),
    }
}

/// Fetch all direct children of a directory in a single query.
pub async fn get_children(pool: &Pool, parent_path: String) -> Result<Vec<FNode>, DaoError> {
    let client = conn(pool).await?;
    let db_pass = get_db_pass();
    let rows = client.query("SELECT
        id,
        pgp_sym_decrypt(name ::bytea, $2 ::text) AS name,
        pgp_sym_decrypt(path ::bytea, $2 ::text) AS path,
        pgp_sym_decrypt(owner ::bytea, $2 ::text) AS owner,
        hash, pgp_sym_decrypt(parent ::bytea, $2 ::text) AS parent, dir,
        CAST (pgp_sym_decrypt(u ::bytea, $2 ::text) AS SMALLINT) AS u,
        CAST (pgp_sym_decrypt(g ::bytea, $2 ::text) AS SMALLINT) AS g,
        CAST (pgp_sym_decrypt(o ::bytea, $2 ::text) AS SMALLINT) AS o,
        (SELECT array_agg(pgp_sym_decrypt(child ::bytea, $2::text)) FROM unnest(children) AS child) AS children,
        encrypted_name,
        file_group,
        size_bytes,
        created_at,
        modified_at,
        link_target
    FROM fnode WHERE pgp_sym_decrypt(parent ::bytea, $2 ::text) = $1",
        &[&parent_path, &db_pass]).await
        .map_err(|e| DaoError::QueryFailed(format!("get children: {}", e)))?;
    let nodes = rows
        .iter()
        .map(|row| FNode {
            id: row.get(0),
            name: row.get(1),
            path: row.get(2),
            owner: row.try_get(3).unwrap_or("".to_string()),
            hash: row.get(4),
            parent: row.get(5),
            dir: row.get(6),
            u: row.get(7),
            g: row.get(8),
            o: row.get(9),
            children: row.try_get(10).unwrap_or(vec![]),
            encrypted_name: row.get(11),
            size: row.try_get("size_bytes").unwrap_or(0),
            created_at: row.try_get("created_at").unwrap_or(0),
            modified_at: row.try_get("modified_at").unwrap_or(0),
            file_group: row.try_get("file_group").unwrap_or(None),
            link_target: row.try_get("link_target").unwrap_or(None),
        })
        .collect();
    Ok(nodes)
}

/// Fetch all nodes under a path prefix in a single query (for find).
pub async fn get_subtree(pool: &Pool, path_prefix: String) -> Result<Vec<FNode>, DaoError> {
    let client = conn(pool).await?;
    let db_pass = get_db_pass();
    let rows = client.query("SELECT
        id,
        pgp_sym_decrypt(name ::bytea, $2 ::text) AS name,
        pgp_sym_decrypt(path ::bytea, $2 ::text) AS path,
        pgp_sym_decrypt(owner ::bytea, $2 ::text) AS owner,
        hash, pgp_sym_decrypt(parent ::bytea, $2 ::text) AS parent, dir,
        CAST (pgp_sym_decrypt(u ::bytea, $2 ::text) AS SMALLINT) AS u,
        CAST (pgp_sym_decrypt(g ::bytea, $2 ::text) AS SMALLINT) AS g,
        CAST (pgp_sym_decrypt(o ::bytea, $2 ::text) AS SMALLINT) AS o,
        (SELECT array_agg(pgp_sym_decrypt(child ::bytea, $2::text)) FROM unnest(children) AS child) AS children,
        encrypted_name,
        file_group,
        size_bytes,
        created_at,
        modified_at,
        link_target
    FROM fnode WHERE left(pgp_sym_decrypt(path ::bytea, $2 ::text), length($1) + 1) = $1 || '/'",
        &[&path_prefix, &db_pass]).await
        .map_err(|e| DaoError::QueryFailed(format!("get subtree: {}", e)))?;
    let nodes = rows
        .iter()
        .map(|row| FNode {
            id: row.get(0),
            name: row.get(1),
            path: row.get(2),
            owner: row.try_get(3).unwrap_or("".to_string()),
            hash: row.get(4),
            parent: row.get(5),
            dir: row.get(6),
            u: row.get(7),
            g: row.get(8),
            o: row.get(9),
            children: row.try_get(10).unwrap_or(vec![]),
            encrypted_name: row.get(11),
            size: row.try_get("size_bytes").unwrap_or(0),
            created_at: row.try_get("created_at").unwrap_or(0),
            modified_at: row.try_get("modified_at").unwrap_or(0),
            file_group: row.try_get("file_group").unwrap_or(None),
            link_target: row.try_get("link_target").unwrap_or(None),
        })
        .collect();
    Ok(nodes)
}

/// Update the numeric permissions on a file or directory.
pub async fn change_file_perms(
    pool: &Pool,
    file_path: String,
    u: i16,
    g: i16,
    o: i16,
) -> Result<(), DaoError> {
    let client = conn(pool).await?;
    let db_pass = get_db_pass();
    let digest = path_digest(&file_path);
    client
        .execute(
            "
        UPDATE fnode SET
            u=pgp_sym_encrypt($2 ::text, $5 ::text),
            g=pgp_sym_encrypt($3 ::text, $5 ::text),
            o=pgp_sym_encrypt($4 ::text, $5 ::text)
        WHERE path_digest = $1",
            &[
                &digest,
                &u.to_string(),
                &g.to_string(),
                &o.to_string(),
                &db_pass,
            ],
        )
        .await
        .map(|_| ())
        .map_err(|e| DaoError::QueryFailed(format!("change perms: {}", e)))
}

/// Delete every `fnode` whose path matches the provided prefix.
pub async fn delete_path(pool: &Pool, file_path: String) -> Result<(), DaoError> {
    let client = conn(pool).await?;
    let db_pass = get_db_pass();
    client
        .execute(
            "DELETE FROM fnode
             WHERE pgp_sym_decrypt(path::bytea, $2::text) = $1
                OR left(pgp_sym_decrypt(path::bytea, $2::text), length($1) + 1) = $1 || '/'",
            &[&file_path, &db_pass],
        )
        .await
        .map(|_| ())
        .map_err(|e| DaoError::QueryFailed(format!("delete path: {}", e)))
}

/// Rename/move a node and its subtree atomically: rewrite the node's path and
/// every descendant's path and parent pointer, update the node's name, and fix
/// the parent's children array — all in one transaction so a partial failure
/// rolls back instead of corrupting the tree.
pub async fn rename_node(
    pool: &Pool,
    parent_path: String,
    old_path: String,
    new_path: String,
    old_name: String,
    new_name: String,
) -> Result<(), DaoError> {
    let mut client = conn(pool).await?;
    let db_pass = get_db_pass();
    let new_path_digest = path_digest(&new_path);
    let parent_digest = path_digest(&parent_path);
    let tx = client
        .transaction()
        .await
        .map_err(|e| DaoError::QueryFailed(format!("begin tx: {}", e)))?;

    tx.execute(
        "UPDATE fnode SET
             path = pgp_sym_encrypt(
                 $2 || substring(pgp_sym_decrypt(path::bytea, $3::text) from length($1) + 1),
                 $3::text),
             path_digest = hmac(
                 $2 || substring(pgp_sym_decrypt(path::bytea, $3::text) from length($1) + 1),
                 $3::text, 'sha256')
         WHERE pgp_sym_decrypt(path::bytea, $3::text) = $1
            OR left(pgp_sym_decrypt(path::bytea, $3::text), length($1) + 1) = $1 || '/'",
        &[&old_path, &new_path, &db_pass],
    )
    .await
    .map_err(|e| DaoError::QueryFailed(format!("rename path: {}", e)))?;

    // Parent is stored encrypted; rewrite it for descendants (already moved
    // under new_path by the previous statement), decrypting/re-encrypting.
    tx.execute(
        "UPDATE fnode SET parent = pgp_sym_encrypt(
             $2 || substring(pgp_sym_decrypt(parent::bytea, $3::text) from length($1) + 1),
             $3::text)
         WHERE left(pgp_sym_decrypt(path::bytea, $3::text), length($2) + 1) = $2 || '/'",
        &[&old_path, &new_path, &db_pass],
    )
    .await
    .map_err(|e| DaoError::QueryFailed(format!("rename parent: {}", e)))?;

    tx.execute(
        "UPDATE fnode SET name = pgp_sym_encrypt($2::text, $3::text), encrypted_name = $2
         WHERE path_digest = $1",
        &[&new_path_digest, &new_name, &db_pass],
    )
    .await
    .map_err(|e| DaoError::QueryFailed(format!("rename name: {}", e)))?;

    tx.execute(
        "UPDATE fnode SET children =
            (SELECT array_agg(pgp_sym_encrypt(child1::text, $3::text)) FROM unnest
                (ARRAY_REMOVE((SELECT array_agg(pgp_sym_decrypt(child ::bytea, $3::text)) FROM unnest(children) AS child), $1)
            ) AS child1)
            WHERE path_digest = $2",
        &[&old_name, &parent_digest, &db_pass],
    )
    .await
    .map_err(|e| DaoError::QueryFailed(format!("rename detach: {}", e)))?;

    tx.execute(
        "UPDATE fnode SET children =
        ARRAY_APPEND(children, pgp_sym_encrypt($1 ::text, $3 ::text)::text)
        WHERE path_digest = $2",
        &[&new_name, &parent_digest, &db_pass],
    )
    .await
    .map_err(|e| DaoError::QueryFailed(format!("rename attach: {}", e)))?;

    tx.commit()
        .await
        .map_err(|e| DaoError::QueryFailed(format!("commit: {}", e)))
}

/// Detach a node from its parent and delete it (plus any subtree) atomically.
pub async fn delete_node(
    pool: &Pool,
    parent_path: String,
    name: String,
    path: String,
) -> Result<(), DaoError> {
    let mut client = conn(pool).await?;
    let db_pass = get_db_pass();
    let parent_digest = path_digest(&parent_path);
    let tx = client
        .transaction()
        .await
        .map_err(|e| DaoError::QueryFailed(format!("begin tx: {}", e)))?;

    tx.execute(
        "UPDATE fnode SET children =
            (SELECT array_agg(pgp_sym_encrypt(child1::text, $3::text)) FROM unnest
                (ARRAY_REMOVE((SELECT array_agg(pgp_sym_decrypt(child ::bytea, $3::text)) FROM unnest(children) AS child), $1)
            ) AS child1)
            WHERE path_digest = $2",
        &[&name, &parent_digest, &db_pass],
    )
    .await
    .map_err(|e| DaoError::QueryFailed(format!("delete detach: {}", e)))?;

    tx.execute(
        "DELETE FROM fnode
         WHERE pgp_sym_decrypt(path::bytea, $2::text) = $1
            OR left(pgp_sym_decrypt(path::bytea, $2::text), length($1) + 1) = $1 || '/'",
        &[&path, &db_pass],
    )
    .await
    .map_err(|e| DaoError::QueryFailed(format!("delete rows: {}", e)))?;

    tx.commit()
        .await
        .map_err(|e| DaoError::QueryFailed(format!("commit: {}", e)))
}

/// Fetch a user record; decrypt the key with `DB_PASS`.
pub async fn get_user(pool: &Pool, user_name: String) -> Result<Option<User>, DaoError> {
    let client = conn(pool).await?;
    let db_pass = get_db_pass();
    let e = client.query_opt("SELECT id, user_name, group_name, pgp_sym_decrypt(key ::bytea, $2 ::text) AS key, salt, is_admin FROM users WHERE user_name = $1",
     &[&user_name, &db_pass]).await;
    match e {
        Ok(Some(row)) => Ok(Some(User {
            id: row.get("id"),
            user_name: row.get("user_name"),
            group_name: row.try_get("group_name").unwrap_or(None),
            key: row.get("key"),
            salt: row.get("salt"),
            is_admin: row.get("is_admin"),
        })),
        Ok(None) => Ok(None),
        Err(e) => Err(DaoError::QueryFailed(format!("get user: {}", e))),
    }
}

/// Check whether a group exists.
pub async fn get_group(pool: &Pool, group_name: String) -> Result<Option<String>, DaoError> {
    let client = conn(pool).await?;
    let e = client
        .query_opt(
            "SELECT g_name FROM groups WHERE g_name = $1",
            &[&group_name],
        )
        .await;
    match e {
        Ok(Some(_)) => Ok(Some(group_name)),
        Ok(None) => Ok(None),
        Err(e) => Err(DaoError::QueryFailed(format!("get group: {}", e))),
    }
}

/// Retrieve all group names from the database.
pub async fn get_all_groups(pool: &Pool) -> Result<Vec<String>, DaoError> {
    let client = conn(pool).await?;
    client
        .query("SELECT g_name FROM groups ORDER BY g_name", &[])
        .await
        .map(|rows| rows.iter().map(|row| row.get("g_name")).collect())
        .map_err(|e| DaoError::QueryFailed(format!("list groups: {}", e)))
}

/// Retrieve all usernames from the database.
pub async fn get_all_users(pool: &Pool) -> Result<Vec<String>, DaoError> {
    let client = conn(pool).await?;
    client
        .query("SELECT user_name FROM users ORDER BY user_name", &[])
        .await
        .map(|rows| rows.iter().map(|row| row.get("user_name")).collect())
        .map_err(|e| DaoError::QueryFailed(format!("list users: {}", e)))
}

/// Check if a user has admin privileges.
pub async fn is_admin(pool: &Pool, user_name: String) -> Result<bool, DaoError> {
    let client = conn(pool).await?;
    let row = client
        .query_opt(
            "SELECT is_admin FROM users WHERE user_name = $1",
            &[&user_name],
        )
        .await;
    match row {
        Ok(Some(row)) => Ok(row.get("is_admin")),
        Ok(None) => Ok(false),
        Err(e) => Err(DaoError::QueryFailed(format!("check admin: {}", e))),
    }
}

/// Change the owner of a file or directory.
pub async fn change_owner(
    pool: &Pool,
    file_path: String,
    new_owner: String,
) -> Result<(), DaoError> {
    let client = conn(pool).await?;
    let db_pass = get_db_pass();
    let digest = path_digest(&file_path);
    client
        .execute(
            "UPDATE fnode SET owner = pgp_sym_encrypt($2 ::text, $3 ::text) WHERE path_digest = $1",
            &[&digest, &new_owner, &db_pass],
        )
        .await
        .map(|_| ())
        .map_err(|e| DaoError::QueryFailed(format!("change owner: {}", e)))
}

/// Get the group associated with a file node.
/// Uses the file-level group if set, otherwise falls back to the owner's group.
pub async fn get_file_group(
    pool: &Pool,
    owner: String,
    file_group: Option<String>,
) -> Result<Option<String>, DaoError> {
    if file_group.is_some() {
        return Ok(file_group);
    }
    let client = conn(pool).await?;
    let row = client
        .query_opt(
            "SELECT group_name FROM users WHERE user_name = $1",
            &[&owner],
        )
        .await;
    match row {
        Ok(Some(row)) => Ok(row.try_get("group_name").unwrap_or(None)),
        Ok(None) => Ok(None),
        Err(e) => Err(DaoError::QueryFailed(format!("get file group: {}", e))),
    }
}

/// Update the group assignment for a file or directory.
pub async fn change_file_group(
    pool: &Pool,
    file_path: String,
    new_group: String,
) -> Result<(), DaoError> {
    let client = conn(pool).await?;
    let digest = path_digest(&file_path);
    client
        .execute(
            "UPDATE fnode SET file_group = $2 WHERE path_digest = $1",
            &[&digest, &new_group],
        )
        .await
        .map(|_| ())
        .map_err(|e| DaoError::QueryFailed(format!("change file group: {}", e)))
}

/// Check if a user belongs to a specific group.
pub async fn user_in_group(
    pool: &Pool,
    user_name: String,
    group_name: String,
) -> Result<bool, DaoError> {
    let client = conn(pool).await?;
    let row = client
        .query_opt(
            "SELECT group_name FROM users WHERE user_name = $1",
            &[&user_name],
        )
        .await;

    let primary_group_match = match row {
        Ok(Some(row)) => {
            let user_group: Option<String> = row.try_get("group_name").unwrap_or(None);
            user_group.map(|g| g == group_name).unwrap_or(false)
        }
        _ => false,
    };

    if primary_group_match {
        return Ok(true);
    }

    let row = client
        .query_opt(
            "SELECT 1 FROM groups WHERE g_name = $2 AND $1 = ANY(users)",
            &[&user_name, &group_name],
        )
        .await;

    match row {
        Ok(Some(_)) => Ok(true),
        Ok(None) => Ok(false),
        Err(e) => Err(DaoError::QueryFailed(format!(
            "check group membership: {}",
            e
        ))),
    }
}

/// Add a user to a group (secondary membership).
pub async fn add_user_to_group(
    pool: &Pool,
    user_name: String,
    group_name: String,
) -> Result<(), DaoError> {
    let group_exists = get_group(pool, group_name.clone()).await?.is_some();
    if !group_exists {
        return Err(DaoError::NotFound);
    }
    let client = conn(pool).await?;
    client.execute(
        "UPDATE groups SET users = array_append(users, $1) WHERE g_name = $2 AND NOT ($1 = ANY(users))",
        &[&user_name, &group_name]
    ).await
        .map(|_| ())
        .map_err(|e| DaoError::QueryFailed(format!("add user to group: {}", e)))
}

/// Remove a user from a group (secondary membership).
pub async fn remove_user_from_group(
    pool: &Pool,
    user_name: String,
    group_name: String,
) -> Result<(), DaoError> {
    let client = conn(pool).await?;
    client
        .execute(
            "UPDATE groups SET users = array_remove(users, $1) WHERE g_name = $2",
            &[&user_name, &group_name],
        )
        .await
        .map(|_| ())
        .map_err(|e| DaoError::QueryFailed(format!("remove user from group: {}", e)))
}

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
             encrypted_name, size_bytes, created_at, modified_at, path_digest)
         SELECT pgp_sym_encrypt('home', $1::text), pgp_sym_encrypt('/home', $1::text),
                pgp_sym_encrypt('', $1::text), '', pgp_sym_encrypt('', $1::text), true,
                pgp_sym_encrypt('4', $1::text), pgp_sym_encrypt('4', $1::text),
                pgp_sym_encrypt('4', $1::text), ARRAY[]::VARCHAR[], '', 0, 0, 0,
                hmac('/home', $1::text, 'sha256')
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

    // Persist FNode metadata that older schemas lacked (idempotent).
    for ddl in [
        "ALTER TABLE fnode ADD COLUMN IF NOT EXISTS size_bytes BIGINT DEFAULT 0",
        "ALTER TABLE fnode ADD COLUMN IF NOT EXISTS created_at BIGINT DEFAULT 0",
        "ALTER TABLE fnode ADD COLUMN IF NOT EXISTS modified_at BIGINT DEFAULT 0",
        "ALTER TABLE fnode ADD COLUMN IF NOT EXISTS link_target VARCHAR",
        "ALTER TABLE fnode ADD COLUMN IF NOT EXISTS path_digest BYTEA",
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
    client
        .execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_user_name ON users(user_name)",
            &[],
        )
        .await
        .map_err(|e| DaoError::QueryFailed(format!("create user_name index: {}", e)))?;

    drop(client);

    bootstrap(pool).await?;
    Ok(())
}

/// Persist an audit log entry.
pub async fn insert_audit_log(
    pool: &Pool,
    event: &str,
    username: &str,
    resource: &str,
    result: &str,
    ip: Option<&str>,
) -> Result<(), DaoError> {
    let client = conn(pool).await?;
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    client
        .execute(
            "INSERT INTO audit_log (ts, event, username, resource, result, ip)
             VALUES ($1, $2, $3, $4, $5, $6)",
            &[&ts, &event, &username, &resource, &result, &ip],
        )
        .await
        .map(|_| ())
        .map_err(|e| DaoError::QueryFailed(format!("insert audit: {}", e)))
}

/// Query audit log entries, most recent first.
pub async fn query_audit_log(
    pool: &Pool,
    limit: i64,
) -> Result<Vec<(i64, String, String, String, String, Option<String>)>, DaoError> {
    let client = conn(pool).await?;
    let rows = client
        .query(
            "SELECT ts, event, username, resource, result, ip
             FROM audit_log ORDER BY ts DESC LIMIT $1",
            &[&limit],
        )
        .await
        .map_err(|e| DaoError::QueryFailed(format!("query audit: {}", e)))?;
    Ok(rows
        .iter()
        .map(|r| {
            (
                r.get::<_, i64>(0),
                r.get::<_, String>(1),
                r.get::<_, String>(2),
                r.get::<_, String>(3),
                r.get::<_, String>(4),
                r.try_get::<_, Option<String>>(5).unwrap_or(None),
            )
        })
        .collect())
}

/// Get the TOTP secret for a user (decrypted). Returns None if not set.
pub async fn get_totp_secret(pool: &Pool, user_name: &str) -> Result<Option<String>, DaoError> {
    let client = conn(pool).await?;
    let db_pass = get_db_pass();
    let row = client
        .query_opt(
            "SELECT pgp_sym_decrypt(totp_secret ::bytea, $2 ::text) AS totp
             FROM users WHERE user_name = $1 AND totp_secret IS NOT NULL",
            &[&user_name.to_string(), &db_pass],
        )
        .await
        .map_err(|e| DaoError::QueryFailed(format!("get totp: {}", e)))?;
    Ok(row.map(|r| r.get::<_, String>("totp")))
}

/// Set the TOTP secret for a user (encrypted with DB_PASS).
pub async fn set_totp_secret(pool: &Pool, user_name: &str, secret: &str) -> Result<(), DaoError> {
    let client = conn(pool).await?;
    let db_pass = get_db_pass();
    client
        .execute(
            "UPDATE users SET totp_secret = pgp_sym_encrypt($2 ::text, $3 ::text)
             WHERE user_name = $1",
            &[&user_name.to_string(), &secret.to_string(), &db_pass],
        )
        .await
        .map(|_| ())
        .map_err(|e| DaoError::QueryFailed(format!("set totp: {}", e)))
}

/// Recursively copy a file or directory tree.
pub async fn copy_recursive(
    pool: &Pool,
    src_root: String,
    dst_root: String,
    owner: String,
) -> Result<(), DaoError> {
    let mut stack = vec![(src_root, dst_root)];

    while let Some((src, dst)) = stack.pop() {
        if let Ok(Some(node)) = get_f_node(pool, src.clone()).await {
            let path_obj = std::path::Path::new(&dst);
            let name = path_obj
                .file_name()
                .unwrap_or_default()
                .to_str()
                .unwrap_or_default()
                .to_string();
            let parent_opt = path_obj.parent().map(|p| p.to_str().unwrap_or("/"));
            let parent = match parent_opt {
                Some("") | None => "/".to_string(),
                Some(p) => p.to_string(),
            };

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            let new_node = FNode {
                id: -1,
                name: name.clone(),
                path: dst.clone(),
                owner: owner.clone(),
                hash: node.hash.clone(),
                parent: parent.clone(),
                dir: node.dir,
                u: node.u,
                g: node.g,
                o: node.o,
                children: vec![],
                encrypted_name: name.clone(),
                size: node.size,
                created_at: now,
                modified_at: now,
                file_group: node.file_group.clone(),
                link_target: None,
            };

            add_file(pool, new_node)
                .await
                .map_err(|e| DaoError::QueryFailed(format!("copy {}: {}", dst, e)))?;
            add_file_to_parent(pool, parent, name)
                .await
                .map_err(|e| DaoError::QueryFailed(format!("copy link {}: {}", dst, e)))?;

            if node.dir {
                for child in node.children {
                    let child_src = if src == "/" {
                        format!("/{}", child)
                    } else {
                        format!("{}/{}", src, child)
                    };
                    let child_dst = if dst == "/" {
                        format!("/{}", child)
                    } else {
                        format!("{}/{}", dst, child)
                    };
                    stack.push((child_src, child_dst));
                }
            } else {
                let src_storage = format!("storage{}", src);
                let dst_storage = format!("storage{}", dst);
                tokio::fs::copy(&src_storage, &dst_storage)
                    .await
                    .map_err(|e| DaoError::QueryFailed(format!("fs copy: {}", e)))?;
            }

            if node.dir {
                let dst_storage = format!("storage{}", dst);
                tokio::fs::create_dir_all(&dst_storage)
                    .await
                    .map_err(|e| DaoError::QueryFailed(format!("fs mkdir: {}", e)))?;
            }
        }
    }
    Ok(())
}
