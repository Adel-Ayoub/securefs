//! Data-access helpers for SecureFS.
//!
//! Handles authentication, key material generation, and CRUD helpers
//! that persist `FNode`, `User`, and `Group` records. Queries are kept
//! thin here so the server loop can stay focused on protocol flow.

use std::{env, fmt};
use std::sync::Once;

use deadpool_postgres::Pool;
use argon2::{
    password_hash::{
        Encoding, PasswordHashString, PasswordHasher, PasswordVerifier, SaltString
    },
    Argon2
};
use securefs_model::protocol::{FNode, User};
use aes_gcm::{Aes256Gcm, KeyInit, Key};
use rand_core::OsRng;
use serde_json;

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
    pool.get().await.map_err(|e| DaoError::QueryFailed(format!("pool: {}", e)))
}

static WARN_DEFAULT_PASS: Once = Once::new();

/// Get database encryption password from environment.
/// Warns loudly if using default (insecure for production).
pub fn get_db_pass() -> String {
    match env::var("DB_PASS") {
        Ok(pass) => pass,
        Err(_) => {
            WARN_DEFAULT_PASS.call_once(|| {
                eprintln!("[SECURITY WARNING] DB_PASS not set, using insecure default!");
                eprintln!("[SECURITY WARNING] Set DB_PASS environment variable for production.");
            });
            "TEMP".to_string()
        }
    }
}

/// Hash and salt a plaintext password using Argon2.
pub fn salt_pass(pass: String) -> Result<String, DaoError> {
    let b_pass = pass.as_bytes();
    let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
    let argon2 = Argon2::default();
    argon2.hash_password(b_pass, &salt)
        .map(|p| p.serialize().as_str().to_string())
        .map_err(|e| DaoError::ParseError(format!("argon2 hash failed: {}", e)))
}

/// Generate a random AES-256 key serialized to JSON for DB storage.
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
    let e = client.query_one("SELECT u.salt FROM users u WHERE u.user_name=$1",
    &[&user_name]).await;
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
pub async fn create_user(pool: &Pool, user_name: String, pass: String, group: Option<String>, is_admin: bool) -> Result<Key<Aes256Gcm>, DaoError>{
    let client = conn(pool).await?;
    let db_pass = get_db_pass();
    let salt = salt_pass(pass)?;
    let key = key_gen().map_err(|_| DaoError::ParseError("could not serialize symmetric key".into()))?;
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
pub async fn create_group(pool: &Pool, group_name: String) -> Result<String, DaoError>{
    let client = conn(pool).await?;
    client.execute("INSERT INTO groups (g_name, users) VALUES ($1, $2)",
    &[&group_name, &Vec::<String>::new()]).await
        .map(|_| group_name)
        .map_err(|e| DaoError::Conflict(format!("create group: {}", e)))
}

/// Persist a file or directory node.
pub async fn add_file(pool: &Pool, file: FNode) -> Result<String, DaoError> {
    let client = conn(pool).await?;
    let db_pass = get_db_pass();
    client.execute("INSERT INTO
    fnode (name, path, owner, hash, parent, dir, u, g, o, children, encrypted_name)
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
        $11)",
    &[&file.name, &file.path, &file.owner, &file.hash, &file.parent, &file.dir, &file.u.to_string(), &file.g.to_string(), &file.o.to_string(), &file.children, &file.encrypted_name, &db_pass]).await
        .map(|_| file.name)
        .map_err(|e| DaoError::QueryFailed(format!("add file: {}", e)))
}

/// Update the stored hash for a file at `path`.
pub async fn update_hash(pool: &Pool, path: String, _file_name: String, hash: String) -> Result<String, DaoError>{
    let client = conn(pool).await?;
    let db_pass = get_db_pass();
    client.execute("UPDATE fnode SET hash = $1 WHERE pgp_sym_decrypt(path ::bytea, $3 ::text)=$2",
    &[&hash, &path, &db_pass]).await
        .map(|_| path)
        .map_err(|e| DaoError::QueryFailed(format!("update hash: {}", e)))
}

/// Append a child entry to the parent's `children` array.
pub async fn add_file_to_parent(pool: &Pool, parent_path: String, new_f_node_name: String) -> Result<(), DaoError>{
    let client = conn(pool).await?;
    let db_pass = get_db_pass();
    client.execute("UPDATE fnode SET children =
        ARRAY_APPEND(children,
            pgp_sym_encrypt($1 ::text, $3 ::text)::text
        )
        WHERE pgp_sym_decrypt(path ::bytea, $3 ::text)=$2",
    &[&new_f_node_name, &parent_path, &db_pass]).await
        .map(|_| ())
        .map_err(|e| DaoError::QueryFailed(format!("add to parent: {}", e)))
}

/// Remove a child entry from the parent's `children` array.
pub async fn remove_file_from_parent(pool: &Pool, parent_path: String, f_node_name: String) -> Result<(), DaoError>{
    let client = conn(pool).await?;
    let db_pass = get_db_pass();
    client.execute("UPDATE fnode
        SET children =
            (SELECT array_agg(pgp_sym_encrypt(child1::text, $3::text)) FROM unnest
                (ARRAY_REMOVE((SELECT array_agg(pgp_sym_decrypt(child ::bytea, $3::text)) FROM unnest(children) AS child), $1)
            ) AS child1)
            WHERE pgp_sym_decrypt(path ::bytea, $3 ::text)=$2",
    &[&f_node_name, &parent_path, &db_pass]).await
        .map(|_| ())
        .map_err(|e| DaoError::QueryFailed(format!("remove from parent: {}", e)))
}

/// Fetch a decrypted `FNode` by path.
pub async fn get_f_node(pool: &Pool, path: String) -> Result<Option<FNode>, DaoError> {
    let client = conn(pool).await?;
    let db_pass = get_db_pass();
    let e = client.query_opt("SELECT
        id,
        pgp_sym_decrypt(name ::bytea, $2 ::text) AS name,
        pgp_sym_decrypt(path ::bytea, $2 ::text) AS path,
        pgp_sym_decrypt(owner ::bytea, $2 ::text) AS owner,
        hash,
        parent,
        dir,
        CAST (pgp_sym_decrypt(u ::bytea, $2 ::text) AS SMALLINT) AS u,
        CAST (pgp_sym_decrypt(g ::bytea, $2 ::text) AS SMALLINT) AS g,
        CAST (pgp_sym_decrypt(o ::bytea, $2 ::text) AS SMALLINT) AS o,
        (SELECT array_agg(pgp_sym_decrypt(child ::bytea, $2::text)) FROM unnest(children) AS child) AS children,
        encrypted_name,
        file_group
    FROM fnode WHERE pgp_sym_decrypt(path::bytea, $2::text) = $1",
        &[&path, &db_pass]).await;
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
                size: 0,
                created_at: 0,
                modified_at: 0,
                file_group: row.try_get("file_group").unwrap_or(None),
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
        hash, parent, dir,
        CAST (pgp_sym_decrypt(u ::bytea, $2 ::text) AS SMALLINT) AS u,
        CAST (pgp_sym_decrypt(g ::bytea, $2 ::text) AS SMALLINT) AS g,
        CAST (pgp_sym_decrypt(o ::bytea, $2 ::text) AS SMALLINT) AS o,
        (SELECT array_agg(pgp_sym_decrypt(child ::bytea, $2::text)) FROM unnest(children) AS child) AS children,
        encrypted_name,
        file_group
    FROM fnode WHERE pgp_sym_decrypt(parent ::bytea, $2 ::text) = $1",
        &[&parent_path, &db_pass]).await
        .map_err(|e| DaoError::QueryFailed(format!("get children: {}", e)))?;
    let nodes = rows.iter().map(|row| FNode {
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
        size: 0,
        created_at: 0,
        modified_at: 0,
        file_group: row.try_get("file_group").unwrap_or(None),
    }).collect();
    Ok(nodes)
}

/// Fetch all nodes under a path prefix in a single query (for find).
pub async fn get_subtree(pool: &Pool, path_prefix: String) -> Result<Vec<FNode>, DaoError> {
    let client = conn(pool).await?;
    let db_pass = get_db_pass();
    let pattern = format!("^{}/", path_prefix);
    let rows = client.query("SELECT
        id,
        pgp_sym_decrypt(name ::bytea, $2 ::text) AS name,
        pgp_sym_decrypt(path ::bytea, $2 ::text) AS path,
        pgp_sym_decrypt(owner ::bytea, $2 ::text) AS owner,
        hash, parent, dir,
        CAST (pgp_sym_decrypt(u ::bytea, $2 ::text) AS SMALLINT) AS u,
        CAST (pgp_sym_decrypt(g ::bytea, $2 ::text) AS SMALLINT) AS g,
        CAST (pgp_sym_decrypt(o ::bytea, $2 ::text) AS SMALLINT) AS o,
        (SELECT array_agg(pgp_sym_decrypt(child ::bytea, $2::text)) FROM unnest(children) AS child) AS children,
        encrypted_name,
        file_group
    FROM fnode WHERE pgp_sym_decrypt(path ::bytea, $2 ::text) ~ $1",
        &[&pattern, &db_pass]).await
        .map_err(|e| DaoError::QueryFailed(format!("get subtree: {}", e)))?;
    let nodes = rows.iter().map(|row| FNode {
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
        size: 0,
        created_at: 0,
        modified_at: 0,
        file_group: row.try_get("file_group").unwrap_or(None),
    }).collect();
    Ok(nodes)
}

/// Update the numeric permissions on a file or directory.
pub async fn change_file_perms(pool: &Pool, file_path: String, u: i16, g: i16, o: i16) -> Result<(), DaoError>{
    let client = conn(pool).await?;
    let db_pass = get_db_pass();
    client.execute("
        UPDATE fnode SET
            u=pgp_sym_encrypt($2 ::text, $5 ::text),
            g=pgp_sym_encrypt($3 ::text, $5 ::text),
            o=pgp_sym_encrypt($4 ::text, $5 ::text)
        WHERE pgp_sym_decrypt(path ::bytea, $5 ::text)=$1",
    &[&file_path, &u.to_string(), &g.to_string(), &o.to_string(), &db_pass]).await
        .map(|_| ())
        .map_err(|e| DaoError::QueryFailed(format!("change perms: {}", e)))
}

/// Rewrite stored paths for a subtree, replacing prefixes in bulk.
pub async fn update_path(pool: &Pool, file_path: String, new_file_path: String) -> Result<(), DaoError>{
    let client = conn(pool).await?;
    let db_pass = get_db_pass();
    client.execute("UPDATE fnode SET path =
        pgp_sym_encrypt(
            regexp_replace(
                pgp_sym_decrypt(path ::bytea, $4 ::text),
            $1, $2, 'g'),
        $4 ::text)
        WHERE pgp_sym_decrypt(path ::bytea, $4 ::text) ~ $3",
        &[&format!("^{}", file_path), &new_file_path, &format!("^{}", file_path), &db_pass]
    ).await
        .map(|_| ())
        .map_err(|e| DaoError::QueryFailed(format!("update path: {}", e)))
}

/// Delete every `fnode` whose path matches the provided prefix.
pub async fn delete_path(pool: &Pool, file_path: String) -> Result<(), DaoError>{
    let client = conn(pool).await?;
    let db_pass = get_db_pass();
    client.execute("
        DELETE FROM fnode WHERE pgp_sym_decrypt(path ::bytea, $2 ::text) ~ $1",
        &[&format!("^{}", file_path), &db_pass]
    ).await
        .map(|_| ())
        .map_err(|e| DaoError::QueryFailed(format!("delete path: {}", e)))
}

/// Update only the display name after a path rename has occurred.
pub async fn update_fnode_name_if_path_is_already_updated(pool: &Pool, path: String, new_name: String) -> Result<(), DaoError>{
    let client = conn(pool).await?;
    let db_pass = get_db_pass();
    client.execute("UPDATE fnode SET name =
        pgp_sym_encrypt($2 ::text, $3 ::text)
        WHERE pgp_sym_decrypt(path::bytea, $3::text) = $1",
    &[&path, &new_name, &db_pass]).await
        .map(|_| ())
        .map_err(|e| DaoError::QueryFailed(format!("update name: {}", e)))
}

/// Update the encrypted on-disk name for a node.
pub async fn update_fnode_enc_name(pool: &Pool, path: String, new_enc_name: String) -> Result<(), DaoError>{
    let client = conn(pool).await?;
    let db_pass = get_db_pass();
    client.execute("UPDATE fnode SET encrypted_name = $2 WHERE pgp_sym_decrypt(path ::bytea, $3 ::text) = $1",
    &[&path, &new_enc_name, &db_pass]).await
        .map(|_| ())
        .map_err(|e| DaoError::QueryFailed(format!("update enc name: {}", e)))
}

/// Fetch a user record; decrypt the key with `DB_PASS`.
pub async fn get_user(pool: &Pool, user_name: String) -> Result<Option<User>, DaoError> {
    let client = conn(pool).await?;
    let db_pass = get_db_pass();
    let e = client.query_opt("SELECT id, user_name, group_name, pgp_sym_decrypt(key ::bytea, $2 ::text) AS key, salt, is_admin FROM users WHERE user_name = $1",
     &[&user_name, &db_pass]).await;
    match e {
        Ok(Some(row)) => Ok(Some(User{
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
    let e = client.query_opt("SELECT g_name FROM groups WHERE g_name = $1", &[&group_name]).await;
    match e {
        Ok(Some(_)) => Ok(Some(group_name)),
        Ok(None) => Ok(None),
        Err(e) => Err(DaoError::QueryFailed(format!("get group: {}", e))),
    }
}

/// Retrieve all group names from the database.
pub async fn get_all_groups(pool: &Pool) -> Result<Vec<String>, DaoError> {
    let client = conn(pool).await?;
    client.query("SELECT g_name FROM groups ORDER BY g_name", &[]).await
        .map(|rows| rows.iter().map(|row| row.get("g_name")).collect())
        .map_err(|e| DaoError::QueryFailed(format!("list groups: {}", e)))
}

/// Retrieve all usernames from the database.
pub async fn get_all_users(pool: &Pool) -> Result<Vec<String>, DaoError> {
    let client = conn(pool).await?;
    client.query("SELECT user_name FROM users ORDER BY user_name", &[]).await
        .map(|rows| rows.iter().map(|row| row.get("user_name")).collect())
        .map_err(|e| DaoError::QueryFailed(format!("list users: {}", e)))
}

/// Check if a user has admin privileges.
pub async fn is_admin(pool: &Pool, user_name: String) -> Result<bool, DaoError> {
    let client = conn(pool).await?;
    let row = client.query_opt("SELECT is_admin FROM users WHERE user_name = $1", &[&user_name]).await;
    match row {
        Ok(Some(row)) => Ok(row.get("is_admin")),
        Ok(None) => Ok(false),
        Err(e) => Err(DaoError::QueryFailed(format!("check admin: {}", e))),
    }
}

/// Change the owner of a file or directory.
pub async fn change_owner(pool: &Pool, file_path: String, new_owner: String) -> Result<(), DaoError> {
    let client = conn(pool).await?;
    let db_pass = get_db_pass();
    client.execute(
        "UPDATE fnode SET owner = pgp_sym_encrypt($2 ::text, $3 ::text) WHERE pgp_sym_decrypt(path ::bytea, $3 ::text) = $1",
        &[&file_path, &new_owner, &db_pass]
    ).await
        .map(|_| ())
        .map_err(|e| DaoError::QueryFailed(format!("change owner: {}", e)))
}

/// Get the group associated with a file node.
/// Uses the file-level group if set, otherwise falls back to the owner's group.
pub async fn get_file_group(pool: &Pool, owner: String, file_group: Option<String>) -> Result<Option<String>, DaoError> {
    if file_group.is_some() {
        return Ok(file_group);
    }
    let client = conn(pool).await?;
    let row = client.query_opt(
        "SELECT group_name FROM users WHERE user_name = $1",
        &[&owner]
    ).await;
    match row {
        Ok(Some(row)) => Ok(row.try_get("group_name").unwrap_or(None)),
        Ok(None) => Ok(None),
        Err(e) => Err(DaoError::QueryFailed(format!("get file group: {}", e))),
    }
}

/// Update the group assignment for a file or directory.
pub async fn change_file_group(pool: &Pool, file_path: String, new_group: String) -> Result<(), DaoError> {
    let client = conn(pool).await?;
    let db_pass = get_db_pass();
    client.execute(
        "UPDATE fnode SET file_group = $2 WHERE pgp_sym_decrypt(path ::bytea, $3 ::text) = $1",
        &[&file_path, &new_group, &db_pass]
    ).await
        .map(|_| ())
        .map_err(|e| DaoError::QueryFailed(format!("change file group: {}", e)))
}

/// Check if a user belongs to a specific group.
pub async fn user_in_group(pool: &Pool, user_name: String, group_name: String) -> Result<bool, DaoError> {
    let client = conn(pool).await?;
    let row = client.query_opt(
        "SELECT group_name FROM users WHERE user_name = $1",
        &[&user_name]
    ).await;

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

    let row = client.query_opt(
        "SELECT 1 FROM groups WHERE g_name = $2 AND $1 = ANY(users)",
        &[&user_name, &group_name]
    ).await;

    match row {
        Ok(Some(_)) => Ok(true),
        Ok(None) => Ok(false),
        Err(e) => Err(DaoError::QueryFailed(format!("check group membership: {}", e))),
    }
}

/// Add a user to a group (secondary membership).
pub async fn add_user_to_group(pool: &Pool, user_name: String, group_name: String) -> Result<(), DaoError> {
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
pub async fn remove_user_from_group(pool: &Pool, user_name: String, group_name: String) -> Result<(), DaoError> {
    let client = conn(pool).await?;
    client.execute(
        "UPDATE groups SET users = array_remove(users, $1) WHERE g_name = $2",
        &[&user_name, &group_name]
    ).await
        .map(|_| ())
        .map_err(|e| DaoError::QueryFailed(format!("remove user from group: {}", e)))
}

/// Ensure required seed data exists (currently `/home` root).
pub async fn init_db(pool: &Pool) -> Result<(), DaoError> {
    let does_home_exist = get_f_node(pool, "/home".to_string()).await?.is_some();
    if !does_home_exist {
        add_file(pool, FNode {
            id: -1,
            name: "home".to_string(),
            path: "/home".to_string(),
            owner: "".to_string(),
            hash: "".to_string(),
            parent: "".to_string(),
            dir: true,
            u: 4,
            g: 4,
            o: 4,
            children: vec![],
            encrypted_name: "".to_string(),
            size: 0,
            created_at: 0,
            modified_at: 0,
            file_group: None,
        }).await?;
    }
    Ok(())
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
            let name = path_obj.file_name().unwrap_or_default().to_str().unwrap_or_default().to_string();
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
            };

            add_file(pool, new_node).await
                .map_err(|e| DaoError::QueryFailed(format!("copy {}: {}", dst, e)))?;
            add_file_to_parent(pool, parent, name).await
                .map_err(|e| DaoError::QueryFailed(format!("copy link {}: {}", dst, e)))?;

            if node.dir {
                for child in node.children {
                    let child_src = if src == "/" { format!("/{}", child) } else { format!("{}/{}", src, child) };
                    let child_dst = if dst == "/" { format!("/{}", child) } else { format!("{}/{}", dst, child) };
                    stack.push((child_src, child_dst));
                }
            } else {
                let src_storage = format!("storage{}", src);
                let dst_storage = format!("storage{}", dst);
                tokio::fs::copy(&src_storage, &dst_storage).await
                    .map_err(|e| DaoError::QueryFailed(format!("fs copy: {}", e)))?;
            }

            if node.dir {
                let dst_storage = format!("storage{}", dst);
                tokio::fs::create_dir_all(&dst_storage).await
                    .map_err(|e| DaoError::QueryFailed(format!("fs mkdir: {}", e)))?;
            }
        }
    }
    Ok(())
}
