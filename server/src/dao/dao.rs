//! Data-access helpers for SecureFS.
//!
//! Handles authentication, key material generation, and CRUD helpers
//! that persist `FNode`, `User`, and `Group` records. Queries are kept
//! thin here so the server loop can stay focused on protocol flow.

use std::{env, sync::Arc};
use std::sync::Once;

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
use tokio::sync::Mutex;
use tokio_postgres::Client;
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

/// Hash and salt a plaintext password using Argon2.
pub fn salt_pass(pass: String) -> Result<String, String> {
    let b_pass = pass.as_bytes();
    let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
    let argon2 = Argon2::default();
    match argon2.hash_password(b_pass, &salt) {
        Ok(p) => Ok(p.serialize().as_str().to_string()),
        Err(_) => Err("Error with salting pass".into()),
    }
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
pub async fn auth_user(client: Arc<Mutex<Client>>, user_name: String, pass: String) -> Result<bool, String> {
    let e = client.lock().await.query_one("SELECT u.salt FROM users u WHERE u.user_name=$1",
    &[&user_name]).await;
    let res = match e {
        Ok(row) => row,
        Err(_) => return Ok(false),
    };
    let hash: String = res.get("salt");
    // SAFETY: Hashes are stored in the DB as valid Argon2 strings; parsing failures fall back
    // to an authentication failure rather than panicking.
    let hash_str: PasswordHashString = PasswordHashString::parse(hash.as_str(), Encoding::B64)
        .map_err(|_| "invalid hash format".to_string())?;
    let true_hash = hash_str.password_hash();
    match Argon2::default().verify_password(pass.as_bytes(), &true_hash) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Create a new user row and return the decrypted symmetric key for the caller.
pub async fn create_user(client: Arc<Mutex<Client>>, user_name: String, pass: String, group: Option<String>, is_admin: bool) -> Result<Key<Aes256Gcm>, String>{
    // NOTE: DB_PASS default is a convenience for local dev only; deployments should set it.
    let db_pass = get_db_pass();
    let salt = match salt_pass(pass){
        Ok(salt) => salt,
        Err(_) => return Err(format!("couldn't hash user pass while creating user!")),
    };
    let key = key_gen().expect("could not serialize symmetric key!");
    let e = match group {
        Some(_) => client.lock().await.execute("INSERT INTO users (user_name, group_name, salt, key, is_admin) VALUES ($1, $2, $3, pgp_sym_encrypt($4 ::text, $6 ::text), $5)",
    &[&user_name, &group, &salt, &key, &is_admin, &db_pass]).await,
        None => client.lock().await.execute("INSERT INTO users (user_name, salt, key, is_admin) VALUES ($1, $2, pgp_sym_encrypt($3 ::text, $5 ::text), $4)",
    &[&user_name, &salt, &key, &is_admin, &db_pass]).await,
    };
    match e {
        Ok(_) => Ok(serde_json::from_str::<[u8; 32]>(&key).map_err(|e| format!("key parse error: {}", e))?.into()),
        Err(e) => Err(format!("couldn't create user! {}", e)),
    }
}

/// Insert a new group into the database.
pub async fn create_group(client: Arc<Mutex<Client>>, group_name: String) -> Result<String, String>{
    let e = client.lock().await.execute("INSERT INTO groups (g_name, users) VALUES ($1, $2)",
    &[&group_name, &Vec::<String>::new()]).await;
    match e {
        Ok(_) => Ok(group_name),
        Err(_) => Err(format!("couldn't create group!")),
    }
}

/// Persist a file or directory node.
pub async fn add_file(client: Arc<Mutex<Client>>, file: FNode) -> Result<String, String> {
    let db_pass = get_db_pass();
    let e = client.lock().await.execute("INSERT INTO
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
    &[&file.name, &file.path, &file.owner, &file.hash, &file.parent, &file.dir, &file.u.to_string(), &file.g.to_string(), &file.o.to_string(), &file.children, &file.encrypted_name, &db_pass]).await;
    match e {
        Ok(_) => Ok(file.name),
        Err(err) => Err(format!("{}",err)),
    }
}

/// Update the stored hash for a file at `path`.
pub async fn update_hash(client: Arc<Mutex<Client>>, path: String, _file_name: String, hash: String) -> Result<String, String>{
    let db_pass = get_db_pass();
    let e = client.lock().await.execute("UPDATE fnode SET hash = $1 WHERE pgp_sym_decrypt(path ::bytea, $3 ::text)=$2",
    &[&hash, &path, &db_pass]).await;
    match e {
        Ok(_) => Ok(path),
        Err(_) => Err(format!("couldn't update hash!")),
    }
}

/// Append a child entry to the parent's `children` array.
pub async fn add_file_to_parent(client: Arc<Mutex<Client>>, parent_path: String, new_f_node_name: String) -> Result<(), String>{
    let db_pass = get_db_pass();
    let e = client.lock().await.execute("UPDATE fnode SET children =
        ARRAY_APPEND(children,
            pgp_sym_encrypt($1 ::text, $3 ::text)::text
        )
        WHERE pgp_sym_decrypt(path ::bytea, $3 ::text)=$2",
    &[&new_f_node_name, &parent_path, &db_pass]).await;
    match e {
        Ok(_) => Ok(()),
        _ => Err("Failed to add file to parent!".to_string()),
    }
}

/// Remove a child entry from the parent's `children` array.
pub async fn remove_file_from_parent(client: Arc<Mutex<Client>>, parent_path: String, f_node_name: String) -> Result<(), String>{
    let db_pass = get_db_pass();
    let e = client.lock().await.execute("UPDATE fnode
        SET children =
            (SELECT array_agg(pgp_sym_encrypt(child1::text, $3::text)) FROM unnest
                (ARRAY_REMOVE((SELECT array_agg(pgp_sym_decrypt(child ::bytea, $3::text)) FROM unnest(children) AS child), $1)
            ) AS child1)
            WHERE pgp_sym_decrypt(path ::bytea, $3 ::text)=$2",
    &[&f_node_name, &parent_path, &db_pass]).await;
    match e {
        Ok(_) => Ok(()),
        _ => Err("Failed to add user to group!".to_string()),
    }
}

/// Fetch a decrypted `FNode` by path.
pub async fn get_f_node(client: Arc<Mutex<Client>>, path: String) -> Result<Option<FNode>, String> {
    let db_pass = get_db_pass();
    let e = client.lock().await.query_opt("SELECT
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
        encrypted_name
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
                // NOTE: These fields are not yet in DB schema; use defaults.
                size: 0,
                created_at: 0,
                modified_at: 0,
            };
            Ok(Some(fnode))
        }
        Ok(None) => Ok(None),
        Err(_) => Err(format!("failed to get fnode!")),
    }
}

/// Update the numeric permissions on a file or directory.
pub async fn change_file_perms(client: Arc<Mutex<Client>>, file_path: String, u: i16, g: i16, o: i16) -> Result<(), String>{
    let db_pass = get_db_pass();
    let e = client.lock().await.execute("
        UPDATE fnode SET
            u=pgp_sym_encrypt($2 ::text, $5 ::text),
            g=pgp_sym_encrypt($3 ::text, $5 ::text),
            o=pgp_sym_encrypt($4 ::text, $5 ::text)
        WHERE pgp_sym_decrypt(path ::bytea, $5 ::text)=$1",
    &[&file_path, &u.to_string(), &g.to_string(), &o.to_string(), &db_pass]).await;
    match e {
        Ok(_) => Ok(()),
        _ => Err("Failed to update file permissions!".to_string()),
    }
}

/// Rewrite stored paths for a subtree, replacing prefixes in bulk.
pub async fn update_path(client: Arc<Mutex<Client>>, file_path: String, new_file_path: String) -> Result<(), String>{
    let db_pass = get_db_pass();
    let e = client.lock().await.execute("UPDATE fnode SET path =
        pgp_sym_encrypt(
            regexp_replace(
                pgp_sym_decrypt(path ::bytea, $4 ::text),
            $1, $2, 'g'),
        $4 ::text)
        WHERE pgp_sym_decrypt(path ::bytea, $4 ::text) ~ $3",
        &[&format!("^{}", file_path), &new_file_path, &format!("^{}", file_path), &db_pass]
    ).await;
    match e {
        Ok(_) => Ok(()),
        _ => Err("Failed to update path!".to_string()),
    }
}

/// Delete every `fnode` whose path matches the provided prefix.
pub async fn delete_path(client: Arc<Mutex<Client>>, file_path: String) -> Result<(), String>{
    let db_pass = get_db_pass();
    let e = client.lock().await.execute("
        DELETE FROM fnode WHERE pgp_sym_decrypt(path ::bytea, $2 ::text) ~ $1",
        &[&format!("^{}", file_path), &db_pass]
    ).await;
    match e {
        Ok(_) => Ok(()),
        _ => Err("Failed to update path!".to_string()),
    }
}

/// Update only the display name after a path rename has occurred.
pub async fn update_fnode_name_if_path_is_already_updated(client: Arc<Mutex<Client>>, path: String, new_name: String) -> Result<(), String>{
    let db_pass = get_db_pass();
    let e = client.lock().await.execute("UPDATE fnode SET name =
        pgp_sym_encrypt($2 ::text, $3 ::text)
        WHERE pgp_sym_decrypt(path::bytea, $3::text) = $1",
    &[&path, &new_name, &db_pass]).await;
    match e {
        Ok(_) => Ok(()),
        _ => Err("Failed to update f_node name!".to_string()),
    }
}

/// Update the encrypted on-disk name for a node.
pub async fn update_fnode_enc_name(client: Arc<Mutex<Client>>, path: String, new_enc_name: String) -> Result<(), String>{
    let db_pass = get_db_pass();
    let e = client.lock().await.execute("UPDATE fnode SET encrypted_name = $2 WHERE pgp_sym_decrypt(path ::bytea, $3 ::text) = $1",
    &[&path, &new_enc_name, &db_pass]).await;
    match e {
        Ok(_) => Ok(()),
        _ => Err("Failed to update f_node name!".to_string()),
    }
}

/// Fetch a user record; decrypt the key with `DB_PASS`.
pub async fn get_user(client: Arc<Mutex<Client>>, user_name: String) -> Result<Option<User>, String> {
    let db_pass = get_db_pass();
    let e = client.lock().await.query_opt("SELECT id, user_name, group_name, pgp_sym_decrypt(key ::bytea, $2 ::text) AS key, salt, is_admin FROM users WHERE user_name = $1",
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
        Err(err) => Err(format!("failed to get user! {}", err)),
    }
}

/// Check whether a group exists.
pub async fn get_group(client: Arc<Mutex<Client>>, group_name: String) -> Result<Option<String>, String> {
    let e = client.lock().await.query_opt("SELECT g_name FROM groups WHERE g_name = $1", &[&group_name]).await;
    match e {
        Ok(Some(_)) => Ok(Some(group_name)),
        Ok(None) => Ok(None),
        Err(_) => Err(format!("failed to get group!")),
    }
}

/// Retrieve all group names from the database.
pub async fn get_all_groups(client: Arc<Mutex<Client>>) -> Result<Vec<String>, String> {
    let rows = client.lock().await.query("SELECT g_name FROM groups ORDER BY g_name", &[]).await;
    match rows {
        Ok(rows) => {
            let groups: Vec<String> = rows.iter().map(|row| row.get("g_name")).collect();
            Ok(groups)
        }
        Err(_) => Err("failed to list groups".to_string()),
    }
}

/// Retrieve all usernames from the database.
pub async fn get_all_users(client: Arc<Mutex<Client>>) -> Result<Vec<String>, String> {
    let rows = client.lock().await.query("SELECT user_name FROM users ORDER BY user_name", &[]).await;
    match rows {
        Ok(rows) => {
            let users: Vec<String> = rows.iter().map(|row| row.get("user_name")).collect();
            Ok(users)
        }
        Err(_) => Err("failed to list users".to_string()),
    }
}

/// Check if a user has admin privileges.
pub async fn is_admin(client: Arc<Mutex<Client>>, user_name: String) -> Result<bool, String> {
    let row = client.lock().await.query_opt("SELECT is_admin FROM users WHERE user_name = $1", &[&user_name]).await;
    match row {
        Ok(Some(row)) => Ok(row.get("is_admin")),
        Ok(None) => Ok(false),
        Err(_) => Err("failed to check admin status".to_string()),
    }
}

/// Change the owner of a file or directory.
pub async fn change_owner(client: Arc<Mutex<Client>>, file_path: String, new_owner: String) -> Result<(), String> {
    let db_pass = get_db_pass();
    let e = client.lock().await.execute(
        "UPDATE fnode SET owner = pgp_sym_encrypt($2 ::text, $3 ::text) WHERE pgp_sym_decrypt(path ::bytea, $3 ::text) = $1",
        &[&file_path, &new_owner, &db_pass]
    ).await;
    match e {
        Ok(_) => Ok(()),
        Err(_) => Err("failed to change owner".to_string()),
    }
}

/// Get the group associated with a file node (via owner's group).
pub async fn get_file_group(client: Arc<Mutex<Client>>, owner: String) -> Result<Option<String>, String> {
    let row = client.lock().await.query_opt(
        "SELECT group_name FROM users WHERE user_name = $1",
        &[&owner]
    ).await;
    match row {
        Ok(Some(row)) => Ok(row.try_get("group_name").unwrap_or(None)),
        Ok(None) => Ok(None),
        Err(_) => Err("failed to get file group".to_string()),
    }
}

/// Check if a user belongs to a specific group.
pub async fn user_in_group(client: Arc<Mutex<Client>>, user_name: String, group_name: String) -> Result<bool, String> {
    // Check primary group first
    let row = client.lock().await.query_opt(
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

    // Check secondary groups in groups table
    let row = client.lock().await.query_opt(
        "SELECT 1 FROM groups WHERE g_name = $2 AND $1 = ANY(users)",
        &[&user_name, &group_name]
    ).await;

    match row {
        Ok(Some(_)) => Ok(true),
        Ok(None) => Ok(false),
        Err(_) => Err("failed to check group membership".to_string()),
    }
}

/// Add a user to a group (secondary membership).
pub async fn add_user_to_group(client: Arc<Mutex<Client>>, user_name: String, group_name: String) -> Result<(), String> {
    // Check if group exists
    let group_exists = get_group(client.clone(), group_name.clone()).await?.is_some();
    if !group_exists {
        return Err(format!("Group {} does not exist", group_name));
    }
    // Update groups table to append user to users array
    let e = client.lock().await.execute(
        "UPDATE groups SET users = array_append(users, $1) WHERE g_name = $2 AND NOT ($1 = ANY(users))",
        &[&user_name, &group_name]
    ).await;
    match e {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("Failed to add user to group: {}", e)),
    }
}

/// Remove a user from a group (secondary membership).
pub async fn remove_user_from_group(client: Arc<Mutex<Client>>, user_name: String, group_name: String) -> Result<(), String> {
    let e = client.lock().await.execute(
        "UPDATE groups SET users = array_remove(users, $1) WHERE g_name = $2",
        &[&user_name, &group_name]
    ).await;
    match e {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("Failed to remove user from group: {}", e)),
    }
}

/// Ensure required seed data exists (currently `/home` root).
pub async fn init_db(client: Arc<Mutex<Client>>) -> Result<(), ()> {
    let does_home_exist = get_f_node(client.clone(), "/home".to_string()).await.unwrap().is_some();
    if !does_home_exist {
        add_file(
            client.clone(),
        FNode {
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
            }).await.unwrap();
    }
    Ok(())
}

/// Recursively copy a file or directory tree.
pub async fn copy_recursive(
    pg_client: Arc<Mutex<Client>>,
    src_root: String,
    dst_root: String,
    owner: String,
) -> Result<(), String> {
    let mut stack = vec![(src_root, dst_root)];

    while let Some((src, dst)) = stack.pop() {
        if let Ok(Some(node)) = get_f_node(pg_client.clone(), src.clone()).await {
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
            };

            if let Err(e) = add_file(pg_client.clone(), new_node).await {
                return Err(format!("db error creating {}: {}", dst, e));
            }
            if let Err(e) = add_file_to_parent(pg_client.clone(), parent, name).await {
                return Err(format!("db parent error linking {}: {}", dst, e));
            }

            if node.dir {
                for child in node.children {
                    // Avoid double slashes if root
                    let child_src = if src == "/" { format!("/{}", child) } else { format!("{}/{}", src, child) };
                    let child_dst = if dst == "/" { format!("/{}", child) } else { format!("{}/{}", dst, child) };
                    stack.push((child_src, child_dst));
                }
            } else {
                let src_storage = format!("storage{}", src);
                let dst_storage = format!("storage{}", dst);
                if let Err(e) = tokio::fs::copy(&src_storage, &dst_storage).await {
                     // Creating directory if it doesn't exist?
                     // Relying on previous loop iteration to have created parent dir.
                     // But if top level is file, parent should exist.
                     // If top level is dir, we handle mkdir below.
                    return Err(format!("fs copy error: {}", e));
                }
            }
            
            if node.dir {
                let dst_storage = format!("storage{}", dst);
                if let Err(e) = tokio::fs::create_dir_all(&dst_storage).await {
                     return Err(format!("fs mkdir error: {}", e));
                }
            }
        }
    }
    Ok(())
}
