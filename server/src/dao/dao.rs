//! Data-access helpers for SecureFS.
//!
//! Handles authentication, key material generation, and CRUD helpers
//! that persist `FNode`, `User`, and `Group` records. Queries are kept
//! thin here so the server loop can stay focused on protocol flow.

use std::{env, sync::Arc};
use tokio::sync::Mutex;
use tokio_postgres::Client;
use argon2::{
    password_hash::{
        Encoding, PasswordHash, PasswordHashString, PasswordHasher, PasswordVerifier, SaltString
    },
    Argon2
};
use securefs_model::protocol::{FNode, User};
use aes_gcm::{Aes256Gcm, KeyInit, Key, aead::{AeadCore}};
use blake3;
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
    let hash_str: PasswordHashString = PasswordHashString::parse(hash.as_str(), Encoding::B64).unwrap();
    let true_hash = hash_str.password_hash();
    match Argon2::default().verify_password(pass.as_bytes(), &true_hash) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Create a new user row and return the decrypted symmetric key for the caller.
pub async fn create_user(client: Arc<Mutex<Client>>, user_name: String, pass: String, group: Option<String>, is_admin: bool) -> Result<Key<Aes256Gcm>, String>{
    // NOTE: DB_PASS default is a convenience for local dev only; deployments should set it.
    let db_pass = env::var("DB_PASS").unwrap_or("TEMP".to_string());
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
        Ok(_) => Ok(serde_json::from_str::<[u8; 32]>(&key).unwrap().into()),
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
    let db_pass = env::var("DB_PASS").unwrap_or("TEMP".to_string());
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
pub async fn update_hash(client: Arc<Mutex<Client>>, path: String, file_name: String, hash: String) -> Result<String, String>{
    let db_pass = env::var("DB_PASS").unwrap_or("TEMP".to_string());
    let e = client.lock().await.execute("UPDATE fnode SET hash = $1 WHERE pgp_sym_decrypt(path ::bytea, $3 ::text)=$2",
    &[&hash, &path, &db_pass]).await;
    match e {
        Ok(_) => Ok(path),
        Err(_) => Err(format!("couldn't update hash!")),
    }
}

/// Append a child entry to the parent's `children` array.
pub async fn add_file_to_parent(client: Arc<Mutex<Client>>, parent_path: String, new_f_node_name: String) -> Result<(), String>{
    let db_pass = env::var("DB_PASS").unwrap_or("TEMP".to_string());
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
    let db_pass = env::var("DB_PASS").unwrap_or("TEMP".to_string());
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
    let db_pass = env::var("DB_PASS").unwrap_or("TEMP".to_string());
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
            };
            Ok(Some(fnode))
        }
        Ok(None) => Ok(None),
        Err(_) => Err(format!("failed to get fnode!")),
    }
}

/// Update the numeric permissions on a file or directory.
pub async fn change_file_perms(client: Arc<Mutex<Client>>, file_path: String, u: i16, g: i16, o: i16) -> Result<(), String>{
    let db_pass = env::var("DB_PASS").unwrap_or("TEMP".to_string());
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
    let db_pass = env::var("DB_PASS").unwrap_or("TEMP".to_string());
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
    let db_pass = env::var("DB_PASS").unwrap_or("TEMP".to_string());
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
    let db_pass = env::var("DB_PASS").unwrap_or("TEMP".to_string());
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
    let db_pass = env::var("DB_PASS").unwrap_or("TEMP".to_string());
    let e = client.lock().await.execute("UPDATE fnode SET encrypted_name = $2 WHERE pgp_sym_decrypt(path ::bytea, $3 ::text) = $1",
    &[&path, &new_enc_name, &db_pass]).await;
    match e {
        Ok(_) => Ok(()),
        _ => Err("Failed to update f_node name!".to_string()),
    }
}

/// Fetch a user record; decrypt the key with `DB_PASS` unless the user is `admin`.
pub async fn get_user(client: Arc<Mutex<Client>>, user_name: String) -> Result<Option<User>, String> {
    let db_pass = env::var("DB_PASS").unwrap_or("TEMP".to_string());
    let e = if user_name == "admin" {
        client.lock().await.query_opt("SELECT id, user_name, group_name, pgp_sym_decrypt(key ::bytea, 'DOES_NOT_MATTER' ::text) AS key, salt, is_admin FROM users WHERE user_name = $1",
     &[&user_name]).await
    } else {
        client.lock().await.query_opt("SELECT id, user_name, group_name, pgp_sym_decrypt(key ::bytea, $2 ::text) AS key, salt, is_admin FROM users WHERE user_name = $1",
     &[&user_name, &db_pass]).await
    };
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
                encrypted_name: "".to_string()
            }).await.unwrap();
    }
    Ok(())
}
