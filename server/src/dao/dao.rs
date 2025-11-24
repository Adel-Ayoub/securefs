use std::{env, sync::Arc};
use tokio::sync::Mutex;
use tokio_postgres::Client;
use argon2::{
    password_hash::{
        Encoding, PasswordHash, PasswordHashString, PasswordHasher, PasswordVerifier, SaltString
    },
    Argon2
};
use securefs_model::User;

pub fn salt_pass(pass: String) -> Result<String, String> {
    let b_pass = pass.as_bytes();
    let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
    let argon2 = Argon2::default();
    match argon2.hash_password(b_pass, &salt) {
        Ok(p) => Ok(p.serialize().as_str().to_string()),
        Err(_) => Err("Error with salting pass".into()),
    }
}

pub async fn auth_user(client: Arc<Mutex<Client>>, user_name: String, pass: String) -> Result<bool, String> {
    let e = client.lock().await.query_one("SELECT salt FROM users WHERE username=$1",
    &[&user_name]).await;
    let res = match e {
        Ok(row) => row,
        Err(_) => return Ok(false),
    };
    let hash: String = res.get("salt");
    let hash_str: PasswordHashString = PasswordHashString::parse(hash.as_str(), Encoding::B64).unwrap();
    let true_hash = hash_str.password_hash();
    match Argon2::default().verify_password(pass.as_bytes(), &true_hash) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

pub async fn create_user(client: Arc<Mutex<Client>>, user_name: String, pass: String, is_admin: bool) -> Result<(), String>{
    let salt = match salt_pass(pass){
        Ok(salt) => salt,
        Err(_) => return Err("couldn't hash user pass while creating user!".into()),
    };
    let e = client.lock().await.execute("INSERT INTO users (username, password_hash, salt, is_admin) VALUES ($1, $2, $3, $4)",
    &[&user_name, &salt, &salt, &is_admin]).await;
    match e {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("couldn't create user! {}", e)),
    }
}

pub async fn get_user(client: Arc<Mutex<Client>>, user_name: String) -> Result<Option<User>, String> {
    let e = client.lock().await.query_opt("SELECT id, username, password_hash, salt, is_admin, created_at, last_login FROM users WHERE username = $1",
     &[&user_name]).await;
    match e {
        Ok(Some(row)) => Ok(Some(User{
            id: row.get("id"),
            username: row.get("username"),
            password_hash: row.get("password_hash"),
            salt: row.get("salt"),
            is_admin: row.get("is_admin"),
            created_at: row.get("created_at"),
            last_login: row.try_get("last_login").unwrap_or(None),
        })),
        Ok(None) => Ok(None),
        Err(err) => Err(format!("failed to get user! {}", err)),
    }
}
