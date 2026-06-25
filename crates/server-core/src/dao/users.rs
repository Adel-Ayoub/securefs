use super::records::User;
use aes_gcm::{Aes256Gcm, Key};
use argon2::{
    password_hash::{Encoding, PasswordHashString, PasswordVerifier},
    Argon2,
};
use deadpool_postgres::Pool;

use super::{conn, get_db_pass, key_gen, salt_pass, DaoError};

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
    let key = key_gen()?;
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

// Atomically record a used TOTP time-step. Returns true only when `step` is
// newer than any step already consumed for the user; false means the code was
// already used (on this or any other connection) and must be rejected.
pub async fn consume_totp_step(pool: &Pool, user_name: &str, step: i64) -> Result<bool, DaoError> {
    let client = conn(pool).await?;
    let n = client
        .execute(
            "UPDATE users SET totp_last_step = $2
             WHERE user_name = $1 AND (totp_last_step IS NULL OR totp_last_step < $2)",
            &[&user_name.to_string(), &step],
        )
        .await
        .map_err(|e| DaoError::QueryFailed(format!("consume totp step: {}", e)))?;
    Ok(n == 1)
}
