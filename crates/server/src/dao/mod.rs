//! Data-access helpers for SecureFS.
//!
//! Handles authentication, key material generation, and CRUD helpers
//! that persist `FNode`, `User`, and `Group` records. Queries are kept
//! thin here so the server loop can stay focused on protocol flow.

use deadpool_postgres::Pool;

pub mod admin;
pub mod audit;
pub mod cryptometa;
pub mod fnode;
pub mod groups;
pub mod perms;
pub mod rate_limit;
pub mod secret;
pub mod sessions;
pub mod users;

pub use admin::*;
pub use audit::*;
pub use cryptometa::*;
pub use fnode::*;
pub use groups::*;
pub use perms::*;
pub use rate_limit::*;
pub use secret::*;
pub use sessions::*;
pub use users::*;

/// Typed error for all DAO operations.
#[derive(Debug, thiserror::Error)]
pub enum DaoError {
    /// Row not found when one was expected.
    #[error("not found")]
    NotFound,
    /// Query or execute failed at the database level.
    #[error("query failed: {0}")]
    QueryFailed(String),
    /// Data could not be parsed (hash, key, JSON, etc.).
    #[error("parse error: {0}")]
    ParseError(String),
    /// A constraint was violated (duplicate, FK, etc.).
    #[error("conflict: {0}")]
    Conflict(String),
}

/// Get a connection from the pool, mapping errors to DaoError.
async fn conn(pool: &Pool) -> Result<deadpool_postgres::Object, DaoError> {
    pool.get()
        .await
        .map_err(|e| DaoError::QueryFailed(format!("pool: {}", e)))
}
