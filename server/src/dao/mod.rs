//! Data-access helpers for SecureFS.
//!
//! Handles authentication, key material generation, and CRUD helpers
//! that persist `FNode`, `User`, and `Group` records. Queries are kept
//! thin here so the server loop can stay focused on protocol flow.

use std::fmt;

use deadpool_postgres::Pool;

pub mod admin;
pub mod audit;
pub mod fnode;
pub mod groups;
pub mod perms;
pub mod secret;
pub mod users;

pub use admin::*;
pub use audit::*;
pub use fnode::*;
pub use groups::*;
pub use perms::*;
pub use secret::*;
pub use users::*;

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
