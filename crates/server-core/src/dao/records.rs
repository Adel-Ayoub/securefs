//! Persistence records for files, users, and groups, stored by the data-access
//! layer. Server-only (never sent to the client), so they live here rather than
//! in the wire-protocol crate.

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
/// File or directory node persisted in storage.
pub struct FNode {
    /// Unique identifier in the database.
    pub id: i64,
    /// File or directory name.
    pub name: String,
    /// Fully qualified path.
    pub path: String,
    /// Owner username.
    pub owner: String,
    /// Integrity hash of contents.
    pub hash: String,
    /// Parent directory path.
    pub parent: String,
    /// True when this node represents a directory.
    pub dir: bool,
    /// Owner permission bits.
    pub u: i16,
    /// Group permission bits.
    pub g: i16,
    /// Other/world permission bits.
    pub o: i16,
    /// Child entry names for directories.
    pub children: Vec<String>,
    /// Encrypted name stored on disk.
    pub encrypted_name: String,
    /// File size in bytes (0 for directories).
    pub size: i64,
    /// Unix timestamp when the node was created.
    pub created_at: i64,
    /// Unix timestamp when the node was last modified.
    pub modified_at: i64,
    /// File-level group override (None = inherit from owner's group).
    #[serde(default)]
    pub file_group: Option<String>,
    /// Symlink target path (None = regular file/dir).
    #[serde(default)]
    pub link_target: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
/// User record used by the protocol and persistence layer.
pub struct User {
    /// Unique identifier in the database.
    pub id: i64,
    /// Username.
    pub user_name: String,
    /// Associated group, if any.
    pub group_name: Option<String>,
    /// Symmetric key used for user encryption.
    pub key: String,
    /// Password hash (Argon2) encoded as text.
    pub salt: String,
    /// Admin privilege flag.
    pub is_admin: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
/// Group record representing a set of users.
pub struct Group {
    /// Unique identifier in the database.
    pub id: i64,
    /// Member usernames.
    pub users: Vec<String>,
    /// Group name.
    pub g_name: String,
}
