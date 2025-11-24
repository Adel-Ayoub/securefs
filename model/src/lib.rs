//! SecureFS shared data models and types
//!
//! This crate contains all the core data structures used throughout
//! the SecureFS system for representing users, files, groups, and commands.

use serde::{Deserialize, Serialize};

/// Represents a file or directory node in the file system
#[derive(Debug, Clone, PartialEq)]
pub struct FNode {
    /// Unique identifier for the node
    pub id: String,
    /// Name of the file or directory
    pub name: String,
    /// Full path to the node
    pub path: String,
    /// True if this is a directory, false for files
    pub is_directory: bool,
    /// Size in bytes (0 for directories)
    pub size: u64,
    /// User ID of the owner
    pub owner_id: String,
    /// Group ID of the owner
    pub group_id: String,
    /// Unix-style permissions (e.g., 0o755)
    pub permissions: u32,
    /// Creation timestamp
    pub created_at: u64,
    /// Last modification timestamp
    pub modified_at: u64,
    /// Parent directory ID (None for root)
    pub parent_id: Option<String>,
}

/// Represents a user in the system
#[derive(Debug, Clone, PartialEq)]
pub struct User {
    /// Unique identifier for the user
    pub id: String,
    /// Username (unique)
    pub username: String,
    /// Argon2 password hash
    pub password_hash: String,
    /// Salt used for password hashing
    pub salt: String,
    /// Whether this user has admin privileges
    pub is_admin: bool,
    /// Creation timestamp
    pub created_at: u64,
    /// Last login timestamp
    pub last_login: Option<u64>,
}

/// Represents a group in the system
#[derive(Debug, Clone, PartialEq)]
pub struct Group {
    /// Unique identifier for the group
    pub id: String,
    /// Group name (unique)
    pub name: String,
    /// User ID of the group owner/creator
    pub owner_id: String,
    /// List of user IDs that are members of this group
    pub members: Vec<String>,
    /// Creation timestamp
    pub created_at: u64,
}
