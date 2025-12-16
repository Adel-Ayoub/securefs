//! SecureFS shared data models and types.
//!
//! This crate contains all the core data structures used throughout
//! the SecureFS system for representing users, files, groups, and commands.

pub mod protocol;
pub mod cmd;

use serde::{Deserialize, Serialize};
use std::fmt;

/// Common result type used throughout SecureFS
pub type Result<T> = std::result::Result<T, Error>;

/// Custom error type for SecureFS operations
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Error {
    /// Authentication failed
    AuthenticationFailed,
    /// User not found
    UserNotFound,
    /// Group not found
    GroupNotFound,
    /// File or directory not found
    NotFound,
    /// Permission denied
    PermissionDenied,
    /// File or directory already exists
    AlreadyExists,
    /// Invalid path
    InvalidPath,
    /// I/O error
    IoError(String),
    /// Database error
    DatabaseError(String),
    /// Network error
    NetworkError(String),
    /// Invalid command or arguments
    InvalidCommand(String),
    /// Session expired or invalid
    SessionError,
    /// Encryption/decryption error
    CryptoError(String),
    /// Serialization error
    SerializationError(String),
    /// Internal server error
    InternalError(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::AuthenticationFailed => write!(f, "Authentication failed"),
            Error::UserNotFound => write!(f, "User not found"),
            Error::GroupNotFound => write!(f, "Group not found"),
            Error::NotFound => write!(f, "File or directory not found"),
            Error::PermissionDenied => write!(f, "Permission denied"),
            Error::AlreadyExists => write!(f, "File or directory already exists"),
            Error::InvalidPath => write!(f, "Invalid path"),
            Error::IoError(msg) => write!(f, "I/O error: {}", msg),
            Error::DatabaseError(msg) => write!(f, "Database error: {}", msg),
            Error::NetworkError(msg) => write!(f, "Network error: {}", msg),
            Error::InvalidCommand(msg) => write!(f, "Invalid command: {}", msg),
            Error::SessionError => write!(f, "Session error"),
            Error::CryptoError(msg) => write!(f, "Cryptography error: {}", msg),
            Error::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            Error::InternalError(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl std::error::Error for Error {}

/// Represents a file or directory node in the file system
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

/// Represents a file system path
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Path {
    /// Components of the path (e.g., ["home", "user", "file.txt"])
    pub components: Vec<String>,
    /// Whether this is an absolute path
    pub is_absolute: bool,
}

impl std::fmt::Display for Path {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.components.is_empty() {
            return write!(f, "{}", if self.is_absolute { "/" } else { "." });
        }

        let mut path_str = String::new();
        if self.is_absolute {
            path_str.push('/');
        }

        for (i, component) in self.components.iter().enumerate() {
            if i > 0 || self.is_absolute {
                path_str.push('/');
            }
            path_str.push_str(component);
        }

        write!(f, "{}", path_str)
    }
}

/// File system commands supported by SecureFS
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Cmd {
    // Authentication
    Login { username: String, password: String },
    Logout,

    // File operations
    List { path: Option<Path> },
    ChangeDir { path: Path },
    PrintWorkingDir,
    ReadFile { path: Path },
    WriteFile { path: Path, data: Vec<u8> },
    CreateFile { path: Path },
    CreateDir { path: Path },
    Remove { path: Path, recursive: bool },
    Copy { src: Path, dst: Path },
    Move { src: Path, dst: Path },

    // User management (admin only)
    CreateUser { username: String, password: String, is_admin: bool },
    DeleteUser { username: String },
    ChangePassword { username: String, new_password: String },

    // Group management
    CreateGroup { name: String },
    DeleteGroup { name: String },
    AddUserToGroup { username: String, groupname: String },
    RemoveUserFromGroup { username: String, groupname: String },

    // Permission management
    ChangePermissions { path: Path, permissions: u32 },
    ChangeOwner { path: Path, username: String },
    ChangeGroup { path: Path, groupname: String },

    // Search operations
    Find { path: Path, pattern: String },

    // System info
    WhoAmI,
    Groups,
}

/// Message wrapper for client-server communication
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AppMessage {
    /// Unique message identifier
    pub id: String,
    /// Session token for authenticated requests
    pub session_token: Option<String>,
    /// The command being executed
    pub command: Cmd,
    /// Timestamp when the message was created
    pub timestamp: u64,
}

/// Response wrapper for server responses
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AppResponse {
    /// Message ID this response corresponds to
    pub message_id: String,
    /// Whether the operation was successful
    pub success: bool,
    /// Response data (varies by command)
    pub data: ResponseData,
    /// Error message if operation failed
    pub error: Option<String>,
    /// Timestamp when the response was created
    pub timestamp: u64,
}

/// Response data variants for different command types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ResponseData {
    /// Authentication response with session token
    Auth { session_token: String, user_id: String },
    /// File listing response
    FileList { nodes: Vec<FNode> },
    /// Single file/directory info
    FileInfo { node: FNode },
    /// File content (for read operations)
    FileContent { data: Vec<u8> },
    /// Current working directory
    WorkingDir { path: Path },
    /// User information
    UserInfo { user: User },
    /// Group information
    GroupInfo { group: Group },
    /// List of groups
    GroupList { groups: Vec<Group> },
    /// Simple acknowledgment (no data)
    Ack,
    /// Search results
    SearchResults { nodes: Vec<FNode> },
}
