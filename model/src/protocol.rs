//! Public wire protocol types exchanged between the SecureFS server and client.

use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Default)]
/// Commands supported by the websocket protocol.
pub enum Cmd {
    /// Read a file's contents.
    Cat,
    /// Change the current working directory.
    Cd,
    /// Delete a file or directory.
    Delete,
    /// Write data to a file (create or overwrite).
    Echo,
    /// Authenticate and start a session.
    Login,
    /// List entries in the current directory.
    Ls,
    /// Create a directory.
    Mkdir,
    /// Download an encrypted file name.
    GetEncryptedFile,
    /// Move or rename a file or directory.
    Mv,
    /// Trigger a server-side scan (if implemented).
    Scan,
    /// Initialize a websocket connection handshake.
    NewConnection,
    /// Create a new group (admin only).
    NewGroup,
    /// Create a new user (admin only).
    NewUser,
    /// Generic failure response.
    Failure,
    /// Print current working directory.
    Pwd,
    /// Create an empty file.
    Touch,
    /// Change permissions on a file or directory.
    Chmod,
    /// List all users (admin only).
    LsUsers,
    /// List all groups (admin only).
    LsGroups,
    /// Terminate the session.
    Logout,
    /// Copy a file or directory.
    Cp,
    /// Search for files by pattern.
    Find,
    /// Change file or directory owner.
    Chown,
    /// Change file or directory group.
    Chgrp,
    /// Client initiates X25519 key exchange with public key.
    KeyExchangeInit,
    /// Server responds with its X25519 public key.
    KeyExchangeResponse,
    /// Add a user to a group (admin only).
    AddUserToGroup,
    /// Remove a user from a group (admin only).
    RemoveUserFromGroup,
    #[default]
    /// Placeholder for unknown commands.
    Invalid,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
/// Application-level message envelope.
pub struct AppMessage {
    /// Command to execute.
    pub cmd: Cmd,
    /// Payload arguments associated with the command.
    pub data: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
/// Normalized filesystem path in tuple form `(is_dir, component)`.
pub struct Path {
    /// Path components and directory markers.
    pub path: Vec<(bool, String)>,
}

impl std::fmt::Display for Path {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut path_string = self
            .path
            .iter()
            .map(|x| x.1.clone())
            .filter(|x| x != "/")
            .collect::<Vec<String>>()
            .join("/");

        path_string.insert_str(0, "/");
        write!(f, "{}", path_string)?;
        Ok(())
    }
}

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
