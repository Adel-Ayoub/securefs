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
    /// Show current user and group.
    Whoami,
    /// Display recursive directory tree.
    Tree,
    /// Show detailed file/directory metadata.
    Stat,
    /// Show disk usage for current directory.
    Du,
    /// Display first N lines of a file.
    Head,
    /// Display last N lines of a file.
    Tail,
    /// Search file contents for a pattern.
    Grep,
    /// Create a symbolic link.
    Ln,
    /// Begin a chunked file upload.
    UploadStart,
    /// Send a base64-encoded chunk during upload.
    UploadChunk,
    /// Finalize a chunked file upload.
    UploadEnd,
    /// Begin a chunked file download.
    DownloadStart,
    /// Request a specific chunk during download.
    DownloadChunk,
    /// Finalize a chunked file download.
    DownloadEnd,
    /// Query the persistent audit log (admin only).
    AuditLog,
    /// Begin TOTP setup — returns provisioning URI.
    TotpSetup,
    /// Verify a 6-digit TOTP code.
    TotpVerify,
    /// List all active sessions (admin only).
    ListSessions,
    /// Force logout a specific session (admin only).
    ForceLogout,
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

        path_string.insert(0, '/');
        write!(f, "{}", path_string)?;
        Ok(())
    }
}
