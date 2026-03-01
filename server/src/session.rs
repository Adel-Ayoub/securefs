use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;

/// Rate limiter tracking failed login attempts per IP address.
/// Stores (attempt_count, first_attempt_time) per IP.
pub type RateLimiter = Arc<Mutex<HashMap<IpAddr, (u8, Instant)>>>;

/// Active upload state for chunked file transfers.
pub struct UploadState {
    pub file_name: String,
    pub chunks: Vec<Vec<u8>>,
}

/// Active download state for chunked file transfers.
pub struct DownloadState {
    pub chunks: Vec<String>,
}

/// Per-connection session state for an authenticated user.
pub struct Session {
    pub authenticated: bool,
    pub current_user: Option<String>,
    pub current_user_group: Option<String>,
    pub current_path: String,
    pub upload: Option<UploadState>,
    pub download: Option<DownloadState>,
}

impl Session {
    pub fn new() -> Self {
        Self {
            authenticated: false,
            current_user: None,
            current_user_group: None,
            current_path: "/home".to_string(),
            upload: None,
            download: None,
        }
    }

    pub fn reset(&mut self) {
        self.authenticated = false;
        self.current_user = None;
        self.current_user_group = None;
        self.current_path = "/home".to_string();
        self.upload = None;
        self.download = None;
    }
}
