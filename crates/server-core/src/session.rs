// Per-connection state. Shared, cross-instance state (the session registry and
// the rate limiter) lives behind the SessionStore / RateLimiter traits in the
// library crate, not here.

/// Active upload state for chunked file transfers.
pub struct UploadState {
    pub file_name: String,
    pub chunks: Vec<Vec<u8>>,
    pub total: usize,
}

/// Active download state for chunked file transfers.
pub struct DownloadState {
    pub chunks: Vec<String>,
}

/// Per-connection session state for an authenticated user.
pub struct Session {
    pub authenticated: bool,
    pub totp_required: bool,
    pub totp_attempts: u8,
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
            totp_required: false,
            totp_attempts: 0,
            current_user: None,
            current_user_group: None,
            current_path: "/home".to_string(),
            upload: None,
            download: None,
        }
    }

    pub fn reset(&mut self) {
        self.authenticated = false;
        self.totp_required = false;
        self.totp_attempts = 0;
        self.current_user = None;
        self.current_user_group = None;
        self.current_path = "/home".to_string();
        self.upload = None;
        self.download = None;
    }

    /// True when the user has fully authenticated (password + TOTP if enabled).
    pub fn is_fully_authenticated(&self) -> bool {
        self.authenticated && !self.totp_required
    }
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}
