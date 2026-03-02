use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;

pub const RATE_LIMIT_WINDOW_SECS: u64 = 900;
const MAX_RATE_LIMITER_ENTRIES: usize = 10_000;

/// Rate limiter tracking failed login attempts per IP address.
/// Stores (attempt_count, first_attempt_time) per IP.
pub type RateLimiter = Arc<Mutex<HashMap<IpAddr, (u8, Instant)>>>;

/// Remove expired entries and enforce a hard cap on the rate limiter.
pub async fn cleanup_rate_limiter(rl: &RateLimiter) {
    let mut map = rl.lock().await;
    map.retain(|_, (_count, first_time)| first_time.elapsed().as_secs() <= RATE_LIMIT_WINDOW_SECS);
    if map.len() > MAX_RATE_LIMITER_ENTRIES {
        let mut entries: Vec<(IpAddr, Instant)> =
            map.iter().map(|(ip, (_c, t))| (*ip, *t)).collect();
        entries.sort_by_key(|(_ip, t)| *t);
        let to_remove = map.len() - MAX_RATE_LIMITER_ENTRIES;
        for (ip, _) in entries.into_iter().take(to_remove) {
            map.remove(&ip);
        }
    }
}

/// Info about an active session, stored in the global registry.
pub struct SessionInfo {
    pub session_id: String,
    pub username: String,
    pub client_ip: IpAddr,
    pub connected_at: Instant,
    pub last_activity: Instant,
    pub force_logout: bool,
}

/// Global registry of all active sessions. Keyed by session_id.
pub type SessionRegistry = Arc<Mutex<HashMap<String, SessionInfo>>>;

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
    pub totp_required: bool,
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
