use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

use async_trait::async_trait;
use deadpool_postgres::Pool;
use tokio::sync::Mutex;

use crate::dao::{self, DaoError};

// One active session as an administrator sees it. uptime/idle are seconds,
// computed by the implementation (database-authoritative for the shared store,
// so any instance reports the same numbers for a session another instance owns).
pub struct SessionView {
    pub session_id: String,
    pub username: String,
    pub client_ip: String,
    pub uptime_secs: i64,
    pub idle_secs: i64,
}

// Registry of active sessions. The in-process impl is for single-instance/dev;
// the Postgres impl lets N stateless instances list and terminate each other's
// sessions. Forced logout is cooperative: one instance flags a session, the
// instance that owns the connection acts on the flag at its next heartbeat.
#[async_trait]
pub trait SessionStore: Send + Sync {
    async fn register(
        &self,
        session_id: &str,
        username: &str,
        client_ip: IpAddr,
    ) -> Result<(), DaoError>;
    // Bump last activity and report whether this session was flagged for forced
    // logout. False when the session is unknown (already removed/reaped).
    async fn heartbeat(&self, session_id: &str) -> Result<bool, DaoError>;
    async fn remove(&self, session_id: &str) -> Result<(), DaoError>;
    // Flag a session for forced logout. Returns true if the session existed.
    async fn flag_force_logout(&self, session_id: &str) -> Result<bool, DaoError>;
    async fn list(&self) -> Result<Vec<SessionView>, DaoError>;
    // Remove sessions idle longer than idle_secs (left behind by a dead instance).
    async fn reap_expired(&self, idle_secs: u64) -> Result<u64, DaoError>;
}

struct Entry {
    username: String,
    client_ip: IpAddr,
    connected_at: Instant,
    last_activity: Instant,
    force_logout: bool,
}

// Single-instance session registry; state lives in this process only.
#[derive(Default)]
pub struct InProcessSessionStore {
    sessions: Mutex<HashMap<String, Entry>>,
}

impl InProcessSessionStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl SessionStore for InProcessSessionStore {
    async fn register(
        &self,
        session_id: &str,
        username: &str,
        client_ip: IpAddr,
    ) -> Result<(), DaoError> {
        let now = Instant::now();
        self.sessions.lock().await.insert(
            session_id.to_string(),
            Entry {
                username: username.to_string(),
                client_ip,
                connected_at: now,
                last_activity: now,
                force_logout: false,
            },
        );
        Ok(())
    }

    async fn heartbeat(&self, session_id: &str) -> Result<bool, DaoError> {
        let mut map = self.sessions.lock().await;
        match map.get_mut(session_id) {
            Some(e) if e.force_logout => Ok(true),
            Some(e) => {
                e.last_activity = Instant::now();
                Ok(false)
            }
            None => Ok(false),
        }
    }

    async fn remove(&self, session_id: &str) -> Result<(), DaoError> {
        self.sessions.lock().await.remove(session_id);
        Ok(())
    }

    async fn flag_force_logout(&self, session_id: &str) -> Result<bool, DaoError> {
        let mut map = self.sessions.lock().await;
        match map.get_mut(session_id) {
            Some(e) => {
                e.force_logout = true;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    async fn list(&self) -> Result<Vec<SessionView>, DaoError> {
        let map = self.sessions.lock().await;
        Ok(map
            .iter()
            .map(|(id, e)| SessionView {
                session_id: id.clone(),
                username: e.username.clone(),
                client_ip: e.client_ip.to_string(),
                uptime_secs: e.connected_at.elapsed().as_secs() as i64,
                idle_secs: e.last_activity.elapsed().as_secs() as i64,
            })
            .collect())
    }

    async fn reap_expired(&self, idle_secs: u64) -> Result<u64, DaoError> {
        let mut map = self.sessions.lock().await;
        let before = map.len();
        map.retain(|_, e| e.last_activity.elapsed().as_secs() < idle_secs);
        Ok(before.saturating_sub(map.len()) as u64)
    }
}

// Session registry backed by Postgres and shared by all server instances.
pub struct PgSessionStore {
    pool: Pool,
}

impl PgSessionStore {
    pub fn new(pool: Pool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl SessionStore for PgSessionStore {
    async fn register(
        &self,
        session_id: &str,
        username: &str,
        client_ip: IpAddr,
    ) -> Result<(), DaoError> {
        dao::register_session(&self.pool, session_id, username, &client_ip.to_string()).await
    }

    async fn heartbeat(&self, session_id: &str) -> Result<bool, DaoError> {
        dao::heartbeat_session(&self.pool, session_id).await
    }

    async fn remove(&self, session_id: &str) -> Result<(), DaoError> {
        dao::remove_session(&self.pool, session_id).await
    }

    async fn flag_force_logout(&self, session_id: &str) -> Result<bool, DaoError> {
        dao::flag_session_logout(&self.pool, session_id).await
    }

    async fn list(&self) -> Result<Vec<SessionView>, DaoError> {
        let rows = dao::list_sessions(&self.pool).await?;
        Ok(rows
            .into_iter()
            .map(
                |(session_id, username, client_ip, uptime_secs, idle_secs)| SessionView {
                    session_id,
                    username,
                    client_ip,
                    uptime_secs,
                    idle_secs,
                },
            )
            .collect())
    }

    async fn reap_expired(&self, idle_secs: u64) -> Result<u64, DaoError> {
        dao::reap_idle_sessions(&self.pool, idle_secs as i64).await
    }
}
