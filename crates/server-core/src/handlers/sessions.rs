use crate::dao;
use crate::session_store::SessionStore;
use deadpool_postgres::Pool;
use securefs_proto::protocol::{AppMessage, Cmd};

use crate::session::Session;

/// List all active sessions. Admin only.
pub async fn list_sessions(session: &Session, pool: &Pool, store: &dyn SessionStore) -> AppMessage {
    if !session.is_fully_authenticated() {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["not authenticated".into()],
        };
    }
    let user = session.current_user.as_deref().unwrap_or("");
    match dao::is_admin(pool, user.to_string()).await {
        Ok(true) => {}
        _ => {
            return AppMessage {
                cmd: Cmd::Failure,
                data: vec!["admin privileges required".into()],
            }
        }
    }
    let views = match store.list().await {
        Ok(v) => v,
        Err(e) => {
            return AppMessage {
                cmd: Cmd::Failure,
                data: vec![format!("failed to list sessions: {}", e)],
            }
        }
    };
    let lines: Vec<String> = views
        .iter()
        .map(|info| {
            format!(
                "{} | {} | {} | up {}s | idle {}s",
                info.session_id, info.username, info.client_ip, info.uptime_secs, info.idle_secs
            )
        })
        .collect();
    AppMessage {
        cmd: Cmd::ListSessions,
        data: lines,
    }
}

/// Force-logout a session by its ID. Admin only.
pub async fn force_logout(
    data: Vec<String>,
    session: &Session,
    pool: &Pool,
    store: &dyn SessionStore,
) -> AppMessage {
    if !session.is_fully_authenticated() {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["not authenticated".into()],
        };
    }
    let user = session.current_user.as_deref().unwrap_or("");
    match dao::is_admin(pool, user.to_string()).await {
        Ok(true) => {}
        _ => {
            return AppMessage {
                cmd: Cmd::Failure,
                data: vec!["admin privileges required".into()],
            }
        }
    }
    let target_id = data.first().cloned().unwrap_or_default();
    if target_id.is_empty() {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["usage: force_logout <session_id>".into()],
        };
    }
    // Flag the session wherever it lives; the instance that owns the connection
    // tears it down at its next heartbeat.
    match store.flag_force_logout(&target_id).await {
        Ok(true) => {
            audit!(pool, "FORCE_LOGOUT", user, &target_id, "flagged");
            AppMessage {
                cmd: Cmd::ForceLogout,
                data: vec![format!("session {} flagged for logout", target_id)],
            }
        }
        Ok(false) => AppMessage {
            cmd: Cmd::Failure,
            data: vec![format!("session {} not found", target_id)],
        },
        Err(e) => AppMessage {
            cmd: Cmd::Failure,
            data: vec![format!("force logout failed: {}", e)],
        },
    }
}
