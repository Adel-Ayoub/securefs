use deadpool_postgres::Pool;
use securefs_model::protocol::{AppMessage, Cmd};
use securefs_server::dao;

use crate::session::{Session, SessionRegistry};

/// List all active sessions. Admin only.
pub async fn list_sessions(
    session: &Session,
    pool: &Pool,
    registry: &SessionRegistry,
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
    let map = registry.lock().await;
    let lines: Vec<String> = map
        .values()
        .map(|info| {
            let uptime = info.connected_at.elapsed().as_secs();
            let idle = info.last_activity.elapsed().as_secs();
            format!(
                "{} | {} | {} | up {}s | idle {}s",
                info.session_id, info.username, info.client_ip, uptime, idle
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
    registry: &SessionRegistry,
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
    let mut map = registry.lock().await;
    if let Some(info) = map.get_mut(&target_id) {
        info.force_logout = true;
        audit!(pool, "FORCE_LOGOUT", user, &target_id, "flagged");
        AppMessage {
            cmd: Cmd::ForceLogout,
            data: vec![format!("session {} flagged for logout", target_id)],
        }
    } else {
        AppMessage {
            cmd: Cmd::Failure,
            data: vec![format!("session {} not found", target_id)],
        }
    }
}
