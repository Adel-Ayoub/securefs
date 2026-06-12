use deadpool_postgres::Pool;
use securefs_model::protocol::{AppMessage, Cmd};
use securefs_server::dao;

use crate::session::Session;

/// Query audit log. Admin only.
/// Usage: audit_log [limit]
pub async fn audit_log(data: Vec<String>, session: &Session, pool: &Pool) -> AppMessage {
    if !session.authenticated {
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
    let limit: i64 = data
        .first()
        .and_then(|s| s.parse().ok())
        .unwrap_or(50)
        .clamp(1, 1000);
    match dao::query_audit_log(pool, limit).await {
        Ok(entries) => {
            let lines: Vec<String> = entries
                .iter()
                .map(|(ts, event, user, resource, result, ip)| {
                    let ip_str = ip.as_deref().unwrap_or("-");
                    format!(
                        "{} | {} | {} | {} | {} | {}",
                        ts, event, user, resource, result, ip_str
                    )
                })
                .collect();
            AppMessage {
                cmd: Cmd::AuditLog,
                data: lines,
            }
        }
        Err(e) => {
            log::warn!("audit query failed: {}", e);
            AppMessage {
                cmd: Cmd::Failure,
                data: vec!["audit query failed".into()],
            }
        }
    }
}
