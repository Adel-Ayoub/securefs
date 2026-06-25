use deadpool_postgres::Pool;

use super::{conn, DaoError};

// Insert or refresh a session row. session_id is a fresh uuid per connection, so
// the conflict branch only fires on a (defensive) re-register of the same id.
pub async fn register_session(
    pool: &Pool,
    session_id: &str,
    username: &str,
    client_ip: &str,
) -> Result<(), DaoError> {
    let client = conn(pool).await?;
    client
        .execute(
            "INSERT INTO sessions
                (session_id, username, client_ip, connected_at, last_activity, force_logout)
             VALUES ($1, $2, $3, now(), now(), false)
             ON CONFLICT (session_id) DO UPDATE SET
                username = EXCLUDED.username,
                client_ip = EXCLUDED.client_ip,
                connected_at = now(),
                last_activity = now(),
                force_logout = false",
            &[&session_id, &username, &client_ip],
        )
        .await
        .map(|_| ())
        .map_err(|e| DaoError::QueryFailed(format!("register session: {}", e)))
}

// Bump last_activity and report whether an admin (possibly on another instance)
// flagged this session for logout. A flagged session is not bumped; an unknown
// session (already removed/reaped) reports false.
pub async fn heartbeat_session(pool: &Pool, session_id: &str) -> Result<bool, DaoError> {
    let client = conn(pool).await?;
    let row = client
        .query_opt(
            "UPDATE sessions
             SET last_activity = CASE WHEN force_logout THEN last_activity ELSE now() END
             WHERE session_id = $1
             RETURNING force_logout",
            &[&session_id],
        )
        .await
        .map_err(|e| DaoError::QueryFailed(format!("heartbeat session: {}", e)))?;
    Ok(row.map(|r| r.get::<_, bool>(0)).unwrap_or(false))
}

pub async fn remove_session(pool: &Pool, session_id: &str) -> Result<(), DaoError> {
    let client = conn(pool).await?;
    client
        .execute("DELETE FROM sessions WHERE session_id = $1", &[&session_id])
        .await
        .map(|_| ())
        .map_err(|e| DaoError::QueryFailed(format!("remove session: {}", e)))
}

// Flag a session for forced logout. Returns true if the session existed.
pub async fn flag_session_logout(pool: &Pool, session_id: &str) -> Result<bool, DaoError> {
    let client = conn(pool).await?;
    let n = client
        .execute(
            "UPDATE sessions SET force_logout = true WHERE session_id = $1",
            &[&session_id],
        )
        .await
        .map_err(|e| DaoError::QueryFailed(format!("flag session logout: {}", e)))?;
    Ok(n == 1)
}

// All active sessions with database-computed uptime and idle seconds, so the
// numbers are consistent regardless of which instance created the session.
pub async fn list_sessions(
    pool: &Pool,
) -> Result<Vec<(String, String, String, i64, i64)>, DaoError> {
    let client = conn(pool).await?;
    let rows = client
        .query(
            "SELECT session_id, username, client_ip,
                    EXTRACT(EPOCH FROM (now() - connected_at))::bigint AS uptime,
                    EXTRACT(EPOCH FROM (now() - last_activity))::bigint AS idle
             FROM sessions ORDER BY connected_at",
            &[],
        )
        .await
        .map_err(|e| DaoError::QueryFailed(format!("list sessions: {}", e)))?;
    Ok(rows
        .iter()
        .map(|r| {
            (
                r.get::<_, String>(0),
                r.get::<_, String>(1),
                r.get::<_, String>(2),
                r.get::<_, i64>(3),
                r.get::<_, i64>(4),
            )
        })
        .collect())
}

// Reap sessions idle longer than idle_secs (an instance that died mid-session
// leaves its rows behind). Returns the number removed.
pub async fn reap_idle_sessions(pool: &Pool, idle_secs: i64) -> Result<u64, DaoError> {
    let client = conn(pool).await?;
    client
        .execute(
            "DELETE FROM sessions
             WHERE last_activity <= now() - ($1::bigint * interval '1 second')",
            &[&idle_secs],
        )
        .await
        .map_err(|e| DaoError::QueryFailed(format!("reap sessions: {}", e)))
}
