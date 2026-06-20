use deadpool_postgres::Pool;

use super::{conn, DaoError};

/// Persist an audit log entry.
pub async fn insert_audit_log(
    pool: &Pool,
    event: &str,
    username: &str,
    resource: &str,
    result: &str,
    ip: Option<&str>,
) -> Result<(), DaoError> {
    let client = conn(pool).await?;
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    client
        .execute(
            "INSERT INTO audit_log (ts, event, username, resource, result, ip)
             VALUES ($1, $2, $3, $4, $5, $6)",
            &[&ts, &event, &username, &resource, &result, &ip],
        )
        .await
        .map(|_| ())
        .map_err(|e| DaoError::QueryFailed(format!("insert audit: {}", e)))
}

/// Query audit log entries, most recent first.
pub async fn query_audit_log(
    pool: &Pool,
    limit: i64,
) -> Result<Vec<(i64, String, String, String, String, Option<String>)>, DaoError> {
    let client = conn(pool).await?;
    let rows = client
        .query(
            "SELECT ts, event, username, resource, result, ip
             FROM audit_log ORDER BY ts DESC LIMIT $1",
            &[&limit],
        )
        .await
        .map_err(|e| DaoError::QueryFailed(format!("query audit: {}", e)))?;
    Ok(rows
        .iter()
        .map(|r| {
            (
                r.get::<_, i64>(0),
                r.get::<_, String>(1),
                r.get::<_, String>(2),
                r.get::<_, String>(3),
                r.get::<_, String>(4),
                r.try_get::<_, Option<String>>(5).unwrap_or(None),
            )
        })
        .collect())
}
