use deadpool_postgres::Pool;

use super::{conn, DaoError};

// True if this IP reached `max_attempts` failures within the last `window_secs`.
pub async fn is_ip_blocked(
    pool: &Pool,
    client_ip: &str,
    max_attempts: i32,
    window_secs: i64,
) -> Result<bool, DaoError> {
    let client = conn(pool).await?;
    let row = client
        .query_opt(
            "SELECT 1 FROM login_attempts
             WHERE client_ip = $1
               AND attempts >= $2
               AND first_attempt > now() - ($3::bigint * interval '1 second')",
            &[&client_ip, &max_attempts, &window_secs],
        )
        .await
        .map_err(|e| DaoError::QueryFailed(format!("is_ip_blocked: {}", e)))?;
    Ok(row.is_some())
}

// Record a failed attempt and return the running count within the window. A
// failure after the window has elapsed resets the count to 1 (matching the old
// in-process limiter, which dropped expired entries before counting). The upsert
// is atomic, so concurrent failures across instances never lose a count.
pub async fn record_login_failure(
    pool: &Pool,
    client_ip: &str,
    window_secs: i64,
) -> Result<u32, DaoError> {
    let client = conn(pool).await?;
    let row = client
        .query_one(
            "INSERT INTO login_attempts (client_ip, attempts, first_attempt)
             VALUES ($1, 1, now())
             ON CONFLICT (client_ip) DO UPDATE SET
                attempts = CASE
                    WHEN login_attempts.first_attempt <= now() - ($2::bigint * interval '1 second')
                    THEN 1 ELSE login_attempts.attempts + 1 END,
                first_attempt = CASE
                    WHEN login_attempts.first_attempt <= now() - ($2::bigint * interval '1 second')
                    THEN now() ELSE login_attempts.first_attempt END
             RETURNING attempts",
            &[&client_ip, &window_secs],
        )
        .await
        .map_err(|e| DaoError::QueryFailed(format!("record_login_failure: {}", e)))?;
    let attempts: i32 = row.get(0);
    Ok(attempts.max(0) as u32)
}

pub async fn clear_login_attempts(pool: &Pool, client_ip: &str) -> Result<(), DaoError> {
    let client = conn(pool).await?;
    client
        .execute(
            "DELETE FROM login_attempts WHERE client_ip = $1",
            &[&client_ip],
        )
        .await
        .map(|_| ())
        .map_err(|e| DaoError::QueryFailed(format!("clear_login_attempts: {}", e)))
}

// Drop entries whose window has elapsed. Returns the number removed.
pub async fn cleanup_login_attempts(pool: &Pool, window_secs: i64) -> Result<u64, DaoError> {
    let client = conn(pool).await?;
    client
        .execute(
            "DELETE FROM login_attempts
             WHERE first_attempt <= now() - ($1::bigint * interval '1 second')",
            &[&window_secs],
        )
        .await
        .map_err(|e| DaoError::QueryFailed(format!("cleanup_login_attempts: {}", e)))
}
