use deadpool_postgres::Pool;

use super::{conn, DaoError};

/// Insert a new group into the database.
pub async fn create_group(pool: &Pool, group_name: String) -> Result<String, DaoError> {
    let client = conn(pool).await?;
    client
        .execute(
            "INSERT INTO groups (g_name, users) VALUES ($1, $2)",
            &[&group_name, &Vec::<String>::new()],
        )
        .await
        .map(|_| group_name)
        .map_err(|e| DaoError::Conflict(format!("create group: {}", e)))
}

/// Check whether a group exists.
pub async fn get_group(pool: &Pool, group_name: String) -> Result<Option<String>, DaoError> {
    let client = conn(pool).await?;
    let e = client
        .query_opt(
            "SELECT g_name FROM groups WHERE g_name = $1",
            &[&group_name],
        )
        .await;
    match e {
        Ok(Some(_)) => Ok(Some(group_name)),
        Ok(None) => Ok(None),
        Err(e) => Err(DaoError::QueryFailed(format!("get group: {}", e))),
    }
}

/// Retrieve all group names from the database.
pub async fn get_all_groups(pool: &Pool) -> Result<Vec<String>, DaoError> {
    let client = conn(pool).await?;
    client
        .query("SELECT g_name FROM groups ORDER BY g_name", &[])
        .await
        .map(|rows| rows.iter().map(|row| row.get("g_name")).collect())
        .map_err(|e| DaoError::QueryFailed(format!("list groups: {}", e)))
}

/// Check if a user belongs to a specific group.
pub async fn user_in_group(
    pool: &Pool,
    user_name: String,
    group_name: String,
) -> Result<bool, DaoError> {
    let client = conn(pool).await?;
    let row = client
        .query_opt(
            "SELECT group_name FROM users WHERE user_name = $1",
            &[&user_name],
        )
        .await;

    let primary_group_match = match row {
        Ok(Some(row)) => {
            let user_group: Option<String> = row.try_get("group_name").unwrap_or(None);
            user_group.map(|g| g == group_name).unwrap_or(false)
        }
        _ => false,
    };

    if primary_group_match {
        return Ok(true);
    }

    let row = client
        .query_opt(
            "SELECT 1 FROM groups WHERE g_name = $2 AND $1 = ANY(users)",
            &[&user_name, &group_name],
        )
        .await;

    match row {
        Ok(Some(_)) => Ok(true),
        Ok(None) => Ok(false),
        Err(e) => Err(DaoError::QueryFailed(format!(
            "check group membership: {}",
            e
        ))),
    }
}

/// Add a user to a group (secondary membership).
pub async fn add_user_to_group(
    pool: &Pool,
    user_name: String,
    group_name: String,
) -> Result<(), DaoError> {
    let group_exists = get_group(pool, group_name.clone()).await?.is_some();
    if !group_exists {
        return Err(DaoError::NotFound);
    }
    let client = conn(pool).await?;
    client.execute(
        "UPDATE groups SET users = array_append(users, $1) WHERE g_name = $2 AND NOT ($1 = ANY(users))",
        &[&user_name, &group_name]
    ).await
        .map(|_| ())
        .map_err(|e| DaoError::QueryFailed(format!("add user to group: {}", e)))
}

/// Remove a user from a group (secondary membership).
pub async fn remove_user_from_group(
    pool: &Pool,
    user_name: String,
    group_name: String,
) -> Result<(), DaoError> {
    let client = conn(pool).await?;
    client
        .execute(
            "UPDATE groups SET users = array_remove(users, $1) WHERE g_name = $2",
            &[&user_name, &group_name],
        )
        .await
        .map(|_| ())
        .map_err(|e| DaoError::QueryFailed(format!("remove user from group: {}", e)))
}
