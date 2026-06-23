use deadpool_postgres::Pool;

use super::{conn, get_db_pass, path_digest, DaoError};

/// Update the numeric permissions on a file or directory.
pub async fn change_file_perms(
    pool: &Pool,
    file_path: String,
    u: i16,
    g: i16,
    o: i16,
) -> Result<(), DaoError> {
    let client = conn(pool).await?;
    let db_pass = get_db_pass();
    let digest = path_digest(&file_path);
    client
        .execute(
            "
        UPDATE fnode SET
            u=pgp_sym_encrypt($2 ::text, $5 ::text),
            g=pgp_sym_encrypt($3 ::text, $5 ::text),
            o=pgp_sym_encrypt($4 ::text, $5 ::text)
        WHERE path_digest = $1",
            &[
                &digest,
                &u.to_string(),
                &g.to_string(),
                &o.to_string(),
                &db_pass,
            ],
        )
        .await
        .map(|_| ())
        .map_err(|e| DaoError::QueryFailed(format!("change perms: {}", e)))
}

/// Change the owner of a file or directory.
pub async fn change_owner(
    pool: &Pool,
    file_path: String,
    new_owner: String,
) -> Result<(), DaoError> {
    let client = conn(pool).await?;
    let db_pass = get_db_pass();
    let digest = path_digest(&file_path);
    client
        .execute(
            "UPDATE fnode SET owner = pgp_sym_encrypt($2 ::text, $3 ::text) WHERE path_digest = $1",
            &[&digest, &new_owner, &db_pass],
        )
        .await
        .map(|_| ())
        .map_err(|e| DaoError::QueryFailed(format!("change owner: {}", e)))
}

/// Get the group associated with a file node.
/// Uses the file-level group if set, otherwise falls back to the owner's group.
pub async fn get_file_group(
    pool: &Pool,
    owner: String,
    file_group: Option<String>,
) -> Result<Option<String>, DaoError> {
    if file_group.is_some() {
        return Ok(file_group);
    }
    let client = conn(pool).await?;
    let row = client
        .query_opt(
            "SELECT group_name FROM users WHERE user_name = $1",
            &[&owner],
        )
        .await;
    match row {
        Ok(Some(row)) => Ok(row.try_get("group_name").unwrap_or(None)),
        Ok(None) => Ok(None),
        Err(e) => Err(DaoError::QueryFailed(format!("get file group: {}", e))),
    }
}

/// Update the group assignment for a file or directory.
pub async fn change_file_group(
    pool: &Pool,
    file_path: String,
    new_group: String,
) -> Result<(), DaoError> {
    let client = conn(pool).await?;
    let digest = path_digest(&file_path);
    client
        .execute(
            "UPDATE fnode SET file_group = $2 WHERE path_digest = $1",
            &[&digest, &new_group],
        )
        .await
        .map(|_| ())
        .map_err(|e| DaoError::QueryFailed(format!("change file group: {}", e)))
}
