use deadpool_postgres::Pool;
use securefs_model::protocol::FNode;

use super::{conn, get_db_pass, path_digest, DaoError};

/// Persist a file or directory node.
pub async fn add_file(pool: &Pool, file: FNode) -> Result<String, DaoError> {
    let client = conn(pool).await?;
    let db_pass = get_db_pass();
    client
        .execute(
            "INSERT INTO fnode
    (name, path, owner, hash, parent, dir, u, g, o, children, encrypted_name,
     file_group, size_bytes, created_at, modified_at, link_target, path_digest,
     parent_digest)
    VALUES (
        pgp_sym_encrypt($1 ::text, $12 ::text),
        pgp_sym_encrypt($2 ::text, $12 ::text),
        pgp_sym_encrypt($3 ::text, $12 ::text),
        $4,
        pgp_sym_encrypt($5 ::text, $12 ::text),
        $6,
        pgp_sym_encrypt($7 ::text, $12 ::text),
        pgp_sym_encrypt($8 ::text, $12 ::text),
        pgp_sym_encrypt($9 ::text, $12 ::text),
        $10,
        $11,
        $13, $14, $15, $16, $17,
        hmac($2 ::text, $12 ::text, 'sha256'),
        hmac($5 ::text, $12 ::text, 'sha256'))",
            &[
                &file.name,
                &file.path,
                &file.owner,
                &file.hash,
                &file.parent,
                &file.dir,
                &file.u.to_string(),
                &file.g.to_string(),
                &file.o.to_string(),
                &file.children,
                &file.encrypted_name,
                &db_pass,
                &file.file_group,
                &file.size,
                &file.created_at,
                &file.modified_at,
                &file.link_target,
            ],
        )
        .await
        .map(|_| file.name)
        .map_err(|e| DaoError::QueryFailed(format!("add file: {}", e)))
}

/// Update the stored hash for a file at `path`.
pub async fn update_hash(
    pool: &Pool,
    path: String,
    _file_name: String,
    hash: String,
) -> Result<String, DaoError> {
    let client = conn(pool).await?;
    let digest = path_digest(&path);
    client
        .execute(
            "UPDATE fnode SET hash = $1 WHERE path_digest = $2",
            &[&hash, &digest],
        )
        .await
        .map(|_| path)
        .map_err(|e| DaoError::QueryFailed(format!("update hash: {}", e)))
}

/// Update a file's hash inside a transaction with an advisory lock.
/// Prevents concurrent writes to the same file.
pub async fn update_hash_locked(pool: &Pool, path: String, hash: String) -> Result<(), DaoError> {
    let mut client = conn(pool).await?;
    let digest = path_digest(&path);
    let tx = client
        .transaction()
        .await
        .map_err(|e| DaoError::QueryFailed(format!("begin tx: {}", e)))?;
    // Look up fnode id for the advisory lock key
    let row = tx
        .query_opt("SELECT id FROM fnode WHERE path_digest = $1", &[&digest])
        .await
        .map_err(|e| DaoError::QueryFailed(format!("lock lookup: {}", e)))?;
    let id: i64 = match row {
        Some(r) => r.get("id"),
        None => return Err(DaoError::NotFound),
    };
    // Non-blocking advisory lock scoped to this transaction
    let lock_row = tx
        .query_one("SELECT pg_try_advisory_xact_lock($1) AS acquired", &[&id])
        .await
        .map_err(|e| DaoError::QueryFailed(format!("advisory lock: {}", e)))?;
    let acquired: bool = lock_row.get("acquired");
    if !acquired {
        return Err(DaoError::Conflict(
            "file is being written by another session".into(),
        ));
    }
    tx.execute(
        "UPDATE fnode SET hash = $1 WHERE path_digest = $2",
        &[&hash, &digest],
    )
    .await
    .map_err(|e| DaoError::QueryFailed(format!("update hash: {}", e)))?;
    tx.commit()
        .await
        .map_err(|e| DaoError::QueryFailed(format!("commit: {}", e)))?;
    Ok(())
}

/// Append a child entry to the parent's `children` array.
pub async fn add_file_to_parent(
    pool: &Pool,
    parent_path: String,
    new_f_node_name: String,
) -> Result<(), DaoError> {
    let client = conn(pool).await?;
    let db_pass = get_db_pass();
    let digest = path_digest(&parent_path);
    client
        .execute(
            "UPDATE fnode SET children =
        ARRAY_APPEND(children,
            pgp_sym_encrypt($1 ::text, $3 ::text)::text
        )
        WHERE path_digest = $2",
            &[&new_f_node_name, &digest, &db_pass],
        )
        .await
        .map(|_| ())
        .map_err(|e| DaoError::QueryFailed(format!("add to parent: {}", e)))
}

/// Fetch a decrypted `FNode` by path.
pub async fn get_f_node(pool: &Pool, path: String) -> Result<Option<FNode>, DaoError> {
    let client = conn(pool).await?;
    let db_pass = get_db_pass();
    let digest = path_digest(&path);
    let e = client.query_opt("SELECT
        id,
        pgp_sym_decrypt(name ::bytea, $2 ::text) AS name,
        pgp_sym_decrypt(path ::bytea, $2 ::text) AS path,
        pgp_sym_decrypt(owner ::bytea, $2 ::text) AS owner,
        hash,
        pgp_sym_decrypt(parent ::bytea, $2 ::text) AS parent,
        dir,
        CAST (pgp_sym_decrypt(u ::bytea, $2 ::text) AS SMALLINT) AS u,
        CAST (pgp_sym_decrypt(g ::bytea, $2 ::text) AS SMALLINT) AS g,
        CAST (pgp_sym_decrypt(o ::bytea, $2 ::text) AS SMALLINT) AS o,
        (SELECT array_agg(pgp_sym_decrypt(child ::bytea, $2::text)) FROM unnest(children) AS child) AS children,
        encrypted_name,
        file_group,
        size_bytes,
        created_at,
        modified_at,
        link_target
    FROM fnode WHERE path_digest = $1",
        &[&digest, &db_pass]).await;
    match e {
        Ok(Some(row)) => {
            let fnode = FNode {
                id: row.get(0),
                name: row.get(1),
                path: row.get(2),
                owner: row.try_get(3).unwrap_or("".to_string()),
                hash: row.get(4),
                parent: row.get(5),
                dir: row.get(6),
                u: row.get(7),
                g: row.get(8),
                o: row.get(9),
                children: row.try_get(10).unwrap_or(vec![]),
                encrypted_name: row.get(11),
                size: row.try_get("size_bytes").unwrap_or(0),
                created_at: row.try_get("created_at").unwrap_or(0),
                modified_at: row.try_get("modified_at").unwrap_or(0),
                file_group: row.try_get("file_group").unwrap_or(None),
                link_target: row.try_get("link_target").unwrap_or(None),
            };
            Ok(Some(fnode))
        }
        Ok(None) => Ok(None),
        Err(e) => Err(DaoError::QueryFailed(format!("get fnode: {}", e))),
    }
}

/// Fetch all direct children of a directory in a single query.
pub async fn get_children(pool: &Pool, parent_path: String) -> Result<Vec<FNode>, DaoError> {
    let client = conn(pool).await?;
    let db_pass = get_db_pass();
    let digest = path_digest(&parent_path);
    let rows = client.query("SELECT
        id,
        pgp_sym_decrypt(name ::bytea, $2 ::text) AS name,
        pgp_sym_decrypt(path ::bytea, $2 ::text) AS path,
        pgp_sym_decrypt(owner ::bytea, $2 ::text) AS owner,
        hash, pgp_sym_decrypt(parent ::bytea, $2 ::text) AS parent, dir,
        CAST (pgp_sym_decrypt(u ::bytea, $2 ::text) AS SMALLINT) AS u,
        CAST (pgp_sym_decrypt(g ::bytea, $2 ::text) AS SMALLINT) AS g,
        CAST (pgp_sym_decrypt(o ::bytea, $2 ::text) AS SMALLINT) AS o,
        (SELECT array_agg(pgp_sym_decrypt(child ::bytea, $2::text)) FROM unnest(children) AS child) AS children,
        encrypted_name,
        file_group,
        size_bytes,
        created_at,
        modified_at,
        link_target
    FROM fnode WHERE parent_digest = $1",
        &[&digest, &db_pass]).await
        .map_err(|e| DaoError::QueryFailed(format!("get children: {}", e)))?;
    let nodes = rows
        .iter()
        .map(|row| FNode {
            id: row.get(0),
            name: row.get(1),
            path: row.get(2),
            owner: row.try_get(3).unwrap_or("".to_string()),
            hash: row.get(4),
            parent: row.get(5),
            dir: row.get(6),
            u: row.get(7),
            g: row.get(8),
            o: row.get(9),
            children: row.try_get(10).unwrap_or(vec![]),
            encrypted_name: row.get(11),
            size: row.try_get("size_bytes").unwrap_or(0),
            created_at: row.try_get("created_at").unwrap_or(0),
            modified_at: row.try_get("modified_at").unwrap_or(0),
            file_group: row.try_get("file_group").unwrap_or(None),
            link_target: row.try_get("link_target").unwrap_or(None),
        })
        .collect();
    Ok(nodes)
}

/// Fetch all nodes under a path prefix in a single query (for find).
pub async fn get_subtree(pool: &Pool, path_prefix: String) -> Result<Vec<FNode>, DaoError> {
    let client = conn(pool).await?;
    let db_pass = get_db_pass();
    let rows = client.query("SELECT
        id,
        pgp_sym_decrypt(name ::bytea, $2 ::text) AS name,
        pgp_sym_decrypt(path ::bytea, $2 ::text) AS path,
        pgp_sym_decrypt(owner ::bytea, $2 ::text) AS owner,
        hash, pgp_sym_decrypt(parent ::bytea, $2 ::text) AS parent, dir,
        CAST (pgp_sym_decrypt(u ::bytea, $2 ::text) AS SMALLINT) AS u,
        CAST (pgp_sym_decrypt(g ::bytea, $2 ::text) AS SMALLINT) AS g,
        CAST (pgp_sym_decrypt(o ::bytea, $2 ::text) AS SMALLINT) AS o,
        (SELECT array_agg(pgp_sym_decrypt(child ::bytea, $2::text)) FROM unnest(children) AS child) AS children,
        encrypted_name,
        file_group,
        size_bytes,
        created_at,
        modified_at,
        link_target
    FROM fnode WHERE left(pgp_sym_decrypt(path ::bytea, $2 ::text), length($1) + 1) = $1 || '/'",
        &[&path_prefix, &db_pass]).await
        .map_err(|e| DaoError::QueryFailed(format!("get subtree: {}", e)))?;
    let nodes = rows
        .iter()
        .map(|row| FNode {
            id: row.get(0),
            name: row.get(1),
            path: row.get(2),
            owner: row.try_get(3).unwrap_or("".to_string()),
            hash: row.get(4),
            parent: row.get(5),
            dir: row.get(6),
            u: row.get(7),
            g: row.get(8),
            o: row.get(9),
            children: row.try_get(10).unwrap_or(vec![]),
            encrypted_name: row.get(11),
            size: row.try_get("size_bytes").unwrap_or(0),
            created_at: row.try_get("created_at").unwrap_or(0),
            modified_at: row.try_get("modified_at").unwrap_or(0),
            file_group: row.try_get("file_group").unwrap_or(None),
            link_target: row.try_get("link_target").unwrap_or(None),
        })
        .collect();
    Ok(nodes)
}

/// Delete every `fnode` whose path matches the provided prefix.
pub async fn delete_path(pool: &Pool, file_path: String) -> Result<(), DaoError> {
    let client = conn(pool).await?;
    let db_pass = get_db_pass();
    client
        .execute(
            "DELETE FROM fnode
             WHERE pgp_sym_decrypt(path::bytea, $2::text) = $1
                OR left(pgp_sym_decrypt(path::bytea, $2::text), length($1) + 1) = $1 || '/'",
            &[&file_path, &db_pass],
        )
        .await
        .map(|_| ())
        .map_err(|e| DaoError::QueryFailed(format!("delete path: {}", e)))
}

/// Rename/move a node and its subtree atomically: rewrite the node's path and
/// every descendant's path and parent pointer, update the node's name, and fix
/// the parent's children array — all in one transaction so a partial failure
/// rolls back instead of corrupting the tree.
pub async fn rename_node(
    pool: &Pool,
    parent_path: String,
    old_path: String,
    new_path: String,
    old_name: String,
    new_name: String,
) -> Result<(), DaoError> {
    let mut client = conn(pool).await?;
    let db_pass = get_db_pass();
    let new_path_digest = path_digest(&new_path);
    let parent_digest = path_digest(&parent_path);
    let tx = client
        .transaction()
        .await
        .map_err(|e| DaoError::QueryFailed(format!("begin tx: {}", e)))?;

    tx.execute(
        "UPDATE fnode SET
             path = pgp_sym_encrypt(
                 $2 || substring(pgp_sym_decrypt(path::bytea, $3::text) from length($1) + 1),
                 $3::text),
             path_digest = hmac(
                 $2 || substring(pgp_sym_decrypt(path::bytea, $3::text) from length($1) + 1),
                 $3::text, 'sha256')
         WHERE pgp_sym_decrypt(path::bytea, $3::text) = $1
            OR left(pgp_sym_decrypt(path::bytea, $3::text), length($1) + 1) = $1 || '/'",
        &[&old_path, &new_path, &db_pass],
    )
    .await
    .map_err(|e| DaoError::QueryFailed(format!("rename path: {}", e)))?;

    // Parent is stored encrypted; rewrite it for descendants (already moved
    // under new_path by the previous statement), decrypting/re-encrypting.
    tx.execute(
        "UPDATE fnode SET parent = pgp_sym_encrypt(
             $2 || substring(pgp_sym_decrypt(parent::bytea, $3::text) from length($1) + 1),
             $3::text),
             parent_digest = hmac(
                 $2 || substring(pgp_sym_decrypt(parent::bytea, $3::text) from length($1) + 1),
                 $3::text, 'sha256')
         WHERE left(pgp_sym_decrypt(path::bytea, $3::text), length($2) + 1) = $2 || '/'",
        &[&old_path, &new_path, &db_pass],
    )
    .await
    .map_err(|e| DaoError::QueryFailed(format!("rename parent: {}", e)))?;

    tx.execute(
        "UPDATE fnode SET name = pgp_sym_encrypt($2::text, $3::text), encrypted_name = $2
         WHERE path_digest = $1",
        &[&new_path_digest, &new_name, &db_pass],
    )
    .await
    .map_err(|e| DaoError::QueryFailed(format!("rename name: {}", e)))?;

    tx.execute(
        "UPDATE fnode SET children =
            (SELECT array_agg(pgp_sym_encrypt(child1::text, $3::text)) FROM unnest
                (ARRAY_REMOVE((SELECT array_agg(pgp_sym_decrypt(child ::bytea, $3::text)) FROM unnest(children) AS child), $1)
            ) AS child1)
            WHERE path_digest = $2",
        &[&old_name, &parent_digest, &db_pass],
    )
    .await
    .map_err(|e| DaoError::QueryFailed(format!("rename detach: {}", e)))?;

    tx.execute(
        "UPDATE fnode SET children =
        ARRAY_APPEND(children, pgp_sym_encrypt($1 ::text, $3 ::text)::text)
        WHERE path_digest = $2",
        &[&new_name, &parent_digest, &db_pass],
    )
    .await
    .map_err(|e| DaoError::QueryFailed(format!("rename attach: {}", e)))?;

    tx.commit()
        .await
        .map_err(|e| DaoError::QueryFailed(format!("commit: {}", e)))
}

/// Detach a node from its parent and delete it (plus any subtree) atomically.
pub async fn delete_node(
    pool: &Pool,
    parent_path: String,
    name: String,
    path: String,
) -> Result<(), DaoError> {
    let mut client = conn(pool).await?;
    let db_pass = get_db_pass();
    let parent_digest = path_digest(&parent_path);
    let tx = client
        .transaction()
        .await
        .map_err(|e| DaoError::QueryFailed(format!("begin tx: {}", e)))?;

    tx.execute(
        "UPDATE fnode SET children =
            (SELECT array_agg(pgp_sym_encrypt(child1::text, $3::text)) FROM unnest
                (ARRAY_REMOVE((SELECT array_agg(pgp_sym_decrypt(child ::bytea, $3::text)) FROM unnest(children) AS child), $1)
            ) AS child1)
            WHERE path_digest = $2",
        &[&name, &parent_digest, &db_pass],
    )
    .await
    .map_err(|e| DaoError::QueryFailed(format!("delete detach: {}", e)))?;

    tx.execute(
        "DELETE FROM fnode
         WHERE pgp_sym_decrypt(path::bytea, $2::text) = $1
            OR left(pgp_sym_decrypt(path::bytea, $2::text), length($1) + 1) = $1 || '/'",
        &[&path, &db_pass],
    )
    .await
    .map_err(|e| DaoError::QueryFailed(format!("delete rows: {}", e)))?;

    tx.commit()
        .await
        .map_err(|e| DaoError::QueryFailed(format!("commit: {}", e)))
}

/// Recursively copy a file or directory tree.
pub async fn copy_recursive(
    pool: &Pool,
    src_root: String,
    dst_root: String,
    owner: String,
) -> Result<(), DaoError> {
    let mut stack = vec![(src_root, dst_root)];

    while let Some((src, dst)) = stack.pop() {
        if let Ok(Some(node)) = get_f_node(pool, src.clone()).await {
            let path_obj = std::path::Path::new(&dst);
            let name = path_obj
                .file_name()
                .unwrap_or_default()
                .to_str()
                .unwrap_or_default()
                .to_string();
            let parent_opt = path_obj.parent().map(|p| p.to_str().unwrap_or("/"));
            let parent = match parent_opt {
                Some("") | None => "/".to_string(),
                Some(p) => p.to_string(),
            };

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            let new_node = FNode {
                id: -1,
                name: name.clone(),
                path: dst.clone(),
                owner: owner.clone(),
                hash: node.hash.clone(),
                parent: parent.clone(),
                dir: node.dir,
                u: node.u,
                g: node.g,
                o: node.o,
                children: vec![],
                encrypted_name: name.clone(),
                size: node.size,
                created_at: now,
                modified_at: now,
                file_group: node.file_group.clone(),
                link_target: None,
            };

            add_file(pool, new_node)
                .await
                .map_err(|e| DaoError::QueryFailed(format!("copy {}: {}", dst, e)))?;
            add_file_to_parent(pool, parent, name)
                .await
                .map_err(|e| DaoError::QueryFailed(format!("copy link {}: {}", dst, e)))?;

            if node.dir {
                for child in node.children {
                    let child_src = if src == "/" {
                        format!("/{}", child)
                    } else {
                        format!("{}/{}", src, child)
                    };
                    let child_dst = if dst == "/" {
                        format!("/{}", child)
                    } else {
                        format!("{}/{}", dst, child)
                    };
                    stack.push((child_src, child_dst));
                }
            } else {
                let src_storage = format!("storage{}", src);
                let dst_storage = format!("storage{}", dst);
                tokio::fs::copy(&src_storage, &dst_storage)
                    .await
                    .map_err(|e| DaoError::QueryFailed(format!("fs copy: {}", e)))?;
            }

            if node.dir {
                let dst_storage = format!("storage{}", dst);
                tokio::fs::create_dir_all(&dst_storage)
                    .await
                    .map_err(|e| DaoError::QueryFailed(format!("fs mkdir: {}", e)))?;
            }
        }
    }
    Ok(())
}
