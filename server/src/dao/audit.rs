use deadpool_postgres::Pool;
use tokio_postgres::Transaction;

use super::{conn, DaoError};

// Serialize audit-log appends (and the one-time backfill) so the hash chain
// stays a single linear sequence even across stateless instances. Transaction-
// scoped, released on commit/rollback. Distinct from the bootstrap/migration keys.
const AUDIT_CHAIN_LOCK: i64 = 776_655_003;

// Folded into every entry hash so an audit digest can never collide with another
// BLAKE3 use in the system (file content hash, Merkle root).
const CHAIN_DOMAIN: &[u8] = b"securefs-audit-v1";

// Predecessor hash for the first entry.
const GENESIS_PREV: [u8; 32] = [0u8; 32];

/// A persisted audit entry's position in the tamper-evident chain.
pub struct AuditChainEntry {
    pub seq: i64,
    pub entry_hash: [u8; 32],
}

/// Outcome of walking the audit chain end to end.
pub enum ChainStatus {
    /// Every link verified; `head_hash` is the chain head an operator can pin.
    Intact {
        entries: u64,
        head_seq: i64,
        head_hash: [u8; 32],
    },
    /// The chain failed at `seq`; `reason` says how (altered row, gap, bad link).
    Broken { seq: i64, reason: String },
}

// Length-prefix a field: u32-BE length then bytes, so field boundaries are
// unambiguous ("a"+"bc" hashes differently from "ab"+"c").
fn push_field(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(bytes);
}

// The five logged content fields of an audit entry. Grouping them keeps the
// hash signature small and makes call sites self-documenting.
struct AuditFields<'a> {
    event: &'a str,
    username: &'a str,
    resource: &'a str,
    result: &'a str,
    ip: Option<&'a str>,
}

// Canonical bytes hashed for one entry. prev_hash is fixed-width so it needs no
// length prefix; numbers are big-endian; the ip presence byte keeps NULL and ""
// distinct.
fn chain_hash(prev_hash: &[u8; 32], seq: i64, ts: i64, fields: &AuditFields) -> [u8; 32] {
    let mut buf = Vec::with_capacity(128);
    push_field(&mut buf, CHAIN_DOMAIN);
    buf.extend_from_slice(prev_hash);
    buf.extend_from_slice(&seq.to_be_bytes());
    buf.extend_from_slice(&ts.to_be_bytes());
    push_field(&mut buf, fields.event.as_bytes());
    push_field(&mut buf, fields.username.as_bytes());
    push_field(&mut buf, fields.resource.as_bytes());
    push_field(&mut buf, fields.result.as_bytes());
    match fields.ip {
        Some(s) => {
            buf.push(1);
            push_field(&mut buf, s.as_bytes());
        }
        None => buf.push(0),
    }
    *blake3::hash(&buf).as_bytes()
}

fn to_hash(bytes: &[u8]) -> Result<[u8; 32], DaoError> {
    bytes.try_into().map_err(|_| {
        DaoError::ParseError(format!("audit hash is {} bytes, expected 32", bytes.len()))
    })
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// Current chain head (seq, entry_hash) under the held lock, or genesis if empty.
async fn chain_head(tx: &Transaction<'_>) -> Result<(i64, [u8; 32]), DaoError> {
    let row = tx
        .query_opt(
            "SELECT seq, entry_hash FROM audit_log
             WHERE seq IS NOT NULL ORDER BY seq DESC LIMIT 1",
            &[],
        )
        .await
        .map_err(|e| DaoError::QueryFailed(format!("audit head: {}", e)))?;
    match row {
        Some(r) => {
            let seq: i64 = r.get(0);
            let h: Vec<u8> = r.get(1);
            Ok((seq, to_hash(&h)?))
        }
        None => Ok((0, GENESIS_PREV)),
    }
}

/// Append an audit entry as the next link in the tamper-evident hash chain. An
/// advisory lock serializes appends so the chain stays linear across instances.
pub async fn append_audit_log(
    pool: &Pool,
    event: &str,
    username: &str,
    resource: &str,
    result: &str,
    ip: Option<&str>,
) -> Result<AuditChainEntry, DaoError> {
    let mut client = conn(pool).await?;
    let tx = client
        .transaction()
        .await
        .map_err(|e| DaoError::QueryFailed(format!("begin audit tx: {}", e)))?;
    tx.execute("SELECT pg_advisory_xact_lock($1)", &[&AUDIT_CHAIN_LOCK])
        .await
        .map_err(|e| DaoError::QueryFailed(format!("audit lock: {}", e)))?;

    let (prev_seq, prev_hash) = chain_head(&tx).await?;
    let seq = prev_seq + 1;
    let ts = now_unix();
    let entry_hash = chain_hash(
        &prev_hash,
        seq,
        ts,
        &AuditFields {
            event,
            username,
            resource,
            result,
            ip,
        },
    );
    let prev_b: &[u8] = &prev_hash;
    let entry_b: &[u8] = &entry_hash;

    tx.execute(
        "INSERT INTO audit_log
            (ts, event, username, resource, result, ip, seq, prev_hash, entry_hash)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        &[
            &ts, &event, &username, &resource, &result, &ip, &seq, &prev_b, &entry_b,
        ],
    )
    .await
    .map_err(|e| DaoError::QueryFailed(format!("insert audit: {}", e)))?;

    tx.commit()
        .await
        .map_err(|e| DaoError::QueryFailed(format!("commit audit: {}", e)))?;
    Ok(AuditChainEntry { seq, entry_hash })
}

/// Chain any audit rows that predate the hash chain (seq IS NULL), oldest first,
/// continuing from the current head. One-time on the first upgrade boot, a cheap
/// no-op afterward. Runs under the chain lock so it cannot race appends.
pub async fn backfill_audit_chain(pool: &Pool) -> Result<u64, DaoError> {
    let mut client = conn(pool).await?;
    let tx = client
        .transaction()
        .await
        .map_err(|e| DaoError::QueryFailed(format!("begin backfill tx: {}", e)))?;
    tx.execute("SELECT pg_advisory_xact_lock($1)", &[&AUDIT_CHAIN_LOCK])
        .await
        .map_err(|e| DaoError::QueryFailed(format!("audit lock: {}", e)))?;

    let rows = tx
        .query(
            "SELECT id, ts, event, username, resource, result, ip
             FROM audit_log WHERE seq IS NULL ORDER BY id ASC",
            &[],
        )
        .await
        .map_err(|e| DaoError::QueryFailed(format!("scan unchained: {}", e)))?;
    if rows.is_empty() {
        return Ok(0);
    }

    let (mut prev_seq, mut prev_hash) = chain_head(&tx).await?;
    let mut count = 0u64;
    for r in &rows {
        let id: i64 = r.get(0);
        let ts: i64 = r.get(1);
        let event: String = r.get(2);
        let username: String = r.get(3);
        let resource: String = r.get(4);
        let result: String = r.get(5);
        let ip: Option<String> = r.get(6);
        let seq = prev_seq + 1;
        let entry_hash = chain_hash(
            &prev_hash,
            seq,
            ts,
            &AuditFields {
                event: &event,
                username: &username,
                resource: &resource,
                result: &result,
                ip: ip.as_deref(),
            },
        );
        let prev_b: &[u8] = &prev_hash;
        let entry_b: &[u8] = &entry_hash;
        tx.execute(
            "UPDATE audit_log SET seq = $1, prev_hash = $2, entry_hash = $3 WHERE id = $4",
            &[&seq, &prev_b, &entry_b, &id],
        )
        .await
        .map_err(|e| DaoError::QueryFailed(format!("chain backfill: {}", e)))?;
        prev_seq = seq;
        prev_hash = entry_hash;
        count += 1;
    }

    tx.commit()
        .await
        .map_err(|e| DaoError::QueryFailed(format!("commit backfill: {}", e)))?;
    Ok(count)
}

/// Walk the whole chain in seq order and report whether it is intact. Pages so
/// memory stays bounded on a large log. The log is append-only, so a concurrent
/// append (a new higher seq at the tail) never disturbs the verified prefix.
pub async fn verify_audit_chain(pool: &Pool) -> Result<ChainStatus, DaoError> {
    const PAGE: i64 = 1024;
    let client = conn(pool).await?;

    let mut after: i64 = 0;
    let mut expected_seq: i64 = 1;
    let mut expected_prev: [u8; 32] = GENESIS_PREV;
    let mut entries: u64 = 0;
    let mut head_hash: [u8; 32] = GENESIS_PREV;

    loop {
        let rows = client
            .query(
                "SELECT seq, ts, event, username, resource, result, ip, prev_hash, entry_hash
                 FROM audit_log WHERE seq IS NOT NULL AND seq > $1
                 ORDER BY seq ASC LIMIT $2",
                &[&after, &PAGE],
            )
            .await
            .map_err(|e| DaoError::QueryFailed(format!("verify scan: {}", e)))?;
        if rows.is_empty() {
            break;
        }
        let page_len = rows.len();
        for r in &rows {
            let seq: i64 = r.get(0);
            if seq != expected_seq {
                return Ok(ChainStatus::Broken {
                    seq,
                    reason: format!(
                        "broken sequence: expected seq {}, found {}",
                        expected_seq, seq
                    ),
                });
            }
            let ts: i64 = r.get(1);
            let event: String = r.get(2);
            let username: String = r.get(3);
            let resource: String = r.get(4);
            let result: String = r.get(5);
            let ip: Option<String> = r.get(6);
            let stored_prev: Vec<u8> = r.get(7);
            let stored_entry: Vec<u8> = r.get(8);

            if stored_prev.as_slice() != expected_prev {
                return Ok(ChainStatus::Broken {
                    seq,
                    reason: "prev_hash does not match the previous entry_hash".into(),
                });
            }
            let computed = chain_hash(
                &expected_prev,
                seq,
                ts,
                &AuditFields {
                    event: &event,
                    username: &username,
                    resource: &resource,
                    result: &result,
                    ip: ip.as_deref(),
                },
            );
            if stored_entry.as_slice() != computed {
                return Ok(ChainStatus::Broken {
                    seq,
                    reason: "entry_hash does not match the row contents (row was altered)".into(),
                });
            }

            expected_prev = computed;
            head_hash = computed;
            expected_seq = seq + 1;
            after = seq;
            entries += 1;
        }
        if (page_len as i64) < PAGE {
            break;
        }
    }

    Ok(ChainStatus::Intact {
        entries,
        head_seq: expected_seq - 1,
        head_hash,
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    fn fields<'a>(
        event: &'a str,
        username: &'a str,
        resource: &'a str,
        result: &'a str,
        ip: Option<&'a str>,
    ) -> AuditFields<'a> {
        AuditFields {
            event,
            username,
            resource,
            result,
            ip,
        }
    }

    #[test]
    fn chain_hash_is_deterministic_and_binds_every_field() {
        let base = chain_hash(
            &GENESIS_PREV,
            1,
            100,
            &fields("LOGIN", "alice", "/x", "ok", None),
        );
        assert_eq!(
            base,
            chain_hash(
                &GENESIS_PREV,
                1,
                100,
                &fields("LOGIN", "alice", "/x", "ok", None)
            ),
            "same inputs hash the same"
        );

        // The predecessor link participates, so reordering breaks the hash.
        let mut other_prev = GENESIS_PREV;
        other_prev[0] = 1;
        assert_ne!(
            base,
            chain_hash(
                &other_prev,
                1,
                100,
                &fields("LOGIN", "alice", "/x", "ok", None)
            )
        );

        // seq and ts participate.
        assert_ne!(
            base,
            chain_hash(
                &GENESIS_PREV,
                2,
                100,
                &fields("LOGIN", "alice", "/x", "ok", None)
            )
        );
        assert_ne!(
            base,
            chain_hash(
                &GENESIS_PREV,
                1,
                101,
                &fields("LOGIN", "alice", "/x", "ok", None)
            )
        );

        // Field boundaries are unambiguous: shifting a byte across a boundary
        // changes the hash even though the concatenation would be identical.
        assert_ne!(
            chain_hash(&GENESIS_PREV, 1, 100, &fields("AB", "C", "/x", "ok", None)),
            chain_hash(&GENESIS_PREV, 1, 100, &fields("A", "BC", "/x", "ok", None))
        );

        // A missing ip differs from an empty ip.
        assert_ne!(
            chain_hash(&GENESIS_PREV, 1, 100, &fields("E", "u", "/x", "ok", None)),
            chain_hash(
                &GENESIS_PREV,
                1,
                100,
                &fields("E", "u", "/x", "ok", Some(""))
            )
        );
    }
}
