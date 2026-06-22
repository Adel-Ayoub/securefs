//! Offline audit-chain verification. Walks the tamper-evident hash chain and
//! validates the signed tree head, then exits - zero if intact, non-zero if the
//! chain was altered, reordered, or truncated, so monitoring or CI can gate on
//! it. Run against the live database:
//!
//!   DATA_KEY=<master> securefs-server verify-audit
//!
//! DATA_KEY must be the master the heads were sealed under; without it the
//! checkpoint seal will not validate.

use securefs_server::config::NetConfig;
use securefs_server::dao::{self, ChainStatus};

use crate::build_pool;
use crate::crypto;

pub async fn run() -> Result<(), String> {
    let net = NetConfig::from_env().map_err(|e| e.to_string())?;
    let db_pass = dao::get_db_pass();
    let pool = build_pool(&net, &db_pass)?;

    let seal_key = crypto::audit_seal_key();
    let key: &[u8; 32] = &seal_key;
    match dao::verify_audit_chain(&pool, Some(key))
        .await
        .map_err(|e| e.to_string())?
    {
        ChainStatus::Intact {
            entries,
            head_seq,
            head_hash,
        } => {
            println!(
                "audit chain intact: {} entries, head seq {}, head {}",
                entries,
                head_seq,
                hex::encode(head_hash)
            );
            Ok(())
        }
        ChainStatus::Broken { seq, reason } => {
            Err(format!("audit chain BROKEN at seq {}: {}", seq, reason))
        }
    }
}
