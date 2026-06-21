use deadpool_postgres::Pool;

use super::{conn, DaoError};

// Current KEK generation that new DEK wraps are stamped with. The crypto_meta
// row is seeded to 1 by migration V3; a missing row defaults to 1.
pub async fn get_kek_generation(pool: &Pool) -> Result<u8, DaoError> {
    let client = conn(pool).await?;
    let row = client
        .query_opt("SELECT kek_generation FROM crypto_meta WHERE id = 1", &[])
        .await
        .map_err(|e| DaoError::QueryFailed(format!("get kek_generation: {}", e)))?;
    let generation: i16 = row.map(|r| r.get::<_, i16>(0)).unwrap_or(1);
    u8::try_from(generation)
        .map_err(|_| DaoError::ParseError(format!("kek_generation {} out of range", generation)))
}

// Record the current KEK generation after a rotation. New writes wrap under it
// once the server restarts with the matching master.
pub async fn set_kek_generation(pool: &Pool, generation: u8) -> Result<(), DaoError> {
    let client = conn(pool).await?;
    client
        .execute(
            "UPDATE crypto_meta SET kek_generation = $1 WHERE id = 1",
            &[&i16::from(generation)],
        )
        .await
        .map(|_| ())
        .map_err(|e| DaoError::QueryFailed(format!("set kek_generation: {}", e)))
}
