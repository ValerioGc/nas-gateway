//! Sessions on the server:
//! The cookie carries an opaque token, the table the SHA-256 of it.
//! A session ends after a while without use, and in any case after a fixed time.

use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use std::{io::Read, time::Duration};

pub const IDLE: Duration = Duration::from_secs(30 * 60);
pub const ABSOLUTE: Duration = Duration::from_secs(12 * 60 * 60);
const TOUCH: Duration = Duration::from_secs(60);

fn millis(duration: Duration) -> i64 {
    i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
}

pub(crate) fn hashed(token: &str) -> String {
    Sha256::digest(token.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub(crate) fn new_token() -> std::io::Result<String> {
    let mut bytes = [0u8; 32];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

pub async fn open(db: &SqlitePool, username: &str) -> Result<String, String> {
    let token = tokio::task::spawn_blocking(new_token)
        .await
        .map_err(|error| error.to_string())?
        .map_err(|error| error.to_string())?;
    let now = crate::now_ms();
    sweep(db, now).await;
    sqlx::query(
        "INSERT INTO sessions (token_hash, username, created_at, seen_at) VALUES (?, ?, ?, ?)",
    )
    .bind(hashed(&token))
    .bind(username)
    .bind(now)
    .bind(now)
    .execute(db)
    .await
    .map_err(|error| error.to_string())?;
    Ok(token)
}

pub async fn user(db: &SqlitePool, token: &str) -> Option<String> {
    let key = hashed(token);
    let (username, created_at, seen_at): (String, i64, i64) =
        sqlx::query_as("SELECT username, created_at, seen_at FROM sessions WHERE token_hash = ?")
            .bind(&key)
            .fetch_optional(db)
            .await
            .ok()
            .flatten()?;

    let now = crate::now_ms();
    if now - seen_at > millis(IDLE) || now - created_at > millis(ABSOLUTE) {
        close(db, token).await;
        return None;
    }

    if now - seen_at > millis(TOUCH) {
        let _ = sqlx::query("UPDATE sessions SET seen_at = ? WHERE token_hash = ?")
            .bind(now)
            .bind(&key)
            .execute(db)
            .await;
    }
    Some(username)
}

pub async fn close(db: &SqlitePool, token: &str) {
    let _ = sqlx::query("DELETE FROM sessions WHERE token_hash = ?")
        .bind(hashed(token))
        .execute(db)
        .await;
}

async fn sweep(db: &SqlitePool, now: i64) {
    let _ = sqlx::query("DELETE FROM sessions WHERE seen_at < ? OR created_at < ?")
        .bind(now - millis(IDLE))
        .bind(now - millis(ABSOLUTE))
        .execute(db)
        .await;
}
