//! The codes sent by mail: one proves a new recovery address is the user's, one resets the
//! password. Six digits, good for a quarter of an hour and five tries, stored only as a SHA-256.

use super::sessions::hashed;
use sqlx::SqlitePool;
use std::{io::Read, time::Duration};

pub const LIFETIME: Duration = Duration::from_secs(15 * 60);
/// A new code for the same purpose is not sent again before this much time.
pub const RESEND_AFTER: Duration = Duration::from_secs(60);
const ATTEMPTS: i64 = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    Verify,
    Reset,
}

impl Purpose {
    pub fn id(self) -> &'static str {
        match self {
            Self::Verify => "verify",
            Self::Reset => "reset",
        }
    }
}

fn millis(duration: Duration) -> i64 {
    i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
}

fn new_code() -> std::io::Result<String> {
    let mut bytes = [0u8; 4];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(format!("{:06}", u32::from_le_bytes(bytes) % 1_000_000))
}

/// A plain `local@domain` address, the only form the mails use.
pub fn valid_email(value: &str) -> bool {
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    value.len() <= 254
        && !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !domain.contains('@')
        && value
            .chars()
            .all(|c| c.is_ascii_graphic() && !"<>()[],;:\"\\".contains(c))
}

/// Whether a code for this purpose went out less than [`RESEND_AFTER`] ago.
pub async fn recently_sent(db: &SqlitePool, purpose: Purpose, username: &str) -> bool {
    let expires: Option<i64> =
        sqlx::query_scalar("SELECT expires_at FROM email_codes WHERE purpose = ? AND username = ?")
            .bind(purpose.id())
            .bind(username)
            .fetch_optional(db)
            .await
            .ok()
            .flatten();
    expires
        .is_some_and(|expires| expires - crate::now_ms() > millis(LIFETIME) - millis(RESEND_AFTER))
}

/// A new code for `email`, replacing the one before it.
pub async fn issue(
    db: &SqlitePool,
    purpose: Purpose,
    username: &str,
    email: &str,
) -> Result<String, String> {
    let code = tokio::task::spawn_blocking(new_code)
        .await
        .map_err(|error| error.to_string())?
        .map_err(|error| error.to_string())?;
    sqlx::query(
        "INSERT INTO email_codes (purpose, username, email, code_hash, expires_at, attempts)
         VALUES (?, ?, ?, ?, ?, 0)
         ON CONFLICT (purpose, username) DO UPDATE SET
             email = excluded.email,
             code_hash = excluded.code_hash,
             expires_at = excluded.expires_at,
             attempts = 0",
    )
    .bind(purpose.id())
    .bind(username)
    .bind(email)
    .bind(hashed(&code))
    .bind(crate::now_ms() + millis(LIFETIME))
    .execute(db)
    .await
    .map_err(|error| error.to_string())?;
    Ok(code)
}

/// The address the code was sent to, when `code` is the right one and still good. A right code
/// works once; a wrong one counts, and the fifth wrong one ends the code.
pub async fn redeem(
    db: &SqlitePool,
    purpose: Purpose,
    username: &str,
    code: &str,
) -> Option<String> {
    let (email, code_hash, expires_at, attempts): (String, String, i64, i64) = sqlx::query_as(
        "SELECT email, code_hash, expires_at, attempts FROM email_codes
         WHERE purpose = ? AND username = ?",
    )
    .bind(purpose.id())
    .bind(username)
    .fetch_optional(db)
    .await
    .ok()
    .flatten()?;
    let forget = || async {
        let _ = sqlx::query("DELETE FROM email_codes WHERE purpose = ? AND username = ?")
            .bind(purpose.id())
            .bind(username)
            .execute(db)
            .await;
    };
    if expires_at < crate::now_ms() || attempts >= ATTEMPTS {
        forget().await;
        return None;
    }
    if hashed(code.trim()) == code_hash {
        forget().await;
        return Some(email);
    }
    let _ = sqlx::query(
        "UPDATE email_codes SET attempts = attempts + 1 WHERE purpose = ? AND username = ?",
    )
    .bind(purpose.id())
    .bind(username)
    .execute(db)
    .await;
    None
}
