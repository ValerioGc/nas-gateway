//! The account that signs in to the NAS

use argon2::{
    password_hash::{phc::PasswordHash, PasswordHasher, PasswordVerifier},
    Argon2,
};
use sqlx::SqlitePool;
use std::{sync::OnceLock, time::Duration};

static DECOY: OnceLock<String> = OnceLock::new();

fn decoy() -> &'static str {
    DECOY.get_or_init(|| {
        Argon2::default()
            .hash_password(b"no account has this password")
            .map(|hash| hash.to_string())
            .unwrap_or_default()
    })
}

pub fn valid(username: &str, password: &str) -> bool {
    valid_username(username) && valid_password(password)
}

pub fn valid_username(username: &str) -> bool {
    (3..=25).contains(&username.len())
        && username
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && username
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
        && !matches!(
            username.to_ascii_lowercase().replace('.', "_").as_str(),
            "nas" | "nas-os" | "root"
        )
}

pub fn valid_password(password: &str) -> bool {
    (8..=128).contains(&password.chars().count())
}

async fn hash(password: String) -> Result<String, String> {
    tokio::task::spawn_blocking(move || {
        Argon2::default()
            .hash_password(password.as_bytes())
            .map(|hash| hash.to_string())
    })
    .await
    .map_err(|error| error.to_string())?
    .map_err(|error| error.to_string())
}

pub async fn available_for_terminal(username: &str) -> bool {
    let name = username.to_ascii_lowercase().replace('.', "_");
    let Ok(Ok(output)) = tokio::time::timeout(
        Duration::from_secs(3),
        tokio::process::Command::new("getent")
            .args(["passwd", &name])
            .kill_on_drop(true)
            .output(),
    )
    .await
    else {
        return false;
    };
    if output.status.code() == Some(2) {
        return true;
    }
    output.status.success()
        && String::from_utf8_lossy(&output.stdout).split(':').nth(4) == Some("nas-os terminal")
}

pub async fn exists(db: &SqlitePool) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM accounts)")
        .fetch_one(db)
        .await
}

/// The name of the account of the NAS, the first one made.
pub async fn owner(db: &SqlitePool) -> Option<String> {
    sqlx::query_scalar("SELECT username FROM accounts ORDER BY created_at, rowid LIMIT 1")
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
}

pub async fn create(db: &SqlitePool, username: &str, password: String) -> Result<(), String> {
    let hash = hash(password).await?;
    sqlx::query("INSERT INTO accounts (username, password_hash, created_at) VALUES (?, ?, ?)")
        .bind(username)
        .bind(hash)
        .bind(crate::now_ms())
        .execute(db)
        .await
        .map_err(|error| error.to_string())?;
    Ok(())
}

pub async fn verify(db: &SqlitePool, username: &str, password: String) -> bool {
    let stored =
        sqlx::query_scalar::<_, String>("SELECT password_hash FROM accounts WHERE username = ?")
            .bind(username)
            .fetch_optional(db)
            .await
            .ok()
            .flatten();
    tokio::task::spawn_blocking(move || {
        let known = stored.is_some();
        let checked = stored.unwrap_or_else(|| decoy().to_owned());
        let matches = PasswordHash::new(&checked).is_ok_and(|hash| {
            Argon2::default()
                .verify_password(password.as_bytes(), &hash)
                .is_ok()
        });
        known && matches
    })
    .await
    .unwrap_or(false)
}

pub async fn set_password(
    db: &SqlitePool,
    username: &str,
    password: String,
    keep_session: Option<&str>,
) -> Result<(), String> {
    let hash = hash(password).await?;
    let mut transaction = db.begin().await.map_err(|error| error.to_string())?;
    sqlx::query("UPDATE accounts SET password_hash = ? WHERE username = ?")
        .bind(hash)
        .bind(username)
        .execute(&mut *transaction)
        .await
        .map_err(|error| error.to_string())?;
    sqlx::query("DELETE FROM sessions WHERE username = ? AND token_hash IS NOT ?")
        .bind(username)
        .bind(keep_session.map(super::sessions::hashed))
        .execute(&mut *transaction)
        .await
        .map_err(|error| error.to_string())?;
    transaction
        .commit()
        .await
        .map_err(|error| error.to_string())
}

/// Renames the account, with its sessions and its codes: who is signed in stays signed in.
pub async fn rename(db: &SqlitePool, from: &str, to: &str) -> Result<(), sqlx::Error> {
    let mut transaction = db.begin().await?;
    // The rows that name the account follow it inside the transaction, checked at its end.
    sqlx::query("PRAGMA defer_foreign_keys = ON")
        .execute(&mut *transaction)
        .await?;
    for table in [
        "UPDATE accounts SET username = ? WHERE username = ?",
        "UPDATE sessions SET username = ? WHERE username = ?",
        "UPDATE email_codes SET username = ? WHERE username = ?",
    ] {
        sqlx::query(table)
            .bind(to)
            .bind(from)
            .execute(&mut *transaction)
            .await?;
    }
    transaction.commit().await
}

/// The verified recovery address of the account.
pub async fn email(db: &SqlitePool, username: &str) -> Option<String> {
    sqlx::query_scalar::<_, Option<String>>("SELECT email FROM accounts WHERE username = ?")
        .bind(username)
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
        .flatten()
}

pub async fn set_email(
    db: &SqlitePool,
    username: &str,
    email: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE accounts SET email = ? WHERE username = ?")
        .bind(email)
        .bind(username)
        .execute(db)
        .await
        .map(|_| ())
}

/// Whether the password of the account may be reset with a code mailed to its recovery address.
pub async fn recovery(db: &SqlitePool, username: &str) -> bool {
    sqlx::query_scalar::<_, i64>("SELECT recovery FROM accounts WHERE username = ?")
        .bind(username)
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
        == Some(1)
}

pub async fn set_recovery(
    db: &SqlitePool,
    username: &str,
    enabled: bool,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE accounts SET recovery = ? WHERE username = ?")
        .bind(i64::from(enabled))
        .bind(username)
        .execute(db)
        .await
        .map(|_| ())
}

pub async fn reset_address(db: &SqlitePool, username: &str) -> Option<String> {
    sqlx::query_scalar::<_, Option<String>>(
        "SELECT email FROM accounts WHERE username = ? AND recovery = 1",
    )
    .bind(username)
    .fetch_optional(db)
    .await
    .ok()
    .flatten()
    .flatten()
}

pub async fn recovery_offered(db: &SqlitePool) -> bool {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM accounts WHERE recovery = 1 AND email IS NOT NULL)",
    )
    .fetch_one(db)
    .await
    .unwrap_or(false)
}
