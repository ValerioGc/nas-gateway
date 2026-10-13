//! The devices allowed in when mTLS is on, each known by the fingerprint of the certificate it was
//! given. A device keeps every certificate it had: the newest is the one it uses, the others are
//! revoked. A certificate is `pending` from its issue to the first sign-in made with it, then
//! `active`; renewing a device revokes what it had and issues a pending one.

use crate::{now_ms, pki::DeviceCredential};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

const SEEN_EVERY_MS: i64 = 60_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Icon {
    Tv,
    Desktop,
    Laptop,
    Phone,
    Projector,
}

impl Icon {
    fn id(self) -> &'static str {
        match self {
            Self::Tv => "tv",
            Self::Desktop => "desktop",
            Self::Laptop => "laptop",
            Self::Phone => "phone",
            Self::Projector => "projector",
        }
    }

    fn parse(id: &str) -> Self {
        match id {
            "tv" => Self::Tv,
            "laptop" => Self::Laptop,
            "phone" => Self::Phone,
            "projector" => Self::Projector,
            _ => Self::Desktop,
        }
    }
}

/// A device as somebody names it: what a new one is created with, and what an edit changes.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceInput {
    pub name: String,
    pub icon: Icon,
}

impl DeviceInput {
    /// The name, trimmed, when it is one.
    pub fn name(&self) -> Option<&str> {
        let name = self.name.trim();
        ((1..=60).contains(&name.chars().count()) && !name.chars().any(char::is_control))
            .then_some(name)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CertificateState {
    Pending,
    Active,
    Revoked,
}

impl CertificateState {
    fn parse(id: &str) -> Self {
        match id {
            "active" => Self::Active,
            "pending" => Self::Pending,
            _ => Self::Revoked,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Certificate {
    pub fingerprint: String,
    pub state: CertificateState,
    pub issued_at: i64,
    pub expires_at: i64,
    pub activated_at: Option<i64>,
    pub seen_at: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Device {
    pub id: i64,
    pub name: String,
    pub icon: Icon,
    pub created_at: i64,
    /// The newest certificate of the device.
    pub certificate: Option<Certificate>,
    /// The device of the connection that asked.
    pub current: bool,
}

/// What lets a connection in: its certificate is the device's, not revoked and not expired.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Admitted {
    pub device_id: i64,
    pub name: String,
    pub state: CertificateState,
}

type Row = (
    i64,
    String,
    String,
    i64,
    Option<String>,
    Option<String>,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    Option<i64>,
);

fn device(row: Row, current: Option<&str>) -> Device {
    let (
        id,
        name,
        icon,
        created_at,
        fingerprint,
        state,
        issued_at,
        expires_at,
        activated_at,
        seen_at,
    ) = row;
    let certificate = fingerprint.map(|fingerprint| Certificate {
        state: CertificateState::parse(state.as_deref().unwrap_or_default()),
        issued_at: issued_at.unwrap_or_default(),
        expires_at: expires_at.unwrap_or_default(),
        activated_at,
        seen_at,
        fingerprint,
    });
    Device {
        current: current.is_some()
            && certificate
                .as_ref()
                .is_some_and(|certificate| Some(certificate.fingerprint.as_str()) == current),
        id,
        name,
        icon: Icon::parse(&icon),
        created_at,
        certificate,
    }
}

/// Every device with its newest certificate, and what narrows or orders them.
macro_rules! select_devices {
    ($tail:literal) => {
        concat!(
            "SELECT d.id, d.name, d.icon, d.created_at, c.fingerprint, c.state,
                c.issued_at, c.expires_at, c.activated_at, c.seen_at
             FROM devices d
             LEFT JOIN device_certificates c ON c.fingerprint = (
                 SELECT fingerprint FROM device_certificates
                 WHERE device_id = d.id ORDER BY issued_at DESC, rowid DESC LIMIT 1) ",
            $tail
        )
    };
}

/// Every device, the newest first, with the one of the connection marked.
pub async fn list(db: &SqlitePool, current: Option<&str>) -> Result<Vec<Device>, sqlx::Error> {
    let rows: Vec<Row> = sqlx::query_as(select_devices!("ORDER BY d.created_at DESC, d.id DESC"))
        .fetch_all(db)
        .await?;
    Ok(rows.into_iter().map(|row| device(row, current)).collect())
}

pub async fn find(
    db: &SqlitePool,
    id: i64,
    current: Option<&str>,
) -> Result<Option<Device>, sqlx::Error> {
    let row: Option<Row> = sqlx::query_as(select_devices!("WHERE d.id = ?"))
        .bind(id)
        .fetch_optional(db)
        .await?;
    Ok(row.map(|row| device(row, current)))
}

async fn insert_certificate<'e>(
    executor: impl sqlx::SqliteExecutor<'e>,
    device_id: i64,
    credential: &DeviceCredential,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO device_certificates (fingerprint, device_id, state, issued_at, expires_at)
         VALUES (?, ?, 'pending', ?, ?)",
    )
    .bind(&credential.fingerprint)
    .bind(device_id)
    .bind(credential.issued_at * 1000)
    .bind(credential.expires_at * 1000)
    .execute(executor)
    .await?;
    Ok(())
}

/// A new device with its first certificate, pending until it signs in.
pub async fn create(
    db: &SqlitePool,
    name: &str,
    icon: Icon,
    credential: &DeviceCredential,
) -> Result<Device, sqlx::Error> {
    let mut transaction = db.begin().await?;
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO devices (name, icon, created_at) VALUES (?, ?, ?) RETURNING id",
    )
    .bind(name)
    .bind(icon.id())
    .bind(now_ms())
    .fetch_one(&mut *transaction)
    .await?;
    insert_certificate(&mut *transaction, id, credential).await?;
    transaction.commit().await?;
    find(db, id, None).await?.ok_or(sqlx::Error::RowNotFound)
}

/// A new name and icon. False when there is no such device.
pub async fn update(db: &SqlitePool, id: i64, name: &str, icon: Icon) -> Result<bool, sqlx::Error> {
    let changed = sqlx::query("UPDATE devices SET name = ?, icon = ? WHERE id = ?")
        .bind(name)
        .bind(icon.id())
        .bind(id)
        .execute(db)
        .await?;
    Ok(changed.rows_affected() > 0)
}

async fn revoke_all<'e>(
    executor: impl sqlx::SqliteExecutor<'e>,
    id: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE device_certificates SET state = 'revoked', revoked_at = ?
         WHERE device_id = ? AND state <> 'revoked'",
    )
    .bind(now_ms())
    .bind(id)
    .execute(executor)
    .await?;
    Ok(())
}

async fn exists(db: &SqlitePool, id: i64) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, i64>("SELECT 1 FROM devices WHERE id = ?")
        .bind(id)
        .fetch_optional(db)
        .await
        .map(|found| found.is_some())
}

/// The certificates of the device revoked, and a new one pending. False when there is no such
/// device.
pub async fn renew(
    db: &SqlitePool,
    id: i64,
    credential: &DeviceCredential,
) -> Result<bool, sqlx::Error> {
    if !exists(db, id).await? {
        return Ok(false);
    }
    let mut transaction = db.begin().await?;
    revoke_all(&mut *transaction, id).await?;
    insert_certificate(&mut *transaction, id, credential).await?;
    transaction.commit().await?;
    Ok(true)
}

/// Every certificate of the device revoked: it stays in the list, and no longer gets in.
pub async fn revoke(db: &SqlitePool, id: i64) -> Result<bool, sqlx::Error> {
    if !exists(db, id).await? {
        return Ok(false);
    }
    revoke_all(db, id).await?;
    Ok(true)
}

pub async fn remove(db: &SqlitePool, id: i64) -> Result<bool, sqlx::Error> {
    let removed = sqlx::query("DELETE FROM devices WHERE id = ?")
        .bind(id)
        .execute(db)
        .await?;
    Ok(removed.rows_affected() > 0)
}

/// The device a certificate lets in, when it does.
pub async fn admitted(db: &SqlitePool, fingerprint: &str) -> Option<Admitted> {
    let row: Option<(i64, String, String)> = sqlx::query_as(
        "SELECT d.id, d.name, c.state FROM device_certificates c JOIN devices d ON d.id = c.device_id
         WHERE c.fingerprint = ? AND c.state <> 'revoked' AND c.expires_at > ?",
    )
    .bind(fingerprint)
    .bind(now_ms())
    .fetch_optional(db)
    .await
    .ok()
    .flatten();
    row.map(|(device_id, name, state)| Admitted {
        device_id,
        name,
        state: CertificateState::parse(&state),
    })
}

/// When a certificate was last used, written at most once a minute.
pub async fn seen(db: &SqlitePool, fingerprint: &str) {
    let now = now_ms();
    let _ = sqlx::query(
        "UPDATE device_certificates SET seen_at = ?
         WHERE fingerprint = ? AND (seen_at IS NULL OR seen_at < ?)",
    )
    .bind(now)
    .bind(fingerprint)
    .bind(now - SEEN_EVERY_MS)
    .execute(db)
    .await;
}

/// A pending certificate becomes the device's active one at its first sign-in.
pub async fn activate(db: &SqlitePool, fingerprint: &str) {
    let now = now_ms();
    let _ = sqlx::query(
        "UPDATE device_certificates SET state = 'active', activated_at = ?, seen_at = ?
         WHERE fingerprint = ? AND state = 'pending' AND expires_at > ?",
    )
    .bind(now)
    .bind(now)
    .bind(fingerprint)
    .bind(now)
    .execute(db)
    .await;
}
