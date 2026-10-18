//! The devices allowed in when mTLS is on, each known by the fingerprint of the certificate it was
//! given. Renewing a device revokes what it had and issues a pending one.

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

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceInput {
    pub name: String,
    pub icon: Icon,
}

impl DeviceInput {
    pub fn name(&self) -> Option<&str> {
        valid_name(&self.name)
    }
}

/// A name of a device, trimmed, when it is one.
pub fn valid_name(name: &str) -> Option<&str> {
    let name = name.trim();
    ((1..=60).contains(&name.chars().count()) && !name.chars().any(char::is_control))
        .then_some(name)
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
    /// A computer of the sync client.
    pub sync: bool,
    /// A phone of the NAS Mobile app.
    pub mobile: bool,
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
    Option<String>,
    bool,
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
        sync_id,
        mobile,
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
        sync: sync_id.is_some(),
        mobile,
    }
}

/// Every device with its newest certificate, and what narrows or orders them.
macro_rules! select_devices {
    ($tail:literal) => {
        concat!(
            "SELECT d.id, d.name, d.icon, d.created_at, c.fingerprint, c.state,
                c.issued_at, c.expires_at, c.activated_at, c.seen_at, d.sync_id, d.mobile
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

pub async fn create_client(
    db: &SqlitePool,
    name: &str,
    sync_id: &str,
    credential: &DeviceCredential,
) -> Result<Device, sqlx::Error> {
    let mut transaction = db.begin().await?;
    sqlx::query("DELETE FROM devices WHERE sync_id = ?")
        .bind(sync_id)
        .execute(&mut *transaction)
        .await?;
    sqlx::query("DELETE FROM sync_revocations WHERE sync_id = ?")
        .bind(sync_id)
        .execute(&mut *transaction)
        .await?;
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO devices (name, icon, created_at, sync_id) VALUES (?, 'desktop', ?, ?)
         RETURNING id",
    )
    .bind(name)
    .bind(now_ms())
    .bind(sync_id)
    .fetch_one(&mut *transaction)
    .await?;
    insert_certificate(&mut *transaction, id, credential).await?;
    transaction.commit().await?;
    find(db, id, None).await?.ok_or(sqlx::Error::RowNotFound)
}

/// A phone of the NAS Mobile app with its first certificate, pending until its first request.
pub async fn create_mobile(
    db: &SqlitePool,
    name: &str,
    credential: &DeviceCredential,
) -> Result<Device, sqlx::Error> {
    let mut transaction = db.begin().await?;
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO devices (name, icon, created_at, mobile) VALUES (?, 'phone', ?, 1)
         RETURNING id",
    )
    .bind(name)
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

/// The engine of a computer of the sync client, kept to be dropped by the sync application.
async fn queue_revocation<'e>(
    executor: impl sqlx::SqliteExecutor<'e>,
    id: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO sync_revocations (sync_id, since)
         SELECT sync_id, ? FROM devices WHERE id = ? AND sync_id IS NOT NULL
         ON CONFLICT (sync_id) DO NOTHING",
    )
    .bind(now_ms())
    .bind(id)
    .execute(executor)
    .await?;
    Ok(())
}

/// Every certificate of the device revoked
pub async fn revoke(db: &SqlitePool, id: i64) -> Result<bool, sqlx::Error> {
    if !exists(db, id).await? {
        return Ok(false);
    }
    let mut transaction = db.begin().await?;
    revoke_all(&mut *transaction, id).await?;
    queue_revocation(&mut *transaction, id).await?;
    transaction.commit().await?;
    Ok(true)
}

pub async fn remove(db: &SqlitePool, id: i64) -> Result<bool, sqlx::Error> {
    let mut transaction = db.begin().await?;
    queue_revocation(&mut *transaction, id).await?;
    let removed = sqlx::query("DELETE FROM devices WHERE id = ?")
        .bind(id)
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok(removed.rows_affected() > 0)
}

/// The engines of revoked computers still to drop.
pub async fn pending_revocations(db: &SqlitePool) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar("SELECT sync_id FROM sync_revocations ORDER BY since")
        .fetch_all(db)
        .await
}

/// The sync application dropped the engine of a revoked computer.
pub async fn revocation_done(db: &SqlitePool, sync_id: &str) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM sync_revocations WHERE sync_id = ?")
        .bind(sync_id)
        .execute(db)
        .await?;
    Ok(())
}

/// What a computer of the sync client is let in as: its engine, and whether its certificate was
/// never used (only then may it pair).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Client {
    pub sync_id: String,
    pub state: CertificateState,
}

/// The computer of the sync client a certificate lets in, when it does.
pub async fn client(db: &SqlitePool, fingerprint: &str) -> Option<Client> {
    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT d.sync_id, c.state FROM device_certificates c JOIN devices d ON d.id = c.device_id
         WHERE c.fingerprint = ? AND c.state <> 'revoked' AND c.expires_at > ?
           AND d.sync_id IS NOT NULL",
    )
    .bind(fingerprint)
    .bind(now_ms())
    .fetch_optional(db)
    .await
    .ok()
    .flatten();
    row.map(|(sync_id, state)| Client {
        sync_id,
        state: CertificateState::parse(&state),
    })
}

/// Whether a certificate lets in a phone of the NAS Mobile app, and how far it got
pub async fn mobile(db: &SqlitePool, fingerprint: &str) -> Option<CertificateState> {
    let state: Option<String> = sqlx::query_scalar(
        "SELECT c.state FROM device_certificates c JOIN devices d ON d.id = c.device_id
         WHERE c.fingerprint = ? AND c.state <> 'revoked' AND c.expires_at > ? AND d.mobile = 1",
    )
    .bind(fingerprint)
    .bind(now_ms())
    .fetch_optional(db)
    .await
    .ok()
    .flatten();
    state.map(|state| CertificateState::parse(&state))
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
