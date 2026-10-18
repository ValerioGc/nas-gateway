pub mod account;
mod account_controller;
mod auth {
    pub mod accounts;
    pub mod devices;
    pub mod email_codes;
    pub mod login;
    pub mod mtls;
    pub mod policy;
    pub mod sessions;
    pub mod throttle;
}
pub mod base64;
mod certificate_controller;
mod client_controller;
mod confirm;
pub mod connection;
mod controller;
mod device_controller;
pub mod discovery;
mod entry;
pub mod first_device;
mod mailer;
mod mobile_controller;
pub mod pki;
mod proxy;
mod router;
mod shares;
mod store;
pub mod tls;
pub use store::copy as copy_database;
mod ui;

use sqlx::SqlitePool;
use std::{path::PathBuf, sync::Arc};

/// The database of the gateway
#[derive(Clone)]
struct Sessions(SqlitePool);

#[derive(Clone, Debug)]
pub struct Config {
    pub launcher: String,
    pub ui: Option<PathBuf>,
    pub database: Option<PathBuf>,
    pub pki: Option<PathBuf>,
    pub tls: bool,
    pub shares: Option<PathBuf>,
}

impl Config {
    pub fn from_env() -> Self {
        let database = std::env::var_os("GATEWAY_DB_PATH")
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("STATE_DIRECTORY")
                    .map(|directory| PathBuf::from(directory).join("gateway.db"))
            })
            .or_else(|| {
                cfg!(debug_assertions)
                    .then(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("data/gateway.db"))
            });
        let pki = std::env::var_os("GATEWAY_PKI_DIR")
            .map(PathBuf::from)
            .or_else(|| {
                database
                    .as_deref()
                    .and_then(std::path::Path::parent)
                    .map(|directory| directory.join("pki"))
            });
        Self {
            launcher: std::env::var("GATEWAY_LAUNCHER")
                .unwrap_or_else(|_| "127.0.0.1:3000".to_owned()),
            ui: std::env::var_os("GATEWAY_UI_DIR").map(PathBuf::from),
            database,
            pki,
            tls: std::env::var_os("GATEWAY_TLS_PORT").is_some(),
            shares: std::env::var_os("GATEWAY_SHARE_PASSWORD_SOCKET").map(PathBuf::from),
        }
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
        })
}

type Failure = Box<dyn std::error::Error + Send + Sync>;

/// The authority of `config`, created the first time.
pub fn authority(config: &Config) -> Result<Option<Arc<pki::Pki>>, Failure> {
    match config.pki.as_deref() {
        Some(directory) => Ok(Some(Arc::new(pki::Pki::open(directory)?))),
        None => Ok(None),
    }
}

/// The gateway of the NAS, which also keeps a copy of its database beside it. `authority` is the
/// one the HTTPS listener answers with: the settings change its certificate in place.
pub async fn app(
    config: Config,
    authority: Option<Arc<pki::Pki>>,
    connection: Arc<connection::Connection>,
) -> Result<axum::Router, Failure> {
    let Some(target) = config.database.as_deref().and_then(store::copy_target) else {
        return Err(
            "no database: set GATEWAY_DB_PATH or run under systemd with StateDirectory".into(),
        );
    };
    let db = store::open(config.database.as_deref()).await?;
    tokio::spawn(store::keep_copy(db.clone(), target));
    tokio::spawn(client_controller::keep_revoking(
        db.clone(),
        config.launcher.clone(),
    ));
    Ok(router::routes(
        Sessions(db),
        Arc::new(config),
        authority,
        connection,
    ))
}

pub async fn app_with(config: Config) -> Result<axum::Router, Failure> {
    let connection = connection::Connection::load(&config, 443)?;
    let authority = authority(&config)?;
    let db = store::open(config.database.as_deref()).await?;
    Ok(router::routes(
        Sessions(db),
        Arc::new(config),
        authority,
        connection,
    ))
}

/// Used only when optional LAN discovery is enabled, after the web listener binds.
pub async fn is_configured(config: &Config) -> Result<bool, Failure> {
    let db = store::open(config.database.as_deref()).await?;
    Ok(auth::accounts::exists(&db).await?)
}
