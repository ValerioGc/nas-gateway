//! The one account of the NAS, created by the wizard on the machine.
//!
//! The wizard runs `nas-os-gateway account create` as root, before the gateway
//! listens, with the name and the password on the input. The rules are the sign-in's own, and the
//! name must be free for the user of the terminal, which the wizard creates with the same name.

use crate::{auth::accounts, store, Config};
use std::fmt;

/// Why the account was not created
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountRefused {
    Invalid,
    /// The NAS has its account already
    Exists,
    /// The database cannot be opened or written
    Unavailable(String),
}

impl AccountRefused {
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Invalid => 2,
            Self::Exists => 3,
            Self::Unavailable(_) => 1,
        }
    }
}

impl fmt::Display for AccountRefused {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid => formatter.write_str(
                "the name or the password is not valid, or the name belongs to the system",
            ),
            Self::Exists => formatter.write_str("the NAS has its account already"),
            Self::Unavailable(reason) => write!(formatter, "the database is unavailable: {reason}"),
        }
    }
}

/// Creates the account in the database of `config`, once.
pub async fn create(
    config: &Config,
    username: &str,
    password: String,
) -> Result<(), AccountRefused> {
    let username = username.trim();
    if !accounts::valid(username, &password) || !accounts::available_for_terminal(username).await {
        return Err(AccountRefused::Invalid);
    }
    let Some(path) = config.database.as_deref() else {
        return Err(AccountRefused::Unavailable(
            "no database: set GATEWAY_DB_PATH or run under systemd with StateDirectory".into(),
        ));
    };
    let db = store::open(Some(path))
        .await
        .map_err(|error| AccountRefused::Unavailable(error.to_string()))?;
    let created = match accounts::exists(&db).await {
        Ok(true) => Err(AccountRefused::Exists),
        Ok(false) => accounts::create(&db, username, password)
            .await
            .map_err(AccountRefused::Unavailable),
        Err(error) => Err(AccountRefused::Unavailable(error.to_string())),
    };
    db.close().await;
    created
}
