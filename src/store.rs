//! Gateway DB

use sqlx::{
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
    SqlitePool,
};
use std::{
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

const COPY_NAME: &str = "copies/gateway.db";
const COPY_EVERY: Duration = Duration::from_secs(24 * 60 * 60);

pub async fn open(path: Option<&Path>) -> Result<SqlitePool, sqlx::Error> {
    let pool = match path {
        Some(path) => {
            if let Some(directory) = path.parent() {
                tokio::fs::create_dir_all(directory).await?;
            }
            let options = SqliteConnectOptions::new()
                .filename(path)
                .create_if_missing(true)
                .journal_mode(SqliteJournalMode::Wal)
                .synchronous(SqliteSynchronous::Full)
                .foreign_keys(true)
                .busy_timeout(Duration::from_secs(5));
            SqlitePoolOptions::new().connect_with(options).await?
        }

        None => {
            SqlitePoolOptions::new()
                .max_connections(1)
                .min_connections(1)
                .idle_timeout(None)
                .max_lifetime(None)
                .connect_with(SqliteConnectOptions::from_str("sqlite::memory:")?.foreign_keys(true))
                .await?
        }
    };
    sqlx::migrate!("./migrations").run(&pool).await?;
    Ok(pool)
}

/// A consistent copy of the database at `target`, made while the gateway keeps working: `VACUUM
/// INTO` reads one snapshot of the database and its write-ahead log, which copying the files would
/// not. Written aside and renamed, so `target` is never half a copy.
pub async fn copy(pool: &SqlitePool, target: &Path) -> Result<(), sqlx::Error> {
    let mut aside = target.as_os_str().to_owned();
    aside.push(".new");
    let aside = PathBuf::from(aside);
    if let Some(directory) = target.parent() {
        tokio::fs::create_dir_all(directory).await?;
    }
    match tokio::fs::remove_file(&aside).await {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error.into()),
        _ => {}
    }
    sqlx::query("VACUUM INTO ?")
        .bind(aside.to_string_lossy().into_owned())
        .execute(pool)
        .await?;
    tokio::fs::rename(&aside, target).await?;
    Ok(())
}

pub fn copy_target(path: &Path) -> Option<PathBuf> {
    path.parent().map(|directory| directory.join(COPY_NAME))
}

pub async fn keep_copy(pool: SqlitePool, target: PathBuf) {
    let mut every = tokio::time::interval(COPY_EVERY);
    loop {
        every.tick().await;
        if let Err(error) = copy(&pool, &target).await {
            eprintln!("the copy of the database was not made: {error}");
        }
    }
}
