#![allow(dead_code)]

use nas_os_gateway::{account, Config};
use std::{
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

pub const USERNAME: &str = "admin";
pub const PASSWORD: &str = "long enough";

static NEXT: AtomicUsize = AtomicUsize::new(0);

pub struct Database(pub PathBuf);

impl Database {
    pub fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "nas-gateway-test-{}-{}.db",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let database = Self(path);
        database.remove();
        database
    }

    pub fn config(&self, launcher: String) -> Config {
        Config {
            launcher,
            ui: None,
            database: Some(self.0.clone()),
            pki: Some(self.pki()),
            tls: false,
            shares: None,
        }
    }

    /// Creates the account as the wizard does, with `nas-os-gateway account create`.
    pub async fn create_account(&self) {
        account::create(&self.config(String::new()), USERNAME, PASSWORD.to_owned())
            .await
            .expect("the account is created");
    }

    /// The authority of this gateway, in a directory of its own beside the database.
    pub fn pki(&self) -> PathBuf {
        self.0.with_extension("pki")
    }

    fn remove(&self) {
        let _ = std::fs::remove_file(self.0.with_extension("connection"));
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", self.0.display()));
        }
        let _ = std::fs::remove_dir_all(self.pki());
    }
}

impl Drop for Database {
    fn drop(&mut self) {
        self.remove();
    }
}
