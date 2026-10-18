//! How many refused sign-ins lock an address, and for how long.

use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Policy {
    pub enabled: bool,
    pub attempts: u32,
    pub lock_minutes: u32,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            enabled: true,
            attempts: 5,
            lock_minutes: 1,
        }
    }
}

impl Policy {
    pub fn valid(&self) -> bool {
        (1..=20).contains(&self.attempts) && (1..=1440).contains(&self.lock_minutes)
    }

    pub fn lockout(&self) -> Duration {
        Duration::from_secs(u64::from(self.lock_minutes) * 60)
    }
}

/// The saved policy, or the default one when the table cannot be read.
pub async fn load(db: &SqlitePool) -> Policy {
    sqlx::query_as::<_, (bool, u32, u32)>(
        "SELECT enabled, attempts, lock_minutes FROM sign_in_policy WHERE id = 1",
    )
    .fetch_optional(db)
    .await
    .ok()
    .flatten()
    .map_or_else(Policy::default, |(enabled, attempts, lock_minutes)| {
        Policy {
            enabled,
            attempts,
            lock_minutes,
        }
    })
}

pub async fn save(db: &SqlitePool, policy: Policy) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO sign_in_policy (id, enabled, attempts, lock_minutes) VALUES (1, ?, ?, ?)
         ON CONFLICT (id) DO UPDATE SET enabled = excluded.enabled,
             attempts = excluded.attempts, lock_minutes = excluded.lock_minutes",
    )
    .bind(policy.enabled)
    .bind(policy.attempts)
    .bind(policy.lock_minutes)
    .execute(db)
    .await
    .map(|_| ())
}
