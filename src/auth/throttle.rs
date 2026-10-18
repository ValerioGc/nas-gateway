//! Refused sign-ins, counted per address.
use std::{collections::HashMap, net::IpAddr, sync::Arc, time::Instant};
use tokio::sync::Mutex;

use super::policy::Policy;

#[derive(Clone, Default)]
pub struct Throttle(Arc<Mutex<HashMap<IpAddr, (u32, Instant)>>>);

impl Throttle {
    pub async fn locked(&self, address: IpAddr, policy: &Policy) -> bool {
        policy.enabled
            && self
                .0
                .lock()
                .await
                .get(&address)
                .is_some_and(|(count, last)| {
                    *count >= policy.attempts && last.elapsed() < policy.lockout()
                })
    }

    pub async fn failed(&self, address: IpAddr, policy: &Policy) {
        let mut failures = self.0.lock().await;
        failures.retain(|_, (_, last)| last.elapsed() < policy.lockout());
        let entry = failures.entry(address).or_insert((0, Instant::now()));
        entry.0 += 1;
        entry.1 = Instant::now();
    }

    pub async fn succeeded(&self, address: IpAddr) {
        self.0.lock().await.remove(&address);
    }
}
