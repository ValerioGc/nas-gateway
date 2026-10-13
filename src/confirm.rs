//! The requests that ask for the password once more, on top of the session: what cannot be undone
//! or what carries the configuration out of the NAS.
//!
//! The browser sends the password to `POST /auth/confirm` and receives a code, good for one request
//! within a minute. The request that needs it carries the code in `x-nas-confirmation`; the gateway
//! takes it off, and forwards the request naming the user it checked in `x-nas-reauthenticated`,
//! which the launcher requires. The body travels untouched and the password never reaches the
//! launcher.

use crate::{
    auth::{accounts, policy, sessions, throttle::Throttle},
    entry::Failure,
    Sessions,
};
use axum::{
    http::{HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

pub(crate) const HEADER: &str = "x-nas-reauthenticated";
pub(crate) const CODE_HEADER: &str = "x-nas-confirmation";
const LIFETIME: Duration = Duration::from_secs(60);

/// What asks for the password: the factory reset, and the export and the import of the
/// configuration.
pub(crate) fn needed(method: &Method, path: &str) -> bool {
    matches!(
        (method.as_str(), path),
        ("POST", "/api/system/reset") | ("GET" | "POST", "/api/system/config")
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Confirmation {
    password: String,
}

/// Why a confirmation was refused, answered as `{ "error": ... }` with its status.
pub(crate) struct Refused(pub(crate) StatusCode, pub(crate) &'static str);

impl IntoResponse for Refused {
    fn into_response(self) -> Response {
        (self.0, Json(Failure { error: self.1 })).into_response()
    }
}

/// The password of `user` once more, counted with the refused sign-ins of the address. A wrong one
/// is a 403, not a 401: the session is still good, and a 401 would send the browser back to the
/// sign-in.
pub(crate) async fn checked(
    sessions: &Sessions,
    throttle: &Throttle,
    address: IpAddr,
    user: &str,
    password: String,
) -> Result<(), Refused> {
    if !(1..=128).contains(&password.chars().count()) {
        return Err(Refused(StatusCode::BAD_REQUEST, "the password is missing"));
    }
    let db = &sessions.0;
    let policy = policy::load(db).await;
    if throttle.locked(address, &policy).await {
        return Err(Refused(StatusCode::TOO_MANY_REQUESTS, "too many attempts"));
    }
    if !accounts::verify(db, user, password).await {
        throttle.failed(address, &policy).await;
        return Err(Refused(StatusCode::FORBIDDEN, "wrong password"));
    }
    throttle.succeeded(address).await;
    Ok(())
}

/// The codes given out and not used yet, in memory: a restart of the gateway forgets them, and the
/// page asks for the password again.
#[derive(Clone, Default)]
pub struct Codes(Arc<Mutex<HashMap<String, (String, Instant)>>>);

impl Codes {
    /// A code for one request of `user`, once the password is right ([`checked`]).
    pub(crate) async fn issue(
        &self,
        sessions: &Sessions,
        throttle: &Throttle,
        address: IpAddr,
        user: &str,
        input: Confirmation,
    ) -> Result<String, Refused> {
        checked(sessions, throttle, address, user, input.password).await?;

        let code = tokio::task::spawn_blocking(sessions::new_token)
            .await
            .ok()
            .and_then(Result::ok)
            .ok_or(Refused(
                StatusCode::SERVICE_UNAVAILABLE,
                "no confirmation could be made",
            ))?;
        let mut codes = self.0.lock().await;
        codes.retain(|_, (_, issued)| issued.elapsed() < LIFETIME);
        codes.insert(code.clone(), (user.to_owned(), Instant::now()));
        Ok(code)
    }

    /// The value of `x-nas-reauthenticated` for the code the request carried, when it is one this
    /// gateway gave to `user` within its lifetime. A code works once.
    pub(crate) async fn redeem(
        &self,
        code: Option<HeaderValue>,
        user: &str,
    ) -> Result<HeaderValue, Refused> {
        let issued = match code.as_ref().and_then(|code| code.to_str().ok()) {
            Some(code) => self.0.lock().await.remove(code),
            None => None,
        };
        let confirmed =
            issued.is_some_and(|(owner, issued)| owner == user && issued.elapsed() < LIFETIME);
        HeaderValue::from_str(user)
            .ok()
            .filter(|_| confirmed)
            .ok_or(Refused(StatusCode::FORBIDDEN, "confirm the password first"))
    }
}
