use crate::{
    auth::{
        accounts, devices,
        login::{self, LoginInput, LoginOutput},
        policy::{self, Policy},
        sessions,
        throttle::Throttle,
    },
    confirm::{Codes, Confirmation},
    tls::Peer,
    Config, Sessions,
};
use axum::response::{IntoResponse, Response};
use axum::{
    body::Bytes,
    extract::{ConnectInfo, State},
    http::{header, HeaderMap, StatusCode},
    Extension, Json,
};
use serde::Serialize;
use std::{net::IpAddr, sync::Arc};

const COOKIE_NAME: &str = "nas_session";

#[derive(Serialize)]
pub(crate) struct SessionOutput {
    authenticated: bool,
    username: String,
}

fn cookie(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .map(str::trim)
        .find_map(|part| part.strip_prefix(&format!("{COOKIE_NAME}=")))
        .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

/// The token of the session the request carries, to keep it open when the others close.
pub(crate) fn session_token(headers: &HeaderMap) -> Option<&str> {
    cookie(headers)
}

pub(crate) fn without_session(headers: &mut HeaderMap) {
    let Some(kept) = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(|cookies| {
            cookies
                .split(';')
                .map(str::trim)
                .filter(|part| !part.starts_with(&format!("{COOKIE_NAME}=")))
                .collect::<Vec<_>>()
                .join("; ")
        })
    else {
        return;
    };
    headers.remove(header::COOKIE);
    if let Ok(value) = header::HeaderValue::from_str(&kept) {
        if !kept.is_empty() {
            headers.insert(header::COOKIE, value);
        }
    }
}

pub(crate) fn keep_session(headers: &mut HeaderMap) {
    let kept: Vec<header::HeaderValue> = headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter(|cookie| {
            cookie
                .to_str()
                .is_ok_and(|text| !text.trim_start().starts_with(&format!("{COOKIE_NAME}=")))
        })
        .cloned()
        .collect();
    headers.remove(header::SET_COOKIE);
    for cookie in kept {
        headers.append(header::SET_COOKIE, cookie);
    }
}

pub async fn login(
    State(sessions): State<Sessions>,
    Extension(throttle): Extension<Throttle>,
    Extension(config): Extension<Arc<Config>>,
    peer: Option<Extension<ConnectInfo<Peer>>>,
    body: Bytes,
) -> Result<([(header::HeaderName, String); 2], Json<LoginOutput>), StatusCode> {
    let Json(input) = Json::<LoginInput>::from_bytes(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    if !login::valid(&input) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let address = address(peer.as_ref());
    let db = &sessions.0;
    let policy = policy::load(db).await;
    if throttle.locked(address, &policy).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    let username = input.username.trim().to_owned();
    if !accounts::verify(db, &username, input.password).await {
        throttle.failed(address, &policy).await;
        return Err(StatusCode::UNAUTHORIZED);
    }
    throttle.succeeded(address).await;

    let token = sessions::open(db, &username)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    // The first sign-in with a new certificate is what makes it the device's.
    let device = match certificate(peer.as_ref()) {
        Some(fingerprint) => {
            devices::activate(db, fingerprint).await;
            devices::admitted(db, fingerprint)
                .await
                .map(|admitted| admitted.name)
        }
        None => None,
    };
    // The same gateway serves HTTP and HTTPS. Only the actual TLS connection gets Secure cookies.
    let encrypted = peer
        .as_ref()
        .map_or(config.tls, |Extension(ConnectInfo(peer))| peer.encrypted);
    let secure = if encrypted { "; Secure" } else { "" };
    Ok((
        [
            (
                header::SET_COOKIE,
                format!(
                    "{COOKIE_NAME}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={}{secure}",
                    sessions::ABSOLUTE.as_secs()
                ),
            ),
            (header::CACHE_CONTROL, "no-store".to_owned()),
        ],
        Json(LoginOutput { username, device }),
    ))
}

#[derive(Serialize)]
pub(crate) struct ConfirmOutput {
    code: String,
}

pub(crate) fn address(peer: Option<&Extension<ConnectInfo<Peer>>>) -> IpAddr {
    peer.map_or(
        IpAddr::from([127, 0, 0, 1]),
        |Extension(ConnectInfo(peer))| peer.address.ip(),
    )
}

/// The fingerprint of the device certificate the connection showed.
fn certificate(peer: Option<&Extension<ConnectInfo<Peer>>>) -> Option<&str> {
    peer.and_then(|Extension(ConnectInfo(peer))| peer.certificate.as_deref())
}

/// The password once more, for one request that needs it (`confirm.rs`)
pub async fn confirm(
    State(sessions): State<Sessions>,
    Extension(throttle): Extension<Throttle>,
    Extension(codes): Extension<Codes>,
    peer: Option<Extension<ConnectInfo<Peer>>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(user) = signed_in(&sessions, &headers).await else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Ok(Json(input)) = Json::<Confirmation>::from_bytes(&body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    match codes
        .issue(&sessions, &throttle, address(peer.as_ref()), &user, input)
        .await
    {
        Ok(code) => (
            [(header::CACHE_CONTROL, "no-store")],
            Json(ConfirmOutput { code }),
        )
            .into_response(),
        Err(refused) => refused.into_response(),
    }
}

pub(crate) async fn signed_in(sessions: &Sessions, headers: &HeaderMap) -> Option<String> {
    sessions::user(&sessions.0, cookie(headers)?).await
}

pub async fn session(
    State(sessions): State<Sessions>,
    headers: HeaderMap,
) -> Result<([(header::HeaderName, &'static str); 1], Json<SessionOutput>), StatusCode> {
    let username = signed_in(&sessions, &headers)
        .await
        .ok_or(StatusCode::UNAUTHORIZED)?;
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(SessionOutput {
            authenticated: true,
            username,
        }),
    ))
}

pub async fn logout(
    State(sessions): State<Sessions>,
    headers: HeaderMap,
) -> (StatusCode, [(header::HeaderName, String); 2]) {
    if let Some(token) = cookie(&headers) {
        sessions::close(&sessions.0, token).await;
    }
    (
        StatusCode::NO_CONTENT,
        [
            (
                header::SET_COOKIE,
                format!("{COOKIE_NAME}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"),
            ),
            (header::CACHE_CONTROL, "no-store".to_owned()),
        ],
    )
}

pub async fn policy(
    State(sessions): State<Sessions>,
    headers: HeaderMap,
) -> Result<Json<Policy>, StatusCode> {
    signed_in(&sessions, &headers)
        .await
        .ok_or(StatusCode::UNAUTHORIZED)?;
    Ok(Json(policy::load(&sessions.0).await))
}

pub async fn save_policy(
    State(sessions): State<Sessions>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Policy>, StatusCode> {
    signed_in(&sessions, &headers)
        .await
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let Json(input) = Json::<Policy>::from_bytes(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    if !input.valid() {
        return Err(StatusCode::BAD_REQUEST);
    }
    policy::save(&sessions.0, input)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok(Json(input))
}
