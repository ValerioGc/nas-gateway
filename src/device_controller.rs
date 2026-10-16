//! The routes of mTLS: the authority to trust, the switch, and the devices with their
//! certificates. They answer the console only, signed in. Issuing a certificate and turning mTLS
//! on need the password again (`confirm.rs`): a stolen session must not be enough to let a new
//! device in. What would shut out the device asking, turning mTLS on without a certificate or
//! revoking its own, is refused.

use crate::{
    auth::{devices, mtls},
    base64, client_controller,
    confirm::{self, Refused},
    controller::signed_in,
    pki::{DeviceCredential, Pki},
    Config, Sessions,
};
use axum::{
    extract::{Path, Request, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// The authority of the NAS, when this gateway has one: none in a development copy without a
/// state directory.
#[derive(Clone, Default)]
pub struct Authority(pub Option<Arc<Pki>>);

pub(crate) type Answer = Result<Response, Refused>;

pub(crate) const UNAVAILABLE: Refused =
    Refused(StatusCode::SERVICE_UNAVAILABLE, "devices are unavailable");
const INVALID: Refused = Refused(StatusCode::BAD_REQUEST, "invalid request");
const NOT_FOUND: Refused = Refused(StatusCode::NOT_FOUND, "no such device");
const OWN_DEVICE: Refused = Refused(
    StatusCode::CONFLICT,
    "this is the device in use: act on it from another one",
);

/// What a handler needs of a request before it reads the body: the headers and the fingerprint
/// of the device certificate of the connection. Taken apart first, since the body cannot be held
/// across a wait.
pub(crate) fn parts(request: &Request) -> (HeaderMap, Option<String>) {
    (request.headers().clone(), mtls::certificate(request))
}

/// The signed-in user.
async fn caller(sessions: &Sessions, headers: &HeaderMap) -> Result<String, Refused> {
    signed_in(sessions, headers)
        .await
        .ok_or(Refused(StatusCode::UNAUTHORIZED, "sign in first"))
}

/// The signed-in user, who also confirmed the password for this one request.
pub(crate) async fn confirmed(
    sessions: &Sessions,
    codes: &confirm::Codes,
    headers: &HeaderMap,
) -> Result<String, Refused> {
    let user = caller(sessions, headers).await?;
    codes
        .redeem(headers.get(confirm::CODE_HEADER).cloned(), &user)
        .await?;
    Ok(user)
}

pub(crate) async fn json<T: serde::de::DeserializeOwned>(request: Request) -> Result<T, Refused> {
    let bytes = axum::body::to_bytes(request.into_body(), 4096)
        .await
        .map_err(|_| INVALID)?;
    Json::<T>::from_bytes(&bytes)
        .map(|Json(value)| value)
        .map_err(|_| INVALID)
}

/// The id of a device in a path.
fn device_id(raw: &str) -> Result<i64, Refused> {
    raw.parse::<i64>()
        .ok()
        .filter(|id| *id > 0)
        .ok_or(Refused(StatusCode::BAD_REQUEST, "invalid device"))
}

fn named(input: &devices::DeviceInput) -> Result<String, Refused> {
    input
        .name()
        .map(str::to_owned)
        .ok_or(Refused(StatusCode::BAD_REQUEST, "invalid device name"))
}

/// The authority, to install as trusted: open to every browser, which needs it before anything.
pub async fn ca(Extension(authority): Extension<Authority>) -> Response {
    match authority.0 {
        Some(pki) => (
            [
                (header::CONTENT_TYPE, "application/x-x509-ca-cert"),
                (
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"nas-os-ca.crt\"",
                ),
            ],
            pki.ca_pem().to_owned(),
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MtlsState {
    enabled: bool,
    available: bool,
    /// The device of this connection, when it showed a certificate of one.
    current: Option<devices::Device>,
}

/// The device whose certificate the connection showed, when it lets one in.
async fn current_device(sessions: &Sessions, current: Option<&str>) -> Option<devices::Device> {
    let admitted = devices::admitted(&sessions.0, current?).await?;
    devices::find(&sessions.0, admitted.device_id, current)
        .await
        .ok()
        .flatten()
}

async fn state(sessions: &Sessions, authority: &Authority, current: Option<&str>) -> Response {
    Json(MtlsState {
        enabled: mtls::enabled(&sessions.0).await,
        available: authority.0.is_some(),
        current: current_device(sessions, current).await,
    })
    .into_response()
}

pub async fn mtls_state(
    State(sessions): State<Sessions>,
    Extension(authority): Extension<Authority>,
    request: Request,
) -> Answer {
    let (headers, current) = parts(&request);
    caller(&sessions, &headers).await?;
    Ok(state(&sessions, &authority, current.as_deref()).await)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Switch {
    enabled: bool,
}

pub async fn save_mtls(
    State(sessions): State<Sessions>,
    Extension(authority): Extension<Authority>,
    Extension(codes): Extension<confirm::Codes>,
    request: Request,
) -> Answer {
    let (headers, current) = parts(&request);
    confirmed(&sessions, &codes, &headers).await?;
    let Switch { enabled } = json(request).await?;
    if enabled {
        if authority.0.is_none() {
            return Err(UNAVAILABLE);
        }
        if current_device(&sessions, current.as_deref())
            .await
            .is_none()
        {
            return Err(Refused(
                StatusCode::CONFLICT,
                "this device has no certificate of the NAS: install one first",
            ));
        }
    }
    mtls::set(&sessions.0, enabled)
        .await
        .map_err(|_| UNAVAILABLE)?;
    Ok(state(&sessions, &authority, current.as_deref()).await)
}

pub async fn list(State(sessions): State<Sessions>, request: Request) -> Answer {
    let (headers, current) = parts(&request);
    caller(&sessions, &headers).await?;
    let found = devices::list(&sessions.0, current.as_deref())
        .await
        .map_err(|_| UNAVAILABLE)?;
    Ok(Json(found).into_response())
}

/// What a device downloads: the PKCS#12 file and its password, shown once.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Credential {
    file: String,
    file_name: String,
    password: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Issued {
    device: devices::Device,
    credential: Credential,
}

/// The name of the file of a device: its name in lower-case letters and digits.
pub fn file_name(name: &str) -> String {
    let safe: String = name
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    let joined = safe
        .split('-')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    format!(
        "nas-os-{}.p12",
        if joined.is_empty() { "device" } else { &joined }
    )
}

fn issued(device: devices::Device, credential: DeviceCredential) -> Issued {
    Issued {
        credential: Credential {
            file: base64::encode(&credential.p12),
            file_name: file_name(&device.name),
            password: credential.password,
        },
        device,
    }
}

/// A certificate for `name`, made apart from the server's threads: key, signature and the
/// encryption of the file take their time.
pub(crate) async fn issue(authority: Authority, name: String) -> Result<DeviceCredential, Refused> {
    let pki = authority.0.ok_or(UNAVAILABLE)?;
    tokio::task::spawn_blocking(move || pki.issue_device(&name))
        .await
        .map_err(|_| UNAVAILABLE)?
        .map_err(|reason| {
            eprintln!("no certificate issued: {reason}");
            UNAVAILABLE
        })
}

pub async fn create(
    State(sessions): State<Sessions>,
    Extension(authority): Extension<Authority>,
    Extension(codes): Extension<confirm::Codes>,
    request: Request,
) -> Answer {
    let (headers, _) = parts(&request);
    confirmed(&sessions, &codes, &headers).await?;
    let input = json::<devices::DeviceInput>(request).await?;
    let name = named(&input)?;
    let credential = issue(authority, name.clone()).await?;
    let device = devices::create(&sessions.0, &name, input.icon, &credential)
        .await
        .map_err(|_| UNAVAILABLE)?;
    Ok((
        StatusCode::CREATED,
        [(header::CACHE_CONTROL, "no-store")],
        Json(issued(device, credential)),
    )
        .into_response())
}

async fn found(
    sessions: &Sessions,
    id: i64,
    current: Option<&str>,
) -> Result<devices::Device, Refused> {
    devices::find(&sessions.0, id, current)
        .await
        .map_err(|_| UNAVAILABLE)?
        .ok_or(NOT_FOUND)
}

pub async fn update(
    State(sessions): State<Sessions>,
    Path(raw): Path<String>,
    request: Request,
) -> Answer {
    let id = device_id(&raw)?;
    let (headers, current) = parts(&request);
    caller(&sessions, &headers).await?;
    let input = json::<devices::DeviceInput>(request).await?;
    let name = named(&input)?;
    if !devices::update(&sessions.0, id, &name, input.icon)
        .await
        .map_err(|_| UNAVAILABLE)?
    {
        return Err(NOT_FOUND);
    }
    Ok(Json(found(&sessions, id, current.as_deref()).await?).into_response())
}

/// Refuses to act on device `id` when that would shut out the connection asking, with mTLS on.
async fn not_own(sessions: &Sessions, id: i64, current: Option<&str>) -> Result<(), Refused> {
    if !mtls::enabled(&sessions.0).await {
        return Ok(());
    }
    match current_device(sessions, current).await {
        Some(device) if device.id == id => Err(OWN_DEVICE),
        _ => Ok(()),
    }
}

pub async fn renew(
    State(sessions): State<Sessions>,
    Extension(authority): Extension<Authority>,
    Extension(codes): Extension<confirm::Codes>,
    Path(raw): Path<String>,
    request: Request,
) -> Answer {
    let id = device_id(&raw)?;
    let (headers, current) = parts(&request);
    confirmed(&sessions, &codes, &headers).await?;
    not_own(&sessions, id, current.as_deref()).await?;
    let device = found(&sessions, id, None).await?;
    let credential = issue(authority, device.name).await?;
    if !devices::renew(&sessions.0, id, &credential)
        .await
        .map_err(|_| UNAVAILABLE)?
    {
        return Err(NOT_FOUND);
    }
    let renewed = found(&sessions, id, current.as_deref()).await?;
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(issued(renewed, credential)),
    )
        .into_response())
}

/// Drops at once the engine of a revoked computer of the sync client from the sync application.
fn revoke_sync(sessions: &Sessions, config: &Config) {
    let (db, launcher) = (sessions.0.clone(), config.launcher.clone());
    tokio::spawn(async move { client_controller::revoke_pending(&db, &launcher).await });
}

pub async fn revoke(
    State(sessions): State<Sessions>,
    Extension(config): Extension<Arc<Config>>,
    Path(raw): Path<String>,
    request: Request,
) -> Answer {
    let id = device_id(&raw)?;
    let (headers, current) = parts(&request);
    caller(&sessions, &headers).await?;
    not_own(&sessions, id, current.as_deref()).await?;
    if !devices::revoke(&sessions.0, id)
        .await
        .map_err(|_| UNAVAILABLE)?
    {
        return Err(NOT_FOUND);
    }
    revoke_sync(&sessions, &config);
    Ok(Json(found(&sessions, id, current.as_deref()).await?).into_response())
}

pub async fn remove(
    State(sessions): State<Sessions>,
    Extension(config): Extension<Arc<Config>>,
    Path(raw): Path<String>,
    request: Request,
) -> Answer {
    let id = device_id(&raw)?;
    let (headers, current) = parts(&request);
    caller(&sessions, &headers).await?;
    not_own(&sessions, id, current.as_deref()).await?;
    if !devices::remove(&sessions.0, id)
        .await
        .map_err(|_| UNAVAILABLE)?
    {
        return Err(NOT_FOUND);
    }
    revoke_sync(&sessions, &config);
    Ok(StatusCode::NO_CONTENT.into_response())
}
