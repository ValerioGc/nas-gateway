//! The phones of the NAS Mobile app. A phone gets its certificate once the account password is
//! confirmed (`POST /auth/mobile`); from then on its requests under `/client/files/` go to the File
//! application with that certificate only, and to the routes that browse and change the files of
//! the disks. The gateway names the account to the application, as it does for a browser that signed in.

use crate::{
    auth::{
        accounts,
        devices::{self, CertificateState},
        mtls,
    },
    confirm::{self, Refused},
    device_controller::{self as device, Answer, Authority, UNAVAILABLE},
    entry::SECURE_HEADER,
    proxy, Config, Sessions,
};
use axum::{
    body::Body,
    extract::{Path, Request, State},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

const APPLICATION: &str = "nas-file-manager";
const USER_HEADER: &str = "x-nas-user";
const ROUTES: [&str; 10] = [
    "files",
    "directories",
    "copy",
    "move",
    "search",
    "volumes",
    "storage",
    "previews",
    "uploads",
    "downloads",
];

const KEPT: [header::HeaderName; 5] = [
    header::CONTENT_TYPE,
    header::CONTENT_LENGTH,
    header::ACCEPT,
    header::RANGE,
    header::IF_RANGE,
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PhoneInput {
    name: String,
}

#[derive(Serialize)]
struct Issued {
    device: devices::Device,
    certificate: String,
    key: String,
    authority: String,
}

pub async fn create(
    State(sessions): State<Sessions>,
    Extension(authority): Extension<Authority>,
    Extension(codes): Extension<confirm::Codes>,
    request: Request,
) -> Answer {
    let (headers, _) = device::parts(&request);
    device::confirmed(&sessions, &codes, &headers).await?;
    let input = device::json::<PhoneInput>(request).await?;
    let name = devices::valid_name(&input.name)
        .map(str::to_owned)
        .ok_or(Refused(StatusCode::BAD_REQUEST, "invalid device name"))?;
    let authority_pem = authority
        .0
        .as_ref()
        .map(|pki| pki.ca_pem().to_owned())
        .ok_or(UNAVAILABLE)?;
    let credential = device::issue(authority, name.clone()).await?;
    let created = devices::create_mobile(&sessions.0, &name, &credential)
        .await
        .map_err(|_| UNAVAILABLE)?;
    Ok((
        StatusCode::CREATED,
        [(header::CACHE_CONTROL, "no-store")],
        Json(Issued {
            device: created,
            certificate: credential.certificate_pem,
            key: credential.key_pem,
            authority: authority_pem,
        }),
    )
        .into_response())
}

/// `api/<route>` of the File application, one of `ROUTES`, and nothing below it.
fn known_route(rest: &str) -> bool {
    rest.strip_prefix("api/")
        .is_some_and(|route| ROUTES.contains(&route))
}

fn refused(status: StatusCode, reason: &'static str) -> Response {
    Refused(status, reason).into_response()
}

pub async fn forward(
    State(sessions): State<Sessions>,
    Extension(config): Extension<Arc<Config>>,
    Path(rest): Path<String>,
    request: Request,
) -> Response {
    let db = &sessions.0;
    let Some(fingerprint) = mtls::certificate(&request) else {
        return refused(
            StatusCode::UNAUTHORIZED,
            "a certificate of the phone is required",
        );
    };
    let Some(state) = devices::mobile(db, &fingerprint).await else {
        return refused(StatusCode::FORBIDDEN, "this phone is not allowed");
    };
    if !known_route(&rest) {
        return refused(StatusCode::NOT_FOUND, "no such route");
    }
    let Some(user) = accounts::owner(db)
        .await
        .and_then(|user| HeaderValue::from_str(&user).ok())
    else {
        return refused(StatusCode::SERVICE_UNAVAILABLE, "the NAS has no account");
    };
    let (parts, body) = request.into_parts();
    let query = parts
        .uri
        .query()
        .map(|query| format!("?{query}"))
        .unwrap_or_default();
    let mut builder = Request::builder()
        .method(parts.method.clone())
        .uri(format!("/apps/{APPLICATION}/{rest}{query}"))
        .header(header::HOST, "nas")
        .header(USER_HEADER, user)
        .header(SECURE_HEADER, "1");
    for name in KEPT {
        if let Some(value) = parts.headers.get(&name) {
            builder = builder.header(name, value.clone());
        }
    }
    // The body goes on as it comes: an upload is never held whole by the gateway.
    let Ok(forwarded) = builder.body(Body::new(body)) else {
        return refused(StatusCode::BAD_REQUEST, "invalid request");
    };
    let response = proxy::forward(&config.launcher, forwarded).await;
    if state == CertificateState::Pending && response.status().is_success() {
        devices::activate(db, &fingerprint).await;
    }
    devices::seen(db, &fingerprint).await;
    response
}
