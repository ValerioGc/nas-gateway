//! The computers of the sync client. A computer gets its certificate once the account password is
//! confirmed (`POST /auth/clients`). from then on its requests under `/client/sync/` go to the
//! client routes of the sync application only with that certificate, and the gateway names the
//! computer to the application (`x-nas-client`, the identity of its sync engine), a header nobody
//! else can set. Revoking or removing the computer drops its engine from the sync application
//! too, retried until the application confirms it.

use crate::{
    auth::{
        devices::{self, CertificateState},
        mtls,
    },
    confirm::{self, Refused},
    device_controller::{self as device, Answer, Authority, UNAVAILABLE},
    proxy, Config, Sessions,
};
use axum::{
    body::{to_bytes, Body},
    extract::{Path, Request, State},
    http::{header, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::{sync::Arc, time::Duration};

const APPLICATION: &str = "nas-sync-manager";

/// header that names the computer to the sync application.
pub const CLIENT_HEADER: &str = "x-nas-client";
const BODY_LIMIT: usize = 64 * 1024;

/// How often the engines of revoked computers are retried.
const RETRY_EVERY: Duration = Duration::from_secs(300);

/// How long a stopped sync application is waited for after it is started.
const START_WAIT: Duration = Duration::from_millis(500);
const START_TRIES: usize = 20;

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ClientInput {
    name: String,
    sync_id: String,
}

#[derive(Serialize)]
struct Issued {
    device: devices::Device,
    certificate: String,
    key: String,
    authority: String,
}

pub fn valid_sync_id(id: &str) -> bool {
    let groups: Vec<&str> = id.split('-').collect();
    groups.len() == 8
        && groups.iter().all(|group| {
            group.len() == 7
                && group
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || (b'2'..=b'7').contains(&byte))
        })
}

pub async fn create(
    State(sessions): State<Sessions>,
    Extension(authority): Extension<Authority>,
    Extension(codes): Extension<confirm::Codes>,
    request: Request,
) -> Answer {
    let (headers, _) = device::parts(&request);
    device::confirmed(&sessions, &codes, &headers).await?;
    let input = device::json::<ClientInput>(request).await?;
    let name = devices::valid_name(&input.name)
        .map(str::to_owned)
        .ok_or(Refused(StatusCode::BAD_REQUEST, "invalid device name"))?;
    if !valid_sync_id(&input.sync_id) {
        return Err(Refused(StatusCode::BAD_REQUEST, "invalid sync identity"));
    }
    let authority_pem = authority
        .0
        .as_ref()
        .map(|pki| pki.ca_pem().to_owned())
        .ok_or(UNAVAILABLE)?;
    let credential = device::issue(authority, name.clone()).await?;
    let created = devices::create_client(&sessions.0, &name, &input.sync_id, &credential)
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

fn known_route(rest: &str) -> bool {
    match rest.split_once('/') {
        None => matches!(rest, "pair" | "folders" | "syncs"),
        Some(("syncs", id)) => {
            (1..=64).contains(&id.len())
                && id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        }
        Some(_) => false,
    }
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
            "a certificate of the computer is required",
        );
    };
    let Some(client) = devices::client(db, &fingerprint).await else {
        return refused(StatusCode::FORBIDDEN, "this computer is not allowed");
    };
    if !known_route(&rest) {
        return refused(StatusCode::NOT_FOUND, "no such route");
    }

    let pairing = rest == "pair";
    if pairing && client.state != CertificateState::Pending {
        return refused(StatusCode::CONFLICT, "pair again with the account password");
    }
    let (parts, body) = request.into_parts();
    let Ok(body) = to_bytes(body, BODY_LIMIT).await else {
        return refused(StatusCode::PAYLOAD_TOO_LARGE, "request too large");
    };
    let query = parts
        .uri
        .query()
        .map(|query| format!("?{query}"))
        .unwrap_or_default();
    let target = format!("/apps/{APPLICATION}/api/client/{rest}{query}");
    let content_type = parts.headers.get(header::CONTENT_TYPE).cloned();
    let Ok(client_id) = HeaderValue::from_str(&client.sync_id) else {
        return refused(StatusCode::FORBIDDEN, "this computer is not allowed");
    };
    let build = || {
        let mut builder = Request::builder()
            .method(parts.method.clone())
            .uri(&target)
            .header(header::HOST, "nas")
            .header(CLIENT_HEADER, client_id.clone());
        if let Some(content_type) = &content_type {
            builder = builder.header(header::CONTENT_TYPE, content_type.clone());
        }
        builder.body(Body::from(body.clone())).ok()
    };
    let response = reach(&config.launcher, build).await;
    if pairing && response.status().is_success() {
        devices::activate(db, &fingerprint).await;
    }
    devices::seen(db, &fingerprint).await;
    response
}

async fn reach(launcher: &str, build: impl Fn() -> Option<Request>) -> Response {
    let Some(request) = build() else {
        return refused(StatusCode::BAD_REQUEST, "invalid request");
    };
    let mut response = proxy::forward(launcher, request).await;
    if response.status() != StatusCode::SERVICE_UNAVAILABLE {
        return response;
    }
    start(launcher).await;
    for _ in 0..START_TRIES {
        tokio::time::sleep(START_WAIT).await;
        let Some(request) = build() else {
            break;
        };
        response = proxy::forward(launcher, request).await;
        if response.status() != StatusCode::SERVICE_UNAVAILABLE {
            break;
        }
    }
    response
}

/// Asks the launcher to start the sync application, which runs only while a sync is on.
async fn start(launcher: &str) {
    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/apps/{APPLICATION}/start"))
        .header(header::HOST, "nas")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("{}"));
    if let Ok(request) = request {
        let _ = proxy::forward(launcher, request).await;
    }
}

/// Drops the engines of the revoked computers from the sync application. One it does not know, or
/// a NAS without the application, counts as dropped.
pub async fn revoke_pending(db: &SqlitePool, launcher: &str) {
    let Ok(pending) = devices::pending_revocations(db).await else {
        return;
    };
    for sync_id in pending {
        let build = || {
            Request::builder()
                .method(Method::DELETE)
                .uri(format!("/apps/{APPLICATION}/api/devices/{sync_id}"))
                .header(header::HOST, "nas")
                .body(Body::empty())
                .ok()
        };
        let status = reach(launcher, build).await.status();
        if status.is_success() || status == StatusCode::NOT_FOUND {
            let _ = devices::revocation_done(db, &sync_id).await;
        } else {
            eprintln!(
                "the sync of a revoked computer is still on: the application answered {status}"
            );
        }
    }
}

/// Retries the revocations the sync application missed, for as long as the gateway runs.
pub async fn keep_revoking(db: SqlitePool, launcher: String) {
    loop {
        revoke_pending(&db, &launcher).await;
        tokio::time::sleep(RETRY_EVERY).await;
    }
}
