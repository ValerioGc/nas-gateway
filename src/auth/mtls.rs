//! Whether a device certificate is required, and the check every request goes through.
//!
//! The handshake accepts a browser with no certificate or with one the authority of the NAS
//! signed (`tls.rs`). When mTLS is on, a request goes on only with a certificate of a device
//! that is not revoked nor expired. The others get a page that says so. What a device needs before
//! it has a certificate, the health of the gateway and the authority to trust, stays open.

use crate::{auth::devices, tls::Peer, Sessions};
use axum::{
    extract::{connect_info::ConnectInfo, Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use sqlx::SqlitePool;

/// Routes that are reachable without a device certificate, even with mTLS on.
const OPEN: [&str; 2] = ["/health", "/auth/ca.crt"];

pub async fn enabled(db: &SqlitePool) -> bool {
    sqlx::query_scalar::<_, bool>("SELECT enabled FROM mtls WHERE id = 1")
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
        .unwrap_or(false)
}

pub async fn set(db: &SqlitePool, enabled: bool) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO mtls (id, enabled) VALUES (1, ?)
         ON CONFLICT (id) DO UPDATE SET enabled = excluded.enabled",
    )
    .bind(enabled)
    .execute(db)
    .await?;
    Ok(())
}

/// Whether a request came on the port of the monitor connected to the NAS: whoever sits at the
/// machine needs no device certificate.
pub fn from_screen(request: &Request) -> bool {
    request
        .extensions()
        .get::<ConnectInfo<Peer>>()
        .is_some_and(|ConnectInfo(peer)| peer.screen)
}

/// The fingerprint of the device certificate of the connection a request came on.
pub fn certificate(request: &Request) -> Option<String> {
    request
        .extensions()
        .get::<ConnectInfo<Peer>>()
        .and_then(|ConnectInfo(peer)| peer.certificate.clone())
}

pub async fn guard(State(sessions): State<Sessions>, request: Request, next: Next) -> Response {
    let db = &sessions.0;
    if OPEN.contains(&request.uri().path()) || from_screen(&request) || !enabled(db).await {
        return next.run(request).await;
    }
    let Some(fingerprint) = certificate(&request) else {
        return refused();
    };
    if devices::admitted(db, &fingerprint).await.is_none() {
        return refused();
    }
    devices::seen(db, &fingerprint).await;
    next.run(request).await
}

/// The page a browser without a valid device certificate gets.
fn refused() -> Response {
    (
        StatusCode::FORBIDDEN,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        r#"<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Device certificate required | NAS</title>
<style>body{margin:0;min-height:100vh;display:grid;place-items:center;font:16px/1.5 system-ui,sans-serif;background:#172027;color:#f2f7f5}main{max-width:32rem;padding:2rem}p{color:#a4b6c3}</style></head>
<body><main>
<h1>Device certificate required</h1>
<p>This NAS only accepts devices with a valid client certificate. Create a certificate in Security Center from an authorized device, then install it in your browser.</p>
</main></body>
</html>
"#,
    )
        .into_response()
}
