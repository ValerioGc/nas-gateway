//! Forwards a request to the launcher on the loopback

use crate::entry::Failure;
use axum::{
    body::Body,
    extract::Request,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use hyper::upgrade::OnUpgrade;
use hyper_util::rt::TokioIo;
use std::time::Duration;
use tokio::net::TcpStream;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

const HOP_BY_HOP: [&str; 8] = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

type Sender = hyper::client::conn::http1::SendRequest<Body>;

async fn connect(launcher: &str) -> Option<Sender> {
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(launcher))
        .await
        .ok()?
        .ok()?;
    let (sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .ok()?;
    tokio::spawn(async move {
        if let Err(error) = connection.with_upgrades().await {
            eprintln!("the connection to the launcher ended: {error}");
        }
    });
    Some(sender)
}

/// Whether the request asks to become a WebSocket, the one upgrade the gateway carries.
fn websocket(headers: &HeaderMap) -> bool {
    let has = |name, token: &str| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value
                    .split(',')
                    .any(|part| part.trim().eq_ignore_ascii_case(token))
            })
    };
    has(header::UPGRADE, "websocket") && has(header::CONNECTION, "upgrade")
}

/// Joins the browser and the launcher once both sides have switched protocol.
async fn tunnel(browser: OnUpgrade, launcher: OnUpgrade) {
    if let (Ok(browser), Ok(launcher)) = (browser.await, launcher.await) {
        let _ =
            tokio::io::copy_bidirectional(&mut TokioIo::new(browser), &mut TokioIo::new(launcher))
                .await;
    }
}

pub async fn forward(launcher: &str, mut request: Request) -> Response {
    let upgrade = websocket(request.headers()).then(|| hyper::upgrade::on(&mut request));
    let Some(mut sender) = connect(launcher).await else {
        return unavailable();
    };

    let (mut parts, body) = request.into_parts();
    let protocol = parts.headers.get(header::UPGRADE).cloned();
    for name in HOP_BY_HOP {
        parts.headers.remove(name);
    }
    if let (Some(_), Some(protocol)) = (&upgrade, protocol) {
        parts
            .headers
            .insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
        parts.headers.insert(header::UPGRADE, protocol);
    }
    let Ok(mut answer) = sender.send_request(Request::from_parts(parts, body)).await else {
        return unavailable();
    };

    if let Some(browser) = upgrade {
        if answer.status() == StatusCode::SWITCHING_PROTOCOLS {
            let launcher = hyper::upgrade::on(&mut answer);
            tokio::spawn(tunnel(browser, launcher));
            let (parts, _) = answer.into_parts();
            return Response::from_parts(parts, Body::empty());
        }
    }

    let (mut parts, body) = answer.into_parts();
    for name in HOP_BY_HOP {
        parts.headers.remove(name);
    }
    Response::from_parts(parts, Body::new(body))
}

// The launcher restarting (during an update, for instance) is a 502 the interface waits out.
fn unavailable() -> Response {
    (
        StatusCode::BAD_GATEWAY,
        Json(Failure {
            error: "the launcher is not answering",
        }),
    )
        .into_response()
}
