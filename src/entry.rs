use crate::{confirm, controller, proxy, tls::Peer, ui, Config, Sessions};
use axum::{
    extract::{ConnectInfo, Request},
    http::{HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use std::sync::Arc;

#[derive(Serialize)]
pub(crate) struct Failure {
    pub error: &'static str,
}

fn is_public(method: &Method, path: &str) -> bool {
    (method == Method::GET && path == "/api/setup")
        || path == "/api/access/failures"
        || path.starts_with("/api/access/failures/")
}

pub async fn handle(
    config: Arc<Config>,
    sessions: Sessions,
    codes: confirm::Codes,
    mut request: Request,
) -> Response {
    request.headers_mut().remove(USER_HEADER);
    request.headers_mut().remove(confirm::HEADER);
    request
        .headers_mut()
        .remove(crate::client_controller::CLIENT_HEADER);
    let code = request.headers_mut().remove(confirm::CODE_HEADER);
    mark_secure(&mut request);
    let path = request.uri().path();
    if path == "/apps" || path.starts_with("/apps/") {
        return application(&config, &sessions, request).await;
    }
    if path == "/api" || path.starts_with("/api/") {
        if !is_public(request.method(), path) {
            let confirmation = confirm::needed(request.method(), path);
            let Some(user) = controller::signed_in(&sessions, request.headers()).await else {
                return sign_in_first();
            };
            mark(&mut request, &user);
            if confirmation {
                match codes.redeem(code, &user).await {
                    Ok(confirmed) => request.headers_mut().insert(confirm::HEADER, confirmed),
                    Err(refusal) => return refusal.into_response(),
                };
            }
        }
        return proxy::forward(&config.launcher, request).await;
    }

    match &config.ui {
        Some(root) => ui::serve(root, request.method(), path).await,
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

const USER_HEADER: &str = "x-nas-user";

pub(crate) const SECURE_HEADER: &str = "x-nas-secure";

fn mark_secure(request: &mut Request) {
    request.headers_mut().remove(SECURE_HEADER);
    let secure = request
        .extensions()
        .get::<ConnectInfo<Peer>>()
        .is_some_and(|ConnectInfo(peer)| peer.encrypted || peer.screen);
    if secure {
        request
            .headers_mut()
            .insert(SECURE_HEADER, HeaderValue::from_static("1"));
    }
}

fn mark(request: &mut Request, user: &str) {
    if let Ok(value) = HeaderValue::from_str(user) {
        request.headers_mut().insert(USER_HEADER, value);
    }
}

fn sign_in_first() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(Failure {
            error: "sign in first",
        }),
    )
        .into_response()
}

async fn application(config: &Config, sessions: &Sessions, mut request: Request) -> Response {
    let Some(user) = controller::signed_in(sessions, request.headers()).await else {
        return sign_in_first();
    };
    controller::without_session(request.headers_mut());
    mark(&mut request, &user);

    let mut response = proxy::forward(&config.launcher, request).await;
    controller::keep_session(response.headers_mut());
    response
}
