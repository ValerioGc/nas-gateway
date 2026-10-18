//! The codes go out by mail through the launcher, which hands them to the mail application
//! installed on the NAS. `/internal/` is a path of the launcher the gateway never forwards from a
//! browser: only the processes of the machine reach it on the loopback.

use crate::{auth::email_codes::Purpose, proxy};
use axum::{
    body::Body,
    extract::Request,
    http::{header, Method},
    response::IntoResponse,
    Json,
};
use serde::Serialize;

const PATH: &str = "/internal/mail/code";

#[derive(Serialize)]
struct Code<'a> {
    to: &'a str,
    purpose: &'a str,
    code: &'a str,
}

/// Sends `code` to `to`, or says the mail application could not.
pub async fn send(launcher: &str, purpose: Purpose, to: &str, code: &str) -> Result<(), ()> {
    // axum writes the JSON; the gateway carries no serializer of its own.
    let body = Json(Code {
        to,
        purpose: purpose.id(),
        code,
    })
    .into_response()
    .into_body();
    let Ok(request) = Request::builder()
        .method(Method::POST)
        .uri(PATH)
        .header(header::HOST, "nas")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::new(body))
    else {
        return Err(());
    };
    let answer = proxy::forward(launcher, request).await;
    if answer.status().is_success() {
        Ok(())
    } else {
        eprintln!(
            "the mail with the code was not sent: the launcher answered {}",
            answer.status()
        );
        Err(())
    }
}
