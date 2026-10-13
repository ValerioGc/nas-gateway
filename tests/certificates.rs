use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
    Router,
};
use nas_os_gateway::app_with;
use rcgen::{CertificateParams, KeyPair};
use tower::ServiceExt;

mod common;
use common::{Database, PASSWORD, USERNAME};

async fn gateway() -> (Router, Database) {
    let database = Database::new();
    let app = app_with(database.config(String::new())).await.unwrap();
    database.create_account().await;
    (app, database)
}

fn request(
    method: &str,
    path: &str,
    cookie: &str,
    code: Option<&str>,
    body: &str,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, cookie);
    if let Some(code) = code {
        builder = builder.header("x-nas-confirmation", code);
    }
    builder.body(Body::from(body.to_owned())).unwrap()
}

async fn send(app: &Router, request: Request<Body>) -> (StatusCode, String) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 1 << 20).await.unwrap();
    (status, String::from_utf8_lossy(&body).into_owned())
}

/// The value of the first `"field":"..."` of a JSON answer: the certificate in use comes first.
fn first(answer: &str, field: &str) -> String {
    answer
        .split(&format!("\"{field}\":\""))
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .unwrap_or_default()
        .to_owned()
}

/// What a JSON answer says before the authority: the certificate in use.
fn active(answer: &str) -> &str {
    answer.split(r#""authority""#).next().unwrap()
}

async fn sign_in(app: &Router) -> String {
    let body = format!(r#"{{"username":"{USERNAME}","password":"{PASSWORD}"}}"#);
    let response = app
        .clone()
        .oneshot(request("POST", "/auth/login", "", None, &body))
        .await
        .unwrap();
    response.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned()
}

async fn confirmation(app: &Router, cookie: &str) -> String {
    let body = format!(r#"{{"password":"{PASSWORD}"}}"#);
    let (status, answer) = send(app, request("POST", "/auth/confirm", cookie, None, &body)).await;
    assert_eq!(status, StatusCode::OK);
    first(&answer, "code")
}

/// A certificate of someone else's authority for `name`, and its key, in PEM.
fn foreign(name: &str) -> (String, String) {
    let key = KeyPair::generate().unwrap();
    let certificate = CertificateParams::new(vec![name.to_owned()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    (certificate.pem(), key.serialize_pem())
}

fn json_string(text: &str) -> String {
    format!("{text:?}")
}

#[tokio::test]
async fn the_certificate_in_use_is_read_only_with_a_session() {
    let (app, _database) = gateway().await;
    let (status, _) = send(&app, request("GET", "/auth/certificate", "", None, "")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let cookie = sign_in(&app).await;
    let (status, state) = send(&app, request("GET", "/auth/certificate", &cookie, None, "")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        state.contains(r#""served":false,"custom":false"#),
        "{state}"
    );
    assert_eq!(first(&state, "issuer"), "nas-os NAS authority");
    assert!(state.contains(r#""subject":"nas-os NAS authority""#));
    assert!(active(&state).contains(r#""localhost""#) && active(&state).contains(r#""127.0.0.1""#));
    assert!(state.contains(r#""extraNames":[]"#));
}

#[tokio::test]
async fn names_added_by_the_user_are_covered_at_once() {
    let (app, _database) = gateway().await;
    let cookie = sign_in(&app).await;
    let body = r#"{"names":["NAS.example.org","10.8.0.2"]}"#;
    let (status, _) = send(
        &app,
        request(
            "PUT",
            "/auth/certificate/names",
            &cookie,
            Some("forged"),
            body,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let code = confirmation(&app, &cookie).await;
    let wrong = r#"{"names":["bad name"]}"#;
    let (status, _) = send(
        &app,
        request(
            "PUT",
            "/auth/certificate/names",
            &cookie,
            Some(&code),
            wrong,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let code = confirmation(&app, &cookie).await;
    let (status, state) = send(
        &app,
        request("PUT", "/auth/certificate/names", &cookie, Some(&code), body),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        state.contains(r#""extraNames":["nas.example.org","10.8.0.2"]"#),
        "{state}"
    );
    assert!(active(&state).contains(r#""nas.example.org""#));
    assert!(active(&state).contains(r#""10.8.0.2""#));
}

#[tokio::test]
async fn a_renewal_issues_a_new_certificate() {
    let (app, _database) = gateway().await;
    let cookie = sign_in(&app).await;
    let (_, before) = send(&app, request("GET", "/auth/certificate", &cookie, None, "")).await;
    let code = confirmation(&app, &cookie).await;
    let (status, after) = send(
        &app,
        request("POST", "/auth/certificate/renew", &cookie, Some(&code), ""),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ne!(first(&after, "fingerprint"), first(&before, "fingerprint"));
    let authority = |state: &str| state.split(r#""authority""#).nth(1).unwrap().to_owned();
    assert_eq!(authority(&after), authority(&before), "the authority stays");
}

#[tokio::test]
async fn a_certificate_brought_by_the_user_replaces_the_nas_own_until_removed() {
    let (app, _database) = gateway().await;
    let cookie = sign_in(&app).await;
    let (certificate, key) = foreign("nas.example.org");
    let (_, other_key) = foreign("other.example.org");
    let upload = |key: &str| {
        format!(
            r#"{{"certificate":{},"key":{}}}"#,
            json_string(&certificate),
            json_string(key)
        )
    };

    let code = confirmation(&app, &cookie).await;
    let (status, _) = send(
        &app,
        request(
            "PUT",
            "/auth/certificate/custom",
            &cookie,
            Some(&code),
            &upload(&other_key),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let code = confirmation(&app, &cookie).await;
    let (status, state) = send(
        &app,
        request(
            "PUT",
            "/auth/certificate/custom",
            &cookie,
            Some(&code),
            &upload(&key),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(state.contains(r#""custom":true"#));
    assert!(active(&state).contains(r#""names":["nas.example.org"]"#));

    let code = confirmation(&app, &cookie).await;
    let (status, state) = send(
        &app,
        request(
            "DELETE",
            "/auth/certificate/custom",
            &cookie,
            Some(&code),
            "",
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(state.contains(r#""custom":false"#));
    assert_eq!(first(&state, "issuer"), "nas-os NAS authority");
}
