use axum::{
    body::{to_bytes, Body},
    extract::ConnectInfo,
    http::{header, Request, StatusCode},
    Router,
};
use nas_os_gateway::{app_with, tls::Peer};
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

mod common;
use common::Database;

const ACCOUNT: &str = r#"{"username":"admin","password":"long enough"}"#;

type Seen = Arc<Mutex<Vec<String>>>;

async fn launcher() -> (String, Seen) {
    let seen: Seen = Arc::default();
    let log = seen.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let echo = Router::new().fallback(move |request: Request<Body>| {
        let log = log.clone();
        async move {
            let (parts, body) = request.into_parts();
            let header = |name: &str| {
                parts
                    .headers
                    .get(name)
                    .map(|value| value.to_str().unwrap().to_owned())
                    .unwrap_or_default()
            };
            let line = format!(
                "{} {} user={} secure={} range={} type={}",
                parts.method,
                parts.uri,
                header("x-nas-user"),
                header("x-nas-secure"),
                header("range"),
                header("content-type"),
            );
            let body = to_bytes(body, 1024 * 1024).await.unwrap();
            log.lock()
                .unwrap()
                .push(format!("{line} body={}", String::from_utf8_lossy(&body)));
            (StatusCode::OK, "[]")
        }
    });
    tokio::spawn(async move { axum::serve(listener, echo).await.unwrap() });
    (address, seen)
}

async fn gateway(launcher: String) -> (Router, Database) {
    let database = Database::new();
    let app = app_with(database.config(launcher)).await.unwrap();
    database.create_account().await;
    (app, database)
}

fn on(mut request: Request<Body>, certificate: Option<&str>) -> Request<Body> {
    request.extensions_mut().insert(ConnectInfo(Peer {
        address: "192.168.1.30:50000".parse().unwrap(),
        certificate: certificate.map(str::to_owned),
        encrypted: true,
        screen: false,
    }));
    request
}

fn json(method: &str, path: &str, cookie: &str, code: Option<&str>, body: &str) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(header::COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(code) = code {
        builder = builder.header("x-nas-confirmation", code);
    }
    on(builder.body(Body::from(body.to_owned())).unwrap(), None)
}

async fn send(app: &Router, request: Request<Body>) -> (StatusCode, String) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    (status, String::from_utf8_lossy(&body).into_owned())
}

async fn sign_in(app: &Router) -> String {
    let login = Request::builder()
        .method("POST")
        .uri("/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(ACCOUNT))
        .unwrap();
    let response = app.clone().oneshot(on(login, None)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned()
}

async fn code(app: &Router, cookie: &str) -> String {
    let (status, body) = send(
        app,
        json(
            "POST",
            "/auth/confirm",
            cookie,
            None,
            r#"{"password":"long enough"}"#,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body.split('"').nth(3).unwrap().to_owned()
}

fn fingerprint_of(certificate_pem: &str) -> String {
    let der = nas_os_gateway::base64::decode(
        &certificate_pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect::<String>(),
    )
    .unwrap();
    nas_os_gateway::pki::fingerprint(&der)
}

fn field(body: &str, key: &str) -> String {
    let start = body.find(&format!("\"{key}\":\"")).unwrap() + key.len() + 4;
    body[start..start + body[start..].find('"').unwrap()].replace("\\n", "\n")
}

async fn new_phone(app: &Router) -> (String, String) {
    let cookie = sign_in(app).await;
    let code = code(app, &cookie).await;
    let (status, body) = send(
        app,
        json(
            "POST",
            "/auth/mobile",
            &cookie,
            Some(&code),
            r#"{"name":"Pixel"}"#,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    (fingerprint_of(&field(&body, "certificate")), body)
}

fn phone(method: &str, path: &str, certificate: Option<&str>, body: &str) -> Request<Body> {
    on(
        Request::builder()
            .method(method)
            .uri(path)
            .header(header::CONTENT_TYPE, "application/json")
            .header("x-nas-user", "forged")
            .header("x-nas-client", "FORGED")
            .header(header::COOKIE, "nas_session=stolen")
            .body(Body::from(body.to_owned()))
            .unwrap(),
        certificate,
    )
}

async fn devices(app: &Router) -> String {
    let cookie = sign_in(app).await;
    let (status, body) = send(app, json("GET", "/auth/devices", &cookie, None, "")).await;
    assert_eq!(status, StatusCode::OK);
    body
}

#[tokio::test]
async fn a_phone_gets_its_certificate_only_with_the_password_confirmed() {
    let (app, _database) = gateway("127.0.0.1:1".to_owned()).await;
    let cookie = sign_in(&app).await;
    let (status, _) = send(
        &app,
        json("POST", "/auth/mobile", &cookie, None, r#"{"name":"Pixel"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    for body in [
        r#"{"name":"  "}"#,
        r#"{"name":"Pixel","syncId":"x"}"#,
        "nope",
    ] {
        let code = code(&app, &cookie).await;
        let (status, _) = send(
            &app,
            json("POST", "/auth/mobile", &cookie, Some(&code), body),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    }

    let (_, issued) = new_phone(&app).await;
    assert!(issued.contains("BEGIN CERTIFICATE"));
    assert!(issued.contains("PRIVATE KEY"));
    assert!(issued.contains(r#""icon":"phone""#));
    assert!(issued.contains(r#""mobile":true"#));
    assert!(issued.contains(r#""sync":false"#));
    assert!(devices(&app).await.contains(r#""mobile":true"#));
}

#[tokio::test]
async fn only_its_certificate_reaches_the_file_routes_named_for_the_account() {
    let (address, seen) = launcher().await;
    let (app, _database) = gateway(address).await;
    let (fingerprint, _) = new_phone(&app).await;

    let (status, _) = send(&app, phone("GET", "/client/files/api/files", None, "")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let stranger = "f".repeat(64);
    let (status, _) = send(
        &app,
        phone("GET", "/client/files/api/files", Some(&stranger), ""),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    for path in [
        "/client/files/api/shares",
        "/client/files/api/documents/settings",
        "/client/files/api/trash",
        "/client/files/api/previews/cache",
        "/client/files/api/files/extra",
        "/client/files/internal/cache",
        "/client/files/index.html",
    ] {
        let (status, _) = send(&app, phone("GET", path, Some(&fingerprint), "")).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
    }
    assert!(seen.lock().unwrap().is_empty());

    assert!(devices(&app).await.contains(r#""state":"pending""#));
    let (status, body) = send(
        &app,
        phone(
            "GET",
            "/client/files/api/files?path=disk%2Fphotos",
            Some(&fingerprint),
            "",
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "[]");
    let (status, _) = send(
        &app,
        phone(
            "POST",
            "/client/files/api/copy",
            Some(&fingerprint),
            r#"{"source":"a","destination":"b"}"#,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        seen.lock().unwrap().clone(),
        vec![
            "GET /apps/nas-file-manager/api/files?path=disk%2Fphotos user=admin secure=1 \
             range= type=application/json body="
                .to_owned(),
            "POST /apps/nas-file-manager/api/copy user=admin secure=1 range= \
             type=application/json body={\"source\":\"a\",\"destination\":\"b\"}"
                .to_owned(),
        ]
    );
    assert!(devices(&app).await.contains(r#""state":"active""#));
}

#[tokio::test]
async fn a_transfer_keeps_its_range_and_its_whole_body() {
    let (address, seen) = launcher().await;
    let (app, _database) = gateway(address).await;
    let (fingerprint, _) = new_phone(&app).await;
    let download = on(
        Request::builder()
            .uri("/client/files/api/downloads?path=disk%2Fmovie.mp4")
            .header(header::RANGE, "bytes=100-")
            .body(Body::empty())
            .unwrap(),
        Some(&fingerprint),
    );
    assert_eq!(send(&app, download).await.0, StatusCode::OK);
    // Larger than any limit the gateway puts on its own routes.
    let large = "x".repeat(200 * 1024);
    let upload = on(
        Request::builder()
            .method("POST")
            .uri("/client/files/api/uploads?path=disk%2Fnotes.txt")
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .body(Body::from(large.clone()))
            .unwrap(),
        Some(&fingerprint),
    );
    assert_eq!(send(&app, upload).await.0, StatusCode::OK);
    let seen = seen.lock().unwrap().clone();
    assert!(seen[0].contains("range=bytes=100-"), "{}", seen[0]);
    assert!(seen[1].ends_with(&format!("body={large}")));
}

#[tokio::test]
async fn a_revoked_phone_and_a_computer_of_the_sync_are_kept_out() {
    let (address, seen) = launcher().await;
    let (app, _database) = gateway(address).await;
    let (fingerprint, issued) = new_phone(&app).await;
    let id = issued
        .split(r#""id":"#)
        .nth(1)
        .unwrap()
        .split(',')
        .next()
        .unwrap()
        .to_owned();
    let cookie = sign_in(&app).await;
    let (status, _) = send(
        &app,
        json(
            "POST",
            &format!("/auth/devices/{id}/revoke"),
            &cookie,
            None,
            "",
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = send(
        &app,
        phone("GET", "/client/files/api/volumes", Some(&fingerprint), ""),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let code = code(&app, &cookie).await;
    let sync_id = "ABCDEFG-HIJKLMN-OPQRSTU-VWXYZ23-4567ABC-DEFGHIJ-KLMNOPQ-RSTUVWX";
    let (status, body) = send(
        &app,
        json(
            "POST",
            "/auth/clients",
            &cookie,
            Some(&code),
            &format!(r#"{{"name":"Studio PC","syncId":"{sync_id}"}}"#),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let computer = fingerprint_of(&field(&body, "certificate"));
    let (status, _) = send(
        &app,
        phone("GET", "/client/files/api/volumes", Some(&computer), ""),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = send(
        &app,
        phone("GET", "/client/sync/syncs", Some(&fingerprint), ""),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(seen.lock().unwrap().is_empty());
}
