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
const SYNC_ID: &str = "ABCDEFG-HIJKLMN-OPQRSTU-VWXYZ23-4567ABC-DEFGHIJ-KLMNOPQ-RSTUVWX";

/// What the fake launcher received: method, path and the computer it was named for.
type Seen = Arc<Mutex<Vec<String>>>;

/// A launcher that echoes what reaches the sync application, and answers `status` to it.
async fn launcher(status: StatusCode) -> (String, Seen) {
    let seen: Seen = Arc::default();
    let log = seen.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let echo = Router::new().fallback(move |request: Request<Body>| {
        let log = log.clone();
        async move {
            let client = request
                .headers()
                .get("x-nas-client")
                .map(|value| value.to_str().unwrap().to_owned())
                .unwrap_or_default();
            log.lock()
                .unwrap()
                .push(format!("{} {} {client}", request.method(), request.uri()));
            (status, r#"{"deviceId":"NAS","port":22000}"#)
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
        address: "192.168.1.20:50000".parse().unwrap(),
        certificate: certificate.map(str::to_owned),
        encrypted: true,
        screen: false,
    }));
    request
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
        .header(header::COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(code) = code {
        builder = builder.header("x-nas-confirmation", code);
    }
    builder.body(Body::from(body.to_owned())).unwrap()
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
        on(
            request(
                "POST",
                "/auth/confirm",
                cookie,
                None,
                r#"{"password":"long enough"}"#,
            ),
            None,
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

/// The value of `"key":"..."` in a JSON text, with its escapes undone.
fn field(body: &str, key: &str) -> String {
    let start = body.find(&format!("\"{key}\":\"")).unwrap() + key.len() + 4;
    body[start..start + body[start..].find('"').unwrap()].replace("\\n", "\n")
}

/// A computer of the sync client, paired with the password: the fingerprint of its certificate.
async fn new_client(app: &Router) -> (String, String) {
    let cookie = sign_in(app).await;
    let code = code(app, &cookie).await;
    let (status, body) = send(
        app,
        on(
            request(
                "POST",
                "/auth/clients",
                &cookie,
                Some(&code),
                &format!(r#"{{"name":"Studio PC","syncId":"{SYNC_ID}"}}"#),
            ),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    (fingerprint_of(&field(&body, "certificate")), body)
}

fn client(method: &str, path: &str, certificate: Option<&str>, body: &str) -> Request<Body> {
    on(
        Request::builder()
            .method(method)
            .uri(path)
            .header(header::CONTENT_TYPE, "application/json")
            .header("x-nas-client", "FORGED")
            .body(Body::from(body.to_owned()))
            .unwrap(),
        certificate,
    )
}

#[tokio::test]
async fn a_computer_gets_its_certificate_only_with_the_password_confirmed() {
    let (app, _database) = gateway("127.0.0.1:1".to_owned()).await;
    let cookie = sign_in(&app).await;
    let body = format!(r#"{{"name":"Studio PC","syncId":"{SYNC_ID}"}}"#);
    let (status, _) = send(
        &app,
        on(request("POST", "/auth/clients", &cookie, None, &body), None),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let code = code(&app, &cookie).await;
    let (status, _) = send(
        &app,
        on(
            request(
                "POST",
                "/auth/clients",
                &cookie,
                Some(&code),
                r#"{"name":"PC","syncId":"nope"}"#,
            ),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (_, issued) = new_client(&app).await;
    assert!(field(&issued, "certificate").starts_with("-----BEGIN CERTIFICATE-----"));
    assert!(field(&issued, "key").contains("PRIVATE KEY"));
    assert!(field(&issued, "authority").starts_with("-----BEGIN CERTIFICATE-----"));
    assert!(issued.contains(r#""sync":true"#));
}

#[tokio::test]
async fn only_its_certificate_reaches_the_client_routes_named_by_the_gateway() {
    let (address, seen) = launcher(StatusCode::OK).await;
    let (app, _database) = gateway(address).await;
    let (status, _) = send(&app, client("GET", "/client/sync/syncs", None, "")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = send(
        &app,
        client("GET", "/client/sync/syncs", Some(&"0".repeat(64)), ""),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (fingerprint, _) = new_client(&app).await;
    let (status, _) = send(
        &app,
        client("GET", "/client/sync/../api/devices", Some(&fingerprint), ""),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = send(
        &app,
        client("POST", "/client/sync/pair", Some(&fingerprint), "{}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = send(
        &app,
        client(
            "GET",
            "/client/sync/folders?path=photos",
            Some(&fingerprint),
            "",
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = send(
        &app,
        client("PUT", "/client/sync/syncs/f-1", Some(&fingerprint), "{}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let seen = seen.lock().unwrap().clone();
    assert_eq!(
        seen,
        vec![
            format!("POST /apps/nas-sync-manager/api/client/pair {SYNC_ID}"),
            format!("GET /apps/nas-sync-manager/api/client/folders?path=photos {SYNC_ID}"),
            format!("PUT /apps/nas-sync-manager/api/client/syncs/f-1 {SYNC_ID}"),
        ]
    );
}

#[tokio::test]
async fn a_certificate_pairs_its_computer_once() {
    let (address, _seen) = launcher(StatusCode::OK).await;
    let (app, _database) = gateway(address).await;
    let (fingerprint, _) = new_client(&app).await;
    let pair = || client("POST", "/client/sync/pair", Some(&fingerprint), "{}");
    assert_eq!(send(&app, pair()).await.0, StatusCode::OK);
    assert_eq!(send(&app, pair()).await.0, StatusCode::CONFLICT);
}

#[tokio::test]
async fn a_browser_never_names_the_computer_of_the_sync() {
    let (address, seen) = launcher(StatusCode::OK).await;
    let (app, _database) = gateway(address).await;
    let cookie = sign_in(&app).await;
    let mut browser = request(
        "GET",
        "/apps/nas-sync-manager/api/client/syncs",
        &cookie,
        None,
        "",
    );
    browser
        .headers_mut()
        .insert("x-nas-client", SYNC_ID.parse().unwrap());
    send(&app, on(browser, None)).await;
    assert_eq!(
        seen.lock().unwrap().clone(),
        vec!["GET /apps/nas-sync-manager/api/client/syncs ".to_owned()]
    );
}

#[tokio::test]
async fn revoking_a_computer_drops_its_engine_from_the_sync() {
    let (address, seen) = launcher(StatusCode::NO_CONTENT).await;
    let (app, _database) = gateway(address).await;
    let (_, issued) = new_client(&app).await;
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
        on(
            request(
                "POST",
                &format!("/auth/devices/{id}/revoke"),
                &cookie,
                None,
                "",
            ),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    for _ in 0..50 {
        if !seen.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(
        seen.lock().unwrap().clone(),
        vec![format!(
            "DELETE /apps/nas-sync-manager/api/devices/{SYNC_ID} "
        )]
    );
}

#[tokio::test]
async fn a_stopped_sync_application_is_started_and_waited_for() {
    let started: Seen = Arc::default();
    let log = started.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let fake = Router::new().fallback(move |request: Request<Body>| {
        let log = log.clone();
        async move {
            let path = request.uri().path().to_owned();
            let mut log = log.lock().unwrap();
            if path == "/api/apps/nas-sync-manager/start" {
                log.push(path);
                return StatusCode::OK;
            }
            if log.is_empty() {
                StatusCode::SERVICE_UNAVAILABLE
            } else {
                StatusCode::OK
            }
        }
    });
    tokio::spawn(async move { axum::serve(listener, fake).await.unwrap() });
    let (app, _database) = gateway(address).await;
    let (fingerprint, _) = new_client(&app).await;
    let (status, _) = send(
        &app,
        client("GET", "/client/sync/syncs", Some(&fingerprint), ""),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        started.lock().unwrap().clone(),
        vec!["/api/apps/nas-sync-manager/start".to_owned()]
    );
}

/// A launcher that writes down whether each request reached it as secure.
async fn secure_launcher() -> (String, Seen) {
    let seen: Seen = Arc::default();
    let log = seen.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let echo = Router::new().fallback(move |request: Request<Body>| {
        let log = log.clone();
        async move {
            let secure = request
                .headers()
                .get("x-nas-secure")
                .map(|value| value.to_str().unwrap().to_owned())
                .unwrap_or_default();
            log.lock().unwrap().push(secure);
            (StatusCode::OK, "{}")
        }
    });
    tokio::spawn(async move { axum::serve(listener, echo).await.unwrap() });
    (address, seen)
}

#[tokio::test]
async fn only_the_gateway_says_a_request_came_over_an_encrypted_connection() {
    let (address, seen) = secure_launcher().await;
    let (app, _database) = gateway(address).await;
    let cookie = sign_in(&app).await;
    let forged = |encrypted: bool, screen: bool| {
        let mut request = request("GET", "/api/storage/disks", &cookie, None, "");
        request
            .headers_mut()
            .insert("x-nas-secure", "1".parse().unwrap());
        request.extensions_mut().insert(ConnectInfo(Peer {
            address: "192.168.1.20:50000".parse().unwrap(),
            certificate: None,
            encrypted,
            screen,
        }));
        request
    };
    for (encrypted, screen) in [(false, false), (true, false), (false, true)] {
        let (status, _) = send(&app, forged(encrypted, screen)).await;
        assert_eq!(status, StatusCode::OK);
    }
    assert_eq!(*seen.lock().unwrap(), ["", "1", "1"]);
}
