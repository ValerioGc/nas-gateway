use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
    Router,
};
use nas_os_gateway::{app_with, Config};
use std::path::PathBuf;
use tower::ServiceExt;

mod common;
use common::{Database, PASSWORD, USERNAME};

fn not_configured() -> Router {
    Router::new().route(
        "/api/setup",
        axum::routing::get(|| async { r#"{"completed":false,"ready":false,"steps":[]}"# }),
    )
}

async fn launcher() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let echo = not_configured().fallback(|request: Request<Body>| async move {
        let host = request.headers()[header::HOST].to_str().unwrap().to_owned();
        format!("{host} {}", request.uri().path())
    });
    tokio::spawn(async move { axum::serve(listener, echo).await.unwrap() });
    address
}

fn interface(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("nas-gateway-{}-{name}", std::process::id()));
    let ui = root.join("ui");
    std::fs::create_dir_all(ui.join("assets")).unwrap();
    std::fs::write(ui.join("index.html"), "<html>launcher</html>").unwrap();
    std::fs::write(ui.join("assets/index-abc.js"), "console.log(1)").unwrap();
    std::fs::write(root.join("secret.txt"), "secret").unwrap();
    ui
}

async fn gateway(name: &str) -> (Router, Database) {
    let database = Database::new();
    let config = Config {
        ui: Some(interface(name)),
        ..database.config(launcher().await)
    };
    (app_with(config).await.unwrap(), database)
}

async fn call(app: &Router, request: Request<Body>) -> (StatusCode, String, header::HeaderMap) {
    let response = app.clone().oneshot(request).await.unwrap();
    let (status, headers) = (response.status(), response.headers().clone());
    let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    (status, String::from_utf8_lossy(&body).into_owned(), headers)
}

fn get(path: &str, host: &str) -> Request<Body> {
    Request::builder()
        .uri(path)
        .header(header::HOST, host)
        .body(Body::empty())
        .unwrap()
}

async fn sign_in(app: &Router, database: &Database) -> String {
    database.create_account().await;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(format!(
                    r#"{{"username":"{USERNAME}","password":"{PASSWORD}"}}"#
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    let cookie = response.headers()[header::SET_COOKIE].to_str().unwrap();
    cookie.split(';').next().unwrap().to_owned()
}

#[tokio::test]
async fn the_interface_is_served_with_its_routes_and_its_assets() {
    let (app, _database) = gateway("serve").await;

    let (status, body, headers) = call(&app, get("/", "nas.internal")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "<html>launcher</html>");
    assert_eq!(headers[header::CACHE_CONTROL], "no-cache");
    assert_eq!(
        headers[header::CONTENT_SECURITY_POLICY],
        "frame-ancestors 'none'"
    );
    assert!(headers["x-robots-tag"]
        .to_str()
        .unwrap()
        .contains("noindex"));

    let (status, body, _) = call(&app, get("/login", "nas.internal")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "<html>launcher</html>");

    let (status, _, headers) = call(&app, get("/assets/index-abc.js", "nas.internal")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(headers[header::CONTENT_TYPE]
        .to_str()
        .unwrap()
        .starts_with("text/javascript"));
    assert!(headers[header::CACHE_CONTROL]
        .to_str()
        .unwrap()
        .contains("immutable"));

    let (status, _, _) = call(&app, get("/assets/missing.js", "nas.internal")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn nothing_outside_the_interface_directory_is_served() {
    let (app, _database) = gateway("escape").await;

    for path in [
        "/../secret.txt",
        "/assets/../../secret.txt",
        "/%2e%2e/secret.txt",
    ] {
        let (status, body, _) = call(&app, get(path, "nas.internal")).await;
        assert_ne!(body, "secret", "{path}");
        assert!(
            status == StatusCode::NOT_FOUND || body.contains("launcher"),
            "{path}"
        );
    }
}

#[tokio::test]
async fn the_api_needs_a_session_and_then_reaches_the_launcher() {
    let (app, database) = gateway("api").await;

    let (status, body, _) = call(&app, get("/api/apps", "nas.internal")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(body.contains("sign in first"));

    let cookie = sign_in(&app, &database).await;
    let mut request = get("/api/apps", "nas.internal");
    request
        .headers_mut()
        .insert(header::COOKIE, cookie.parse().unwrap());
    let (status, body, _) = call(&app, request).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "nas.internal /api/apps");
}

#[tokio::test]
async fn only_the_setup_state_and_refused_sign_ins_pass_without_a_session() {
    let (app, _database) = gateway("public").await;

    let (status, body, _) = call(&app, get("/api/setup", "nas.internal")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("\"completed\":false"));
    let (status, body, _) = call(&app, get("/api/access/failures", "nas.internal")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "nas.internal /api/access/failures");
    for path in [
        "/api/setup/complete",
        "/api/setupx",
        "/api/access/rules",
        "/api/apps",
    ] {
        let (status, _, _) = call(&app, get(path, "nas.internal")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{path}");
    }

    let mut complete = get("/api/setup", "nas.internal");
    *complete.method_mut() = axum::http::Method::POST;
    let (status, _, _) = call(&app, complete).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

async fn echoing_launcher() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let echo = not_configured().fallback(|request: Request<Body>| async move {
        let cookies = request
            .headers()
            .get(header::COOKIE)
            .map_or("-", |value| value.to_str().unwrap())
            .to_owned();
        (
            [
                (header::SET_COOKIE, "nas_session=forged; Path=/"),
                (header::SET_COOKIE, "theme=dark; Path=/"),
            ],
            format!("{cookies} {}", request.uri().path()),
        )
    });
    tokio::spawn(async move { axum::serve(listener, echo).await.unwrap() });
    address
}

#[tokio::test]
async fn an_application_is_for_the_signed_in_and_never_sees_the_session() {
    let database = Database::new();
    let app = app_with(database.config(echoing_launcher().await))
        .await
        .unwrap();

    let (status, _, _) = call(&app, get("/apps/photos/", "localhost")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let session = sign_in(&app, &database).await;
    let mut request = get("/apps/photos/index.html", "localhost");
    request.headers_mut().insert(
        header::COOKIE,
        format!("{session}; theme=light").parse().unwrap(),
    );
    let (status, body, headers) = call(&app, request).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "theme=light /apps/photos/index.html");
    let cookies: Vec<_> = headers.get_all(header::SET_COOKIE).iter().collect();
    assert_eq!(cookies, ["theme=dark; Path=/"]);
}

#[tokio::test]
async fn a_launcher_that_does_not_answer_is_a_bad_gateway() {
    let app = app_with(Config {
        launcher: "127.0.0.1:1".to_owned(),
        ui: None,
        database: None,
        pki: None,
        tls: false,
        shares: None,
    })
    .await
    .unwrap();

    let (status, body, _) = call(&app, get("/api/setup", "nas.internal")).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert!(body.contains("not answering"));
}

#[tokio::test]
async fn an_unreadable_interface_is_unavailable_rather_than_missing() {
    use std::os::unix::fs::PermissionsExt;

    let ui = interface("unreadable");
    let index = ui.join("index.html");
    std::fs::set_permissions(&index, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::read(&index).is_ok() {
        return;
    }
    let app = app_with(Config {
        launcher: "127.0.0.1:1".to_owned(),
        ui: Some(ui),
        database: None,
        pki: None,
        tls: false,
        shares: None,
    })
    .await
    .unwrap();

    let (status, _, _) = call(&app, get("/", "nas.internal")).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

/// A launcher that turns every request into a WebSocket that sends back what it receives.
async fn websocket_launcher() -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut buffer = [0_u8; 1024];
                while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                    let read = stream.read(&mut buffer).await.unwrap();
                    request.extend_from_slice(&buffer[..read]);
                }
                stream
                    .write_all(b"HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nconnection: upgrade\r\n\r\n")
                    .await
                    .unwrap();
                let read = stream.read(&mut buffer).await.unwrap();
                stream.write_all(&buffer[..read]).await.unwrap();
            });
        }
    });
    address
}

#[tokio::test]
async fn a_websocket_of_an_application_goes_through_for_the_signed_in() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let database = Database::new();
    let app = app_with(database.config(websocket_launcher().await))
        .await
        .unwrap();
    let session = sign_in(&app, &database).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let mut browser = tokio::net::TcpStream::connect(address).await.unwrap();
    let handshake = format!(
        "GET /apps/photos/live HTTP/1.1\r\nhost: localhost\r\ncookie: {session}\r\nconnection: Upgrade\r\nupgrade: websocket\r\nsec-websocket-version: 13\r\nsec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
    );
    browser.write_all(handshake.as_bytes()).await.unwrap();
    let mut answer = Vec::new();
    let mut buffer = [0_u8; 1024];
    while !answer.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = browser.read(&mut buffer).await.unwrap();
        answer.extend_from_slice(&buffer[..read]);
    }
    assert!(String::from_utf8_lossy(&answer).starts_with("HTTP/1.1 101"));

    browser.write_all(b"ping").await.unwrap();
    let read = browser.read(&mut buffer).await.unwrap();
    assert_eq!(&buffer[..read], b"ping");
}
