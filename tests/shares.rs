use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
    Router,
};
use nas_os_gateway::{app_with, Config};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixListener,
};
use tower::ServiceExt;

mod common;
use common::{Database, PASSWORD, USERNAME};

struct Helper {
    socket: PathBuf,
    received: Arc<Mutex<Vec<String>>>,
}

impl Helper {
    fn start(database: &Database, answer: &'static str) -> Self {
        let socket = database.0.with_extension("sock");
        let _ = std::fs::remove_file(&socket);
        let listener = UnixListener::bind(&socket).expect("the socket of the helper");
        let received = Arc::new(Mutex::new(Vec::new()));
        let kept = received.clone();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut request = String::new();
                let _ = stream.read_to_string(&mut request).await;
                kept.lock().unwrap().push(request);
                let _ = stream.write_all(answer.as_bytes()).await;
            }
        });
        Self { socket, received }
    }

    fn requests(&self) -> Vec<String> {
        self.received.lock().unwrap().clone()
    }
}

impl Drop for Helper {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket);
    }
}

async fn gateway(database: &Database, shares: Option<PathBuf>) -> Router {
    let app = app_with(Config {
        shares,
        ..database.config("127.0.0.1:1".to_owned())
    })
    .await
    .unwrap();
    database.create_account().await;
    app
}

fn request(method: &str, path: &str, cookie: Option<&str>, body: String) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    builder.body(Body::from(body)).unwrap()
}

async fn send(app: &Router, request: Request<Body>) -> (StatusCode, String) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    (status, String::from_utf8_lossy(&body).into_owned())
}

async fn sign_in(app: &Router, password: &str) -> String {
    let body = format!(r#"{{"username":"{USERNAME}","password":"{password}"}}"#);
    let response = app
        .clone()
        .oneshot(request("POST", "/auth/login", None, body))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned()
}

fn password(value: &str) -> String {
    format!(r#"{{"password":"{value}"}}"#)
}

const SHARE: &str = "/auth/account/share-password";

#[tokio::test]
async fn the_password_reaches_samba_only_once_checked() {
    let database = Database::new();
    let helper = Helper::start(&database, "ok\n");
    let app = gateway(&database, Some(helper.socket.clone())).await;

    let (status, _) = send(&app, request("PUT", SHARE, None, password(PASSWORD))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let cookie = sign_in(&app, PASSWORD).await;
    let (status, body) = send(
        &app,
        request("PUT", SHARE, Some(&cookie), password("not the password")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(helper.requests().is_empty());

    let (status, _) = send(
        &app,
        request("PUT", SHARE, Some(&cookie), password(PASSWORD)),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(helper.requests(), [format!("set\n{PASSWORD}\n")]);
}

#[tokio::test]
async fn a_nas_without_shares_says_so() {
    let database = Database::new();
    let app = gateway(&database, None).await;
    let cookie = sign_in(&app, PASSWORD).await;
    let (status, body) = send(
        &app,
        request("PUT", SHARE, Some(&cookie), password(PASSWORD)),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(body.contains("not available"), "{body}");

    let gone = database.0.with_extension("gone");
    let other = Database::new();
    let app = gateway(&other, Some(gone)).await;
    let cookie = sign_in(&app, PASSWORD).await;
    let (status, _) = send(
        &app,
        request("PUT", SHARE, Some(&cookie), password(PASSWORD)),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn what_the_helper_refuses_is_told_apart_from_a_missing_samba() {
    for (answer, expected) in [
        (
            "error: samba is not installed\n",
            StatusCode::SERVICE_UNAVAILABLE,
        ),
        ("error: no user for the shares\n", StatusCode::BAD_GATEWAY),
    ] {
        let database = Database::new();
        let helper = Helper::start(&database, answer);
        let app = gateway(&database, Some(helper.socket.clone())).await;
        let cookie = sign_in(&app, PASSWORD).await;
        let (status, _) = send(
            &app,
            request("PUT", SHARE, Some(&cookie), password(PASSWORD)),
        )
        .await;
        assert_eq!(status, expected, "{answer}");
    }
}

#[tokio::test]
async fn a_new_password_follows_into_samba() {
    let database = Database::new();
    let helper = Helper::start(&database, "ok\n");
    let app = gateway(&database, Some(helper.socket.clone())).await;
    let cookie = sign_in(&app, PASSWORD).await;

    let (status, body) = send(
        &app,
        request("POST", "/auth/confirm", Some(&cookie), password(PASSWORD)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let code = body.split('"').nth(3).unwrap().to_owned();
    let mut change = request(
        "PUT",
        "/auth/account/password",
        Some(&cookie),
        password("another password"),
    );
    change
        .headers_mut()
        .insert("x-nas-confirmation", code.parse().unwrap());
    let (status, _) = send(&app, change).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    for _ in 0..100 {
        if !helper.requests().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(helper.requests(), ["update\nanother password\n"]);
}
