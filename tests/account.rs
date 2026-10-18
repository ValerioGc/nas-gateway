use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
    routing::post,
    Router,
};
use nas_os_gateway::app_with;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

mod common;
use common::{Database, PASSWORD, USERNAME};

#[derive(Clone, Default)]
struct Mailbox {
    sent: Arc<Mutex<Vec<String>>>,
    broken: bool,
}

impl Mailbox {
    fn last_code(&self) -> String {
        let sent = self.sent.lock().unwrap();
        let body = sent.last().expect("a mail");
        body.split("\"code\":\"").nth(1).unwrap()[..6].to_owned()
    }

    fn count(&self) -> usize {
        self.sent.lock().unwrap().len()
    }
}

async fn launcher(mailbox: Mailbox) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let routes = Router::new().route(
        "/internal/mail/code",
        post(move |request: Request<Body>| {
            let mailbox = mailbox.clone();
            async move {
                let body = to_bytes(request.into_body(), 4096).await.unwrap();
                mailbox
                    .sent
                    .lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&body).into_owned());
                if mailbox.broken {
                    StatusCode::SERVICE_UNAVAILABLE
                } else {
                    StatusCode::NO_CONTENT
                }
            }
        }),
    );
    tokio::spawn(async move { axum::serve(listener, routes).await.unwrap() });
    address
}

async fn gateway(mailbox: Mailbox) -> (Router, Database) {
    let database = Database::new();
    let app = app_with(database.config(launcher(mailbox).await))
        .await
        .unwrap();
    database.create_account().await;
    (app, database)
}

fn request(
    method: &str,
    path: &str,
    cookie: Option<&str>,
    code: Option<&str>,
    body: &str,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    if let Some(code) = code {
        builder = builder.header("x-nas-confirmation", code);
    }
    builder.body(Body::from(body.to_owned())).unwrap()
}

async fn send(app: &Router, request: Request<Body>) -> (StatusCode, String) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    (status, String::from_utf8_lossy(&body).into_owned())
}

async fn sign_in(app: &Router, username: &str, password: &str) -> Option<String> {
    let body = format!(r#"{{"username":"{username}","password":"{password}"}}"#);
    let response = app
        .clone()
        .oneshot(request("POST", "/auth/login", None, None, &body))
        .await
        .unwrap();
    (response.status() == StatusCode::OK).then(|| {
        response.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned()
    })
}

async fn confirmation(app: &Router, cookie: &str, password: &str) -> String {
    let body = format!(r#"{{"password":"{password}"}}"#);
    let (status, body) = send(
        app,
        request("POST", "/auth/confirm", Some(cookie), None, &body),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    body.split('"').nth(3).unwrap().to_owned()
}

async fn verified_email(app: &Router, mailbox: &Mailbox, cookie: &str) {
    let code = confirmation(app, cookie, PASSWORD).await;
    let (status, _) = send(
        app,
        request(
            "POST",
            "/auth/account/email",
            Some(cookie),
            Some(&code),
            r#"{"email":"me@example.com"}"#,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let body = format!(r#"{{"code":"{}"}}"#, mailbox.last_code());
    let (status, account) = send(
        app,
        request(
            "POST",
            "/auth/account/email/verify",
            Some(cookie),
            None,
            &body,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(account.contains(r#""email":"me@example.com""#));
}

#[tokio::test]
async fn the_account_is_read_only_with_a_session() {
    let (app, _database) = gateway(Mailbox::default()).await;
    let (status, _) = send(&app, request("GET", "/auth/account", None, None, "")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let cookie = sign_in(&app, USERNAME, PASSWORD).await.unwrap();
    let (status, body) = send(
        &app,
        request("GET", "/auth/account", Some(&cookie), None, ""),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        r#"{"username":"admin","email":null,"recovery":false}"#
    );
}

#[tokio::test]
async fn a_change_needs_the_password_again() {
    let (app, _database) = gateway(Mailbox::default()).await;
    let cookie = sign_in(&app, USERNAME, PASSWORD).await.unwrap();
    for (method, path, body) in [
        ("PUT", "/auth/account/username", r#"{"username":"keeper"}"#),
        (
            "PUT",
            "/auth/account/password",
            r#"{"password":"another password"}"#,
        ),
        (
            "POST",
            "/auth/account/email",
            r#"{"email":"me@example.com"}"#,
        ),
        ("DELETE", "/auth/account/email", ""),
        ("PUT", "/auth/account/recovery", r#"{"enabled":true}"#),
    ] {
        let (status, _) = send(
            &app,
            request(method, path, Some(&cookie), Some("forged"), body),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method} {path}");
    }
}

#[tokio::test]
async fn the_username_changes_and_the_session_follows_it() {
    let (app, _database) = gateway(Mailbox::default()).await;
    let cookie = sign_in(&app, USERNAME, PASSWORD).await.unwrap();
    let code = confirmation(&app, &cookie, PASSWORD).await;
    let (status, _) = send(
        &app,
        request(
            "PUT",
            "/auth/account/username",
            Some(&cookie),
            Some(&code),
            r#"{"username":"root"}"#,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, body) = send(
        &app,
        request(
            "PUT",
            "/auth/account/username",
            Some(&cookie),
            Some(&code),
            r#"{"username":"keeper"}"#,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains(r#""username":"keeper""#));

    let (_, session) = send(
        &app,
        request("GET", "/auth/session", Some(&cookie), None, ""),
    )
    .await;
    assert!(session.contains(r#""username":"keeper""#));
    assert!(sign_in(&app, USERNAME, PASSWORD).await.is_none());
    assert!(sign_in(&app, "keeper", PASSWORD).await.is_some());
}

#[tokio::test]
async fn a_new_password_closes_the_other_sessions() {
    let (app, _database) = gateway(Mailbox::default()).await;
    let cookie = sign_in(&app, USERNAME, PASSWORD).await.unwrap();
    let other = sign_in(&app, USERNAME, PASSWORD).await.unwrap();
    let code = confirmation(&app, &cookie, PASSWORD).await;
    let (status, _) = send(
        &app,
        request(
            "PUT",
            "/auth/account/password",
            Some(&cookie),
            Some(&code),
            r#"{"password":"short"}"#,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _) = send(
        &app,
        request(
            "PUT",
            "/auth/account/password",
            Some(&cookie),
            Some(&code),
            r#"{"password":"another password"}"#,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let alive = |cookie: String| {
        let app = app.clone();
        async move {
            send(
                &app,
                request("GET", "/auth/session", Some(&cookie), None, ""),
            )
            .await
            .0
        }
    };
    assert_eq!(alive(cookie).await, StatusCode::OK);
    assert_eq!(alive(other).await, StatusCode::UNAUTHORIZED);
    assert!(sign_in(&app, USERNAME, "another password").await.is_some());
}

#[tokio::test]
async fn a_recovery_address_counts_once_its_code_comes_back() {
    let mailbox = Mailbox::default();
    let (app, _database) = gateway(mailbox.clone()).await;
    let cookie = sign_in(&app, USERNAME, PASSWORD).await.unwrap();
    let code = confirmation(&app, &cookie, PASSWORD).await;
    let (status, _) = send(
        &app,
        request(
            "POST",
            "/auth/account/email",
            Some(&cookie),
            Some(&code),
            r#"{"email":"not an address"}"#,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _) = send(
        &app,
        request(
            "POST",
            "/auth/account/email",
            Some(&cookie),
            Some(&code),
            r#"{"email":"me@example.com"}"#,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let mail = mailbox.sent.lock().unwrap().last().unwrap().clone();
    assert!(mail.contains(r#""to":"me@example.com""#) && mail.contains(r#""purpose":"verify""#));
    let (_, account) = send(
        &app,
        request("GET", "/auth/account", Some(&cookie), None, ""),
    )
    .await;
    assert!(account.contains(r#""email":null"#), "not verified yet");

    let right = mailbox.last_code();
    let wrong = if right == "000000" {
        "111111"
    } else {
        "000000"
    };
    let (status, _) = send(
        &app,
        request(
            "POST",
            "/auth/account/email/verify",
            Some(&cookie),
            None,
            &format!(r#"{{"code":"{wrong}"}}"#),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = send(
        &app,
        request(
            "POST",
            "/auth/account/email/verify",
            Some(&cookie),
            None,
            &format!(r#"{{"code":"{right}"}}"#),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = send(
        &app,
        request(
            "POST",
            "/auth/account/email/verify",
            Some(&cookie),
            None,
            &format!(r#"{{"code":"{right}"}}"#),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "a code works once");

    let code = confirmation(&app, &cookie, PASSWORD).await;
    let (status, _) = send(
        &app,
        request(
            "DELETE",
            "/auth/account/email",
            Some(&cookie),
            Some(&code),
            "",
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, account) = send(
        &app,
        request("GET", "/auth/account", Some(&cookie), None, ""),
    )
    .await;
    assert!(account.contains(r#""email":null"#));
}

#[tokio::test]
async fn a_failed_mail_is_said() {
    let mailbox = Mailbox {
        broken: true,
        ..Mailbox::default()
    };
    let (app, _database) = gateway(mailbox).await;
    let cookie = sign_in(&app, USERNAME, PASSWORD).await.unwrap();
    let code = confirmation(&app, &cookie, PASSWORD).await;
    let (status, body) = send(
        &app,
        request(
            "POST",
            "/auth/account/email",
            Some(&cookie),
            Some(&code),
            r#"{"email":"me@example.com"}"#,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert!(body.contains("could not be sent"));
}

async fn switch_recovery(app: &Router, cookie: &str, enabled: bool) {
    let code = confirmation(app, cookie, PASSWORD).await;
    let body = format!(r#"{{"enabled":{enabled}}}"#);
    let (status, account) = send(
        app,
        request(
            "PUT",
            "/auth/account/recovery",
            Some(cookie),
            Some(&code),
            &body,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(account.contains(&format!(r#""recovery":{enabled}"#)));
}

#[tokio::test]
async fn a_code_sent_before_the_reset_was_turned_off_is_no_longer_good() {
    let mailbox = Mailbox::default();
    let (app, _database) = gateway(mailbox.clone()).await;
    let cookie = sign_in(&app, USERNAME, PASSWORD).await.unwrap();
    verified_email(&app, &mailbox, &cookie).await;
    switch_recovery(&app, &cookie, true).await;
    send(
        &app,
        request(
            "POST",
            "/auth/recovery",
            None,
            None,
            r#"{"username":"admin"}"#,
        ),
    )
    .await;
    let code = mailbox.last_code();
    switch_recovery(&app, &cookie, false).await;
    let body = format!(r#"{{"username":"admin","code":"{code}","password":"a new password"}}"#);
    let (status, _) = send(
        &app,
        request("POST", "/auth/recovery/reset", None, None, &body),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(sign_in(&app, USERNAME, PASSWORD).await.is_some());
}

#[tokio::test]
async fn the_password_is_reset_with_the_code_sent_to_the_verified_address() {
    let mailbox = Mailbox::default();
    let (app, _database) = gateway(mailbox.clone()).await;
    let cookie = sign_in(&app, USERNAME, PASSWORD).await.unwrap();

    let (status, _) = send(
        &app,
        request(
            "POST",
            "/auth/recovery",
            None,
            None,
            r#"{"username":"admin"}"#,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(mailbox.count(), 0);

    verified_email(&app, &mailbox, &cookie).await;
    let (_, offer) = send(&app, request("GET", "/auth/recovery", None, None, "")).await;
    assert_eq!(offer, r#"{"enabled":false}"#);
    // A verified address alone is not enough: the reset by mail is off until turned on.
    let (status, _) = send(
        &app,
        request(
            "POST",
            "/auth/recovery",
            None,
            None,
            r#"{"username":"admin"}"#,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(mailbox.count(), 1, "only the verification");
    switch_recovery(&app, &cookie, true).await;
    let (_, offer) = send(&app, request("GET", "/auth/recovery", None, None, "")).await;
    assert_eq!(offer, r#"{"enabled":true}"#);

    for username in ["admin", "nobody"] {
        let body = format!(r#"{{"username":"{username}"}}"#);
        let (status, _) = send(&app, request("POST", "/auth/recovery", None, None, &body)).await;
        assert_eq!(status, StatusCode::ACCEPTED);
    }
    assert_eq!(mailbox.count(), 2, "one verification, one reset");
    let mail = mailbox.sent.lock().unwrap().last().unwrap().clone();
    assert!(mail.contains(r#""purpose":"reset""#));
    let (_, _) = send(
        &app,
        request(
            "POST",
            "/auth/recovery",
            None,
            None,
            r#"{"username":"admin"}"#,
        ),
    )
    .await;
    assert_eq!(mailbox.count(), 2, "not sent again within a minute");

    let code = mailbox.last_code();
    let reset = |code: String, password: &'static str| {
        request(
            "POST",
            "/auth/recovery/reset",
            None,
            None,
            &format!(r#"{{"username":"admin","code":"{code}","password":"{password}"}}"#),
        )
    };
    let (status, _) = send(&app, reset(code.clone(), "short")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let wrong = if code == "000000" { "111111" } else { "000000" };
    let (status, _) = send(&app, reset(wrong.to_owned(), "a new password")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = send(&app, reset(code, "a new password")).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, _) = send(
        &app,
        request("GET", "/auth/session", Some(&cookie), None, ""),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "every session is closed");
    assert!(sign_in(&app, USERNAME, "a new password").await.is_some());
}

#[tokio::test]
async fn wrong_reset_codes_make_the_address_wait() {
    let (app, _database) = gateway(Mailbox::default()).await;
    let body = r#"{"username":"admin","code":"123456","password":"a new password"}"#;
    for _ in 0..5 {
        let (status, _) = send(
            &app,
            request("POST", "/auth/recovery/reset", None, None, body),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    let (status, _) = send(
        &app,
        request("POST", "/auth/recovery/reset", None, None, body),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    let (status, _) = send(
        &app,
        request(
            "POST",
            "/auth/recovery",
            None,
            None,
            r#"{"username":"admin"}"#,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}
