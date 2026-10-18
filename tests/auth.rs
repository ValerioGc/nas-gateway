use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
    Router,
};
use nas_os_gateway::{
    account::{self, AccountRefused},
    app_with,
};
use tower::ServiceExt;

mod common;
use common::Database;

const ACCOUNT: &str = r#"{"username":"admin","password":"long enough"}"#;

async fn gateway(launcher: String) -> (Router, Database) {
    let database = Database::new();
    let app = app_with(database.config(launcher)).await.unwrap();
    (app, database)
}

async fn with_account() -> (Router, Database) {
    let (app, database) = gateway(bare_launcher().await).await;
    database.create_account().await;
    (app, database)
}

fn login(body: &'static str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap()
}

#[tokio::test]
async fn login_session_and_logout_use_a_private_cookie() {
    let (app, _database) = with_account().await;
    let response = app.clone().oneshot(login(ACCOUNT)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = response.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .to_owned();
    assert!(cookie.contains("HttpOnly; SameSite=Strict"));
    let body = to_bytes(response.into_body(), 1024).await.unwrap();
    let body = String::from_utf8_lossy(&body);

    assert!(body.contains("\"device\":null"));
    assert!(body.contains("\"username\":\"admin\""));
    let cookie = cookie.split(';').next().unwrap();

    let session = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/auth/session")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(session.status(), StatusCode::OK);
    let logout = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/logout")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(logout.status(), StatusCode::NO_CONTENT);
    let expired = app
        .oneshot(
            Request::builder()
                .uri("/auth/session")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(expired.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn malformed_login_and_missing_session_are_rejected() {
    let (app, _database) = with_account().await;
    let login = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"username":"ab","password":"secret"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(login.status(), StatusCode::BAD_REQUEST);
    let session = app
        .oneshot(
            Request::builder()
                .uri("/auth/session")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(session.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_wrong_password_opens_no_session() {
    let (app, _database) = with_account().await;

    let response = app
        .oneshot(login(r#"{"username":"admin","password":"not the one"}"#))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(response.headers().get(header::SET_COOKIE).is_none());
}

#[tokio::test]
async fn no_session_opens_before_the_account_exists() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let closed = listener.local_addr().unwrap().to_string();
    drop(listener);

    let (app, _database) = gateway(closed).await;
    let response = app.oneshot(login(ACCOUNT)).await.unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(response.headers().get(header::SET_COOKIE).is_none());
}

#[tokio::test]
async fn repeated_refusals_make_the_address_wait() {
    let (app, _database) = with_account().await;
    for _ in 0..5 {
        let refused = app
            .clone()
            .oneshot(login(r#"{"username":"admin","password":"not the one"}"#))
            .await
            .unwrap();
        assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
    }

    let waiting = app.oneshot(login(ACCOUNT)).await.unwrap();

    assert_eq!(waiting.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(waiting.headers().get(header::SET_COOKIE).is_none());
}

async fn bare_launcher() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let routes = Router::new().fallback(|request: Request<Body>| async move {
        request
            .headers()
            .get("x-nas-user")
            .map_or("-".to_owned(), |user| user.to_str().unwrap().to_owned())
    });
    tokio::spawn(async move { axum::serve(listener, routes).await.unwrap() });
    address
}

async fn signed_in(app: &Router) -> String {
    let response = app.clone().oneshot(login(ACCOUNT)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn the_wizard_creates_the_one_account_and_the_gateway_checks_it_alone() {
    let (app, database) = gateway(bare_launcher().await).await;
    let config = database.config(String::new());

    account::create(&config, " admin ", "long enough".to_owned())
        .await
        .unwrap();
    assert_eq!(
        account::create(&config, "other", "long enough".to_owned()).await,
        Err(AccountRefused::Exists)
    );
    assert_eq!(
        account::create(
            &Database::new().config(String::new()),
            "admin",
            "short".to_owned()
        )
        .await,
        Err(AccountRefused::Invalid)
    );

    signed_in(&app).await;
    let wrong = app
        .oneshot(login(r#"{"username":"admin","password":"not the one"}"#))
        .await
        .unwrap();
    assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn the_wizard_refuses_names_owned_by_the_system() {
    let database = Database::new();
    for username in ["nas", "root", "nobody"] {
        let refused = account::create(
            &database.config(String::new()),
            username,
            "long enough".to_owned(),
        )
        .await;
        assert_eq!(refused, Err(AccountRefused::Invalid), "{username}");
    }
}

#[tokio::test]
async fn an_account_needs_a_database_on_disk() {
    let mut config = Database::new().config(String::new());
    config.database = None;

    let refused = account::create(&config, "admin", "long enough".to_owned()).await;

    assert!(matches!(refused, Err(AccountRefused::Unavailable(_))));
    assert_eq!(AccountRefused::Invalid.exit_code(), 2);
    assert_eq!(AccountRefused::Exists.exit_code(), 3);
}

#[tokio::test]
async fn no_route_creates_an_account() {
    let (app, _database) = gateway(bare_launcher().await).await;

    let refused = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/setup")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(ACCOUNT))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(refused.status(), StatusCode::NOT_FOUND);
    let response = app.oneshot(login(ACCOUNT)).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_session_outlives_a_restart_and_ends_with_the_logout() {
    let database = Database::new();
    let launcher = bare_launcher().await;
    let config = || database.config(launcher.clone());
    let before = app_with(config()).await.unwrap();
    database.create_account().await;
    let cookie = signed_in(&before).await;
    drop(before);

    let after = app_with(config()).await.unwrap();
    let session = |app: Router| {
        app.oneshot(
            Request::builder()
                .uri("/auth/session")
                .header(header::COOKIE, cookie.as_str())
                .body(Body::empty())
                .unwrap(),
        )
    };
    let alive = session(after.clone()).await.unwrap();
    assert_eq!(alive.status(), StatusCode::OK);
    let body = to_bytes(alive.into_body(), 1024).await.unwrap();
    assert!(String::from_utf8_lossy(&body).contains("\"username\":\"admin\""));

    after
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/logout")
                .header(header::COOKIE, cookie.as_str())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        session(after).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn what_is_forwarded_names_the_user_of_the_session() {
    let (app, _database) = with_account().await;
    let cookie = signed_in(&app).await;

    for path in ["/api/apps", "/apps/photos/"] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .header(header::COOKIE, cookie.as_str())
                    .header("x-nas-user", "root")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        assert_eq!(body, "admin", "{path}");
    }
}

fn policy_request(cookie: Option<&str>, body: Option<&'static str>) -> Request<Body> {
    let mut request = Request::builder().uri("/auth/policy");
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    match body {
        Some(body) => request
            .method("PUT")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body)),
        None => request.body(Body::empty()),
    }
    .unwrap()
}

#[tokio::test]
async fn the_sign_in_policy_is_read_and_changed_only_with_a_session() {
    let (app, _database) = with_account().await;
    let anonymous = app
        .clone()
        .oneshot(policy_request(None, None))
        .await
        .unwrap();
    assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);

    let cookie = signed_in(&app).await;
    let current = app
        .clone()
        .oneshot(policy_request(Some(&cookie), None))
        .await
        .unwrap();
    assert_eq!(current.status(), StatusCode::OK);
    let body = to_bytes(current.into_body(), 1024).await.unwrap();
    assert_eq!(body, r#"{"enabled":true,"attempts":5,"lockMinutes":1}"#);

    for invalid in [
        r#"{"enabled":true,"attempts":0,"lockMinutes":1}"#,
        r#"{"enabled":true,"attempts":5,"lockMinutes":1441}"#,
        r#"{"enabled":true,"attempts":5}"#,
    ] {
        let refused = app
            .clone()
            .oneshot(policy_request(Some(&cookie), Some(invalid)))
            .await
            .unwrap();
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST, "{invalid}");
    }
}

#[tokio::test]
async fn the_address_waits_after_the_attempts_the_policy_allows() {
    let (app, _database) = with_account().await;
    let cookie = signed_in(&app).await;
    let saved = app
        .clone()
        .oneshot(policy_request(
            Some(&cookie),
            Some(r#"{"enabled":true,"attempts":2,"lockMinutes":5}"#),
        ))
        .await
        .unwrap();
    assert_eq!(saved.status(), StatusCode::OK);

    for _ in 0..2 {
        let refused = app
            .clone()
            .oneshot(login(r#"{"username":"admin","password":"not the one"}"#))
            .await
            .unwrap();
        assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
    }
    let waiting = app.oneshot(login(ACCOUNT)).await.unwrap();
    assert_eq!(waiting.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn no_address_waits_when_the_lock_is_off() {
    let (app, _database) = with_account().await;
    let cookie = signed_in(&app).await;
    app.clone()
        .oneshot(policy_request(
            Some(&cookie),
            Some(r#"{"enabled":false,"attempts":1,"lockMinutes":1}"#),
        ))
        .await
        .unwrap();

    for _ in 0..6 {
        let refused = app
            .clone()
            .oneshot(login(r#"{"username":"admin","password":"not the one"}"#))
            .await
            .unwrap();
        assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
    }
    signed_in(&app).await;
}

async fn confirming_launcher() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let routes = Router::new().fallback(|request: Request<Body>| async move {
        let confirmed = request
            .headers()
            .get("x-nas-reauthenticated")
            .map_or("-".to_owned(), |user| user.to_str().unwrap().to_owned());
        let body = to_bytes(request.into_body(), 1024).await.unwrap();
        format!("{confirmed}:{}", String::from_utf8_lossy(&body))
    });
    tokio::spawn(async move { axum::serve(listener, routes).await.unwrap() });
    address
}

fn confirm(cookie: &str, body: &'static str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/auth/confirm")
        .header(header::COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap()
}

async fn code(app: &Router, cookie: &str) -> String {
    let response = app
        .clone()
        .oneshot(confirm(cookie, r#"{"password":"long enough"}"#))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024).await.unwrap();
    let body = String::from_utf8_lossy(&body).into_owned();
    body.split('"').nth(3).unwrap().to_owned()
}

fn confirmed(
    method: &str,
    path: &str,
    cookie: &str,
    code: &str,
    body: &'static str,
) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(path)
        .header(header::COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-nas-confirmation", code)
        .header("x-nas-reauthenticated", "root")
        .body(Body::from(body))
        .unwrap()
}

#[tokio::test]
async fn a_confirmed_request_names_the_user_and_keeps_its_body() {
    let (app, database) = gateway(confirming_launcher().await).await;
    database.create_account().await;
    let cookie = signed_in(&app).await;

    for (method, path, body) in [
        ("POST", "/api/system/reset", ""),
        ("GET", "/api/system/config", ""),
        ("POST", "/api/system/config", r#"{"general":{}}"#),
    ] {
        let code = code(&app, &cookie).await;
        let response = app
            .clone()
            .oneshot(confirmed(method, path, &cookie, &code, body))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{method} {path}");
        let echoed = to_bytes(response.into_body(), 1024).await.unwrap();
        assert_eq!(echoed, format!("admin:{body}"), "{method} {path}");
    }
}

#[tokio::test]
async fn a_code_works_once_and_only_with_the_right_password() {
    let (app, database) = gateway(confirming_launcher().await).await;
    database.create_account().await;
    let cookie = signed_in(&app).await;

    for (body, status) in [
        (r#"{"password":"not the one"}"#, StatusCode::FORBIDDEN),
        (r#"{"password":""}"#, StatusCode::BAD_REQUEST),
        ("{}", StatusCode::BAD_REQUEST),
    ] {
        let refused = app.clone().oneshot(confirm(&cookie, body)).await.unwrap();
        assert_eq!(refused.status(), status, "{body}");
    }

    let code = code(&app, &cookie).await;
    let reset = |code: &str| confirmed("POST", "/api/system/reset", &cookie, code, "");
    assert_eq!(
        app.clone().oneshot(reset(&code)).await.unwrap().status(),
        StatusCode::OK
    );
    for used in [code.as_str(), "", "made up"] {
        assert_eq!(
            app.clone().oneshot(reset(used)).await.unwrap().status(),
            StatusCode::FORBIDDEN,
            "{used}"
        );
    }
}

#[tokio::test]
async fn the_browser_cannot_name_a_confirmation_itself() {
    let (app, database) = gateway(confirming_launcher().await).await;
    database.create_account().await;
    let cookie = signed_in(&app).await;

    let forwarded = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/system/settings")
                .header(header::COOKIE, cookie.as_str())
                .header("x-nas-reauthenticated", "admin")
                .header("x-nas-confirmation", code(&app, &cookie).await)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = to_bytes(forwarded.into_body(), 1024).await.unwrap();
    assert_eq!(body, "-:");

    let anonymous = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/confirm")
                .body(Body::from(r#"{"password":"long enough"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn wrong_confirmations_count_with_the_refused_sign_ins() {
    let (app, database) = gateway(confirming_launcher().await).await;
    database.create_account().await;
    let cookie = signed_in(&app).await;

    let mut last = StatusCode::OK;
    for _ in 0..10 {
        last = app
            .clone()
            .oneshot(confirm(&cookie, r#"{"password":"not the one"}"#))
            .await
            .unwrap()
            .status();
    }
    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
}
