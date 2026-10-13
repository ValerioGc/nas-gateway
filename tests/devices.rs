use axum::{
    body::{to_bytes, Body},
    extract::ConnectInfo,
    http::{header, Request, StatusCode},
    Router,
};
use nas_os_gateway::{app_with, tls::Peer};
use tower::ServiceExt;

mod common;
use common::Database;

const ACCOUNT: &str = r#"{"username":"admin","password":"long enough"}"#;

async fn gateway() -> (Router, Database) {
    let database = Database::new();
    let app = app_with(database.config("127.0.0.1:1".to_owned()))
        .await
        .unwrap();
    database.create_account().await;
    (app, database)
}

/// A request on a connection that showed the certificate `certificate`, or none.
fn on(mut request: Request<Body>, certificate: Option<&str>) -> Request<Body> {
    request.extensions_mut().insert(ConnectInfo(Peer {
        address: "192.168.1.20:50000".parse().unwrap(),
        certificate: certificate.map(str::to_owned),
        encrypted: true,
        screen: false,
    }));
    request
}

/// A request on the port of the monitor connected to the NAS.
fn screen(mut request: Request<Body>) -> Request<Body> {
    request.extensions_mut().insert(ConnectInfo(Peer {
        address: "127.0.0.1:50000".parse().unwrap(),
        certificate: None,
        encrypted: false,
        screen: true,
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

/// Signs in on a connection with `certificate`, and answers the cookie and what the login said.
async fn sign_in(app: &Router, certificate: Option<&str>) -> (String, String) {
    let login = Request::builder()
        .method("POST")
        .uri("/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(ACCOUNT))
        .unwrap();
    let response = app.clone().oneshot(on(login, certificate)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = response.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let body = to_bytes(response.into_body(), 1024).await.unwrap();
    (cookie, String::from_utf8_lossy(&body).into_owned())
}

async fn code(app: &Router, cookie: &str, certificate: Option<&str>) -> String {
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
            certificate,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body.split('"').nth(3).unwrap().to_owned()
}

/// The value of `"key":"..."` in a JSON text.
fn field<'a>(body: &'a str, key: &str) -> &'a str {
    let start = body.find(&format!("\"{key}\":\"")).unwrap() + key.len() + 4;
    &body[start..start + body[start..].find('"').unwrap()]
}

fn number(body: &str, key: &str) -> i64 {
    let start = body.find(&format!("\"{key}\":")).unwrap() + key.len() + 3;
    body[start..]
        .split(|character: char| !character.is_ascii_digit())
        .next()
        .unwrap()
        .parse()
        .unwrap()
}

/// A new device, issued with the password confirmed: its id and the fingerprint of its certificate.
async fn new_device(
    app: &Router,
    cookie: &str,
    certificate: Option<&str>,
    body: &str,
) -> (i64, String) {
    let code = code(app, cookie, certificate).await;
    let (status, created) = send(
        app,
        on(
            request("POST", "/auth/devices", cookie, Some(&code), body),
            certificate,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    (
        number(&created, "id"),
        field(&created, "fingerprint").to_owned(),
    )
}

#[tokio::test]
async fn a_device_is_issued_only_with_the_password_confirmed() {
    let (app, _database) = gateway().await;
    let (cookie, _) = sign_in(&app, None).await;
    let body = r#"{"name":"Notebook","icon":"laptop"}"#;

    let (status, _) = send(&app, request("POST", "/auth/devices", &cookie, None, body)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let code = code(&app, &cookie, None).await;
    let (status, created) = send(
        &app,
        request("POST", "/auth/devices", &cookie, Some(&code), body),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(field(&created, "fileName"), "nas-os-notebook.p12");
    assert_eq!(field(&created, "password").len(), 20);
    assert!(field(&created, "file").len() > 100);
    assert_eq!(field(&created, "state"), "pending");
    assert_eq!(field(&created, "icon"), "laptop");

    let (_, listed) = send(&app, request("GET", "/auth/devices", &cookie, None, "")).await;
    assert!(listed.contains("\"name\":\"Notebook\""));
    assert!(
        !listed.contains("password"),
        "a password is shown once only"
    );
}

#[tokio::test]
async fn what_is_not_a_device_is_refused() {
    let (app, _database) = gateway().await;
    let (cookie, _) = sign_in(&app, None).await;

    for body in [
        r#"{"name":"","icon":"laptop"}"#,
        r#"{"name":"Tv","icon":"toaster"}"#,
        r#"{"name":"Tv"}"#,
        r#"{"name":"Tv","icon":"tv","extra":1}"#,
    ] {
        let code = code(&app, &cookie, None).await;
        let (status, _) = send(
            &app,
            request("POST", "/auth/devices", &cookie, Some(&code), body),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    }
    let (status, _) = send(
        &app,
        request("POST", "/auth/devices/abc/revoke", &cookie, None, ""),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = send(
        &app,
        request("POST", "/auth/devices/99/revoke", &cookie, None, ""),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = send(
        &app,
        request("GET", "/auth/devices", "nas_session=none", None, ""),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_device_is_renamed_renewed_revoked_and_removed() {
    let (app, _database) = gateway().await;
    let (cookie, _) = sign_in(&app, None).await;
    let (id, first) = new_device(&app, &cookie, None, r#"{"name":"Tv","icon":"tv"}"#).await;

    let (status, renamed) = send(
        &app,
        request(
            "PUT",
            &format!("/auth/devices/{id}"),
            &cookie,
            None,
            r#"{"name":"Tv sala","icon":"projector"}"#,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(renamed.contains("\"name\":\"Tv sala\"") && renamed.contains("\"icon\":\"projector\""));

    let code = code(&app, &cookie, None).await;
    let (status, renewed) = send(
        &app,
        request(
            "POST",
            &format!("/auth/devices/{id}/renew"),
            &cookie,
            Some(&code),
            "",
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ne!(field(&renewed, "fingerprint"), first);
    assert_eq!(field(&renewed, "state"), "pending");
    assert_eq!(field(&renewed, "fileName"), "nas-os-tv-sala.p12");

    let (status, revoked) = send(
        &app,
        request(
            "POST",
            &format!("/auth/devices/{id}/revoke"),
            &cookie,
            None,
            "",
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(field(&revoked, "state"), "revoked");

    let (status, _) = send(
        &app,
        request("DELETE", &format!("/auth/devices/{id}"), &cookie, None, ""),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, listed) = send(&app, request("GET", "/auth/devices", &cookie, None, "")).await;
    assert_eq!(listed, "[]");
}

#[tokio::test]
async fn mtls_turns_on_only_from_a_device_with_a_certificate_and_then_keeps_the_others_out() {
    let (app, _database) = gateway().await;
    let (cookie, _) = sign_in(&app, None).await;
    let (id, certificate) = new_device(
        &app,
        &cookie,
        None,
        r#"{"name":"Desktop","icon":"desktop"}"#,
    )
    .await;
    let on_off = |enabled: bool| format!("{{\"enabled\":{enabled}}}");

    // Without a certificate of its own, turning it on would shut this device out.
    let code_without = code(&app, &cookie, None).await;
    let (status, _) = send(
        &app,
        request(
            "PUT",
            "/auth/mtls",
            &cookie,
            Some(&code_without),
            &on_off(true),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    let mine = Some(certificate.as_str());
    let code_with = code(&app, &cookie, mine).await;
    let (status, state) = send(
        &app,
        on(
            request(
                "PUT",
                "/auth/mtls",
                &cookie,
                Some(&code_with),
                &on_off(true),
            ),
            mine,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{state}");
    assert!(state.contains("\"enabled\":true") && state.contains("\"current\":{"));

    // Nobody without a certificate gets further than a page that says why.
    let (status, page) = send(&app, request("GET", "/auth/devices", &cookie, None, "")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(page.contains("Certificato del dispositivo richiesto"));
    let stranger = "0".repeat(64);
    let (status, _) = send(
        &app,
        on(
            request("GET", "/auth/session", &cookie, None, ""),
            Some(&stranger),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    for open in ["/health", "/auth/ca.crt"] {
        let (status, _) = send(&app, request("GET", open, "", None, "")).await;
        assert_eq!(status, StatusCode::OK, "{open}");
    }

    // At the machine, on the monitor connected to it, no certificate is asked: the session is.
    let (status, session) = send(
        &app,
        screen(request("GET", "/auth/session", &cookie, None, "")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{session}");
    let (status, _) = send(&app, screen(request("GET", "/auth/session", "", None, ""))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // The device itself goes on, and cannot revoke what lets it in.
    let (status, listed) = send(
        &app,
        on(request("GET", "/auth/devices", &cookie, None, ""), mine),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(listed.contains("\"current\":true"));
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
            mine,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    // A second device, revoked from the first, is out.
    let (other, theirs) =
        new_device(&app, &cookie, mine, r#"{"name":"Phone","icon":"phone"}"#).await;
    let (status, _) = send(
        &app,
        on(
            request("GET", "/auth/session", &cookie, None, ""),
            Some(&theirs),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    send(
        &app,
        on(
            request(
                "POST",
                &format!("/auth/devices/{other}/revoke"),
                &cookie,
                None,
                "",
            ),
            mine,
        ),
    )
    .await;
    let (status, _) = send(
        &app,
        on(
            request("GET", "/auth/session", &cookie, None, ""),
            Some(&theirs),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Off again: everybody is back.
    let code_off = code(&app, &cookie, mine).await;
    send(
        &app,
        on(
            request(
                "PUT",
                "/auth/mtls",
                &cookie,
                Some(&code_off),
                &on_off(false),
            ),
            mine,
        ),
    )
    .await;
    let (status, _) = send(&app, request("GET", "/auth/session", &cookie, None, "")).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn the_first_sign_in_with_a_new_certificate_makes_it_the_device_s() {
    let (app, _database) = gateway().await;
    let (cookie, _) = sign_in(&app, None).await;
    let (_, certificate) =
        new_device(&app, &cookie, None, r#"{"name":"Studio","icon":"desktop"}"#).await;

    let (_, said) = sign_in(&app, Some(&certificate)).await;
    assert!(said.contains("\"device\":\"Studio\""));
    let (_, listed) = send(&app, request("GET", "/auth/devices", &cookie, None, "")).await;
    assert_eq!(field(&listed, "state"), "active");
    assert!(listed.contains("\"activatedAt\":1"));
}

#[tokio::test]
async fn the_authority_is_handed_to_anybody_who_asks() {
    let (app, _database) = gateway().await;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/auth/ca.crt")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::CONTENT_DISPOSITION],
        "attachment; filename=\"nas-os-ca.crt\""
    );
    let body = to_bytes(response.into_body(), 8192).await.unwrap();
    assert!(String::from_utf8_lossy(&body).starts_with("-----BEGIN CERTIFICATE-----"));
}
