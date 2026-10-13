//! The executable with every listener enabled: HTTP stays usable behind a forwarded port, and the
//! monitor connected to the NAS has its own port on the loopback.
use common::{Database, PASSWORD, USERNAME};
use std::{net::TcpListener, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    process::Command,
};

mod common;

async fn request(port: u16, method: &str, path: &str, body: &str, cookie: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream.write_all(format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost:8080\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCookie: {cookie}\r\nX-Forwarded-Proto: https\r\n\r\n{body}", body.len()
    ).as_bytes()).await.unwrap();
    let mut response = String::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_string(&mut response))
        .await
        .unwrap()
        .unwrap();
    response
}

#[tokio::test]
async fn http_serves_the_interface_and_password_session_even_when_https_is_enabled() {
    let database = Database::new();
    database.create_account().await;
    let ui = database.pki().join("ui");
    std::fs::create_dir_all(&ui).unwrap();
    std::fs::write(ui.join("index.html"), "<html>NAS launcher</html>").unwrap();
    let plain = TcpListener::bind("127.0.0.1:0").unwrap();
    let secure = TcpListener::bind("127.0.0.1:0").unwrap();
    let monitor = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = plain.local_addr().unwrap().port();
    let tls_port = secure.local_addr().unwrap().port();
    let screen_port = monitor.local_addr().unwrap().port();
    drop((plain, secure, monitor));
    let mut server = Command::new(env!("CARGO_BIN_EXE_nas-os-gateway"))
        .env("GATEWAY_DB_PATH", &database.0)
        .env("GATEWAY_PKI_DIR", database.pki())
        .env("GATEWAY_UI_DIR", &ui)
        .env("GATEWAY_ADDRESS", "127.0.0.1")
        .env("GATEWAY_PORT", port.to_string())
        .env("GATEWAY_TLS_PORT", tls_port.to_string())
        .env("GATEWAY_SCREEN_PORT", screen_port.to_string())
        .env("GATEWAY_LAUNCHER", "127.0.0.1:1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            assert!(
                server.try_wait().unwrap().is_none(),
                "gateway exited before listening"
            );
            if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();

    let page = request(port, "GET", "/", "", "").await;
    assert!(page.starts_with("HTTP/1.1 200"), "{page}");
    assert!(page.ends_with("<html>NAS launcher</html>"));
    assert!(!page.to_ascii_lowercase().contains("\r\nlocation:"));
    let account = format!(r#"{{"username":"{USERNAME}","password":"{PASSWORD}"}}"#);
    let login = request(port, "POST", "/auth/login", &account, "").await;
    assert!(login.starts_with("HTTP/1.1 200"));
    let cookie = login
        .lines()
        .find(|line| line.starts_with("set-cookie:"))
        .unwrap();
    assert!(
        !cookie.contains("Secure"),
        "HTTP must not receive a TLS-only session cookie"
    );
    let cookie = cookie
        .trim_start_matches("set-cookie: ")
        .split(';')
        .next()
        .unwrap();
    let session = request(port, "GET", "/auth/session", "", cookie).await;
    assert!(session.starts_with("HTTP/1.1 200"));
    assert!(session.contains(r#""authenticated":true"#));
    let mtls = request(port, "GET", "/auth/mtls", "", cookie).await;
    assert!(mtls.contains(r#""enabled":false"#) && mtls.contains(r#""available":true"#));

    // The monitor connected to the NAS: the same interface, and the same password.
    let screen = request(screen_port, "GET", "/", "", "").await;
    assert!(screen.ends_with("<html>NAS launcher</html>"), "{screen}");
    let refused = request(screen_port, "GET", "/auth/session", "", "").await;
    assert!(refused.contains(r#""authenticated":false"#) || refused.starts_with("HTTP/1.1 401"));
    let signed_in = request(screen_port, "POST", "/auth/login", &account, "").await;
    assert!(signed_in.starts_with("HTTP/1.1 200"), "{signed_in}");
    server.kill().await.unwrap();
    server.wait().await.unwrap();
}

#[tokio::test]
async fn the_executable_says_its_version_for_the_updates_of_the_launcher() {
    let output = Command::new(env!("CARGO_BIN_EXE_nas-os-gateway"))
        .arg("--version")
        .stdin(Stdio::null())
        .output()
        .await
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        env!("CARGO_PKG_VERSION")
    );
}
