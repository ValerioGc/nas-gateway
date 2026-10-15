use super::*;
use crate::{
    pki::Pki,
    tls::{server_config, TlsListener},
};
use axum::{
    body::{to_bytes, Body},
    middleware,
    routing::get,
    Router,
};
use rustls::{
    pki_types::{CertificateDer, ServerName},
    ClientConfig, RootCertStore,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;
use tower::ServiceExt;

static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn fixture(port: u16) -> (Fixture, Config, Arc<Connection>) {
    let path = std::env::temp_dir().join(format!(
        "nas-https-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&path).unwrap();
    let config = Config {
        database: Some(path.join("gateway.db")),
        pki: Some(path.join("pki")),
        launcher: String::new(),
        ui: None,
        tls: true,
        shares: None,
    };
    let mut connection = Connection::load(&config, port).unwrap();
    Arc::get_mut(&mut connection).unwrap().firewall = false;
    (Fixture(path), config, connection)
}

async fn https(port: u16, pki: &Pki) -> String {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(pki.ca_der().to_vec()))
        .unwrap();
    let client =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let mut tls = TlsConnector::from(Arc::new(client))
        .connect(ServerName::try_from("localhost").unwrap(), stream)
        .await
        .unwrap();
    tls.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut answer = String::new();
    tls.read_to_string(&mut answer).await.unwrap();
    answer
}

#[tokio::test]
async fn changes_the_real_tls_listener_and_persists_without_changing_certificates() {
    let initial = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let old_port = initial.local_addr().unwrap().port();
    let (_fixture, config, connection) = fixture(old_port);
    let pki = Arc::new(Pki::open(config.pki.as_ref().unwrap()).unwrap());
    pki.activate(&["localhost".into()]).unwrap();
    let original = pki.active().unwrap().0.fingerprint;
    let ca = pki.ca_pem();
    let (sender, receiver) = mpsc::channel(1);
    let listener =
        TlsListener::with_updates(initial, server_config(pki.clone()).unwrap(), receiver).unwrap();
    connection
        .attach("127.0.0.1".parse().unwrap(), sender)
        .await;
    let task = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route("/", get(|| async { "ready" })),
        )
        .await
        .unwrap();
    });
    assert!(https(old_port, &pki).await.contains("ready"));

    let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = Settings {
        port: occupied.local_addr().unwrap().port(),
        force: true,
    };
    assert_eq!(
        connection.save(target).await.unwrap_err().0,
        StatusCode::CONFLICT
    );
    assert_eq!(connection.settings().port, old_port);
    assert!(!connection.path.as_ref().unwrap().exists());
    assert!(https(old_port, &pki).await.contains("ready"));

    drop(occupied);
    connection
        .save(target)
        .await
        .unwrap_or_else(|reason| panic!("{}", reason.1));
    assert!(https(target.port, &pki).await.contains("ready"));
    assert!(tokio::net::TcpStream::connect(("127.0.0.1", old_port))
        .await
        .is_err());
    assert_eq!(Connection::load(&config, 443).unwrap().settings(), target);
    assert_eq!(pki.active().unwrap().0.fingerprint, original);
    assert_eq!(pki.ca_pem(), ca);

    // Un errore di persistenza non chiude la porta in funzione e non cambia lo stato.
    std::fs::create_dir(
        connection
            .path
            .as_ref()
            .unwrap()
            .with_extension("connection.new"),
    )
    .unwrap();
    assert_eq!(
        connection
            .save(Settings {
                port: target.port,
                force: false
            })
            .await
            .unwrap_err()
            .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(connection.settings(), target);
    assert!(https(target.port, &pki).await.contains("ready"));
    std::fs::remove_dir(
        connection
            .path
            .as_ref()
            .unwrap()
            .with_extension("connection.new"),
    )
    .unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let custom = rcgen::CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    pki.install_custom(&custom.pem(), &key.serialize_pem())
        .unwrap();
    pki.activate(&["localhost".into()]).unwrap();
    let custom_fingerprint = pki.active().unwrap().0.fingerprint;
    connection
        .save(Settings {
            port: target.port,
            force: false,
        })
        .await
        .unwrap_or_else(|reason| panic!("{}", reason.1));
    assert!(pki.active().unwrap().1);
    assert_eq!(pki.active().unwrap().0.fingerprint, custom_fingerprint);
    assert_eq!(pki.ca_pem(), ca);
    task.abort();
}

#[tokio::test]
async fn redirects_before_access_checks_but_keeps_tls_screen_and_local_health_usable() {
    let (_fixture, _config, connection) = fixture(443);
    connection.current.send_replace(Settings {
        port: 8443,
        force: true,
    });
    let app = Router::new()
        .fallback(|| async { (StatusCode::FORBIDDEN, "access check") })
        .layer(middleware::from_fn_with_state(connection.clone(), redirect));
    for (host, encrypted, screen, ip, path, expected) in [
        (
            "nas:80",
            false,
            false,
            "192.168.1.2",
            "/console?a=b",
            Some("https://nas:8443/console?a=b"),
        ),
        (
            "[::1]:80",
            false,
            false,
            "::1",
            "/console?a=b",
            Some("https://[::1]:8443/console?a=b"),
        ),
        (
            "nas",
            false,
            false,
            "192.168.1.2",
            "/health",
            Some("https://nas:8443/health"),
        ),
        ("nas", false, false, "127.0.0.1", "/health", None),
        ("nas", true, false, "192.168.1.2", "/", None),
        ("localhost", false, true, "127.0.0.1", "/", None),
    ] {
        let mut request = Request::builder()
            .uri(path)
            .header(header::HOST, host)
            .body(Body::empty())
            .unwrap();
        request.extensions_mut().insert(ConnectInfo(Peer {
            address: std::net::SocketAddr::new(ip.parse().unwrap(), 1234),
            certificate: None,
            encrypted,
            screen,
        }));
        let response = app.clone().oneshot(request).await.unwrap();
        if let Some(expected) = expected {
            assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
            assert_eq!(response.headers()[header::LOCATION], expected);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        } else {
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            assert_eq!(
                to_bytes(response.into_body(), 100).await.unwrap(),
                "access check"
            );
        }
    }
    connection.current.send_replace(Settings {
        port: 443,
        force: true,
    });
    let mut request = Request::builder()
        .uri("/console")
        .header(header::HOST, "nas:80")
        .body(Body::empty())
        .unwrap();
    request.extensions_mut().insert(ConnectInfo(Peer {
        address: "192.168.1.2:1234".parse().unwrap(),
        certificate: None,
        encrypted: false,
        screen: false,
    }));
    assert_eq!(
        app.oneshot(request).await.unwrap().headers()[header::LOCATION],
        "https://nas/console"
    );
}
