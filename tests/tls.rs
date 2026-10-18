use axum::{extract::ConnectInfo, routing::get, Router};
use nas_os_gateway::{
    pki::{DeviceCredential, Pki},
    tls::{server_config, Peer, TlsListener},
};
use p12_keystore::{KeyStore, Pkcs12ImportPolicy};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
    ClientConfig, RootCertStore,
};
use std::{net::SocketAddr, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::TlsConnector;

mod common;
use common::Database;

async fn serve(pki: &Arc<Pki>) -> SocketAddr {
    pki.activate(&["localhost".to_owned(), "127.0.0.1".to_owned()])
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let secure = TlsListener::new(listener, server_config(pki.clone()).unwrap()).unwrap();
    let routes = Router::new().route(
        "/who",
        get(|ConnectInfo(peer): ConnectInfo<Peer>| async move {
            assert!(peer.encrypted);
            peer.certificate.unwrap_or_else(|| "none".to_owned())
        }),
    );
    tokio::spawn(async move {
        axum::serve(secure, routes.into_make_service_with_connect_info::<Peer>())
            .await
            .unwrap();
    });
    address
}

fn client(pki: &Pki, device: Option<&DeviceCredential>) -> ClientConfig {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(pki.ca_der().to_vec()))
        .unwrap();
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots);
    match device {
        None => builder.with_no_client_auth(),
        Some(device) => {
            let store =
                KeyStore::from_pkcs12(&device.p12, &device.password, Pkcs12ImportPolicy::Strict)
                    .unwrap();
            let (_, chain) = store.private_key_chain().unwrap();
            let certificates = chain
                .certs()
                .iter()
                .map(|certificate| CertificateDer::from(certificate.as_der().to_vec()))
                .collect();
            let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(chain.key().as_der().to_vec()));
            builder.with_client_auth_cert(certificates, key).unwrap()
        }
    }
}

async fn ask(address: SocketAddr, config: ClientConfig) -> Result<String, String> {
    ask_as(address, config, "localhost").await
}

async fn ask_as(address: SocketAddr, config: ClientConfig, name: &str) -> Result<String, String> {
    let stream = TcpStream::connect(address).await.unwrap();
    let mut tls = TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from(name.to_owned()).unwrap(), stream)
        .await
        .map_err(|error| error.to_string())?;
    tls.write_all(b"GET /who HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .map_err(|error| error.to_string())?;
    let mut answer = String::new();
    tls.read_to_string(&mut answer)
        .await
        .map_err(|error| error.to_string())?;
    Ok(answer
        .rsplit("\r\n\r\n")
        .next()
        .unwrap_or_default()
        .to_owned())
}

#[tokio::test]
async fn the_gateway_knows_a_device_by_its_certificate_and_lets_the_others_connect_unnamed() {
    let database = Database::new();
    let pki = Arc::new(Pki::open(&database.pki()).unwrap());
    let address = serve(&pki).await;
    let device = pki.issue_device("Notebook").unwrap();

    assert_eq!(
        ask(address, client(&pki, Some(&device))).await.unwrap(),
        device.fingerprint
    );
    assert_eq!(ask(address, client(&pki, None)).await.unwrap(), "none");
}

#[tokio::test]
async fn a_browser_that_trusts_the_authority_accepts_the_nas_by_its_names_and_addresses_only() {
    let database = Database::new();
    let pki = Arc::new(Pki::open(&database.pki()).unwrap());
    let address = serve(&pki).await;

    let trusted = || trusting(pki.ca_der());
    assert_eq!(
        ask_as(address, trusted(), "127.0.0.1").await.unwrap(),
        "none"
    );
    assert_eq!(
        ask_as(address, trusted(), "localhost").await.unwrap(),
        "none"
    );
    let refused = ask_as(address, trusted(), "other.example")
        .await
        .unwrap_err();
    assert!(refused.to_lowercase().contains("certificate"), "{refused}");
}

#[tokio::test]
async fn a_certificate_of_another_authority_does_not_get_through_the_handshake() {
    let ours = Database::new();
    let theirs = Database::new();
    let pki = Arc::new(Pki::open(&ours.pki()).unwrap());
    let foreign = Pki::open(&theirs.pki()).unwrap();
    let address = serve(&pki).await;
    let intruder = foreign.issue_device("Intruder").unwrap();

    assert!(ask(address, client(&pki, Some(&intruder))).await.is_err());
}

#[tokio::test]
async fn a_browser_that_does_not_trust_the_authority_is_not_served_unknowingly() {
    let database = Database::new();
    let other = Database::new();
    let pki = Arc::new(Pki::open(&database.pki()).unwrap());
    let stranger = Pki::open(&other.pki()).unwrap();
    let address = serve(&pki).await;

    let refused = ask(address, client(&stranger, None)).await.unwrap_err();
    assert!(refused.to_lowercase().contains("certificate"), "{refused}");
}

fn trusting(root: &[u8]) -> ClientConfig {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(root.to_vec())).unwrap();
    ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth()
}

#[tokio::test]
async fn a_certificate_brought_by_the_user_answers_the_next_connection_without_a_restart() {
    let database = Database::new();
    let pki = Arc::new(Pki::open(&database.pki()).unwrap());
    let address = serve(&pki).await;
    assert!(ask(address, client(&pki, None)).await.is_ok());

    let key = rcgen::KeyPair::generate().unwrap();
    let custom = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    pki.install_custom(&custom.pem(), &key.serialize_pem())
        .unwrap();
    pki.activate(&["localhost".to_owned()]).unwrap();

    assert_eq!(ask(address, trusting(custom.der())).await.unwrap(), "none");
    assert!(
        ask(address, client(&pki, None)).await.is_err(),
        "no longer the NAS's own"
    );

    pki.remove_custom().unwrap();
    pki.activate(&["localhost".to_owned()]).unwrap();
    assert!(ask(address, client(&pki, None)).await.is_ok());
}
