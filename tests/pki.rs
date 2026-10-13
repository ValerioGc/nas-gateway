use nas_os_gateway::{
    base64,
    pki::{fingerprint, Pki},
};
use p12_keystore::{KeyStore, Pkcs12ImportPolicy};
use std::{os::unix::fs::PermissionsExt, path::PathBuf};

mod common;
use common::Database;

fn directory() -> (Database, PathBuf) {
    let database = Database::new();
    let path = database.pki();
    (database, path)
}

#[test]
fn the_authority_is_made_once_and_its_key_is_the_gateway_s_alone() {
    let (_database, path) = directory();
    let first = Pki::open(&path).expect("authority");

    let mode = std::fs::metadata(path.join("ca.key"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert!(first.ca_pem().starts_with("-----BEGIN CERTIFICATE-----"));

    let again = Pki::open(&path).expect("the same authority");
    assert_eq!(again.ca_der(), first.ca_der());
}

#[test]
fn the_certificate_of_the_nas_changes_only_with_its_names() {
    let (_database, path) = directory();
    let pki = Pki::open(&path).unwrap();
    let names = vec![
        "nas".to_owned(),
        "nas.local".to_owned(),
        "127.0.0.1".to_owned(),
    ];

    let first = pki.server(&names).unwrap();
    assert_eq!(first.chain.len(), 2, "the certificate and the authority");
    assert_eq!(first.chain[1], pki.ca_der());
    assert_eq!(pki.server(&names).unwrap().chain[0], first.chain[0]);

    let renamed = pki.server(&["cellar".to_owned()]).unwrap();
    assert_ne!(renamed.chain[0], first.chain[0]);
}

#[test]
fn a_device_gets_its_own_certificate_in_a_file_only_its_password_opens() {
    let (_database, path) = directory();
    let pki = Pki::open(&path).unwrap();

    let laptop = pki.issue_device("Laptop di casa").unwrap();
    let phone = pki.issue_device("Telefono").unwrap();
    assert_ne!(laptop.fingerprint, phone.fingerprint);
    assert_eq!(laptop.password.len(), 20);
    assert!(laptop.expires_at > laptop.issued_at);

    let store = KeyStore::from_pkcs12(&laptop.p12, &laptop.password, Pkcs12ImportPolicy::Strict)
        .expect("the file opens with its password");
    let (_, chain) = store
        .private_key_chain()
        .expect("a key and its certificates");
    assert_eq!(fingerprint(chain.certs()[0].as_der()), laptop.fingerprint);
    assert!(chain.certs()[0].subject().contains("Laptop di casa"));
    assert!(chain
        .certs()
        .iter()
        .any(|certificate| certificate.as_der() == pki.ca_der()));

    assert!(
        KeyStore::from_pkcs12(&laptop.p12, "not the password", Pkcs12ImportPolicy::Strict).is_err()
    );
}

#[test]
fn base64_goes_there_and_back() {
    for bytes in [
        b"".as_slice(),
        b"f",
        b"fo",
        b"foo",
        b"foob",
        &[0, 255, 128, 7, 3],
    ] {
        assert_eq!(base64::decode(&base64::encode(bytes)).unwrap(), bytes);
    }
    assert_eq!(base64::encode(b"foobar"), "Zm9vYmFy");
    assert_eq!(base64::decode("Zm9v\nYmFy").unwrap(), b"foobar");
    assert!(base64::decode("abc").is_none());
    assert!(base64::decode("ab!d").is_none());
}

#[test]
fn only_names_a_certificate_can_be_issued_for_are_added() {
    for name in [
        "nas.example.org",
        "*.example.org",
        "10.8.0.2",
        "fe80::1",
        "nas",
    ] {
        assert!(nas_os_gateway::pki::valid_name(name), "{name}");
    }
    for name in [
        "",
        "bad name",
        "-nas.example",
        "nas..example",
        "a/b",
        "300.1.1.1",
        &"x".repeat(64),
    ] {
        assert!(!nas_os_gateway::pki::valid_name(name), "{name}");
    }

    let (_database, path) = directory();
    let pki = Pki::open(&path).unwrap();
    assert!(pki.extra_names().is_empty());
    pki.set_extra_names(&["nas.example.org".to_owned()])
        .unwrap();
    assert_eq!(pki.extra_names(), ["nas.example.org"]);
    assert!(pki.set_extra_names(&["bad name".to_owned()]).is_err());
    assert!(pki
        .set_extra_names(&vec!["nas.example.org".to_owned(); 21])
        .is_err());
    pki.activate(&["localhost".to_owned()]).unwrap();
    let (info, custom) = pki.active().unwrap();
    assert!(!custom);
    assert_eq!(info.names, ["localhost", "nas.example.org"]);
}
