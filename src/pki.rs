//! The certificate authority of the NAS and what it signs: the certificate the gateway answers
//! HTTPS with, and one certificate for each device allowed in when mTLS is on.
//!
//! Everything lives in one directory of the gateway's state: `ca.key` (readable by the gateway
//! only), `ca.crt`, and the server's `server.key`, `server.crt` and `server.names`, the names it was
//! issued for. The server certificate is issued again when the names change or it is about to
//! expire; the authority stays, so browsers that trust it keep trusting the NAS. `server.extra`
//! holds the names the user added (a domain, a forwarded address), and `custom.crt` with
//! `custom.key` a certificate the user brought, which takes the place of the NAS's own.
//!
//! The certificate in use lives in memory and is what rustls answers with (`ResolvesServerCert`):
//! it changes without a restart of the gateway, when the settings change it or the names of the
//! machine change.

use p12_keystore::{
    Certificate as P12Certificate, KeyStore, KeyStoreEntry, PrivateKey, PrivateKeyChain,
};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SerialNumber,
};
use rustls::{
    crypto::ring::sign::any_supported_type,
    pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fmt, fs,
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    time::{SystemTime, UNIX_EPOCH},
};
use x509_parser::{
    certificate::X509Certificate, extensions::GeneralName, prelude::FromDer, x509::X509Name,
};

const DAY: i64 = 24 * 60 * 60;
const CA_DAYS: i64 = 20 * 365;
/// The longest a browser accepts for a server certificate.
const SERVER_DAYS: i64 = 397;
const SERVER_RENEW_DAYS: i64 = 30;
const DEVICE_DAYS: i64 = 2 * 365;
/// Letters and digits that cannot be mistaken for one another when read off a screen.
const PASSWORD_ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const PASSWORD_LENGTH: usize = 20;

const EXTRA_NAMES: &str = "server.extra";
const CUSTOM_CERTIFICATE: &str = "custom.crt";
const CUSTOM_KEY: &str = "custom.key";
/// How many names the user may add to the certificate of the NAS.
pub const EXTRA_LIMIT: usize = 20;

/// The authority of the NAS, loaded from its directory, and the certificate HTTPS answers with.
pub struct Pki {
    directory: PathBuf,
    ca_pem: String,
    ca_der: Vec<u8>,
    ca_key_pem: String,
    active: RwLock<Option<Active>>,
}

struct Active {
    key: Arc<CertifiedKey>,
    custom: bool,
}

impl fmt::Debug for Pki {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Pki")
            .field("directory", &self.directory)
            .finish_non_exhaustive()
    }
}

/// HTTPS answers every handshake with the certificate in use now.
impl ResolvesServerCert for Pki {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let active = self.active.read().ok()?;
        active.as_ref().map(|active| active.key.clone())
    }
}

/// A certificate as the settings show it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateInfo {
    pub subject: String,
    pub issuer: String,
    /// The names and addresses it is valid for.
    pub names: Vec<String>,
    pub not_before: i64,
    pub not_after: i64,
    pub fingerprint: String,
}

fn readable(name: &X509Name<'_>) -> String {
    name.iter_common_name()
        .next()
        .and_then(|common| common.as_str().ok())
        .map_or_else(|| name.to_string(), str::to_owned)
}

fn address(bytes: &[u8]) -> Option<String> {
    match bytes.len() {
        4 => <[u8; 4]>::try_from(bytes)
            .ok()
            .map(|ip| Ipv4Addr::from(ip).to_string()),
        16 => <[u8; 16]>::try_from(bytes)
            .ok()
            .map(|ip| Ipv6Addr::from(ip).to_string()),
        _ => None,
    }
}

/// What a certificate in DER says: who it is, who signed it, what it is valid for and until when.
pub fn describe(der: &[u8]) -> Result<CertificateInfo, String> {
    let (_, certificate) = X509Certificate::from_der(der)
        .map_err(|_| "a certificate that cannot be read".to_owned())?;
    let names = certificate
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|extension| {
            extension
                .value
                .general_names
                .iter()
                .filter_map(|name| match name {
                    GeneralName::DNSName(dns) => Some((*dns).to_owned()),
                    GeneralName::IPAddress(ip) => address(ip),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(CertificateInfo {
        subject: readable(certificate.subject()),
        issuer: readable(certificate.issuer()),
        names,
        not_before: certificate.validity().not_before.timestamp(),
        not_after: certificate.validity().not_after.timestamp(),
        fingerprint: fingerprint(der),
    })
}

/// A name the certificate can be issued for: an address, or a host name with an optional `*.`.
pub fn valid_name(name: &str) -> bool {
    if name.parse::<IpAddr>().is_ok() {
        return true;
    }
    // Only digits and dots is an address a browser reads as one, never a host name.
    if name
        .bytes()
        .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        return false;
    }
    let host = name.strip_prefix("*.").unwrap_or(name);
    !host.is_empty()
        && name.len() <= 253
        && host.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

/// The names the certificate of the NAS is issued for by itself: its host name, the same under
/// `.local`, the loopback, the address it reaches the network with, and any `GATEWAY_TLS_NAMES`.
pub fn automatic_names() -> Vec<String> {
    let mut names = Vec::new();
    if let Ok(host) = fs::read_to_string("/proc/sys/kernel/hostname") {
        let host = host.trim().to_ascii_lowercase();
        if !host.is_empty() {
            names.push(format!("{host}.local"));
            names.insert(0, host);
        }
    }
    names.extend(["localhost".to_owned(), "127.0.0.1".to_owned()]);
    // Connecting a datagram socket sends nothing: it only picks the address a packet would leave
    // from, which is the one the other devices of the network reach the NAS on.
    let primary = UdpSocket::bind("0.0.0.0:0")
        .and_then(|socket| socket.connect("192.0.2.1:9").map(|()| socket))
        .and_then(|socket| socket.local_addr())
        .map(|address| address.ip())
        .ok()
        .filter(|address| !address.is_unspecified() && !address.is_loopback());
    if let Some(address) = primary {
        names.push(address.to_string());
    }
    if let Ok(extra) = std::env::var("GATEWAY_TLS_NAMES") {
        names.extend(
            extra
                .split(',')
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(str::to_owned),
        );
    }
    names
}

fn certified(
    chain: Vec<CertificateDer<'static>>,
    key: &PrivateKeyDer<'_>,
) -> Result<CertifiedKey, String> {
    let signer = any_supported_type(key).map_err(|_| "a key this gateway cannot use".to_owned())?;
    let certified = CertifiedKey::new(chain, signer);
    certified
        .keys_match()
        .map_err(|_| "the key does not belong to the certificate".to_owned())?;
    Ok(certified)
}

/// A certificate chain and its key, in PEM, ready for HTTPS: the key matches the first certificate,
/// and that one is valid now.
pub fn custom_identity(certificate: &str, key: &str) -> Result<CertifiedKey, String> {
    let chain = CertificateDer::pem_slice_iter(certificate.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "the certificate is not PEM".to_owned())?;
    let leaf = chain.first().ok_or("no certificate in the file")?;
    let info = describe(leaf)?;
    let now = now_seconds();
    if info.not_before > now || info.not_after <= now {
        return Err("the certificate is not valid now".to_owned());
    }
    let key = PrivateKeyDer::from_pem_slice(key.as_bytes())
        .map_err(|_| "the key is not a PEM private key".to_owned())?;
    certified(chain, &key)
}

/// What a device receives: its certificate and key in a PKCS#12 file, and the password of the
/// file, shown once.
pub struct DeviceCredential {
    pub fingerprint: String,
    pub p12: Vec<u8>,
    pub password: String,
    pub issued_at: i64,
    pub expires_at: i64,
}

/// The certificate and key the gateway answers HTTPS with, in DER.
pub struct ServerIdentity {
    pub chain: Vec<Vec<u8>>,
    pub key: Vec<u8>,
}

/// The SHA-256 of a certificate in DER, in lower-case hexadecimal: how the gateway knows a device.
pub fn fingerprint(der: &[u8]) -> String {
    Sha256::digest(der)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn now_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
        })
}

/// The calendar day of a Unix time, by the algorithm of Howard Hinnant's `civil_from_days`.
fn civil(seconds: i64) -> (i32, u8, u8) {
    let days = seconds.div_euclid(DAY) + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (
        i32::try_from(year).unwrap_or(i32::MAX),
        u8::try_from(month).unwrap_or(1),
        u8::try_from(day).unwrap_or(1),
    )
}

/// Validity from yesterday, against a clock a little behind, to `days` from now. Answers when it
/// ends, in Unix seconds.
fn validity(params: &mut CertificateParams, days: i64) -> i64 {
    let now = now_seconds();
    let (year, month, day) = civil(now - DAY);
    params.not_before = rcgen::date_time_ymd(year, month, day);
    let end = now + days * DAY;
    let (year, month, day) = civil(end);
    params.not_after = rcgen::date_time_ymd(year, month, day);
    end - end.rem_euclid(DAY)
}

fn random(length: usize) -> Result<Vec<u8>, String> {
    let mut bytes = vec![0_u8; length];
    fs::File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut bytes))
        .map_err(|error| format!("no randomness: {error}"))?;
    Ok(bytes)
}

fn serial() -> Result<SerialNumber, String> {
    let mut bytes = random(16)?;
    // Positive, as RFC 5280 wants it.
    bytes[0] &= 0x7f;
    Ok(SerialNumber::from_slice(&bytes))
}

/// A password for a PKCS#12 file, from an alphabet without look-alikes.
fn password() -> Result<String, String> {
    let mut chosen = String::with_capacity(PASSWORD_LENGTH);
    while chosen.len() < PASSWORD_LENGTH {
        for byte in random(PASSWORD_LENGTH * 2)? {
            // Only the bytes that map evenly, so every letter is as likely as the others.
            let limit = 256 - 256 % PASSWORD_ALPHABET.len();
            if usize::from(byte) < limit && chosen.len() < PASSWORD_LENGTH {
                chosen.push(char::from(
                    PASSWORD_ALPHABET[usize::from(byte) % PASSWORD_ALPHABET.len()],
                ));
            }
        }
    }
    Ok(chosen)
}

/// Writes a file aside and moves it in place, readable by the gateway only when `private`.
fn write(path: &Path, contents: &[u8], private: bool) -> Result<(), String> {
    let aside = path.with_extension("new");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(if private { 0o600 } else { 0o644 })
        .open(&aside)
        .map_err(|error| format!("cannot write {}: {error}", aside.display()))?;
    file.write_all(contents)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("cannot write {}: {error}", aside.display()))?;
    fs::rename(&aside, path).map_err(|error| format!("cannot write {}: {error}", path.display()))
}

fn named(common_name: &str) -> DistinguishedName {
    let mut name = DistinguishedName::new();
    name.push(DnType::OrganizationName, "nas-os");
    name.push(DnType::CommonName, common_name);
    name
}

fn pem_der(pem: &str) -> Result<Vec<u8>, String> {
    let body: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    crate::base64::decode(&body).ok_or_else(|| "a certificate that is not PEM".to_owned())
}

impl Pki {
    /// The authority in `directory`, created there the first time.
    pub fn open(directory: &Path) -> Result<Self, String> {
        fs::create_dir_all(directory)
            .and_then(|()| fs::set_permissions(directory, fs::Permissions::from_mode(0o700)))
            .map_err(|error| format!("cannot prepare {}: {error}", directory.display()))?;
        let certificate = directory.join("ca.crt");
        let key = directory.join("ca.key");
        if !certificate.exists() || !key.exists() {
            let pair = KeyPair::generate().map_err(|error| error.to_string())?;
            let mut params = CertificateParams::default();
            params.distinguished_name = named("nas-os NAS authority");
            params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
            params.key_usages = vec![
                KeyUsagePurpose::KeyCertSign,
                KeyUsagePurpose::CrlSign,
                KeyUsagePurpose::DigitalSignature,
            ];
            params.serial_number = Some(serial()?);
            validity(&mut params, CA_DAYS);
            let issued = params
                .self_signed(&pair)
                .map_err(|error| error.to_string())?;
            write(&key, pair.serialize_pem().as_bytes(), true)?;
            write(&certificate, issued.pem().as_bytes(), false)?;
        }
        let ca_pem = fs::read_to_string(&certificate)
            .map_err(|error| format!("cannot read {}: {error}", certificate.display()))?;
        let ca_key_pem = fs::read_to_string(&key)
            .map_err(|error| format!("cannot read {}: {error}", key.display()))?;
        Ok(Self {
            directory: directory.to_owned(),
            ca_der: pem_der(&ca_pem)?,
            ca_pem,
            ca_key_pem,
            active: RwLock::new(None),
        })
    }

    /// The names the user added to the certificate of the NAS.
    pub fn extra_names(&self) -> Vec<String> {
        fs::read_to_string(self.directory.join(EXTRA_NAMES))
            .unwrap_or_default()
            .lines()
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(str::to_owned)
            .collect()
    }

    pub fn set_extra_names(&self, names: &[String]) -> Result<(), String> {
        if names.len() > EXTRA_LIMIT || !names.iter().all(|name| valid_name(name)) {
            return Err("a name the certificate cannot be issued for".to_owned());
        }
        let text: String = names.iter().map(|name| format!("{name}\n")).collect();
        write(&self.directory.join(EXTRA_NAMES), text.as_bytes(), false)
    }

    pub fn has_custom(&self) -> bool {
        self.directory.join(CUSTOM_CERTIFICATE).exists() && self.directory.join(CUSTOM_KEY).exists()
    }

    /// Keeps a certificate the user brought, once it is checked: it answers HTTPS from now on.
    pub fn install_custom(&self, certificate: &str, key: &str) -> Result<(), String> {
        custom_identity(certificate, key)?;
        write(&self.directory.join(CUSTOM_KEY), key.as_bytes(), true)?;
        write(
            &self.directory.join(CUSTOM_CERTIFICATE),
            certificate.as_bytes(),
            false,
        )
    }

    /// Goes back to the certificate of the NAS.
    pub fn remove_custom(&self) -> Result<(), String> {
        for name in [CUSTOM_CERTIFICATE, CUSTOM_KEY] {
            match fs::remove_file(self.directory.join(name)) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(format!("cannot remove {name}: {error}")),
            }
        }
        Ok(())
    }

    fn custom(&self) -> Result<CertifiedKey, String> {
        let read = |name: &str| {
            fs::read_to_string(self.directory.join(name))
                .map_err(|error| format!("cannot read {name}: {error}"))
        };
        custom_identity(&read(CUSTOM_CERTIFICATE)?, &read(CUSTOM_KEY)?)
    }

    /// Puts in use the certificate HTTPS answers with: the one the user brought, while it is
    /// valid, otherwise the NAS's own for `automatic` and the names the user added, issued again
    /// when they changed or it is about to expire.
    pub fn activate(&self, automatic: &[String]) -> Result<(), String> {
        let chosen = if self.has_custom() {
            match self.custom() {
                Ok(key) => Some(Active {
                    key: Arc::new(key),
                    custom: true,
                }),
                Err(reason) => {
                    eprintln!("the certificate brought by the user is not used: {reason}");
                    None
                }
            }
        } else {
            None
        };
        let active = match chosen {
            Some(active) => active,
            None => {
                let mut names = automatic.to_vec();
                names.extend(self.extra_names());
                let mut seen = std::collections::HashSet::new();
                names.retain(|name| seen.insert(name.clone()));
                let identity = self.server(&names)?;
                let chain = identity
                    .chain
                    .into_iter()
                    .map(CertificateDer::from)
                    .collect();
                let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(identity.key));
                Active {
                    key: Arc::new(certified(chain, &key)?),
                    custom: false,
                }
            }
        };
        *self
            .active
            .write()
            .map_err(|_| "the certificate in use is not reachable".to_owned())? = Some(active);
        Ok(())
    }

    /// Issues the certificate of the NAS again, whatever its names and its age.
    pub fn renew(&self, automatic: &[String]) -> Result<(), String> {
        let _ = fs::remove_file(self.directory.join("server.names"));
        self.activate(automatic)
    }

    /// The certificate in use, and whether the user brought it.
    pub fn active(&self) -> Option<(CertificateInfo, bool)> {
        let active = self.active.read().ok()?;
        let active = active.as_ref()?;
        let leaf = active.key.cert.first()?;
        describe(leaf).ok().map(|info| (info, active.custom))
    }

    pub fn ca_pem(&self) -> &str {
        &self.ca_pem
    }

    pub fn ca_der(&self) -> &[u8] {
        &self.ca_der
    }

    fn issue(&self, params: &CertificateParams, pair: &KeyPair) -> Result<Vec<u8>, String> {
        let signer = KeyPair::from_pem(&self.ca_key_pem).map_err(|error| error.to_string())?;
        let issuer =
            Issuer::from_ca_cert_pem(&self.ca_pem, signer).map_err(|error| error.to_string())?;
        params
            .signed_by(pair, &issuer)
            .map(|issued| issued.der().to_vec())
            .map_err(|error| error.to_string())
    }

    /// The certificate for `names`, issued again when they changed or it is about to expire.
    pub fn server(&self, names: &[String]) -> Result<ServerIdentity, String> {
        let certificate = self.directory.join("server.crt");
        let key = self.directory.join("server.key");
        let recorded = self.directory.join("server.names");
        let wanted = format!("{}\n", names.join("\n"));
        let current = fs::read_to_string(&recorded).unwrap_or_default();
        let (listed, expires) = current.rsplit_once("expires ").unwrap_or((&current, "0"));
        let fresh = listed == wanted
            && expires.trim().parse::<i64>().unwrap_or(0) > now_seconds() + SERVER_RENEW_DAYS * DAY;
        if !fresh || !certificate.exists() || !key.exists() {
            let pair = KeyPair::generate().map_err(|error| error.to_string())?;
            let mut params =
                CertificateParams::new(names.to_vec()).map_err(|error| error.to_string())?;
            params.distinguished_name = named(names.first().map_or("nas", String::as_str));
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
            params.serial_number = Some(serial()?);
            let end = validity(&mut params, SERVER_DAYS);
            let issued = self.issue(&params, &pair)?;
            write(&key, &pair.serialize_der(), true)?;
            write(&certificate, &issued, false)?;
            write(
                &recorded,
                format!("{wanted}expires {end}\n").as_bytes(),
                false,
            )?;
        }
        let read = |path: &Path| {
            fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))
        };
        Ok(ServerIdentity {
            chain: vec![read(&certificate)?, self.ca_der.clone()],
            key: read(&key)?,
        })
    }

    /// A certificate for one device, named after it, in a PKCS#12 file with the authority, under a
    /// password made for it.
    pub fn issue_device(&self, name: &str) -> Result<DeviceCredential, String> {
        let pair = KeyPair::generate().map_err(|error| error.to_string())?;
        let mut params = CertificateParams::default();
        params.distinguished_name = named(name);
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params.serial_number = Some(serial()?);
        let expires_at = validity(&mut params, DEVICE_DAYS);
        let issued = self.issue(&params, &pair)?;
        let password = password()?;

        let failed = |error: p12_keystore::error::Error| format!("cannot build the file: {error}");
        let device = P12Certificate::from_der(&issued).map_err(failed)?;
        let authority = P12Certificate::from_der(&self.ca_der).map_err(failed)?;
        let key = PrivateKey::from_der(&pair.serialize_der()).map_err(failed)?;
        let fingerprint = fingerprint(&issued);
        let chain = PrivateKeyChain::new(
            fingerprint.as_bytes()[..20].to_vec(),
            key,
            vec![device, authority],
        );
        let mut store = KeyStore::new();
        store.add_entry(name, KeyStoreEntry::PrivateKeyChain(chain));
        let p12 = store.writer(&password).write().map_err(failed)?;
        Ok(DeviceCredential {
            fingerprint,
            p12,
            password,
            issued_at: now_seconds(),
            expires_at,
        })
    }
}
