//! IPv4 LAN discovery for NAS Finder, taken over from the wizard. The responder always run, the
//! base firewall decides whether a query reaches it,
//! This protocol exposes no account, session, token or machine-id, and grants no access.
use sha2::{Digest, Sha256};
use std::{
    fmt::Write,
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};
use tokio::{net::UdpSocket, task::JoinHandle, time::Instant};

pub const PORT: u16 = 39877;

pub fn query_nonce(bytes: &[u8]) -> Option<&str> {
    let nonce = std::str::from_utf8(bytes)
        .ok()?
        .strip_prefix("NAS-OS-DISCOVER/1 ")?;
    (nonce.len() == 16 && nonce.bytes().all(|byte| byte.is_ascii_hexdigit())).then_some(nonce)
}

pub fn local_peer(peer: SocketAddr) -> bool {
    let SocketAddr::V4(peer) = peer else {
        return false;
    };
    peer.port() >= 1024
        && (peer.ip().is_private() || peer.ip().is_link_local() || peer.ip().is_loopback())
}

pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".-_".contains(&byte))
}

pub fn identity(machine_id: &str) -> Option<String> {
    let machine_id = machine_id.trim();
    if machine_id.len() != 32 || !machine_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let digest = Sha256::digest(format!("nas-os-discovery-v1:{machine_id}"));
    let mut id = String::with_capacity(64);
    for byte in digest {
        write!(&mut id, "{byte:02x}").ok()?;
    }
    Some(id)
}

pub fn reply(
    nonce: &str,
    id: &str,
    name: &str,
    configured: bool,
    port: u16,
    secure: bool,
) -> Option<String> {
    if nonce.len() != 16
        || !nonce.bytes().all(|byte| byte.is_ascii_hexdigit())
        || id.len() != 64
        || !id.bytes().all(|byte| byte.is_ascii_hexdigit())
        || !valid_name(name)
        || port == 0
    {
        return None;
    }
    Some(format!(
        "NAS-OS/1\n{nonce}\n{id}\n{name}\n{}\n{port}\n{}\n",
        if configured { "ready" } else { "setup" },
        if secure { "https" } else { "http" }
    ))
}

async fn hostname() -> String {
    let name = tokio::fs::read_to_string("/etc/hostname")
        .await
        .unwrap_or_default();
    let name = name.trim();
    if valid_name(name) {
        name.to_owned()
    } else {
        "nas-os".to_owned()
    }
}

pub async fn respond(
    socket: UdpSocket,
    id: String,
    configured: bool,
    web_port: u16,
    secure: bool,
) -> std::io::Result<()> {
    let mut buffer = [0; 128];
    let mut last = None::<Instant>;
    loop {
        let (length, peer) = socket.recv_from(&mut buffer).await?;
        if !local_peer(peer) {
            continue;
        }
        let Some(nonce) = query_nonce(&buffer[..length]) else {
            continue;
        };
        // Bounded replies, no periodic broadcasts, and a global maximum of ten replies per second.
        if last.is_some_and(|last| last.elapsed() < Duration::from_millis(100)) {
            continue;
        }
        last = Some(Instant::now());
        let name = hostname().await;
        if let Some(message) = reply(nonce, &id, &name, configured, web_port, secure) {
            socket.send_to(message.as_bytes(), peer).await?;
        }
    }
}

/// Failure of the discovery must never stop the wizard or the gateway.
pub async fn start(configured: bool, web_port: u16, secure: bool) -> Option<JoinHandle<()>> {
    let result = async {
        let machine_id = tokio::fs::read_to_string("/etc/machine-id").await?;
        let id = identity(&machine_id).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid machine identity")
        })?;
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, PORT)).await?;
        Ok::<_, std::io::Error>((socket, id))
    }
    .await;
    match result {
        Ok((socket, id)) => Some(tokio::spawn(async move {
            if let Err(error) = respond(socket, id, configured, web_port, secure).await {
                eprintln!("NAS discovery stopped: {error}");
            }
        })),
        Err(error) => {
            eprintln!("NAS discovery unavailable: {error}");
            None
        }
    }
}

pub async fn stop(task: Option<JoinHandle<()>>) {
    if let Some(task) = task {
        task.abort();
        let _ = task.await;
    }
}

#[cfg(test)]
#[path = "../tests/discovery/mod.rs"]
mod tests;
