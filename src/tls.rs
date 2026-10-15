//! HTTPS with the certificate of the NAS, asking every browser for a device certificate signed by
//! the same authority and accepting the ones that have none: whether a request may go on without
//! one is the gateway's to decide (`auth::mtls`), not the handshake's, so a device without a
//! certificate still gets a page that says why.
//!
//! The handshakes run apart from the accepting loop, each with a deadline, so a client that opens a
//! connection and says nothing holds up nobody else.

use crate::pki::{fingerprint, Pki};
use axum::{extract::connect_info::Connected, serve::IncomingStream};
use rustls::{
    pki_types::CertificateDer, server::WebPkiClientVerifier, RootCertStore, ServerConfig,
};
use std::{io, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::mpsc,
};
use tokio_rustls::{server::TlsStream, TlsAcceptor};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const WAITING: usize = 64;

/// Who is on the other end of a connection: the address, and the fingerprint of the device
/// certificate it showed, if any.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    pub address: SocketAddr,
    pub certificate: Option<String>,
    /// The connection completed a TLS handshake, even if no client certificate was shown.
    pub encrypted: bool,
    /// The connection came on the port of the monitor connected to the NAS (`ScreenListener`).
    pub screen: bool,
}

impl Connected<IncomingStream<'_, TcpListener>> for Peer {
    fn connect_info(stream: IncomingStream<'_, TcpListener>) -> Self {
        Self {
            address: *stream.remote_addr(),
            certificate: None,
            encrypted: false,
            screen: false,
        }
    }
}

impl Connected<IncomingStream<'_, ScreenListener>> for Peer {
    fn connect_info(stream: IncomingStream<'_, ScreenListener>) -> Self {
        stream.remote_addr().clone()
    }
}

/// The port of the monitor connected to the NAS, on the loopback: plain HTTP, which the base
/// firewall lets only the browser of the screen reach. Whoever sits at the machine needs no device
/// certificate; the password is asked all the same.
pub struct ScreenListener(pub TcpListener);

impl axum::serve::Listener for ScreenListener {
    type Io = TcpStream;
    type Addr = Peer;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match self.0.accept().await {
                Ok((stream, address)) => {
                    return (
                        stream,
                        Peer {
                            address,
                            certificate: None,
                            encrypted: false,
                            screen: true,
                        },
                    )
                }
                // Out of descriptors, most likely: a pause instead of a busy loop.
                Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        Ok(Peer {
            address: self.0.local_addr()?,
            certificate: None,
            encrypted: false,
            screen: true,
        })
    }
}

impl Connected<IncomingStream<'_, TlsListener>> for Peer {
    fn connect_info(stream: IncomingStream<'_, TlsListener>) -> Self {
        stream.remote_addr().clone()
    }
}

/// The TLS settings of the gateway: the certificate in use of `pki`, which can change while the
/// gateway runs, and its authority, which device certificates are checked against.
pub fn server_config(pki: Arc<Pki>) -> Result<ServerConfig, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(pki.ca_der().to_vec()))
        .map_err(|error| format!("the authority of the NAS is not usable: {error}"))?;
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .allow_unauthenticated()
        .build()
        .map_err(|error| format!("cannot check device certificates: {error}"))?;
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| error.to_string())?
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(pki);
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

/// Connections whose handshake is over, ready for the server.
pub struct TlsListener {
    ready: mpsc::Receiver<(TlsStream<TcpStream>, Peer)>,
    local: SocketAddr,
}

impl TlsListener {
    pub fn new(listener: TcpListener, config: ServerConfig) -> io::Result<Self> {
        let (_, updates) = mpsc::channel(1);
        Self::with_updates(listener, config, updates)
    }

    pub fn with_updates(
        mut listener: TcpListener,
        config: ServerConfig,
        mut updates: mpsc::Receiver<TcpListener>,
    ) -> io::Result<Self> {
        let local = listener.local_addr()?;
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let (sender, ready) = mpsc::channel(WAITING);
        tokio::spawn(async move {
            loop {
                let accepted = tokio::select! {
                    _ = sender.closed() => return,
                    Some(replacement) = updates.recv() => { listener = replacement; continue; }
                    accepted = listener.accept() => accepted,
                };
                let Ok((stream, address)) = accepted else {
                    // Out of descriptors, most likely: a pause instead of a busy loop.
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                };
                if sender.is_closed() {
                    return;
                }
                let acceptor = acceptor.clone();
                let ready = sender.clone();
                tokio::spawn(async move {
                    let Ok(Ok(stream)) =
                        tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await
                    else {
                        return;
                    };
                    let certificate = stream
                        .get_ref()
                        .1
                        .peer_certificates()
                        .and_then(<[CertificateDer]>::first)
                        .map(|der| fingerprint(der));
                    let _ = ready
                        .send((
                            stream,
                            Peer {
                                address,
                                certificate,
                                encrypted: true,
                                screen: false,
                            },
                        ))
                        .await;
                });
            }
        });
        Ok(Self { ready, local })
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = Peer;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.ready.recv().await {
            Some(ready) => ready,
            // The accepting loop never ends while the listener lives.
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        Ok(Peer {
            address: self.local,
            certificate: None,
            encrypted: true,
            screen: false,
        })
    }
}
