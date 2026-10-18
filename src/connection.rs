use crate::{
    account_controller::{confirmed, parse, reply, user},
    confirm::{Codes, Refused},
    tls::Peer,
    Config, Sessions,
};
use axum::{
    body::Bytes,
    extract::{ConnectInfo, Request, State},
    http::{header, uri::Authority, HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use std::{net::IpAddr, path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    net::TcpListener,
    process::Command,
    sync::{mpsc, watch, Mutex},
};

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Settings {
    pub port: u16,
    pub force: bool,
}

pub struct Connection {
    current: watch::Sender<Settings>,
    path: Option<PathBuf>,
    runtime: Mutex<Option<(IpAddr, mpsc::Sender<TcpListener>)>>,
    firewall: bool,
    enabled: bool,
}

impl Connection {
    pub fn load(config: &Config, port: u16) -> Result<Arc<Self>, String> {
        let path = config
            .database
            .as_ref()
            .map(|path| path.with_extension("connection"));
        let settings = match path.as_ref().map(std::fs::read_to_string) {
            Some(Ok(text)) => {
                let mut lines = text.lines();
                let port = lines
                    .next()
                    .and_then(|line| line.parse::<u16>().ok())
                    .filter(|port| *port != 0)
                    .ok_or("invalid HTTPS port")?;
                let force = match lines.next() {
                    Some("1") => true,
                    Some("0") => false,
                    _ => return Err("invalid HTTPS redirection setting".into()),
                };
                Settings { port, force }
            }
            Some(Err(error)) if error.kind() != std::io::ErrorKind::NotFound => {
                return Err(error.to_string())
            }
            _ => Settings { port, force: false },
        };
        let (current, _) = watch::channel(settings);
        Ok(Arc::new(Self {
            current,
            path,
            runtime: Mutex::new(None),
            firewall: std::env::var_os("STATE_DIRECTORY").is_some(),
            enabled: config.tls,
        }))
    }

    pub fn settings(&self) -> Settings {
        *self.current.borrow()
    }

    pub fn subscribe(&self) -> watch::Receiver<Settings> {
        self.current.subscribe()
    }

    pub async fn attach(&self, address: IpAddr, sender: mpsc::Sender<TcpListener>) {
        *self.runtime.lock().await = Some((address, sender));
    }

    async fn persist(&self, settings: Settings) -> Result<(), String> {
        let path = self
            .path
            .as_ref()
            .ok_or("HTTPS settings have no persistent storage")?;
        let pending = path.with_extension("connection.new");
        tokio::fs::write(
            &pending,
            format!("{}\n{}\n", settings.port, u8::from(settings.force)),
        )
        .await
        .map_err(|error| error.to_string())?;
        tokio::fs::rename(&pending, path)
            .await
            .map_err(|error| error.to_string())
    }

    async fn apply_firewall(&self) -> Result<(), String> {
        if !self.firewall {
            return Ok(());
        }
        let apply = async {
            for _ in 0..2 {
                let result = Command::new("/usr/bin/systemctl")
                    .args(["start", "nas-os-firewall.service"])
                    .kill_on_drop(true)
                    .output()
                    .await
                    .map_err(|error| error.to_string())?;
                if !result.status.success() {
                    return Err("HTTPS firewall update failed".into());
                }
            }
            Ok(())
        };
        tokio::time::timeout(Duration::from_secs(10), apply)
            .await
            .map_err(|_| "HTTPS firewall update timed out")?
    }

    async fn save(&self, settings: Settings) -> Result<(), Refused> {
        if settings.port == 0 {
            return Err(Refused(StatusCode::BAD_REQUEST, "invalid HTTPS port"));
        }
        let runtime = self.runtime.lock().await;
        let (address, sender) = runtime.as_ref().ok_or(Refused(
            StatusCode::SERVICE_UNAVAILABLE,
            "HTTPS is unavailable",
        ))?;
        let previous = self.settings();
        if settings == previous {
            return Ok(());
        }
        let listener = if settings.port != previous.port {
            Some(
                TcpListener::bind((*address, settings.port))
                    .await
                    .map_err(|_| {
                        Refused(
                            StatusCode::CONFLICT,
                            "the HTTPS port is already in use or unavailable",
                        )
                    })?,
            )
        } else {
            None
        };
        self.persist(settings).await.map_err(unavailable)?;
        if let Err(reason) = self.apply_firewall().await {
            self.persist(previous).await.map_err(unavailable)?;
            self.apply_firewall().await.map_err(unavailable)?;
            return Err(unavailable(reason));
        }
        if let Some(listener) = listener {
            if sender.send(listener).await.is_err() {
                self.persist(previous).await.map_err(unavailable)?;
                self.apply_firewall().await.map_err(unavailable)?;
                return Err(unavailable("the HTTPS listener stopped".into()));
            }
        }
        self.current.send_replace(settings);
        Ok(())
    }
}

fn unavailable(reason: String) -> Refused {
    eprintln!("HTTPS settings not applied: {reason}");
    Refused(
        StatusCode::SERVICE_UNAVAILABLE,
        "HTTPS settings could not be applied",
    )
}

pub(crate) async fn read(
    State(sessions): State<Sessions>,
    Extension(connection): Extension<Arc<Connection>>,
    headers: HeaderMap,
) -> Response {
    reply(
        async {
            user(&sessions, &headers).await?;
            Ok(Json(connection.settings()))
        }
        .await,
    )
}

pub(crate) async fn save(
    State(sessions): State<Sessions>,
    Extension(codes): Extension<Codes>,
    Extension(connection): Extension<Arc<Connection>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let mut response = reply(
        async {
            let settings = parse(&body)?;
            confirmed(&sessions, &codes, &headers).await?;
            connection.save(settings).await?;
            Ok(Json(connection.settings()))
        }
        .await,
    );
    response
        .headers_mut()
        .insert(header::CONNECTION, "close".parse().unwrap());
    response
}

pub async fn redirect(
    State(connection): State<Arc<Connection>>,
    request: Request,
    next: Next,
) -> Response {
    let settings = connection.settings();
    let plain = request
        .extensions()
        .get::<ConnectInfo<Peer>>()
        .is_some_and(|ConnectInfo(peer)| {
            !peer.encrypted
                && !peer.screen
                && !(peer.address.ip().is_loopback() && request.uri().path() == "/health")
        });
    if !connection.enabled || !settings.force || !plain {
        return next.run(request).await;
    }
    let Some(host) = request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<Authority>().ok())
    else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let suffix = if settings.port == 443 {
        String::new()
    } else {
        format!(":{}", settings.port)
    };
    let target = format!(
        "https://{}{suffix}{}",
        host.host(),
        request
            .uri()
            .path_and_query()
            .map_or("/", |path| path.as_str())
    );
    let Ok(location) = target.parse::<axum::http::HeaderValue>() else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    (
        StatusCode::TEMPORARY_REDIRECT,
        [
            (header::LOCATION, location),
            (header::CACHE_CONTROL, "no-store".parse().unwrap()),
        ],
    )
        .into_response()
}

#[cfg(test)]
#[path = "../tests/connection/mod.rs"]
mod tests;
