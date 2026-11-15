//! The password of the folders shared on the local network. The gateway hands it to the root helper
//! behind `Config::shares` at every check and change, then forgets it. DEVELOPMENT.md describes the
//! two-line protocol.

use std::{path::Path, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};

const TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Request {
    Set,
    Update,
}

impl Request {
    fn verb(self) -> &'static str {
        match self {
            Self::Set => "set",
            Self::Update => "update",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Failure {
    Unavailable,
    Refused(String),
}

pub(crate) fn carries(password: &str) -> bool {
    !password.is_empty() && !password.chars().any(char::is_control)
}

/// Hands the password to the helper of root and waits for its answer.
pub(crate) async fn hand(socket: &Path, request: Request, password: &str) -> Result<(), Failure> {
    if !carries(password) {
        return Err(Failure::Refused("the password cannot be shared".to_owned()));
    }
    let exchange = async {
        let mut stream = UnixStream::connect(socket)
            .await
            .map_err(|_| Failure::Unavailable)?;
        let text = format!("{}\n{password}\n", request.verb());
        stream
            .write_all(text.as_bytes())
            .await
            .map_err(|_| Failure::Unavailable)?;
        stream.shutdown().await.map_err(|_| Failure::Unavailable)?;
        let mut answer = String::new();
        stream
            .take(512)
            .read_to_string(&mut answer)
            .await
            .map_err(|_| Failure::Unavailable)?;
        Ok(answer)
    };
    let answer = tokio::time::timeout(TIMEOUT, exchange)
        .await
        .map_err(|_| Failure::Unavailable)??;
    match answer.trim() {
        "ok" => Ok(()),
        "error: samba is not installed" => Err(Failure::Unavailable),
        other => Err(Failure::Refused(
            other.strip_prefix("error: ").unwrap_or(other).to_owned(),
        )),
    }
}

pub(crate) fn follow(socket: Option<&Path>, password: String) {
    let Some(socket) = socket.map(Path::to_path_buf) else {
        return;
    };
    tokio::spawn(async move {
        match hand(&socket, Request::Update, &password).await {
            Ok(()) | Err(Failure::Unavailable) => {}
            Err(Failure::Refused(reason)) => {
                eprintln!("the password of the shares did not follow: {reason}");
            }
        }
    });
}
