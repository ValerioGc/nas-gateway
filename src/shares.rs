//! The password of the folders shared on the local network.
//!
//! Samba checks the password of a share against a copy of its own, which only root writes and
//! which can be made only from the password in clear. The gateway is the one part of the NAS that
//! sees it, at a check of the user and at every change: it hands it to the helper of root behind
//! `Config::shares` (`share-password.sh`, started for each connection by
//! `nas-os-share-password.socket`) and forgets it. The launcher and the applications never see it.
//!
//! A request is two lines, `set` or `update` and the password; the answer is one line, `ok` or
//! `error: <why>`. `set` makes the copy of the user of the shares, `update` changes it only where
//! one was made, so a change of the password never adds anything to Samba.

use std::{path::Path, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};

const TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Request {
    /// The user turned the password of a share on: the copy is made, or made again.
    Set,
    /// The password of the account changed: the copy follows, where there is one.
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

/// Why the password did not reach Samba.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Failure {
    /// Nothing on this NAS keeps the password of the shares: no helper, or no Samba.
    Unavailable,
    /// The helper answered, and refused.
    Refused(String),
}

/// A password the two lines of a request can carry.
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

/// After a change of the password: Samba follows in the background, and a helper that is not
/// there or refuses never undoes the change. The journal says so, never with the password.
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
