//! The account from the settings, and the password reset from the sign-in page.

use crate::{
    auth::{
        accounts,
        email_codes::{self, Purpose},
        policy,
        throttle::Throttle,
    },
    confirm::{self, Codes, Refused, CODE_HEADER},
    controller::{self, session_token},
    mailer,
    shares::{self, Failure, Request},
    tls::Peer,
    Config, Sessions,
};
use axum::{
    body::Bytes,
    extract::{ConnectInfo, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::sync::Arc;

#[derive(Serialize)]
pub(crate) struct Account {
    username: String,
    email: Option<String>,
    recovery: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoverySwitch {
    enabled: bool,
}

#[derive(Serialize)]
pub(crate) struct RecoveryOffer {
    enabled: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NewUsername {
    username: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NewPassword {
    password: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NewEmail {
    email: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EmailCode {
    code: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoveryRequest {
    username: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoveryReset {
    username: String,
    code: String,
    password: String,
}

pub(crate) fn parse<T: DeserializeOwned>(body: &Bytes) -> Result<T, Refused> {
    Json::<T>::from_bytes(body)
        .map(|Json(input)| input)
        .map_err(|_| Refused(StatusCode::BAD_REQUEST, "the request is not valid"))
}

fn unavailable() -> Refused {
    Refused(
        StatusCode::SERVICE_UNAVAILABLE,
        "the account is unavailable",
    )
}

fn mail_failed() -> Refused {
    Refused(
        StatusCode::BAD_GATEWAY,
        "the mail with the code could not be sent",
    )
}

/// The user of the session, or a 401 that sends the browser to the sign-in.
pub(crate) async fn user(sessions: &Sessions, headers: &HeaderMap) -> Result<String, Refused> {
    controller::signed_in(sessions, headers)
        .await
        .ok_or(Refused(StatusCode::UNAUTHORIZED, "sign in first"))
}

/// The user of the session, once the request carries the code of the password confirmed again.
pub(crate) async fn confirmed(
    sessions: &Sessions,
    codes: &Codes,
    headers: &HeaderMap,
) -> Result<String, Refused> {
    let user = user(sessions, headers).await?;
    codes
        .redeem(headers.get(CODE_HEADER).cloned(), &user)
        .await?;
    Ok(user)
}

pub(crate) fn reply<T: IntoResponse>(result: Result<T, Refused>) -> Response {
    match result {
        Ok(answer) => ([(header::CACHE_CONTROL, "no-store")], answer).into_response(),
        Err(refused) => refused.into_response(),
    }
}

async fn account_of(sessions: &Sessions, username: String) -> Json<Account> {
    let email = accounts::email(&sessions.0, &username).await;
    let recovery = accounts::recovery(&sessions.0, &username).await;
    Json(Account {
        username,
        email,
        recovery,
    })
}

pub async fn read(State(sessions): State<Sessions>, headers: HeaderMap) -> Response {
    reply(
        async {
            let user = user(&sessions, &headers).await?;
            Ok(account_of(&sessions, user).await)
        }
        .await,
    )
}

pub async fn rename(
    State(sessions): State<Sessions>,
    Extension(codes): Extension<Codes>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    reply(
        async {
            let input: NewUsername = parse(&body)?;
            let username = input.username.trim().to_owned();
            if !accounts::valid_username(&username) {
                return Err(Refused(
                    StatusCode::BAD_REQUEST,
                    "the username is not valid",
                ));
            }
            let user = confirmed(&sessions, &codes, &headers).await?;
            if username != user {
                accounts::rename(&sessions.0, &user, &username)
                    .await
                    .map_err(|_| unavailable())?;
            }
            Ok(account_of(&sessions, username).await)
        }
        .await,
    )
}

pub async fn change_password(
    State(sessions): State<Sessions>,
    Extension(codes): Extension<Codes>,
    Extension(config): Extension<Arc<Config>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    reply(
        async {
            let input: NewPassword = parse(&body)?;
            if !accounts::valid_password(&input.password) {
                return Err(Refused(
                    StatusCode::BAD_REQUEST,
                    "the password is not valid",
                ));
            }
            let user = confirmed(&sessions, &codes, &headers).await?;
            accounts::set_password(
                &sessions.0,
                &user,
                input.password.clone(),
                session_token(&headers),
            )
            .await
            .map_err(|_| unavailable())?;
            shares::follow(config.shares.as_deref(), input.password);
            Ok(StatusCode::NO_CONTENT)
        }
        .await,
    )
}

pub async fn change_email(
    State(sessions): State<Sessions>,
    Extension(codes): Extension<Codes>,
    Extension(config): Extension<Arc<Config>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    reply(
        async {
            let input: NewEmail = parse(&body)?;
            let email = input.email.trim().to_owned();
            if !email_codes::valid_email(&email) {
                return Err(Refused(StatusCode::BAD_REQUEST, "the address is not valid"));
            }
            let user = confirmed(&sessions, &codes, &headers).await?;
            let code = email_codes::issue(&sessions.0, Purpose::Verify, &user, &email)
                .await
                .map_err(|_| unavailable())?;
            mailer::send(&config.launcher, Purpose::Verify, &email, &code)
                .await
                .map_err(|()| mail_failed())?;
            Ok(StatusCode::ACCEPTED)
        }
        .await,
    )
}

pub async fn verify_email(
    State(sessions): State<Sessions>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    reply(
        async {
            let input: EmailCode = parse(&body)?;
            let user = user(&sessions, &headers).await?;
            let email = email_codes::redeem(&sessions.0, Purpose::Verify, &user, &input.code)
                .await
                .ok_or(Refused(
                    StatusCode::BAD_REQUEST,
                    "the code is wrong or expired",
                ))?;
            accounts::set_email(&sessions.0, &user, Some(&email))
                .await
                .map_err(|_| unavailable())?;
            Ok(account_of(&sessions, user).await)
        }
        .await,
    )
}

pub async fn remove_email(
    State(sessions): State<Sessions>,
    Extension(codes): Extension<Codes>,
    headers: HeaderMap,
) -> Response {
    reply(
        async {
            let user = confirmed(&sessions, &codes, &headers).await?;
            accounts::set_email(&sessions.0, &user, None)
                .await
                .map_err(|_| unavailable())?;
            Ok(StatusCode::NO_CONTENT)
        }
        .await,
    )
}

pub async fn switch_recovery(
    State(sessions): State<Sessions>,
    Extension(codes): Extension<Codes>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    reply(
        async {
            let input: RecoverySwitch = parse(&body)?;
            let user = confirmed(&sessions, &codes, &headers).await?;
            accounts::set_recovery(&sessions.0, &user, input.enabled)
                .await
                .map_err(|_| unavailable())?;
            Ok(account_of(&sessions, user).await)
        }
        .await,
    )
}

/// Whether the sign-in page offers the reset: a verified address with the reset by mail on.
pub async fn recovery_offer(State(sessions): State<Sessions>) -> Response {
    let enabled = accounts::recovery_offered(&sessions.0).await;
    reply(Ok(Json(RecoveryOffer { enabled })))
}

pub async fn request_reset(
    State(sessions): State<Sessions>,
    Extension(throttle): Extension<Throttle>,
    Extension(config): Extension<Arc<Config>>,
    peer: Option<Extension<ConnectInfo<Peer>>>,
    body: Bytes,
) -> Response {
    reply(
        async {
            let input: RecoveryRequest = parse(&body)?;
            let db = &sessions.0;
            if throttle
                .locked(controller::address(peer.as_ref()), &policy::load(db).await)
                .await
            {
                return Err(Refused(StatusCode::TOO_MANY_REQUESTS, "too many attempts"));
            }
            let username = input.username.trim();
            if let Some(email) = accounts::reset_address(db, username).await {
                if !email_codes::recently_sent(db, Purpose::Reset, username).await {
                    let code = email_codes::issue(db, Purpose::Reset, username, &email)
                        .await
                        .map_err(|_| unavailable())?;
                    // A failed mail is not told apart from an account without an address.
                    let _ = mailer::send(&config.launcher, Purpose::Reset, &email, &code).await;
                }
            }
            Ok(StatusCode::ACCEPTED)
        }
        .await,
    )
}

pub async fn reset(
    State(sessions): State<Sessions>,
    Extension(throttle): Extension<Throttle>,
    Extension(config): Extension<Arc<Config>>,
    peer: Option<Extension<ConnectInfo<Peer>>>,
    body: Bytes,
) -> Response {
    reply(
        async {
            let input: RecoveryReset = parse(&body)?;
            if !accounts::valid_password(&input.password) {
                return Err(Refused(
                    StatusCode::BAD_REQUEST,
                    "the password is not valid",
                ));
            }
            let db = &sessions.0;
            let address = controller::address(peer.as_ref());
            let policy = policy::load(db).await;
            if throttle.locked(address, &policy).await {
                return Err(Refused(StatusCode::TOO_MANY_REQUESTS, "too many attempts"));
            }
            let username = input.username.trim();
            let allowed = accounts::reset_address(db, username).await.is_some();
            if !allowed
                || email_codes::redeem(db, Purpose::Reset, username, &input.code)
                    .await
                    .is_none()
            {
                throttle.failed(address, &policy).await;
                return Err(Refused(
                    StatusCode::BAD_REQUEST,
                    "the code is wrong or expired",
                ));
            }
            throttle.succeeded(address).await;
            accounts::set_password(db, username, input.password.clone(), None)
                .await
                .map_err(|_| unavailable())?;
            shares::follow(config.shares.as_deref(), input.password);
            Ok(StatusCode::NO_CONTENT)
        }
        .await,
    )
}

pub async fn share_password(
    State(sessions): State<Sessions>,
    Extension(throttle): Extension<Throttle>,
    Extension(config): Extension<Arc<Config>>,
    peer: Option<Extension<ConnectInfo<Peer>>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    reply(
        async {
            let input: NewPassword = parse(&body)?;
            let user = user(&sessions, &headers).await?;
            let address = controller::address(peer.as_ref());
            confirm::checked(&sessions, &throttle, address, &user, input.password.clone()).await?;
            let socket = config.shares.as_deref().ok_or(sharing_unavailable())?;
            match shares::hand(socket, Request::Set, &input.password).await {
                Ok(()) => Ok(StatusCode::NO_CONTENT),
                Err(Failure::Unavailable) => Err(sharing_unavailable()),
                Err(Failure::Refused(reason)) => {
                    eprintln!("Samba refused the password of the shares: {reason}");
                    Err(Refused(
                        StatusCode::BAD_GATEWAY,
                        "Samba refused the password",
                    ))
                }
            }
        }
        .await,
    )
}

fn sharing_unavailable() -> Refused {
    Refused(
        StatusCode::SERVICE_UNAVAILABLE,
        "the shared folders are not available on this NAS",
    )
}
