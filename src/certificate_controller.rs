//! The certificate HTTPS answers with, from the security center.
//! Every change needs the password again (`x-nas-confirmation`) and takes
//! effect on the next connection, without a restart.

use crate::{
    account_controller::{confirmed, parse, reply, user},
    confirm::{Codes, Refused},
    device_controller::Authority,
    pki::{self, CertificateInfo, Pki},
    Config, Sessions,
};
use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Response,
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CertificateState {
    served: bool,
    custom: bool,
    active: Option<CertificateInfo>,
    authority: CertificateInfo,
    /// The names the NAS's own certificate covers by itself.
    automatic_names: Vec<String>,
    extra_names: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExtraNames {
    names: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CustomCertificate {
    certificate: String,
    key: String,
}

fn authority(Authority(pki): Authority) -> Result<Arc<Pki>, Refused> {
    pki.ok_or(Refused(
        StatusCode::SERVICE_UNAVAILABLE,
        "the NAS has no certificate authority",
    ))
}

fn refused(reason: String) -> Refused {
    eprintln!("certificate not changed: {reason}");
    Refused(StatusCode::BAD_REQUEST, "the certificate was not accepted")
}

fn state(pki: &Pki, config: &Config) -> Result<Json<CertificateState>, Refused> {
    let automatic = pki::automatic_names();
    if pki.active().is_none() {
        pki.activate(&automatic).map_err(refused)?;
    }
    let authority = pki::describe(pki.ca_der()).map_err(refused)?;
    let (active, custom) = pki
        .active()
        .map_or((None, false), |(info, custom)| (Some(info), custom));
    Ok(Json(CertificateState {
        served: config.tls,
        custom,
        active,
        authority,
        automatic_names: automatic,
        extra_names: pki.extra_names(),
    }))
}

pub async fn read(
    State(sessions): State<Sessions>,
    Extension(found): Extension<Authority>,
    Extension(config): Extension<Arc<Config>>,
    headers: HeaderMap,
) -> Response {
    reply(
        async {
            user(&sessions, &headers).await?;
            let pki = authority(found)?;
            state(&pki, &config)
        }
        .await,
    )
}

pub async fn save_names(
    State(sessions): State<Sessions>,
    Extension(codes): Extension<Codes>,
    Extension(found): Extension<Authority>,
    Extension(config): Extension<Arc<Config>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    reply(
        async {
            let input: ExtraNames = parse(&body)?;
            let names: Vec<String> = input
                .names
                .iter()
                .map(|name| name.trim().to_ascii_lowercase())
                .filter(|name| !name.is_empty())
                .collect();
            if names.len() > pki::EXTRA_LIMIT || !names.iter().all(|name| pki::valid_name(name)) {
                return Err(Refused(StatusCode::BAD_REQUEST, "a name is not valid"));
            }
            let pki = authority(found)?;
            confirmed(&sessions, &codes, &headers).await?;
            pki.set_extra_names(&names).map_err(refused)?;
            pki.activate(&pki::automatic_names()).map_err(refused)?;
            state(&pki, &config)
        }
        .await,
    )
}

pub async fn renew(
    State(sessions): State<Sessions>,
    Extension(codes): Extension<Codes>,
    Extension(found): Extension<Authority>,
    Extension(config): Extension<Arc<Config>>,
    headers: HeaderMap,
) -> Response {
    reply(
        async {
            let pki = authority(found)?;
            confirmed(&sessions, &codes, &headers).await?;
            pki.renew(&pki::automatic_names()).map_err(refused)?;
            state(&pki, &config)
        }
        .await,
    )
}

pub async fn install_custom(
    State(sessions): State<Sessions>,
    Extension(codes): Extension<Codes>,
    Extension(found): Extension<Authority>,
    Extension(config): Extension<Arc<Config>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    reply(
        async {
            let input: CustomCertificate = parse(&body)?;
            let pki = authority(found)?;
            confirmed(&sessions, &codes, &headers).await?;
            pki::custom_identity(&input.certificate, &input.key).map_err(|reason| {
                eprintln!("certificate refused: {reason}");
                Refused(
                    StatusCode::BAD_REQUEST,
                    "the certificate or its key is not valid",
                )
            })?;
            pki.install_custom(&input.certificate, &input.key)
                .map_err(refused)?;
            pki.activate(&pki::automatic_names()).map_err(refused)?;
            state(&pki, &config)
        }
        .await,
    )
}

pub async fn remove_custom(
    State(sessions): State<Sessions>,
    Extension(codes): Extension<Codes>,
    Extension(found): Extension<Authority>,
    Extension(config): Extension<Arc<Config>>,
    headers: HeaderMap,
) -> Response {
    reply(
        async {
            let pki = authority(found)?;
            confirmed(&sessions, &codes, &headers).await?;
            pki.remove_custom().map_err(refused)?;
            pki.activate(&pki::automatic_names()).map_err(refused)?;
            state(&pki, &config)
        }
        .await,
    )
}
