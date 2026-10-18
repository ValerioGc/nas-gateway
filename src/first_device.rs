//! A device created locally on the NAS for administration with `nas-os-gateway device create`.

use crate::{
    auth::{devices, mtls},
    base64,
    pki::Pki,
    store, Config,
};

fn quoted(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            control if control.is_control() => {
                out.push_str(&format!("\\u{:04x}", u32::from(control)));
            }
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

fn icon(id: &str) -> Option<devices::Icon> {
    match id {
        "tv" => Some(devices::Icon::Tv),
        "desktop" => Some(devices::Icon::Desktop),
        "laptop" => Some(devices::Icon::Laptop),
        "phone" => Some(devices::Icon::Phone),
        "projector" => Some(devices::Icon::Projector),
        _ => None,
    }
}

/// Creates the device `name` with icon `icon_id` and, when `enable`, turns mTLS on. Answers the
/// JSON the wizard reads.
pub async fn create(
    config: &Config,
    name: &str,
    icon_id: &str,
    enable: bool,
) -> Result<String, String> {
    let input = devices::DeviceInput {
        name: name.to_owned(),
        icon: icon(icon_id).ok_or_else(|| format!("not a device icon: {icon_id}"))?,
    };
    let name = input
        .name()
        .ok_or("the name of a device takes 1 to 60 characters")?
        .to_owned();
    let directory = config
        .pki
        .as_deref()
        .ok_or("no place for the authority: run under systemd with StateDirectory")?;
    let pki = Pki::open(directory)?;
    let db = store::open(config.database.as_deref())
        .await
        .map_err(|error| format!("the database is unavailable: {error}"))?;

    let issued = pki.issue_device(&name)?;
    let unused = devices::list(&db, None)
        .await
        .map_err(|error| error.to_string())?
        .into_iter()
        .find(|device| {
            device.name == name
                && device.certificate.as_ref().is_some_and(|certificate| {
                    certificate.state == devices::CertificateState::Pending
                })
        });
    let saved = match unused {
        Some(device) => devices::renew(&db, device.id, &issued).await.map(|_| ()),
        None => devices::create(&db, &name, input.icon, &issued)
            .await
            .map(|_| ()),
    };
    saved.map_err(|error| format!("the device was not saved: {error}"))?;
    if enable {
        mtls::set(&db, true)
            .await
            .map_err(|error| format!("mTLS was not turned on: {error}"))?;
    }
    db.close().await;

    Ok(format!(
        "{{\"caPem\":{},\"file\":{},\"password\":{},\"fingerprint\":{}}}",
        quoted(pki.ca_pem()),
        quoted(&base64::encode(&issued.p12)),
        quoted(&issued.password),
        quoted(&issued.fingerprint),
    ))
}
