use crate::{
    account_controller as account,
    auth::{mtls, throttle::Throttle},
    certificate_controller as certificate,
    confirm::Codes,
    controller,
    device_controller::{self as devices, Authority},
    entry,
    pki::Pki,
    Config, Sessions,
};
use axum::{
    extract::{DefaultBodyLimit, Request},
    middleware,
    routing::{get, post, put},
    Extension, Router,
};
use std::sync::Arc;

pub fn routes(sessions: Sessions, config: Arc<Config>, authority: Option<Arc<Pki>>) -> Router {
    let signed_in = sessions.clone();
    // One count of refused passwords, for the sign-in and for the confirmations alike, and the
    // codes the confirmations give out, redeemed by what goes to the launcher.
    let throttle = Throttle::default();
    let codes = Codes::default();
    let redeemed = codes.clone();
    Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/auth/login", post(controller::login))
        .route("/auth/session", get(controller::session))
        .route("/auth/logout", post(controller::logout))
        .route("/auth/confirm", post(controller::confirm))
        .route("/auth/account", get(account::read))
        .route("/auth/account/username", put(account::rename))
        .route("/auth/account/password", put(account::change_password))
        .route("/auth/account/share-password", put(account::share_password))
        .route(
            "/auth/account/email",
            post(account::change_email).delete(account::remove_email),
        )
        .route("/auth/account/email/verify", post(account::verify_email))
        .route("/auth/account/recovery", put(account::switch_recovery))
        .route(
            "/auth/recovery",
            get(account::recovery_offer).post(account::request_reset),
        )
        .route("/auth/recovery/reset", post(account::reset))
        .route(
            "/auth/policy",
            get(controller::policy).put(controller::save_policy),
        )
        .route("/auth/ca.crt", get(devices::ca))
        .route("/auth/certificate", get(certificate::read))
        .route("/auth/certificate/names", put(certificate::save_names))
        .route("/auth/certificate/renew", post(certificate::renew))
        .route(
            "/auth/certificate/custom",
            put(certificate::install_custom)
                // A chain and its key in PEM: a few kilobytes, more than the other routes take.
                .layer(DefaultBodyLimit::max(64 * 1024))
                .delete(certificate::remove_custom),
        )
        .route(
            "/auth/mtls",
            get(devices::mtls_state).put(devices::save_mtls),
        )
        .route("/auth/devices", get(devices::list).post(devices::create))
        .route(
            "/auth/devices/{id}",
            put(devices::update).delete(devices::remove),
        )
        .route("/auth/devices/{id}/renew", post(devices::renew))
        .route("/auth/devices/{id}/revoke", post(devices::revoke))
        .layer(DefaultBodyLimit::max(1024))
        .layer(Extension(Authority(authority)))
        .layer(Extension(config.clone()))
        .layer(Extension(throttle))
        .layer(Extension(codes))
        .fallback(move |request: Request| entry::handle(config, signed_in, redeemed, request))
        // Every request, the fallback included: with mTLS on, only a device certificate lets one in.
        .layer(middleware::from_fn_with_state(
            sessions.clone(),
            mtls::guard,
        ))
        .with_state(sessions)
}
