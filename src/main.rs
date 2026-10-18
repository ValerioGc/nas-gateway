//! The gateway: with no argument it serves the NAS. `account create` creates the one account, from
//! the name and the password on two lines of the input, and ends with the status of
//! [`nas_os_gateway::account::AccountRefused::exit_code`]. `ca` writes the authority of the NAS,
//! creating it the first time, and `device create --name <name> [--icon <icon>] [--enable-mtls]`
//! creates a device for local administration (`first_device.rs`). `--version` prints the version,
//! which the launcher reads to offer the update of the gateway.
//!
//! With `GATEWAY_TLS_PORT` the NAS is served over HTTPS there, and `GATEWAY_PORT`
//! serves HTTP too, optionally redirecting it; without TLS, only plain HTTP on `GATEWAY_PORT`, as a
//! development copy runs. `GATEWAY_SCREEN_PORT` adds the port of the monitor connected to the NAS,
//! on the loopback (`tls::ScreenListener`).

use nas_os_gateway::{
    account, authority,
    connection::Connection,
    discovery, first_device, pki,
    tls::{self, Peer, ScreenListener, TlsListener},
    Config,
};
use std::{
    net::{IpAddr, Ipv4Addr},
    process::ExitCode,
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    net::TcpListener,
    signal::unix::{signal, SignalKind},
    sync::{mpsc, watch},
};

type Failure = Box<dyn std::error::Error + Send + Sync>;

const REFRESH_EVERY: Duration = Duration::from_secs(60 * 60);

async fn shutdown_signal() {
    let terminate = async {
        match signal(SignalKind::terminate()) {
            Ok(mut terminate) => {
                terminate.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = terminate => {}
    }
}

fn port_of(name: &str) -> Option<u16> {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
}

async fn serve() -> Result<(), Failure> {
    let config = Config::from_env();
    let port = port_of("GATEWAY_PORT").unwrap_or(3003);
    let address = std::env::var("GATEWAY_ADDRESS")
        .ok()
        .and_then(|value| value.parse::<IpAddr>().ok())
        .unwrap_or(IpAddr::from([127, 0, 0, 1]));
    let pki = authority(&config)?;
    let connection = Connection::load(&config, port_of("GATEWAY_TLS_PORT").unwrap_or(443))?;
    let app = nas_os_gateway::app(config.clone(), pki.clone(), connection.clone()).await?;

    let (stop, stopped) = watch::channel(false);
    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = stop.send(true);
    });
    let until = |mut stopped: watch::Receiver<bool>| async move {
        let _ = stopped.wait_for(|stop| *stop).await;
    };

    // The monitor connected to the NAS, on the loopback only, as plain HTTP.
    let screen = match port_of("GATEWAY_SCREEN_PORT") {
        Some(screen) => Some(ScreenListener(
            TcpListener::bind((Ipv4Addr::LOCALHOST, screen)).await?,
        )),
        None => None,
    };
    let on_screen = {
        let app = app.clone();
        let stopped = stopped.clone();
        async move {
            match screen {
                Some(screen) => {
                    axum::serve(screen, app.into_make_service_with_connect_info::<Peer>())
                        .with_graceful_shutdown(until(stopped))
                        .await
                }
                None => Ok(()),
            }
        }
    };

    let Some(_) = port_of("GATEWAY_TLS_PORT") else {
        let listener = TcpListener::bind((address, port)).await?;
        let discovery = start_discovery(&config, port, false).await;
        println!("gateway listening on http://{address}:{port}");
        let http = axum::serve(listener, app.into_make_service_with_connect_info::<Peer>())
            .with_graceful_shutdown(until(stopped));
        let result = tokio::try_join!(async { http.await }, on_screen);
        discovery::stop(discovery).await;
        result?;
        return Ok(());
    };

    let pki = pki.ok_or("no place for the authority of the NAS")?;
    pki.activate(&pki::automatic_names())?;
    let tls_port = connection.settings().port;
    let (sender, updates) = mpsc::channel(1);
    let secure = TlsListener::with_updates(
        TcpListener::bind((address, tls_port)).await?,
        tls::server_config(pki.clone())?,
        updates,
    )?;
    connection.attach(address, sender).await;
    let plain = TcpListener::bind((address, port)).await?;
    let mut changes = connection.subscribe();
    let discovery_config = config.clone();
    let discovery = tokio::spawn(async move {
        let port = changes.borrow().port;
        let mut responder = start_discovery(&discovery_config, port, true).await;
        while changes.changed().await.is_ok() {
            discovery::stop(responder).await;
            let port = changes.borrow().port;
            responder = start_discovery(&discovery_config, port, true).await;
        }
        discovery::stop(responder).await;
    });
    let names = pki.active().map(|(info, _)| info.names).unwrap_or_default();
    println!(
        "gateway listening on https://{address}:{tls_port} for {}, and on http://{address}:{port}",
        names.join(", ")
    );

    let refreshed = pki.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(REFRESH_EVERY).await;
            if let Err(reason) = refreshed.activate(&pki::automatic_names()) {
                eprintln!("the certificate was not refreshed: {reason}");
            }
        }
    });

    let https = axum::serve(
        secure,
        app.clone().into_make_service_with_connect_info::<Peer>(),
    )
    .with_graceful_shutdown(until(stopped.clone()));
    let http = axum::serve(plain, app.into_make_service_with_connect_info::<Peer>())
        .with_graceful_shutdown(until(stopped));
    let result = tokio::try_join!(async { https.await }, async { http.await }, on_screen);
    discovery.abort();
    result?;
    Ok(())
}

async fn start_discovery(
    config: &Config,
    port: u16,
    secure: bool,
) -> Option<tokio::task::JoinHandle<()>> {
    match nas_os_gateway::is_configured(config).await {
        Ok(configured) => discovery::start(configured, port, secure).await,
        Err(error) => {
            eprintln!("NAS discovery status unavailable: {error}");
            None
        }
    }
}

/// The name and the password on the input, never on the command line, where anybody reads them.
async fn create_account() -> ExitCode {
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let username = lines.next_line().await.ok().flatten().unwrap_or_default();
    let password = lines.next_line().await.ok().flatten().unwrap_or_default();
    match account::create(&Config::from_env(), &username, password).await {
        Ok(()) => {
            println!("account {} created", username.trim());
            ExitCode::SUCCESS
        }
        Err(refused) => {
            eprintln!("account not created: {refused}");
            ExitCode::from(refused.exit_code())
        }
    }
}

/// The authority of the NAS, in PEM, created the first time.
fn print_ca() -> ExitCode {
    match authority(&Config::from_env()) {
        Ok(Some(pki)) => {
            print!("{}", pki.ca_pem());
            ExitCode::SUCCESS
        }
        Ok(None) => {
            eprintln!("no place for the authority: run under systemd with StateDirectory");
            ExitCode::FAILURE
        }
        Err(reason) => {
            eprintln!("no authority: {reason}");
            ExitCode::FAILURE
        }
    }
}

/// `--name <name> [--icon <icon>] [--enable-mtls]`, read from the arguments after `device create`.
async fn create_device(arguments: &[String]) -> ExitCode {
    let mut name = None;
    let mut icon = "desktop".to_owned();
    let mut enable = false;
    let mut rest = arguments.iter();
    while let Some(argument) = rest.next() {
        match argument.as_str() {
            "--name" => name = rest.next().cloned(),
            "--icon" => icon = rest.next().cloned().unwrap_or_default(),
            "--enable-mtls" => enable = true,
            other => {
                eprintln!("unknown option: {other}");
                return ExitCode::from(2);
            }
        }
    }
    let Some(name) = name else {
        eprintln!(
            "usage: nas-os-gateway device create --name <name> [--icon <icon>] [--enable-mtls]"
        );
        return ExitCode::from(2);
    };
    match first_device::create(&Config::from_env(), &name, &icon, enable).await {
        Ok(json) => {
            println!("{json}");
            ExitCode::SUCCESS
        }
        Err(reason) => {
            eprintln!("no device created: {reason}");
            ExitCode::FAILURE
        }
    }
}

#[tokio::main]
async fn main() -> Result<ExitCode, Failure> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match arguments.as_slice() {
        [] => serve().await.map(|()| ExitCode::SUCCESS),
        [command, action] if command == "account" && action == "create" => {
            Ok(create_account().await)
        }
        [command] if command == "ca" => Ok(print_ca()),
        [flag] if flag == "--version" => {
            println!("{}", env!("CARGO_PKG_VERSION"));
            Ok(ExitCode::SUCCESS)
        }
        [command, action, rest @ ..] if command == "device" && action == "create" => {
            Ok(create_device(rest).await)
        }
        _ => {
            eprintln!(
                "usage: nas-os-gateway [account create | ca | device create --name <name> | --version]"
            );
            Ok(ExitCode::from(2))
        }
    }
}
