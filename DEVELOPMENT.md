# Developing nas-gateway

## Structure

```text
src/
  main.rs            # Serve the NAS over HTTP or HTTPS; account create, ca, device create
  lib.rs             # Environment configuration and router construction
  account.rs         # Create the single account for the wizard
  router.rs          # /auth routes and forwarding to entry
  entry.rs           # Forward requests to the launcher, with or without a session, and serve the UI
  controller.rs      # Sign-in, sessions, sign-out, and failed-attempt policy
  confirm.rs         # Password reconfirmation: single-use codes for reset, export, and import
  account_controller.rs # Account username, password, recovery email, and password reset
  mailer.rs          # Email codes requested from the launcher through /internal/mail/code
  certificate_controller.rs # HTTPS certificate settings: names, renewal, and custom certificates
  connection.rs      # Persist HTTPS settings, replace listeners, and enforce HTTPS redirects
  pki.rs             # NAS CA, live server certificate replacement, and device certificates
  tls.rs             # HTTPS listener and the client certificate fingerprint of each connection
  device_controller.rs # mTLS and device routes
  client_controller.rs # NAS Sync computers: certificates, /client/sync routes, and revocations
  mobile_controller.rs # NAS Mobile phones: certificates and /client/files routes to File Manager
  discovery.rs       # Optional NAS Finder discovery over UDP
  first_device.rs    # Local device administration command
  base64.rs          # Base64 for PEM and .p12 values in JSON
  proxy.rs           # Launcher proxy built on hyper, including WebSocket support
  ui.rs              # Static UI files
  shares.rs          # Shared-folder password synchronization through the privileged helper
  store.rs           # SQLite database and migrations
  auth/              # Accounts (Argon2id), sessions, email codes, policy, lockout, devices, and mTLS
migrations/          # Numbered SQL migrations embedded in the binary
tests/               # Router integration tests; common/ contains shared helpers
tests/scripts/       # Installation script tests using node --test
system/packages/gateway_installation/   # Installer, checks, uninstaller, and systemd units
scripts/release/     # Local release checks, packaging, publishing, and release notes
```

## Certificates and the password of the shares

`pki.rs` keeps everything in one directory of the gateway's state. `ca.key` is readable by the
gateway only, next to `ca.crt` and the server's `server.key`, `server.crt` and `server.names`, the
names it was issued for. The server certificate is issued again when the names change or it is
about to expire, while the authority stays, so browsers that trust it keep trusting the NAS.
`server.extra` holds the names the user added, and `custom.crt` with `custom.key` a certificate the
user brought, which takes the place of the NAS's own. The certificate in use lives in memory and
rustls answers with it (`ResolvesServerCert`), so it changes without a restart.

Samba checks the password of a share against a copy of its own, which only root writes and only
from the password in clear. The gateway is the one part of the NAS that sees it, at a check of the
user and at every change. `shares.rs` hands it to `share-password.sh`, started for each connection
by `nas-os-share-password.socket`, and forgets it. A request is two lines, `set` or `update` and the
password, and the answer is one line, `ok` or `error` with the reason. `set` makes the copy of the
user of the shares, `update` changes it only where one was made, so a change of the password never
adds anything to Samba.

## Rules

- Keep `cargo fmt` and `cargo clippy --all-targets -- -D warnings` clean.
- Return typed `Result` errors. Use `unwrap()` and `expect()` only when failure is impossible by
  construction, never on input.
- No blocking I/O in handlers: use tokio equivalents or `spawn_blocking` for Argon2id hashing.
- Never edit an applied migration; add a new one.
- Tests belong in `tests/` and call the router externally through `app_with`. Each test gateway
  uses a file-backed database (`tests/common`), because account creation happens outside the
  router, just as on the NAS.
- No npm dependencies: scripts use Node built-ins, and their tests use `node:test`.
- Ask before adding any Rust dependency.
- Never use an em dash (U+2014) in any file.

## Releases

Verify releases locally and publish them through the build pipeline, which does not run tests.
Tests run on every pull request targeting `main` (`.github/workflows/ci.yml`: Rust and
installation scripts).

- `npm run release:test` runs the local checks: formatting, clippy, Rust tests, script tests,
  release binary, and package.
- `npm run release:merge -- --type=patch|minor|major --branch=main` selects the version, runs the
  same checks, updates the version in `package.json`, `Cargo.toml`, and
  `sonar-project.properties`, and publishes the tag. `--dry-run` only reports the proposed version.
- The tag triggers `.github/workflows/build.yml`: validate the tag and version, compile, build
  the package, publish the release archive and its `.sha256`, and retain the two latest releases.
  Release notes come from the matching version section in `CHANGELOG.txt`, falling back to the
  commits since the previous tag.

The package is named `nas-gateway-<version>-linux-x64.tar.gz`, as expected by the wizard.

## Quality checks

`npm run test:sonar` generates coverage with `cargo llvm-cov` and a clippy report, then runs the
scanner through Podman. Start SonarQube with `npm run podman:sonar:up`: it shares the instance used
by other nas-os projects, with its own project key (`nas-gateway`).

```bash
cargo install cargo-llvm-cov --locked
rustup component add llvm-tools-preview
```
