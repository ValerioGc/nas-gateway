# nas-gateway

The nas-os authentication gateway is the browser entry point on the NAS, serving HTTPS on port
443 and HTTP on port 80 without automatic redirection by default. It serves the compiled UI,
authenticates the account created by the wizard, and forwards APIs and applications to the
launcher, which listens only on loopback. This is a standalone project with its own repository
(`ValerioGc/nas-gateway`), version, and releases. The [wizard](../nas-wizard/README.md) installs it;
updates use the same installer from a newer release.

## Development

```bash
cargo run
```

The gateway listens on `127.0.0.1:3003`. Override the port with `GATEWAY_PORT` and the address with
`GATEWAY_ADDRESS`. Accounts and sessions are stored in `data/gateway.db`. The UI's Vite server
([../nas-launcher](../nas-launcher/README.md)) proxies `/auth` to it. Create a development account
using the same command as the wizard:

```bash
printf 'admin\nlong enough\n' | cargo run -- account create
```

## Routes

| Route                                          | Result                                                                                                                                                                                            |
| ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `POST /auth/login`                             | Validate the account and open a session using the opaque `nas_session` cookie, with HttpOnly and SameSite=Strict. Errors: 401, 429, or 502.                                                       |
| `GET /auth/session`                            | Return `{ authenticated, username }` for an active session cookie; otherwise 401.                                                                                                                 |
| `POST /auth/logout`                            | Close the session and expire its cookie.                                                                                                                                                          |
| `POST /auth/confirm`                           | With a session and `{ password }`, return a single-use confirmation code valid for one minute.                                                                                                    |
| `GET /auth/policy`                             | With a session, return the failed-login policy: `{ enabled, attempts, lockMinutes }`.                                                                                                             |
| `PUT /auth/policy`                             | With a session, change the policy: 1 to 20 attempts and 1 to 1440 minutes; otherwise 400.                                                                                                         |
| `GET /health`                                  | Public readiness check.                                                                                                                                                                           |
| `GET /auth/ca.crt`                             | Public NAS CA download, including when mTLS is enabled, for installation as a trusted authority.                                                                                                  |
| `GET /auth/mtls`                               | With a session, return `{ enabled, available, current }`, where `current` identifies the device on this connection.                                                                               |
| `PUT /auth/mtls`                               | With password confirmation, enable or disable mTLS. Enabling it without a valid certificate on the connection returns 409.                                                                        |
| `GET /auth/devices`                            | With a session, list devices and each device's latest certificate.                                                                                                                                |
| `POST /auth/devices`                           | With password confirmation and `{ name, icon }`, create a device and return its `.p12` file (base64) and password.                                                                                |
| `PUT /auth/devices/{id}`                       | Change the device name and icon.                                                                                                                                                                  |
| `POST /auth/devices/{id}/renew`                | With password confirmation, revoke the device's certificates and issue a new one.                                                                                                                 |
| `POST /auth/devices/{id}/revoke`               | Revoke the device's certificates while keeping it in the list.                                                                                                                                    |
| `DELETE /auth/devices/{id}`                    | Remove the device and its certificates.                                                                                                                                                           |
| `POST /auth/clients`                           | With password confirmation and `{ name, syncId }`, create a sync client computer (`syncId` is its Syncthing identity) and return its certificate, key, and authority in PEM format.               |
| `/client/sync/{pair,folders,syncs,syncs/<id>}` | With an active sync client certificate, forward to the client routes of `nas-sync-manager`, identifying the computer in `x-nas-client`. `pair` requires a previously unused certificate.          |
| `POST /auth/mobile`                            | With password confirmation and `{ name }`, create a NAS Mobile phone and return its certificate, key, and authority in PEM format.                                                                |
| `/client/files/api/<route>`                    | With a NAS Mobile phone certificate, forward to `nas-file-manager`: `files`, `directories`, `copy`, `move`, `search`, `volumes`, `storage`, `previews`, `uploads`, and `downloads`.               |
| `GET /auth/account`                            | With a session, return `{ username, email, recovery }`. `email` is the verified recovery address or `null`; `recovery` indicates whether email password reset is enabled.                         |
| `PUT /auth/account/username`                   | With password confirmation and `{ username }`, change the sign-in name while keeping sessions active.                                                                                             |
| `PUT /auth/account/password`                   | With password confirmation and `{ password }`, change the password and close other sessions.                                                                                                      |
| `PUT /auth/account/share-password`             | With a session and `{ password }`, validate the account password as a confirmation and pass it to Samba for shared folders. Return 204, 403 for a wrong password, or 503 if Samba is unavailable. |
| `POST /auth/account/email`                     | With password confirmation and `{ email }`, send a verification code. Return 202, or 502 if sending fails.                                                                                        |
| `POST /auth/account/email/verify`              | With a session and `{ code }`, set the recovery address after successful verification; otherwise 400.                                                                                             |
| `DELETE /auth/account/email`                   | With password confirmation, remove the recovery address.                                                                                                                                          |
| `GET /auth/certificate`                        | With a session, return the active HTTPS certificate (subject, issuer, names, validity, fingerprint), authority, automatic names, and additional names.                                            |
| `PUT /auth/certificate/names`                  | With password confirmation and `{ names }`, set up to 20 additional NAS certificate names and immediately reissue the certificate.                                                                |
| `POST /auth/certificate/renew`                 | With password confirmation, issue a new NAS certificate using the same authority.                                                                                                                 |
| `PUT /auth/certificate/custom`                 | With password confirmation and PEM `{ certificate, key }`, validate and install a custom certificate.                                                                                             |
| `DELETE /auth/certificate/custom`              | With password confirmation, restore the NAS certificate.                                                                                                                                          |
| `GET /auth/https`                              | With a session, return the HTTPS connection settings: `{ port, force }`.                                                                                                                          |
| `PUT /auth/https`                              | With password confirmation and `{ port, force }`, save the HTTPS port and redirect policy.                                                                                                        |
| `PUT /auth/account/recovery`                   | With password confirmation and `{ enabled }`, enable or disable email password reset. Disabled by default.                                                                                        |
| `GET /auth/recovery`                           | Public `{ enabled }` response indicating whether sign-in offers password reset: recovery must be enabled and the email address verified.                                                          |
| `POST /auth/recovery`                          | Public `{ username }` request. When recovery is enabled, send a code to the verified address. Always return 202, or 429.                                                                          |
| `POST /auth/recovery/reset`                    | Public `{ username, code, password }` request. A valid code changes the password and closes all sessions; otherwise 400.                                                                          |

No route creates the account. The wizard creates it locally before the gateway starts listening,
using `nas-os-gateway account create`. This command reads the username and password from two
lines of standard input, never from command-line arguments, and applies the same validation as
sign-in. The username must also be available for the terminal user that the wizard creates with
the same name. Exit codes are 0 for successful creation, 2 for an invalid username or password,
3 if an account already exists, and 1 if the database cannot be opened.

`nas-os-gateway --version` prints the version. The launcher reads it to offer gateway updates
alongside its own and installs them by rerunning `gateway_installation/install.sh` from the
release package.

Accounts and sessions live in the gateway's SQLite database (`migrations/`). Its location is
`GATEWAY_DB_PATH`, otherwise `gateway.db` in the systemd state directory, or `data/gateway.db` in
a debug build. At startup and once a day, the gateway creates a consistent copy in the adjacent
`copies/gateway.db` using `VACUUM INTO` while running. Passwords are hashed with Argon2id, and
session tokens are stored as SHA-256 hashes. Sessions expire after 30 minutes of inactivity or
12 hours after sign-in. Once an address reaches the configured failed-attempt limit, the
gateway returns 429 until the lockout expires. The default policy is enabled, with five attempts
and a one-minute lockout. Without an account, all sign-in attempts are rejected.

## HTTPS and mTLS

With `GATEWAY_TLS_PORT`, the gateway terminates TLS itself through rustls. On first start it
creates the NAS CA in `pki/` beside the database, or in `GATEWAY_PKI_DIR` if set, with a private
key readable only by the gateway. It uses this CA to sign its server certificate for the hostname,
its `.local` variant, `localhost`, `127.0.0.1`, the primary address, and names from
`GATEWAY_TLS_NAMES`. At startup it reissues the certificate if the names change or fewer than
30 days remain before expiration. `GATEWAY_PORT` serves the same UI and APIs over HTTP, unless
HTTPS redirection is enabled in settings. Session cookies use `Secure` only on HTTPS connections.
Without `GATEWAY_TLS_PORT`, as in development, the gateway listens over plain HTTP.

`GET /auth/https` returns `{ port, force }` for the signed-in user. `PUT /auth/https` requires
password confirmation and saves those connection settings in `gateway.connection`, beside the
database. The gateway binds the new port before replacing the current listener and updates the
base firewall through the existing `nas-os-firewall.service`. A failed bind or firewall update
keeps the previous settings. These changes never regenerate the server certificate or CA, and
do not replace an installed custom certificate. With enforcement enabled, HTTP requests receive
a temporary redirect preserving their path and query. The physical screen and loopback health
checks retain their local HTTP access. Update the wizard's base firewall and the launcher helper
alongside the gateway before enabling a custom port.

With `GATEWAY_SCREEN_PORT` (8081 in the service unit), the gateway also listens over HTTP on
`127.0.0.1` for the monitor connected to the NAS. The base firewall permits access only to the
screen's browser user. Sign-in still requires a password but does not require a device
certificate, because the user is physically at the machine.

Each TLS handshake requests a client certificate signed by the NAS CA but also accepts clients
without one. When mTLS is enabled (disabled by default), requests without a valid device
certificate receive an explanatory 403 page. `/health` and `/auth/ca.crt` remain public. Devices
are identified by the SHA-256 fingerprint of their certificate. A new certificate is `pending`
until its first sign-in, then becomes `active`. Revocation is recorded in the database without
a CRL. Device files are PKCS#12 archives containing the key, certificate, and CA, encrypted with
a random password shown only once. Enabling mTLS requires a valid certificate on the current
connection, and that certificate cannot be revoked from the same connection, preventing lockout.

A NAS Sync client receives its certificate through `POST /auth/clients` after password
confirmation. It can then access only `/client/sync/...`. The gateway validates the certificate,
removes any incoming `x-nas-client` header, sets it to the computer's Syncthing identity, and
starts `nas-sync-manager` if it is not responding. Revoking or removing the computer asks that
application to remove its Syncthing identity and sync rules. Until the application confirms, the
gateway retries every five minutes (`sync_revocations`). New computers cannot request a
certificate while mTLS is enabled.

A NAS Mobile phone receives its certificate through `POST /auth/mobile` after password
confirmation. It can then access only the `nas-file-manager` routes that list, search, and modify
disk files, excluding application settings, shares, trash, and documents. The gateway streams
the request body without buffering it, sets the account in `x-nas-user`, and marks the request
as encrypted. The phone appears among the devices in Security Center, where it can be revoked
or removed like other devices (`mobile` column, migration `0006_mobile_clients.sql`).

The wizard only uses `nas-os-gateway ca` to create the HTTPS CA and creates the password account.
Devices and mTLS activation are managed in Security Center after signing in: create and import
the first certificate, reopen the NAS over HTTPS, then enable mTLS with password confirmation.
The local administration command
`nas-os-gateway device create --name <name> [--icon <icon>] [--enable-mtls]` remains available
on the NAS and outputs the CA, certificate file, and password as one JSON line. If a device with
the same name has a previously unused certificate, it is renewed rather than duplicated.

## On the NAS

With `GATEWAY_UI_DIR`, the gateway serves the UI installed by the launcher in
`/usr/local/share/nas-os/ui`. It forwards `/api/*` to the launcher only with an active session
(`GATEWAY_LAUNCHER`, default `127.0.0.1:3000`). Exceptions are `GET /api/setup`, which the UI
calls before sign-in to check whether the NAS is ready, and `/api/access/failures`. Applications
under `/apps/<id>/` are forwarded in the same way, with an active session and without the
session cookie.

The gateway removes any browser-supplied `X-NAS-User` header and sets it to the signed-in username.
It similarly sets `X-NAS-Secure: 1` only for requests received over TLS or from the NAS screen.
The launcher requires this before accepting or returning passwords or keys for disk encryption
or network disks. System reset (`POST /api/system/reset`), configuration export
(`GET /api/system/config`), and configuration import (`POST /api/system/config`) require the
account password again. The browser sends it to `POST /auth/confirm`, which returns a code valid
for one request within one minute. The browser includes it in `X-NAS-Confirmation`. The gateway
removes the code and forwards the request with its body intact, adding `X-NAS-Reauthenticated`
and the username. Browser-supplied authentication headers cannot be trusted. The password never
reaches the launcher. A wrong password returns `403`, keeps the session active, and counts toward
the address's failed-attempt limit, just like a failed sign-in. The launcher remains on loopback.

The active HTTPS certificate is held in memory and replaced without a restart; rustls reads it
for each connection. The NAS certificate covers automatic names (hostname, `.local`,
`localhost`, `127.0.0.1`, primary address, and `GATEWAY_TLS_NAMES`) plus names added through
settings (`server.extra` in the authority directory). Every hour the gateway checks the names
and reissues the certificate only if they change, for example after an address change. A custom
certificate (`custom.crt` and `custom.key`, with key mode `0600`) overrides the NAS certificate
while valid. Its key must match, and its validity period must include the current time;
otherwise it is rejected.

Changing the sign-in username only affects the gateway. The Linux terminal user and disk
folders under `.nas-users/<user>` keep the names created by the wizard. Email codes contain six
digits, expire after 15 minutes or five attempts, and are stored only as SHA-256 hashes. Recovery
codes cannot be resent within one minute. The gateway does not send mail itself: it calls the
launcher over loopback at `POST /internal/mail/code` with `{ to, purpose, code }` (`verify` or
`reset`), and the launcher delegates to the Email application (`nas-mail-client`). `/internal/`
is never forwarded from the browser. Recovery responses are identical whether the account or
address exists or not, and invalid codes count toward the address's failed-attempt limit.

## Installation

Each release publishes `nas-gateway-<version>-linux-x64.tar.gz` and its `.sha256`. The package
contains `packages/gateway_installation`; see its
[README](system/packages/gateway_installation/README.md).

## Checks

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
npm run test:scripts
```

`npm run release:test` runs all checks in sequence and builds the package. See
[DEVELOPMENT.md](DEVELOPMENT.md) for development and release details.

## NAS Finder

The gateway responds to NAS Finder requests on UDP 39877 with the hostname, configuration
status, and web port. The base firewall controls access: the port is open only to the local
network while it belongs to the `nas_discovery` set. The wizard opens it during initial setup
and closes it when handing control to the gateway. Afterward, the launcher reopens it only
while Security Center's network discovery option is enabled.

Behavior, checks, and verification limits are documented in
[NAS Finder integration](../destkop-apps/nas-finder/NAS-INTEGRATION.md).
Discovery does not change authentication, HTTPS, mTLS, or system access.
