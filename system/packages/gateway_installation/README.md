# Gateway installation

Scripts for installing the gateway on a real Debian 13 machine. On the NAS, the wizard runs them
after configuring the operating system. They are not needed for development.

| File                                                                         | Purpose                                                                                                   |
| ---------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| `install.sh`                                                                 | Install or update the binary and units; `--no-start` enables the service without starting it              |
| `scripts/check.sh`                                                           | Check that the gateway is installed and responding without changing anything                              |
| `scripts/uninstall.sh`                                                       | Remove the gateway; keep the account unless `--purge` is specified                                        |
| `scripts/copy-database.sh`                                                   | Copy the database before an update, retaining the five latest copies                                      |
| `files/nas-os-gateway.service`                                               | Service unit with a dynamic user and permission to bind privileged ports, including HTTP 80 and HTTPS 443 |
| `files/nas-os-share-password.socket`, `files/nas-os-share-password@.service` | Socket for passing shared-folder passwords to Samba, and the root service that handles it                 |
| `scripts/share-password.sh`                                                  | Helper that passes the password from stdin to Samba through `smbpasswd`                                   |
| `bin/nas-os-gateway`                                                         | Binary added during packaging                                                                             |

## Usage

The wizard runs the installer with `--no-start` because it uses port 80 during setup. It creates
the account with `nas-os-gateway account create` and starts the gateway when setup is complete.

To update an already configured NAS manually:

```bash
sha256sum -c nas-gateway-<version>-linux-x64.tar.gz.sha256
mkdir nas-gateway && tar -xzf nas-gateway-<version>-linux-x64.tar.gz -C nas-gateway
cd nas-gateway/packages/gateway_installation
./install.sh --dry-run
sudo ./install.sh
sudo /usr/local/lib/nas-os-gateway/check.sh
```

Installation preserves the account and sessions in `/var/lib/private/nas-os-gateway/gateway.db`,
the dynamic user's state directory, readable only by root. Before the new binary opens the
database and applies migrations, `install.sh` stops the gateway and copies the database and its
log files (`-wal`, `-shm`) into `before-update/gateway-<UTC-time>.db` beside it. With the service
stopped, these files form a consistent set. The five latest copies are retained. Even with
`--no-start`, a previously running gateway is restarted.

`install.sh` also creates the `nas-os-share-password` group before installing the unit that
references it. This is the gateway's only supplementary group, and the only group allowed to
open `/run/nas-os-share-password.sock`. To disable password forwarding to Samba, run
`sudo systemctl disable --now nas-os-share-password.socket`.

To restore the previous version, including its account and sessions:

```bash
sudo systemctl stop nas-os-gateway
cd /var/lib/private/nas-os-gateway
sudo rm -f gateway.db-wal gateway.db-shm
for suffix in '' -wal -shm; do
  [[ -e before-update/gateway-<time>.db$suffix ]] && sudo cp -a before-update/gateway-<time>.db$suffix gateway.db$suffix
done
cd -    # The package directory of the previous version
sudo ./install.sh
```

The running gateway also creates a consistent copy at startup and once a day using `VACUUM INTO`
without stopping: `copies/gateway.db` in the same directory. Use this copy for backups instead of
the live database files.

## Installed files

The installer keeps `/usr/local/bin/nas-os-gateway`,
`/etc/systemd/system/nas-os-gateway.service`, and the `check.sh` and `uninstall.sh` tools in
`/usr/local/lib/nas-os-gateway/` on the machine, because the release package is not retained.

## Removal

```bash
sudo /usr/local/lib/nas-os-gateway/uninstall.sh            # Remove the service and binary; keep the account
sudo /usr/local/lib/nas-os-gateway/uninstall.sh --purge    # Also remove the account and sessions, with confirmation
```

The wizard's package handles full NAS removal and delegates gateway removal to this script.
