#!/usr/bin/env bash
#
# Installs the gateway of the NAS, the binary and its unit
# serving HTTP on port 80 and HTTPS on port 443 without an automatic redirect.
#
#   sudo ./install.sh [--no-start] [path/to/binary]
#   ./install.sh --dry-run        # prints the commands without running them
#
# It runs from the release package (`npm run release:package`), which puts the binary in bin/ next
# to this script. The wizard runs it with --no-start. It holds port 80 while it works, creates the
# account with `nas-os-gateway account create` and starts the gateway itself when it is done.
#
# Before the new binary takes over, the database in its state directory is copied, with the gateway
# stopped, so the previous release can be put back with the account and the sessions it knew
# (scripts/copy-database.sh).

set -euo pipefail

readonly NAME=nas-os-gateway
readonly BINARY_TARGET=/usr/local/bin/nas-os-gateway
readonly UNIT_TARGET=/etc/systemd/system/nas-os-gateway.service

readonly STATE_DIR=/var/lib/private/nas-os-gateway
readonly TOOLS_DIR=/usr/local/lib/nas-os-gateway
readonly SHARE_GROUP=nas-os-share-password
readonly SHARE_SOCKET=nas-os-share-password.socket
readonly SHARE_SOCKET_TARGET=/etc/systemd/system/nas-os-share-password.socket
readonly SHARE_UNIT_TARGET='/etc/systemd/system/nas-os-share-password@.service'

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
dry_run=false
start=true
binary_source=''

for argument in "$@"; do
  case $argument in
    --dry-run) dry_run=true ;;
    --no-start) start=false ;;
    -*) printf 'unknown option: %s\n' "$argument" >&2 && exit 2 ;;
    *) binary_source=$argument ;;
  esac
done
binary_source=${binary_source:-"$here/bin/nas-os-gateway"}

say() { printf '\n== %s\n' "$1"; }
fail() {
  printf 'error: %s\n' "$1" >&2
  exit 1
}

run() {
  if $dry_run; then
    printf '   [dry run] %s\n' "$*"
  else
    "$@"
  fi
}

if ! $dry_run; then
  [[ $EUID -eq 0 ]] || fail "it has to run as root: sudo $0"
fi
[[ -f $binary_source ]] || fail "binary not found at $binary_source
  build it first:  cargo build --release
  or run this script from the release package (npm run release:package)"
command -v systemctl >/dev/null || fail "systemd is not available on this machine"
$dry_run && printf '\nDry run: no change will be applied.\n'

# Keep uninstallation available even if installation stops halfway through.
run install -d -m 0755 -o root -g root "$TOOLS_DIR"
run install -m 0755 -o root -g root "$here/scripts/uninstall.sh" "$TOOLS_DIR/uninstall.sh"

say "Copy of the database"
was_active=false
if [[ -f $STATE_DIR/gateway.db ]]; then
  systemctl is-active --quiet "$NAME" && was_active=true
  if $was_active; then
    run systemctl stop "$NAME"
  fi
  run bash "$here/scripts/copy-database.sh" "$STATE_DIR"
else
  echo "   no database yet: nothing to copy"
fi

say "Binary"
run install -m 0755 -o root -g root "$binary_source" "$BINARY_TARGET"
echo "   $binary_source -> $BINARY_TARGET"

say "Tools on the machine"
run install -m 0755 -o root -g root "$here/scripts/check.sh" "$TOOLS_DIR/check.sh"
run install -m 0755 -o root -g root "$here/scripts/share-password.sh" "$TOOLS_DIR/share-password.sh"
echo "   $TOOLS_DIR/check.sh, uninstall.sh and share-password.sh"

say "Password of the shared folders"
if getent group "$SHARE_GROUP" >/dev/null; then
  echo "   group $SHARE_GROUP already there"
else
  run groupadd --system "$SHARE_GROUP"
fi
run install -m 0644 -o root -g root "$here/files/nas-os-share-password.socket" "$SHARE_SOCKET_TARGET"
run install -m 0644 -o root -g root "$here/files/nas-os-share-password@.service" "$SHARE_UNIT_TARGET"
echo "   $SHARE_SOCKET: only the gateway may hand the password to Samba"

say "Systemd unit"
run install -m 0644 -o root -g root "$here/files/nas-os-gateway.service" "$UNIT_TARGET"
run systemctl daemon-reload
run systemctl enable "$NAME"
run systemctl enable --now "$SHARE_SOCKET"
if $start; then
  run systemctl restart "$NAME"
  echo "   $NAME started and enabled at boot, on ports 443 and 80"
elif $was_active; then
  run systemctl start "$NAME"
  echo "   $NAME started again and enabled at boot, on ports 443 and 80"
else
  echo "   $NAME enabled at boot, not started: whoever asked for --no-start starts it"
fi

say "Done"
address=$(hostname -I 2>/dev/null | awk '{print $1}') || address=''
cat <<EOF
   interface:  http://${address:-<address of this machine>}/
   HTTPS:      https://${address:-<address of this machine>}/
   status:     systemctl status $NAME
   log:        journalctl -u $NAME -f
   check:      $TOOLS_DIR/check.sh
   account:    created by the wizard (nas-os-gateway account create), with the sessions in
               /var/lib/private/$NAME/gateway.db (not touched by this script)
EOF
