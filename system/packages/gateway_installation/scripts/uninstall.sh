#!/usr/bin/env bash
#
# Removes the gateway from the machine. **The account stays**: the database in its state directory
# is not deleted unless --purge asks for it, and even then a confirmation is required.
#
#   sudo scripts/uninstall.sh [--purge]
#
# The installation copies it to /usr/local/lib/nas-os-gateway/uninstall.sh, which the removal of
# the whole NAS, in the package of the wizard, runs.

set -euo pipefail

readonly NAME=nas-os-gateway
readonly RESTORE=${NAS_CONFIGURATION_HELPER:-/usr/local/lib/nas-wizard/packages/os_configuration/scripts/uninstall.sh}
purge=false
case ${1:-} in
  --purge) purge=true ;;
  '') ;;
  *) printf 'error: unknown option: %s\n' "$1" >&2 && exit 2 ;;
esac

say() { printf '\n== %s\n' "$1"; }
fail() {
  printf 'error: %s\n' "$1" >&2
  exit 1
}

[[ $EUID -eq 0 ]] || fail "it has to run as root: sudo $0 ${1:-}"

stop_unit() {
  local unit=$1 load
  shift
  load=$(systemctl show "$unit" --property=LoadState --value)
  if [[ $load != not-found ]]; then systemctl "$@" "$unit"; fi
}

say "Service"
# Read the entire listing: grep -q can close the pipe early and make pipefail skip the stop.
if systemctl list-unit-files --no-pager --no-legend | grep "^$NAME\.service[[:space:]]" >/dev/null; then
  systemctl disable --now "$NAME"
  rm -f "/etc/systemd/system/$NAME.service"
  systemctl daemon-reload
  echo "   stopped, disabled and unit removed"
else
  echo "   it was not installed"
fi

say "Password of the shared folders"
stop_unit nas-os-share-password.socket disable --now
rm -f /run/nas-os-share-password.sock
listing=$(systemctl list-units --all --plain --no-legend 'nas-os-share-password@*.service')
mapfile -t instances < <(printf '%s\n' "$listing" | awk 'NF { print $1 }')
if ((${#instances[@]} > 0)); then systemctl stop "${instances[@]}"; fi
rm -f /etc/systemd/system/nas-os-share-password.socket \
  '/etc/systemd/system/nas-os-share-password@.service'
systemctl daemon-reload
# The group goes with the gateway that was its one member.
if getent group nas-os-share-password >/dev/null; then
  [[ -x $RESTORE ]] || fail 'the system restoration helper is missing'
  existed=$("$RESTORE" --group-existed nas-os-share-password)
  if [[ $existed == no ]]; then groupdel nas-os-share-password; fi
fi
echo "   socket, unit and group removed"

say "Binary"
# This very script among them: bash has it open already, and goes on reading it.
rm -f "/usr/local/bin/$NAME" /usr/local/lib/nas-os-gateway/check.sh \
  /usr/local/lib/nas-os-gateway/uninstall.sh /usr/local/lib/nas-os-gateway/share-password.sh
rmdir /usr/local/lib/nas-os-gateway 2>/dev/null || true
echo "   binary and tools removed"

if $purge; then
  say "Account and sessions"
  printf '   About to delete the account and the sessions of the NAS.\n'
  read -r -p "   Type 'delete' to confirm: " answer
  if [[ $answer == delete ]]; then
    # The gateway runs as a dynamic user, whose state systemd keeps under /var/lib/private.
    rm -rf "/var/lib/$NAME" "/var/lib/private/$NAME"
    echo "   account and sessions removed"
  else
    echo "   cancelled: the account stays"
  fi
else
  say "Account"
  echo "   the account stays. To remove it: sudo $0 --purge"
fi

printf '\nDone.\n'
