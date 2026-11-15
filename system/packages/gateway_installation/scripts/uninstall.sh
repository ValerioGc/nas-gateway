#!/usr/bin/env bash
#
# Removes the gateway from the machine. The account and the sessions stay unless --purge asks for
# them. --purge asks to type 'delete' first, --yes next to it skips the question. The installation
# leaves it in /usr/local/lib/nas-os-gateway, where the removal of the whole NAS runs it.
#
#   sudo scripts/uninstall.sh [--purge [--yes]]

set -euo pipefail

readonly NAME=nas-os-gateway
readonly RESTORE=${NAS_CONFIGURATION_HELPER:-/usr/local/lib/nas-wizard/packages/os_configuration/scripts/uninstall.sh}
purge=false
confirmed=false
for argument in "$@"; do
  case $argument in
    --purge) purge=true ;;
    --yes) confirmed=true ;;
    *) printf 'error: unknown option %s\n' "$argument" >&2 && exit 2 ;;
  esac
done

say() {
  step=$1
  printf '\n== %s\n' "$1"
}
fail() {
  printf 'error: %s\n' "$1" >&2
  exit 1
}

[[ $EUID -eq 0 ]] || fail "it has to run as root, with sudo $0 $*"

stop_unit() {
  local unit=$1 load
  shift
  load=$(systemctl show "$unit" --property=LoadState --value)
  if [[ $load != not-found ]]; then systemctl "$@" "$unit"; fi
}

# Every step can be repeated, so a removal that stopped halfway is finished by running it again.
step='the start'
trap 'status=$?; ((status == 0)) || printf "error: the removal stopped at \"%s\", run it again to finish\n" "$step" >&2' EXIT

say "Service"
load=$(systemctl show "$NAME.service" --property=LoadState --value)
if [[ $load != not-found ]]; then
  systemctl disable --now "$NAME.service"
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
if getent group nas-os-share-password >/dev/null; then
  [[ -x $RESTORE ]] || fail 'the system restoration helper is missing'
  existed=$("$RESTORE" --group-existed nas-os-share-password)
  if [[ $existed == no ]]; then groupdel nas-os-share-password; fi
fi
echo "   socket, unit and group removed"

say "Binary"
rm -f "/usr/local/bin/$NAME" /usr/local/lib/nas-os-gateway/check.sh \
  /usr/local/lib/nas-os-gateway/uninstall.sh /usr/local/lib/nas-os-gateway/share-password.sh
rmdir /usr/local/lib/nas-os-gateway 2>/dev/null || true
echo "   binary and tools removed"

if $purge; then
  say "Account and sessions"
  printf '   About to delete the account and the sessions of the NAS.\n'
  if $confirmed; then
    answer=delete
  else
    read -r -p "   Type 'delete' to confirm: " answer
  fi
  if [[ $answer == delete ]]; then
    rm -rf "/var/lib/$NAME" "/var/lib/private/$NAME"
    echo "   account and sessions removed"
  else
    echo "   cancelled, the account stays"
  fi
else
  say "Account"
  echo "   the account stays, sudo $0 --purge removes it"
fi

printf '\nDone.\n'
