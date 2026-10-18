#!/usr/bin/env bash
#
# Checks that the gateway is installed and answers
#
#   scripts/check.sh

set -uo pipefail

readonly NAME=nas-os-gateway
readonly DATABASE=/var/lib/private/nas-os-gateway/gateway.db
readonly INTERFACE=/usr/local/share/nas-os/ui/index.html
problems=0

ok() { printf '  [ok]   %s\n' "$1"; }
no() {
  printf '  [KO]   %s\n' "$1"
  problems=$((problems + 1))
}
skip() { printf '  [--]   %s\n' "$1"; }

answers() {
  local name=$1 url=$2 code=''
  if command -v curl >/dev/null; then
    code=$(curl -s -k -o /dev/null -w '%{http_code}' --max-time 3 "$url" || true)
  elif command -v wget >/dev/null; then
    code=$(wget -S --no-check-certificate -O /dev/null -T 3 -t 1 "$url" 2>&1 | awk '/HTTP\//{code=$2} END{print code}')
  else
    skip "neither curl nor wget available"
    return
  fi
  [[ $code == 200 ]] && ok "$name answers 200" || no "$name does not answer (code: ${code:-none})"
}

printf '\n== Installation\n'
[[ -x /usr/local/bin/$NAME ]] && ok "binary installed" || no "binary missing from /usr/local/bin"
[[ -f /etc/systemd/system/$NAME.service ]] && ok "unit installed" || no "unit missing"
systemctl is-enabled --quiet "$NAME" && ok "enabled at boot" || no "not enabled at boot (systemctl enable $NAME)"
getent group nas-os-share-password >/dev/null && ok "group of the share password present" || no "group nas-os-share-password missing: the gateway does not start (run install.sh again)"
systemctl is-enabled --quiet nas-os-share-password.socket && ok "socket of the share password enabled" || no "nas-os-share-password.socket not enabled: the password of the shared folders does not reach Samba"

printf '\n== Service\n'
if systemctl is-active --quiet "$NAME"; then
  ok "service running"
  answers "/health on port 80" http://127.0.0.1/health
  port=443
  if [[ -r ${DATABASE%.db}.connection ]]; then IFS= read -r port <"${DATABASE%.db}.connection"; fi
  [[ $port =~ ^[1-9][0-9]{0,4}$ ]] && ((port <= 65535)) || exit 1
  answers "/health over HTTPS on port $port" "https://127.0.0.1:$port/health"
else
  no "service not running (journalctl -u $NAME)"
fi

printf '\n== Account\n'
if [[ $EUID -ne 0 ]]; then
  skip "sudo is needed to look at the database of the gateway"
elif [[ -f $DATABASE ]]; then
  ok "database present in $(dirname "$DATABASE")"
  [[ -f $(dirname "$DATABASE")/pki/ca.crt ]] && ok "authority of the NAS present" || no "no authority of the NAS yet: the gateway makes it when it starts"
else
  no "no database yet: the wizard creates it with the account (nas-os-gateway account create)"
fi

printf '\n== Interface\n'
[[ -f $INTERFACE ]] && ok "interface present for the gateway to serve" || no "interface missing from $(dirname "$INTERFACE"): install the launcher"

printf '\n'
if [[ $problems -eq 0 ]]; then
  printf 'All in order.\n'
else
  printf '%d things to fix. Run again: sudo ./install.sh\n' "$problems"
  exit 1
fi
