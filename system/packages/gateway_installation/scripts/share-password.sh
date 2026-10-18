#!/usr/bin/env bash
#
# Keeps in Samba the password of the account of the NAS, for the folders shared on the local
# network. It runs as root for one connection of nas-os-share-password.socket, which only the
# gateway may open, and reads two lines from it:
#
#   set|update
#   <password>
#
# `set` makes (or makes again) the Samba account of the user of the shares, `update` changes it
# only where it was made. The user is the one of the machine the launcher created for the account
# of the setup wizard (nas-os-terminal@.service.d/user.conf). The answer is one line, `ok` or
# `error: <why>`. The password goes to smbpasswd on its standard input, never in an argument.

set -euo pipefail

readonly USER_CONF=${NAS_TERMINAL_DROPIN:-/etc/systemd/system/nas-os-terminal@.service.d}/user.conf

answer() {
  printf '%s\n' "$1"
  exit 0
}

request=''
password=''
IFS= read -r request || answer 'error: no request'
IFS= read -r password || answer 'error: no password'
case $request in
  set | update) ;;
  *) answer 'error: unknown request' ;;
esac
((${#password} >= 1 && ${#password} <= 128)) || answer 'error: the password is not valid'

if ! command -v smbpasswd >/dev/null || ! command -v pdbedit >/dev/null; then
  [[ $request == update ]] && answer ok
  answer 'error: samba is not installed'
fi

user=$(sed -n 's/^User=//p' "$USER_CONF" 2>/dev/null | head -n 1) || user=''
[[ $user =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || answer 'error: no user for the shares'
getent passwd "$user" >/dev/null || answer 'error: no user for the shares'

if [[ $request == update ]] && ! pdbedit --user="$user" >/dev/null 2>&1; then
  answer ok
fi

printf '%s\n%s\n' "$password" "$password" | smbpasswd -s -a "$user" >/dev/null 2>&1 ||
  answer 'error: samba refused the password'
smbpasswd -e "$user" >/dev/null 2>&1 || answer 'error: samba did not enable the user'
answer ok
