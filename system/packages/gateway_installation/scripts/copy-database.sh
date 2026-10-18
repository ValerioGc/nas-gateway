#!/usr/bin/env bash
#
# Copies the database of the gateway before an update, so going back to the previous release finds
# the account and the sessions as it knew them:
#
#   scripts/copy-database.sh <state directory>
#
# install.sh runs it with the gateway stopped, then gateway.db and its write-ahead log, when there
# is one, are one consistent set of files, copied together with their owner (the dynamic user of the
# unit) into before-update/gateway-<UTC time>.db. The last five copies are kept.

set -euo pipefail

readonly KEPT=5

fail() {
  printf 'error: %s\n' "$1" >&2
  exit 1
}

state=${1:-}
[[ -n $state ]] || fail "usage: $0 <state directory>"
readonly database=$state/gateway.db
readonly copies=$state/before-update
[[ -f $database ]] || fail "no database at $database"

install -d -m 0700 "$copies"
chown --reference="$state" -- "$copies"
copy=$copies/gateway-$(date -u +%Y%m%dT%H%M%SZ).db
for suffix in '' -wal -shm; do
  [[ -e $database$suffix ]] && cp -a -- "$database$suffix" "$copy$suffix"
done
echo "   $database -> $copy"

mapfile -t made < <(find "$copies" -maxdepth 1 -name 'gateway-*.db' -printf '%f\n' | sort)
for ((index = 0; index < ${#made[@]} - KEPT; index++)); do
  rm -f -- "$copies/${made[index]}" "$copies/${made[index]}-wal" "$copies/${made[index]}-shm"
  echo "   older copy removed: ${made[index]}"
done
