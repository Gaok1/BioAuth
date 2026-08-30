#!/usr/bin/env bash
set -euo pipefail

here="$(cd -- "$(dirname -- "$0")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf -- "$tmp"' EXIT
plain="$tmp/report with spaces.txt"
locked="$tmp/report with spaces.txt.balock"
recovery="$tmp/offline code.recovery"
printf plain >"$plain"
printf locked >"$locked"

plan="$(PHONEAUTH_RECOVERY_OUT="$recovery" "$here/phone-auth-file-manager.sh" \
  --dry-run --auto -- "$plain")"
[[ "$plan" == *'locker lock'* ]]
[[ "$plan" == *'--keep-original'* ]]
[[ "$plan" == *'offline\ code.recovery'* ]]

plan="$("$here/phone-auth-file-manager.sh" --dry-run --auto -- "$locked")"
[[ "$plan" == *'locker unlock'* ]]
[[ "$plan" == *'--keep-container'* ]]

if "$here/phone-auth-file-manager.sh" --dry-run --auto -- "$plain" "$locked"; then
  echo 'mixed selections were accepted' >&2
  exit 1
fi

XDG_DATA_HOME="$tmp/share" "$here/install-nautilus.sh"
test -x "$tmp/share/nautilus/scripts/Lock with PhoneAuth"
test -x "$tmp/share/nautilus/scripts/Unlock with PhoneAuth"
grep -F 'application/x-bioauth-locker' \
  "$tmp/share/mime/packages/org.bioauth.phoneauth.locker.xml"
grep -F -- '--auto %F' \
  "$tmp/share/applications/org.bioauth.phoneauth.locker.desktop"

XDG_DATA_HOME="$tmp/share" "$here/install-nautilus.sh" --uninstall
test ! -e "$tmp/share/nautilus/scripts/Lock with PhoneAuth"
test ! -e "$tmp/share/applications/org.bioauth.phoneauth.locker.desktop"
