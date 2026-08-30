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

# Nautilus hands over absolute paths, but the `.desktop` entry and the command
# line do not have to, and what receives them can delete the original.
plan="$(cd -- "$tmp" && PHONEAUTH_RECOVERY_OUT="$recovery" \
  "$here/phone-auth-file-manager.sh" --dry-run --auto -- 'report with spaces.txt')"
# The file itself, not merely the directory: `--recovery-out` is absolute
# either way, so a plan that only has to mention `$tmp` somewhere passes
# whether or not the selection was resolved.
resolved="lock $tmp/report\ with\ spaces.txt"
if [[ "$plan" != *"$resolved"* ]]; then
  echo 'a relative selection reached phone-auth unresolved' >&2
  echo "$plan" >&2
  exit 1
fi

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
