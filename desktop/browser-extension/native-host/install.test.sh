#!/usr/bin/env bash
set -euo pipefail

root=$(mktemp -d)
trap 'rm -rf -- "$root"' EXIT
export HOME="$root/home"
host="$root/bin/phone-auth-webauthn-host"
mkdir -p -- "$(dirname -- "$host")"
# Stands in for the real binary, which answers `--version` and blocks on
# stdin for anything else. The installer only ever asks it the one question.
printf '#!/usr/bin/env sh\ncase ${1:-} in --version) echo "phone-auth-webauthn-host 0.0.0-test";; esac\nexit 0\n' >"$host"
chmod +x "$host"

installer=$(cd -- "$(dirname -- "$0")" && pwd -P)/install.sh

# A binary that exists, is executable, and does not run. The mode bits are
# satisfied and every launch the browser makes would fail silently -- which
# a browser reports as nothing at all -- so the installer has to refuse it
# here rather than leave a manifest behind pointing at it.
broken="$root/broken/phone-auth-webauthn-host"
mkdir -p -- "$(dirname -- "$broken")"
printf '#!/usr/bin/env sh\nexit 3\n' >"$broken"
chmod +x "$broken"
if "$installer" install --host "$broken" \
  --chrome-extension-id aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --edge-extension-id bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb 2>/dev/null; then
  echo 'installer accepted a host that will not run' >&2
  exit 1
fi
[[ ! -e "$HOME/.config/google-chrome/NativeMessagingHosts/com.bioauth.webauthn.json" ]]
"$installer" install --host "$host" \
  --chrome-extension-id aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --edge-extension-id bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb

chrome="$HOME/.config/google-chrome/NativeMessagingHosts/com.bioauth.webauthn.json"
edge="$HOME/.config/microsoft-edge/NativeMessagingHosts/com.bioauth.webauthn.json"
firefox="$HOME/.mozilla/native-messaging-hosts/com.bioauth.webauthn.json"
for manifest in "$chrome" "$edge" "$firefox"; do
  [[ -f $manifest ]]
  grep -Fq "\"path\": \"$host\"" "$manifest"
done
grep -Fq 'chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/' "$chrome"
grep -Fq 'chrome-extension://bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/' "$edge"
grep -Fq '"allowed_extensions": ["webauthn@bioauth.local"]' "$firefox"

"$installer" uninstall
[[ ! -e $chrome && ! -e $edge && ! -e $firefox ]]
echo 'Linux native-host installer test passed.'
