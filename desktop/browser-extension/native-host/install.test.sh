#!/usr/bin/env bash
set -euo pipefail

root=$(mktemp -d)
trap 'rm -rf -- "$root"' EXIT
export HOME="$root/home"
host="$root/bin/phone-auth-webauthn-host"
mkdir -p -- "$(dirname -- "$host")"
printf '#!/usr/bin/env sh\nexit 0\n' >"$host"
chmod +x "$host"

installer=$(cd -- "$(dirname -- "$0")" && pwd -P)/install.sh
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
