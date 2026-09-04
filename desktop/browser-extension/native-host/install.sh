#!/usr/bin/env bash
set -euo pipefail

host_name=com.bioauth.webauthn
action=install
host_path=
chrome_id=
edge_id=
firefox_id=webauthn@bioauth.local
browsers=chrome,edge,firefox
firefox_id_pattern='^[^[:space:]"\\]{1,255}$'

usage() {
  echo "usage: $0 [install|uninstall] [--host PATH] [--chrome-extension-id ID] [--edge-extension-id ID] [--firefox-extension-id ID] [--browsers LIST]" >&2
  exit 2
}

if [[ ${1:-} == install || ${1:-} == uninstall ]]; then action=$1; shift; fi
while (($#)); do
  case $1 in
    --host) host_path=${2:-}; shift 2 ;;
    --chrome-extension-id) chrome_id=${2:-}; shift 2 ;;
    --edge-extension-id) edge_id=${2:-}; shift 2 ;;
    --firefox-extension-id) firefox_id=${2:-}; shift 2 ;;
    --browsers) browsers=${2:-}; shift 2 ;;
    *) usage ;;
  esac
done

declare -A directory=(
  [chrome]="$HOME/.config/google-chrome/NativeMessagingHosts"
  [edge]="$HOME/.config/microsoft-edge/NativeMessagingHosts"
  [firefox]="$HOME/.mozilla/native-messaging-hosts"
)

json_escape() {
  local value=$1
  [[ $value != *$'\n'* && $value != *$'\r'* && $value != *$'\t'* ]] || { echo 'paths may not contain control characters' >&2; exit 2; }
  value=${value//\\/\\\\}; value=${value//\"/\\\"}
  printf '%s' "$value"
}

write_manifest() {
  local browser=$1 path=$2 id=$3 allowlist value temporary
  if [[ $browser == firefox ]]; then
    allowlist=allowed_extensions; value="\"$(json_escape "$id")\""
  else
    allowlist=allowed_origins; value="\"chrome-extension://$(json_escape "$id")/\""
  fi
  temporary="$path.tmp.$$"
  printf '{\n  "name": "%s",\n  "description": "PhoneAuth WebAuthn bridge",\n  "path": "%s",\n  "type": "stdio",\n  "%s": [%s]\n}\n' \
    "$host_name" "$(json_escape "$host_path")" "$allowlist" "$value" >"$temporary"
  chmod 0644 "$temporary"
  mv -f "$temporary" "$path"
}

IFS=, read -ra selected <<<"$browsers"
for browser in "${selected[@]}"; do
  [[ -n ${directory[$browser]+x} ]] || { echo "unsupported browser: $browser" >&2; exit 2; }
done

if [[ $action == uninstall ]]; then
  for browser in "${selected[@]}"; do
    rm -f -- "${directory[$browser]}/$host_name.json"
    rmdir --ignore-fail-on-non-empty "${directory[$browser]}" 2>/dev/null || true
  done
  exit 0
fi

[[ -n $host_path ]] || { echo '--host is required for installation' >&2; exit 2; }
[[ -f $host_path && -x $host_path ]] || { echo "host is not an executable file: $host_path" >&2; exit 2; }
host_path="$(cd -- "$(dirname -- "$host_path")" && pwd -P)/$(basename -- "$host_path")"
[[ $(basename -- "$host_path") == phone-auth-webauthn-host ]] || { echo 'host must be named phone-auth-webauthn-host' >&2; exit 2; }
# The mode bits say a file may be executed, not that it can be. A binary built
# for another architecture, or half-copied, satisfies `-x` and then fails
# silently at every launch the browser makes -- and a browser reports that as
# nothing at all. `--version` is the cheapest way to find out now.
"$host_path" --version >/dev/null 2>&1 || { echo "host will not run: $host_path" >&2; exit 2; }

for browser in "${selected[@]}"; do
  case $browser in
    chrome) id=$chrome_id ;;
    edge) id=$edge_id ;;
    firefox) id=$firefox_id ;;
  esac
  if [[ $browser == firefox ]]; then
    [[ $id =~ $firefox_id_pattern ]] || { echo 'invalid Firefox extension ID' >&2; exit 2; }
  else
    [[ $id =~ ^[a-p]{32}$ ]] || { echo "invalid $browser extension ID" >&2; exit 2; }
  fi
done

for browser in "${selected[@]}"; do
  case $browser in chrome) id=$chrome_id ;; edge) id=$edge_id ;; firefox) id=$firefox_id ;; esac
  mkdir -p -- "${directory[$browser]}"
  write_manifest "$browser" "${directory[$browser]}/$host_name.json" "$id"
done
