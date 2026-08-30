#!/usr/bin/env bash
set -euo pipefail

root="${XDG_DATA_HOME:-$HOME/.local/share}"
scripts="$root/nautilus/scripts"
apps="$root/applications"
mime="$root/mime/packages"
source_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
launcher="$root/phone-auth/phone-auth-file-manager.sh"

if [[ "${1:-}" == --uninstall ]]; then
  rm -f -- "$scripts/Lock with PhoneAuth" "$scripts/Unlock with PhoneAuth" \
    "$apps/org.bioauth.phoneauth.locker.desktop" \
    "$mime/org.bioauth.phoneauth.locker.xml" "$launcher"
  command -v update-mime-database >/dev/null && update-mime-database "$root/mime" || true
  command -v update-desktop-database >/dev/null && update-desktop-database "$apps" || true
  exit 0
fi

mkdir -p -- "$scripts" "$apps" "$mime" "$(dirname -- "$launcher")"
install -m 755 "$source_dir/phone-auth-file-manager.sh" "$launcher"

cat >"$scripts/Lock with PhoneAuth" <<EOF
#!/bin/sh
exec "$launcher" --lock
EOF
cat >"$scripts/Unlock with PhoneAuth" <<EOF
#!/bin/sh
exec "$launcher" --unlock
EOF
chmod 755 "$scripts/Lock with PhoneAuth" "$scripts/Unlock with PhoneAuth"

cat >"$mime/org.bioauth.phoneauth.locker.xml" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<mime-info xmlns="http://www.freedesktop.org/standards/shared-mime-info">
  <mime-type type="application/x-bioauth-locker">
    <comment>BioAuth locked file</comment>
    <glob pattern="*.balock"/>
  </mime-type>
</mime-info>
EOF

cat >"$apps/org.bioauth.phoneauth.locker.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=PhoneAuth File Locker
Comment=Lock files or unlock BioAuth File Locker containers
Exec="$launcher" --auto %F
MimeType=application/x-bioauth-locker;
Terminal=false
NoDisplay=false
Categories=Utility;Security;
EOF

command -v update-mime-database >/dev/null && update-mime-database "$root/mime" || true
command -v update-desktop-database >/dev/null && update-desktop-database "$apps" || true
printf 'Installed Nautilus actions and the .balock handler under %s\n' "$root"
