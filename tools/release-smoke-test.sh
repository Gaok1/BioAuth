#!/usr/bin/env bash
# Release smoke test: REL-14.
#
# Building a package does not prove it works. This installs from the release
# artefacts, exercises the paths a first-time user takes, and records what
# happened — so the P0 stops being "somebody should check" and becomes a
# transcript with a date on it.
#
# Deliberately not a CI job. What it verifies is the artefact reaching a
# machine that never built it, which is the one thing a build runner cannot
# tell you about itself.
#
#   tools/release-smoke-test.sh ~/Downloads/phoneauth-v0.1.5
#
# The directory is the one the release assets were downloaded into. The phone
# half is prompted for by hand, because there is no way to script a fingerprint
# and pretending otherwise would test something else.

set -uo pipefail

ARTIFACTS="${1:-}"
if [ -z "$ARTIFACTS" ] || [ ! -d "$ARTIFACTS" ]; then
  echo "usage: $0 <directory of downloaded release artefacts>" >&2
  exit 2
fi

LOG="${ARTIFACTS}/smoke-$(date -u +%Y%m%dT%H%M%SZ).log"
PASS=0
FAIL=0
SKIP=0

say() { printf '%s\n' "$*" | tee -a "$LOG"; }

# Each check records its own verdict. Nothing aborts the run: a smoke test that
# stops at the first failure tells you about one problem per attempt, and the
# attempt costs an install.
check() {
  local name="$1"; shift
  if "$@" >>"$LOG" 2>&1; then
    say "PASS  $name"
    PASS=$((PASS + 1))
  else
    say "FAIL  $name"
    FAIL=$((FAIL + 1))
  fi
}

# For the halves that need a person and a phone.
ask() {
  local name="$1"
  local instruction="$2"
  say ""
  say "-- $instruction"
  read -r -p "   did it work? [y/n/s(kip)] " answer
  case "$answer" in
    y|Y) say "PASS  $name"; PASS=$((PASS + 1)) ;;
    s|S) say "SKIP  $name"; SKIP=$((SKIP + 1)) ;;
    *)   say "FAIL  $name"; FAIL=$((FAIL + 1))
         read -r -p "   what happened? " why
         say "      $why" ;;
  esac
}

say "PhoneAuth release smoke test"
say "artefacts: $ARTIFACTS"
say "host:      $(uname -s) $(uname -m)"
say "date:      $(date -u +%Y-%m-%dT%H:%M:%SZ)"
say ""

# --- what was downloaded ----------------------------------------------------
#
# Checksums first. Every check after this one is meaningless if the bytes are
# not the published bytes, and finding that out at the end wastes an install.

check "SHA256SUMS.txt is present" test -f "$ARTIFACTS/SHA256SUMS.txt"
if [ -f "$ARTIFACTS/SHA256SUMS.txt" ]; then
  check "every artefact matches its published checksum" \
    bash -c "cd '$ARTIFACTS' && sha256sum --check --ignore-missing SHA256SUMS.txt"
fi

# The APK's signature decides whether this build can ever upgrade in place. A
# debug-signed artefact is fine to test with and cannot be upgraded to a
# release-signed one — the user has to uninstall, and uninstalling destroys
# every Keystore-bound pairing, passkey and vault item.
APK="$(ls "$ARTIFACTS"/PhoneAuth-android*.apk 2>/dev/null | head -1 || true)"
if [ -n "$APK" ]; then
  case "$APK" in
    *-debug.apk)
      say "WARN  the APK is debug-signed: it cannot be upgraded in place, and"
      say "      uninstalling it destroys the pairings and vault created here" ;;
    *) say "note  release-signed APK: $(basename "$APK")" ;;
  esac
else
  say "FAIL  no APK among the artefacts"
  FAIL=$((FAIL + 1))
fi

# --- the desktop side -------------------------------------------------------
#
# The automated half runs against the Linux tarball, because it is the only
# artefact whose binaries can be exercised without an installer taking over the
# machine. On Windows the installer is checked for and the manual steps below
# are run against what it puts on disk — the phone half is identical either way.

SETUP="$(ls "$ARTIFACTS"/PhoneAuth-Setup-*.exe 2>/dev/null | head -1 || true)"
if [ -n "$SETUP" ]; then
  say "note  Windows installer present: $(basename "$SETUP")"
  say "      Code signing is REL-07's remaining half. Until it is configured,"
  say "      SmartScreen will warn, and that warning is the correct behaviour."
  ask "the Windows installer installs and the tray starts" \
    "run $(basename "$SETUP"), then confirm the tray icon appears and shows a verifier name"
fi

TARBALL="$(ls "$ARTIFACTS"/phone-auth-linux-*.tar.gz 2>/dev/null | head -1 || true)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

if [ -n "$TARBALL" ]; then
  check "the headless tarball extracts" tar -xzf "$TARBALL" -C "$WORK"
  BIN="$WORK/phone-auth"
  check "it carries the agent"  test -x "$BIN/phone-auth-agent"
  check "it carries the CLI"    test -x "$BIN/phone-auth"
  check "it carries the native host" test -x "$BIN/phone-auth-webauthn-host"
  check "it carries the extension"   test -f "$BIN/browser-extension/manifest.json"

  # An installed binary that cannot say what it is is an installed binary
  # nobody can support.
  check "the CLI runs from the artefact" "$BIN/phone-auth" --help

  # The agent is started against a scratch root so this never touches the
  # tester's real pairings.
  ROOT="$WORK/root"
  mkdir -p "$ROOT"
  say ""
  say "-- starting the agent from the artefact"
  "$BIN/phone-auth-agent" --root "$ROOT" >>"$LOG" 2>&1 &
  AGENT=$!
  sleep 3
  check "the agent stays up" kill -0 "$AGENT"
  check "the CLI reaches it" "$BIN/phone-auth" status --root "$ROOT"
  check "it starts with no phone paired" bash -c \
    "'$BIN/phone-auth' devices --root '$ROOT' | grep -q '(none)'"
  check "it can print a pairing code" "$BIN/phone-auth" pair --root "$ROOT"

  # --- the half that needs a person and a phone ---------------------------
  ask "the APK installs" \
    "install $APK on the phone and open it"
  ask "the phone pairs" \
    "run '$BIN/phone-auth pair --root $ROOT' and scan the code; confirm the codes match on both sides"
  ask "an authorization is approved on the phone" \
    "run '$BIN/phone-auth authorize --service sudo --action test --resource smoke --user \$USER --root $ROOT' and approve it"
  ask "a refusal is a refusal" \
    "run the same command again and decline on the phone; the CLI must exit 1"
  ask "the vault lists from the desktop" \
    "add one item on the phone, then run '$BIN/phone-auth vault list --root $ROOT'"
  ask "a copy is approved on the phone with its context" \
    "run '$BIN/phone-auth vault copy <item> --root $ROOT'; the phone must name this computer and the item before releasing anything"
  ask "the File Locker round-trips" \
    "lock and unlock a scratch file with '$BIN/phone-auth locker ...'"
  ask "revoking is immediate" \
    "forget the phone in the app; the desktop must stop being able to authorize"

  kill "$AGENT" 2>/dev/null || true
  wait "$AGENT" 2>/dev/null || true
else
  say "SKIP  no Linux tarball among the artefacts"
  SKIP=$((SKIP + 1))
fi

# Uninstalling is part of the test, not cleanup after it: an app that cannot be
# removed cleanly is a release problem, and it is the step people skip.
ask "the app uninstalls cleanly" \
  "uninstall the app on the phone and confirm it leaves no notification or foreground service behind"

say ""
say "----"
say "pass $PASS   fail $FAIL   skip $SKIP"
say "transcript: $LOG"
say ""
say "Attach this file to the release. A smoke test with no record is a smoke"
say "test nobody can point at later."

[ "$FAIL" -eq 0 ]
