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
  if ! read -r -p "   did it work? [y/n/s(kip)] " answer; then
    # No terminal to answer on. Unanswered is not the same as answered no,
    # and treating it as no would invent a defect per question out of a run
    # nobody was sitting at -- in a transcript meant to be attached to a
    # release, where the invented ones are indistinguishable from the real.
    say "SKIP  $name (no terminal to answer on)"
    SKIP=$((SKIP + 1))
    return
  fi
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
  # Asked of the signature rather than of the filename. The release workflow
  # falls back to Android's debug key when the signing secrets are absent and
  # names the file exactly the same either way, so the filename is the one
  # thing that cannot answer this.
  # python3 on a distribution, python on a Windows install; either runs it.
  PYTHON="$(command -v python3 || command -v python || true)"
  if [ -n "$PYTHON" ]; then
    check "the APK is signed with the project key" \
      "$PYTHON" "$(dirname "$0")/apk-signing-cert.py" "$APK" --expect project
  else
    say "SKIP  no python, so the APK signing key was not checked -- and the"
    say "      filename cannot tell you: a debug-signed release is named the"
    say "      same, cannot be installed over an existing copy, and the"
    say "      uninstall that unblocks it destroys pairings and vault"
    SKIP=$((SKIP + 1))
  fi
else
  say "FAIL  no APK among the artefacts"
  FAIL=$((FAIL + 1))
fi

# --- the desktop side -------------------------------------------------------
#
# Two artefacts carry the desktop side, and only one of them runs on the
# machine in front of you. The Linux tarball can be unpacked and driven in
# place, which is why it needs nothing installed. On Windows the same binaries
# arrive inside an installer, so the equivalent of "unpack it" is "install it",
# and what the checks then read is what it left on disk.
#
# Both paths end up setting the same three variables, and every check after
# this point uses those rather than asking again which platform it is on.
case "$(uname -s)" in
  MINGW* | MSYS* | CYGWIN*) PLATFORM=windows ;;
  Darwin) PLATFORM=macos ;;
  *) PLATFORM=linux ;;
esac
say "platform:  $PLATFORM"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

BIN=
SUFFIX=
EXTENSIONS=
INSTALLED=false

SETUP="$(ls "$ARTIFACTS"/PhoneAuth-Setup-*.exe 2>/dev/null | head -1 || true)"
TARBALL="$(ls "$ARTIFACTS"/phone-auth-linux-*.tar.gz 2>/dev/null | head -1 || true)"

if [ "$PLATFORM" = windows ] && [ -n "$SETUP" ]; then
  say ""
  say "note  Windows installer present: $(basename "$SETUP")"
  say "      Code signing is REL-07's remaining half. Until a certificate is"
  say "      configured, SmartScreen will warn, and that warning is correct."
  ask "the Windows installer installs and the tray starts" \
    "run $(basename "$SETUP"), then confirm the tray icon appears and shows a verifier name"

  # LOCALAPPDATA arrives with backslashes, and gluing forward slashes onto it
  # produces a path that works but that nobody can retype -- and this one is
  # printed for a person to paste into a browser's "load unpacked".
  ROOT_DIR="$(printf '%s' "${LOCALAPPDATA:-$HOME/AppData/Local}" | tr '\\' '/')/Programs/PhoneAuth"
  BIN="$ROOT_DIR/resources/bin"
  SUFFIX=.exe
  EXTENSIONS="$ROOT_DIR/resources/browser-extension"
  INSTALLED=true
  check "the install left the binaries where it says" test -d "$BIN"
elif [ -n "$TARBALL" ]; then
  check "the headless tarball extracts" tar -xzf "$TARBALL" -C "$WORK"
  BIN="$WORK/phone-auth"
  EXTENSIONS="$BIN/browser-extension"
  # Releases up to 1.0.1 copied the development source directory in here,
  # which is the one directory deliberately not loadable: both engines'
  # manifest shapes at once, and no per-browser subdirectory to point a
  # browser at. Worth naming, rather than failing the checks below on the
  # absence of directories this artefact never had.
  if [ -f "$EXTENSIONS/manifest.json" ] && [ ! -d "$EXTENSIONS/chrome" ]; then
    say "FAIL  the tarball ships the unloadable source directory, not the"
    say "      per-browser ones every other package ships"
    FAIL=$((FAIL + 1))
    EXTENSIONS=
  fi
else
  say "SKIP  no artefact for this platform, so the desktop half cannot run"
  SKIP=$((SKIP + 1))
fi

if [ -n "$BIN" ] && [ -d "$BIN" ]; then
  check "it carries the agent"        test -x "$BIN/phone-auth-agent$SUFFIX"
  check "it carries the CLI"          test -x "$BIN/phone-auth$SUFFIX"
  check "it carries the native host"  test -x "$BIN/phone-auth-webauthn-host$SUFFIX"

  # An installed binary that cannot say what it is is an installed binary
  # nobody can support.
  check "the CLI runs from the artefact" "$BIN/phone-auth$SUFFIX" --help

  # --- the identity the whole passkey path hangs on -----------------------
  #
  # On Chromium an unpacked extension's ID is a hash of the directory it was
  # loaded from, unless the manifest carries a `key` -- and the native host is
  # registered for one ID, chosen before anybody loads anything. 1.0.0 shipped
  # per-browser directories with the key stripped, so the ID moved with the
  # install path and the host answered a caller it had never heard of. The
  # symptom is a passkey prompt that never arrives and nothing in the browser
  # saying why, which is precisely the kind of thing a smoke test exists for.
  #
  # So the ID is derived here the way Chromium derives it, rather than read off
  # a screen and trusted.
  derive_chromium_id() {
    local key hex
    key="$(sed -n 's/.*"key": "\([^"]*\)".*/\1/p' "$1" | head -1)"
    [ -n "$key" ] || return 1
    hex="$(printf '%s' "$key" | base64 -d | sha256sum | cut -c1-32)"
    printf '%s' "$hex" | tr '0123456789abcdef' 'abcdefghijklmnop'
  }

  PINNED_ID=kiekpmjnpdkhpaanjefbmojlgmbdkdcg
  for browser in ${EXTENSIONS:+chrome edge}; do
    manifest="$EXTENSIONS/$browser/manifest.json"
    if [ ! -f "$manifest" ]; then
      say "FAIL  the $browser directory to load is missing"
      FAIL=$((FAIL + 1))
      continue
    fi
    derived="$(derive_chromium_id "$manifest" || true)"
    if [ "$derived" = "$PINNED_ID" ]; then
      say "PASS  the $browser directory loads as $PINNED_ID"
      PASS=$((PASS + 1))
    else
      say "FAIL  the $browser directory would load as '${derived:-a hash of its path}',"
      say "      not $PINNED_ID: the native host will refuse it"
      FAIL=$((FAIL + 1))
    fi
  done

  # Gecko never derives an ID from a key, so Firefox is a different question
  # with a different answer in the same place.
  if [ -n "$EXTENSIONS" ]; then
    check "the firefox directory pins its own id" \
      grep -q 'webauthn@bioauth.local' "$EXTENSIONS/firefox/manifest.json"
  fi

  # And the other half of the same fact: what the host was actually registered
  # for. Registered for one ID and loading another is the whole failure, and it
  # is invisible from either side alone.
  if [ "$INSTALLED" = true ]; then
    registered="$(reg.exe query \
      'HKCU\Software\Google\Chrome\NativeMessagingHosts\com.bioauth.webauthn' \
      2>/dev/null | sed -n 's/.*REG_SZ[[:space:]]*//p' | tr -d '\r')"
    if [ -z "$registered" ]; then
      say "FAIL  no native host registered for Chrome; the installer should have"
      say "      done this, and without it the extension relays nothing"
      FAIL=$((FAIL + 1))
    elif grep -q "$PINNED_ID" "$registered" 2>/dev/null; then
      say "PASS  the registered host allows $PINNED_ID"
      PASS=$((PASS + 1))
    else
      say "FAIL  the registered host does not allow $PINNED_ID:"
      say "      $registered"
      FAIL=$((FAIL + 1))
    fi
  fi

  # --- the agent ----------------------------------------------------------
  #
  # Started against a scratch root so this never touches the tester's real
  # pairings. Which also means it is NOT the agent the browser extension talks
  # to: the native host looks for the agent in the default location, so the
  # passkey section further down deliberately uses the installed app instead.
  ROOT="$WORK/root"
  mkdir -p "$ROOT"
  say ""
  say "-- starting the agent from the artefact, against a scratch root"
  "$BIN/phone-auth-agent$SUFFIX" --root "$ROOT" >>"$LOG" 2>&1 &
  AGENT=$!
  sleep 3
  check "the agent stays up" kill -0 "$AGENT"
  check "the CLI reaches it" "$BIN/phone-auth$SUFFIX" status --root "$ROOT"
  check "it starts with no phone paired" bash -c \
    "'$BIN/phone-auth$SUFFIX' devices --root '$ROOT' | grep -q '(none)'"
  check "it can print a pairing code" "$BIN/phone-auth$SUFFIX" pair --root "$ROOT"

  # --- the half that needs a person and a phone ---------------------------
  ask "the APK installs" \
    "install $APK on the phone and open it"
  ask "the phone pairs" \
    "run '$BIN/phone-auth$SUFFIX pair --root $ROOT' and scan the code; confirm the codes match on both sides"
  ask "an authorization is approved on the phone" \
    "run '$BIN/phone-auth$SUFFIX authorize --service sudo --action test --resource smoke --user \$USER --root $ROOT' and approve it"
  ask "a refusal is a refusal" \
    "run the same command again and decline on the phone; the CLI must exit 1"
  ask "the vault lists from the desktop" \
    "add one item on the phone, then run '$BIN/phone-auth$SUFFIX vault list --root $ROOT'"
  ask "a copy is approved on the phone with its context" \
    "run '$BIN/phone-auth$SUFFIX vault copy <item> --root $ROOT'; the phone must name this computer and the item before releasing anything"
  ask "the File Locker round-trips" \
    "lock and unlock a scratch file with '$BIN/phone-auth$SUFFIX locker ...'"

  kill "$AGENT" 2>/dev/null || true
  wait "$AGENT" 2>/dev/null || true
fi

# --- passkeys ---------------------------------------------------------------
#
# The reason 1.0 was cut, and the one feature no amount of CLI exercising
# reaches: it runs through a browser, an extension, a native host and the
# installed agent, and every one of those four is a place it has silently
# failed before.
#
# Against the installed app on purpose. The native host resolves the agent from
# the default root, so the scratch-root agent above is invisible to it -- which
# means this section needs a phone paired with the real one.
if [ -n "$EXTENSIONS" ] && [ -d "$EXTENSIONS" ]; then
  say ""
  say "-- passkeys, against the installed app and a phone paired with it"
  say "   load unpacked from $EXTENSIONS/<browser>"
  say "   not from a phoneauth-passkeys-*.zip: those are store uploads with the"
  say "   key removed, and they load under an ID the host will refuse"

  ask "the extension loads with the pinned id" \
    "load $EXTENSIONS/chrome unpacked and confirm chrome://extensions shows $PINNED_ID"
  ask "a passkey registers" \
    "on https://webauthn.io register a credential; the phone must prompt, and the browser must accept the result"
  ask "the same passkey authenticates" \
    "authenticate with it on the same site, approving on the phone"
  ask "a declined passkey fails closed" \
    "start an authentication and decline on the phone; the site must report a failure, not a hang"
  ask "the autofill bridge fills a vault password" \
    "open a login form, use the extension's action, and confirm the phone approves before anything is typed"
  ask "the tray survives it" \
    "confirm the tray is still running and still names the same verifier"
else
  say "SKIP  no extension directories, so the passkey half cannot run"
  SKIP=$((SKIP + 1))
fi

ask "revoking is immediate" \
  "forget the phone in the app; the desktop must stop being able to authorize"

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

# Skips count against it, the way they do in the pairing drill. The item this
# closes is "someone ran all of it against real artefacts", so exiting zero on
# a run with skips would close it on the strength of exactly the checks that
# needed nobody present.
if [ "$FAIL" -gt 0 ] || [ "$SKIP" -gt 0 ]; then
  say ""
  say "not a clean run: $FAIL failed, $SKIP not done."
  exit 1
fi
exit 0
