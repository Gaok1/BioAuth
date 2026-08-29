#!/usr/bin/env bash
# Physical PC↔phone drill: REL-13.
#
# `docs/pairing-reliability-plan.md` lists ten boundaries to drop the
# connection at and five matrices to walk. Every one of them is currently
# tested against doubles, which is exactly the class of bug the plan was
# written after: the doubles agreed with each other and the devices did not.
#
# This does not automate the drops — dropping a real link at a real boundary
# means pulling Wi-Fi, killing a process, or walking out of range, and a script
# that faked those would be testing the fake. What it does is make the run
# ordered, complete and recorded, so a partial drill is visibly partial instead
# of quietly so.
#
#   tools/pairing-drill.sh [--resume transcript.log]
#
# Each step names the invariant it exists to break. A step that passes for the
# wrong reason is worse than a failure, so the expected behaviour is stated
# before the question rather than left to the tester's memory.

set -uo pipefail

RESUME=""
[ "${1:-}" = "--resume" ] && RESUME="${2:-}"

LOG="${RESUME:-pairing-drill-$(date -u +%Y%m%dT%H%M%SZ).log}"
PASS=0; FAIL=0; SKIP=0

say() { printf '%s\n' "$*" | tee -a "$LOG"; }

# Steps with a verdict are not asked again, so a drill interrupted after step
# seven resumes at eight. A drill that has to restart from the top is a drill
# that gets abandoned.
#
# A previous SKIP does not count. Those are precisely the steps a resume exists
# to finish, and treating them as done would let a partial drill launder itself
# into a complete-looking one.
done_already() {
  [ -n "$RESUME" ] || return 1
  grep -qE "^(PASS|FAIL)  \[$1\]" "$LOG" 2>/dev/null
}

step() {
  local id="$1" invariant="$2" action="$3" expected="$4"
  if done_already "$id"; then
    say "SKIP  [$id] already recorded"
    SKIP=$((SKIP + 1))
    return
  fi
  say ""
  say "[$id] invariant: $invariant"
  say "      do:       $action"
  say "      expect:   $expected"
  read -r -p "      result [y/n/s]: " answer
  case "$answer" in
    y|Y) say "PASS  [$id]"; PASS=$((PASS + 1)) ;;
    s|S) say "SKIP  [$id]"; SKIP=$((SKIP + 1)) ;;
    *)   read -r -p "      what happened instead? " why
         say "FAIL  [$id] $why"; FAIL=$((FAIL + 1)) ;;
  esac
}

say "PhoneAuth pairing drill — REL-13"
say "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
say "phone / android version: ${PHONE:-unrecorded}"
say "desktop:                 $(uname -s) $(uname -m)"
say ""
say "Set PHONE=... before running so the transcript says what it was run on."

# --- the ten boundaries -----------------------------------------------------

step B1 "8: failure always ends in a state with a clear retry" \
  "start pairing, then kill the phone's Wi-Fi before the ServerHello arrives" \
  "both sides show a failure with a retry, and neither shows a spinner that never ends"

step B2 "7: connected means an authenticated handshake finished" \
  "drop the link immediately after the handshake, before any request" \
  "the phone leaves connected rather than sitting on it, and reconnects on its own"

step B3 "2: every attempt has its own identity" \
  "drop the link just before the enrolment is sent" \
  "the desktop's attempt is not confirmable afterwards; a new QR is required"

step B4 "5: revocation only reads as done once it is persisted" \
  "drop the link just after the enrolment is sent, before the desktop persists" \
  "no half-pairing survives: either both sides have it or neither, and a new QR repairs it"

step B5 "10: an old confirmation never confirms a new attempt" \
  "start an attempt, cancel it, start another, then confirm with the FIRST code" \
  "the confirmation is refused even if the six digits happen to match"

step B6 "9: a new QR repairs any one-sided pairing" \
  "force a one-sided state (B4), then scan a fresh QR" \
  "pairing completes and the stale side is replaced, not duplicated"

step B7 "6: a removed record leaves no parked session" \
  "leave a paired session idle, then pull the network for two minutes and restore it" \
  "the phone returns to connected by itself, without the four-minute idle timeout"

step B8 "8: a failed authorization has a clear retry" \
  "start an authorization and drop the link while the phone is showing it" \
  "the desktop reports a failure rather than a grant, and the phone does not leave a stale prompt"

step B9 "5 and 6: revocation is immediate and survives" \
  "revoke the desktop on the phone while a session is live" \
  "the live session closes at once — not after four minutes — and the desktop can no longer authorize"

step B10 "1: at most one active attempt per verifier" \
  "after a refusal, immediately arm a new QR" \
  "the new attempt gets a new code, and the refused one cannot be confirmed"

step B11 "5: revocation survives a restart" \
  "restart the phone app, the agent and the tray, separately, after a revocation" \
  "the revoked device does not reappear in any of the three"

# --- the five matrices ------------------------------------------------------

step M1 "9" "revoke on the phone, then new QR, then pair again" \
  "pairing completes and the device appears once on both sides"

step M2 "6 and 9" "forget on the PC, then new QR, then pair again" \
  "the peer is gone from the listener immediately, and re-pairing works"

step M3 "5" "revoke on the phone with the PC offline, then bring the PC back" \
  "the PC does not resurrect the pairing, and a new QR repairs it"

step M4 "4: reading pending state does not consume it" \
  "lose the IPC reply (close the tray window mid-pairing), then reopen it" \
  "the same six-digit code is still shown — not a new one, and not nothing"

step M5 "7 and 8" "drop Wi-Fi during a live session and restore it" \
  "the phone goes unreachable and returns to connected on its own, with no tap"

say ""
say "----"
say "pass $PASS   fail $FAIL   skip $SKIP"
say "transcript: $LOG"
say ""
if [ "$SKIP" -gt 0 ]; then
  say "Skipped steps mean this drill is partial. Re-run with:"
  say "  tools/pairing-drill.sh --resume $LOG"
fi
say "Attach this file to the release. REL-13 closes on a complete transcript,"
say "not on a recollection of having tried most of it."

[ "$FAIL" -eq 0 ] && [ "$SKIP" -eq 0 ]
