#!/usr/bin/env bash
set -euo pipefail

mode=auto
dry_run=0
paths=()
while (($#)); do
  case "$1" in
    --lock) mode=lock ;;
    --unlock) mode=unlock ;;
    --auto) mode=auto ;;
    --dry-run) dry_run=1 ;;
    --) shift; paths+=("$@"); break ;;
    *) paths+=("$1") ;;
  esac
  shift
done

# Nautilus exposes local selections here. It is newline-delimited by Nautilus,
# so filenames containing a newline cannot be represented and are refused.
if ((${#paths[@]} == 0)) && [[ -n "${NAUTILUS_SCRIPT_SELECTED_FILE_PATHS:-}" ]]; then
  while IFS= read -r path; do
    [[ -n "$path" ]] && paths+=("$path")
  done <<<"$NAUTILUS_SCRIPT_SELECTED_FILE_PATHS"
fi

zenity_bin="${ZENITY_BIN:-zenity}"
phone_auth="${PHONEAUTH_BIN:-phone-auth}"
fail() {
  if ((dry_run)); then printf 'error: %s\n' "$*" >&2
  elif command -v "$zenity_bin" >/dev/null 2>&1; then
    "$zenity_bin" --error --title='PhoneAuth File Locker' --text="$*"
  else printf 'phone-auth-file-manager: %s\n' "$*" >&2
  fi
  exit 2
}

((${#paths[@]} > 0)) || fail 'Select at least one regular file.'
locked=0
plain=0
# Collected rather than assigned in place: `path` is the loop's own variable,
# so resolving it there left `paths` holding whatever was typed. That is the
# difference between naming a file and naming a name for it, and what it is
# handed to can delete the original.
resolved=()
for path in "${paths[@]}"; do
  [[ "$path" != *$'\n'* ]] || fail 'Filenames containing a newline are not supported by Nautilus scripts.'
  [[ -f "$path" ]] || fail "Not a regular file: $path"
  path="$(realpath -- "$path")"
  [[ "$path" == *.balock ]] && ((locked += 1)) || ((plain += 1))
  resolved+=("$path")
done
paths=("${resolved[@]}")

if [[ "$mode" == auto ]]; then
  if ((locked == ${#paths[@]})); then mode=unlock
  elif ((plain == ${#paths[@]})); then mode=lock
  else fail 'Lock and unlock selections cannot be mixed.'
  fi
fi
[[ "$mode" == lock && $locked -eq 0 || "$mode" == unlock && $plain -eq 0 ]] ||
  fail "The selected files do not match the requested $mode action."

args=(locker "$mode" "${paths[@]}")
((${#paths[@]} == 1)) || args+=(--batch)
if [[ "$mode" == lock ]]; then
  recovery="${PHONEAUTH_RECOVERY_OUT:-}"
  if [[ -z "$recovery" && $dry_run -eq 0 ]]; then
    command -v "$zenity_bin" >/dev/null 2>&1 || fail 'zenity is required to choose a recovery-code destination.'
    if ((${#paths[@]} == 1)); then
      recovery="$($zenity_bin --file-selection --save --confirm-overwrite \
        --title='Save the offline recovery code somewhere separate' \
        --filename="${paths[0]}.recovery")" || exit 1
    else
      recovery="$($zenity_bin --file-selection --directory \
        --title='Choose a directory for one recovery code per file')" || exit 1
    fi
  fi
  [[ -n "$recovery" ]] || recovery=RECOVERY_PATH
  args+=(--recovery-out "$recovery" --keep-original)
else
  args+=(--keep-container)
fi

if ((dry_run)); then
  printf '%q ' "$phone_auth" "${args[@]}"
  printf '\n'
  exit 0
fi

set +e
output="$("$phone_auth" "${args[@]}" 2>&1)"
status=$?
set -e
if command -v "$zenity_bin" >/dev/null 2>&1; then
  if ((status == 0)); then
    "$zenity_bin" --info --title='PhoneAuth File Locker' --text="$output"
  else
    "$zenity_bin" --error --title='PhoneAuth File Locker' --text="$output"
  fi
else
  printf '%s\n' "$output" >&2
fi
exit "$status"
