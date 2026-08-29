#!/usr/bin/env bash
# Runs the `desktop` CI job's checks on Linux, from any host with Docker.
#
# This exists because of a specific, repeated failure. The CI runs on
# `ubuntu-latest`; a contributor on Windows or macOS runs `cargo test` and sees
# it pass. Neither result is wrong — they are answers to different questions,
# and the gap between them is not small:
#
#   - `#[cfg(unix)]` code is not compiled at all on Windows, so an unused
#     binding or a broken assertion inside it is invisible to `clippy -D
#     warnings` no matter how carefully it is run.
#   - `std::env::temp_dir()` is a private per-user directory on Windows and
#     `/tmp` on Linux — root-owned, sticky, and not chmod-able by the user.
#     Code that narrows the permissions of a directory it writes into passes
#     on one and gets EPERM on the other.
#   - `symlink_metadata` and permission bits behave differently enough that a
#     test can be green on one platform and meaningless on it.
#
# Each of those cost a push, a five-minute CI round trip, and a wrong claim
# that the fix had been verified. Verifying on the host you happen to have is
# not verifying; it is sampling one of the two platforms and hoping.
#
#   tools/linux-check.sh              # fmt, clippy and the full test suite
#   tools/linux-check.sh -p phone-auth-locker --test container
#
# Any arguments are passed to `cargo test` instead of running the whole set,
# for iterating on one failure without recompiling everything.
#
# The container runs as a non-root user on purpose. As root the chmod on /tmp
# succeeds and the whole EPERM class of bug quietly disappears — which would
# make this script agree with the host it is meant to disagree with.

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${LINUX_CHECK_IMAGE:-rust:1}"
VOLUME="${LINUX_CHECK_VOLUME:-bioauth-linux-target}"

if ! docker info >/dev/null 2>&1; then
  echo "docker is not reachable. Start Docker Desktop (or the daemon) first." >&2
  echo "Without it there is no way to run these checks off Linux." >&2
  exit 2
fi

# Built here rather than inlined into `docker run`, so no shell quoting sits
# between this file and what actually executes.
INNER="$(mktemp)"
trap 'rm -f "$INNER"' EXIT

# Git Bash rewrites anything that looks like a Unix path in an argument,
# so `/work` reaches docker as `C:/Program Files/Git/work`.
# MSYS_NO_PATHCONV stops that, and the repo path then has to be spelled
# the way a Windows docker expects it.
REPO_MOUNT="$REPO"
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*)
    REPO_MOUNT="$(cygpath -w "$REPO")"
    export MSYS_NO_PATHCONV=1
    ;;
esac

{
  echo 'set -uo pipefail'
  # libdbus is not optional: `bluer` pulls `libdbus-sys`, whose build script
  # needs pkg-config to find the system library. This is also why the same
  # checks cannot simply be cross-compiled with `--target
  # x86_64-unknown-linux-gnu` from a Windows host.
  echo 'apt-get update -qq >/dev/null 2>&1'
  echo 'apt-get install -y -qq libdbus-1-dev pkg-config >/dev/null 2>&1'
  echo 'rustup component add rustfmt clippy >/dev/null 2>&1'
  echo 'id -u ci >/dev/null 2>&1 || useradd -m -u 1000 ci'
  echo 'mkdir -p /target'
  echo 'chown -R ci /target /usr/local/cargo /usr/local/rustup'
  if [ "$#" -gt 0 ]; then
    printf 'su ci -c %s\n' \
      "'export CARGO_TARGET_DIR=/target; cd /work/desktop && cargo test $* '"
  else
    cat <<'STEPS'
su ci -c '
  export CARGO_TARGET_DIR=/target
  cd /work/desktop || exit 1
  status=0
  echo "===== fmt ====="
  cargo fmt --all -- --check || status=1
  echo "===== clippy ====="
  cargo clippy --workspace --all-targets -- -D warnings || status=1
  echo "===== test ====="
  cargo test --workspace || status=1
  exit $status
'
STEPS
  fi
} > "$INNER"

# The script goes in on stdin rather than as a second mount: one less
# path for a host shell to rewrite on the way into the container.
docker run --rm -i \
  -v "$REPO_MOUNT:/work" \
  -v "$VOLUME:/target" \
  "$IMAGE" bash -s < "$INNER"
