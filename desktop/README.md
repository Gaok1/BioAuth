# PhoneAuth — desktop

The verifier half. Holds public keys and policy, and nothing that could
authorize anything on its own.

```text
crates/phone-auth-protocol/   canonical CBOR, AuthRequest/Response, enrolment
crates/phone-auth-session/    handshake, key schedule, record layer
crates/phone-auth-verifier/   policy, replay guard, pairing store
crates/phone-auth-agent/      the daemon, its IPC surface, the QR transport
crates/phone-auth-cli/        `phone-auth`, for scripts and PAM
crates/phone-auth-initrd/     boot-time client for unlocking a LUKS volume
ui/                           Electron tray
nixos/                        package and NixOS module
```

## Running it

```bash
cargo run -p phone-auth-agent            # the daemon
(cd ui && npm install && npm start)      # the tray
```

The tray starts the agent when nothing is already serving, so on a packaged
install one launch brings up both. Under systemd — the NixOS module — the unit
owns the agent and the tray stays out of the way.

For development without a phone:

```bash
cargo run -p phone-auth-agent --features dev-simulator -- --dev-simulator
```

The simulator signs in-process with a software key. It is not a phone and
cannot unlock a disk. The feature is compile-time and off in every release
build, because a binary that could be flipped into simulator mode by a runtime
flag would defeat the point of gating it.

## Checks

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

`crates/phone-auth-session/tests/handshake_vectors.rs` asserts the values in
[`docs/protocol-handshake.md`](../docs/protocol-handshake.md), which the Flutter
app asserts independently. Where the two disagree, nothing works and the symptom
is always a decryption failure with no explanation — so those vectors matter
more than they look.

## Packaging

```bash
cargo build --release -p phone-auth-agent -p phone-auth-cli
cd ui && npm ci
npx electron-builder --win      # NSIS installer
npx electron-builder --linux    # AppImage and deb
```

The installers bundle the agent and the CLI alongside the tray. On Windows the
installer also adds a Startup shortcut: PhoneAuth has to be listening before you
need to approve anything, and an app you must remember to launch first is one
that is never running at the moment it matters.

`phone-auth-initrd` is Linux-only by intent — it unwraps an encrypted root
volume before there is a service manager — and is left out of the Windows build.

## NixOS

```nix
{
  inputs.phone-auth.url = "github:Gaok1/BioAuth";

  # in your configuration
  imports = [ inputs.phone-auth.nixosModules.default ];
}
```

`packages.default` is the headless set: agent, CLI and initrd client.
`packages.phone-auth-tray` also builds the Electron UI and needs an npm
dependency hash Nix can only produce by fetching — the release workflow prints
the current value.
