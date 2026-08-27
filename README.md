# PhoneAuth / BioAuth

PhoneAuth is a transport-independent, offline-first authentication protocol.
The phone holds non-exportable private credentials; verifiers retain public
keys and policy. BLE is the first device link, not the identity or protocol.

## Repository

- `mobile/` — Flutter app, Riverpod state, protocol/core, and fake/BLE
  transports.
- `packages/phone_auth_native/` — Android Keystore, strong biometric
  `CryptoObject`, and native BLE GATT bridge.
- `desktop/` — Rust protocol/verifier, agent, CLI, and gated initrd scaffold.
- `docs/` — architecture, threat model, roadmap, and implementation status.

## Security status

The transport-independent request/signature path and fake end-to-end flow are
implemented and tested. Android authorization is auth-per-use and permits only
`BIOMETRIC_STRONG`; no app PIN, device-credential fallback, remembered
approval, or proximity approval exists.

Physical BLE is **not yet production-ready**: Android GATT and framing exist,
but cryptographic pairing, the production secure-session handshake, and the
desktop GATT adapter remain open. The app fails closed rather than treating a
raw BLE link as secure. QR/network follows only after that gate.

## Local checks

```text
cd mobile
flutter analyze
flutter test
flutter build apk --debug --flavor dev --target lib/main_dev.dart

cd ../desktop
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Production APKs are intentionally not signed with a debug key. Distribution
signing must be supplied by the release pipeline.
