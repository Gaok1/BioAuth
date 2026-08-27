# PhoneAuth Roadmap

## Current: Phase 1 — Core PhoneAuth

- [x] Flutter Material 3 shell, Riverpod state, contextual approval UI, audit UI
- [x] Explicit connection/authorization states and debug-only mocks
- [x] Approval duplicate grouping, flood warning, temporary device block
- [x] Canonical transport-independent `AuthRequest`/`AuthResponse`, with a
      shared Dart/Rust golden vector
- [x] `AuthTransport` and `SecureTransportSession`
- [x] Full FakeTransport -> biometric abstraction -> signature -> verifier test
- [x] Android Keystore authorization credential
- [x] `BIOMETRIC_STRONG` + `BiometricPrompt.CryptoObject(Signature)`
- [ ] Cryptographic PhoneAuth pairing and per-verifier permissions
- [x] Desktop agent, CLI verifier and tray UI (see `desktop.md`)

Exit gate: the same encoded request and authorization core run unchanged over a
fake session and BLE; the verifier checks the full context-bound signature.

The transport-independent gate is met in tests: `FakeTransport` and
`BleTransport` use the same `PhoneAuthCore`, protocol frames, authorization
policy, and full-context signature. Physical BLE currently reaches Android's
native GATT client and framing layer, but production pairing/session handshake
and the desktop BLE adapter are still required before claiming real-device
end-to-end authorization.

## Phase 1A — BLE transport

- [x] Android scanning/GATT client, explicit permissions, MTU, notifications,
      bounded framing, disconnect handling, and connection timeout
- [x] Transport substitution test with the same core and request semantics
- [ ] Desktop GATT server/role implementation and real-device tests
- [ ] Cryptographic pairing and production secure session handshake
- [ ] Reconnect policy, ping/pong, and app lifecycle integration
- Android background behavior with explicit user-visible policy

BLE remains optional and never leaks BLE concepts into protocol/domain types.

## Phase 1B — QR bootstrap + local network

- Short-lived canonical QR bootstrap (version, session, nonce, ephemeral key,
  endpoint, expiry; no permanent secrets)
- QR scanner UI and verifier QR generation
- Standard TLS local connection plus independent PhoneAuth handshake/binding
- `QrNetworkTransport` and cross-transport conformance tests
- Research-only offline request/response QR profile

## Phase 1C — Android platform integration

- Credential Manager provider
- WebAuthn/FIDO/passkey integration using platform standards
- Local-mode policy distinct from remote pairing

## Phase 2 — NixOS/LUKS (blocked on Phase 1 gates)

- [x] Minimal Rust `phone-auth-initrd`, separate from `phone-auth-agent`
      — credential selection and the key-separation and hardware-key gates are
      implemented; it has no transport, so it always falls through to the
      recovery keyslot today
- [x] NixOS module, with separate system and user agents so that a PAM rule
      never depends on a user-writable pairing store
- Selected BLE/network transports in initrd after attack-surface review
- Dedicated LUKS wrapping credential and PhoneAuth keyslot
- Mandatory offline recovery keyslot and recovery drills

## Phase 3 — Physical access

- Paired door verifier over BLE/network
- Dynamic QR bootstrap and fresh session challenge
- Delegated credentials only after standards research
- Static QR identity hints with fresh online/session challenge

## Later

- Phase 4: SSH, PAM, sudo, Windows Credential Provider
- Phase 5: UWB, temporary/enterprise credentials, multi-user authorization

No later phase may replace biometric authorization with proximity or transport
identity.
