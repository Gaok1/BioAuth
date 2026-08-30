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
- [x] Cryptographic PhoneAuth pairing and per-verifier permissions
- [x] Desktop agent, CLI verifier and tray UI (see `desktop.md`)

Exit gate: the same encoded request and authorization core run unchanged over a
fake session and BLE; the verifier checks the full context-bound signature.

The transport-independent gate is met in tests: `FakeTransport` and
`BleTransport` use the same `PhoneAuthCore`, protocol frames, authorization
policy, and full-context signature. Physical BLE reaches Android's native GATT
client and the Linux/BlueZ GATT server, using the production session handshake
and shared framing. A real-device run is still required before claiming
end-to-end BLE authorization.

## Phase 1A — BLE transport

- [x] Android scanning/GATT client, explicit permissions, MTU, notifications,
      bounded framing, disconnect handling, and connection timeout
- [x] Transport substitution test with the same core and request semantics
- [x] Linux/BlueZ desktop GATT server/role implementation
- [ ] Real-device BLE authorization tests
- [x] Cryptographic pairing and production secure session handshake
- [x] Paired-session reconnect policy and Android foreground-service survival
- Ping/pong only if sessions become long-lived; current sessions carry one request
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

- [x] Credential Manager provider implementation and fail-closed caller/RP tests
- [x] WebAuthn/CTAP2 core, per-credential Keystore aliases, and fixed vectors
- [x] Chrome/Edge/Firefox extension, native host, agent relay, and phone origin UI
- [x] Local Credential Manager policy distinct from authenticated desktop relay
- [ ] Real-device webauthn.io matrix (Android Chrome, desktop Chrome/Edge/Firefox)

## Phase 2 — NixOS/LUKS (blocked on Phase 1 gates)

- [x] Minimal Rust `phone-auth-initrd`, separate from `phone-auth-agent`
      — credential selection and the key-separation and hardware-key gates are
      implemented
- [x] Minimal wired IPv4 transport with paired mutual handshake, bounded
      framing and one boot deadline; no agent, BlueZ or D-Bus dependency
- [x] NixOS module, with separate system and user agents so that a PAM rule
      never depends on a user-writable pairing store
- [x] Initrd attack-surface review: wired IPv4/TCP selected; Wi-Fi rejected and
      BLE/HCI deferred to a separate review
- Dedicated LUKS wrapping credential and PhoneAuth keyslot
- Mandatory offline recovery keyslot and recovery drills

## Phase 3 — Physical access

- Paired door verifier over BLE/network
- Dynamic QR bootstrap and fresh session challenge
- Delegated credentials only after standards research
- Static QR identity hints with fresh online/session challenge

## Phase 3A — Secrets vault on the phone

Ciphertext lives on the phone; the desktop app browses it and copies an item to
the clipboard. A fetch is an ordinary `AuthRequest` over the existing session,
shown on the phone as what it is — *"PC-DO-LUIS wants to read: GitHub token"* —
and released by the fingerprint. Session binding already prevents that fetch
being replayed into another session, so the protocol work is mostly done.

Four things decide whether "the plaintext never reaches the desktop's disk" is
true or decorative:

- The clipboard is the leak, not swap. On Windows it is global to every
  process, Win+V records history, and cloud clipboard syncs it off the machine.
  Requires `ExcludeClipboardContentFromMonitorProcessing` and
  `CanIncludeInClipboardHistory`, plus a clear-on-timer.
- The secret must never enter the Electron process. JS strings are immutable and
  garbage-collected, so they cannot be zeroed. Keep it in the agent, in a
  `Zeroize` buffer under `VirtualLock`/`mlock` so it cannot be paged out, and let
  the agent write the clipboard. The UI sees item names only.
- Android Keystore stores keys, not blobs: an AES-GCM key gated by
  `BIOMETRIC_STRONG`, ciphertext in ordinary app storage.
- Lose the phone, lose the vault, unless there is an export path.

Its background-session dependency is implemented below; vault work remains future.

## Phase 3B — Sessions that survive the app being backgrounded

- [x] Android `connectedDevice` foreground service and persistent notification
- [x] Cached Flutter engine and lifecycle test: activity pause does not close sessions
- [ ] Real-device/OEM background and task-removal matrix

## Later

- Phase 4: SSH, PAM, sudo, Windows Credential Provider
- Phase 5: UWB, temporary/enterprise credentials, multi-user authorization

No later phase may replace biometric authorization with proximity or transport
identity.
