# PhoneAuth Architecture

## Definition

PhoneAuth is a transport-independent authentication protocol. Bluetooth Low
Energy (BLE), local networking, QR, USB, and future transports only move opaque
protocol frames; none of them defines identity or authorization.

```text
Authenticator (mobile/private credentials)
                |
        PhoneAuth protocol
                |
        secure session binding
                |
 AuthTransport (BLE, LAN, QR, USB, ...)
                |
Verifier (PC, lock, vault, server/public credentials + policy)
```

BLE addresses, IP addresses, hostnames, QR contents, and proximity are hints,
not identities. Identity comes from cryptographic keys, pairing records, or
issuer-signed credentials.

## Layers

```text
mobile/lib/
|- app, features, shared       Material 3 UI and Riverpod state
|- domain                     requests, devices, permissions, audit
`- core/
   |- protocol                canonical CBOR and protocol validation
   |- session                 authorization orchestration
   |- transport               AuthTransport contracts only
   `- security                rate limits and authorization policy

packages/phone_auth_native/
|- Dart contract              public key, capabilities, sign payload
|- Android/Kotlin             Keystore + BIOMETRIC_STRONG + CryptoObject
`- iOS/Swift                  future Keychain/Secure Enclave implementation
```

The private key never crosses a Flutter platform channel. Dart receives only a
public key, signature, algorithm identifier, and non-sensitive capability
metadata.

## Protocol objects

`AuthRequest` has transport-independent semantics (the wire frame also carries
an explicit message type):

```text
protocolVersion, requestId, verifierId, verifierName, credentialId, challenge,
service, action, resource, user, issuedAt, expiresAt, sessionBinding
```

The signature covers the canonical CBOR representation of every field above.
It never covers only `challenge`. A fixed-order CBOR array is used to avoid map
ordering ambiguity. Timestamp precision and field bounds are part of the wire
contract. Unknown versions and message types fail closed.

`sessionBinding` is produced by the secure handshake. It prevents a request
captured on one transport session from being authorized on another. It is not a
BLE address, IP address, or QR nonce by itself.

## Authorization invariant

Every sensitive proprietary PhoneAuth approval performs:

1. Validate version, canonical frame, expiry, session binding, verifier, and
   permission.
2. Show verifier, service, action, resource, user, origin, and time.
3. Require an explicit user tap on **Authorize**.
4. Prepare a Keystore `Signature` for the canonical request.
5. Invoke `BiometricPrompt` with `BIOMETRIC_STRONG` and that `CryptoObject`.
6. Return the resulting signature to the session.

There is no app PIN, password, grace period, remembered approval, proximity
approval, `BIOMETRIC_WEAK`, or device-credential fallback. If strong biometrics
are unavailable, authorization is denied. Android's own prerequisite unlock
rules remain under Android control.

## Trust modes

- **Local:** Android Credential Manager to the local provider; no remote
  pairing.
- **Paired remote:** both parties retain the other party's public identity and
  per-verifier permissions. Pairing is PhoneAuth cryptographic pairing, not
  Bluetooth pairing.
- **Delegated remote (future):** verifier trusts an issuer and validates a
  short-lived credential plus proof-of-possession. A standard credential format
  must be selected before implementation.

## Transport contract

`AuthTransport` owns discovery and connection. `SecureTransportSession` owns
opaque framed bytes and exposes authenticated session-binding material. The
PhoneAuth core consumes only that interface.

Each transport declares availability, latency/proximity characteristics,
network requirement, and whether it supplies confidentiality and peer
authentication. Policy selects transports explicitly; there is no silent
downgrade.

Planned implementations:

1. `FakeTransport` for deterministic end-to-end tests.
2. `BleTransport` as the first device transport.
3. `QrNetworkTransport`: QR bootstraps a short-lived LAN endpoint and secure
   session. TLS is provided by a standard TLS stack; PhoneAuth authentication
   remains separate.
4. Offline request/response QR, USB, NFC, and UWB are future transports.

## Key separation

Aliases and credentials are versioned by purpose and, where practical, by
verifier/service:

```text
device identity root
|- pairing identity
|- PC authorization credentials
|- WebAuthn/passkeys
|- password-vault credential
|- file-locker credential
|- LUKS wrapping credential
`- physical-access credentials
```

The MVP Android alias is scoped to PhoneAuth authorization and must not later be
reused for vault, locker, LUKS, WebAuthn, or physical access. The verifier maps
the reserved `vault`, `locker`, `luks`, and `webauthn` service names to their
credential purposes instead of trusting a purpose supplied over IPC.

## Background execution

Android paired sessions use a `connectedDevice` foreground service with a
persistent notification. A cached Flutter engine outlives the activity; the
session runner does not start unless that service is available and notification
permission is granted. Force-stop still stops it, and Doze/background rules
still apply.
iOS will use declared CoreBluetooth modes and state restoration but remains
subject to suspension. Background receipt never bypasses foreground context and
biometric approval.

WebAuthn uses per-credential `bioauth_webauthn_v1_...` aliases and never the
authorization or session-identity aliases. See `webauthn.md` for its CTAP2
encoding and local-versus-desktop trust boundary.

Pairing metadata and Android passkey metadata use explicit v2 envelopes. An
upgrade migrates the legacy snapshot into a new key without deleting it; every
later write preserves the last valid v2 snapshot before replacing the current
one. Malformed current data is restored from that snapshot and surfaced as an
error, while an unknown future version is preserved and rejected rather than
misclassified as corruption. The authoritative replacement is one atomic
SharedPreferences value/commit, so process death cannot expose a half-encoded
record set.

The Android vault was introduced directly as version 1, so it has no legacy
plaintext or unversioned format to migrate. Both its authenticated ciphertext
envelope and its encrypted JSON payload carry explicit versions, and writes use
Android `AtomicFile`. A future version is reported as
`store_version_unsupported`, not as corruption: recovery UI must not offer to
discard data merely because the installed build is older than the store.
