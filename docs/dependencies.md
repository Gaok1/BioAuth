# Dependency decisions

Dependencies are deliberately small because PhoneAuth handles authorization
material and must remain buildable offline after the toolchains are cached.

## Flutter application

| Dependency | Purpose | Security boundary |
|---|---|---|
| `flutter_riverpod` 3.4.2 | Explicit, testable asynchronous UI state | No secret handling |
| `cbor` 6.5.1 | CBOR primitives for the fixed-order protocol codec | All decoded fields are bounded and canonical bytes are re-encoded before use |
| `cryptography` 2.9.0 | Test-only/fake signatures and hashes used by shared session helpers | Production Android private keys stay in Keystore |
| `phone_auth_native` (workspace path) | Narrow platform bridge | Returns public keys, signatures and capability metadata only |

No generic secure-storage package is used for private keys. No Flutter BLE
package is used: the evaluated plugin compiled its Android module against an
obsolete SDK and introduced Kotlin/Gradle incompatibilities. The small native
client in `phone_auth_native` uses Android's official GATT APIs instead. This
also keeps permission, lifecycle and callback behavior under project control.

## Android native plugin

- `androidx.biometric:biometric:1.1.0` is the current stable AndroidX
  Biometric release. Alpha APIs are not required for the auth-per-use
  `CryptoObject(Signature)` flow.
- Android Keystore, `BiometricPrompt`, `BluetoothGatt`, and BLE scanner APIs
  are platform APIs. StrongBox is attempted only when present and safely falls
  back to another Android Keystore implementation; biometric strength never
  falls back.

## Rust verifier

The desktop workspace uses narrowly scoped crates for serialization, P-256
verification, hashing, and OS randomness. `Cargo.lock` is committed and CI
runs formatting, Clippy, and the full workspace test suite. Network/TLS crates
will be selected only when `QrNetworkTransport` is implemented; TLS will not
be reimplemented by PhoneAuth.

## Review rule

Before adding or upgrading a package, record maintenance activity, current
platform support, license, sensitive-data behavior, transitive dependencies,
and why a platform or standard-library API is insufficient. Production logs
must never contain challenges, signatures, session secrets, or private-key
material.
