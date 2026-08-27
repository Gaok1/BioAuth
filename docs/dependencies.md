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
- `androidx.credentials:credentials:1.6.0` supplies the Android 14+
  `CredentialProviderService` compatibility surface. Caller validation still
  uses platform `CallingAppInfo` and Digital Asset Links contracts.
- CTAP2 CBOR is a small local canonical encoder because the existing Dart codec
  supports fixed PhoneAuth arrays, not integer-keyed COSE maps, and moving
  credential construction out of Kotlin would widen the key boundary.

### Bundled data

Two reference lists ship as raw resources. They are data, not code: nothing in
them executes, and neither adds a build or runtime dependency. Both are stored
verbatim from their canonical source so a refresh is a download and a diff.

| File | Source | License |
|---|---|---|
| `public_suffix_list.dat` | `https://publicsuffix.org/list/public_suffix_list.dat` | MPL-2.0, header kept intact |
| `privileged_browsers.json` | `https://www.gstatic.com/gpm-passkeys-privileged-apps/apps.json` | Google's published passkey allowlist |

The suffix list is what makes an RP ID check mean anything — a hand-written
approximation would miss the private section (`github.io`, `vercel.app`), which
is precisely where a page can be hosted by someone who does not own the parent
domain. `PublicSuffixListTest` asserts the shipped file still covers the
suffixes that matter, so a truncated or emptied list fails the build rather
than silently making every suffix registrable.

Refreshing either file is a reviewed app release. Neither is fetched at
runtime: a security decision must not depend on a network call that can fail
open.

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
