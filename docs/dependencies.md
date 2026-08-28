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

Refreshing either file is automated by
`scripts/update_android_trust_snapshots.py` and enters the repository through a
reviewed pull request after Android unit tests. CI verifies the committed hashes
and freshness metadata. Neither is fetched at
runtime: a security decision must not depend on a network call that can fail
open.

## Rust verifier

The desktop workspace uses narrowly scoped crates for serialization, P-256
verification, hashing, and OS randomness. `Cargo.lock` is committed and CI
runs formatting, Clippy, and the full workspace test suite. Network/TLS crates
will be selected only when `QrNetworkTransport` is implemented; TLS will not
be reimplemented by PhoneAuth.

### File Locker

`phone-auth-locker` adds no crate the workspace was not already building. It
reuses `chacha20poly1305`, `hkdf`, `sha2` and `getrandom` — the same primitives
the secure channel uses — and declares `zeroize`, which was already in
`Cargo.lock` as a transitive dependency of the AEAD stack. The container's CBOR
comes from `phone-auth-protocol` rather than a second encoder, so both formats
obey one set of canonicality rules.

Three things were deliberately **not** added:

- an Argon2/scrypt crate: the recovery secret is 256 random bits rendered as a
  code, so there is no low-entropy passphrase for a KDF to defend;
- `libc`/`windows-sys` for `mlock`/`VirtualLock`: keys are wiped on drop, but
  pages are not pinned. The realistic path from a key in RAM to an attacker is
  a process that can already read that RAM, and swap is what full-disk
  encryption is for;
- a streaming-AEAD helper: the chunk construction is a counter, a final-block
  flag and one AAD value, and writing those out keeps the format readable next
  to its specification.

### Personal vault

The vault wire format adds no crate at all: `phone-auth-protocol::vault` uses
the same dependency-free canonical CBOR the rest of that crate uses, and its
Dart counterpart uses `mobile/lib/core/protocol/cbor.dart`.

The password generator in `phone-auth-agent` reuses `getrandom` for OS
randomness and `zeroize` to hold the generated password. Both were already
workspace dependencies; `zeroize` was promoted from a `phone-auth-locker`
declaration to a workspace one when the agent became its second consumer, so
the version is pinned in one place.

### Resolved: page locking and the clipboard

The open question recorded here — whether vault plaintext may use the
`libc`/`windows-sys` dependency the File Locker section above declined — was
put to the owner on 2026-08-28 and **approved**. `VLT-06` and `VLT-07` may add
`windows-sys` under `cfg(windows)` and `libc` under `cfg(unix)`.

The File Locker section is not wrong and stays as written. The two cases differ
in exposure window: a data key lives for one operation, whereas a fetched
password sits in the agent while the user goes to paste it. The same dependency
was declined for the shorter window and accepted for the longer one.

What page locking buys, stated honestly so nobody over-claims it later:
`VirtualLock`/`mlock` keeps a page out of the pagefile, and
`WerRegisterExcludedMemoryBlock`/`MADV_DONTDUMP` keeps it out of crash and core
dumps. It does **not** survive hibernation, which writes all of RAM to disk and
ignores the lock, and it does not defend against a process that can already read
this one's memory. Full-disk encryption remains the answer to both.

Encrypting the buffer in place was considered and rejected: the decryption key
would live in the same address space, so any dump that captures the ciphertext
captures the key beside it. The goal is to stop the bytes leaving the process,
not to re-encrypt them inside it.

The clipboard is the leak this pair exists to close. The Windows clipboard is
global to the session, `Win+V` records history, and cloud clipboard synchronises
off-machine, so a copied password can outlive the paste and leave the device.
`VLT-07` clears on a timer and sets `CanIncludeInClipboardHistory`,
`CanUploadToCloudClipboard` and `ExcludeClipboardContentFromMonitorProcessing`.
X11 and Wayland offer different guarantees; the result reports what was actually
achieved rather than showing a lock that is not there.

### Bundled data: passphrase wordlist

`VLT-12` embeds the EFF long wordlist (7776 words) as a raw resource, approved
on 2026-08-28 under the same rule as the two Android lists above: stored
verbatim from its canonical source, licensed **CC-BY**, attribution recorded,
refreshed by download and diff.

| File | Source | License |
|---|---|---|
| `eff_large_wordlist.txt` | `https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt` | CC-BY 3.0 US |

The list length is load-bearing: entropy per word is `log2(7776)` ≈ 12.9 bits,
so a truncated or substituted list silently weakens every passphrase without
failing to produce one. A test pins the count.

## Review rule

Before adding or upgrading a package, record maintenance activity, current
platform support, license, sensitive-data behavior, transitive dependencies,
and why a platform or standard-library API is insufficient. Production logs
must never contain challenges, signatures, session secrets, or private-key
material.
