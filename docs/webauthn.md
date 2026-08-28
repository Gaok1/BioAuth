# WebAuthn / passkeys

## Implemented scope

PhoneAuth has one Android passkey store shared by two entry points:

1. Android 14+ Credential Manager calls `BioAuthCredentialProviderService`.
2. Chrome, Edge, or Firefox on a paired computer calls the browser extension,
   native-messaging host, agent IPC, and the existing authenticated phone
   session.

Each credential has a random 32-byte ID and its own P-256 Android Keystore
alias under `bioauth_webauthn_v1_`. Metadata (`credentialId`, RP ID, user
handle/name and signature counter) is ordinary app-private storage. The private
key is non-exportable, is invalidated by biometric enrollment changes, and is
auth-per-use with `BIOMETRIC_STRONG`. StrongBox is attempted when available;
failure falls back only to another Android Keystore implementation.

Registration returns CTAP2 authenticator data, an ES256 COSE key, and an
attestation object with `fmt: "none"` and an empty `attStmt`. None attestation
is deliberate: this phase proves possession of a per-RP passkey without
creating a stable device-attestation identifier. Fixed W3C/CTAP2 vectors pin
the canonical bytes. The existing Dart CBOR codec was not reused: it encodes
fixed protocol arrays, while CTAP2 requires canonical integer-keyed maps and
the implementation runs inside the Kotlin security boundary.

### Supported request options

The Android parser validates options before showing UI or touching a key:

- only the platform authenticator and ES256 are supported;
- `residentKey` and `userVerification` accept the standard
  `discouraged`/`preferred`/`required` values; authenticator data always records
  user presence and strong user verification, and credentials are discoverable;
- only `attestation: "none"` is accepted because the provider emits none
  attestation;
- creation supports only the `credProps` extension and reports `rk: true`;
  assertion extensions are currently rejected.

Unsupported attachment, attestation, enum value, or extension fails before the
ceremony rather than being accepted with different semantics. This is the
deliberately narrow Android feature set; new options need byte-level tests before
they are admitted. The option vocabulary follows the
[WebAuthn Level 3 specification](https://www.w3.org/TR/webauthn-3/).

## RP/origin validation

- A privileged browser Credential Manager call is accepted only when
  `CallingAppInfo.getOrigin()` validates its package and signing certificate
  against `privileged_browsers.json`. Browser responses omit `clientDataJSON`;
  assertions sign the browser-supplied `clientDataHash` as required by the API.
- A native Android app must have an HTTPS `/.well-known/assetlinks.json` entry
  binding every current signer to `delegate_permission/common.get_login_creds`.
- A desktop extension origin must be HTTPS and its host must equal the RP ID or
  be a subdomain. The phone performs this check again.
- On every path the RP ID must be a *registrable* domain, checked against the
  bundled Public Suffix List. Suffix matching alone is not enough: a page on
  `evil.com.br` would otherwise claim `rpId = "com.br"` and every sibling site
  could then ask for that credential. The list's private section is the part
  that matters most — `github.io`, `vercel.app`, `pages.dev` are where someone
  can host a page without owning the parent domain.
- The extension re-checks the `publickey-credentials-create`/`-get` Permissions
  Policy before relaying. Overriding `navigator.credentials` also bypasses the
  browser's own gate, which is what normally stops a third-party iframe from
  asking for a passkey. Firefox exposes no policy object, so a cross-origin
  frame fails closed there.

Two lists are bundled as Android raw resources, both verbatim from their
canonical source so they can be re-pulled and diffed. Retrieval dates and
SHA-256 digests live in `packages/phone_auth_native/android/trust-snapshots.json`.

| File | Source |
|---|---|
| `privileged_browsers.json` | `https://www.gstatic.com/gpm-passkeys-privileged-apps/apps.json` |
| `public_suffix_list.dat` | `https://publicsuffix.org/list/public_suffix_list.dat` |

Run `python scripts/update_android_trust_snapshots.py --update` to refresh them.
The weekly `Android trust snapshots` workflow validates the canonical downloads,
runs `:phone_auth_native:testDebugUnitTest`, and opens a data-only pull request
when a snapshot changes (or its verification date needs refreshing). CI checks
the committed hashes and rejects snapshots older than 45 days. Both remain
release-reviewed snapshots: trust is never expanded by a runtime fetch.

Every assertion uses a Keystore `Signature` inside `BiometricPrompt`. Desktop
requests first appear as a notification containing the origin; tapping it opens
the biometric flow whose subtitle repeats RP ID and origin. No challenge,
signature, credential ID, user handle, or key material is logged.

## Passkey management on Android

`Ajustes → Passkeys` lists RP, account, creation date, and native-key health.
The inventory compares stored metadata with every `bioauth_webauthn_v1_...`
Android Keystore alias, so it exposes metadata whose key is missing or invalid
and aliases whose metadata is missing. Deletion requires a foreground
`BIOMETRIC_STRONG` prompt. For a normal credential Android deletes the Keystore
entry first and then its metadata; if the metadata commit fails, the remaining
record is visibly retryable as `missingKey` rather than silently claiming a
usable passkey.

Metadata is stored in a versioned v2 envelope. The original array remains as a
compatibility snapshot, and one previous v2 envelope is committed atomically
with each update. Corruption rolls back once and is reported; an unknown future
version fails without modifying either snapshot.

Passkeys are currently device-bound and have no backup or sync. The first-run
screen says so and tells the user to keep another login method at every RP.
Both Android Credential Manager creation and desktop-relay creation repeat the
same warning inside the final biometric confirmation; assertions do not repeat
it.

Discoverable credentials are account-selectable on both supported paths.
Android Credential Manager renders one `PublicKeyCredentialEntry` per matching
account. A desktop request without `allowCredentials` shows an account chooser
on the phone when more than one passkey matches, then initializes the selected
key's biometric signature. `mediation: "conditional"` is deliberately left to
the browser's native authenticator instead of being intercepted by the desktop
extension; PhoneAuth does not claim conditional mediation in this release.

## Desktop installation

Build both agent binaries:

```console
cd desktop
cargo build --release --bin phone-auth-agent --bin phone-auth-webauthn-host
```

Load `desktop/browser-extension/` as an unpacked extension. Chrome and Edge use
their extensions developer page; Firefox uses `about:debugging` for a temporary
development install.

The extension carries both engines' shapes, because they disagree twice.
Firefox resolves a promise returned from `runtime.onMessage`; Chrome ignores it
and closes the channel, so replies go through `sendResponse` with `return true`.
Sending to the native host is the mirror image — `browser.*` returns a promise
and rejects a callback, `chrome.*` wants a callback and only returns a promise
from Chrome 116 — so the code branches on the namespace rather than guessing.
Firefox needs 128 or newer for `world: "MAIN"` content scripts. Copy the matching example from
`desktop/browser-extension/native-host/` to `com.bioauth.webauthn.json`, replace
the executable path, and for Chromium replace the unpacked extension ID.

Per-user native-host locations:

| Browser | Linux | Windows registry key |
|---|---|---|
| Chrome | `~/.config/google-chrome/NativeMessagingHosts/` | `HKCU\Software\Google\Chrome\NativeMessagingHosts\com.bioauth.webauthn` |
| Edge | `~/.config/microsoft-edge/NativeMessagingHosts/` | `HKCU\Software\Microsoft\Edge\NativeMessagingHosts\com.bioauth.webauthn` |
| Firefox | `~/.mozilla/native-messaging-hosts/` | `HKCU\Software\Mozilla\NativeMessagingHosts\com.bioauth.webauthn` |

The registry default value is the absolute path to the JSON host manifest. The
agent must be running and the phone paired. If several phones are paired, the
IPC request must name a credential; the extension fails rather than selecting
one by map order.

## Foreground lifetime

Paired sessions are a hard dependency on Android's `connectedDevice`
foreground service and its visible notification. Notification permission
denial prevents the session runner from starting. A cached Flutter engine is
created by `BioAuthApplication`, outlives `MainActivity`, and is recreated with
the service process, so backgrounding or removing the activity does not tear
down paired-session loops. Force-stop still stops everything by Android design.

## Manual webauthn.io procedure

This procedure is documented but **not claimed as completed without real
devices and browsers**:

1. Install on Android 14+, enable PhoneAuth under Credential Manager providers,
   grant notifications, enroll a strong biometric, and pair the computer.
2. On `https://webauthn.io` in Android Chrome, register with PhoneAuth and sign
   in. Record only pass/fail; do not capture protocol material.
3. Install the desktop extension/native host, open the same RP/account in
   Chrome, tap the phone notification, verify the displayed origin, and sign in
   with the credential from step 2.
4. Repeat in the opposite direction: register in desktop Chrome, then sign in
   through Android Credential Manager. Repeat desktop sign-in in Edge and
   Firefox.
5. Background/remove the PhoneAuth activity while leaving its persistent
   notification active, then repeat a desktop assertion.

The automated suite covers CTAP2 fixed vectors, malformed frames, request-ID
binding, RP/origin and asset-links rejection, background lifecycle, native
message framing, BufferSource serialization, reconstructed WebAuthn response
objects, abort/timeout, iframe Permissions Policy, native-host failure, and
fallback to the browser authenticator. It does not substitute for the manual
matrix.

## Desktop relay boundary review

| Boundary | Enforced invariant |
|---|---|
| Page → main-world bridge | The page is untrusted and may forge DOM events. Both the main-world and isolated bridges independently require `create`/`get` and re-check iframe Permissions Policy; unknown policy fails closed. |
| Isolated bridge → service worker | The worker ignores a page-supplied origin and derives the HTTPS origin from the browser-provided `sender.url`; operation and options shape are validated again. |
| Service worker → native host | The installed native-host manifest allowlists only the reviewed extension ID (`allowed_origins` on Chromium, `allowed_extensions` on Firefox). A Chromium package/install must replace the placeholder with its final ID. |
| Native host → agent | Native messages are capped at 128 KiB before allocation. The host accepts only JSON `create`/`get` objects; the agent additionally caps origin at 2,048 characters and encoded options at 6,000 bytes. |
| Agent → phone | The transport must be authenticated and confidential. The phone binds the response to the request ID, validates origin against RP ID again, displays the origin, and requires strong biometric authentication. |

A fake extension cannot reach the host unless it is added to the OS-installed
manifest. A malicious top-level page can still cause its own WebAuthn request,
as it can with the native API, but cannot produce a server-valid signature
without the biometric ceremony. A compromised reviewed extension or desktop OS
remains able to lie before the phone boundary; this residual risk is why the
phone never treats the reported origin as session identity and always displays
it for confirmation.

## Cancellation and request lifetime

The browser-generated request ID now survives unchanged through page bridge,
content script, service worker, native host, agent, authenticated session, and
Android. Abort or browser timeout sends a separate native-host cancellation.
The agent keeps a bounded five-minute cancellation map outside the main service
mutex, polls the phone session at 250 ms, and sends a `webauthn.cancel` frame on
the same authenticated channel. TCP framing retains a partial prefix/body across
those short polls; BLE already receives whole records. The agent's own 90-second
deadline sends the same cancel frame.

The mobile runner races that frame against the native ceremony. Android removes
the notification, cancels an active `BiometricPrompt`, prevents a prepared
activity from reopening the prompt, and completes each request only once. A
disconnect also cancels the native ceremony. The phone's generic denial remains
bound to the original request ID and contains no credential material.

Cancellation cannot undo a passkey creation that committed immediately before
the cancel won the race; such a credential remains visible in passkey management
for explicit deletion. Application-protocol operations still need operation-
specific idempotency before `FND-08` can be considered complete globally.

## Deliberately out of scope

- Windows Plugin Authenticator API is the future native desktop path, but it
  requires Windows 11 24H2+; this phase keeps the extension relay.
- caBLE/hybrid transport, iOS credential providers, and passkey sync/export.
- Any change to transport pairing or the authenticated-session handshake.

## Trust asymmetry and recovery

Credential Manager provides a system-validated caller identity. The desktop
path instead trusts the installed extension/native-host boundary to report the
tab origin; the authenticated PhoneAuth session proves which paired computer
sent the request, not which web page caused it. Revalidation and displaying the
origin on the phone reduce phishing risk but cannot make a compromised desktop
browser trustworthy.

Passkeys are not synchronized or exported in this phase. Every relying party
must retain a second passkey, recovery code, or other recovery path.
