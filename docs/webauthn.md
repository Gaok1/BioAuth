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

## RP/origin validation

- A privileged browser Credential Manager call is accepted only when
  `CallingAppInfo.getOrigin()` validates its package and signing certificate
  against `privileged_browsers.json`. Browser responses omit `clientDataJSON`;
  assertions sign the browser-supplied `clientDataHash` as required by the API.
- A native Android app must have an HTTPS `/.well-known/assetlinks.json` entry
  binding every current signer to `delegate_permission/common.get_login_creds`.
- A desktop extension origin must be HTTPS and its host must equal the RP ID or
  be a subdomain. The phone performs this check again.

The privileged-browser allowlist is a deliberate snapshot of Google's
published passkey allowlist retrieved on 2026-08-27; changes require review and
an app release rather than a runtime network trust expansion.

Every assertion uses a Keystore `Signature` inside `BiometricPrompt`. Desktop
requests first appear as a notification containing the origin; tapping it opens
the biometric flow whose subtitle repeats RP ID and origin. No challenge,
signature, credential ID, user handle, or key material is logged.

## Desktop installation

Build both agent binaries:

```console
cd desktop
cargo build --release --bin phone-auth-agent --bin phone-auth-webauthn-host
```

Load `desktop/browser-extension/` as an unpacked extension. Chrome and Edge use
their extensions developer page; Firefox uses `about:debugging` for a temporary
development install. Copy the matching example from
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
binding, RP/origin and asset-links rejection, background lifecycle, and native
message framing. It does not substitute for the manual matrix.

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
