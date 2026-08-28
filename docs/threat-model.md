# PhoneAuth Threat Model

## Security objectives

- Private credentials remain non-exportable in Android Keystore or the future
  iOS Secure Enclave/Keychain implementation.
- A verifier accepts only a fresh, context-bound authorization produced after
  `BIOMETRIC_STRONG` for the intended verifier, credential, and secure session.
- Transport compromise does not change request semantics or grant authority.
- Approval floods are grouped, rate-limited, clearly attributed, and blockable.
- Recovery remains possible without weakening the normal biometric path.

## Trust boundaries

1. Untrusted transport bytes entering the protocol decoder.
2. Flutter-to-native platform channel. Only bounded canonical payloads and
   display context enter native code; private keys never leave it.
3. Mobile UI-to-biometric transition. A tap is consent, not authorization;
   cryptographic authorization occurs only through `CryptoObject`.
4. Verifier policy and paired-key storage.
5. Future relays/TLS endpoints. They provide delivery/confidentiality, never
   PhoneAuth identity by themselves.

## Principal threats and controls

| Threat | Required control |
|---|---|
| Request replay | Fresh 32-byte challenge, unique request ID, short expiry, session binding, verifier replay cache |
| Cross-service substitution | Sign service, action, resource, verifier ID, credential ID, and version |
| Transport swapping/injection | Authenticated secure-session binding is inside the signed request |
| Malicious QR/deep link | Treat only as bootstrap; validate expiry, endpoint policy, handshake, peer key, and nonce |
| BLE spoofing | Never use MAC, advertised name, or proximity as identity |
| LAN MITM | Standard TLS plus PhoneAuth peer authentication and session binding; never invent TLS |
| Biometric downgrade | Allow only `BIOMETRIC_STRONG`; deny all unavailable/weak/device-credential cases |
| Boolean-biometric TOCTOU | Keystore auth-per-use key and `BiometricPrompt.CryptoObject(Signature)` |
| Approval fatigue | Duplicate grouping, bounded rate window, warning with full origin/context, temporary block |
| Stolen unlocked phone | Explicit consent and auth-per-use strong biometric for every sensitive request |
| Key extraction | Non-exportable Keystore/Secure Enclave key; no persistence in Dart stores or logs |
| Compromised Flutter runtime | Native validates payload bounds; Keystore still requires biometric per operation |
| Compromised verifier | Per-verifier/service permissions and credential separation limit blast radius |
| Clock manipulation | Short windows plus verifier/session nonce and replay cache; do not rely on time alone |
| Sensitive logging | Never log challenges, session keys, payloads, signatures, credentials, or LUKS material |
| WebAuthn RP confusion | Validate HTTPS origin host against RP ID on phone; validate Android callers with privileged allowlist or asset links; fail closed |
| RP ID claiming a public suffix | Bundled Public Suffix List rejects an RP ID that is not registrable, so a page under `com.br` or `github.io` cannot scope a credential to the whole suffix |
| Passkey requested by a third-party iframe | Main-world and isolated bridges independently re-check the `publickey-credentials-create`/`-get` Permissions Policy, including forged DOM events; unknown policy fails closed |
| Malicious desktop page/extension | Authenticated session proves the paired computer, not the tab; show origin on phone and require biometric for every assertion |
| Passkey loss | No sync/export in this phase; require a second service recovery path |

## Explicit non-goals and forbidden fallbacks

- Proximity is not authorization.
- QR is not authorization.
- Bluetooth pairing is not PhoneAuth pairing.
- TLS endpoint identity alone is not PhoneAuth authorization.
- No PhoneAuth PIN/password, cached biometric grace period, automatic approval,
  `BIOMETRIC_WEAK`, or system-credential fallback.
- No permanent secret, password, private key, or LUKS key in a QR/deep link.

## LUKS-specific future constraints

LUKS work starts only after the core, BLE, and QR/network transports are solid.
It uses a separate wrapping credential and a dedicated keyslot. An offline
recovery keyslot is mandatory; the phone must never be the sole recovery path.
Initrd networking, Wi-Fi credentials, DHCP, firewall exposure, QR hardware, and
BLE stack size require a separate review before implementation.

## Residual risks

- A compromised OS can alter displayed context or suppress UI; hardware-backed
  signing limits key extraction but cannot make a compromised UI trustworthy.
- Biometric sensors and vendor secure hardware have platform-dependent assurance.
- Denial of service remains possible at radio/network and verifier layers.
- Traffic metadata can remain visible even when protocol contents are encrypted.
- The desktop extension/native host reports tab origin. A compromised browser or
  desktop OS can lie; unlike Credential Manager, the remote path has no Android
  system attestation of that origin.
