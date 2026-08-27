# PhoneAuth — phone app

The authenticator half. Holds the credential that approves logins, shows the
user what is being asked, and signs it behind the fingerprint sensor.

<table>
<tr>
<td width="33%"><img src="../docs/media/request.png" alt="An authorization request"></td>
<td width="33%"><img src="../docs/media/pairing-code.png" alt="Pairing verification code"></td>
<td width="33%"><img src="../docs/media/history.png" alt="Local history"></td>
</tr>
</table>

## Layout

```text
lib/
  core/protocol/     canonical CBOR, AuthRequest/Response, enrolment
  core/session/      key schedule, record layer, session binding, the core
  core/transport/    handshake client, QR bootstrap, TCP transport, framing
  core/pairing/      pairing flow and where paired verifiers are stored
  core/auth/         biometric signing and the bridge to the screen
  features/          the screens
test/                unit tests plus the shared protocol vectors
test/media/          renders the screenshots above from the real widgets
```

## Two keys, never confused

| Key | Guarded by | Signs |
|---|---|---|
| `bioauth_session_identity_v1` | nothing | handshake messages |
| `bioauth_authorization_v1` | `BIOMETRIC_STRONG`, per use | `AuthRequest` |

A handshake happens whenever the phone comes into range, with no user present.
It must never touch the key that approves a login. Both live in the Android
Keystore and neither is exportable; Dart only ever sees public halves and
signatures.

## Running it

```bash
flutter pub get

# Mock data, no network, no keystore
flutter run --flavor dev -t lib/main_dev.dart

# The real thing
flutter run --flavor prod -t lib/main_prod.dart
```

## Checks

```bash
dart format --output=none --set-exit-if-changed lib test integration_test
flutter analyze
flutter test
```

`flutter test` covers the wire format against the vectors in
[`docs/protocol-handshake.md`](../docs/protocol-handshake.md) — the same values
the Rust verifier asserts — and runs the pairing and authorization flow end to
end over a real TCP socket against a desktop written from that specification.

## Regenerating the screenshots

They are captures of the real widget tree, not mockups:

```bash
flutter test test/media/capture_screens.dart   # writes docs/media/*.png
dart run tool/build_flow_gif.dart              # writes the animation
```

Both are excluded from `flutter test`'s default run. If a screen changes, the
picture changes with it on the next run.

## Wiring

`lib/app/providers.dart` is the whole dependency graph. Production defaults are
the real ones — TCP transport, platform keystore, on-device storage — and every
piece is a provider so a test can replace one without rebuilding the rest.

Nothing holds a socket open until a widget watches `pairedSessionRunnerProvider`,
which is deliberate: an app that is not on screen has no business keeping
connections to your computers alive.
