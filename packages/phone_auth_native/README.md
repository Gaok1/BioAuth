# phone_auth_native

Narrow Flutter platform bridge for PhoneAuth security operations.

## Android

- Generates a non-exportable P-256 authorization key in Android Keystore.
- Attempts StrongBox only when supported and reports actual key security.
- Prepares `SHA256withECDSA`, passes it to `BiometricPrompt.CryptoObject`, and
  permits only `BIOMETRIC_STRONG`.
- Returns only public material and capability metadata to Dart.
- Exposes the Android BLE GATT client used by `BleTransport`.

No private key crosses a method channel. There is no device-credential,
password, pattern, weak-biometric, or app-PIN fallback.

## iOS

The Dart API is platform-neutral, but the Swift Keychain/Secure Enclave and
CoreBluetooth implementation is not built yet. Calls fail closed until it is.

The native BLE link is not itself a secure PhoneAuth session. Production code
must layer the authenticated secure-session handshake above it; only tests may
use the fake establisher.

