/// The SSH key, as the phone actually holds it.
///
/// Two things happen here. The signature comes out of the Android Keystore in
/// DER, because that is what `Signature` produces, and SSH wants the raw
/// `r || s` pair — the conversion is not a formality: DER integers are signed,
/// so a coordinate whose top bit is set carries a leading zero that must come
/// off, and one shorter than 32 bytes must be padded back. Dropping either
/// rule produces a signature that verifies about half the time, which reads as
/// a flaky network rather than as a bug.
///
/// And the biometric prompt is raised by the platform, not by us: the key is
/// `setUserAuthenticationRequired`, so the signature cannot exist without it.
library;

import 'dart:typed_data';

import 'package:phone_auth_native/phone_auth_native.dart';

import 'ssh_service.dart';

/// The length of a P-256 scalar, and half of the SSH signature.
const int _scalarLength = 32;

/// The prompt in English, for callers with no language pack to hand.
///
/// That is tests, and nothing in production: the runner is built from a
/// provider that passes the words the user's language pack holds.
const String defaultSshPromptTitle = 'SSH login';
const String defaultSshPromptDetail =
    'The session stays open until the terminal closes.';

class NativeSshSigner implements SshSigner {
  const NativeSshSigner({
    required this.promptTitle,
    required this.promptDetail,
    SecureAuthenticator authenticator = const PhoneAuthNative(),
  }) : _authenticator = authenticator;

  /// The two lines the platform prompt shows.
  ///
  /// Passed in rather than written here: this runs in a background session
  /// with none of the app's own UI on screen, so there is no `Localizations`
  /// to read, and the words still have to be in the language the user picked.
  final String promptTitle;
  final String promptDetail;

  final SecureAuthenticator _authenticator;

  @override
  Future<Uint8List?> sign(Uint8List data, {required String prompt}) async {
    final SignatureResult result;
    try {
      result = await _authenticator.sign(
        payload: data,
        purpose: 'ssh',
        context: AuthenticationContext(
          title: promptTitle,
          subtitle: prompt,
          // The prompt is the last thing between a request and a session, so it
          // says what approving costs rather than only what it is.
          description: promptDetail,
        ),
      );
    } on Object {
      // A cancelled prompt, a key invalidated by a new fingerprint, a phone
      // with no biometrics left: all of them are "no signature", and the
      // desktop is told the same thing for each. Which one it was is the
      // user's to see on their own screen, not the asking computer's.
      return null;
    }
    return rawEcdsaSignature(result.signature);
  }
}

/// Converts a DER `SEQUENCE { INTEGER r, INTEGER s }` to `r || s`.
///
/// Returns null for anything that is not exactly that, rather than salvaging
/// what it can: a signature this cannot read is not one to guess at.
Uint8List? rawEcdsaSignature(Uint8List der) {
  var offset = 0;

  int? byte() => offset < der.length ? der[offset++] : null;

  if (byte() != 0x30) return null;
  final length = byte();
  // Short form only. A P-256 signature is at most 72 bytes, so a long-form
  // length here means this is not one.
  if (length == null || length != der.length - offset) return null;

  final scalars = <Uint8List>[];
  for (var i = 0; i < 2; i++) {
    if (byte() != 0x02) return null;
    final size = byte();
    if (size == null || size == 0 || size > der.length - offset) return null;
    var value = der.sublist(offset, offset + size);
    offset += size;

    // DER integers are signed: a coordinate with its top bit set is written
    // with a leading zero, which is padding, not part of the number.
    if (value.length > 1 && value[0] == 0x00) value = value.sublist(1);
    if (value.length > _scalarLength) return null;

    final padded = Uint8List(_scalarLength);
    padded.setRange(_scalarLength - value.length, _scalarLength, value);
    scalars.add(padded);
  }
  if (offset != der.length) return null;

  return Uint8List(_scalarLength * 2)
    ..setRange(0, _scalarLength, scalars[0])
    ..setRange(_scalarLength, _scalarLength * 2, scalars[1]);
}
