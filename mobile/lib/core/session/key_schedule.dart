/// Key schedule and the pairing verification code.
///
/// Both ends of a handshake run exactly this derivation. Mirrors
/// `desktop/crates/phone-auth-session/src/keys.rs`; the test vectors in
/// `docs/protocol-handshake.md` pin every output here, because a divergence
/// shows up on the wire only as an unexplained decryption failure.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

/// Length of every key and of the session binding.
const int keyLength = 32;

/// Number of digits in the pairing verification code.
const int verificationCodeDigits = 6;

const String _kdfDomain = 'PhoneAuth/secure-session/v1';
const String _verificationDomain = 'PhoneAuth/pairing-verification/v1';

/// Everything derived from one completed handshake.
///
/// Directions are named rather than positional: a caller cannot pick the wrong
/// half without writing the wrong field name.
class KeySchedule {
  const KeySchedule._({
    required this.clientToServer,
    required this.serverToClient,
    required this.exporter,
  });

  /// Traffic key for phone → desktop.
  final Uint8List clientToServer;

  /// Traffic key for desktop → phone.
  final Uint8List serverToClient;

  /// Secret output bound into the session binding and the verification code.
  /// Never sent, and never used to encrypt anything.
  final Uint8List exporter;

  /// Expands the X25519 shared secret, salted with the handshake transcript.
  ///
  /// Salting with the transcript ties the keys to the exact messages exchanged:
  /// a replayed handshake against a fresh nonce produces a different transcript
  /// and therefore different keys.
  static Future<KeySchedule> derive({
    required SecretKey sharedSecret,
    required Uint8List transcriptHash,
  }) async {
    final material =
        await Hkdf(hmac: Hmac.sha256(), outputLength: keyLength * 3).deriveKey(
          secretKey: sharedSecret,
          nonce: transcriptHash, // HKDF salt
          info: utf8.encode(_kdfDomain),
        );
    final bytes = Uint8List.fromList(await material.extractBytes());
    return KeySchedule._(
      clientToServer: Uint8List.sublistView(bytes, 0, keyLength),
      serverToClient: Uint8List.sublistView(bytes, keyLength, keyLength * 2),
      exporter: Uint8List.sublistView(bytes, keyLength * 2, keyLength * 3),
    );
  }
}

/// Six digits both ends derive from the same handshake.
///
/// The QR already authenticates the desktop to the phone; this closes the other
/// direction, where someone who photographed the code races to pair their own
/// device. Zero-padding is part of the contract — `42` on one screen and
/// `000042` on the other is a failed comparison.
Future<String> verificationCode(List<int> exporter) async {
  final input = BytesBuilder(copy: false)
    ..add(utf8.encode(_verificationDomain))
    ..add(exporter);
  final digest = await Sha256().hash(input.takeBytes());
  final value = ByteData.sublistView(
    Uint8List.fromList(digest.bytes),
    0,
    4,
  ).getUint32(0, Endian.big);
  final modulus = BigInt.from(10).pow(verificationCodeDigits).toInt();
  return (value % modulus).toString().padLeft(verificationCodeDigits, '0');
}
