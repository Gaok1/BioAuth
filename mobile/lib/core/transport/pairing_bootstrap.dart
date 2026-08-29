/// The pairing bootstrap: what a QR code carries.
///
/// It is the only authenticated channel that exists before pairing. A phone
/// that has never met this desktop cannot tell the desktop's handshake key from
/// an attacker's — except that the user physically pointed a camera at this
/// screen. The identity commitment in `k` is what turns that physical act into
/// a cryptographic check, so a bootstrap without it is refused rather than
/// defaulted.
///
/// Mirrors `desktop/crates/phone-auth-session/src/bootstrap.rs`.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import '../protocol/enrolment.dart';

/// URL scheme and path the phone scans.
const String bootstrapPrefix = 'phoneauth://pair/v1?';

const String _identityDomain = 'PhoneAuth/identity/v1';

class BootstrapException implements Exception {
  const BootstrapException(this.message);

  final String message;

  @override
  String toString() => 'BootstrapException: $message';
}

/// The contents of a pairing QR code. Both ends hold the same values.
class PairingBootstrap {
  PairingBootstrap({
    required this.sessionId,
    required Uint8List nonce,
    required this.verifierId,
    required Uint8List verifierIdentityHash,
    required this.endpoint,
    required this.expiresAtMs,
    this.purpose = CredentialPurpose.authorization,
  }) : nonce = Uint8List.fromList(nonce),
       verifierIdentityHash = Uint8List.fromList(verifierIdentityHash) {
    _validate();
  }

  final String sessionId;

  /// 32 fresh bytes, tying one scan to one handshake.
  final Uint8List nonce;

  final String verifierId;

  /// SHA-256 of the verifier's handshake identity SPKI.
  final Uint8List verifierIdentityHash;

  /// Where to connect, e.g. `192.168.1.10:8765`. Empty when the transport does
  /// not need an address, as with BLE.
  final String endpoint;

  /// Milliseconds since the Unix epoch, after which this must be refused.
  final int expiresAtMs;

  /// What the credential enrolled by this scan is for.
  ///
  /// The desktop decides it — it is the side that knows whether it wants a key
  /// for `sudo` or for `ssh` — and the phone cannot infer it, because scanning
  /// is the same gesture either way. Absent means authorization, which is what
  /// every code produced before this field existed meant.
  final CredentialPurpose purpose;

  bool isExpiredAt(int nowMs) => nowMs >= expiresAtMs;

  /// Parses a scanned string.
  ///
  /// Every field is required and an unknown field is a hard failure: a future
  /// version that adds a meaningful field must not be silently half-understood.
  static PairingBootstrap parse(String uri) {
    if (!uri.startsWith(bootstrapPrefix)) {
      throw const BootstrapException('not a PhoneAuth v1 pairing bootstrap');
    }

    String? verifierId;
    String? sessionId;
    Uint8List? nonce;
    Uint8List? hash;
    String? endpoint;
    int? expiresAtMs;
    var purpose = CredentialPurpose.authorization;

    for (final pair in uri.substring(bootstrapPrefix.length).split('&')) {
      final separator = pair.indexOf('=');
      if (separator < 0) {
        throw const BootstrapException('malformed bootstrap field');
      }
      final key = pair.substring(0, separator);
      final value = pair.substring(separator + 1);
      switch (key) {
        case 'vid':
          verifierId = value;
        case 'sid':
          sessionId = value;
        case 'n':
          nonce = _fixedBase64(value, 'invalid bootstrap nonce');
        case 'k':
          hash = _fixedBase64(value, 'invalid verifier identity hash');
        case 'ep':
          endpoint = _routableEndpoint(value);
        case 'exp':
          expiresAtMs =
              int.tryParse(value) ??
              (throw const BootstrapException('invalid bootstrap expiry'));
        case 'p':
          // A number this build has no name for is a purpose it does not
          // understand. Enrolling it as an authorization key is the single
          // outcome this field exists to prevent, so it fails instead.
          final index = int.tryParse(value);
          if (index == null ||
              index < 0 ||
              index >= CredentialPurpose.values.length) {
            throw const BootstrapException('invalid credential purpose');
          }
          purpose = CredentialPurpose.values[index];
        default:
          throw const BootstrapException('unknown bootstrap field');
      }
    }

    if (verifierId == null ||
        sessionId == null ||
        nonce == null ||
        hash == null ||
        endpoint == null ||
        expiresAtMs == null) {
      throw const BootstrapException('bootstrap is missing a required field');
    }

    return PairingBootstrap(
      sessionId: sessionId,
      nonce: nonce,
      verifierId: verifierId,
      verifierIdentityHash: hash,
      endpoint: endpoint,
      expiresAtMs: expiresAtMs,
      purpose: purpose,
    );
  }

  /// Rejects an address this phone could never reach the desktop on.
  ///
  /// `0.0.0.0` is the case that matters: it is what a server binds to, not
  /// something a client dials, and a phone that dials it dials itself. The
  /// desktop used to put its bind address in the code, and the failure surfaced
  /// as a connection error — which the UI reasonably, and wrongly, explained as
  /// the two devices being on different networks. Naming the real fault here
  /// costs one comparison and saves that whole diagnosis.
  static String _routableEndpoint(String value) {
    // BLE and anything else that does not dial an address carries no endpoint.
    if (value.isEmpty) return value;

    final colon = value.lastIndexOf(':');
    if (colon <= 0) {
      throw const BootstrapException('bootstrap endpoint has no port');
    }
    final address = value
        .substring(0, colon)
        .replaceAll(RegExp(r'^\[|\]$'), '');
    if (address == '0.0.0.0' || address == '::' || address.isEmpty) {
      throw BootstrapException(
        'the computer advertised an address no phone can reach ($address). '
        'It is running a version with a known pairing bug — update it.',
      );
    }
    return value;
  }

  /// Renders the scannable string. Present so a test can round-trip against
  /// the desktop's `to_uri`.
  String toUri() =>
      '${bootstrapPrefix}vid=$verifierId'
      '&sid=$sessionId'
      '&n=${toBase64Url(nonce)}'
      '&k=${toBase64Url(verifierIdentityHash)}'
      '&ep=$endpoint'
      '&exp=$expiresAtMs'
      // Written only when it is not the default, matching the desktop: an
      // ordinary login code stays scannable by a phone built before this
      // field existed, and anything else is refused there rather than
      // enrolled under the wrong purpose.
      '${purpose == CredentialPurpose.authorization ? '' : '&p=${purpose.index}'}';

  void _validate() {
    if (sessionId.isEmpty || sessionId.length > 64) {
      throw const BootstrapException('invalid session identifier');
    }
    if (verifierId.isEmpty || verifierId.length > 64) {
      throw const BootstrapException('invalid verifier identifier');
    }
    if (endpoint.length > 128) {
      throw const BootstrapException('endpoint is too long');
    }
    if (nonce.length != 32 || verifierIdentityHash.length != 32) {
      throw const BootstrapException('invalid bootstrap key material');
    }
    // The separators used by the query encoding must not appear inside a
    // value, or a round trip would silently split a field in two.
    for (final field in [sessionId, verifierId, endpoint]) {
      if (field.contains('&') || field.contains('=')) {
        throw const BootstrapException(
          'bootstrap fields may not contain `&` or `=`',
        );
      }
    }
  }
}

/// The commitment a bootstrap carries: `SHA-256("PhoneAuth/identity/v1" ‖ spki)`.
Future<Uint8List> hashIdentity(List<int> spki) async {
  final input = BytesBuilder(copy: false)
    ..add(utf8.encode(_identityDomain))
    ..add(spki);
  final digest = await Sha256().hash(input.takeBytes());
  return Uint8List.fromList(digest.bytes);
}

/// Unpadded base64url, matching `phone_auth_protocol::encoding`.
String toBase64Url(List<int> bytes) =>
    base64Url.encode(bytes).replaceAll('=', '');

Uint8List _fixedBase64(String value, String message) {
  try {
    final padded = value.padRight((value.length + 3) & ~3, '=');
    final decoded = base64Url.decode(padded);
    if (decoded.length != 32) throw const FormatException();
    return Uint8List.fromList(decoded);
  } on FormatException {
    throw BootstrapException(message);
  } on ArgumentError {
    throw BootstrapException(message);
  }
}
