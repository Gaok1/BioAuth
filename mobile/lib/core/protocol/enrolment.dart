/// Credential enrolment: what the phone sends after a pairing handshake.
///
/// The handshake establishes *which device* is talking. It exchanges session
/// identity keys and nothing else. The key that actually signs authorizations
/// lives behind a biometric gate in the phone's keystore, and this frame is how
/// its public half reaches the verifier.
///
/// Sent inside the encrypted channel, never in the clear and never in a QR
/// code. Mirrors `desktop/crates/phone-auth-protocol/src/enrolment.rs`.
library;

import 'dart:typed_data';

import 'cbor.dart';

const int _enrolmentType = 3;
const int _protocolVersion = 1;
const int _enrolmentFrameLength = 9;

/// The only public key encoding this protocol carries.
const String publicKeyEcP256Spki = 'EC_P256_SPKI';

/// Where the enrolled credential's private key lives.
///
/// Reported by the phone. The verifier cannot prove it and uses it only to
/// *withhold* authority — a software key is never enough for disk unlock —
/// never to grant more than the paired public key already establishes.
/// Reporting it honestly is a correctness requirement on this side.
enum KeyKind {
  /// A discrete secure element: Android StrongBox, iOS Secure Enclave.
  strongBox,

  /// TEE-backed keystore without a separate secure element.
  hardware,

  /// Not hardware-backed. Development fixtures only.
  software,
}

/// What the credential may be used for.
///
/// Enforces key separation: a credential enrolled for [authorization] is
/// refused if later offered for [diskUnlock], so a phone that wants both must
/// enrol two credentials from two distinct keystore aliases.
enum CredentialPurpose {
  /// Interactive authorization: login, sudo, unlocking an app.
  authorization,

  /// Boot-time volume unwrapping. Requires a hardware-backed key.
  diskUnlock,

  /// WebAuthn assertions. Uses a separate per-RP Keystore alias.
  webAuthn,

  /// Password-vault encryption and release operations.
  vault,

  /// File-locker key wrapping and release operations.
  fileLocker,
}

class EnrolmentException implements Exception {
  const EnrolmentException(this.message);

  final String message;

  @override
  String toString() => 'EnrolmentException: $message';
}

/// One credential offered for enrolment.
class Enrolment {
  Enrolment({
    required this.deviceName,
    required this.credentialId,
    required Uint8List publicKey,
    required this.keyKind,
    required this.purpose,
    this.algorithm = publicKeyEcP256Spki,
    this.protocolVersion = _protocolVersion,
  }) : publicKey = Uint8List.fromList(publicKey) {
    _validate();
  }

  final int protocolVersion;

  /// Name the user will see in the paired-devices list.
  final String deviceName;
  final String credentialId;
  final String algorithm;
  final Uint8List publicKey;
  final KeyKind keyKind;
  final CredentialPurpose purpose;

  Uint8List encode() {
    final writer = CborWriter()
      ..array(_enrolmentFrameLength)
      ..uint(_enrolmentType)
      ..uint(protocolVersion)
      ..text(deviceName)
      ..text(credentialId)
      ..text(algorithm)
      ..bytes(publicKey)
      ..uint(keyKind.index)
      ..uint(purpose.index)
      // Reserved for a future field; keeping the arity fixed means adding one
      // is a version bump rather than a silent shape change.
      ..uint(0);
    return writer.takeBytes();
  }

  static Enrolment decode(Uint8List frame) {
    final reader = CborReader(frame);
    if (reader.array() != _enrolmentFrameLength) {
      throw const EnrolmentException('unexpected enrolment frame shape');
    }
    if (reader.uint() != _enrolmentType) {
      throw const EnrolmentException('unexpected message type');
    }
    final enrolment = Enrolment(
      protocolVersion: reader.uint(),
      deviceName: reader.text(),
      credentialId: reader.text(),
      algorithm: reader.text(),
      publicKey: reader.bytes(),
      keyKind: _wireValue(KeyKind.values, reader.uint(), 'key kind'),
      purpose: _wireValue(CredentialPurpose.values, reader.uint(), 'purpose'),
    );
    if (reader.uint() != 0) {
      throw const EnrolmentException('reserved field is not zero');
    }
    reader.finish();
    return enrolment;
  }

  void _validate() {
    if (protocolVersion != _protocolVersion) {
      throw const EnrolmentException('unsupported protocol version');
    }
    _checkText('deviceName', deviceName, 128);
    _checkText('credentialId', credentialId, 64);
    _checkText('algorithm', algorithm, 64);
    // A SubjectPublicKeyInfo for P-256 is 91 bytes; the bound is generous
    // enough for other curves without accepting an arbitrary blob.
    if (publicKey.isEmpty || publicKey.length > 512) {
      throw const EnrolmentException('publicKey is empty or oversized');
    }
  }
}

void _checkText(String field, String value, int limit) {
  if (value.trim().isEmpty) {
    throw EnrolmentException('$field is empty');
  }
  if (value.length > limit) {
    throw EnrolmentException('$field is longer than $limit characters');
  }
}

T _wireValue<T>(List<T> values, int index, String what) {
  if (index < 0 || index >= values.length) {
    throw EnrolmentException('unknown $what `$index`');
  }
  return values[index];
}
