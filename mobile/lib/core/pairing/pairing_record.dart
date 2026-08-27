import 'dart:convert';
import 'dart:typed_data';

import '../protocol/enrolment.dart';
import '../transport/pairing_bootstrap.dart';

/// Everything the phone must remember about one paired desktop.
///
/// [verifierIdentitySpki] is the load-bearing field: after pairing there is no
/// QR code to authenticate against, so this stored key is the only thing that
/// distinguishes the real desktop from anything else answering on that address.
class PairingRecord {
  PairingRecord({
    required this.verifierId,
    required Uint8List verifierIdentitySpki,
    required this.endpoint,
    required this.credentialId,
    required this.keyKind,
    required this.purpose,
    required this.pairedAt,
  }) : verifierIdentitySpki = Uint8List.fromList(verifierIdentitySpki);

  final String verifierId;
  final Uint8List verifierIdentitySpki;

  /// `host:port` the phone dials. Re-learned on each pairing, because a
  /// desktop's address changes and the identity key does not.
  final String endpoint;

  final String credentialId;
  final KeyKind keyKind;
  final CredentialPurpose purpose;
  final DateTime pairedAt;

  PairingRecord copyWith({String? endpoint}) => PairingRecord(
    verifierId: verifierId,
    verifierIdentitySpki: verifierIdentitySpki,
    endpoint: endpoint ?? this.endpoint,
    credentialId: credentialId,
    keyKind: keyKind,
    purpose: purpose,
    pairedAt: pairedAt,
  );

  Map<String, Object?> toJson() => {
    'verifierId': verifierId,
    'identitySpki': toBase64Url(verifierIdentitySpki),
    'endpoint': endpoint,
    'credentialId': credentialId,
    'keyKind': keyKind.index,
    'purpose': purpose.index,
    'pairedAt': pairedAt.toUtc().toIso8601String(),
  };

  static PairingRecord fromJson(Map<String, Object?> json) {
    final spki = json['identitySpki'];
    final keyKind = json['keyKind'];
    final purpose = json['purpose'];
    if (spki is! String ||
        keyKind is! int ||
        purpose is! int ||
        keyKind >= KeyKind.values.length ||
        purpose >= CredentialPurpose.values.length) {
      throw const FormatException('malformed pairing record');
    }
    return PairingRecord(
      verifierId: json['verifierId']! as String,
      verifierIdentitySpki: _decodeBase64Url(spki),
      endpoint: json['endpoint']! as String,
      credentialId: json['credentialId']! as String,
      keyKind: KeyKind.values[keyKind],
      purpose: CredentialPurpose.values[purpose],
      pairedAt: DateTime.parse(json['pairedAt']! as String).toUtc(),
    );
  }
}

Uint8List _decodeBase64Url(String value) => Uint8List.fromList(
  base64Url.decode(value.padRight((value.length + 3) & ~3, '=')),
);
