import 'dart:convert';
import 'dart:typed_data';

class AuthenticationRequest {
  AuthenticationRequest({
    this.protocolVersion = 1,
    required this.requestId,
    required this.verifierId,
    required this.verifierName,
    required this.credentialId,
    required Uint8List challenge,
    required this.origin,
    required this.service,
    required this.action,
    required this.resource,
    required this.user,
    required this.issuedAt,
    required this.expiresAt,
    required Uint8List sessionBinding,
    this.duplicateCount = 1,
  }) : challenge = Uint8List.fromList(challenge),
       sessionBinding = Uint8List.fromList(sessionBinding) {
    _validate();
  }

  factory AuthenticationRequest.fromJson(Map<String, Object?> json) {
    String requiredString(String key, {int maxLength = 128}) {
      final value = json[key];
      if (value is! String ||
          value.trim().isEmpty ||
          value.length > maxLength) {
        throw FormatException('invalid field: $key');
      }
      return value.trim();
    }

    DateTime requiredDate(String key) {
      final value = json[key];
      final parsed = value is String ? DateTime.tryParse(value) : null;
      if (parsed == null || !parsed.isUtc) {
        throw FormatException('invalid UTC date: $key');
      }
      return parsed;
    }

    Uint8List requiredBytes(String key, int length) {
      final value = requiredString(key, maxLength: 256);
      try {
        final decoded = base64Url.decode(base64Url.normalize(value));
        if (decoded.length != length) throw const FormatException();
        return decoded;
      } on FormatException {
        throw FormatException('$key must be $length base64url bytes');
      }
    }

    return AuthenticationRequest(
      protocolVersion: json['protocolVersion'] as int? ?? 1,
      requestId: requiredString('requestId', maxLength: 64),
      verifierId: requiredString('verifierId', maxLength: 64),
      verifierName: requiredString('verifierName'),
      credentialId: requiredString('credentialId', maxLength: 64),
      challenge: requiredBytes('challenge', 32),
      origin: requiredString('origin'),
      service: requiredString('service', maxLength: 64),
      action: requiredString('action'),
      resource: requiredString('resource', maxLength: 256),
      user: requiredString('user'),
      issuedAt: requiredDate('issuedAt'),
      expiresAt: requiredDate('expiresAt'),
      sessionBinding: requiredBytes('sessionBinding', 32),
    );
  }

  final int protocolVersion;
  final String requestId;
  final String verifierId;
  final String verifierName;
  final String credentialId;
  final Uint8List challenge;
  final String origin;
  final String service;
  final String action;
  final String resource;
  final String user;
  final DateTime issuedAt;
  final DateTime expiresAt;
  final Uint8List sessionBinding;
  final int duplicateCount;

  String get id => requestId;
  String get deviceId => verifierId;
  String get deviceName => verifierName;
  DateTime get requestedAt => issuedAt;

  bool isExpiredAt(DateTime now) => !now.isBefore(expiresAt);

  String get fingerprint =>
      '$verifierId\u0000$credentialId\u0000$service\u0000$action\u0000$resource\u0000$user';

  AuthenticationRequest copyWith({int? duplicateCount, String? origin}) =>
      AuthenticationRequest(
        protocolVersion: protocolVersion,
        requestId: requestId,
        verifierId: verifierId,
        verifierName: verifierName,
        credentialId: credentialId,
        challenge: challenge,
        origin: origin ?? this.origin,
        service: service,
        action: action,
        resource: resource,
        user: user,
        issuedAt: issuedAt,
        expiresAt: expiresAt,
        sessionBinding: sessionBinding,
        duplicateCount: duplicateCount ?? this.duplicateCount,
      );

  void _validate() {
    if (protocolVersion != 1) {
      throw const FormatException('unsupported protocol version');
    }
    final fields = <String, (String, int)>{
      'requestId': (requestId, 64),
      'verifierId': (verifierId, 64),
      'verifierName': (verifierName, 128),
      'credentialId': (credentialId, 64),
      'origin': (origin, 128),
      'service': (service, 64),
      'action': (action, 128),
      'resource': (resource, 256),
      'user': (user, 128),
    };
    for (final entry in fields.entries) {
      if (entry.value.$1.trim().isEmpty ||
          entry.value.$1.length > entry.value.$2) {
        throw FormatException('invalid field: ${entry.key}');
      }
    }
    if (challenge.length != 32 || sessionBinding.length != 32) {
      throw const FormatException(
        'challenge and session binding must be 32 bytes',
      );
    }
    if (!issuedAt.isUtc ||
        !expiresAt.isUtc ||
        !expiresAt.isAfter(issuedAt) ||
        expiresAt.difference(issuedAt) > const Duration(minutes: 2)) {
      throw const FormatException('invalid validity window');
    }
  }
}
