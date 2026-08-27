import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/domain/authentication_request.dart';

void main() {
  Map<String, Object?> validPayload() => {
    'protocolVersion': 1,
    'requestId': 'request-1',
    'verifierId': 'desktop-1',
    'verifierName': 'Desktop-Casa',
    'credentialId': 'desktop-1-login',
    'challenge': base64Url.encode(Uint8List(32)),
    'origin': 'BLE pareado',
    'service': 'SSH',
    'action': 'Iniciar sessão',
    'resource': 'prod-server',
    'user': 'alice',
    'issuedAt': '2026-08-26T12:00:00Z',
    'expiresAt': '2026-08-26T12:01:00Z',
    'sessionBinding': base64Url.encode(Uint8List(32)),
  };

  test('parses a bounded UTC request', () {
    final request = AuthenticationRequest.fromJson(validPayload());

    expect(request.service, 'SSH');
    expect(request.expiresAt.difference(request.requestedAt).inMinutes, 1);
  });

  test('rejects malformed and overlong payloads', () {
    final missingUser = validPayload()..remove('user');
    final longResource = validPayload()..['resource'] = 'x' * 257;

    expect(
      () => AuthenticationRequest.fromJson(missingUser),
      throwsFormatException,
    );
    expect(
      () => AuthenticationRequest.fromJson(longResource),
      throwsFormatException,
    );
  });

  test('rejects excessive validity windows and non-UTC dates', () {
    final excessive = validPayload()..['expiresAt'] = '2026-08-26T12:03:00Z';
    final localDate = validPayload()..['issuedAt'] = '2026-08-26T12:00:00';

    expect(
      () => AuthenticationRequest.fromJson(excessive),
      throwsFormatException,
    );
    expect(
      () => AuthenticationRequest.fromJson(localDate),
      throwsFormatException,
    );
  });
}
