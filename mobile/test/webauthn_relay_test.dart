import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/core/protocol/webauthn_relay.dart';

void main() {
  Uint8List frame(Map<String, Object?> value) => Uint8List.fromList([
    ...utf8.encode('BAWA1\n'),
    ...utf8.encode(jsonEncode(value)),
  ]);

  Map<String, Object?> request({
    String verifierId = 'desktop-1',
    String origin = 'https://login.example.com',
  }) => {
    'version': 1,
    'type': 'webauthn.request',
    'requestId': 'request-1',
    'verifierId': verifierId,
    'operation': 'get',
    'origin': origin,
    'options': {'rpId': 'example.com', 'challenge': 'AAECAwQFBgcICQoLDA0ODw'},
  };

  test('accepts a bounded request from the authenticated verifier', () {
    final decoded = WebAuthnRelayRequest.decode(
      frame(request()),
      expectedVerifierId: 'desktop-1',
    );
    expect(decoded.origin, 'https://login.example.com');
    expect(decoded.operation, 'get');
  });

  test('rejects a request naming another verifier or insecure origin', () {
    expect(
      () => WebAuthnRelayRequest.decode(
        frame(request(verifierId: 'desktop-2')),
        expectedVerifierId: 'desktop-1',
      ),
      throwsFormatException,
    );
    expect(
      () => WebAuthnRelayRequest.decode(
        frame(request(origin: 'http://example.com')),
        expectedVerifierId: 'desktop-1',
      ),
      throwsFormatException,
    );
  });
}
