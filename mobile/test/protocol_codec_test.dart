import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/core/protocol/auth_response.dart';
import 'package:phone_auth/core/protocol/protocol_codec.dart';
import 'package:phone_auth/domain/authentication_request.dart';

void main() {
  final codec = PhoneAuthProtocolCodec();
  final now = DateTime.utc(2026, 8, 26, 12);

  AuthenticationRequest request() => AuthenticationRequest(
    requestId: 'request-1',
    verifierId: 'desktop-1',
    verifierName: 'Desktop-Casa',
    credentialId: 'desktop-1-sudo-v1',
    challenge: Uint8List.fromList(List<int>.generate(32, (i) => i)),
    origin: 'not serialized',
    service: 'sudo',
    action: 'nixos-rebuild switch',
    resource: 'Desktop-NixOS',
    user: 'alice',
    issuedAt: now,
    expiresAt: now.add(const Duration(minutes: 1)),
    sessionBinding: Uint8List.fromList(List<int>.generate(32, (i) => 255 - i)),
  );

  test('request CBOR is deterministic and transport-independent', () {
    final original = request();
    final encoded = codec.encodeRequest(original);
    final decoded = codec.decodeRequest(encoded, origin: 'LAN authenticated');

    expect(codec.encodeRequest(decoded), encoded);
    expect(decoded.origin, 'LAN authenticated');
    expect(decoded.challenge, original.challenge);
    expect(decoded.sessionBinding, original.sessionBinding);
    expect(decoded.action, 'nixos-rebuild switch');
  });

  test('rejects malformed and unknown message frames', () {
    final encoded = codec.encodeRequest(request());
    encoded[0] = 0xff;

    expect(
      () => codec.decodeRequest(encoded, origin: 'test'),
      throwsFormatException,
    );
    expect(
      () => codec.decodeRequest(Uint8List(9000), origin: 'test'),
      throwsFormatException,
    );
  });

  test('response round-trips signature metadata', () {
    final response = AuthResponse(
      requestId: 'request-1',
      verifierId: 'desktop-1',
      credentialId: 'desktop-1-sudo-v1',
      decision: AuthorizationDecision.authorized,
      algorithm: 'Ed25519',
      signature: Uint8List.fromList([1, 2, 3]),
    );

    final decoded = codec.decodeResponse(codec.encodeResponse(response));
    expect(decoded.decision, AuthorizationDecision.authorized);
    expect(decoded.signature, [1, 2, 3]);
  });
}
