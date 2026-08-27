// Cross-language wire format lock, Dart side.
//
// The hex below is the same constant as
// `desktop/crates/phone-auth-protocol/tests/golden_vectors.rs`. It was derived
// from RFC 8949 independently of both codecs, so the two implementations
// agreeing with it is evidence they agree with each other — not just that they
// share a bug.
//
// If this test fails, a phone's signatures will not verify on the desktop and
// every paired device would need re-pairing. Treat a change to the constant as
// a protocol version bump, not as a fix.

import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/core/protocol/auth_response.dart';
import 'package:phone_auth/core/protocol/protocol_codec.dart';
import 'package:phone_auth/domain/authentication_request.dart';

/// Canonical encoding of the shared fixture request.
const String requestFrameHex =
    '8e0101'
    '69726571756573742d31' // "request-1"
    '696465736b746f702d31' // "desktop-1"
    '6c4465736b746f702d43617361' // "Desktop-Casa"
    '716465736b746f702d312d7375646f2d7631' // "desktop-1-sudo-v1"
    '5820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
    '647375646f' // "sudo"
    '746e69786f732d72656275696c6420737769746368' // "nixos-rebuild switch"
    '6d4465736b746f702d4e69784f53' // "Desktop-NixOS"
    '65616c696365' // "alice"
    '1b000001a03df10200' // issuedAt  1787745600000
    '1b000001a03df1ec60' // expiresAt 1787745660000
    '5820fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0';

Uint8List fromHex(String hex) {
  final bytes = Uint8List(hex.length ~/ 2);
  for (var index = 0; index < bytes.length; index++) {
    bytes[index] = int.parse(
      hex.substring(index * 2, index * 2 + 2),
      radix: 16,
    );
  }
  return bytes;
}

String toHex(List<int> bytes) =>
    bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();

void main() {
  const codec = PhoneAuthProtocolCodec();
  final issuedAt = DateTime.utc(2026, 8, 26, 12);

  AuthenticationRequest fixture() => AuthenticationRequest(
    requestId: 'request-1',
    verifierId: 'desktop-1',
    verifierName: 'Desktop-Casa',
    credentialId: 'desktop-1-sudo-v1',
    challenge: Uint8List.fromList(List<int>.generate(32, (i) => i)),
    // Not serialized: origin is a property of the session, never of the frame.
    origin: 'not serialized',
    service: 'sudo',
    action: 'nixos-rebuild switch',
    resource: 'Desktop-NixOS',
    user: 'alice',
    issuedAt: issuedAt,
    expiresAt: issuedAt.add(const Duration(minutes: 1)),
    sessionBinding: Uint8List.fromList(List<int>.generate(32, (i) => 255 - i)),
  );

  test('the fixture timestamps match the shared vector', () {
    // Guards against a timezone mistake silently shifting the whole frame.
    expect(issuedAt.millisecondsSinceEpoch, 1787745600000);
    expect(
      issuedAt.add(const Duration(minutes: 1)).millisecondsSinceEpoch,
      1787745660000,
    );
  });

  test('request encoding matches the golden vector', () {
    final expected = fromHex(requestFrameHex);
    expect(expected.length, 186, reason: 'golden vector length');
    expect(toHex(codec.encodeRequest(fixture())), toHex(expected));
  });

  test('the golden vector decodes back to the fixture', () {
    final decoded = codec.decodeRequest(
      fromHex(requestFrameHex),
      origin: 'test',
    );
    final original = fixture();

    expect(decoded.requestId, original.requestId);
    expect(decoded.verifierId, original.verifierId);
    expect(decoded.verifierName, original.verifierName);
    expect(decoded.credentialId, original.credentialId);
    expect(decoded.challenge, original.challenge);
    expect(decoded.service, original.service);
    expect(decoded.action, original.action);
    expect(decoded.resource, original.resource);
    expect(decoded.user, original.user);
    expect(decoded.issuedAt, original.issuedAt);
    expect(decoded.expiresAt, original.expiresAt);
    expect(decoded.sessionBinding, original.sessionBinding);
  });

  test('the signed payload is the whole frame, not just the challenge', () {
    // What the native layer receives as `canonicalRequest` must be the frame
    // itself; signing a subset would let one approval stand in for another.
    final frame = codec.encodeRequest(fixture());
    expect(frame, fromHex(requestFrameHex));
    expect(
      toHex(frame).contains(toHex('nixos-rebuild switch'.codeUnits)),
      isTrue,
      reason: 'the action must be inside the signed bytes',
    );
  });

  test('decision indices are pinned to the wire values', () {
    // The desktop reads these as 0 and 1. Reordering the enum would turn a
    // denial into an authorization.
    expect(AuthorizationDecision.authorized.index, 0);
    expect(AuthorizationDecision.denied.index, 1);
  });
}
