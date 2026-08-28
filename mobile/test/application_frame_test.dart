import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/core/protocol/application_frame.dart';

void main() {
  ApplicationFrame fixture() => ApplicationFrame(
    protocolVersion: 1,
    kind: ApplicationFrameKind.request,
    requestId: 'request-1',
    sessionBinding: Uint8List.fromList(List<int>.generate(32, (i) => i)),
    operation: 'vault.list',
    issuedAt: DateTime.fromMillisecondsSinceEpoch(1787745600000, isUtc: true),
    expiresAt: DateTime.fromMillisecondsSinceEpoch(1787745660000, isUtc: true),
    payload: const [1, 2, 3],
  );

  test('matches the Rust application-frame vector and round-trips', () {
    final original = fixture();
    expect(
      _hex(original.encode()),
      '8904010069726571756573742d315820000102030405060708090a0b0c0d0e0f'
      '101112131415161718191a1b1c1d1e1f6a7661756c742e6c6973741b000001a0'
      '3df102001b000001a03df1ec6043010203',
    );

    final decoded = ApplicationFrame.decode(original.encode());
    expect(decoded.kind, ApplicationFrameKind.request);
    expect(decoded.requestId, 'request-1');
    expect(decoded.sessionBinding, original.sessionBinding);
    expect(decoded.operation, 'vault.list');
    expect(decoded.payload, [1, 2, 3]);
  });

  test('rejects foreign services, bad bindings, payloads, and validity', () {
    expect(
      () => ApplicationFrame(
        protocolVersion: 1,
        kind: ApplicationFrameKind.request,
        requestId: 'request-1',
        sessionBinding: Uint8List(31),
        operation: 'sudo.run',
        issuedAt: DateTime.utc(2026),
        expiresAt: DateTime.utc(2026),
        payload: Uint8List(maxApplicationPayloadBytes + 1),
      ).validate(),
      throwsFormatException,
    );

    final expired = fixture();
    expect(expired.isExpiredAt(expired.expiresAt), isTrue);
    expect(
      expired.isExpiredAt(
        expired.expiresAt.subtract(const Duration(milliseconds: 1)),
      ),
      isFalse,
    );
  });

  test('a reply matches only its request, session, operation, and expiry', () {
    final request = fixture();
    final reply = ApplicationFrame(
      protocolVersion: request.protocolVersion,
      kind: ApplicationFrameKind.response,
      requestId: request.requestId,
      sessionBinding: request.sessionBinding,
      operation: request.operation,
      issuedAt: request.issuedAt,
      expiresAt: request.expiresAt,
      payload: const [9],
    );
    expect(
      reply.isReplyTo(
        request,
        request.expiresAt.subtract(const Duration(milliseconds: 1)),
      ),
      isTrue,
    );

    final wrongSession = ApplicationFrame(
      protocolVersion: reply.protocolVersion,
      kind: reply.kind,
      requestId: reply.requestId,
      sessionBinding: Uint8List(32)..[0] = 1,
      operation: reply.operation,
      issuedAt: reply.issuedAt,
      expiresAt: reply.expiresAt,
      payload: reply.payload,
    );
    expect(wrongSession.isReplyTo(request, request.issuedAt), isFalse);
    expect(reply.isReplyTo(request, request.expiresAt), isFalse);
  });

  test('generic application errors round-trip without detail', () {
    for (final code in ApplicationErrorCode.values) {
      expect(ApplicationErrorCode.decode(code.encode()), code);
    }
    // The same bytes are pinned in the Rust test
    // `application_errors_are_coarse_and_canonical`. Written against the hex,
    // not against the other encoder, so a matching mistake on one side does
    // not make the pair agree.
    expect(_hex(ApplicationErrorCode.rejected.encode()), '820100');
    expect(_hex(ApplicationErrorCode.invalidRequest.encode()), '820101');
    expect(_hex(ApplicationErrorCode.unavailable.encode()), '820102');
    expect(
      () => ApplicationErrorCode.decode(Uint8List.fromList([0x82, 0x01, 0x03])),
      throwsFormatException,
    );
  });
}

String _hex(List<int> bytes) =>
    bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();
