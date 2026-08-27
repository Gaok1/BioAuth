import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/core/session/session_binding.dart';

void main() {
  test('matches the Rust session-binding golden vector', () async {
    final binding = await deriveSessionBinding(
      SessionBindingInputs(
        transportName: 'loopback',
        sessionId: 's-1',
        verifierHandshakeKey: Uint8List.fromList(List.filled(32, 1)),
        peerHandshakeKey: Uint8List.fromList(List.filled(32, 2)),
        transcriptSecret: Uint8List.fromList(List.filled(32, 3)),
      ),
    );

    expect(
      binding.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join(),
      '79963f7bc3780d6284bcdc71010c0d633a0bc8340f7546de52020167a530a45e',
    );
  });

  test('rejects an incomplete handshake secret', () {
    expect(
      () => SessionBindingInputs(
        transportName: 'ble',
        sessionId: 's-1',
        verifierHandshakeKey: Uint8List(32),
        peerHandshakeKey: Uint8List(32),
        transcriptSecret: Uint8List(16),
      ),
      throwsArgumentError,
    );
  });
}
