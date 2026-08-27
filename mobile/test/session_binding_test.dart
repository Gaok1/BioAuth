import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/core/session/session_binding.dart';

void main() {
  test('matches the Rust session-binding golden vector', () async {
    final binding = await deriveSessionBinding(
      SessionBindingInputs(
        transportName: 'loopback',
        sessionId: 's-1',
        serverEphemeral: Uint8List.fromList(List.filled(32, 1)),
        clientEphemeral: Uint8List.fromList(List.filled(32, 2)),
        exporter: Uint8List.fromList(List.filled(32, 3)),
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
        serverEphemeral: Uint8List(32),
        clientEphemeral: Uint8List(32),
        exporter: Uint8List(16),
      ),
      throwsArgumentError,
    );
  });

  test('matches the shared handshake vector for QrNetworkTransport', () async {
    // From docs/protocol-handshake.md, derived independently of both codecs.
    // A mismatch here means every request the phone signs is rejected.
    final binding = await deriveSessionBinding(
      SessionBindingInputs(
        transportName: 'QrNetworkTransport',
        sessionId: 'session-1',
        serverEphemeral: Uint8List.fromList(List.filled(32, 0x11)),
        clientEphemeral: Uint8List.fromList(List.filled(32, 0x22)),
        exporter: fromHex(
          'eb2501574690d2f829f0f625cf1789e5c3203b8d402d2e6fe6fee9d911cc5522',
        ),
      ),
    );

    expect(
      toHex(binding),
      'e8435f560ac83635c296802cfb1b07c01aba8c47efead3b880dcc3bbed024017',
    );
  });

  test('length prefixes prevent field boundary collisions', () async {
    // "ble" + "12" and "ble1" + "2" would collide under plain concatenation.
    Future<String> binding(String transport, String session) async => toHex(
      await deriveSessionBinding(
        SessionBindingInputs(
          transportName: transport,
          sessionId: session,
          serverEphemeral: Uint8List(32),
          clientEphemeral: Uint8List(32),
          exporter: Uint8List(32),
        ),
      ),
    );

    expect(await binding('ble', '12'), isNot(await binding('ble1', '2')));
  });
}

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
