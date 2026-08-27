import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/core/transport/length_prefixed_framer.dart';
import 'package:phone_auth/core/transport/qr_network_transport.dart';

void main() {
  test('frames round-trip', () {
    final wire = BytesBuilder(copy: false)
      ..add(encodeFrame('first'.codeUnits))
      ..add(encodeFrame('second'.codeUnits));

    final frames = LengthPrefixedFramer().addChunk(wire.takeBytes());
    expect(frames.map(String.fromCharCodes), ['first', 'second']);
  });

  test('a frame split across chunks is reassembled', () {
    // A real socket splits wherever it likes, including inside the prefix.
    final wire = encodeFrame(List<int>.generate(300, (i) => i & 0xff));
    final framer = LengthPrefixedFramer();

    expect(framer.addChunk(wire.sublist(0, 2)), isEmpty);
    expect(framer.addChunk(wire.sublist(2, 10)), isEmpty);
    expect(framer.addChunk(wire.sublist(10, wire.length - 1)), isEmpty);
    expect(framer.hasPartialFrame, isTrue);

    final frames = framer.addChunk(wire.sublist(wire.length - 1));
    expect(frames, hasLength(1));
    expect(frames.single, hasLength(300));
    expect(framer.hasPartialFrame, isFalse);
  });

  test('several frames in one chunk all come out', () {
    final wire = BytesBuilder(copy: false);
    for (var index = 0; index < 5; index++) {
      wire.add(encodeFrame([index]));
    }
    expect(LengthPrefixedFramer().addChunk(wire.takeBytes()), hasLength(5));
  });

  test('an announced length beyond the maximum is refused', () {
    // Only the prefix is present: a reader that allocated first would ask for
    // four gigabytes on this input.
    expect(
      () => LengthPrefixedFramer().addChunk([0xff, 0xff, 0xff, 0xff]),
      throwsA(isA<FramingException>()),
    );
  });

  test('a zero-length frame is refused', () {
    expect(
      () => LengthPrefixedFramer().addChunk([0, 0, 0, 0]),
      throwsA(isA<FramingException>()),
    );
  });

  test('empty and oversized frames never reach the wire', () {
    expect(() => encodeFrame(const []), throwsA(isA<FramingException>()));
    expect(
      () => encodeFrame(Uint8List(maxFramedBytes + 1)),
      throwsA(isA<FramingException>()),
    );
    expect(
      encodeFrame(Uint8List(maxFramedBytes)),
      hasLength(maxFramedBytes + 4),
    );
  });

  test('endpoints parse into a host and a port', () {
    expect(parseEndpoint('192.168.1.10:8765'), ('192.168.1.10', 8765));
    expect(parseEndpoint('desktop.local:1'), ('desktop.local', 1));
    // Splitting on the first colon would read this host as `[fe80`.
    expect(parseEndpoint('[fe80::1]:8765'), ('fe80::1', 8765));
  });

  test('an endpoint without a usable port is refused', () {
    for (final endpoint in [
      '192.168.1.10',
      ':8765',
      'host:',
      'host:0',
      'host:70000',
      'host:abc',
    ]) {
      expect(
        () => parseEndpoint(endpoint),
        throwsFormatException,
        reason: '`$endpoint` must be refused',
      );
    }
  });
}
