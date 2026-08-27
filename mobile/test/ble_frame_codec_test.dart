import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/core/bluetooth/ble_frame_codec.dart';

void main() {
  test('uses the shared Rust-compatible big-endian chunk header', () {
    final chunks = BleFrameCodec()
        .encode(Uint8List.fromList('abcdefghij'.codeUnits), attPayloadBytes: 10)
        .map((chunk) => chunk.toList())
        .toList();

    expect(chunks, [
      [0, 0, 0, 0, 0, 3, 97, 98, 99, 100],
      [0, 0, 0, 1, 0, 3, 101, 102, 103, 104],
      [0, 0, 0, 2, 0, 3, 105, 106],
    ]);
  });

  test('fragments and reassembles a bounded frame out of order', () {
    final sender = BleFrameCodec();
    final receiver = BleFrameCodec();
    final frame = Uint8List.fromList(List<int>.generate(400, (i) => i & 0xff));
    final chunks = sender.encode(frame, attPayloadBytes: 20).toList().reversed;

    Uint8List? decoded;
    for (final chunk in chunks) {
      decoded = receiver.addChunk(chunk) ?? decoded;
    }
    expect(decoded, frame);
  });

  test('rejects oversized frames and malformed chunks', () {
    final codec = BleFrameCodec(maxFrameBytes: 8);

    expect(
      () => codec.encode(Uint8List(9), attPayloadBytes: 20).toList(),
      throwsFormatException,
    );
    expect(codec.addChunk([0, 1, 0]), isNull);
  });
}
