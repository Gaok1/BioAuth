import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/core/bluetooth/ble_frame_codec.dart';

void main() {
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
