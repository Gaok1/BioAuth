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

  /// The desktop's decoder refuses a fifth concurrent frame and keeps the four
  /// it is assembling. This one dropped one of those to make room, and picked
  /// the oldest — which in an exchange that is making progress is the one
  /// closest to being finished. Its chunks went, nothing said so, and the peer
  /// went on sending the rest of a frame that could never complete.
  test('a fifth frame is refused rather than evicting one in progress', () {
    final codec = BleFrameCodec();
    Uint8List chunk(int frameId, int index) {
      final bytes = Uint8List(BleFrameCodec.headerBytes + 2);
      final header = ByteData.sublistView(bytes);
      header.setUint16(0, frameId);
      header.setUint16(2, index);
      header.setUint16(4, 2);
      bytes[BleFrameCodec.headerBytes] = frameId;
      bytes[BleFrameCodec.headerBytes + 1] = index;
      return bytes;
    }

    // Four frames, each half arrived. The first is the one eviction took.
    for (
      var frameId = 1;
      frameId <= BleFrameCodec.maxPartialFrames;
      frameId++
    ) {
      expect(codec.addChunk(chunk(frameId, 0)), isNull);
    }

    // One more than the decoder holds.
    expect(codec.addChunk(chunk(99, 0)), isNull, reason: 'the fifth was taken');

    // And the first frame can still be finished, which is the whole point.
    expect(
      codec.addChunk(chunk(1, 1)),
      Uint8List.fromList([1, 0, 1, 1]),
      reason: 'a frame in progress was thrown away for one that arrived later',
    );
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
