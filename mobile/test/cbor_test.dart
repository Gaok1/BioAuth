import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/core/protocol/cbor.dart';

void main() {
  Uint8List encoded(void Function(CborWriter writer) build) {
    final writer = CborWriter();
    build(writer);
    return writer.takeBytes();
  }

  test('integer heads use the shortest form', () {
    expect(encoded((w) => w.uint(0)), [0x00]);
    expect(encoded((w) => w.uint(23)), [0x17]);
    expect(encoded((w) => w.uint(24)), [0x18, 0x18]);
    expect(encoded((w) => w.uint(255)), [0x18, 0xff]);
    expect(encoded((w) => w.uint(256)), [0x19, 0x01, 0x00]);
    expect(encoded((w) => w.uint(65536)), [0x1a, 0x00, 0x01, 0x00, 0x00]);
    expect(encoded((w) => w.uint(4294967296)), [
      0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, //
    ]);
  });

  test('the protocol timestamp encodes as the desktop writes it', () {
    // `1b000001a03df1ec60` appears verbatim in the shared wire vectors.
    expect(
      encoded(
        (w) => w.int64(1787745660000),
      ).map((b) => b.toRadixString(16).padLeft(2, '0')).join(),
      '1b000001a03df1ec60',
    );
  });

  test('negative integers round-trip', () {
    for (final value in [-1, -24, -25, -256, -1000000]) {
      expect(CborReader(encoded((w) => w.int64(value))).int64(), value);
    }
  });

  test('padded integer arguments are refused', () {
    // Two encodings of one value would otherwise both parse, while only one of
    // them matches the bytes that were signed.
    expect(
      () => CborReader(Uint8List.fromList([0x18, 0x17])).uint(),
      throwsA(isA<CborException>()),
    );
    expect(
      () => CborReader(Uint8List.fromList([0x19, 0x00, 0xff])).uint(),
      throwsA(isA<CborException>()),
    );
  });

  test('indefinite lengths are refused', () {
    expect(
      () => CborReader(Uint8List.fromList([0x9f, 0xff])).array(),
      throwsA(isA<CborException>()),
    );
  });

  test('trailing bytes are refused', () {
    final reader = CborReader(Uint8List.fromList([0x01, 0x02]));
    expect(reader.uint(), 1);
    expect(reader.finish, throwsA(isA<CborException>()));
  });

  test('a truncated payload is an error, not a short read', () {
    // 0x45 announces a five-byte text string with only two bytes behind it.
    expect(
      () => CborReader(Uint8List.fromList([0x65, 0x61, 0x62])).text(),
      throwsA(isA<CborException>()),
    );
  });

  test('text and bytes round-trip', () {
    final frame = encoded(
      (w) => w
        ..array(2)
        ..text('nixos-rebuild switch')
        ..bytes([0xde, 0xad, 0xbe, 0xef]),
    );
    final reader = CborReader(frame);
    expect(reader.array(), 2);
    expect(reader.text(), 'nixos-rebuild switch');
    expect(reader.bytes(), [0xde, 0xad, 0xbe, 0xef]);
    reader.finish();
  });

  test('a text length counts UTF-8 bytes, not code units', () {
    // "é" is two bytes. Counting characters would put the length prefix out of
    // step with the payload and desynchronise everything after it.
    final frame = encoded((w) => w.text('é'));
    expect(frame, [0x62, 0xc3, 0xa9]);
    expect(CborReader(frame).text(), 'é');
  });

  test('a major type mismatch is refused', () {
    expect(
      () => CborReader(encoded((w) => w.text('x'))).bytes(),
      throwsA(isA<CborException>()),
    );
  });
}
