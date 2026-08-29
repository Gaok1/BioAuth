/// DER to `r || s`.
///
/// The Keystore signs in DER and SSH reads raw pairs, and the gap between them
/// is where a signature that verifies "most of the time" comes from: DER
/// integers are signed, so a coordinate with its top bit set carries a leading
/// zero, and one that happens to start with a zero byte is written short. Both
/// cases are ordinary — roughly half of all signatures hit the first — so a
/// converter that gets them wrong looks like an unreliable network.
library;

import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/core/ssh/native_ssh_signer.dart';

Uint8List bytes(List<int> values) => Uint8List.fromList(values);

/// Builds `SEQUENCE { INTEGER r, INTEGER s }` the way a DER encoder would.
Uint8List der(List<int> r, List<int> s) {
  List<int> integer(List<int> value) {
    var body = value.skipWhile((byte) => byte == 0).toList();
    if (body.isEmpty) body = [0];
    if (body.first & 0x80 != 0) body = [0, ...body];
    return [0x02, body.length, ...body];
  }

  final body = [...integer(r), ...integer(s)];
  return bytes([0x30, body.length, ...body]);
}

void main() {
  test('an ordinary signature becomes two 32-byte halves', () {
    final r = List<int>.filled(32, 0x11);
    final s = List<int>.filled(32, 0x22);

    final raw = rawEcdsaSignature(der(r, s));

    expect(raw, isNotNull);
    expect(raw!.length, 64);
    expect(raw.sublist(0, 32), r);
    expect(raw.sublist(32), s);
  });

  /// The case that bites. `0x80` at the top means DER prefixes a zero byte, and
  /// carrying that zero into the SSH pair shifts every byte of `r` by one.
  test('a leading zero added by DER is not part of the scalar', () {
    final r = [0x80, ...List<int>.filled(31, 0x01)];
    final s = List<int>.filled(32, 0x02);

    final encoded = der(r, s);
    // 0x30, sequence length, 0x02, integer length, then the content — where
    // the zero DER had to add sits.
    expect(encoded[4], 0x00, reason: 'the fixture is not exercising the case');
    expect(encoded[3], 33, reason: 'the padded integer should be 33 bytes');

    final raw = rawEcdsaSignature(encoded);

    expect(raw!.sublist(0, 32), r);
  });

  /// The mirror case: a scalar that genuinely starts with zeros is written
  /// short, and has to be padded back or it lands in the wrong half.
  test('a short scalar is padded back to 32 bytes on the left', () {
    final r = [0x00, 0x00, ...List<int>.filled(30, 0x07)];
    final s = List<int>.filled(32, 0x09);

    final raw = rawEcdsaSignature(der(r, s));

    expect(raw!.sublist(0, 32), r);
    expect(raw.sublist(32), s);
  });

  test('a one-byte scalar still lands at the right end', () {
    final raw = rawEcdsaSignature(der([0x05], [0x06]));

    expect(raw!.sublist(0, 32), [...List<int>.filled(31, 0), 0x05]);
    expect(raw.sublist(32), [...List<int>.filled(31, 0), 0x06]);
  });

  /// Anything unreadable is refused outright. A converter that salvages what it
  /// can from a malformed signature is guessing at the one value nobody may
  /// guess at.
  test('malformed input is refused rather than salvaged', () {
    final valid = der(List<int>.filled(32, 1), List<int>.filled(32, 2));

    final cases = <String, Uint8List>{
      'empty': bytes([]),
      'not a sequence': bytes([0x31, ...valid.skip(1)]),
      'truncated': valid.sublist(0, valid.length - 1),
      'trailing bytes': bytes([...valid, 0x00]),
      'wrong inner tag': bytes([...valid.take(2), 0x04, ...valid.skip(3)]),
      'zero-length integer': bytes([0x30, 0x04, 0x02, 0x00, 0x02, 0x00]),
      'a scalar too long for P-256': der(
        List<int>.filled(33, 0x11),
        List<int>.filled(32, 0x22),
      ),
      'only one integer': bytes([0x30, 0x03, 0x02, 0x01, 0x05]),
    };

    for (final entry in cases.entries) {
      expect(
        rawEcdsaSignature(entry.value),
        isNull,
        reason: '`${entry.key}` was accepted',
      );
    }
  });
}
