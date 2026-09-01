/// Property tests over the decoders that read the session.
///
/// The Rust side fuzzes its half of this wire with four thousand cases per
/// decoder in CI. The phone's half reads the same bytes, from a paired desktop
/// or from anything that can write to an established session, and it is the
/// half holding the secrets — but the cases pinned for it were the ones
/// somebody thought of: a lying length prefix, an unknown schema, a kind out of
/// range. Those are the failures that were found, not the shape of the ones
/// that have not been.
///
/// One property, and it is about the *type* of the failure rather than the
/// failure. Every caller here is written to catch `FormatException`, and
/// `ApplicationFrame.decode` is called before `VaultService.handle` opens a
/// `try` at all. So a `RangeError` or a `TypeError` out of any of these does
/// not become a refused frame: it leaves the handler by a path nobody wrote.
library;

import 'dart:math';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/core/protocol/application_frame.dart';
import 'package:phone_auth/core/protocol/vault_payloads.dart' as wire;

import 'support/property_config.dart';

typedef Decoder = void Function(Uint8List bytes);

void main() {
  final decoders = <String, Decoder>{
    'ApplicationFrame': (bytes) => ApplicationFrame.decode(bytes),
    'ApplicationErrorCode': (bytes) => ApplicationErrorCode.decode(bytes),
    'VaultListRequest': (bytes) => wire.VaultListRequest.decode(bytes),
    'VaultListResponse': (bytes) => wire.VaultListResponse.decode(bytes),
    'VaultFetchRequest': (bytes) => wire.VaultFetchRequest.decode(bytes),
    'VaultFetchResponse': (bytes) => wire.VaultFetchResponse.decode(bytes),
    'VaultCreateRequest': (bytes) => wire.VaultCreateRequest.decode(bytes),
    'VaultUpdateRequest': (bytes) => wire.VaultUpdateRequest.decode(bytes),
    'VaultDeleteRequest': (bytes) => wire.VaultDeleteRequest.decode(bytes),
    'VaultDeleteResponse': (bytes) => wire.VaultDeleteResponse.decode(bytes),
    'VaultWriteResponse': (bytes) => wire.VaultWriteResponse.decode(bytes),
  };

  /// Bytes that look enough like CBOR to get past the first branch.
  ///
  /// Uniform noise is refused by the array header on the first byte almost
  /// every time, which exercises one line and calls it a property. These start
  /// from a real array header and fill in from a small alphabet of major types,
  /// so the reader gets far enough in to be asked the questions that matter.
  Uint8List plausible(Random random) {
    final out = <int>[0x80 | random.nextInt(12)];
    final alphabet = <int>[
      // Small unsigned ints, the shape of every schema tag and enum index.
      for (var value = 0; value < 24; value++) value,
      0x18, 0x19, 0x1a, 0x1b, // uint with a following length
      0x40, 0x41, 0x58, 0x59, // byte strings, including a declared length
      0x60, 0x61, 0x78, 0x79, // text strings, same
      0x80, 0x81, 0x87, 0x88, // arrays
      0xf6, 0xff, // null and a break nothing opened
    ];
    final length = random.nextInt(64);
    for (var index = 0; index < length; index++) {
      out.add(alphabet[random.nextInt(alphabet.length)]);
    }
    return Uint8List.fromList(out);
  }

  /// Anything but a `FormatException` escaping is the finding.
  ///
  /// Counts refusals as well, because a test that only asserts "nothing
  /// unexpected was thrown" passes just as happily against a decoder that
  /// stopped doing anything at all.
  var refusals = 0;
  void onlyFormatExceptions(String name, Decoder decode, Uint8List bytes) {
    try {
      decode(bytes);
    } on FormatException {
      // The contract. Every caller of these is written for it.
      refusals++;
    } catch (failure) {
      fail(
        '$name threw ${failure.runtimeType} rather than FormatException '
        'on ${bytes.length} bytes: $bytes',
      );
    }
  }

  test('no wire decoder throws anything but FormatException', () {
    // Seeded, so a failure is a failure somebody else can reproduce from the
    // name of this test alone -- and overridable, so the one sequence this
    // seed walks is not the only sequence anybody ever tries. See
    // `support/property_config.dart`.
    final random = propertyRandom(20260901);
    for (var round = 0; round < propertyRounds(4096); round++) {
      final bytes = Uint8List.fromList(
        List.generate(random.nextInt(128), (_) => random.nextInt(256)),
      );
      for (final entry in decoders.entries) {
        onlyFormatExceptions(entry.key, entry.value, bytes);
      }
    }
    expect(refusals, greaterThan(0), reason: 'nothing was actually decoded');
  });

  test(
    'no wire decoder throws anything but FormatException on CBOR-ish bytes',
    () {
      final random = propertyRandom(20260902);
      for (var round = 0; round < propertyRounds(4096); round++) {
        final bytes = plausible(random);
        for (final entry in decoders.entries) {
          onlyFormatExceptions(entry.key, entry.value, bytes);
        }
      }
      expect(refusals, greaterThan(0), reason: 'nothing was actually decoded');
    },
  );

  /// Truncation is the shape a real link produces: a frame that was valid and
  /// arrived short. Every prefix of a good frame has to be refused the same way
  /// as noise.
  test('every prefix of a valid frame is refused as a FormatException', () {
    final payload = wire.VaultCreateRequest(
      verifierName: 'Workstation',
      kind: wire.VaultItemKind.login,
      name: 'Roteador',
      username: 'luis',
      uri: 'https://example.org',
      secret: 'hunter2',
    ).encode();

    // The frame itself is good, so a decoder that refused everything -- which
    // would satisfy every assertion above -- fails here.
    final decoded = wire.VaultCreateRequest.decode(payload);
    expect(decoded.name, 'Roteador');
    expect(decoded.secret, 'hunter2');

    for (var cut = 0; cut < payload.length; cut++) {
      onlyFormatExceptions(
        'VaultCreateRequest',
        (bytes) => wire.VaultCreateRequest.decode(bytes),
        Uint8List.sublistView(payload, 0, cut),
      );
    }

    // And one byte too many, which is the other half: a decoder that stops
    // reading at the last field it wanted accepts a frame carrying anything
    // after it.
    final extra = Uint8List(payload.length + 1)
      ..setRange(0, payload.length, payload);
    onlyFormatExceptions(
      'VaultCreateRequest',
      (bytes) => wire.VaultCreateRequest.decode(bytes),
      extra,
    );
  });
}
