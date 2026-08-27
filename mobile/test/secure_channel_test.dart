import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/core/session/key_schedule.dart';
import 'package:phone_auth/core/session/secure_channel.dart';

void main() {
  /// A connected pair, as a completed handshake would produce.
  Future<(SecureChannel, SecureChannel)> pair({int bindingByte = 0xab}) async {
    final schedule = await KeySchedule.derive(
      sharedSecret: SecretKeyData(Uint8List.fromList(List.filled(32, 5))),
      transcriptHash: Uint8List.fromList(List.filled(32, 6)),
    );
    final binding = Uint8List.fromList(List.filled(32, bindingByte));
    return (
      SecureChannel(role: Role.server, schedule: schedule, binding: binding),
      SecureChannel(role: Role.client, schedule: schedule, binding: binding),
    );
  }

  final request = Uint8List.fromList('request'.codeUnits);

  test('a pair talks in both directions', () async {
    final (server, client) = await pair();

    expect(await client.open(await server.seal(request)), request);
    expect(await server.open(await client.seal(Uint8List.fromList([9, 9]))), [
      9,
      9,
    ]);
  });

  test('the two ends agree on the binding', () async {
    final (server, client) = await pair();
    expect(server.sessionBinding, client.sessionBinding);
  });

  test('cleartext does not survive into the record', () async {
    final (server, _) = await pair();
    final secret = Uint8List.fromList('nixos-rebuild switch'.codeUnits);
    final record = await server.seal(secret);

    expect(
      String.fromCharCodes(record).contains('nixos-rebuild switch'),
      isFalse,
    );
  });

  test('tampering with any byte is rejected', () async {
    // Every byte, not a spot check: the counter prefix, the ciphertext and the
    // tag each have to be covered, and it is easy to authenticate only part of
    // a record by accident.
    final (server, client) = await pair();
    final record = await server.seal(request);

    for (var index = 0; index < record.length; index++) {
      for (var bit = 0; bit < 8; bit++) {
        final mutated = Uint8List.fromList(record);
        mutated[index] ^= 1 << bit;

        final (_, freshClient) = await pair();
        await expectLater(
          freshClient.open(mutated),
          throwsA(anything),
          reason: 'byte $index bit $bit was accepted after tampering',
        );
      }
    }
    // The untouched record still opens, so the loop was not merely rejecting
    // everything it was handed.
    expect(await client.open(record), request);
  });

  test('a replayed or skipped record is rejected', () async {
    final (server, client) = await pair();
    final first = await server.seal(Uint8List.fromList([1]));
    final second = await server.seal(Uint8List.fromList([2]));

    expect(await client.open(first), [1]);
    expect(await client.open(second), [2]);
    await expectLater(client.open(first), throwsA(isA<ChannelException>()));

    final (otherServer, otherClient) = await pair();
    final a = await otherServer.seal(Uint8List.fromList([1]));
    final b = await otherServer.seal(Uint8List.fromList([2]));
    await expectLater(
      otherClient.open(b),
      throwsA(isA<ChannelException>()),
      reason: 'skipping a record must be refused',
    );
    // The stream is still usable from where it actually is.
    expect(await otherClient.open(a), [1]);
    expect(await otherClient.open(b), [2]);
  });

  test('a channel cannot open what it sealed', () async {
    // Directions use different keys. A test that sealed and opened on one
    // channel would fail on the key mismatch before any tampering mattered.
    final (server, _) = await pair();
    await expectLater(
      server.open(await server.seal(request)),
      throwsA(anything),
    );
  });

  test('a record replayed into a different binding is rejected', () async {
    // Same keys, different binding: the binding is the associated data, so it
    // must break authentication on its own.
    final schedule = await KeySchedule.derive(
      sharedSecret: SecretKeyData(Uint8List.fromList(List.filled(32, 5))),
      transcriptHash: Uint8List.fromList(List.filled(32, 6)),
    );
    final server = SecureChannel(
      role: Role.server,
      schedule: schedule,
      binding: Uint8List.fromList(List.filled(32, 0xab)),
    );
    final client = SecureChannel(
      role: Role.client,
      schedule: schedule,
      binding: Uint8List.fromList(List.filled(32, 0xcd)),
    );

    await expectLater(
      client.open(await server.seal(request)),
      throwsA(anything),
    );
  });

  test('empty and oversized frames are refused', () async {
    final (server, _) = await pair();
    await expectLater(
      server.seal(Uint8List(0)),
      throwsA(isA<ChannelException>()),
    );
    await expectLater(
      server.seal(Uint8List(maxFrame + 1)),
      throwsA(isA<ChannelException>()),
    );
    expect(await server.seal(Uint8List(maxFrame)), isNotEmpty);
  });

  test('undersized records are refused before decryption', () async {
    final (_, client) = await pair();
    for (var length = 0; length <= 24; length++) {
      await expectLater(
        client.open(Uint8List(length)),
        throwsA(isA<ChannelException>()),
        reason: 'a $length-byte record must be refused on size',
      );
    }
  });
}
