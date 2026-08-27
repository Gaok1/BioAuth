/// The record layer: ChaCha20-Poly1305 over an established handshake.
///
/// Mirrors `desktop/crates/phone-auth-session/src/channel.rs`.
library;

import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'key_schedule.dart';

/// Largest cleartext frame a record may carry.
const int maxFrame = 8192;

/// Bytes a record adds on top of its cleartext: an 8-byte counter and the
/// Poly1305 tag.
const int _recordOverhead = 8 + 16;

class ChannelException implements Exception {
  const ChannelException(this.message);

  final String message;

  @override
  String toString() => 'ChannelException: $message';
}

/// Which end of the handshake a channel belongs to.
///
/// The two ends use opposite keys for opposite directions. Selecting them from
/// this rather than by slicing the schedule by hand is what stops one side from
/// being built with the other's keys.
enum Role {
  /// The verifier: the desktop that published the bootstrap.
  server,

  /// The authenticator: the phone that scanned it.
  client,
}

class SecureChannel {
  SecureChannel({
    required Role role,
    required KeySchedule schedule,
    required Uint8List binding,
  }) : _sendKey = SecretKeyData(
         role == Role.server
             ? schedule.serverToClient
             : schedule.clientToServer,
       ),
       _receiveKey = SecretKeyData(
         role == Role.server
             ? schedule.clientToServer
             : schedule.serverToClient,
       ),
       _binding = Uint8List.fromList(binding);

  final SecretKey _sendKey;
  final SecretKey _receiveKey;
  final Uint8List _binding;
  final Cipher _cipher = Chacha20.poly1305Aead();

  int _sendCounter = 0;
  int _receiveCounter = 0;

  /// The session binding to put inside the signed authorization request.
  Uint8List get sessionBinding => Uint8List.fromList(_binding);

  /// Encrypts one frame.
  ///
  /// The binding is authenticated as associated data, so a record cannot be
  /// lifted into a different session even by someone holding its keys.
  Future<Uint8List> seal(List<int> cleartext) async {
    if (cleartext.isEmpty || cleartext.length > maxFrame) {
      throw const ChannelException('invalid cleartext frame size');
    }
    final counter = _sendCounter;
    final box = await _cipher.encrypt(
      cleartext,
      secretKey: _sendKey,
      nonce: _nonce(counter),
      aad: _binding,
    );
    // Refuse to wrap rather than reuse a nonce. Unreachable at one record per
    // authorization; a bug that reset the counter is not, and reuse would leak
    // the keystream.
    if (counter == _maxCounter) {
      throw const ChannelException('record counter exhausted');
    }
    _sendCounter = counter + 1;

    return (BytesBuilder(copy: false)
          ..add(_counterBytes(counter))
          ..add(box.cipherText)
          ..add(box.mac.bytes))
        .takeBytes();
  }

  /// Decrypts one frame.
  ///
  /// Records must arrive in order. The transports below this are reliable and
  /// ordered, so a gap means loss or tampering, and a tolerance window would
  /// only widen what an attacker can replay.
  Future<Uint8List> open(Uint8List record) async {
    if (record.length <= _recordOverhead ||
        record.length > maxFrame + _recordOverhead) {
      throw const ChannelException('invalid encrypted record size');
    }
    final counter = ByteData.sublistView(record, 0, 8).getUint64(0, Endian.big);
    if (counter != _receiveCounter) {
      throw const ChannelException('replayed or out-of-order record');
    }
    final clear = await _cipher.decrypt(
      SecretBox(
        Uint8List.sublistView(record, 8, record.length - 16),
        nonce: _nonce(counter),
        mac: Mac(Uint8List.sublistView(record, record.length - 16)),
      ),
      secretKey: _receiveKey,
      aad: _binding,
    );
    if (counter == _maxCounter) {
      throw const ChannelException('record counter exhausted');
    }
    _receiveCounter = counter + 1;
    return Uint8List.fromList(clear);
  }

  /// Dart integers are signed 64-bit, so the counter stops one short of where
  /// the desktop's `u64` would.
  static const int _maxCounter = 0x7fffffffffffffff;
}

/// Builds a 96-bit nonce from the record counter: `0x00000000 ‖ u64be(counter)`.
Uint8List _nonce(int counter) {
  final nonce = Uint8List(12);
  ByteData.sublistView(nonce).setUint64(4, counter, Endian.big);
  return nonce;
}

Uint8List _counterBytes(int counter) {
  final bytes = Uint8List(8);
  ByteData.sublistView(bytes).setUint64(0, counter, Endian.big);
  return bytes;
}
