/// Canonical CBOR primitives for PhoneAuth frames.
///
/// A direct mirror of `desktop/crates/phone-auth-protocol/src/cbor.rs`. Only
/// the subset the protocol uses exists here: definite-length arrays, integers,
/// text strings and byte strings. Maps are absent on purpose — every frame is a
/// fixed-order array, so no key ordering can differ between the two sides.
///
/// The reader is strict. A head whose argument is not in the shortest possible
/// form is rejected rather than normalised: two encodings of the same value
/// would otherwise both parse while only one matches the bytes that were
/// signed.
///
/// Written by hand rather than taken from `package:cbor` because the signatures
/// in this protocol cover exact bytes. A general-purpose encoder that is
/// canonical today is a silent break the day it is not.
library;

import 'dart:convert';
import 'dart:typed_data';

const int _majorUint = 0;
const int _majorNegInt = 1;
const int _majorBytes = 2;
const int _majorText = 3;
const int _majorArray = 4;

class CborException implements Exception {
  const CborException(this.message);

  final String message;

  @override
  String toString() => 'CborException: $message';
}

/// Appends canonical CBOR items to a growing buffer.
class CborWriter {
  final BytesBuilder _buffer = BytesBuilder(copy: false);

  Uint8List takeBytes() => _buffer.takeBytes();

  void array(int length) => _head(_majorArray, length);

  void uint(int value) {
    if (value < 0) throw const CborException('negative value written as uint');
    _head(_majorUint, value);
  }

  /// Writes a signed integer. Negative values use major type 1, whose argument
  /// encodes `-1 - value`.
  void int64(int value) {
    if (value < 0) {
      _head(_majorNegInt, -1 - value);
    } else {
      _head(_majorUint, value);
    }
  }

  void text(String value) {
    final encoded = utf8.encode(value);
    _head(_majorText, encoded.length);
    _buffer.add(encoded);
  }

  void bytes(List<int> value) {
    _head(_majorBytes, value.length);
    _buffer.add(value);
  }

  /// Writes a major type with its argument in the shortest form that fits.
  void _head(int major, int argument) {
    final prefix = major << 5;
    if (argument < 24) {
      _buffer.addByte(prefix | argument);
    } else if (argument <= 0xff) {
      _buffer
        ..addByte(prefix | 24)
        ..addByte(argument);
    } else if (argument <= 0xffff) {
      final head = Uint8List(3)..[0] = prefix | 25;
      ByteData.sublistView(head).setUint16(1, argument, Endian.big);
      _buffer.add(head);
    } else if (argument <= 0xffffffff) {
      final head = Uint8List(5)..[0] = prefix | 26;
      ByteData.sublistView(head).setUint32(1, argument, Endian.big);
      _buffer.add(head);
    } else {
      final head = Uint8List(9)..[0] = prefix | 27;
      ByteData.sublistView(head).setUint64(1, argument, Endian.big);
      _buffer.add(head);
    }
  }
}

/// Reads canonical CBOR items, rejecting anything outside the subset.
class CborReader {
  CborReader(this._buffer);

  final Uint8List _buffer;
  int _position = 0;

  int array() => _expect(_majorArray);

  int uint() => _expect(_majorUint);

  /// Reads a signed integer from either integer major type.
  int int64() {
    final (major, argument) = _head();
    if (major == _majorUint) return argument;
    if (major == _majorNegInt) return -1 - argument;
    throw const CborException('unexpected CBOR major type');
  }

  String text() {
    final length = _expect(_majorText);
    try {
      return const Utf8Decoder(allowMalformed: false).convert(_take(length));
    } on FormatException {
      throw const CborException('CBOR text string is not valid UTF-8');
    }
  }

  Uint8List bytes() => Uint8List.fromList(_take(_expect(_majorBytes)));

  /// Fails unless every byte of the input has been consumed.
  void finish() {
    if (_position != _buffer.length) {
      throw const CborException('trailing bytes after CBOR item');
    }
  }

  Uint8List _take(int length) {
    final end = _position + length;
    if (length < 0 || end > _buffer.length) {
      throw const CborException('truncated CBOR item');
    }
    final slice = Uint8List.sublistView(_buffer, _position, end);
    _position = end;
    return slice;
  }

  int _expect(int major) {
    final (actual, argument) = _head();
    if (actual != major) {
      throw const CborException('unexpected CBOR major type');
    }
    return argument;
  }

  /// Reads one head, rejecting non-shortest arguments and every item shape the
  /// protocol does not use.
  (int, int) _head() {
    final initial = _take(1)[0];
    final major = initial >> 5;
    final additional = initial & 0x1f;
    if (additional < 24) return (major, additional);

    final int argument;
    switch (additional) {
      case 24:
        argument = _take(1)[0];
        if (argument < 24) throw const CborException(_nonCanonical);
      case 25:
        argument = ByteData.sublistView(_take(2)).getUint16(0, Endian.big);
        if (argument <= 0xff) throw const CborException(_nonCanonical);
      case 26:
        argument = ByteData.sublistView(_take(4)).getUint32(0, Endian.big);
        if (argument <= 0xffff) throw const CborException(_nonCanonical);
      case 27:
        argument = ByteData.sublistView(_take(8)).getUint64(0, Endian.big);
        // Dart integers are signed; an argument with the top bit set reads back
        // negative and nothing in this protocol legitimately reaches it.
        if (argument < 0) throw const CborException('CBOR value out of range');
        if (argument <= 0xffffffff) throw const CborException(_nonCanonical);
      // 28..30 are reserved; 31 is an indefinite length.
      default:
        throw const CborException('unsupported CBOR item');
    }
    return (major, argument);
  }

  static const _nonCanonical = 'non-canonical integer encoding';
}
