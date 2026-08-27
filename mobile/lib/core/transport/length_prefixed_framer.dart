/// Length-prefixed framing over a byte stream.
///
/// TCP delivers a stream, not messages. Every frame the protocol defines has a
/// definite length, so a four-byte big-endian prefix recovers the boundaries —
/// and the explicit length is what lets a reader refuse an oversized frame
/// before allocating for it.
///
/// Mirrors `desktop/crates/phone-auth-agent/src/framing.rs`.
library;

import 'dart:typed_data';

/// Largest frame this will read. Covers a handshake hello, the biggest thing on
/// the wire.
const int maxFramedBytes = 8192;

const int _prefixBytes = 4;

class FramingException implements Exception {
  const FramingException(this.message);

  final String message;

  @override
  String toString() => 'FramingException: $message';
}

/// Prefixes a frame for the wire. One buffer, so a caller cannot put a length
/// on the wire with no body behind it.
Uint8List encodeFrame(List<int> frame) {
  if (frame.isEmpty || frame.length > maxFramedBytes) {
    throw FramingException('refusing to write a ${frame.length}-byte frame');
  }
  final buffer = Uint8List(_prefixBytes + frame.length);
  ByteData.sublistView(buffer).setUint32(0, frame.length, Endian.big);
  buffer.setRange(_prefixBytes, buffer.length, frame);
  return buffer;
}

/// Reassembles frames from arbitrary chunk boundaries.
class LengthPrefixedFramer {
  final BytesBuilder _pending = BytesBuilder(copy: true);

  /// Feeds one chunk and returns whichever frames completed.
  ///
  /// A chunk may carry half a frame, several frames, or a prefix split across
  /// two reads; all three happen on a real socket.
  List<Uint8List> addChunk(List<int> chunk) {
    _pending.add(chunk);
    final frames = <Uint8List>[];
    var buffer = _pending.takeBytes();
    var offset = 0;

    while (buffer.length - offset >= _prefixBytes) {
      final length = ByteData.sublistView(
        buffer,
        offset,
        offset + _prefixBytes,
      ).getUint32(0, Endian.big);
      // Checked before allocating: a peer that claims four gigabytes must not
      // be able to make this process ask for them.
      if (length == 0 || length > maxFramedBytes) {
        throw FramingException('peer announced a $length-byte frame');
      }
      final end = offset + _prefixBytes + length;
      if (end > buffer.length) break;
      frames.add(
        Uint8List.fromList(
          Uint8List.sublistView(buffer, offset + _prefixBytes, end),
        ),
      );
      offset = end;
    }

    if (offset < buffer.length) {
      _pending.add(Uint8List.sublistView(buffer, offset));
    }
    return frames;
  }

  /// True when a partial frame is still buffered, which on a closed connection
  /// means the peer went away mid-frame.
  bool get hasPartialFrame => _pending.length > 0;
}
