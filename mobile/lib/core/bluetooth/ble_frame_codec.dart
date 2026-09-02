import 'dart:typed_data';

/// The chunk header is shared with `ble_framing.rs` on the desktop, and so are
/// the three bounds below. They are named here for the same reason they are
/// named there: two decoders that disagree about a limit disagree about which
/// frames exist.
class BleFrameCodec {
  BleFrameCodec({this.maxFrameBytes = 8192});

  static const headerBytes = 6;

  /// `MAX_CHUNKS` in `ble_framing.rs`.
  static const maxChunks = 1024;

  /// `MAX_PARTIAL_FRAMES` in `ble_framing.rs`.
  static const maxPartialFrames = 4;
  final int maxFrameBytes;
  int _nextFrameId = 0;
  final Map<int, _PartialFrame> _partialFrames = {};

  Iterable<Uint8List> encode(
    Uint8List frame, {
    required int attPayloadBytes,
  }) sync* {
    if (frame.isEmpty || frame.length > maxFrameBytes) {
      throw const FormatException('invalid BLE frame length');
    }
    final dataBytes = attPayloadBytes - headerBytes;
    if (dataBytes < 1) throw const FormatException('MTU BLE insuficiente');
    final total = (frame.length + dataBytes - 1) ~/ dataBytes;
    if (total > maxChunks) {
      throw const FormatException('Frame BLE muito fragmentado');
    }
    final frameId = _nextFrameId++ & 0xffff;

    for (var index = 0; index < total; index++) {
      final start = index * dataBytes;
      final end = (start + dataBytes).clamp(0, frame.length);
      final chunk = Uint8List(headerBytes + end - start);
      final header = ByteData.sublistView(chunk);
      header.setUint16(0, frameId);
      header.setUint16(2, index);
      header.setUint16(4, total);
      chunk.setRange(headerBytes, chunk.length, frame, start);
      yield chunk;
    }
  }

  Uint8List? addChunk(List<int> bytes) {
    if (bytes.length <= headerBytes) return null;
    final chunk = Uint8List.fromList(bytes);
    final header = ByteData.sublistView(chunk);
    final frameId = header.getUint16(0);
    final index = header.getUint16(2);
    final total = header.getUint16(4);
    if (total < 1 || total > maxChunks || index >= total) return null;

    // Refused, not evicted. `ble_framing.rs` answers a fifth concurrent frame
    // with an error and keeps the four it is already assembling; this dropped
    // one of those to make room, and chose `keys.first` — insertion order, so
    // the oldest, which in an exchange that is making progress is the one
    // closest to being finished.
    //
    // Nothing said so either. The evicted frame's chunks were gone, the peer
    // went on sending the rest of a frame that could never complete, and the
    // session waited out its idle timeout. Refusing costs the fifth frame,
    // which nothing legitimate sends: the desktop puts one frame at a time on
    // one characteristic.
    if (!_partialFrames.containsKey(frameId) &&
        _partialFrames.length >= maxPartialFrames) {
      return null;
    }
    final partial = _partialFrames.putIfAbsent(
      frameId,
      () => _PartialFrame(total),
    );
    if (partial.total != total || partial.chunks.containsKey(index)) {
      _partialFrames.remove(frameId);
      return null;
    }
    partial.chunks[index] = Uint8List.sublistView(chunk, headerBytes);
    partial.bytes += chunk.length - headerBytes;
    if (partial.bytes > maxFrameBytes) {
      _partialFrames.remove(frameId);
      return null;
    }
    if (partial.chunks.length != total) return null;

    final frame = Uint8List(partial.bytes);
    var offset = 0;
    for (var chunkIndex = 0; chunkIndex < total; chunkIndex++) {
      final part = partial.chunks[chunkIndex];
      if (part == null) {
        _partialFrames.remove(frameId);
        return null;
      }
      frame.setRange(offset, offset + part.length, part);
      offset += part.length;
    }
    _partialFrames.remove(frameId);
    return frame;
  }
}

class _PartialFrame {
  _PartialFrame(this.total);

  final int total;
  final Map<int, Uint8List> chunks = {};
  int bytes = 0;
}
