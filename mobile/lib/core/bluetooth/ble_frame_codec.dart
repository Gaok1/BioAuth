import 'dart:typed_data';

class BleFrameCodec {
  BleFrameCodec({this.maxFrameBytes = 8192});

  static const headerBytes = 6;
  final int maxFrameBytes;
  int _nextFrameId = 0;
  final Map<int, _PartialFrame> _partialFrames = {};

  Iterable<Uint8List> encode(
    Uint8List frame, {
    required int attPayloadBytes,
  }) sync* {
    if (frame.isEmpty || frame.length > maxFrameBytes) {
      throw const FormatException('Tamanho de frame BLE inválido');
    }
    final dataBytes = attPayloadBytes - headerBytes;
    if (dataBytes < 1) throw const FormatException('MTU BLE insuficiente');
    final total = (frame.length + dataBytes - 1) ~/ dataBytes;
    if (total > 1024) {
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
    if (total < 1 || total > 1024 || index >= total) return null;

    if (!_partialFrames.containsKey(frameId) && _partialFrames.length >= 4) {
      _partialFrames.remove(_partialFrames.keys.first);
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
