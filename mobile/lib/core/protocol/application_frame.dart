import 'dart:typed_data';

import 'cbor.dart';

const int maxApplicationPayloadBytes = 6 * 1024;

enum ApplicationFrameKind { request, response, cancel, error }

/// Missing items and stale revisions are deliberately the same [rejected]
/// value, so an unauthorized peer cannot probe whether an item exists.
enum ApplicationErrorCode {
  rejected,
  invalidRequest,
  unavailable;

  Uint8List encode() =>
      (CborWriter()
            ..array(2)
            ..uint(1)
            ..uint(index))
          .takeBytes();

  static ApplicationErrorCode decode(Uint8List payload) {
    try {
      final reader = CborReader(payload);
      if (reader.array() != 2 || reader.uint() != 1) {
        throw const FormatException('invalid application error');
      }
      final value = reader.uint();
      if (value >= values.length) {
        throw const FormatException('invalid application error');
      }
      reader.finish();
      final decoded = values[value];
      if (!_sameBytes(payload, decoded.encode())) {
        throw const FormatException('non-canonical application error');
      }
      return decoded;
    } on CborException catch (error) {
      throw FormatException(error.message);
    }
  }

  static bool _sameBytes(List<int> left, List<int> right) {
    if (left.length != right.length) return false;
    for (var index = 0; index < left.length; index++) {
      if (left[index] != right[index]) return false;
    }
    return true;
  }
}

/// Versioned `vault.*`/`locker.*`/`ssh.*` envelope inside the secure channel.
///
/// It is deliberately separate from the biometric-signed authorization frame.
/// Do not add a `toString` that could place [payload] in logs.
class ApplicationFrame {
  ApplicationFrame({
    required this.protocolVersion,
    required this.kind,
    required this.requestId,
    required List<int> sessionBinding,
    required this.operation,
    required this.issuedAt,
    required this.expiresAt,
    required List<int> payload,
  }) : sessionBinding = Uint8List.fromList(sessionBinding),
       payload = Uint8List.fromList(payload);

  static const _messageType = 4;
  static const _frameLength = 9;
  static const _maxFrameBytes = 8192;
  static const _maxValidityMs = 120000;

  final int protocolVersion;
  final ApplicationFrameKind kind;
  final String requestId;
  final Uint8List sessionBinding;
  final String operation;
  final DateTime issuedAt;
  final DateTime expiresAt;
  final Uint8List payload;

  static bool recognizes(Uint8List frame) =>
      frame.length >= 2 && frame[0] == 0x89 && frame[1] == _messageType;

  void validate() {
    if (protocolVersion != 1) {
      throw const FormatException('unsupported frame version');
    }
    if (requestId.trim().isEmpty || requestId.length > 64) {
      throw const FormatException('invalid requestId');
    }
    if (!_validOperation(operation)) {
      throw const FormatException('invalid application operation');
    }
    if (sessionBinding.length != 32) {
      throw const FormatException('invalid session binding');
    }
    if (payload.length > maxApplicationPayloadBytes) {
      throw const FormatException('application payload too large');
    }
    final validity =
        expiresAt.millisecondsSinceEpoch - issuedAt.millisecondsSinceEpoch;
    if (validity <= 0 || validity > _maxValidityMs) {
      throw const FormatException('invalid frame validity');
    }
  }

  bool isExpiredAt(DateTime now) => !now.toUtc().isBefore(expiresAt.toUtc());

  bool isReplyTo(ApplicationFrame request, DateTime now) =>
      request.kind == ApplicationFrameKind.request &&
      (kind == ApplicationFrameKind.response ||
          kind == ApplicationFrameKind.error) &&
      requestId == request.requestId &&
      _bytesEqual(sessionBinding, request.sessionBinding) &&
      operation == request.operation &&
      issuedAt.millisecondsSinceEpoch ==
          request.issuedAt.millisecondsSinceEpoch &&
      expiresAt.millisecondsSinceEpoch ==
          request.expiresAt.millisecondsSinceEpoch &&
      !isExpiredAt(now);

  Uint8List encode() {
    validate();
    final writer = CborWriter()
      ..array(_frameLength)
      ..uint(_messageType)
      ..uint(protocolVersion)
      ..uint(kind.index)
      ..text(requestId)
      ..bytes(sessionBinding)
      ..text(operation)
      ..int64(issuedAt.millisecondsSinceEpoch)
      ..int64(expiresAt.millisecondsSinceEpoch)
      ..bytes(payload);
    return writer.takeBytes();
  }

  static ApplicationFrame decode(Uint8List frame) {
    if (frame.isEmpty || frame.length > _maxFrameBytes) {
      throw const FormatException('invalid frame length');
    }
    try {
      final reader = CborReader(frame);
      if (reader.array() != _frameLength || reader.uint() != _messageType) {
        throw const FormatException('Estrutura de frame inesperada');
      }
      final version = reader.uint();
      final kindIndex = reader.uint();
      if (kindIndex >= ApplicationFrameKind.values.length) {
        throw const FormatException('invalid frame type');
      }
      final decoded = ApplicationFrame(
        protocolVersion: version,
        kind: ApplicationFrameKind.values[kindIndex],
        requestId: reader.text(),
        sessionBinding: reader.bytes(),
        operation: reader.text(),
        issuedAt: DateTime.fromMillisecondsSinceEpoch(
          reader.int64(),
          isUtc: true,
        ),
        expiresAt: DateTime.fromMillisecondsSinceEpoch(
          reader.int64(),
          isUtc: true,
        ),
        payload: reader.bytes(),
      );
      reader.finish();
      decoded.validate();
      if (!_bytesEqual(frame, decoded.encode())) {
        throw const FormatException('non-canonical CBOR frame');
      }
      return decoded;
    } on CborException catch (error) {
      throw FormatException(error.message);
    }
  }

  static bool _validOperation(String value) {
    final String suffix;
    if (value.startsWith('vault.')) {
      suffix = value.substring(6);
    } else if (value.startsWith('locker.')) {
      suffix = value.substring(7);
    } else if (value.startsWith('luks.')) {
      suffix = value.substring(5);
    } else if (value.startsWith('ssh.')) {
      suffix = value.substring(4);
    } else if (value.startsWith('permissions.')) {
      suffix = value.substring(12);
    } else {
      return false;
    }
    return suffix.isNotEmpty &&
        value.length <= 64 &&
        !suffix.contains('..') &&
        suffix.codeUnits.every(
          (unit) =>
              (unit >= 0x61 && unit <= 0x7a) ||
              (unit >= 0x30 && unit <= 0x39) ||
              unit == 0x2e ||
              unit == 0x2d,
        );
  }

  static bool _bytesEqual(List<int> left, List<int> right) {
    if (left.length != right.length) return false;
    for (var index = 0; index < left.length; index++) {
      if (left[index] != right[index]) return false;
    }
    return true;
  }
}
