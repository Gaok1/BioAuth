import 'dart:typed_data';

import 'cbor.dart';

const int maxApplicationPayloadBytes = 6 * 1024;

enum ApplicationFrameKind { request, response, cancel, error }

/// Versioned `vault.*`/`locker.*` envelope inside the secure channel.
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

  void validate() {
    if (protocolVersion != 1) {
      throw const FormatException('Versão de frame não suportada');
    }
    if (requestId.trim().isEmpty || requestId.length > 64) {
      throw const FormatException('requestId inválido');
    }
    if (!_validOperation(operation)) {
      throw const FormatException('Operação de aplicação inválida');
    }
    if (sessionBinding.length != 32) {
      throw const FormatException('Session binding inválido');
    }
    if (payload.length > maxApplicationPayloadBytes) {
      throw const FormatException('Payload de aplicação grande demais');
    }
    final validity =
        expiresAt.millisecondsSinceEpoch - issuedAt.millisecondsSinceEpoch;
    if (validity <= 0 || validity > _maxValidityMs) {
      throw const FormatException('Validade de frame inválida');
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
      throw const FormatException('Tamanho de frame inválido');
    }
    try {
      final reader = CborReader(frame);
      if (reader.array() != _frameLength || reader.uint() != _messageType) {
        throw const FormatException('Estrutura de frame inesperada');
      }
      final version = reader.uint();
      final kindIndex = reader.uint();
      if (kindIndex >= ApplicationFrameKind.values.length) {
        throw const FormatException('Tipo de frame inválido');
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
        throw const FormatException('Frame CBOR não canônico');
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
