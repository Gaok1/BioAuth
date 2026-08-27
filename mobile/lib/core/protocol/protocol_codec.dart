import 'dart:typed_data';

import 'package:cbor/simple.dart';

import '../../domain/authentication_request.dart';
import 'auth_response.dart';

class PhoneAuthProtocolCodec {
  const PhoneAuthProtocolCodec();

  static const _codec = CborSimpleCodec(parseDateTime: false);
  static const _requestType = 1;
  static const _responseType = 2;
  static const _maxFrameBytes = 8192;

  Uint8List encodeRequest(AuthenticationRequest request) => Uint8List.fromList(
    _codec.encode([
      _requestType,
      request.protocolVersion,
      request.requestId,
      request.verifierId,
      request.verifierName,
      request.credentialId,
      request.challenge,
      request.service,
      request.action,
      request.resource,
      request.user,
      request.issuedAt.millisecondsSinceEpoch,
      request.expiresAt.millisecondsSinceEpoch,
      request.sessionBinding,
    ]),
  );

  AuthenticationRequest decodeRequest(
    Uint8List frame, {
    required String origin,
  }) {
    final values = _decodeList(frame, expectedLength: 14);
    if (_int(values, 0) != _requestType) {
      throw const FormatException('Tipo de mensagem inesperado');
    }
    final request = AuthenticationRequest(
      protocolVersion: _int(values, 1),
      requestId: _string(values, 2),
      verifierId: _string(values, 3),
      verifierName: _string(values, 4),
      credentialId: _string(values, 5),
      challenge: _bytes(values, 6),
      origin: origin,
      service: _string(values, 7),
      action: _string(values, 8),
      resource: _string(values, 9),
      user: _string(values, 10),
      issuedAt: DateTime.fromMillisecondsSinceEpoch(
        _int(values, 11),
        isUtc: true,
      ),
      expiresAt: DateTime.fromMillisecondsSinceEpoch(
        _int(values, 12),
        isUtc: true,
      ),
      sessionBinding: _bytes(values, 13),
    );
    if (!_bytesEqual(frame, encodeRequest(request))) {
      throw const FormatException('CBOR não canônico');
    }
    return request;
  }

  Uint8List encodeResponse(AuthResponse response) => Uint8List.fromList(
    _codec.encode([
      _responseType,
      response.protocolVersion,
      response.requestId,
      response.verifierId,
      response.credentialId,
      response.decision.index,
      response.algorithm,
      response.signature,
    ]),
  );

  AuthResponse decodeResponse(Uint8List frame) {
    final values = _decodeList(frame, expectedLength: 8);
    if (_int(values, 0) != _responseType) {
      throw const FormatException('Tipo de mensagem inesperado');
    }
    final decisionIndex = _int(values, 5);
    if (decisionIndex < 0 ||
        decisionIndex >= AuthorizationDecision.values.length) {
      throw const FormatException('Decisão inválida');
    }
    final response = AuthResponse(
      protocolVersion: _int(values, 1),
      requestId: _string(values, 2),
      verifierId: _string(values, 3),
      credentialId: _string(values, 4),
      decision: AuthorizationDecision.values[decisionIndex],
      algorithm: _string(values, 6, allowEmpty: true),
      signature: _bytes(values, 7),
    );
    if (!_bytesEqual(frame, encodeResponse(response))) {
      throw const FormatException('CBOR não canônico');
    }
    return response;
  }

  List<Object?> _decodeList(Uint8List frame, {required int expectedLength}) {
    if (frame.isEmpty || frame.length > _maxFrameBytes) {
      throw const FormatException('Tamanho de frame inválido');
    }
    final decoded = _codec.decode(frame);
    if (decoded is! List<Object?> || decoded.length != expectedLength) {
      throw const FormatException('Estrutura CBOR inválida');
    }
    return decoded;
  }

  int _int(List<Object?> values, int index) {
    final value = values[index];
    if (value is! int) throw const FormatException('Inteiro esperado');
    return value;
  }

  String _string(List<Object?> values, int index, {bool allowEmpty = false}) {
    final value = values[index];
    if (value is! String || (!allowEmpty && value.isEmpty)) {
      throw const FormatException('Texto esperado');
    }
    return value;
  }

  Uint8List _bytes(List<Object?> values, int index) {
    final value = values[index];
    if (value is Uint8List) return Uint8List.fromList(value);
    if (value is List<int>) return Uint8List.fromList(value);
    throw const FormatException('Bytes esperados');
  }

  bool _bytesEqual(List<int> left, List<int> right) {
    if (left.length != right.length) return false;
    for (var index = 0; index < left.length; index++) {
      if (left[index] != right[index]) return false;
    }
    return true;
  }
}
