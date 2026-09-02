import 'dart:typed_data';

import '../../domain/authentication_request.dart';
import 'auth_response.dart';
import 'cbor.dart';

/// Encodes and decodes the authorization request and response frames.
///
/// The encoded request is also the exact byte string the biometric key signs,
/// so the encoding is canonical by construction rather than by convention —
/// see `cbor.dart`. Mirrors `phone-auth-protocol/src/{request,response}.rs`.
class PhoneAuthProtocolCodec {
  const PhoneAuthProtocolCodec();

  static const _requestType = 1;
  static const _responseType = 2;
  static const _requestFrameLength = 14;
  static const _responseFrameLength = 8;
  static const _maxFrameBytes = 8192;

  Uint8List encodeRequest(AuthenticationRequest request) {
    final writer = CborWriter()
      ..array(_requestFrameLength)
      ..uint(_requestType)
      ..uint(request.protocolVersion)
      ..text(request.requestId)
      ..text(request.verifierId)
      ..text(request.verifierName)
      ..text(request.credentialId)
      ..bytes(request.challenge)
      ..text(request.service)
      ..text(request.action)
      ..text(request.resource)
      ..text(request.user)
      ..int64(request.issuedAt.millisecondsSinceEpoch)
      ..int64(request.expiresAt.millisecondsSinceEpoch)
      ..bytes(request.sessionBinding);
    return writer.takeBytes();
  }

  AuthenticationRequest decodeRequest(
    Uint8List frame, {
    required String origin,
  }) => _decode(frame, _requestFrameLength, (reader) {
    if (reader.uint() != _requestType) {
      throw const FormatException('Tipo de mensagem inesperado');
    }
    return AuthenticationRequest(
      protocolVersion: reader.uint(),
      requestId: _text(reader),
      verifierId: _text(reader),
      verifierName: _text(reader),
      credentialId: _text(reader),
      challenge: reader.bytes(),
      // Not on the wire: origin is a property of the session the frame arrived
      // on, is not signed, and must never be treated as identity.
      origin: origin,
      service: _text(reader),
      action: _text(reader),
      resource: _text(reader),
      user: _text(reader),
      issuedAt: DateTime.fromMillisecondsSinceEpoch(
        reader.int64(),
        isUtc: true,
      ),
      expiresAt: DateTime.fromMillisecondsSinceEpoch(
        reader.int64(),
        isUtc: true,
      ),
      sessionBinding: reader.bytes(),
    );
  });

  Uint8List encodeResponse(AuthResponse response) {
    final writer = CborWriter()
      ..array(_responseFrameLength)
      ..uint(_responseType)
      ..uint(response.protocolVersion)
      ..text(response.requestId)
      ..text(response.verifierId)
      ..text(response.credentialId)
      ..uint(response.decision.index)
      ..text(response.algorithm)
      ..bytes(response.signature);
    return writer.takeBytes();
  }

  AuthResponse decodeResponse(Uint8List frame) =>
      _decode(frame, _responseFrameLength, (reader) {
        if (reader.uint() != _responseType) {
          throw const FormatException('Tipo de mensagem inesperado');
        }
        final protocolVersion = reader.uint();
        final requestId = _text(reader);
        final verifierId = _text(reader);
        final credentialId = _text(reader);
        final decisionIndex = reader.uint();
        if (decisionIndex >= AuthorizationDecision.values.length) {
          throw const FormatException('invalid decision');
        }
        return AuthResponse(
          protocolVersion: protocolVersion,
          requestId: requestId,
          verifierId: verifierId,
          credentialId: credentialId,
          decision: AuthorizationDecision.values[decisionIndex],
          algorithm: reader.text(),
          signature: reader.bytes(),
        );
      });

  /// Reads one frame, surfacing every malformed-input failure as a
  /// [FormatException] so callers have one thing to catch.
  T _decode<T>(
    Uint8List frame,
    int expectedLength,
    T Function(CborReader reader) build,
  ) {
    if (frame.isEmpty || frame.length > _maxFrameBytes) {
      throw const FormatException('invalid frame length');
    }
    try {
      final reader = CborReader(frame);
      if (reader.array() != expectedLength) {
        throw const FormatException('invalid CBOR structure');
      }
      final decoded = build(reader);
      // Trailing bytes would mean the frame carried more than it declared.
      reader.finish();
      return decoded;
    } on CborException catch (error) {
      throw FormatException(error.message);
    }
  }

  String _text(CborReader reader) {
    final value = reader.text();
    if (value.isEmpty) throw const FormatException('Texto esperado');
    return value;
  }
}
