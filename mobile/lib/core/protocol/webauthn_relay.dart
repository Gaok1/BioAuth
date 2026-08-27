import 'dart:convert';
import 'dart:typed_data';

import 'package:phone_auth_native/phone_auth_native.dart';

const _magic = <int>[0x42, 0x41, 0x57, 0x41, 0x31, 0x0a]; // BAWA1\n

class WebAuthnRelayRequest {
  const WebAuthnRelayRequest({
    required this.requestId,
    required this.verifierId,
    required this.operation,
    required this.origin,
    required this.optionsJson,
  });

  final String requestId;
  final String verifierId;
  final String operation;
  final String origin;
  final String optionsJson;

  static bool recognizes(Uint8List frame) =>
      frame.length > _magic.length && _matchesMagic(frame);

  static bool _matchesMagic(Uint8List frame) {
    for (var index = 0; index < _magic.length; index++) {
      if (frame[index] != _magic[index]) return false;
    }
    return true;
  }

  factory WebAuthnRelayRequest.decode(
    Uint8List frame, {
    required String expectedVerifierId,
  }) {
    if (!recognizes(frame) || frame.length > 8192) {
      throw const FormatException('Invalid WebAuthn relay frame');
    }
    final value = jsonDecode(utf8.decode(frame.sublist(_magic.length)));
    if (value is! Map<String, dynamic> ||
        value['version'] != 1 ||
        value['type'] != 'webauthn.request') {
      throw const FormatException('Invalid WebAuthn relay envelope');
    }
    final requestId = value['requestId'];
    final verifierId = value['verifierId'];
    final operation = value['operation'];
    final origin = value['origin'];
    final options = value['options'];
    final uri = origin is String ? Uri.tryParse(origin) : null;
    if (requestId is! String ||
        requestId.length > 128 ||
        requestId.isEmpty ||
        verifierId != expectedVerifierId ||
        operation is! String ||
        !const {'create', 'get'}.contains(operation) ||
        uri == null ||
        uri.scheme != 'https' ||
        uri.host.isEmpty ||
        uri.userInfo.isNotEmpty ||
        options is! Map<String, dynamic>) {
      throw const FormatException('Rejected WebAuthn relay request');
    }
    final optionsJson = jsonEncode(options);
    if (optionsJson.length > 6000) {
      throw const FormatException('WebAuthn relay options are too large');
    }
    return WebAuthnRelayRequest(
      requestId: requestId,
      verifierId: verifierId,
      operation: operation,
      origin: origin,
      optionsJson: optionsJson,
    );
  }
}

class WebAuthnRelayHandler {
  const WebAuthnRelayHandler({
    PhoneAuthWebAuthnRelay native = const PhoneAuthWebAuthnRelay(),
  }) : _native = native;

  final PhoneAuthWebAuthnRelay _native;

  Future<Uint8List> perform(WebAuthnRelayRequest request) async {
    try {
      final response = jsonDecode(
        await _native.perform(
          operation: request.operation,
          origin: request.origin,
          optionsJson: request.optionsJson,
        ),
      );
      if (response is! Map<String, dynamic>) {
        throw const FormatException('Invalid passkey response');
      }
      return _encode({
        'version': 1,
        'type': 'webauthn.response',
        'requestId': request.requestId,
        'ok': true,
        'response': response,
      });
    } on Object {
      return _encode({
        'version': 1,
        'type': 'webauthn.response',
        'requestId': request.requestId,
        'ok': false,
        'error': 'Passkey operation was cancelled or rejected',
      });
    }
  }

  Uint8List _encode(Map<String, Object?> value) {
    final bytes = Uint8List.fromList([
      ..._magic,
      ...utf8.encode(jsonEncode(value)),
    ]);
    if (bytes.length > 8192) {
      throw const FormatException('WebAuthn relay response is too large');
    }
    return bytes;
  }
}
