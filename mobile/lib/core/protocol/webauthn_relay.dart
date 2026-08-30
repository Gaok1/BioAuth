import 'dart:convert';

import 'package:flutter/services.dart';
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
        requestId.length > 64 ||
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

/// What the desktop is told, per reason the phone had for refusing.
///
/// Every refusal used to arrive in the browser as the same sentence: that the
/// operation was cancelled or rejected. Only one of them is that. The phone
/// also refuses before it shows anything at all -- when desktop passkey
/// notifications are off there is no prompt to cancel, and telling the person
/// they cancelled sends them to look at the phone's biometrics, which is the
/// one part that was working. A reason the phone knew exactly was thrown away
/// at the last step and replaced with a wrong one.
///
/// Keyed by code and closed, rather than forwarding the native message: those
/// strings are written for this app's own log, one of them carries a parser's
/// words about the request, and none of them were written to be read by a
/// stranger's website. A code not named here keeps the old sentence, which is
/// where `webauthn_cancelled` belongs anyway.
const _refusals = <String, String>{
  'background_sessions_unavailable':
      'Turn on desktop passkey notifications in the PhoneAuth app',
  'operation_in_progress': 'The phone is already handling another passkey',
  'invalid_arguments': 'The phone rejected this request as malformed',
  'webauthn_failed': 'The passkey operation failed on the phone',
};

class WebAuthnRelayHandler {
  const WebAuthnRelayHandler({
    PhoneAuthWebAuthnRelay native = const PhoneAuthWebAuthnRelay(),
  }) : _native = native;

  final PhoneAuthWebAuthnRelay _native;

  Future<Uint8List> perform(WebAuthnRelayRequest request) async {
    try {
      final response = jsonDecode(
        await _native.perform(
          requestId: request.requestId,
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
    } on PlatformException catch (error) {
      return _refused(request.requestId, _refusals[error.code]);
    } on Object {
      return _refused(request.requestId, null);
    }
  }

  Uint8List _refused(String requestId, String? reason) => _encode({
    'version': 1,
    'type': 'webauthn.response',
    'requestId': requestId,
    'ok': false,
    'error': reason ?? 'Passkey operation was cancelled or rejected',
  });

  Future<void> cancel(String requestId) => _native.cancel(requestId);

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

class WebAuthnRelayCancel {
  const WebAuthnRelayCancel(this.requestId);

  final String requestId;

  factory WebAuthnRelayCancel.decode(Uint8List frame) {
    if (!WebAuthnRelayRequest.recognizes(frame) || frame.length > 8192) {
      throw const FormatException('Invalid WebAuthn cancellation frame');
    }
    final value = jsonDecode(utf8.decode(frame.sublist(_magic.length)));
    if (value is! Map<String, dynamic> ||
        value['version'] != 1 ||
        value['type'] != 'webauthn.cancel' ||
        value['requestId'] is! String ||
        (value['requestId'] as String).isEmpty ||
        (value['requestId'] as String).length > 64) {
      throw const FormatException('Rejected WebAuthn cancellation frame');
    }
    return WebAuthnRelayCancel(value['requestId'] as String);
  }
}
