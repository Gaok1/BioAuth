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

/// Refusals whose native wording is not fit to be read by the person.
///
/// Only these two. `background_sessions_unavailable` says "notification
/// permission is required", which is a fact about Android and not an
/// instruction anyone can act on; what a person needs is the setting to go
/// turn on. Everything else the phone says about a refusal was written to be
/// read -- "the passkey is no longer available", "the browser origin is not
/// authorized for this relying party", "biometric verification did not
/// complete" -- and passes through with the code that carried it.
///
/// It did not, at first. A closed table with a catch-all beneath it looked
/// careful and was not: the sentence underneath claimed the operation was
/// cancelled or rejected, which for anything the table did not name was a
/// guess, and usually a wrong one. It hid a message this same relay had just
/// written, and cost a round trip with a person at a keyboard to find out
/// what the phone had said all along.
const _refusals = <String, String>{
  'background_sessions_unavailable':
      'Turn on desktop passkey notifications in the PhoneAuth app',
  'operation_in_progress': 'The phone is already handling another passkey',
};

/// The phone's own words, bounded, with the code that carried them.
///
/// Bounded because this ends up in a DOMException on a website and none of
/// these are long. The code is always one of a handful of fixed identifiers
/// the plugin writes itself, so it names the path without describing the
/// request.
String _reported(PlatformException error) {
  final detail = error.message?.trim() ?? '';
  final bounded = detail.length > 120 ? detail.substring(0, 120) : detail;
  return bounded.isEmpty
      ? 'The phone refused the passkey (${error.code})'
      : '$bounded (${error.code})';
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
      return _refused(
        request.requestId,
        _refusals[error.code] ?? _reported(error),
      );
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
