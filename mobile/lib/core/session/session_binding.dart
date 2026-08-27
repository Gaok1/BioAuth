import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

const _domain = 'PhoneAuth/session-binding/v1';

class SessionBindingInputs {
  SessionBindingInputs({
    required this.transportName,
    required this.sessionId,
    required Uint8List verifierHandshakeKey,
    required Uint8List peerHandshakeKey,
    required Uint8List transcriptSecret,
  }) : verifierHandshakeKey = Uint8List.fromList(verifierHandshakeKey),
       peerHandshakeKey = Uint8List.fromList(peerHandshakeKey),
       transcriptSecret = Uint8List.fromList(transcriptSecret) {
    if (transportName.isEmpty || sessionId.isEmpty) {
      throw ArgumentError('Transport and session identifiers must be present');
    }
    if (verifierHandshakeKey.isEmpty ||
        peerHandshakeKey.isEmpty ||
        transcriptSecret.length < 32) {
      throw ArgumentError('Handshake keys and a 32-byte secret are required');
    }
  }

  final String transportName;
  final String sessionId;
  final Uint8List verifierHandshakeKey;
  final Uint8List peerHandshakeKey;
  final Uint8List transcriptSecret;
}

/// Derives the exporter binding embedded in a transport-independent request.
///
/// This is byte-for-byte identical to the Rust verifier implementation. The
/// transcript secret must come from an authenticated secure handshake; public
/// bootstrap values alone are not sufficient.
Future<Uint8List> deriveSessionBinding(SessionBindingInputs inputs) async {
  final fields = <List<int>>[
    utf8.encode(inputs.transportName),
    utf8.encode(inputs.sessionId),
    inputs.verifierHandshakeKey,
    inputs.peerHandshakeKey,
    inputs.transcriptSecret,
  ];
  final bytes = BytesBuilder(copy: false)..add(utf8.encode(_domain));
  for (final field in fields) {
    final length = ByteData(8)..setUint64(0, field.length, Endian.big);
    bytes
      ..add(length.buffer.asUint8List())
      ..add(field);
  }
  final digest = await Sha256().hash(bytes.takeBytes());
  return Uint8List.fromList(digest.bytes);
}
