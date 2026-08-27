import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

const _domain = 'PhoneAuth/session-binding/v1';

/// Inputs both peers must agree on to derive the same session binding.
class SessionBindingInputs {
  SessionBindingInputs({
    required this.transportName,
    required this.sessionId,
    required Uint8List serverEphemeral,
    required Uint8List clientEphemeral,
    required Uint8List exporter,
  }) : serverEphemeral = Uint8List.fromList(serverEphemeral),
       clientEphemeral = Uint8List.fromList(clientEphemeral),
       exporter = Uint8List.fromList(exporter) {
    if (transportName.isEmpty || sessionId.isEmpty) {
      throw ArgumentError('Transport and session identifiers must be present');
    }
    if (serverEphemeral.isEmpty ||
        clientEphemeral.isEmpty ||
        exporter.length < 32) {
      throw ArgumentError('Handshake keys and a 32-byte exporter are required');
    }
  }

  /// The exact string the transport reports: `QrNetworkTransport`,
  /// `BleTransport`. Both sides must use the same one, or every request fails.
  final String transportName;
  final String sessionId;

  /// The verifier's ephemeral X25519 public key.
  final Uint8List serverEphemeral;

  /// The authenticator's ephemeral X25519 public key.
  final Uint8List clientEphemeral;

  /// `KeySchedule.exporter`. Never sent on the wire, which is what makes the
  /// binding unforgeable by an observer who saw the whole handshake.
  final Uint8List exporter;
}

/// Derives the 32-byte session binding embedded in the signed request.
///
/// Byte-for-byte identical to the Rust verifier. Every field is length-prefixed
/// because under plain concatenation a transport name ending in digits and a
/// session id starting with them would hash the same as a different split of
/// the same characters.
Future<Uint8List> deriveSessionBinding(SessionBindingInputs inputs) async {
  final fields = <List<int>>[
    utf8.encode(inputs.transportName),
    utf8.encode(inputs.sessionId),
    inputs.serverEphemeral,
    inputs.clientEphemeral,
    inputs.exporter,
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
