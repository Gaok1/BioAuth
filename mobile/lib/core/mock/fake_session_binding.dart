import 'dart:typed_data';

import '../session/session_binding.dart';
import '../transport/auth_transport.dart';

Future<Uint8List> deriveFakeSessionBinding(SessionBootstrap bootstrap) async {
  final sessionId = bootstrap.sessionId;
  final ephemeral = bootstrap.ephemeralPublicKey;
  final nonce = bootstrap.nonce;
  if (sessionId == null || ephemeral == null || nonce == null) {
    throw StateError('Fake sessions require a complete test bootstrap');
  }
  return deriveSessionBinding(
    SessionBindingInputs(
      transportName: 'fake',
      sessionId: sessionId,
      verifierHandshakeKey: ephemeral,
      peerHandshakeKey: nonce,
      transcriptSecret: nonce,
    ),
  );
}
