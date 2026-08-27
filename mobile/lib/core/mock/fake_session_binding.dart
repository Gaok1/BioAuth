import 'dart:typed_data';

import '../session/session_binding.dart';
import '../transport/pairing_bootstrap.dart';
import '../transport/secure_session_establisher.dart';

/// A deterministic binding for the in-process fakes.
///
/// Derived from the real function so the fakes cannot accidentally agree on a
/// binding the production code would never produce, but from fixed key material
/// because no handshake ran.
Future<Uint8List> deriveFakeSessionBinding(VerifierExpectation expectation) {
  final sessionId = switch (expectation) {
    ScannedVerifier(:final bootstrap) => bootstrap.sessionId,
    PairedVerifier() => 'fake-paired-session',
  };
  final material = switch (expectation) {
    ScannedVerifier(:final bootstrap) => bootstrap.verifierIdentityHash,
    PairedVerifier(:final identitySpki) => _padded(identitySpki),
  };
  return deriveSessionBinding(
    SessionBindingInputs(
      transportName: 'fake',
      sessionId: sessionId,
      serverEphemeral: material,
      clientEphemeral: material,
      exporter: material,
    ),
  );
}

/// A fixed 32-byte fixture. The [SessionBindingInputs] guard rejects a short
/// exporter, and a test key may be any length.
Uint8List _padded(Uint8List source) {
  final bytes = Uint8List(32);
  for (var index = 0; index < bytes.length; index++) {
    bytes[index] = source.isEmpty ? index : source[index % source.length];
  }
  return bytes;
}

/// A bootstrap fixture for tests and the development seed.
PairingBootstrap fakeBootstrap({
  String sessionId = 'fake-session',
  String verifierId = 'fake-verifier',
  String endpoint = '',
  int? expiresAtMs,
}) => PairingBootstrap(
  sessionId: sessionId,
  nonce: Uint8List.fromList(List<int>.generate(32, (index) => index)),
  verifierId: verifierId,
  verifierIdentityHash: Uint8List.fromList(
    List<int>.generate(32, (index) => 255 - index),
  ),
  endpoint: endpoint,
  expiresAtMs:
      expiresAtMs ?? DateTime.now().toUtc().millisecondsSinceEpoch + 120000,
);
