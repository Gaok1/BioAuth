import 'dart:typed_data';

import '../transport/auth_transport.dart';
import '../transport/secure_session_establisher.dart';
import 'fake_session_binding.dart';

/// Substitutes for the real handshake so a transport can be exercised without
/// key material. It authenticates nothing and must never be reachable from a
/// release build.
class FakeSecureSessionEstablisher implements SecureSessionEstablisher {
  const FakeSecureSessionEstablisher();

  @override
  Future<SecureSessionOutcome> establish(
    RawTransportLink link,
    VerifierExpectation expectation,
  ) async => SecureSessionOutcome(
    session: _FakeSecureSession(
      link,
      await deriveFakeSessionBinding(expectation),
    ),
    verifierIdentitySpki: Uint8List.fromList(List<int>.filled(91, 0xa0)),
    verifierId: switch (expectation) {
      ScannedVerifier(:final bootstrap) => bootstrap.verifierId,
      PairedVerifier() => 'fake-verifier',
    },
    sessionId: switch (expectation) {
      ScannedVerifier(:final bootstrap) => bootstrap.sessionId,
      PairedVerifier() => 'fake-paired-session',
    },
    verificationCode: '000000',
    wasPairing: expectation is ScannedVerifier,
  );
}

class _FakeSecureSession implements SecureTransportSession {
  _FakeSecureSession(this._link, Uint8List sessionBinding)
    : _sessionBinding = Uint8List.fromList(sessionBinding);

  final RawTransportLink _link;
  final Uint8List _sessionBinding;

  @override
  String get originLabel => '${_link.originLabel} • fake secure session';

  @override
  Uint8List get sessionBinding => Uint8List.fromList(_sessionBinding);

  @override
  TransportSecurityProperties get securityProperties =>
      TransportSecurityProperties(
        transportName: _link.rawSecurityProperties.transportName,
        confidential: true,
        peerAuthenticated: true,
        requiresNetwork: _link.rawSecurityProperties.requiresNetwork,
        proximitySignal: _link.rawSecurityProperties.proximitySignal,
        expectedLatency: _link.rawSecurityProperties.expectedLatency,
      );

  @override
  Stream<Uint8List> get incomingFrames => _link.incomingFrames;

  @override
  Future<void> send(Uint8List frame) => _link.send(frame);

  @override
  Future<void> close() => _link.close();
}
