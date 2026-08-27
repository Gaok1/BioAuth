import 'dart:typed_data';

import 'secure_session_establisher.dart';

abstract interface class AuthTransport {
  TransportSecurityProperties get securityProperties;

  Future<void> start();

  Future<void> stop();

  Stream<TransportPeer> discoverPeers();

  /// Opens an authenticated, confidential session to [peer].
  ///
  /// [expectation] decides what the phone will accept on the other end: a
  /// freshly scanned bootstrap, or the verifier key stored at pairing.
  Future<SecureSessionOutcome> connect(
    TransportPeer peer,
    VerifierExpectation expectation,
  );
}

class TransportPeer {
  const TransportPeer({required this.transportId, required this.displayName});

  final String transportId;
  final String displayName;
}

abstract interface class SecureTransportSession {
  String get originLabel;

  Uint8List get sessionBinding;

  TransportSecurityProperties get securityProperties;

  Stream<Uint8List> get incomingFrames;

  Future<void> send(Uint8List frame);

  Future<void> close();
}

class TransportSecurityProperties {
  const TransportSecurityProperties({
    required this.transportName,
    required this.confidential,
    required this.peerAuthenticated,
    required this.requiresNetwork,
    required this.proximitySignal,
    required this.expectedLatency,
  });

  final String transportName;
  final bool confidential;
  final bool peerAuthenticated;
  final bool requiresNetwork;
  final bool proximitySignal;
  final Duration expectedLatency;
}
