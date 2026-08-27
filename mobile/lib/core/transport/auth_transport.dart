import 'dart:typed_data';

abstract interface class AuthTransport {
  TransportSecurityProperties get securityProperties;

  Future<void> start();

  Future<void> stop();

  Stream<TransportPeer> discoverPeers();

  Future<SecureTransportSession> connect(
    TransportPeer peer,
    SessionBootstrap bootstrap,
  );
}

class TransportPeer {
  const TransportPeer({required this.transportId, required this.displayName});

  final String transportId;
  final String displayName;
}

class SessionBootstrap {
  SessionBootstrap({
    required String sessionId,
    required this.verifierId,
    required Uint8List nonce,
    required Uint8List ephemeralPublicKey,
    required Uint8List verifierIdentityPublicKey,
    required DateTime expiresAt,
  }) : sessionId = sessionId,
       nonce = Uint8List.fromList(nonce),
       ephemeralPublicKey = Uint8List.fromList(ephemeralPublicKey),
       verifierIdentityPublicKey = Uint8List.fromList(
         verifierIdentityPublicKey,
       ),
       expiresAt = expiresAt.toUtc() {
    if (sessionId.isEmpty || verifierId.isEmpty) {
      throw ArgumentError('Session and verifier identifiers are required');
    }
    if (nonce.length != 32 ||
        ephemeralPublicKey.length != 32 ||
        verifierIdentityPublicKey.isEmpty) {
      throw ArgumentError('Invalid secure-session bootstrap material');
    }
  }

  SessionBootstrap.paired({
    required this.verifierId,
    required Uint8List verifierIdentityPublicKey,
  }) : sessionId = null,
       nonce = null,
       ephemeralPublicKey = null,
       verifierIdentityPublicKey = Uint8List.fromList(
         verifierIdentityPublicKey,
       ),
       expiresAt = null {
    if (verifierId.isEmpty || verifierIdentityPublicKey.isEmpty) {
      throw ArgumentError('Paired verifier identity is required');
    }
  }

  final String? sessionId;
  final String verifierId;
  final Uint8List? nonce;
  final Uint8List? ephemeralPublicKey;
  final Uint8List verifierIdentityPublicKey;
  final DateTime? expiresAt;
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
