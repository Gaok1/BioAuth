import 'dart:typed_data';

import 'auth_transport.dart';
import 'pairing_bootstrap.dart';

/// A link that moves whole frames and authenticates nothing.
///
/// TCP, BLE and the test doubles all look like this. Everything that makes a
/// session trustworthy is layered on top by a [SecureSessionEstablisher].
abstract interface class RawTransportLink {
  String get originLabel;

  TransportSecurityProperties get rawSecurityProperties;

  Stream<Uint8List> get incomingFrames;

  Future<void> send(Uint8List frame);

  Future<void> close();
}

/// Who the authenticator will accept as the verifier on the other end.
///
/// The two cases are deliberately separate types. Under [ScannedVerifier] every
/// field of the hello is checked against a code the user physically pointed a
/// camera at; under [PairedVerifier] the session parameters are taken *from*
/// the hello, and are trustworthy only because the stored key signed them.
/// Collapsing them into one nullable-field object is how a phone ends up
/// accepting an unauthenticated hello as if it were paired.
sealed class VerifierExpectation {
  const VerifierExpectation();
}

/// First contact. Nothing else vouches for the verifier at this point.
class ScannedVerifier extends VerifierExpectation {
  const ScannedVerifier(this.bootstrap);

  final PairingBootstrap bootstrap;
}

/// Already paired. The hello carries its own session id, nonce and deadline.
class PairedVerifier extends VerifierExpectation {
  PairedVerifier(Uint8List identitySpki)
    : identitySpki = Uint8List.fromList(identitySpki);

  final Uint8List identitySpki;
}

/// A completed handshake.
class SecureSessionOutcome {
  SecureSessionOutcome({
    required this.session,
    required Uint8List verifierIdentitySpki,
    required this.verifierId,
    required this.sessionId,
    required this.verificationCode,
    required this.wasPairing,
  }) : verifierIdentitySpki = Uint8List.fromList(verifierIdentitySpki);

  final SecureTransportSession session;

  /// The identity the verifier presented. Under [PairedVerifier] this equals
  /// what was expected; under [ScannedVerifier] it is what must be stored.
  final Uint8List verifierIdentitySpki;

  final String verifierId;
  final String sessionId;

  /// Six digits shown on both screens during pairing.
  final String verificationCode;

  /// True when the verifier was accepted without a prior pairing record.
  final bool wasPairing;
}

abstract interface class SecureSessionEstablisher {
  Future<SecureSessionOutcome> establish(
    RawTransportLink link,
    VerifierExpectation expectation,
  );
}
