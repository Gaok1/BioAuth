/// Holds a connection to a paired desktop and serves one authorization on it.
///
/// The desktop listens and the phone dials, but the *request* travels the other
/// way: the desktop parks the session and sends an `AuthRequest` when it needs
/// one. So the phone connects and waits, and one session carries exactly one
/// authorization — holding a channel open across requests would make a phone
/// that walked out of range look available until the first timeout.
library;

import 'dart:async';

import '../pairing/pairing_record.dart';
import '../protocol/auth_response.dart';
import '../protocol/webauthn_relay.dart';
import '../transport/auth_transport.dart';
import '../transport/secure_session_establisher.dart';
import 'phone_auth_core.dart';

/// How long a connected phone waits for the desktop to ask for something.
///
/// Shorter than the desktop's 300-second idle timeout, so the phone reconnects
/// while the desktop still considers the previous session live.
const Duration pairedSessionIdleTimeout = Duration(minutes: 4);

class PairedSessionService {
  PairedSessionService({
    required AuthTransport transport,
    required BiometricAuthorizer authorizer,
    required AuthorizationConsent consent,
    DateTime Function()? clock,
  }) : _transport = transport,
       _authorizer = authorizer,
       _consent = consent,
       _clock = clock;

  final AuthTransport _transport;
  final BiometricAuthorizer _authorizer;
  final AuthorizationConsent _consent;
  final DateTime Function()? _clock;
  final Set<SecureTransportSession> _active = {};
  final WebAuthnRelayHandler _webAuthn = const WebAuthnRelayHandler();
  bool _stopped = false;

  /// Stops discovery and closes sessions when the app leaves the foreground.
  Future<void> stop() async {
    if (_stopped) return;
    _stopped = true;
    await _transport.stop();
    await Future.wait(
      _active.toList().map((session) async {
        try {
          await session.close();
        } on Object {
          // Every session is independent; one broken link must not keep the
          // others alive after the lifecycle owner has stopped.
        }
      }),
    );
  }

  /// Connects, waits for one request, answers it, and closes.
  ///
  /// Returns the response that was sent, or null when the desktop asked for
  /// nothing before the timeout. A null is not an error: the caller simply
  /// dials again.
  Future<AuthResponse?> serveOne(PairingRecord record) async {
    if (_stopped) throw StateError('Serviço de sessões encerrado');
    final outcome = await _transport.connect(
      TransportPeer(
        transportId: record.endpoint,
        displayName: record.verifierId,
      ),
      PairedVerifier(record.verifierIdentitySpki),
    );
    if (_stopped) {
      await outcome.session.close();
      throw StateError('Serviço de sessões encerrado');
    }
    if (outcome.wasPairing) {
      // The transport reported first contact for a device that is already
      // paired. Nothing about that session is trusted.
      await outcome.session.close();
      throw StateError(
        'O computador respondeu como se nunca tivesse sido pareado',
      );
    }
    _active.add(outcome.session);

    final core = PhoneAuthCore(
      authorizer: _authorizer,
      consent: _consent,
      policy: policyFor(record),
      clock: _clock,
    );
    try {
      final frame = await outcome.session.incomingFrames.first.timeout(
        pairedSessionIdleTimeout,
      );
      if (WebAuthnRelayRequest.recognizes(frame)) {
        final request = WebAuthnRelayRequest.decode(
          frame,
          expectedVerifierId: record.verifierId,
        );
        await outcome.session.send(await _webAuthn.perform(request));
        return null;
      }
      return await core.serveFrame(outcome.session, frame);
    } on TimeoutException {
      // Nothing was asked for. Not an error: the desktop is simply idle.
      return null;
    } finally {
      _active.remove(outcome.session);
      await outcome.session.close();
    }
  }
}

/// What the phone will carry for a paired verifier.
VerifierPolicy policyFor(PairingRecord record) => VerifierPolicy(
  verifierId: record.verifierId,
  credentialId: record.credentialId,
  permissions: const [VerifierPermission.any()],
);
