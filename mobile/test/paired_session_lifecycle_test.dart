import 'dart:async';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/core/pairing/pairing_record.dart';
import 'package:phone_auth/core/protocol/enrolment.dart';
import 'package:phone_auth/core/session/paired_session_service.dart';
import 'package:phone_auth/core/session/phone_auth_core.dart';
import 'package:phone_auth/core/transport/auth_transport.dart';
import 'package:phone_auth/core/transport/secure_session_establisher.dart';
import 'package:phone_auth/domain/authentication_request.dart';

void main() {
  test('stopping the lifecycle owner closes an idle paired session', () async {
    final session = _IdleSession();
    final transport = _LifecycleTransport(session);
    final service = PairedSessionService(
      transport: transport,
      authorizer: _UnusedAuthorizer(),
      consent: _UnusedConsent(),
    );
    final serving = service.serveOne(
      PairingRecord(
        verifierId: 'desktop-1',
        verifierIdentitySpki: Uint8List.fromList([1, 2, 3]),
        endpoint: '192.0.2.1:42371',
        credentialId: 'credential-1',
        keyKind: KeyKind.hardware,
        purpose: CredentialPurpose.authorization,
        pairedAt: DateTime.utc(2026, 8, 27),
      ),
    );
    await session.listening.future;

    await service.stop();

    expect(transport.stopped, isTrue);
    expect(session.closed, isTrue);
    await expectLater(serving, throwsA(anything));
  });
}

class _LifecycleTransport implements AuthTransport {
  _LifecycleTransport(this.session);

  final _IdleSession session;
  bool stopped = false;

  @override
  TransportSecurityProperties get securityProperties => _properties;

  @override
  Future<void> start() async {}

  @override
  Future<void> stop() async {
    stopped = true;
  }

  @override
  Stream<TransportPeer> discoverPeers() => const Stream.empty();

  @override
  Future<SecureSessionOutcome> connect(
    TransportPeer peer,
    VerifierExpectation expectation,
  ) async {
    return SecureSessionOutcome(
      session: session,
      verifierIdentitySpki: Uint8List.fromList([1, 2, 3]),
      verifierId: 'desktop-1',
      sessionId: 'session-1',
      verificationCode: '123456',
      wasPairing: false,
    );
  }
}

class _IdleSession implements SecureTransportSession {
  _IdleSession() {
    _incoming = StreamController<Uint8List>(onListen: listening.complete);
  }

  late final StreamController<Uint8List> _incoming;
  final listening = Completer<void>();
  bool closed = false;

  @override
  String get originLabel => 'test';

  @override
  Uint8List get sessionBinding => Uint8List(32);

  @override
  TransportSecurityProperties get securityProperties => _properties;

  @override
  Stream<Uint8List> get incomingFrames => _incoming.stream;

  @override
  Future<void> send(Uint8List frame) async {}

  @override
  Future<void> close() async {
    if (closed) return;
    closed = true;
    await _incoming.close();
  }
}

class _UnusedAuthorizer implements BiometricAuthorizer {
  @override
  Future<AuthorizationProof> authorize({
    required AuthenticationRequest request,
    required Uint8List canonicalRequest,
  }) => throw UnimplementedError();
}

class _UnusedConsent implements AuthorizationConsent {
  @override
  Future<bool> confirm(
    AuthenticationRequest request,
    TransportSecurityProperties transport,
  ) => throw UnimplementedError();
}

const _properties = TransportSecurityProperties(
  transportName: 'test',
  confidential: true,
  peerAuthenticated: true,
  requiresNetwork: false,
  proximitySignal: false,
  expectedLatency: Duration.zero,
);
