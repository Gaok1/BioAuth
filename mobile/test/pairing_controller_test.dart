import 'dart:async';
import 'dart:typed_data';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/app/providers.dart';
import 'package:phone_auth/core/pairing/pairing_record.dart';
import 'package:phone_auth/core/pairing/pairing_service.dart';
import 'package:phone_auth/core/pairing/pairing_store.dart';
import 'package:phone_auth/core/protocol/enrolment.dart';
import 'package:phone_auth/core/transport/auth_transport.dart';
import 'package:phone_auth/core/transport/pairing_bootstrap.dart';
import 'package:phone_auth/core/transport/secure_session_establisher.dart';
import 'package:phone_auth/features/pairing/pairing_controller.dart';

void main() {
  test('credential failure closes the newly opened pairing session', () async {
    final transportSession = _TestTransportSession();
    final service = PairingService(
      transport: _PairingTransport(transportSession),
      store: InMemoryPairingStore(),
      deviceName: 'test phone',
      credential: _FailingCredential(),
      clock: () => DateTime.utc(2026, 8, 27),
    );
    final bootstrap = PairingBootstrap(
      sessionId: 'session-1',
      nonce: Uint8List(32),
      verifierId: 'desktop-1',
      verifierIdentityHash: Uint8List(32),
      endpoint: '192.0.2.1:42371',
      expiresAtMs: DateTime.utc(2026, 8, 28).millisecondsSinceEpoch,
    );

    await expectLater(service.begin(bootstrap.toUri()), throwsStateError);
    expect(transportSession.closeCalls, 1);
  });

  test('reject returns to idle even when closing the session fails', () async {
    final transportSession = _TestTransportSession(failClose: true);
    final service = _ControlledPairingService({
      'attempt': Future.value(_pairing('desktop-1', transportSession)),
    });
    final container = _container(service);
    addTearDown(container.dispose);
    final controller = container.read(pairingControllerProvider.notifier);

    await controller.submitScan('attempt');
    expect(
      container.read(pairingControllerProvider).stage,
      PairingStage.awaitingCode,
    );

    await expectLater(controller.reject(), completes);
    expect(container.read(pairingControllerProvider).stage, PairingStage.idle);
    expect(transportSession.closeCalls, 1);
  });

  test(
    'reset closes the pending session before allowing another scan',
    () async {
      final transportSession = _TestTransportSession();
      final service = _ControlledPairingService({
        'attempt': Future.value(_pairing('desktop-1', transportSession)),
      });
      final container = _container(service);
      addTearDown(container.dispose);
      final controller = container.read(pairingControllerProvider.notifier);

      await controller.submitScan('attempt');
      await controller.reset();

      expect(
        container.read(pairingControllerProvider).stage,
        PairingStage.idle,
      );
      expect(transportSession.closeCalls, 1);
    },
  );

  test('a cancelled attempt cannot overwrite the next attempt', () async {
    final first = Completer<PairingSession>();
    final second = Completer<PairingSession>();
    final firstTransport = _TestTransportSession();
    final service = _ControlledPairingService({
      'first': first.future,
      'second': second.future,
    });
    final container = _container(service);
    addTearDown(container.dispose);
    final controller = container.read(pairingControllerProvider.notifier);

    final firstSubmission = controller.submitScan('first');
    await _waitUntil(() => service.requested.contains('first'));
    await controller.reset();

    final secondSubmission = controller.submitScan('second');
    await _waitUntil(() => service.requested.contains('second'));
    first.complete(_pairing('old-desktop', firstTransport));
    await firstSubmission;

    expect(firstTransport.closeCalls, 1, reason: 'cancelled session is closed');
    expect(
      container.read(pairingControllerProvider).stage,
      PairingStage.connecting,
    );

    second.complete(_pairing('new-desktop', _TestTransportSession()));
    await secondSubmission;
    final state = container.read(pairingControllerProvider);
    expect(state.stage, PairingStage.awaitingCode);
    expect(state.verifierId, 'new-desktop');
  });
}

ProviderContainer _container(PairingService service) => ProviderContainer(
  overrides: [pairingServiceProvider.overrideWith((ref) async => service)],
);

PairingSession _pairing(
  String verifierId,
  SecureTransportSession transportSession,
) => PairingSession(
  verificationCode: '123456',
  proposed: PairingRecord(
    verifierId: verifierId,
    verifierIdentitySpki: Uint8List.fromList([1, 2, 3]),
    endpoint: '192.0.2.1:42371',
    credentialId: '$verifierId-authorization-v1',
    keyKind: KeyKind.hardware,
    purpose: CredentialPurpose.authorization,
    pairedAt: DateTime.utc(2026, 8, 27),
  ),
  session: transportSession,
  store: InMemoryPairingStore(),
);

Future<void> _waitUntil(bool Function() condition) async {
  while (!condition()) {
    await Future<void>.delayed(Duration.zero);
  }
}

class _ControlledPairingService extends PairingService {
  _ControlledPairingService(this.answers)
    : super(
        transport: _UnusedTransport(),
        store: InMemoryPairingStore(),
        deviceName: 'test phone',
      );

  final Map<String, Future<PairingSession>> answers;
  final List<String> requested = [];

  @override
  Future<PairingSession> begin(String scannedUri) {
    requested.add(scannedUri);
    return answers[scannedUri]!;
  }
}

class _FailingCredential implements AuthorizationCredential {
  @override
  Future<({Uint8List publicKey, String algorithm, KeyKind keyKind})> describe(
    CredentialPurpose purpose,
  ) => Future.error(StateError('keystore unavailable'));
}

class _PairingTransport extends _UnusedTransport {
  _PairingTransport(this.session);

  final SecureTransportSession session;

  @override
  Future<SecureSessionOutcome> connect(
    TransportPeer peer,
    VerifierExpectation expectation,
  ) async => SecureSessionOutcome(
    session: session,
    verifierIdentitySpki: Uint8List.fromList([1, 2, 3]),
    verifierId: peer.displayName,
    sessionId: 'session-1',
    verificationCode: '123456',
    wasPairing: true,
  );
}

class _UnusedTransport implements AuthTransport {
  @override
  TransportSecurityProperties get securityProperties => _properties;

  @override
  Future<void> start() async {}

  @override
  Future<void> stop() async {}

  @override
  Stream<TransportPeer> discoverPeers() => const Stream.empty();

  @override
  Future<SecureSessionOutcome> connect(
    TransportPeer peer,
    VerifierExpectation expectation,
  ) => throw UnimplementedError();
}

class _TestTransportSession implements SecureTransportSession {
  _TestTransportSession({this.failClose = false});

  final bool failClose;
  int closeCalls = 0;

  @override
  String get originLabel => 'test';

  @override
  Uint8List get sessionBinding => Uint8List(32);

  @override
  TransportSecurityProperties get securityProperties => _properties;

  @override
  Stream<Uint8List> get incomingFrames => const Stream.empty();

  @override
  Future<void> send(Uint8List frame) async {}

  @override
  Future<void> close() async {
    closeCalls++;
    if (failClose) throw StateError('close failed');
  }
}

const _properties = TransportSecurityProperties(
  transportName: 'test',
  confidential: true,
  peerAuthenticated: true,
  requiresNetwork: false,
  proximitySignal: false,
  expectedLatency: Duration.zero,
);
