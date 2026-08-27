import 'dart:async';
import 'dart:typed_data';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/app/app_controller.dart';
import 'package:phone_auth/app/config.dart';
import 'package:phone_auth/app/providers.dart';
import 'package:phone_auth/core/auth/interactive_authorizer.dart';
import 'package:phone_auth/core/pairing/pairing_record.dart';
import 'package:phone_auth/core/pairing/pairing_store.dart';
import 'package:phone_auth/core/protocol/enrolment.dart';
import 'package:phone_auth/core/session/paired_session_runner.dart';
import 'package:phone_auth/core/session/paired_session_service.dart';
import 'package:phone_auth/core/session/phone_auth_core.dart';
import 'package:phone_auth/core/transport/auth_transport.dart';
import 'package:phone_auth/core/transport/secure_session_establisher.dart';
import 'package:phone_auth/domain/authentication_request.dart';
import 'package:phone_auth/domain/connection_phase.dart';

final _record = PairingRecord(
  verifierId: 'desktop-1',
  verifierIdentitySpki: Uint8List.fromList([1, 2, 3]),
  endpoint: '192.0.2.1:42371',
  credentialId: 'credential-1',
  keyKind: KeyKind.hardware,
  purpose: CredentialPurpose.authorization,
  pairedAt: DateTime.utc(2026, 8, 27),
);

void main() {
  // The desktop speaks first in a paired session, so a working connection can
  // legitimately carry no traffic for four minutes. Waiting for a request
  // before reporting `connected` left every idle desktop reading "Conectando".
  test(
    'an authenticated handshake reports connected before any request',
    () async {
      final session = _IdleSession();
      final service = PairedSessionService(
        transport: _StubTransport(session),
        authorizer: _UnusedAuthorizer(),
        consent: _UnusedConsent(),
      );

      var established = false;
      final serving = service.serveOne(
        _record,
        onEstablished: () => established = true,
      );
      await session.listening.future;

      expect(
        established,
        isTrue,
        reason: 'connected must not wait for the first request',
      );
      await service.stop();
      await expectLater(serving, throwsA(anything));
    },
  );

  test('closing one device leaves the others connected', () async {
    final wanted = _IdleSession();
    final other = _IdleSession();
    final service = PairedSessionService(
      transport: _PerDeviceTransport({'desktop-1': wanted, 'desktop-2': other}),
      authorizer: _UnusedAuthorizer(),
      consent: _UnusedConsent(),
    );
    final first = service.serveOne(_record);
    final second = service.serveOne(_record.copyWithVerifier('desktop-2'));
    await wanted.listening.future;
    await other.listening.future;

    await service.closeDevice('desktop-1');

    expect(wanted.closed, isTrue);
    expect(other.closed, isFalse, reason: 'only the revoked device hangs up');
    await expectLater(first, throwsA(anything));
    await service.stop();
    await expectLater(second, throwsA(anything));
  });

  test('a revoked device is refused even if its loop dials again', () async {
    final session = _IdleSession();
    final service = PairedSessionService(
      transport: _StubTransport(session),
      authorizer: _UnusedAuthorizer(),
      consent: _UnusedConsent(),
    );

    await service.closeDevice('desktop-1');

    await expectLater(service.serveOne(_record), throwsStateError);
    expect(session.listening.isCompleted, isFalse);
  });

  test('pairing again after a revocation is allowed once more', () async {
    final session = _IdleSession();
    final runner = PairedSessionRunner(
      transport: _StubTransport(session),
      authorizer: _UnusedAuthorizer(),
      consent: InteractiveAuthorizer(
        onRequest: (_) => throw UnimplementedError(),
      ),
    );

    await runner.stopDevice('desktop-1');
    // A record that comes back is a fresh pairing, not the revoked one.
    runner.sync([_record]);
    await session.listening.future;

    expect(session.listening.isCompleted, isTrue);
    await runner.stop();
  });

  // Removing the row was never revocation: the record stayed on disk, so a
  // restart put the desktop straight back on screen.
  test('revoking removes the record and does not come back', () async {
    final store = InMemoryPairingStore(seed: [_record]);
    final container = ProviderContainer(
      overrides: [
        appConfigProvider.overrideWithValue(const AppConfig.production()),
        pairingStoreProvider.overrideWithValue(store),
      ],
    );
    addTearDown(container.dispose);

    final controller = container.read(appControllerProvider.notifier);
    controller.syncPairedDevices(await store.load());
    expect(container.read(appControllerProvider).devices, hasLength(1));

    await controller.revokeDevice('desktop-1');

    expect(await store.load(), isEmpty, reason: 'the record must be gone');
    expect(container.read(appControllerProvider).devices, isEmpty);

    // What a restart would do: read the store back into the UI.
    controller.syncPairedDevices(await store.load());
    expect(container.read(appControllerProvider).devices, isEmpty);
  });

  test('a store that refuses to forget does not report success', () async {
    final container = ProviderContainer(
      overrides: [
        appConfigProvider.overrideWithValue(const AppConfig.production()),
        pairingStoreProvider.overrideWithValue(_FailingStore(_record)),
      ],
    );
    addTearDown(container.dispose);

    final controller = container.read(appControllerProvider.notifier);
    controller.syncPairedDevices([_record]);

    await expectLater(controller.revokeDevice('desktop-1'), throwsException);

    final devices = container.read(appControllerProvider).devices;
    expect(devices, hasLength(1), reason: 'the pairing is still real');
    expect(devices.single.phase, ConnectionPhase.error);
  });
}

extension on PairingRecord {
  PairingRecord copyWithVerifier(String verifierId) => PairingRecord(
    verifierId: verifierId,
    verifierIdentitySpki: verifierIdentitySpki,
    endpoint: endpoint,
    credentialId: credentialId,
    keyKind: keyKind,
    purpose: purpose,
    pairedAt: pairedAt,
  );
}

class _FailingStore implements PairingStore {
  _FailingStore(this._record);

  final PairingRecord _record;

  @override
  Future<List<PairingRecord>> load() async => [_record];

  @override
  Future<void> save(PairingRecord record) async {}

  @override
  Future<void> remove(String verifierId) async =>
      throw Exception('storage is read-only');

  @override
  Future<String> deviceId() async => 'phone-test';
}

class _StubTransport implements AuthTransport {
  _StubTransport(this.session);

  final _IdleSession session;
  bool stopped = false;

  @override
  TransportSecurityProperties get securityProperties => _properties;

  @override
  Future<void> start() async {}

  @override
  Future<void> stop() async => stopped = true;

  @override
  Stream<TransportPeer> discoverPeers() => const Stream.empty();

  @override
  Future<SecureSessionOutcome> connect(
    TransportPeer peer,
    VerifierExpectation expectation,
  ) async => _outcome(session, peer.displayName);
}

class _PerDeviceTransport implements AuthTransport {
  _PerDeviceTransport(this.sessions);

  final Map<String, _IdleSession> sessions;
  bool stopped = false;

  @override
  TransportSecurityProperties get securityProperties => _properties;

  @override
  Future<void> start() async {}

  @override
  Future<void> stop() async => stopped = true;

  @override
  Stream<TransportPeer> discoverPeers() => const Stream.empty();

  @override
  Future<SecureSessionOutcome> connect(
    TransportPeer peer,
    VerifierExpectation expectation,
  ) async => _outcome(sessions[peer.displayName]!, peer.displayName);
}

SecureSessionOutcome _outcome(_IdleSession session, String verifierId) =>
    SecureSessionOutcome(
      session: session,
      verifierIdentitySpki: Uint8List.fromList([1, 2, 3]),
      verifierId: verifierId,
      sessionId: 'session-1',
      verificationCode: '123456',
      wasPairing: false,
    );

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
