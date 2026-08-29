import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:fake_async/fake_async.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/app/app_controller.dart';
import 'package:phone_auth/app/config.dart';
import 'package:phone_auth/app/providers.dart';
import 'package:phone_auth/core/auth/interactive_authorizer.dart';
import 'package:phone_auth/core/pairing/pairing_record.dart';
import 'package:phone_auth/core/pairing/pairing_store.dart';
import 'package:phone_auth/core/protocol/enrolment.dart';
import 'package:phone_auth/core/protocol/protocol_codec.dart';
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

  // A blip must not read as "offline". The desktop sleeping for a moment or
  // the Wi-Fi roaming used to cost a flat fifteen seconds and an offline badge
  // on the first failure.
  test('a short outage retries quickly and does not report offline', () {
    fakeAsync((async) {
      final transport = _RefusingTransport();
      final statuses = <PairedSessionStatus>[];
      final runner = PairedSessionRunner(
        transport: transport,
        authorizer: _UnusedAuthorizer(),
        consent: InteractiveAuthorizer(
          onRequest: (_) => throw UnimplementedError(),
        ),
        onStatus: (_, status) => statuses.add(status),
      );
      runner.sync([_record]);

      async.elapse(const Duration(seconds: 3));
      expect(
        transport.attempts,
        greaterThan(1),
        reason: 'a blip must be retried in seconds, not after a flat wait',
      );
      expect(
        statuses.take(_kFailuresBeforeOffline),
        everyElement(PairedSessionStatus.connecting),
        reason: 'the first few failures are still "connecting"',
      );

      // A desktop that stays away does eventually read as unreachable, and the
      // backoff stops it being dialled continuously.
      async.elapse(const Duration(minutes: 1));
      expect(statuses, contains(PairedSessionStatus.unreachable));
      expect(
        transport.attempts,
        lessThan(20),
        reason: 'the delay grows instead of hammering an absent desktop',
      );

      runner.stop();
      async.flushMicrotasks();
    });
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

  // One desktop, two credentials, so two loops. A session ending is ordinary:
  // it carries one request and closes, and the phone dials again. When that
  // unwinding abandoned everything pending rather than what the session itself
  // had raised, the healthy loop's prompt was cancelled by the other loop's
  // perfectly normal reconnect -- the sheet vanished mid-tap and the desktop
  // that had asked was told the phone failed.
  test(
    'one session ending does not cancel another session\'s prompt',
    () async {
      final now = DateTime.utc(2026, 8, 27, 12);
      final transport = _OneAsksOneBreaksTransport();
      final consent = InteractiveAuthorizer(onRequest: (_) {});
      final runner = PairedSessionRunner(
        transport: transport,
        authorizer: _UnusedAuthorizer(),
        consent: consent,
        clock: () => now,
      );
      addTearDown(runner.stop);

      runner.sync([_record, _vaultRecord]);
      await transport.asking.listening.future;
      transport.asking.ask(
        AuthenticationRequest(
          requestId: 'request-1',
          verifierId: 'desktop-1',
          verifierName: 'Desktop-NixOS',
          credentialId: _record.credentialId,
          challenge: Uint8List.fromList(List<int>.generate(32, (i) => i)),
          origin: 'replaced by session',
          service: 'sudo',
          action: 'nixos-rebuild switch',
          resource: 'Desktop-NixOS',
          user: 'alice',
          issuedAt: now,
          expiresAt: now.add(const Duration(minutes: 1)),
          sessionBinding: Uint8List(32),
        ),
      );
      await _until(() => consent.pendingRequestIds.contains('request-1'));

      // Only now let the other credential's session end, so the failure lands
      // while there is a prompt on screen to destroy.
      transport.releaseBreak();
      await _until(() => transport.broken?.closed ?? false);
      await pumpEventQueue();

      expect(
        consent.pendingRequestIds,
        contains('request-1'),
        reason: 'the prompt belongs to the session that is still up',
      );
    },
  );
}

/// Waits for [ready], failing the test rather than hanging if it never comes.
Future<void> _until(bool Function() ready) async {
  for (var i = 0; i < 100 && !ready(); i++) {
    await pumpEventQueue(times: 5);
  }
  expect(ready(), isTrue, reason: 'the precondition never happened');
}

/// The same desktop's second credential. Two records, two loops, one computer.
final _vaultRecord = PairingRecord(
  verifierId: _record.verifierId,
  verifierIdentitySpki: _record.verifierIdentitySpki,
  endpoint: _record.endpoint,
  credentialId: 'credential-2',
  keyKind: _record.keyKind,
  purpose: CredentialPurpose.vault,
  pairedAt: _record.pairedAt,
);

/// First caller gets a session that asks for something and then waits; the
/// next gets one that ends, on the test's cue.
class _OneAsksOneBreaksTransport implements AuthTransport {
  final _AskingSession asking = _AskingSession();
  final _break = Completer<void>();
  _EndedSession? broken;
  var _connects = 0;

  void releaseBreak() => _break.complete();

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
  ) async {
    if (_connects++ == 0) return _outcome(asking, peer.displayName);
    await _break.future;
    return _outcome(broken = _EndedSession(), peer.displayName);
  }
}

/// Carries one request and then stays open, the way a session waiting on an
/// unanswered prompt does.
class _AskingSession extends _IdleSession {
  void ask(AuthenticationRequest request) =>
      _incoming.add(const PhoneAuthProtocolCodec().encodeRequest(request));
}

/// A desktop that hung up: the frame stream is already done.
class _EndedSession extends _IdleSession {
  _EndedSession() {
    unawaited(_incoming.close());
  }
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

/// Mirrors `_failuresBeforeUnreachable` in the runner, which is private.
const int _kFailuresBeforeOffline = 3;

class _RefusingTransport implements AuthTransport {
  int attempts = 0;

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
  ) async {
    attempts++;
    throw const SocketException('desktop is not answering');
  }
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

SecureSessionOutcome _outcome(
  SecureTransportSession session,
  String verifierId,
) => SecureSessionOutcome(
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
    // Not awaited. A real session close tears the socket down; it does not
    // wait for the peer's reader to drain. Awaiting it here deadlocked any
    // test whose session was parked mid-request, because `StreamIterator`
    // pauses its subscription between `moveNext` calls and a paused listener
    // never receives the done event.
    unawaited(_incoming.close());
  }
}

class _UnusedAuthorizer implements BiometricAuthorizer {
  @override
  Future<AuthorizationProof> authorize({
    required AuthenticationRequest request,
    required Uint8List canonicalRequest,
    String purpose = 'authorization',
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
