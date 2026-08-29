import 'dart:async';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/app/app.dart';
import 'package:phone_auth/app/config.dart';
import 'package:phone_auth/app/providers.dart';
import 'package:phone_auth/core/pairing/pairing_record.dart';
import 'package:phone_auth/core/protocol/enrolment.dart';
import 'package:phone_auth/core/transport/auth_transport.dart';
import 'package:phone_auth/core/transport/secure_session_establisher.dart';
import 'package:phone_auth/core/vault/vault_approval.dart';

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
  testWidgets('backgrounding the app keeps the paired session open', (
    tester,
  ) async {
    final session = _IdleSession();
    final transport = _LifecycleTransport(session);
    final record = _record;
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);

    await tester.pumpWidget(
      ProviderScope(
        overrides: [
          appConfigProvider.overrideWithValue(const AppConfig.production()),
          pairedVerifiersProvider.overrideWith((ref) async => [record]),
          backgroundSessionsReadyProvider.overrideWith((ref) async => true),
          transportProvider.overrideWith((ref) async => transport),
        ],
        child: const PhoneAuthApp(),
      ),
    );
    for (var pump = 0; pump < 5 && !session.listening.isCompleted; pump++) {
      await tester.pump();
    }
    expect(session.listening.isCompleted, isTrue);

    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.paused);
    await tester.pump();
    await tester.pump();

    expect(transport.stopped, isFalse);
    expect(session.closed, isFalse);

    await tester.pumpWidget(const SizedBox.shrink());
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
  });

  // Android reports `inactive` for the biometric prompt, the notification
  // shade and permission dialogs. The app is still on screen, and the session
  // waiting on that prompt has to survive it.
  testWidgets('losing window focus keeps the paired session open', (
    tester,
  ) async {
    final session = _IdleSession();
    final transport = _LifecycleTransport(session);
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);

    await tester.pumpWidget(
      ProviderScope(
        overrides: [
          appConfigProvider.overrideWithValue(const AppConfig.production()),
          pairedVerifiersProvider.overrideWith((ref) async => [_record]),
          backgroundSessionsReadyProvider.overrideWith((ref) async => true),
          transportProvider.overrideWith((ref) async => transport),
        ],
        child: const PhoneAuthApp(),
      ),
    );
    for (var pump = 0; pump < 5 && !session.listening.isCompleted; pump++) {
      await tester.pump();
    }
    expect(session.listening.isCompleted, isTrue);

    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
    await tester.pump();
    await tester.pump();

    expect(transport.stopped, isFalse);
    expect(session.closed, isFalse);

    await tester.pumpWidget(const SizedBox.shrink());
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
  });

  // The same distinction, for the answer rather than the connection. This is
  // the one the user feels: a desktop asks for a password, the sheet appears,
  // the user taps approve, and approving raises the biometric prompt — which
  // costs the app focus. Refusing on `inactive` refused the request the person
  // was in the middle of saying yes to, and the desktop reported a denial
  // nobody made.
  testWidgets('the biometric prompt does not refuse the request it is for', (
    tester,
  ) async {
    final session = _IdleSession();
    final transport = _LifecycleTransport(session);
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);

    late InteractiveVaultApproval approval;
    await tester.pumpWidget(
      ProviderScope(
        overrides: [
          appConfigProvider.overrideWithValue(const AppConfig.production()),
          pairedVerifiersProvider.overrideWith((ref) async => [_record]),
          backgroundSessionsReadyProvider.overrideWith((ref) async => true),
          transportProvider.overrideWith((ref) async => transport),
        ],
        child: Consumer(
          builder: (context, ref, _) {
            approval = ref.watch(vaultApprovalProvider);
            return const PhoneAuthApp();
          },
        ),
      ),
    );
    await tester.pump();

    const request = VaultApprovalRequest(
      id: 'request-1',
      verifierName: 'desktop-1',
      operation: VaultOperation.read,
      itemName: 'example.com',
    );
    bool? answer;
    unawaited(approval.confirm(request).then((value) => answer = value));
    await tester.pumpAndSettle();
    expect(approval.pendingRequestIds, contains('request-1'));
    expect(find.text('Recusar'), findsOneWidget, reason: 'the sheet is up');

    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
    await tester.pump();
    expect(
      answer,
      isNull,
      reason: 'raising the biometric prompt is not an answer',
    );
    expect(approval.pendingRequestIds, contains('request-1'));

    // Actually leaving still refuses: a sheet nobody can see must not stay
    // answerable.
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.hidden);
    await tester.pump();
    expect(answer, isFalse);

    // And the sheet goes with the answer. Refusing behind a sheet that stays
    // up leaves its buttons looking live: the user comes back, taps the button,
    // passes the biometric, and has approved nothing — the request was refused
    // while the phone was in their pocket and the session is long gone.
    // The sheet is dismissed with the answer, and finishes going while the
    // app is on screen: a hidden app runs no frames, so the exit animation
    // waits for the user to come back — which is exactly when it matters that
    // the sheet is not there to be tapped.
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
    await tester.pumpAndSettle();
    expect(find.text('Recusar'), findsNothing);

    await tester.pumpWidget(const SizedBox.shrink());
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
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
  ) async => SecureSessionOutcome(
    session: session,
    verifierIdentitySpki: Uint8List.fromList([1, 2, 3]),
    verifierId: 'desktop-1',
    sessionId: 'session-1',
    verificationCode: '123456',
    wasPairing: false,
  );
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

const _properties = TransportSecurityProperties(
  transportName: 'test',
  confidential: true,
  peerAuthenticated: true,
  requiresNetwork: false,
  proximitySignal: false,
  expectedLatency: Duration.zero,
);
