import 'dart:async';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/app/app.dart';
import 'package:phone_auth/app/app_controller.dart';
import 'package:phone_auth/app/config.dart';
import 'package:phone_auth/app/providers.dart';
import 'package:phone_auth/core/pairing/pairing_record.dart';
import 'package:phone_auth/core/protocol/enrolment.dart';
import 'package:phone_auth/features/pairing/pairing_controller.dart';
import 'package:phone_auth/core/pairing/pairing_service.dart';
import 'package:phone_auth/core/pairing/pairing_store.dart';
import 'package:phone_auth/core/transport/auth_transport.dart';
import 'package:phone_auth/core/transport/secure_session_establisher.dart';
import 'package:phone_auth/core/auth/interactive_authorizer.dart';
import 'package:phone_auth/core/ssh/ssh_service.dart';
import 'package:phone_auth/core/vault/vault_approval.dart';
import 'package:phone_auth/domain/authentication_request.dart';

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

  // The verification code is a sheet too, and the most consequential one:
  // confirming it is what makes a computer trusted. It was the one sheet this
  // rule was never applied to.
  testWidgets('leaving the foreground takes down a pairing code', (
    tester,
  ) async {
    final pairing = _IdleSession();
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);

    WidgetRef? reader;
    await tester.pumpWidget(
      ProviderScope(
        overrides: [
          appConfigProvider.overrideWithValue(const AppConfig.production()),
          pairedVerifiersProvider.overrideWith((ref) async => [_record]),
          backgroundSessionsReadyProvider.overrideWith((ref) async => false),
          pairingServiceProvider.overrideWith(
            (ref) async => _StubPairingService(pairing),
          ),
        ],
        child: Consumer(
          builder: (context, ref, _) {
            reader = ref;
            return const PhoneAuthApp();
          },
        ),
      ),
    );
    await tester.pumpAndSettle();

    await reader!.read(pairingControllerProvider.notifier).submitScan('code');
    await tester.pump();
    expect(
      reader!.read(pairingControllerProvider).stage,
      PairingStage.awaitingCode,
      reason: 'the code is on screen before anything is asked to take it down',
    );

    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.paused);
    await tester.pumpAndSettle();

    expect(
      reader!.read(pairingControllerProvider).stage,
      PairingStage.idle,
      reason:
          'a code the user cannot see must not stay confirmable -- a tap on '
          'the way back would pair a desktop scanned who knows when',
    );
    expect(
      pairing.closed,
      isTrue,
      reason: 'and the socket it was holding open to that desktop goes with it',
    );

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

  // The same rule again, for the two sheets it was never applied to. The
  // handler stated it in general terms -- a sheet the user can no longer see
  // must not stay answerable -- and called it on the vault's approval alone,
  // so an untapped `sudo` and an untapped SSH signature survived a trip to
  // the background still live. Those are the two that grant more than a
  // copied password does.
  testWidgets('leaving refuses the sudo and the ssh prompt too', (
    tester,
  ) async {
    final session = _IdleSession();
    final transport = _LifecycleTransport(session);
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);

    late InteractiveSshApproval ssh;
    late InteractiveAuthorizer auth;
    WidgetRef? reader;
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
            ssh = ref.watch(sshApprovalProvider);
            auth = ref.watch(interactiveAuthorizerProvider);
            reader = ref;
            return const PhoneAuthApp();
          },
        ),
      ),
    );
    // Settled, not pumped once: the paired list arrives from an async provider,
    // and until it has been reflected into the devices list the controller
    // knows of no desktop to attribute a request to. In the app nothing can
    // arrive that early -- the session runner learns which desktops to dial
    // from the same provider -- so pumping only once would model an order the
    // transport cannot produce.
    await tester.pumpAndSettle();

    bool? signed;
    unawaited(
      ssh
          .confirm(
            const SshApprovalRequest(
              id: 'ssh-1',
              verifierName: 'desktop-1',
              user: 'alice',
              destination: 'git@github.com',
            ),
          )
          .then((value) => signed = value),
    );
    bool? approved;
    unawaited(
      auth.confirm(_sudoRequest, _properties).then((value) => approved = value),
    );
    await tester.pumpAndSettle();
    expect(ssh.pendingRequestIds, contains('ssh-1'));
    expect(auth.pendingRequestIds, contains('request-1'));
    // Asked of the controller, not only of the authorizer. The authorizer
    // holds whatever `confirm` was called with, whether or not it survived the
    // checks in `receive` -- so on its own it cannot tell a prompt that came
    // down from one that was never up.
    expect(
      reader!.read(appControllerProvider).requests.map((item) => item.id),
      contains('request-1'),
      reason: 'the sudo is on screen before anything is asked to refuse it',
    );

    // Same carve-out as the vault's: losing focus is the biometric prompt
    // going up, not the user walking away.
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
    await tester.pump();
    expect(signed, isNull);
    expect(approved, isNull);

    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.hidden);
    await tester.pump();
    expect(signed, isFalse, reason: 'an ssh signature nobody read is refused');
    expect(approved, isFalse, reason: 'so is a sudo nobody read');

    await tester.pumpWidget(const SizedBox.shrink());
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
  });
}

final _sudoNow = DateTime.now().toUtc();

/// Dated from the clock, not from a constant.
///
/// It used to carry a fixed August 2026 window, which stopped being a live
/// request the day after it was written: `AppController.receive` drops an
/// expired one before it ever reaches a sheet. The test still passed, because
/// it asked the authorizer what it was holding rather than the screen what it
/// was showing -- so it proved the prompt came down without ever proving the
/// prompt went up.
final _sudoRequest = AuthenticationRequest(
  requestId: 'request-1',
  verifierId: 'desktop-1',
  verifierName: 'Desktop-NixOS',
  credentialId: 'credential-1',
  challenge: Uint8List(32),
  origin: 'replaced by session',
  service: 'sudo',
  action: 'nixos-rebuild switch',
  resource: 'Desktop-NixOS',
  user: 'alice',
  issuedAt: _sudoNow,
  expiresAt: _sudoNow.add(const Duration(minutes: 1)),
  sessionBinding: Uint8List(32),
);

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

/// A pairing service that hands back one session, without a network.
class _StubPairingService extends PairingService {
  _StubPairingService(this.session)
    : super(
        transport: _LifecycleTransport(_IdleSession()),
        store: InMemoryPairingStore(),
        deviceName: 'test phone',
      );

  final SecureTransportSession session;

  @override
  Future<PairingSession> begin(String scannedUri) async => PairingSession(
    verificationCode: '123456',
    proposed: _record,
    session: session,
    store: InMemoryPairingStore(),
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
