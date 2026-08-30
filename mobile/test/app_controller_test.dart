import 'dart:async';
import 'dart:typed_data';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/app/app_controller.dart';
import 'package:phone_auth/app/config.dart';
import 'package:phone_auth/app/providers.dart';
import 'package:phone_auth/core/mock/fake_phone_authenticator.dart';
import 'package:phone_auth/core/pairing/pairing_store.dart';
import 'package:phone_auth/core/mock/mock_seed.dart';
import 'package:phone_auth/domain/audit_entry.dart';
import 'package:phone_auth/domain/authentication_request.dart';
import 'package:phone_auth/core/transport/auth_transport.dart';
import 'package:phone_auth/domain/connection_phase.dart';

void main() {
  late DateTime now;
  late ProviderContainer container;

  setUp(() {
    now = DateTime.now().toUtc();
    container = ProviderContainer(
      overrides: [
        appConfigProvider.overrideWithValue(
          AppConfig.development(buildMockSeed(now)),
        ),
        phoneAuthenticatorProvider.overrideWithValue(
          const FakePhoneAuthenticator(),
        ),
        pairingStoreProvider.overrideWithValue(InMemoryPairingStore()),
      ],
    );
    addTearDown(container.dispose);
  });

  test('approval follows biometric and signing states', () async {
    final phases = <ConnectionPhase>[];
    container.listen(
      appControllerProvider,
      (_, next) => phases.addAll(next.requestPhases.values),
      fireImmediately: true,
    );

    await container
        .read(appControllerProvider.notifier)
        .approve('mock-request-1', at: now);

    final state = container.read(appControllerProvider);
    expect(phases, contains(ConnectionPhase.awaitingBiometric));
    expect(phases, contains(ConnectionPhase.signing));
    expect(state.requests, isEmpty);
    expect(state.auditEntries.single.outcome, AuditOutcome.approved);
  });

  test('expired requests are never authorized', () async {
    await container
        .read(appControllerProvider.notifier)
        .approve('mock-request-1', at: now.add(const Duration(minutes: 2)));

    final state = container.read(appControllerProvider);
    expect(state.auditEntries.single.outcome, AuditOutcome.expired);
    expect(state.requestPhases['mock-request-1'], ConnectionPhase.expired);
  });

  test('duplicates are grouped and flood can block a device', () {
    final controller = container.read(appControllerProvider.notifier);
    AuthenticationRequest incoming(int index) => AuthenticationRequest(
      requestId: 'incoming-$index',
      verifierId: 'desktop-casa',
      verifierName: 'Desktop-Casa',
      credentialId: 'desktop-casa-login-v1',
      challenge: Uint8List.fromList(List<int>.filled(32, index)),
      origin: 'BLE pareado',
      service: 'SSH',
      action: 'Login',
      resource: 'server-$index',
      user: 'alice',
      issuedAt: now,
      expiresAt: now.add(const Duration(minutes: 1)),
      sessionBinding: Uint8List(32),
    );

    for (var i = 0; i < 6; i++) {
      controller.receive(incoming(i), at: now.add(Duration(seconds: i)));
    }

    expect(container.read(appControllerProvider).securityWarning, isNotNull);
    controller.blockDevice('desktop-casa', at: now);
    final device = container
        .read(appControllerProvider)
        .devices
        .firstWhere((item) => item.id == 'desktop-casa');
    expect(device.phase, ConnectionPhase.disconnected);
    expect(device.isBlockedAt(now), isTrue);
  });

  test('a repeat folded into a sheet is answered, not left hanging', () async {
    // Running `sudo` twice inside the guard's window is the ordinary way to
    // make one: the fingerprint covers the verifier, credential, service,
    // action, resource and user, and not the request id. The screen groups the
    // repeat into the sheet already up and shows a count, which is the right
    // thing to show -- and used to be the wrong thing to answer. Only the
    // sheet's own request was ever settled, so the repeat's session sat
    // unanswered until its deadline.
    final authorizer = container.read(interactiveAuthorizerProvider);
    AuthenticationRequest twin(String id) => AuthenticationRequest(
      requestId: id,
      verifierId: 'desktop-casa',
      verifierName: 'Desktop-Casa',
      credentialId: 'desktop-casa-login-v1',
      challenge: Uint8List.fromList(List<int>.filled(32, id.length)),
      origin: 'BLE pareado',
      service: 'sudo',
      action: 'nixos-rebuild switch',
      resource: 'Desktop-Casa',
      user: 'alice',
      issuedAt: now,
      expiresAt: now.add(const Duration(minutes: 1)),
      sessionBinding: Uint8List(32),
    );

    bool? onScreen;
    unawaited(
      authorizer.confirm(twin('first'), _properties).then((v) => onScreen = v),
    );
    bool? repeat;
    unawaited(
      authorizer.confirm(twin('second-x'), _properties).then((v) => repeat = v),
    );
    await pumpEventQueue();

    // Filtered rather than counted: the mock seed the container is built with
    // puts its own request on the list, and this is about the two twins.
    final sheets = container
        .read(appControllerProvider)
        .requests
        .where((candidate) => candidate.service == 'sudo');
    expect(sheets, hasLength(1), reason: 'one sheet, not two');
    expect(
      sheets.single.duplicateCount,
      2,
      reason: 'the count is occurrences, and it starts at one',
    );
    expect(
      onScreen,
      isNull,
      reason: 'the sheet on screen still waits on a tap',
    );
    expect(
      repeat,
      isFalse,
      reason:
          'the repeat cannot share the sheet answer -- a different request id '
          'is a different payload and its own signature -- so it has to be '
          'refused rather than left waiting out its deadline',
    );
  });

  test('a flooded request is refused rather than left waiting', () async {
    final authorizer = container.read(interactiveAuthorizerProvider);
    AuthenticationRequest incoming(int index) => AuthenticationRequest(
      requestId: 'flood-$index',
      verifierId: 'desktop-casa',
      verifierName: 'Desktop-Casa',
      credentialId: 'desktop-casa-login-v1',
      challenge: Uint8List.fromList(List<int>.filled(32, index)),
      origin: 'BLE pareado',
      service: 'SSH',
      action: 'Login',
      resource: 'server-$index',
      user: 'alice',
      issuedAt: now,
      expiresAt: now.add(const Duration(minutes: 1)),
      sessionBinding: Uint8List(32),
    );

    final answers = <int, bool>{};
    for (var i = 0; i < 6; i++) {
      unawaited(
        authorizer
            .confirm(incoming(i), _properties)
            .then((v) => answers[i] = v),
      );
    }
    await pumpEventQueue();

    expect(container.read(appControllerProvider).securityWarning, isNotNull);
    expect(
      answers[5],
      isFalse,
      reason:
          'the device is hammering and gets no sheet, so it gets a refusal -- '
          'holding the session open until its deadline answers nobody',
    );
  });

  test('denial and revocation update local state', () async {
    final controller = container.read(appControllerProvider.notifier);
    controller.deny('mock-request-1', at: now);
    expect(
      container.read(appControllerProvider).auditEntries.single.outcome,
      AuditOutcome.denied,
    );

    // Revocation now writes through to the store before touching the screen,
    // so it is asynchronous and needs somewhere to write.
    await controller.revokeDevice('notebook');
    expect(
      container
          .read(appControllerProvider)
          .devices
          .any((device) => device.id == 'notebook'),
      isFalse,
    );
  });
}

const _properties = TransportSecurityProperties(
  transportName: 'test',
  confidential: true,
  peerAuthenticated: true,
  requiresNetwork: false,
  proximitySignal: false,
  expectedLatency: Duration.zero,
);
