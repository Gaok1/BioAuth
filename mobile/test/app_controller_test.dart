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
