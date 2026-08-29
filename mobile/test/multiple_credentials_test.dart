/// One computer, several credentials.
///
/// This became reachable the moment a pairing could say what it was for: a
/// desktop can hold a login credential and a vault one at the same time, and
/// they are different keys with different powers. Everything keyed by verifier
/// alone was wrong under that — the store deleted the first pairing when the
/// second arrived, the runner never gave the second a loop, and the list
/// showed the same computer twice.
library;

import 'dart:typed_data';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/app/app_controller.dart';
import 'package:phone_auth/app/config.dart';
import 'package:phone_auth/app/providers.dart';
import 'package:phone_auth/core/pairing/pairing_record.dart';
import 'package:phone_auth/core/pairing/pairing_store.dart';
import 'package:phone_auth/core/protocol/enrolment.dart';
import 'package:phone_auth/domain/connection_phase.dart';

PairingRecord recordFor(
  CredentialPurpose purpose, {
  String verifierId = 'desktop-1',
}) => PairingRecord(
  verifierId: verifierId,
  verifierIdentitySpki: Uint8List(91),
  endpoint: '192.168.1.10:8765',
  credentialId: '$verifierId-${purpose.name}-v1',
  keyKind: KeyKind.hardware,
  purpose: purpose,
  pairedAt: DateTime.utc(2026, 8, 29),
);

void main() {
  /// A controller with an empty seed: this file is about what the store puts
  /// on the list, not about the development fixtures.
  AppController controller() {
    final container = ProviderContainer(
      overrides: [
        appConfigProvider.overrideWithValue(const AppConfig.production()),
        pairingStoreProvider.overrideWithValue(InMemoryPairingStore()),
      ],
    );
    addTearDown(container.dispose);
    return container.read(appControllerProvider.notifier);
  }

  /// The bug this file was written for. Pairing the vault used to delete the
  /// login pairing, and nothing on screen said so — `sudo` simply stopped
  /// working, on a phone that still listed the computer.
  test('a second pairing with one desktop does not evict the first', () async {
    final store = InMemoryPairingStore();

    await store.save(recordFor(CredentialPurpose.authorization));
    await store.save(recordFor(CredentialPurpose.vault));

    final stored = await store.load();
    expect(stored.map((record) => record.purpose), [
      CredentialPurpose.authorization,
      CredentialPurpose.vault,
    ]);
  });

  test(
    're-pairing the same credential replaces it rather than duplicating',
    () async {
      final store = InMemoryPairingStore();

      await store.save(recordFor(CredentialPurpose.vault));
      await store.save(recordFor(CredentialPurpose.vault));

      expect(await store.load(), hasLength(1));
    },
  );

  /// Revocation is about the computer, not one of its keys: someone who no
  /// longer trusts a desktop does not mean "except for the vault".
  test('revoking a desktop takes every credential it held', () async {
    final store = InMemoryPairingStore();
    await store.save(recordFor(CredentialPurpose.authorization));
    await store.save(recordFor(CredentialPurpose.ssh));
    await store.save(recordFor(CredentialPurpose.vault, verifierId: 'other'));

    await store.remove('desktop-1');

    expect((await store.load()).map((record) => record.verifierId), ['other']);
  });

  test(
    'the devices list shows one row per computer, naming its credentials',
    () {
      final app = controller()
        ..syncPairedDevices([
          recordFor(CredentialPurpose.authorization),
          recordFor(CredentialPurpose.vault),
          recordFor(CredentialPurpose.ssh, verifierId: 'laptop'),
        ]);

      final devices = app.state.devices;
      expect(devices.map((device) => device.id), ['desktop-1', 'laptop']);
      expect(devices.first.purposes, [
        CredentialPurpose.authorization,
        CredentialPurpose.vault,
      ]);
      expect(devices.last.purposes, [CredentialPurpose.ssh]);
    },
  );

  /// The row keeps the connection state it already had; only the credential
  /// list is refreshed. Rebuilding it would flash every desktop back to
  /// "connecting" whenever any pairing changed.
  test('a re-sync does not reset what the list already knew', () {
    final app = controller()
      ..syncPairedDevices([recordFor(CredentialPurpose.authorization)])
      ..setDevicePhase('desktop-1', ConnectionPhase.connected)
      ..syncPairedDevices([
        recordFor(CredentialPurpose.authorization),
        recordFor(CredentialPurpose.vault),
      ]);

    final device = app.state.devices.single;
    expect(device.phase, ConnectionPhase.connected);
    expect(device.purposes, hasLength(2));
  });
}
