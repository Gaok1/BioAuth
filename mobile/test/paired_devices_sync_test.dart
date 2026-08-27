import 'dart:typed_data';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/app/app_controller.dart';
import 'package:phone_auth/app/providers.dart';
import 'package:phone_auth/core/pairing/pairing_record.dart';
import 'package:phone_auth/core/pairing/pairing_store.dart';
import 'package:phone_auth/core/protocol/enrolment.dart';

void main() {
  test(
    'stored pairings populate devices without waiting for transport',
    () async {
      final store = InMemoryPairingStore(
        seed: [
          PairingRecord(
            verifierId: 'desktop-1',
            verifierIdentitySpki: Uint8List.fromList([1, 2, 3]),
            endpoint: '192.0.2.1:42371',
            credentialId: 'desktop-1-authorization-v1',
            keyKind: KeyKind.hardware,
            purpose: CredentialPurpose.authorization,
            pairedAt: DateTime.utc(2026, 8, 27),
          ),
        ],
      );
      final container = ProviderContainer(
        overrides: [pairingStoreProvider.overrideWithValue(store)],
      );
      addTearDown(container.dispose);

      container.read(pairedDevicesSyncProvider);
      await container.read(pairedVerifiersProvider.future);
      await Future<void>.delayed(Duration.zero);

      expect(
        container.read(appControllerProvider).devices.single.id,
        'desktop-1',
      );
      expect(container.read(appControllerProvider).onboardingComplete, isTrue);
    },
  );
}
