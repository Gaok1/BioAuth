import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/core/pairing/pairing_record.dart';
import 'package:phone_auth/core/pairing/pairing_service.dart';
import 'package:phone_auth/core/pairing/pairing_store.dart';
import 'package:phone_auth/core/protocol/enrolment.dart';
import 'package:phone_auth/core/transport/auth_transport.dart';

void main() {
  test(
    'a close failure after the local commit does not undo pairing',
    () async {
      final store = InMemoryPairingStore();
      final record = PairingRecord(
        verifierId: 'desktop-1',
        verifierIdentitySpki: Uint8List.fromList([1, 2, 3]),
        endpoint: '192.0.2.1:42371',
        credentialId: 'desktop-1-authorization-v1',
        keyKind: KeyKind.hardware,
        purpose: CredentialPurpose.authorization,
        pairedAt: DateTime.utc(2026, 8, 27),
      );
      final pairing = PairingSession(
        verificationCode: '123456',
        proposed: record,
        session: _CloseFailsSession(),
        store: store,
      );

      await expectLater(pairing.confirm(), completes);
      expect((await store.load()).single.verifierId, 'desktop-1');
    },
  );
}

class _CloseFailsSession implements SecureTransportSession {
  @override
  String get originLabel => 'test';

  @override
  Uint8List get sessionBinding => Uint8List(32);

  @override
  TransportSecurityProperties get securityProperties =>
      const TransportSecurityProperties(
        transportName: 'test',
        confidential: true,
        peerAuthenticated: true,
        requiresNetwork: false,
        proximitySignal: false,
        expectedLatency: Duration.zero,
      );

  @override
  Stream<Uint8List> get incomingFrames => const Stream.empty();

  @override
  Future<void> send(Uint8List frame) async {}

  @override
  Future<void> close() => Future.error(StateError('desktop closed first'));
}
