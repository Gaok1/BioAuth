import 'dart:async';
import 'dart:convert';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/core/auth/interactive_authorizer.dart';
import 'package:phone_auth/core/mock/fake_biometric_authorizer.dart';
import 'package:phone_auth/core/pairing/pairing_record.dart';
import 'package:phone_auth/core/protocol/enrolment.dart';
import 'package:phone_auth/core/session/paired_session_service.dart';
import 'package:phone_auth/core/transport/auth_transport.dart';
import 'package:phone_auth/core/transport/secure_session_establisher.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const channel = MethodChannel('phone_auth_native');

  test(
    'desktop cancellation dismisses native relay and returns a bound denial',
    () async {
      final nativeResult = Completer<Object?>();
      var cancelled = false;
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (call) async {
            if (call.method == 'performWebAuthn') return nativeResult.future;
            if (call.method == 'cancelWebAuthn') {
              cancelled = true;
              nativeResult.completeError(
                PlatformException(code: 'webauthn_cancelled'),
              );
              return null;
            }
            throw MissingPluginException();
          });
      addTearDown(() {
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
            .setMockMethodCallHandler(channel, null);
      });

      final transport = _RelayTransport();
      final service = PairedSessionService(
        transport: transport,
        authorizer: await FakeBiometricAuthorizer.create(),
        consent: InteractiveAuthorizer(onRequest: (_) {}),
      );
      final serving = service.serveOne(_record);
      await transport.connected.future;
      transport.session.incoming.add(
        _frame({
          'version': 1,
          'type': 'webauthn.request',
          'requestId': 'request-1',
          'verifierId': 'desktop-1',
          'operation': 'get',
          'origin': 'https://login.example.com',
          'options': {
            'rpId': 'example.com',
            'challenge': 'AAECAwQFBgcICQoLDA0ODw',
          },
        }),
      );
      await Future<void>.delayed(Duration.zero);
      transport.session.incoming.add(
        _frame({
          'version': 1,
          'type': 'webauthn.cancel',
          'requestId': 'request-1',
        }),
      );

      await serving;
      final response =
          jsonDecode(utf8.decode(transport.session.outgoing.single.sublist(6)))
              as Map<String, dynamic>;
      expect(cancelled, isTrue);
      expect(response['requestId'], 'request-1');
      expect(response['ok'], isFalse);
    },
  );
}

Uint8List _frame(Map<String, Object?> value) => Uint8List.fromList([
  ...utf8.encode('BAWA1\n'),
  ...utf8.encode(jsonEncode(value)),
]);

final _record = PairingRecord(
  verifierId: 'desktop-1',
  verifierIdentitySpki: Uint8List.fromList([1, 2, 3]),
  endpoint: 'fake',
  credentialId: 'credential-1',
  keyKind: KeyKind.hardware,
  purpose: CredentialPurpose.webAuthn,
  pairedAt: DateTime.utc(2026, 8, 28),
);

class _RelayTransport implements AuthTransport {
  final connected = Completer<void>();
  final session = _RelaySession();

  @override
  TransportSecurityProperties get securityProperties =>
      session.securityProperties;

  @override
  Future<SecureSessionOutcome> connect(
    TransportPeer selectedPeer,
    VerifierExpectation expectation,
  ) async {
    connected.complete();
    return SecureSessionOutcome(
      session: session,
      verifierIdentitySpki: Uint8List.fromList([1, 2, 3]),
      verifierId: 'desktop-1',
      sessionId: 'session-1',
      verificationCode: '000000',
      wasPairing: false,
    );
  }

  @override
  Stream<TransportPeer> discoverPeers() => const Stream.empty();

  @override
  Future<void> start() async {}

  @override
  Future<void> stop() async {}
}

class _RelaySession implements SecureTransportSession {
  final incoming = StreamController<Uint8List>();
  final outgoing = <Uint8List>[];

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
  Stream<Uint8List> get incomingFrames => incoming.stream;

  @override
  Future<void> send(Uint8List frame) async => outgoing.add(frame);

  @override
  Future<void> close() async => incoming.close();
}
