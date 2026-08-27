import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/core/transport/auth_transport.dart';
import 'package:phone_auth/core/transport/fallback_auth_transport.dart';
import 'package:phone_auth/core/transport/pairing_bootstrap.dart';
import 'package:phone_auth/core/transport/secure_session_establisher.dart';

void main() {
  final identity = Uint8List.fromList([1, 2, 3]);

  test('a paired verifier falls back from its saved endpoint to BLE', () async {
    final primary = _TestTransport(error: StateError('LAN unavailable'));
    final fallback = _TestTransport(
      peers: const [
        TransportPeer(transportId: 'wrong', displayName: 'Outro PC'),
        TransportPeer(transportId: 'right', displayName: 'Meu PC'),
      ],
      errors: {'wrong': StateError('verifier identity mismatch')},
      outcome: _outcome(_TestSession()),
    );
    final transport = FallbackAuthTransport(
      primary: primary,
      discoveredFallback: fallback,
      discoveryTimeout: const Duration(milliseconds: 50),
    );

    final result = await transport.connect(
      const TransportPeer(
        transportId: '192.0.2.1:42371',
        displayName: 'desktop-1',
      ),
      PairedVerifier(identity),
    );

    expect(primary.connectedIds, ['192.0.2.1:42371']);
    expect(fallback.connectedIds, ['wrong', 'right']);
    expect(fallback.starts, 2);
    expect(fallback.stops, 2);
    expect(result.session.securityProperties.requiresNetwork, isFalse);
    await result.session.close();
  });

  test(
    'first contact never escapes the endpoint committed by the QR',
    () async {
      final failure = StateError('QR endpoint unavailable');
      final primary = _TestTransport(error: failure);
      final fallback = _TestTransport(
        peers: const [TransportPeer(transportId: 'ble', displayName: 'PC')],
        outcome: _outcome(_TestSession()),
      );
      final transport = FallbackAuthTransport(
        primary: primary,
        discoveredFallback: fallback,
      );

      await expectLater(
        transport.connect(
          const TransportPeer(transportId: 'qr-endpoint', displayName: 'PC'),
          ScannedVerifier(
            PairingBootstrap(
              sessionId: 'session-1',
              nonce: Uint8List(32),
              verifierId: 'desktop-1',
              verifierIdentityHash: Uint8List(32),
              endpoint: 'qr-endpoint',
              expiresAtMs: 4102444800000,
            ),
          ),
        ),
        throwsA(same(failure)),
      );
      expect(fallback.starts, 0);
      expect(fallback.connectedIds, isEmpty);
    },
  );

  test(
    'the native BLE slot is released only when its session closes',
    () async {
      final fallback = _TestTransport(
        peers: const [TransportPeer(transportId: 'ble', displayName: 'PC')],
        outcomeFactory: () => _outcome(_TestSession()),
      );
      final transport = FallbackAuthTransport(
        primary: _TestTransport(error: StateError('offline')),
        discoveredFallback: fallback,
        discoveryTimeout: const Duration(milliseconds: 50),
      );
      final peer = const TransportPeer(transportId: 'LAN', displayName: 'PC');

      final first = await transport.connect(peer, PairedVerifier(identity));
      var secondCompleted = false;
      final secondFuture = transport
          .connect(peer, PairedVerifier(identity))
          .then((value) {
            secondCompleted = true;
            return value;
          });
      await Future<void>.delayed(Duration.zero);
      expect(secondCompleted, isFalse);

      await first.session.close();
      final second = await secondFuture;
      expect(secondCompleted, isTrue);
      await second.session.close();
    },
  );
}

class _TestTransport implements AuthTransport {
  _TestTransport({
    this.error,
    this.peers = const [],
    this.errors = const {},
    this.outcome,
    this.outcomeFactory,
  });

  final Object? error;
  final List<TransportPeer> peers;
  final Map<String, Object> errors;
  final SecureSessionOutcome? outcome;
  final SecureSessionOutcome Function()? outcomeFactory;
  final List<String> connectedIds = [];
  int starts = 0;
  int stops = 0;

  @override
  TransportSecurityProperties get securityProperties => _properties;

  @override
  Future<void> start() async {
    starts++;
  }

  @override
  Future<void> stop() async {
    stops++;
  }

  @override
  Stream<TransportPeer> discoverPeers() => Stream.fromIterable(peers);

  @override
  Future<SecureSessionOutcome> connect(
    TransportPeer peer,
    VerifierExpectation expectation,
  ) async {
    connectedIds.add(peer.transportId);
    final peerError = errors[peer.transportId] ?? error;
    if (peerError != null) throw peerError;
    return outcomeFactory?.call() ?? outcome!;
  }
}

SecureSessionOutcome _outcome(SecureTransportSession session) =>
    SecureSessionOutcome(
      session: session,
      verifierIdentitySpki: Uint8List.fromList([1, 2, 3]),
      verifierId: 'desktop-1',
      sessionId: 'session-1',
      verificationCode: '123456',
      wasPairing: false,
    );

class _TestSession implements SecureTransportSession {
  bool closed = false;

  @override
  String get originLabel => 'BLE';

  @override
  Uint8List get sessionBinding => Uint8List(32);

  @override
  TransportSecurityProperties get securityProperties => _properties;

  @override
  Stream<Uint8List> get incomingFrames => const Stream.empty();

  @override
  Future<void> send(Uint8List frame) async {}

  @override
  Future<void> close() async {
    closed = true;
  }
}

const _properties = TransportSecurityProperties(
  transportName: 'BleTransport',
  confidential: true,
  peerAuthenticated: true,
  requiresNetwork: false,
  proximitySignal: true,
  expectedLatency: Duration(milliseconds: 250),
);
