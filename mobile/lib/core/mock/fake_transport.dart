import 'dart:async';
import 'dart:typed_data';

import '../transport/auth_transport.dart';
import '../transport/secure_session_establisher.dart';
import 'fake_session_binding.dart';

class FakeTransport implements AuthTransport {
  FakeTransport();

  static const peer = TransportPeer(
    transportId: 'fake-verifier',
    displayName: 'Fake verifier',
  );

  final _discovery = StreamController<TransportPeer>.broadcast();
  bool _started = false;
  FakeSecureTransportSession? _verifierSession;

  @override
  TransportSecurityProperties get securityProperties =>
      const TransportSecurityProperties(
        transportName: 'FakeTransport',
        confidential: true,
        peerAuthenticated: true,
        requiresNetwork: false,
        proximitySignal: false,
        expectedLatency: Duration.zero,
      );

  FakeSecureTransportSession get verifierSession =>
      _verifierSession ??
      (throw StateError('connect() must be called before verifierSession'));

  @override
  Future<void> start() async {
    if (_started) return;
    _started = true;
    _discovery.add(peer);
  }

  @override
  Future<void> stop() async {
    _started = false;
    await _verifierSession?.close();
    await _discovery.close();
  }

  @override
  Stream<TransportPeer> discoverPeers() => _discovery.stream;

  @override
  Future<SecureSessionOutcome> connect(
    TransportPeer selectedPeer,
    VerifierExpectation expectation,
  ) async {
    if (!_started || selectedPeer.transportId != peer.transportId) {
      throw StateError('Fake peer is unavailable');
    }
    if (expectation case ScannedVerifier(:final bootstrap)) {
      if (bootstrap.isExpiredAt(
        DateTime.now().toUtc().millisecondsSinceEpoch,
      )) {
        throw StateError('Session bootstrap expired');
      }
    }

    final sessionBinding = await deriveFakeSessionBinding(expectation);
    final mobileIncoming = StreamController<Uint8List>();
    final verifierIncoming = StreamController<Uint8List>();
    final mobile = FakeSecureTransportSession(
      originLabel: 'FakeTransport • authenticated test peer',
      sessionBinding: sessionBinding,
      securityProperties: securityProperties,
      incoming: mobileIncoming,
      outgoing: verifierIncoming,
    );
    _verifierSession = FakeSecureTransportSession(
      originLabel: 'FakeTransport • mobile',
      sessionBinding: sessionBinding,
      securityProperties: securityProperties,
      incoming: verifierIncoming,
      outgoing: mobileIncoming,
    );
    return SecureSessionOutcome(
      session: mobile,
      verifierIdentitySpki: Uint8List.fromList(List<int>.filled(91, 0xa0)),
      verifierId: switch (expectation) {
        ScannedVerifier(:final bootstrap) => bootstrap.verifierId,
        PairedVerifier() => 'fake-verifier',
      },
      sessionId: 'fake-session',
      verificationCode: '000000',
      wasPairing: expectation is ScannedVerifier,
    );
  }
}

class FakeSecureTransportSession implements SecureTransportSession {
  FakeSecureTransportSession({
    required this.originLabel,
    required Uint8List sessionBinding,
    required this.securityProperties,
    required StreamController<Uint8List> incoming,
    required StreamController<Uint8List> outgoing,
  }) : _sessionBinding = Uint8List.fromList(sessionBinding),
       _incoming = incoming,
       _outgoing = outgoing;

  @override
  final String originLabel;

  final Uint8List _sessionBinding;
  final StreamController<Uint8List> _incoming;
  final StreamController<Uint8List> _outgoing;
  bool _closed = false;

  @override
  Uint8List get sessionBinding => Uint8List.fromList(_sessionBinding);

  @override
  final TransportSecurityProperties securityProperties;

  @override
  Stream<Uint8List> get incomingFrames => _incoming.stream;

  @override
  Future<void> send(Uint8List frame) async {
    if (_closed) throw StateError('Session is closed');
    _outgoing.add(Uint8List.fromList(frame));
  }

  @override
  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    await _incoming.close();
  }
}
