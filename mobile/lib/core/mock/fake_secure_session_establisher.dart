import 'dart:typed_data';

import '../transport/auth_transport.dart';
import '../transport/secure_session_establisher.dart';
import 'fake_session_binding.dart';

class FakeSecureSessionEstablisher implements SecureSessionEstablisher {
  const FakeSecureSessionEstablisher();

  @override
  Future<SecureTransportSession> establish(
    RawTransportLink link,
    SessionBootstrap bootstrap,
  ) async =>
      _FakeSecureSession(link, await deriveFakeSessionBinding(bootstrap));
}

class _FakeSecureSession implements SecureTransportSession {
  _FakeSecureSession(this._link, Uint8List sessionBinding)
    : _sessionBinding = Uint8List.fromList(sessionBinding);

  final RawTransportLink _link;
  final Uint8List _sessionBinding;

  @override
  String get originLabel => '${_link.originLabel} • fake secure session';

  @override
  Uint8List get sessionBinding => Uint8List.fromList(_sessionBinding);

  @override
  TransportSecurityProperties get securityProperties =>
      TransportSecurityProperties(
        transportName: _link.rawSecurityProperties.transportName,
        confidential: true,
        peerAuthenticated: true,
        requiresNetwork: _link.rawSecurityProperties.requiresNetwork,
        proximitySignal: _link.rawSecurityProperties.proximitySignal,
        expectedLatency: _link.rawSecurityProperties.expectedLatency,
      );

  @override
  Stream<Uint8List> get incomingFrames => _link.incomingFrames;

  @override
  Future<void> send(Uint8List frame) => _link.send(frame);

  @override
  Future<void> close() => _link.close();
}
