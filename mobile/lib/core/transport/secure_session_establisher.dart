import 'dart:typed_data';

import 'auth_transport.dart';

abstract interface class RawTransportLink {
  String get originLabel;

  TransportSecurityProperties get rawSecurityProperties;

  Stream<Uint8List> get incomingFrames;

  Future<void> send(Uint8List frame);

  Future<void> close();
}

abstract interface class SecureSessionEstablisher {
  Future<SecureTransportSession> establish(
    RawTransportLink link,
    SessionBootstrap bootstrap,
  );
}
