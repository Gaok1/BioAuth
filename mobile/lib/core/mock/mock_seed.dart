import 'dart:typed_data';

import '../../domain/app_seed.dart';
import '../../domain/authentication_request.dart';
import '../../domain/connection_phase.dart';
import '../../domain/desktop_device.dart';

AppSeed buildMockSeed([DateTime? at]) {
  final now = at ?? DateTime.now().toUtc();
  return AppSeed(
    devices: [
      DesktopDevice(
        id: 'desktop-casa',
        name: 'Desktop-Casa',
        phase: ConnectionPhase.connected,
        lastSeen: now,
      ),
      DesktopDevice(
        id: 'notebook',
        name: 'Notebook',
        phase: ConnectionPhase.disconnected,
        lastSeen: now.subtract(const Duration(days: 1)),
      ),
    ],
    requests: [
      AuthenticationRequest(
        requestId: 'mock-request-1',
        verifierId: 'desktop-casa',
        verifierName: 'Desktop-Casa',
        credentialId: 'desktop-casa-login-v1',
        challenge: Uint8List.fromList(List<int>.generate(32, (index) => index)),
        origin: 'QrNetworkTransport • pareado',
        service: 'SSH',
        action: 'Iniciar sessão',
        resource: 'prod-server',
        user: 'alice',
        issuedAt: now,
        expiresAt: now.add(const Duration(minutes: 1)),
        sessionBinding: Uint8List.fromList(
          List<int>.generate(32, (index) => 255 - index),
        ),
      ),
    ],
  );
}
