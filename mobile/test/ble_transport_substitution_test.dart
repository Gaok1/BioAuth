import 'dart:async';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/core/bluetooth/ble_transport.dart';
import 'package:phone_auth/core/mock/fake_biometric_authorizer.dart';
import 'package:phone_auth/core/mock/fake_secure_session_establisher.dart';
import 'package:phone_auth/core/protocol/auth_response.dart';
import 'package:phone_auth/core/protocol/protocol_codec.dart';
import 'package:phone_auth/core/session/phone_auth_core.dart';
import 'package:phone_auth/core/transport/auth_transport.dart';
import 'package:phone_auth/core/transport/secure_session_establisher.dart';
import 'package:phone_auth/domain/authentication_request.dart';

void main() {
  test(
    'BleTransport replaces FakeTransport without changing PhoneAuth Core',
    () async {
      final now = DateTime.utc(2026, 8, 26, 12);
      final client = _FakeBleClient();
      final transport = BleTransport(
        sessionEstablisher: const FakeSecureSessionEstablisher(),
        client: client,
        permissionGate: const _GrantedBlePermissions(),
      );
      final discovery = transport.discoverPeers().first;
      await transport.start();
      final mobileSession = await transport.connect(
        await discovery,
        SessionBootstrap(
          sessionId: 'ble-session',
          verifierId: 'desktop-1',
          nonce: Uint8List(32),
          ephemeralPublicKey: Uint8List(32),
          verifierIdentityPublicKey: Uint8List.fromList([1]),
          expiresAt: DateTime.now().toUtc().add(const Duration(minutes: 1)),
        ),
      );
      final request = AuthenticationRequest(
        requestId: 'ble-request',
        verifierId: 'desktop-1',
        verifierName: 'Desktop-NixOS',
        credentialId: 'sudo-v1',
        challenge: Uint8List.fromList(List<int>.filled(32, 7)),
        origin: 'ignored',
        service: 'sudo',
        action: 'nixos-rebuild switch',
        resource: 'Desktop-NixOS',
        user: 'alice',
        issuedAt: now,
        expiresAt: now.add(const Duration(minutes: 1)),
        sessionBinding: mobileSession.sessionBinding,
      );
      final authorizer = await FakeBiometricAuthorizer.create();
      final core = PhoneAuthCore(
        authorizer: authorizer,
        consent: const FakeAuthorizationConsent(),
        policy: const VerifierPolicy(
          verifierId: 'desktop-1',
          credentialId: 'sudo-v1',
          permissions: [
            VerifierPermission(service: 'sudo', action: 'nixos-rebuild switch'),
          ],
        ),
        clock: () => now,
      );
      const codec = PhoneAuthProtocolCodec();

      final serving = core.serveOne(mobileSession);
      await client.verifierLink.send(codec.encodeRequest(request));
      final response = codec.decodeResponse(
        await client.verifierLink.incomingFrames.first,
      );
      await serving;

      expect(response.decision, AuthorizationDecision.authorized);
      expect(
        await Ed25519().verify(
          codec.encodeRequest(request),
          signature: Signature(
            response.signature,
            publicKey: authorizer.publicKey,
          ),
        ),
        isTrue,
      );
      await transport.stop();
    },
  );
}

class _GrantedBlePermissions implements BlePermissionGate {
  const _GrantedBlePermissions();

  @override
  Future<bool> ensureGranted() async => true;
}

class _FakeBleClient implements BleClient {
  late _FakeRawLink verifierLink;

  @override
  Stream<BlePeer> scan() => Stream.value(
    const BlePeer(connectionId: 'ble-connection', displayName: 'Desktop-NixOS'),
  );

  @override
  Future<RawTransportLink> connect(String connectionId) async {
    final mobileIncoming = StreamController<Uint8List>();
    final verifierIncoming = StreamController<Uint8List>();
    verifierLink = _FakeRawLink(
      incoming: verifierIncoming,
      outgoing: mobileIncoming,
    );
    return _FakeRawLink(incoming: mobileIncoming, outgoing: verifierIncoming);
  }
}

class _FakeRawLink implements RawTransportLink {
  _FakeRawLink({required this.incoming, required this.outgoing});

  final StreamController<Uint8List> incoming;
  final StreamController<Uint8List> outgoing;

  @override
  Stream<Uint8List> get incomingFrames => incoming.stream;

  @override
  String get originLabel => 'Bluetooth LE test link';

  @override
  TransportSecurityProperties get rawSecurityProperties =>
      const TransportSecurityProperties(
        transportName: 'Bluetooth LE',
        confidential: false,
        peerAuthenticated: false,
        requiresNetwork: false,
        proximitySignal: true,
        expectedLatency: Duration(milliseconds: 1),
      );

  @override
  Future<void> send(Uint8List frame) async {
    outgoing.add(Uint8List.fromList(frame));
  }

  @override
  Future<void> close() async {
    if (!incoming.isClosed) await incoming.close();
  }
}
