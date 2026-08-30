// The MVP loop, end to end, over a real TCP socket.
//
// Pair, enrol, reconnect as a paired device, receive a request, sign it, answer
// it. Nothing is stubbed below the transport: this exercises the framing, the
// handshake, the record layer and both codecs, which is where the phone and the
// desktop actually have to agree.

import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/core/auth/interactive_authorizer.dart';
import 'package:phone_auth/core/auth/phone_authenticator.dart';
import 'package:phone_auth/core/mock/fake_biometric_authorizer.dart';
import 'package:phone_auth/core/luks/luks_service.dart';
import 'package:phone_auth/core/pairing/pairing_service.dart';
import 'package:phone_auth/core/pairing/pairing_store.dart';
import 'package:phone_auth/core/protocol/auth_response.dart';
import 'package:phone_auth/core/protocol/application_frame.dart';
import 'package:phone_auth/core/protocol/enrolment.dart';
import 'package:phone_auth/core/protocol/luks_payloads.dart';
import 'package:phone_auth/core/protocol/protocol_codec.dart';
import 'package:phone_auth/core/session/paired_session_service.dart';
import 'package:phone_auth/core/transport/authenticated_session_establisher.dart';
import 'package:phone_auth/core/transport/qr_network_transport.dart';
import 'package:phone_auth/domain/authentication_request.dart';

import 'support/fake_desktop.dart';
import 'support/handshake_fixtures.dart';

void main() {
  late FakeDesktop desktop;
  late InMemoryPairingStore store;
  late QrNetworkTransport transport;

  setUp(() async {
    desktop = await FakeDesktop.bind();
    store = InMemoryPairingStore(id: 'phone-under-test');
    transport = QrNetworkTransport(
      sessionEstablisher: AuthenticatedSessionEstablisher(
        deviceId: await store.deviceId(),
        identity: await TestIdentity.create(),
      ),
    );
  });

  tearDown(() => desktop.close());

  PairingService pairingService() => PairingService(
    transport: transport,
    store: store,
    deviceName: 'Pixel sob teste',
    credential: _FakeCredential(),
  );

  AuthenticationRequest requestFor(Uint8List binding) {
    final now = DateTime.now().toUtc();
    return AuthenticationRequest(
      requestId: 'request-1',
      verifierId: 'desktop-1',
      verifierName: 'Desktop-Casa',
      credentialId: 'desktop-1-authorization-v1',
      challenge: Uint8List.fromList(List<int>.filled(32, 7)),
      origin: 'set by the session',
      service: 'sudo',
      action: 'nixos-rebuild switch',
      resource: 'Desktop-NixOS',
      user: 'alice',
      issuedAt: now,
      expiresAt: now.add(const Duration(minutes: 1)),
      sessionBinding: binding,
    );
  }

  /// The QR says what the pairing is for, and that decides which key is
  /// enrolled. Getting this wrong is not a cosmetic mislabel: it is the same
  /// key approving a `sudo` and signing an SSH login, which is what the
  /// purposes exist to keep apart.
  test('a purpose in the code is the purpose that is enrolled', () async {
    final credential = _FakeCredential();
    final bootstrap = await desktop.bootstrap(purpose: CredentialPurpose.ssh);
    final accepting = desktop.accept(bootstrap);

    final session = await PairingService(
      transport: transport,
      store: store,
      deviceName: 'Pixel sob teste',
      credential: credential,
    ).begin(bootstrap.toUri());
    final enrolment = await (await accepting).readEnrolment();

    expect(credential.asked, [CredentialPurpose.ssh]);
    expect(enrolment.purpose, CredentialPurpose.ssh);
    // The id says it too, so two credentials from one desktop cannot collide.
    expect(enrolment.credentialId, 'desktop-1-ssh-v1');

    await session.confirm();
    expect((await store.load()).single.purpose, CredentialPurpose.ssh);
  });

  test('pairing enrols a credential and stores the verifier key', () async {
    final bootstrap = await desktop.bootstrap();
    final accepting = desktop.accept(bootstrap);

    final session = await pairingService().begin(bootstrap.toUri());
    final desktopSession = await accepting;
    final enrolment = await desktopSession.readEnrolment();

    // Both ends derive this from an exporter that never went on the wire.
    expect(session.verificationCode, desktopSession.verificationCode);
    expect(session.verificationCode, hasLength(6));

    expect(enrolment.deviceName, 'Pixel sob teste');
    expect(enrolment.credentialId, 'desktop-1-authorization-v1');
    expect(enrolment.keyKind, KeyKind.software);
    expect(enrolment.purpose, CredentialPurpose.authorization);
    expect(desktopSession.deviceId, 'phone-under-test');

    expect(await store.load(), isEmpty, reason: 'nothing is stored yet');
    await session.confirm();

    final stored = await store.load();
    expect(stored, hasLength(1));
    expect(stored.single.verifierId, 'desktop-1');
    expect(
      stored.single.verifierIdentitySpki,
      await desktop.identity.publicKey(),
      reason: 'this key is the only thing authenticating the desktop later',
    );
    expect(stored.single.endpoint, desktop.endpoint);

    await desktopSession.close();
  });

  test('rejecting the code stores nothing', () async {
    final bootstrap = await desktop.bootstrap();
    final accepting = desktop.accept(bootstrap);

    final session = await pairingService().begin(bootstrap.toUri());
    final desktopSession = await accepting;
    await desktopSession.readEnrolment();

    await session.reject();

    expect(await store.load(), isEmpty);
    await desktopSession.close();
  });

  test(
    'a paired phone answers an authorization over the real socket',
    () async {
      // Phase one: pair.
      final pairingBootstrap = await desktop.bootstrap();
      final acceptingPairing = desktop.accept(pairingBootstrap);
      final pairing = await pairingService().begin(pairingBootstrap.toUri());
      final pairingSession = await acceptingPairing;
      await pairingSession.readEnrolment();
      await pairing.confirm();
      await pairingSession.close();

      final record = (await store.load()).single;

      // Phase two: reconnect as a paired device. There is no scanned code now —
      // only the stored key vouches for the desktop.
      final authorizer = await FakeBiometricAuthorizer.create();
      final consent = InteractiveAuthorizer(onRequest: (_) {});
      final service = PairedSessionService(
        transport: transport,
        authorizer: authorizer,
        consent: consent,
      );

      final freshBootstrap = await desktop.bootstrap(sessionId: 'session-2');
      final acceptingPaired = desktop.accept(freshBootstrap);
      final serving = service.serveOne(record);
      final desktopSession = await acceptingPaired;

      final request = requestFor(desktopSession.binding);
      // The user taps approve as soon as the card appears. The biometric prompt
      // runs inside the core, after that tap releases it.
      final answering = desktopSession.requestAuthorization(request);
      final tapped = _tapApprove(consent, request);

      final response = await answering;
      await serving;

      expect(response.decision, AuthorizationDecision.authorized);
      expect(response.requestId, 'request-1');
      expect(
        await Ed25519().verify(
          const PhoneAuthProtocolCodec().encodeRequest(request),
          signature: Signature(
            response.signature,
            publicKey: authorizer.publicKey,
          ),
        ),
        isTrue,
        reason: 'the signature must cover the whole request frame',
      );

      // What the runner does once the exchange finishes: tell the screen.
      consent.settle(response.requestId, AuthorizationResult.approved);
      expect(await tapped, AuthorizationResult.approved);

      await desktopSession.close();
    },
  );

  test('a request whose binding is not this session is refused', () async {
    final pairingBootstrap = await desktop.bootstrap();
    final acceptingPairing = desktop.accept(pairingBootstrap);
    final pairing = await pairingService().begin(pairingBootstrap.toUri());
    final pairingSession = await acceptingPairing;
    await pairingSession.readEnrolment();
    await pairing.confirm();
    await pairingSession.close();

    final record = (await store.load()).single;
    final consent = InteractiveAuthorizer(onRequest: (_) {});
    final service = PairedSessionService(
      transport: transport,
      authorizer: await FakeBiometricAuthorizer.create(),
      consent: consent,
    );

    final acceptingPaired = desktop.accept(
      await desktop.bootstrap(sessionId: 'session-2'),
    );
    final serving = service.serveOne(record);
    final desktopSession = await acceptingPaired;

    // A binding lifted from somewhere else. Nothing must reach a human.
    final request = requestFor(Uint8List.fromList(List<int>.filled(32, 0xaa)));
    final answering = desktopSession.requestAuthorization(request);

    await expectLater(serving, throwsA(anything));
    await expectLater(answering, throwsA(anything));
    expect(
      consent.pendingRequestIds,
      isEmpty,
      reason: 'consent must never have been asked for',
    );

    await desktopSession.close();
  });

  test('a disk-unlock credential routes only to the LUKS guardian', () async {
    final pairingBootstrap = await desktop.bootstrap(
      purpose: CredentialPurpose.diskUnlock,
    );
    final acceptingPairing = desktop.accept(pairingBootstrap);
    final pairing = await pairingService().begin(pairingBootstrap.toUri());
    final pairingSession = await acceptingPairing;
    await pairingSession.readEnrolment();
    await pairing.confirm();
    await pairingSession.close();

    final record = (await store.load()).single;
    final guardian = _FakeLuksGuardian();
    final service = PairedSessionService(
      transport: transport,
      authorizer: await FakeBiometricAuthorizer.create(),
      consent: InteractiveAuthorizer(onRequest: (_) {}),
      luksGuardian: guardian,
    );
    final acceptingPaired = desktop.accept(
      await desktop.bootstrap(
        sessionId: 'session-luks',
        purpose: CredentialPurpose.diskUnlock,
      ),
    );
    final serving = service.serveOne(record);
    final desktopSession = await acceptingPaired;
    final now = DateTime.now().toUtc();
    final answer = await desktopSession.requestApplication(
      ApplicationFrame(
        protocolVersion: 1,
        kind: ApplicationFrameKind.request,
        requestId: 'luks-request-1',
        sessionBinding: desktopSession.binding,
        operation: luksUnlockOperation,
        issuedAt: now,
        expiresAt: now.add(const Duration(minutes: 1)),
        payload: LuksUnlockRequest(
          verifierName: 'Desktop-Casa',
          volumeName: 'cryptroot',
          volumeBinding: Uint8List(32),
          credentialId: record.credentialId,
          wrapper: Uint8List.fromList([8]),
        ).encode(),
      ),
    );
    await serving;

    expect(answer.kind, ApplicationFrameKind.response);
    expect(
      LuksUnlockResponse.decode(answer.payload).diskKey,
      List.filled(32, 7),
    );
    expect(guardian.unlocks, 1);
    await desktopSession.close();
  });
}

/// Waits for the consent bridge to be asked, then answers yes.
///
/// Returns the future the screen would be waiting on, which only completes once
/// the runner reports what was actually sent.
Future<AuthorizationResult> _tapApprove(
  InteractiveAuthorizer consent,
  AuthenticationRequest request,
) async {
  while (!consent.pendingRequestIds.contains(request.id)) {
    await Future<void>.delayed(const Duration(milliseconds: 5));
  }
  return consent.authorize(request, onPhase: (_) {});
}

/// The credential a phone with no keystore can offer.
class _FakeCredential implements AuthorizationCredential {
  final List<CredentialPurpose> asked = [];

  @override
  Future<({Uint8List publicKey, String algorithm, KeyKind keyKind})> describe(
    CredentialPurpose purpose,
  ) async {
    asked.add(purpose);
    return (
      publicKey: Uint8List.fromList(List<int>.filled(91, 3)),
      algorithm: publicKeyEcP256Spki,
      // Reported honestly. A verifier must be able to refuse this for disk
      // unlock, and it can only do that if the phone says what it really has.
      keyKind: KeyKind.software,
    );
  }
}

class _FakeLuksGuardian implements LuksKeyGuardian {
  int unlocks = 0;

  @override
  Future<Uint8List> wrap({
    required Uint8List binding,
    required String credentialId,
    required Uint8List diskKey,
    required String volumeName,
    required String verifierName,
  }) => throw UnimplementedError();

  @override
  Future<Uint8List> unwrap({
    required Uint8List binding,
    required String credentialId,
    required Uint8List wrapper,
    required String volumeName,
    required String verifierName,
  }) async {
    unlocks++;
    return Uint8List.fromList(List.filled(32, 7));
  }
}
