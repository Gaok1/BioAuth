import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/core/mock/fake_biometric_authorizer.dart';
import 'package:phone_auth/core/mock/fake_session_binding.dart';
import 'package:phone_auth/core/mock/fake_transport.dart';
import 'package:phone_auth/core/protocol/auth_response.dart';
import 'package:phone_auth/core/protocol/protocol_codec.dart';
import 'package:phone_auth/core/session/phone_auth_core.dart';
import 'package:phone_auth/core/transport/auth_transport.dart';
import 'package:phone_auth/core/transport/secure_session_establisher.dart';
import 'package:phone_auth/domain/authentication_request.dart';

void main() {
  final now = DateTime.utc(2026, 8, 26, 12);
  const codec = PhoneAuthProtocolCodec();

  AuthenticationRequest request({required Uint8List sessionBinding}) =>
      AuthenticationRequest(
        requestId: 'request-1',
        verifierId: 'desktop-1',
        verifierName: 'Desktop-NixOS',
        credentialId: 'desktop-1-sudo-v1',
        challenge: Uint8List.fromList(List<int>.generate(32, (i) => i)),
        origin: 'replaced by session',
        service: 'sudo',
        action: 'nixos-rebuild switch',
        resource: 'Desktop-NixOS',
        user: 'alice',
        issuedAt: now,
        expiresAt: now.add(const Duration(minutes: 1)),
        sessionBinding: sessionBinding,
      );

  Future<(FakeTransport, SecureTransportSession)> connectedTransport() async {
    final transport = FakeTransport();
    final discovered = transport.discoverPeers().first;
    await transport.start();
    final peer = await discovered;
    final outcome = await transport.connect(
      peer,
      ScannedVerifier(fakeBootstrap(sessionId: 'session-1')),
    );
    return (transport, outcome.session);
  }

  test(
    'FakeTransport -> core -> biometric signature -> verifier authorized',
    () async {
      final (transport, mobileSession) = await connectedTransport();
      final authorizer = await FakeBiometricAuthorizer.create();
      final core = PhoneAuthCore(
        authorizer: authorizer,
        consent: const FakeAuthorizationConsent(),
        policy: const VerifierPolicy(
          verifierId: 'desktop-1',
          credentialId: 'desktop-1-sudo-v1',
          permissions: [
            VerifierPermission(
              service: 'sudo',
              action: 'nixos-rebuild switch',
              resource: 'Desktop-NixOS',
            ),
          ],
        ),
        clock: () => now,
      );
      final original = request(sessionBinding: mobileSession.sessionBinding);

      final serving = core.serveOne(mobileSession);
      await transport.verifierSession.send(codec.encodeRequest(original));
      final responseFrame =
          await transport.verifierSession.incomingFrames.first;
      final response = codec.decodeResponse(responseFrame);
      await serving;

      final valid = await Ed25519().verify(
        codec.encodeRequest(original),
        signature: Signature(
          response.signature,
          publicKey: authorizer.publicKey,
        ),
      );
      expect(response.decision, AuthorizationDecision.authorized);
      expect(valid, isTrue);
      expect(authorizer.authorizationCount, 1);

      final changedContext = AuthenticationRequest(
        requestId: original.requestId,
        verifierId: original.verifierId,
        verifierName: original.verifierName,
        credentialId: original.credentialId,
        challenge: original.challenge,
        origin: original.origin,
        service: original.service,
        action: 'abrir porta',
        resource: original.resource,
        user: original.user,
        issuedAt: original.issuedAt,
        expiresAt: original.expiresAt,
        sessionBinding: original.sessionBinding,
      );
      expect(
        await Ed25519().verify(
          codec.encodeRequest(changedContext),
          signature: Signature(
            response.signature,
            publicKey: authorizer.publicKey,
          ),
        ),
        isFalse,
      );
      await transport.stop();
    },
  );

  test('denial never invokes biometric authorization', () async {
    final (_, mobileSession) = await connectedTransport();
    final authorizer = await FakeBiometricAuthorizer.create();
    final core = PhoneAuthCore(
      authorizer: authorizer,
      consent: const FakeAuthorizationConsent(approved: false),
      policy: const VerifierPolicy(
        verifierId: 'desktop-1',
        credentialId: 'desktop-1-sudo-v1',
        permissions: [
          VerifierPermission(service: 'sudo', action: 'nixos-rebuild switch'),
        ],
      ),
      clock: () => now,
    );

    final response = await core.authorize(
      request(sessionBinding: mobileSession.sessionBinding),
      mobileSession,
    );
    expect(response.decision, AuthorizationDecision.denied);
    expect(authorizer.authorizationCount, 0);
  });

  test('mismatched session binding and replay fail closed', () async {
    final (_, mobileSession) = await connectedTransport();
    final authorizer = await FakeBiometricAuthorizer.create();
    final core = PhoneAuthCore(
      authorizer: authorizer,
      consent: const FakeAuthorizationConsent(),
      policy: const VerifierPolicy(
        verifierId: 'desktop-1',
        credentialId: 'desktop-1-sudo-v1',
        permissions: [
          VerifierPermission(service: 'sudo', action: 'nixos-rebuild switch'),
        ],
      ),
      clock: () => now,
    );

    expect(
      () =>
          core.authorize(request(sessionBinding: Uint8List(32)), mobileSession),
      throwsA(isA<PhoneAuthProtocolException>()),
    );
    final validRequest = request(sessionBinding: mobileSession.sessionBinding);
    await core.authorize(validRequest, mobileSession);
    expect(
      () => core.authorize(validRequest, mobileSession),
      throwsA(isA<PhoneAuthProtocolException>()),
    );
  });

  test('a tap that lands after the request expired does not sign it', () async {
    // The validity window was checked once, against the clock of the moment
    // the request arrived, and consent suspends for as long as a human takes.
    // This request is good for a minute; this user answers after two.
    final (_, mobileSession) = await connectedTransport();
    final authorizer = await FakeBiometricAuthorizer.create();
    var moment = now;
    final core = PhoneAuthCore(
      authorizer: authorizer,
      consent: _SlowConsent(() => moment = now.add(const Duration(minutes: 2))),
      policy: const VerifierPolicy(
        verifierId: 'desktop-1',
        credentialId: 'desktop-1-sudo-v1',
        permissions: [
          VerifierPermission(service: 'sudo', action: 'nixos-rebuild switch'),
        ],
      ),
      clock: () => moment,
    );

    final response = await core.authorize(
      request(sessionBinding: mobileSession.sessionBinding),
      mobileSession,
    );

    expect(response.decision, AuthorizationDecision.denied);
    expect(
      authorizer.authorizationCount,
      0,
      reason:
          'the desktop refuses an answer past the deadline anyway, so a '
          'fingerprint spent here buys a signature nobody can use',
    );
  });
}

/// Someone who says yes, long after being asked.
class _SlowConsent implements AuthorizationConsent {
  _SlowConsent(this.onAsked);

  final void Function() onAsked;

  @override
  Future<bool> confirm(
    AuthenticationRequest request,
    TransportSecurityProperties transport,
  ) async {
    onAsked();
    return true;
  }
}
