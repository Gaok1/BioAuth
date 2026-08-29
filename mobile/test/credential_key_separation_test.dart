/// One key per purpose, chosen by the pairing.
///
/// The rule this file exists for: a signature made to approve a `sudo` must
/// not be a signature an SSH server or a vault-holding desktop would accept.
/// That holds only if two things are true — a pairing enrols the key named by
/// its own purpose, and the key that signs a request is chosen by the
/// credential the session was opened with rather than by anything in the
/// request. A desktop that could name the key would be able to reach every
/// other credential on the phone by asking for it.
library;

import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/core/auth/native_biometric_authorizer.dart';
import 'package:phone_auth/core/pairing/pairing_record.dart';
import 'package:phone_auth/core/pairing/pairing_service.dart';
import 'package:phone_auth/core/protocol/enrolment.dart';
import 'package:phone_auth/core/session/paired_session_service.dart';
import 'package:phone_auth/domain/authentication_request.dart';
import 'package:phone_auth_native/phone_auth_native.dart';

class _RecordingKeystore implements SecureAuthenticator {
  final List<String> generated = [];
  final List<String> signed = [];

  @override
  Future<DevicePublicKey> generateKey({
    String purpose = 'authorization',
  }) async {
    generated.add(purpose);
    return DevicePublicKey(
      bytes: Uint8List(91),
      algorithm: publicKeyEcP256Spki,
    );
  }

  @override
  Future<SignatureResult> sign({
    required Uint8List payload,
    required AuthenticationContext context,
    String purpose = 'authorization',
  }) async {
    signed.add(purpose);
    return SignatureResult(signature: Uint8List(64), algorithm: 'test');
  }

  @override
  Future<SecurityCapabilities> getSecurityCapabilities() async =>
      const SecurityCapabilities(
        keyExists: true,
        hardwareBacked: true,
        strongBoxBacked: false,
        biometrics: BiometricCapabilities(
          availability: BiometricAvailability.available,
          strongBiometrics: true,
        ),
      );

  @override
  Future<BiometricCapabilities> getBiometricCapabilities() async =>
      (await getSecurityCapabilities()).biometrics;

  @override
  Future<bool> isHardwareBacked() async => true;

  @override
  Future<DevicePublicKey> getPublicKey({String purpose = 'authorization'}) =>
      throw UnimplementedError();
}

PairingRecord recordFor(CredentialPurpose purpose) => PairingRecord(
  verifierId: 'desktop-1',
  verifierIdentitySpki: Uint8List(91),
  endpoint: '',
  credentialId: 'desktop-1-${purpose.name}-v1',
  keyKind: KeyKind.hardware,
  purpose: purpose,
  pairedAt: DateTime.utc(2026, 8, 29),
);

AuthenticationRequest requestFor(String credentialId) {
  final now = DateTime.now().toUtc();
  return AuthenticationRequest(
    requestId: 'request-1',
    verifierId: 'desktop-1',
    verifierName: 'Desktop',
    credentialId: credentialId,
    challenge: Uint8List(32),
    origin: 'lan',
    service: 'sudo',
    action: 'reboot',
    resource: 'desktop',
    user: 'alice',
    issuedAt: now,
    expiresAt: now.add(const Duration(minutes: 1)),
    sessionBinding: Uint8List(32),
  );
}

void main() {
  test('a pairing enrols the key named by its own purpose', () async {
    final keystore = _RecordingKeystore();
    final credential = NativeAuthorizationCredential(authenticator: keystore);

    for (final purpose in CredentialPurpose.values) {
      await credential.describe(purpose);
    }

    expect(
      keystore.generated,
      CredentialPurpose.values.map((purpose) => purpose.name),
    );
  });

  test('the key that signs is the one the session was opened with', () async {
    for (final purpose in CredentialPurpose.values) {
      final keystore = _RecordingKeystore();
      final record = recordFor(purpose);

      await NativeBiometricAuthorizer(authenticator: keystore).authorize(
        request: requestFor(record.credentialId),
        canonicalRequest: Uint8List.fromList([1, 2, 3]),
        purpose: policyFor(record).purpose,
      );

      expect(keystore.signed, [
        purpose.name,
      ], reason: 'a $purpose session signed with the wrong key');
    }
  });

  /// The policy carries the purpose from the stored pairing. Nothing in the
  /// request reaches it, which is what keeps a desktop from naming a key.
  test('the purpose comes from the record, not from the request', () {
    for (final purpose in CredentialPurpose.values) {
      expect(policyFor(recordFor(purpose)).purpose, purpose.name);
    }
  });
}
