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
  final List<String> described = [];

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

  /// Only the keys this keystore was actually asked to generate exist, and
  /// those are Keystore-backed. That is what makes the question answerable:
  /// a keystore that says the same thing about every alias cannot tell whether
  /// the caller asked about the right one.
  @override
  Future<SecurityCapabilities> getSecurityCapabilities({
    String purpose = 'authorization',
  }) async {
    described.add(purpose);
    final exists = generated.contains(purpose);
    return SecurityCapabilities(
      keyExists: exists,
      hardwareBacked: exists,
      strongBoxBacked: false,
      biometrics: const BiometricCapabilities(
        availability: BiometricAvailability.available,
        strongBiometrics: true,
      ),
    );
  }

  @override
  Future<BiometricCapabilities> getBiometricCapabilities() async =>
      (await getSecurityCapabilities()).biometrics;

  @override
  Future<bool> isHardwareBacked() async => true;

  @override
  Future<DevicePublicKey> getPublicKey({String purpose = 'authorization'}) =>
      throw UnimplementedError();
}

class _RecordingWrappingKeys implements WrappingKeyProvisioner {
  final List<CredentialPurpose> generated = [];

  @override
  Future<({bool hardwareBacked, bool strongBoxBacked})?> ensure(
    CredentialPurpose purpose,
  ) async {
    if (purpose != CredentialPurpose.fileLocker &&
        purpose != CredentialPurpose.diskUnlock) {
      return null;
    }
    generated.add(purpose);
    return (hardwareBacked: true, strongBoxBacked: false);
  }
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
    final wrappingKeys = _RecordingWrappingKeys();
    final credential = NativeAuthorizationCredential(
      authenticator: keystore,
      wrappingKeys: wrappingKeys,
    );

    for (final purpose in CredentialPurpose.values) {
      await credential.describe(purpose);
    }

    expect(
      keystore.generated,
      CredentialPurpose.values.map((purpose) => purpose.name),
    );
    expect(
      wrappingKeys.generated,
      unorderedEquals([
        CredentialPurpose.fileLocker,
        CredentialPurpose.diskUnlock,
      ]),
    );
  });

  test('a pairing describes the key it enrolled, not another one', () async {
    // The enrolment carries how well protected the key is, and it used to ask
    // about the authorization key whichever purpose it had just generated. A
    // phone paired only for passkeys or the vault has no authorization key at
    // all, so a Keystore-backed credential enrolled as `software` -- which is
    // what the desktop then showed. The direction that matters is the other
    // one: StrongBox is attempted per key and falls back per key, so an
    // authorization key that got it would have vouched for a purpose key that
    // did not, and this value exists to withhold authority, never to grant it.
    for (final purpose in CredentialPurpose.values) {
      final keystore = _RecordingKeystore();
      // The wrapping provisioner too, and not only to keep a unit test off
      // the method channel: for the two purposes that wrap rather than sign,
      // it is the wrapping key whose backing gets reported, so leaving it out
      // would test the wrong key -- which is the very mistake this test names.
      final enrolment = await NativeAuthorizationCredential(
        authenticator: keystore,
        wrappingKeys: _RecordingWrappingKeys(),
      ).describe(purpose);

      expect(keystore.described, [purpose.name]);
      expect(
        enrolment.keyKind,
        KeyKind.hardware,
        reason: 'a $purpose credential was described by the wrong key',
      );
    }
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
