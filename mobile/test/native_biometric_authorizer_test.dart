import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/core/auth/native_biometric_authorizer.dart';
import 'package:phone_auth/domain/authentication_request.dart';
import 'package:phone_auth_native/phone_auth_native.dart';

class _RecordingAuthenticator implements SecureAuthenticator {
  _RecordingAuthenticator({required this.strongBiometrics});

  final bool strongBiometrics;
  Uint8List? signedPayload;
  AuthenticationContext? displayedContext;

  @override
  Future<SecurityCapabilities> getSecurityCapabilities() async =>
      SecurityCapabilities(
        keyExists: true,
        hardwareBacked: true,
        strongBoxBacked: false,
        biometrics: BiometricCapabilities(
          availability: strongBiometrics
              ? BiometricAvailability.available
              : BiometricAvailability.unavailable,
          strongBiometrics: strongBiometrics,
        ),
      );

  @override
  Future<DevicePublicKey> generateSshKey() =>
      throw UnimplementedError('not part of this test');

  @override
  Future<SignatureResult> signSsh({
    required Uint8List payload,
    required AuthenticationContext context,
  }) => throw UnimplementedError('not part of this test');

  @override
  Future<SignatureResult> sign({
    required Uint8List payload,
    required AuthenticationContext context,
  }) async {
    signedPayload = Uint8List.fromList(payload);
    displayedContext = context;
    return SignatureResult(
      signature: Uint8List.fromList([1, 2, 3]),
      algorithm: 'test',
    );
  }

  @override
  Future<BiometricCapabilities> getBiometricCapabilities() async =>
      (await getSecurityCapabilities()).biometrics;

  @override
  Future<DevicePublicKey> generateKey() => throw UnimplementedError();

  @override
  Future<DevicePublicKey> getPublicKey() => throw UnimplementedError();

  @override
  Future<bool> isHardwareBacked() async => true;
}

void main() {
  final now = DateTime.utc(2026, 8, 26, 12);
  final request = AuthenticationRequest(
    requestId: 'request-1',
    verifierId: 'desktop-1',
    verifierName: 'Desktop-NixOS',
    credentialId: 'sudo-v1',
    challenge: Uint8List(32),
    origin: 'secure session',
    service: 'sudo',
    action: 'nixos-rebuild switch',
    resource: 'Desktop-NixOS',
    user: 'alice',
    issuedAt: now,
    expiresAt: now.add(const Duration(minutes: 1)),
    sessionBinding: Uint8List(32),
  );

  test(
    'passes the complete canonical request to the CryptoObject signer',
    () async {
      final native = _RecordingAuthenticator(strongBiometrics: true);
      final authorizer = NativeBiometricAuthorizer(authenticator: native);
      final canonical = Uint8List.fromList([1, 2, 3, 4]);

      await authorizer.authorize(request: request, canonicalRequest: canonical);

      expect(native.signedPayload, canonical);
      expect(native.displayedContext?.title, 'Desktop-NixOS');
      expect(native.displayedContext?.description, contains('nixos-rebuild'));
    },
  );

  test(
    'denies instead of falling back when strong biometrics are unavailable',
    () {
      final native = _RecordingAuthenticator(strongBiometrics: false);
      final authorizer = NativeBiometricAuthorizer(authenticator: native);

      expect(
        () => authorizer.authorize(
          request: request,
          canonicalRequest: Uint8List.fromList([1]),
        ),
        throwsStateError,
      );
      expect(native.signedPayload, isNull);
    },
  );
}
