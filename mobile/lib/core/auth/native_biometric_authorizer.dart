import 'dart:typed_data';

import 'package:phone_auth_native/phone_auth_native.dart';

import '../../domain/authentication_request.dart';
import '../session/phone_auth_core.dart';

class NativeBiometricAuthorizer implements BiometricAuthorizer {
  const NativeBiometricAuthorizer({
    SecureAuthenticator authenticator = const PhoneAuthNative(),
  }) : _authenticator = authenticator;

  final SecureAuthenticator _authenticator;

  @override
  Future<AuthorizationProof> authorize({
    required AuthenticationRequest request,
    required Uint8List canonicalRequest,
    String purpose = 'authorization',
  }) async {
    final capabilities = await _authenticator.getSecurityCapabilities();
    if (!capabilities.biometrics.strongBiometrics) {
      throw StateError('BIOMETRIC_STRONG unavailable');
    }
    final result = await _authenticator.sign(
      payload: canonicalRequest,
      purpose: purpose,
      context: AuthenticationContext(
        title: request.verifierName,
        subtitle: '${request.service} • ${request.user}',
        description: '${request.action} • ${request.resource}',
      ),
    );
    return AuthorizationProof(
      algorithm: result.algorithm,
      signature: result.signature,
    );
  }
}
