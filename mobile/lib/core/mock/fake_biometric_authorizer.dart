import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import '../../domain/authentication_request.dart';
import '../session/phone_auth_core.dart';
import '../transport/auth_transport.dart';

class FakeBiometricAuthorizer implements BiometricAuthorizer {
  FakeBiometricAuthorizer._(this._keyPair, this.publicKey);

  final SimpleKeyPair _keyPair;
  final SimplePublicKey publicKey;
  int authorizationCount = 0;

  static Future<FakeBiometricAuthorizer> create() async {
    final keyPair = await Ed25519().newKeyPair();
    return FakeBiometricAuthorizer._(keyPair, await keyPair.extractPublicKey());
  }

  @override
  Future<AuthorizationProof> authorize({
    required AuthenticationRequest request,
    required Uint8List canonicalRequest,
    String purpose = 'authorization',
  }) async {
    authorizationCount++;
    final signature = await Ed25519().sign(canonicalRequest, keyPair: _keyPair);
    return AuthorizationProof(
      algorithm: 'Ed25519',
      signature: Uint8List.fromList(signature.bytes),
    );
  }
}

class FakeAuthorizationConsent implements AuthorizationConsent {
  const FakeAuthorizationConsent({this.approved = true});

  final bool approved;

  @override
  Future<bool> confirm(
    AuthenticationRequest request,
    TransportSecurityProperties transport,
  ) async => approved;
}
