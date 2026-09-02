import 'dart:typed_data';

import '../../domain/authentication_request.dart';

enum AuthorizationDecision { authorized, denied }

class AuthResponse {
  AuthResponse({
    this.protocolVersion = 1,
    required this.requestId,
    required this.verifierId,
    required this.credentialId,
    required this.decision,
    required this.algorithm,
    required Uint8List signature,
  }) : signature = Uint8List.fromList(signature) {
    if (protocolVersion != 1 ||
        requestId.isEmpty ||
        verifierId.isEmpty ||
        credentialId.isEmpty ||
        (decision == AuthorizationDecision.authorized &&
            (algorithm.isEmpty || signature.isEmpty))) {
      throw const FormatException('invalid authorization response');
    }
  }

  factory AuthResponse.denied(AuthenticationRequest request) => AuthResponse(
    protocolVersion: request.protocolVersion,
    requestId: request.requestId,
    verifierId: request.verifierId,
    credentialId: request.credentialId,
    decision: AuthorizationDecision.denied,
    algorithm: '',
    signature: Uint8List(0),
  );

  final int protocolVersion;
  final String requestId;
  final String verifierId;
  final String credentialId;
  final AuthorizationDecision decision;
  final String algorithm;
  final Uint8List signature;
}
