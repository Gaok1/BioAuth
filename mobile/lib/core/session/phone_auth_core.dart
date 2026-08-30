import 'dart:async';
import 'dart:collection';
import 'dart:typed_data';

import '../../domain/authentication_request.dart';
import '../protocol/auth_response.dart';
import '../protocol/protocol_codec.dart';
import '../transport/auth_transport.dart';

abstract interface class BiometricAuthorizer {
  Future<AuthorizationProof> authorize({
    required AuthenticationRequest request,
    required Uint8List canonicalRequest,
    // Which key signs. The credential the session was opened with decides it,
    // never the request: a desktop asking with one credential must not be able
    // to reach the key of another by naming it.
    String purpose,
  });
}

abstract interface class AuthorizationConsent {
  Future<bool> confirm(
    AuthenticationRequest request,
    TransportSecurityProperties transport,
  );
}

class AuthorizationProof {
  AuthorizationProof({required this.algorithm, required Uint8List signature})
    : signature = Uint8List.fromList(signature);

  final String algorithm;
  final Uint8List signature;
}

class VerifierPolicy {
  const VerifierPolicy({
    required this.verifierId,
    required this.credentialId,
    required this.permissions,
    this.purpose = 'authorization',
  });

  final String verifierId;
  final String credentialId;

  /// The credential's purpose, which is also the name of the key that signs
  /// for it. Stored with the pairing, so a desktop cannot change it later.
  final String purpose;
  final List<VerifierPermission> permissions;

  bool allows(AuthenticationRequest request) =>
      request.verifierId == verifierId &&
      request.credentialId == credentialId &&
      permissions.any((permission) => permission.allows(request));
}

/// One thing a verifier is allowed to ask for.
///
/// `*` matches anything in that position. A permission holding three of them is
/// the pairing default: the phone is not the place that enumerates a desktop's
/// operations, and every request still costs an explicit tap and a biometric
/// signature. The narrowing that matters happens on the verifier, where a
/// freshly enrolled credential authorizes nothing until permissions are
/// granted.
class VerifierPermission {
  const VerifierPermission({
    required this.service,
    required this.action,
    this.resource = '*',
  });

  /// Anything the paired verifier asks for, still gated by consent.
  const VerifierPermission.any() : service = '*', action = '*', resource = '*';

  final String service;
  final String action;
  final String resource;

  bool allows(AuthenticationRequest request) =>
      _matches(service, request.service) &&
      _matches(action, request.action) &&
      _matches(resource, request.resource);

  static bool _matches(String pattern, String value) =>
      pattern == '*' || pattern == value;
}

class PhoneAuthCore {
  PhoneAuthCore({
    required this.authorizer,
    required this.consent,
    required this.policy,
    this.codec = const PhoneAuthProtocolCodec(),
    DateTime Function()? clock,
  }) : _clock = clock ?? DateTime.now;

  final BiometricAuthorizer authorizer;
  final AuthorizationConsent consent;
  final VerifierPolicy policy;
  final PhoneAuthProtocolCodec codec;
  final DateTime Function() _clock;
  final Set<String> _seenRequestIds = <String>{};
  final Queue<String> _seenOrder = Queue<String>();

  Future<AuthResponse> authorize(
    AuthenticationRequest request,
    SecureTransportSession session,
  ) async {
    final now = _clock().toUtc();
    if (!session.securityProperties.confidential ||
        !session.securityProperties.peerAuthenticated) {
      throw const PhoneAuthProtocolException(
        'Sensitive authorization requires an authenticated confidential session',
      );
    }
    if (!_bytesEqual(request.sessionBinding, session.sessionBinding)) {
      throw const PhoneAuthProtocolException('Session binding mismatch');
    }
    if (request.issuedAt.isAfter(now.add(const Duration(seconds: 30))) ||
        request.isExpiredAt(now)) {
      throw const PhoneAuthProtocolException(
        'Request is outside its validity window',
      );
    }
    if (_seenRequestIds.contains(request.requestId)) {
      throw const PhoneAuthProtocolException('Request replay detected');
    }
    _remember(request.requestId);

    if (!policy.allows(request) ||
        !await consent.confirm(request, session.securityProperties)) {
      return AuthResponse.denied(request);
    }

    // The window above was measured against the clock of the moment the
    // request arrived, and `consent.confirm` suspends for as long as a human
    // takes to answer -- which is not bounded by anything in here. A tap that
    // lands after the request died is not consent to sign it: the desktop
    // refuses an answer past `expiresAt`, so what the old code produced was a
    // fingerprint spent on a signature nobody could use, given by someone who
    // by then was answering a prompt they had left on screen.
    //
    // Checked here rather than after the signature, because this is where the
    // human delay is. What comes next is a biometric prompt measured in
    // seconds, and refusing after it would waste the gesture this avoids.
    if (request.isExpiredAt(_clock().toUtc())) {
      return AuthResponse.denied(request);
    }

    try {
      final proof = await authorizer.authorize(
        request: request,
        canonicalRequest: codec.encodeRequest(request),
        purpose: policy.purpose,
      );
      return AuthResponse(
        protocolVersion: request.protocolVersion,
        requestId: request.requestId,
        verifierId: request.verifierId,
        credentialId: request.credentialId,
        decision: AuthorizationDecision.authorized,
        algorithm: proof.algorithm,
        signature: proof.signature,
      );
    } on Object {
      return AuthResponse.denied(request);
    }
  }

  /// Waits for one request on [session], answers it, and closes.
  ///
  /// Throws [TimeoutException] if nothing arrives within [timeout], which is a
  /// normal outcome for a phone that connected while the desktop was idle.
  /// Returns the response that was sent, so a caller can report the outcome
  /// without re-deriving it from the request.
  Future<AuthResponse> serveOne(
    SecureTransportSession session, {
    Duration timeout = const Duration(minutes: 2),
  }) async {
    try {
      final frame = await session.incomingFrames.first.timeout(timeout);
      return await serveFrame(session, frame);
    } finally {
      await session.close();
    }
  }

  Future<AuthResponse> serveFrame(
    SecureTransportSession session,
    Uint8List frame,
  ) async {
    final request = codec.decodeRequest(frame, origin: session.originLabel);
    final response = await authorize(request, session);
    await session.send(codec.encodeResponse(response));
    return response;
  }

  void _remember(String requestId) {
    _seenRequestIds.add(requestId);
    _seenOrder.addLast(requestId);
    if (_seenOrder.length > 1024) {
      _seenRequestIds.remove(_seenOrder.removeFirst());
    }
  }

  bool _bytesEqual(List<int> left, List<int> right) {
    if (left.length != right.length) return false;
    for (var index = 0; index < left.length; index++) {
      if (left[index] != right[index]) return false;
    }
    return true;
  }
}

class PhoneAuthProtocolException implements Exception {
  const PhoneAuthProtocolException(this.message);

  final String message;

  @override
  String toString() => 'PhoneAuthProtocolException: $message';
}
