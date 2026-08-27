import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/core/security/approval_guard.dart';
import 'package:phone_auth/domain/authentication_request.dart';

void main() {
  final at = DateTime.utc(2026, 8, 26, 12);

  AuthenticationRequest request(String id, {String resource = 'server'}) =>
      AuthenticationRequest(
        requestId: id,
        verifierId: 'desktop-1',
        verifierName: 'Desktop',
        credentialId: 'desktop-1-login',
        challenge: Uint8List(32),
        origin: 'BLE pareado',
        service: 'SSH',
        action: 'Login',
        resource: resource,
        user: 'alice',
        issuedAt: at,
        expiresAt: at.add(const Duration(minutes: 1)),
        sessionBinding: Uint8List(32),
      );

  test('groups duplicates but still detects a flood', () {
    final guard = ApprovalGuard(maxRequestsPerWindow: 2);

    expect(guard.inspect(request('1'), at), ApprovalDecision.accept);
    expect(
      guard.inspect(request('2'), at.add(const Duration(seconds: 1))),
      ApprovalDecision.duplicate,
    );
    expect(
      guard.inspect(request('3'), at.add(const Duration(seconds: 2))),
      ApprovalDecision.flood,
    );
  });

  test('forgets observations outside the rate window', () {
    final guard = ApprovalGuard(maxRequestsPerWindow: 1);
    expect(guard.inspect(request('1'), at), ApprovalDecision.accept);
    expect(
      guard.inspect(
        request('2', resource: 'other'),
        at.add(const Duration(seconds: 31)),
      ),
      ApprovalDecision.accept,
    );
  });
}
