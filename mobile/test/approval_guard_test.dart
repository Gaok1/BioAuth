import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:phone_auth/core/security/approval_guard.dart';
import 'package:phone_auth/domain/authentication_request.dart';

void main() {
  final at = DateTime.utc(2026, 8, 26, 12);

  AuthenticationRequest request(
    String id, {
    String resource = 'server',
    String verifierId = 'desktop-1',
  }) => AuthenticationRequest(
    requestId: id,
    verifierId: verifierId,
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

  /// A flood is a device that keeps sending after it has been told no, and
  /// every arrival was written down. Nothing ever read past the first few, so
  /// the list grew for as long as the flood lasted -- one fingerprint string
  /// per attempt, from a device the phone is already refusing.
  test('a flood does not grow what the guard is holding', () {
    final guard = ApprovalGuard(maxRequestsPerWindow: 2);

    for (var attempt = 0; attempt < 200; attempt++) {
      final decision = guard.inspect(
        request('$attempt', resource: 'server-$attempt'),
        at.add(Duration(milliseconds: attempt)),
      );
      // The answers are unchanged by the ceiling: the first two land, and
      // everything after them is a flood.
      expect(
        decision,
        attempt < 2 ? isNot(ApprovalDecision.flood) : ApprovalDecision.flood,
      );
    }

    expect(guard.observations, 3);
  });

  /// The lists were pruned and the keys were not, so a phone that had paired
  /// with several desktops over its life kept a map entry for each of them
  /// forever -- an empty list nothing would read again.
  test('a device that goes quiet is forgotten entirely', () {
    final guard = ApprovalGuard();

    guard.inspect(request('1', verifierId: 'desktop-1'), at);
    guard.inspect(request('2', verifierId: 'desktop-2'), at);
    expect(guard.trackedDevices, 2);

    guard.inspect(
      request('3', verifierId: 'desktop-3'),
      at.add(const Duration(seconds: 31)),
    );
    expect(guard.trackedDevices, 1);
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
