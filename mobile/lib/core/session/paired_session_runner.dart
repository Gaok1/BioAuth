/// Keeps one connection alive per paired desktop.
///
/// The phone dials and then waits, because the desktop is the side that decides
/// when an authorization is needed. A session carries exactly one request and
/// is then closed, so the loop below is the normal steady state rather than a
/// retry path: connect, wait, answer, reconnect.
library;

import 'dart:async';

import '../auth/interactive_authorizer.dart';
import '../auth/phone_authenticator.dart';
import '../pairing/pairing_record.dart';
import '../protocol/auth_response.dart';
import '../transport/auth_transport.dart';
import 'paired_session_service.dart';
import 'phone_auth_core.dart';

/// How long to wait after a failed dial before trying again.
///
/// Long enough not to hammer a desktop that is asleep, short enough that a user
/// who just walked back into range does not wait on it.
const Duration _reconnectDelay = Duration(seconds: 15);

class PairedSessionRunner {
  PairedSessionRunner({
    required AuthTransport transport,
    required BiometricAuthorizer authorizer,
    required InteractiveAuthorizer consent,
    this.onStatus,
    DateTime Function()? clock,
  }) : _service = PairedSessionService(
         transport: transport,
         authorizer: authorizer,
         consent: consent,
         clock: clock,
       ),
       _consent = consent;

  final PairedSessionService _service;
  final InteractiveAuthorizer _consent;

  /// Reports connection state per verifier, for the devices list.
  final void Function(String verifierId, PairedSessionStatus status)? onStatus;

  final Map<String, _Loop> _loops = {};

  /// Starts a loop for every record, and stops loops for records that are gone.
  void sync(List<PairingRecord> records) {
    final wanted = {for (final record in records) record.verifierId: record};
    for (final verifierId in _loops.keys.toList()) {
      if (!wanted.containsKey(verifierId)) _loops.remove(verifierId)?.stop();
    }
    for (final record in records) {
      // A record that is back after a revocation is a fresh pairing, so lift
      // the refusal the revocation installed.
      _service.allowDevice(record.verifierId);
      final existing = _loops[record.verifierId];
      if (existing != null) {
        existing.record = record;
        continue;
      }
      final loop = _Loop(record: record, run: _serve);
      _loops[record.verifierId] = loop;
      unawaited(loop.start());
    }
  }

  Future<void> stop() async {
    for (final loop in _loops.values) {
      loop.stop();
    }
    _loops.clear();
    await _service.stop();
    for (final requestId in _consent.pendingRequestIds.toList()) {
      _consent.abandon(requestId, StateError('Conexão encerrada'));
    }
  }

  /// Drops one verifier now, without waiting for the next [sync].
  ///
  /// Revocation needs the live session gone before the UI says it is gone, so
  /// this closes the channel rather than only marking the loop stopped — a
  /// `serveOne` already blocked on the idle timeout would otherwise stay up
  /// for minutes after the user revoked the desktop.
  Future<void> stopDevice(String verifierId) async {
    _loops.remove(verifierId)?.stop();
    await _service.closeDevice(verifierId);
  }

  Future<void> _serve(PairingRecord record) async {
    onStatus?.call(record.verifierId, PairedSessionStatus.connecting);
    try {
      final response = await _service.serveOne(
        record,
        onEstablished: () =>
            onStatus?.call(record.verifierId, PairedSessionStatus.connected),
      );
      if (response != null) {
        _consent.settle(
          response.requestId,
          response.decision == AuthorizationDecision.authorized
              ? AuthorizationResult.approved
              : AuthorizationResult.denied,
        );
      }
    } on Object catch (error) {
      // Anything left waiting on this session will never be answered.
      for (final requestId in _consent.pendingRequestIds.toList()) {
        _consent.abandon(requestId, error);
      }
      onStatus?.call(record.verifierId, PairedSessionStatus.unreachable);
      rethrow;
    }
  }
}

enum PairedSessionStatus { connecting, connected, unreachable }

/// One verifier's reconnect loop.
class _Loop {
  _Loop({required this.record, required this.run});

  PairingRecord record;
  final Future<void> Function(PairingRecord record) run;
  bool _stopped = false;

  Future<void> start() async {
    while (!_stopped) {
      try {
        await run(record);
      } on Object {
        if (_stopped) return;
        await Future<void>.delayed(_reconnectDelay);
      }
    }
  }

  void stop() => _stopped = true;
}
