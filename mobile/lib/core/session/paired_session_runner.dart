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

/// The first pause after a failed dial, doubled on each further failure.
///
/// Most failures are a blip — the Wi-Fi roamed, the desktop slept for a second.
/// Waiting a flat fifteen seconds for those made a link that was already back
/// look dead. Starting at a second recovers from them almost immediately, and
/// the doubling still keeps a genuinely absent desktop from being hammered.
const Duration _firstReconnectDelay = Duration(seconds: 1);

/// The ceiling the backoff climbs to for a desktop that is simply not there.
const Duration _maxReconnectDelay = Duration(seconds: 15);

/// How many quick attempts a blip gets before the UI admits it is offline.
///
/// Roughly the first seven seconds. Reporting `unreachable` on the first
/// failure would flicker the devices list on every hiccup.
const int _failuresBeforeUnreachable = 3;

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

  Future<void> _serve(
    PairingRecord record, {
    required int consecutiveFailures,
  }) async {
    // A blip is still "connecting" as far as the user is concerned. Only after
    // a few quick attempts have all failed is the desktop actually gone.
    onStatus?.call(
      record.verifierId,
      consecutiveFailures >= _failuresBeforeUnreachable
          ? PairedSessionStatus.unreachable
          : PairedSessionStatus.connecting,
    );
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
      rethrow;
    }
  }
}

enum PairedSessionStatus { connecting, connected, unreachable }

/// One verifier's reconnect loop.
class _Loop {
  _Loop({required this.record, required this.run});

  PairingRecord record;
  final Future<void> Function(
    PairingRecord record, {
    required int consecutiveFailures,
  })
  run;
  bool _stopped = false;
  int _failures = 0;

  Future<void> start() async {
    while (!_stopped) {
      try {
        await run(record, consecutiveFailures: _failures);
        // A session that ran to completion means the desktop is reachable,
        // whatever happened before it.
        _failures = 0;
      } on Object {
        if (_stopped) return;
        _failures++;
        await Future<void>.delayed(_delay());
      }
    }
  }

  /// Doubles from one second up to the ceiling, so a hiccup costs a second and
  /// a desktop that is switched off is dialled four times a minute.
  Duration _delay() {
    final scaled = _firstReconnectDelay * (1 << (_failures - 1).clamp(0, 8));
    return scaled > _maxReconnectDelay ? _maxReconnectDelay : scaled;
  }

  void stop() => _stopped = true;
}
