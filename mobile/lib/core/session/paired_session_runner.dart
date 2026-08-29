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
import '../ssh/native_ssh_signer.dart';
import '../ssh/ssh_service.dart';
import '../transport/auth_transport.dart';
import '../vault/vault_approval.dart';
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
    InteractiveVaultApproval? vaultApproval,
    InteractiveSshApproval? sshApproval,
    SshSigner? sshSigner,
    this.onStatus,
    DateTime Function()? clock,
  }) : _service = PairedSessionService(
         transport: transport,
         authorizer: authorizer,
         consent: consent,
         vaultApproval: vaultApproval,
         sshApproval: sshApproval,
         // The real key by default. A test passes its own; nothing else has
         // reason to, and forgetting to pass one must not silently produce a
         // runner that cannot sign.
         sshSigner: sshSigner ?? const NativeSshSigner(),
         clock: clock,
       ),
       _consent = consent,
       _vaultApproval = vaultApproval,
       _sshApproval = sshApproval;

  final PairedSessionService _service;
  final InteractiveAuthorizer _consent;

  /// Held so that stopping the runner refuses whatever sheet is still up: a
  /// session that is gone cannot be answered, and leaving the sheet tappable
  /// would let a later tap approve a request that no longer has a session.
  final InteractiveVaultApproval? _vaultApproval;
  final InteractiveSshApproval? _sshApproval;

  /// Reports connection state per verifier, for the devices list.
  final void Function(String verifierId, PairedSessionStatus status)? onStatus;

  /// Keyed by credential, not by desktop: one computer can hold a login
  /// credential and a vault one at the same time, and they are separate
  /// sessions carrying separate keys. Keyed by verifier, the second one never
  /// got a loop at all — it looked paired and answered nothing.
  final Map<String, _Loop> _loops = {};

  /// Starts a loop for every record, and stops loops for records that are gone.
  void sync(List<PairingRecord> records) {
    final wanted = {for (final record in records) record.credentialId: record};
    for (final credentialId in _loops.keys.toList()) {
      if (!wanted.containsKey(credentialId)) {
        _loops.remove(credentialId)?.stop();
      }
    }
    for (final record in records) {
      // A record that is back after a revocation is a fresh pairing, so lift
      // the refusal the revocation installed.
      _service.allowDevice(record.verifierId);
      final existing = _loops[record.credentialId];
      if (existing != null) {
        existing.record = record;
        continue;
      }
      final loop = _Loop(record: record, run: _serve);
      _loops[record.credentialId] = loop;
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
    _vaultApproval?.abandonAll();
    _sshApproval?.abandonAll();
  }

  /// Drops one verifier now, without waiting for the next [sync].
  ///
  /// Revocation needs the live session gone before the UI says it is gone, so
  /// this closes the channel rather than only marking the loop stopped — a
  /// `serveOne` already blocked on the idle timeout would otherwise stay up
  /// for minutes after the user revoked the desktop.
  Future<void> stopDevice(String verifierId) async {
    // Every credential of that desktop, because revoking a computer is not
    // "except for the vault".
    for (final entry in _loops.entries.toList()) {
      if (entry.value.record.verifierId == verifierId) {
        _loops.remove(entry.key)?.stop();
      }
    }
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
