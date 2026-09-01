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
import '../locker/locker_service.dart';
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
    LockerKeyGuardian? lockerGuardian,
    Duration? answerTimeout,
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
         lockerGuardian: lockerGuardian,
         answerTimeout: answerTimeout,
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

  /// The latest status of each credential, keyed the way [_loops] is.
  ///
  /// The devices list has one row per computer, but a computer has one loop
  /// per credential and they are never in step: one is answering a request
  /// while the other is between sessions. Reported straight through, the last
  /// loop to move decided what the row said, so a connected desktop flickered
  /// to "conectando" every few minutes and a desktop whose vault credential
  /// was never paired sat on "offline" while its login session worked.
  final Map<String, PairedSessionStatus> _statuses = {};

  /// What each credential's live session has put in front of the user.
  ///
  /// Kept here rather than only in [_serve]'s local scope so that [stopDevice]
  /// can reach it. Hanging up the channel does not bring down a sheet that is
  /// waiting on a person: `_answered` only gives up when the request's own
  /// window runs out, and until then the sheet is still on screen and still
  /// tappable. Keyed the way [_loops] is, because a raised request belongs to
  /// the credential whose session raised it.
  final Map<String, Set<String>> _raised = {};

  /// Starts a loop for every record, and stops loops for records that are gone.
  void sync(List<PairingRecord> records) {
    final wanted = {for (final record in records) record.credentialId: record};
    for (final credentialId in _loops.keys.toList()) {
      if (!wanted.containsKey(credentialId)) {
        _loops.remove(credentialId)?.stop();
        _statuses.remove(credentialId);
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
    // The sets themselves, not their contents. Each is the live set its
    // session adds to as it raises requests, and the hang-up below is long
    // enough to raise one in: `closeDevice` closes one session at a time and
    // waits for each, a desktop holds one per credential, and the sessions
    // still open during that can put a request in front of the user.
    //
    // Copied here, the withdrawal covered the sheets that existed when the
    // user tapped revoke and left the ones that arrived while the revoking was
    // running -- the sheets from a desktop's last moments, still tappable, and
    // a tap on one spends a fingerprint approving something for a computer the
    // user has already revoked. Read after the await instead. `stop()` has
    // always read its pending set on that side of its own await; this is the
    // same thing, per verifier.
    final credentials = <String>{};
    final raisedByStoppedLoops = <Set<String>>[];
    for (final entry in _loops.entries.toList()) {
      if (entry.value.record.verifierId == verifierId) {
        credentials.add(entry.key);
        _loops.remove(entry.key)?.stop();
        _statuses.remove(entry.key);
        final raised = _raised.remove(entry.key);
        if (raised != null) raisedByStoppedLoops.add(raised);
      }
    }
    await _service.closeDevice(verifierId);
    final orphaned = <String>{
      for (final raised in raisedByStoppedLoops) ...raised,
    };
    // And a set installed since: a session whose teardown had not reached the
    // `finally` in `_serve` when the sweep above ran still owns its key.
    for (final credentialId in credentials) {
      orphaned.addAll(_raised.remove(credentialId) ?? const <String>{});
    }
    // The channel being gone is not the sheet being gone. A vault or ssh
    // approval waits on a person, so closing the socket underneath it leaves
    // it on screen and answerable for as long as the request's own window
    // lasts -- and a tap on it then raises the Keystore prompt and decrypts
    // the secret for a desktop the user has just revoked. Nothing would reach
    // that desktop, but the fingerprint was still spent approving it.
    _withdraw(orphaned, StateError('Dispositivo revogado'));
  }

  /// Records one credential's status and reports its computer's.
  ///
  /// A computer is reachable if any of its credentials has a live session --
  /// the phone is talking to it, whatever the others are doing -- and offline
  /// only once none of them can be. In between it is still connecting.
  void _report(PairingRecord record, PairedSessionStatus status) {
    _statuses[record.credentialId] = status;
    // Starting from this credential's own status, so a loop reporting after
    // the runner has been torn down still says something true about itself.
    var union = status;
    for (final loop in _loops.values) {
      if (loop.record.verifierId != record.verifierId) continue;
      // A credential whose loop has not reported yet is dialling.
      final each =
          _statuses[loop.record.credentialId] ?? PairedSessionStatus.connecting;
      if (_reach(each) > _reach(union)) union = each;
    }
    onStatus?.call(record.verifierId, union);
  }

  static int _reach(PairedSessionStatus status) => switch (status) {
    PairedSessionStatus.connected => 2,
    PairedSessionStatus.connecting => 1,
    PairedSessionStatus.unreachable => 0,
  };

  Future<void> _serve(
    PairingRecord record, {
    required int consecutiveFailures,
  }) async {
    // A blip is still "connecting" as far as the user is concerned. Only after
    // a few quick attempts have all failed is the desktop actually gone.
    _report(
      record,
      consecutiveFailures >= _failuresBeforeUnreachable
          ? PairedSessionStatus.unreachable
          : PairedSessionStatus.connecting,
    );
    // What this session put on screen, so the failure path below can name it.
    final raised = <String>{};
    _raised[record.credentialId] = raised;
    try {
      final response = await _service.serveOne(
        record,
        onEstablished: () => _report(record, PairedSessionStatus.connected),
        onRequestRaised: raised.add,
      );
      if (response != null) {
        _consent.settle(
          response.requestId,
          response.decision == AuthorizationDecision.authorized
              ? AuthorizationResult.approved
              : AuthorizationResult.denied,
        );
      }
    } on PairedSessionAnswerExpired catch (error) {
      // Nobody answered inside the window the desktop gave. The link is fine,
      // so this is not a failure to back off from -- it is a session that did
      // its job and found no one home. Take down what it put on screen and let
      // the loop dial again straight away.
      _withdraw(raised, error);
    } on Object catch (error) {
      // Anything left waiting on *this* session will never be answered.
      //
      // Not everything pending. There is one loop per credential and a desktop
      // can hold several, so the process-wide pending set names prompts raised
      // by other, still-healthy sessions -- and a session ending is ordinary:
      // it carries one request and closes. Abandoning the whole set meant one
      // loop's routine reconnect cancelled the prompt the user was reading,
      // and the desktop that had actually asked was told the phone failed.
      _withdraw(raised, error);
      rethrow;
    } finally {
      // Identity, not the key: the next session for this credential has
      // already installed its own set by the time a slow teardown gets here,
      // and dropping the key would leave that one unreachable from
      // [stopDevice].
      if (identical(_raised[record.credentialId], raised)) {
        _raised.remove(record.credentialId);
      }
    }
  }

  /// Refuses everything this session put in front of the user.
  ///
  /// The sheets as well as the prompts. A vault or ssh approval used to be
  /// withdrawn only when the whole runner stopped, so one whose session ended
  /// stayed pending for good -- and since a repeat of a request id waits on
  /// the answer already pending for it, the desktop's retry after reconnecting
  /// joined that dead wait instead of raising a sheet of its own.
  void _withdraw(Iterable<String> raised, Object error) {
    for (final requestId in raised) {
      _consent.abandon(requestId, error);
      _vaultApproval?.abandon(requestId);
      _sshApproval?.settle(requestId, approved: false);
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
