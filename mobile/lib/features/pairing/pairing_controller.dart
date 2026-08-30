import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../app/providers.dart';
import '../../core/pairing/pairing_service.dart';
import '../../core/protocol/enrolment.dart';

/// Where a pairing attempt is.
///
/// [awaitingCode] is not an intermediate step to be skipped: without the user
/// comparing the two codes, anyone who photographed the QR could pair.
enum PairingStage { idle, connecting, awaitingCode, paired, failed }

class PairingState {
  const PairingState({
    required this.stage,
    this.verificationCode,
    this.verifierId,
    this.purpose,
    this.message,
  });

  const PairingState.idle() : this(stage: PairingStage.idle);

  final PairingStage stage;
  final String? verificationCode;
  final String? verifierId;

  /// What the credential being enrolled is for, as the desktop's code asked.
  ///
  /// Carried into the confirmation because the six digits only prove *which*
  /// computer is on the other end. What that computer will be able to ask for
  /// is the other half of the decision, and it is the half the user cannot
  /// work out from the screen otherwise.
  final CredentialPurpose? purpose;
  final String? message;

  bool get isBusy => stage == PairingStage.connecting;
}

final pairingControllerProvider =
    NotifierProvider<PairingController, PairingState>(PairingController.new);

class PairingController extends Notifier<PairingState> {
  PairingSession? _pending;
  int _attemptId = 0;

  @override
  PairingState build() => const PairingState.idle();

  /// Called once per scanned code.
  ///
  /// A camera fires the same code many times a second, so this refuses to start
  /// a second attempt while one is in flight.
  Future<void> submitScan(String raw) async {
    if (state.stage != PairingStage.idle &&
        state.stage != PairingStage.failed) {
      return;
    }
    final attemptId = ++_attemptId;
    state = const PairingState(stage: PairingStage.connecting);
    try {
      final service = await ref.read(pairingServiceProvider.future);
      final session = await service.begin(raw);
      if (attemptId != _attemptId) {
        try {
          await session.reject();
        } on Object {
          // The attempt is already cancelled; closing is best effort.
        }
        return;
      }
      _pending = session;
      state = PairingState(
        stage: PairingStage.awaitingCode,
        verificationCode: session.verificationCode,
        verifierId: session.proposed.verifierId,
        purpose: session.proposed.purpose,
      );
    } on PairingException catch (error) {
      if (attemptId == _attemptId) _fail(error.message);
    } on Object catch (error) {
      if (attemptId == _attemptId) _fail(_readable(error));
    }
  }

  /// The user says the codes match.
  Future<void> confirm() async {
    final session = _pending;
    if (session == null) return;
    final attemptId = ++_attemptId;
    _pending = null;
    try {
      await session.confirm();
      // The record is committed by now, whatever became of the attempt while
      // the write was in flight -- and "Recusar" stays on screen for all of
      // it. Refreshing the list is not a cosmetic follow-up to the success
      // state below: the session runner learns which desktops to dial from
      // this provider, so an attempt the user backed out of mid-write left a
      // desktop paired durably on both sides and dialled by neither until the
      // app was restarted. Only the screen belongs behind the staleness check.
      ref.invalidate(pairedVerifiersProvider);
      if (attemptId != _attemptId) return;
      state = PairingState(
        stage: PairingStage.paired,
        verifierId: session.proposed.verifierId,
        message: 'Pareado com ${session.proposed.verifierId}.',
      );
    } on Object catch (error) {
      if (attemptId == _attemptId) _fail(_readable(error));
    }
  }

  /// The user says they do not, or backs out.
  Future<void> reject() => _cancel();

  Future<void> reset() => _cancel();

  Future<void> _cancel() async {
    ++_attemptId;
    final session = _pending;
    _pending = null;
    state = const PairingState.idle();
    try {
      await session?.reject();
    } on Object {
      // Cancellation already won locally. A close failure must not trap the
      // user on a verification code that can no longer be acted on.
    }
  }

  void _fail(String message) {
    _pending = null;
    state = PairingState(stage: PairingStage.failed, message: message);
  }

  /// Turns a socket or handshake failure into something worth reading.
  ///
  /// Deliberately vague about *which* check failed: the spec requires a
  /// signature mismatch not to report what did not match.
  static String _readable(Object error) {
    final text = error.toString();
    if (text.contains('SocketException') ||
        text.contains('Connection refused')) {
      return 'Não foi possível conectar ao computador. '
          'Confira se ele está na mesma rede.';
    }
    if (text.contains('TimeoutException')) {
      return 'O computador não respondeu a tempo.';
    }
    return 'O pareamento falhou. Gere um novo código no computador.';
  }
}
