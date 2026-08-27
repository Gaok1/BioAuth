import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../app/providers.dart';
import '../../core/pairing/pairing_service.dart';

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
    this.message,
  });

  const PairingState.idle() : this(stage: PairingStage.idle);

  final PairingStage stage;
  final String? verificationCode;
  final String? verifierId;
  final String? message;

  bool get isBusy => stage == PairingStage.connecting;
}

final pairingControllerProvider =
    NotifierProvider<PairingController, PairingState>(PairingController.new);

class PairingController extends Notifier<PairingState> {
  PairingSession? _pending;

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
    state = const PairingState(stage: PairingStage.connecting);
    try {
      final service = await ref.read(pairingServiceProvider.future);
      final session = await service.begin(raw);
      _pending = session;
      state = PairingState(
        stage: PairingStage.awaitingCode,
        verificationCode: session.verificationCode,
        verifierId: session.proposed.verifierId,
      );
    } on PairingException catch (error) {
      _fail(error.message);
    } on Object catch (error) {
      _fail(_readable(error));
    }
  }

  /// The user says the codes match.
  Future<void> confirm() async {
    final session = _pending;
    if (session == null) return;
    _pending = null;
    await session.confirm();
    ref.invalidate(pairedVerifiersProvider);
    state = PairingState(
      stage: PairingStage.paired,
      verifierId: session.proposed.verifierId,
      message: 'Pareado com ${session.proposed.verifierId}.',
    );
  }

  /// The user says they do not, or backs out.
  Future<void> reject() async {
    final session = _pending;
    _pending = null;
    await session?.reject();
    state = const PairingState.idle();
  }

  void reset() {
    _pending = null;
    state = const PairingState.idle();
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
