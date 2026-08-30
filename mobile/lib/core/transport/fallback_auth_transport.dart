/// Uses the paired verifier over its saved LAN endpoint, then discovers BLE.
///
/// Pairing itself never falls back: a scanned QR commits to one endpoint and
/// the first-contact handshake must use exactly that bootstrap. Fallback is
/// only for a verifier whose identity key is already stored on the phone.
library;

import 'dart:async';
import 'dart:typed_data';

import 'auth_transport.dart';
import 'secure_session_establisher.dart';

class FallbackAuthTransport implements AuthTransport {
  FallbackAuthTransport({
    required AuthTransport primary,
    required AuthTransport discoveredFallback,
    this.discoveryTimeout = const Duration(seconds: 8),
    this.maxCandidates = 4,
  }) : _primary = primary,
       _fallback = discoveredFallback;

  final AuthTransport _primary;
  final AuthTransport _fallback;
  final Duration discoveryTimeout;
  final int maxCandidates;
  final _fallbackGate = _SerialGate();

  @override
  TransportSecurityProperties get securityProperties =>
      _primary.securityProperties;

  @override
  Future<void> start() async {
    await _primary.start();
    await _fallback.start();
  }

  @override
  Future<void> stop() async {
    await _fallback.stop();
    await _primary.stop();
  }

  @override
  Stream<TransportPeer> discoverPeers() => _fallback.discoverPeers();

  @override
  Future<SecureSessionOutcome> connect(
    TransportPeer peer,
    VerifierExpectation expectation,
  ) async {
    Object primaryError;
    StackTrace primaryStack;
    try {
      return await _primary.connect(peer, expectation);
    } on Object catch (error, stack) {
      primaryError = error;
      primaryStack = stack;
    }

    if (expectation is ScannedVerifier) {
      Error.throwWithStackTrace(primaryError, primaryStack);
    }

    final void Function() release;
    try {
      release = await _fallbackGate.acquire();
    } on Object catch (gateError, gateStack) {
      // Reported together with why the LAN was not used, because "Bluetooth is
      // busy" on its own does not say what was being fallen back from.
      Error.throwWithStackTrace(
        FallbackTransportException(primaryError, gateError),
        gateStack,
      );
    }
    try {
      final outcome = await _connectDiscovered(expectation);
      return SecureSessionOutcome(
        session: _ReleasingSession(outcome.session, release),
        verifierIdentitySpki: outcome.verifierIdentitySpki,
        verifierId: outcome.verifierId,
        sessionId: outcome.sessionId,
        verificationCode: outcome.verificationCode,
        wasPairing: outcome.wasPairing,
      );
    } on Object catch (fallbackError, fallbackStack) {
      release();
      Error.throwWithStackTrace(
        FallbackTransportException(primaryError, fallbackError),
        fallbackStack,
      );
    }
  }

  Future<SecureSessionOutcome> _connectDiscovered(
    VerifierExpectation expectation,
  ) async {
    final seen = <String>{};
    Object? lastError;

    for (var attempt = 0; attempt < maxCandidates; attempt++) {
      final TransportPeer candidate;
      await _fallback.start();
      try {
        candidate = await _fallback
            .discoverPeers()
            .firstWhere((peer) => !seen.contains(peer.transportId))
            .timeout(discoveryTimeout);
      } finally {
        // Android should not scan while opening a GATT connection.
        await _fallback.stop();
      }
      seen.add(candidate.transportId);

      try {
        return await _fallback.connect(candidate, expectation);
      } on Object catch (error) {
        lastError = error;
      }
    }

    throw lastError ??
        TimeoutException('Nenhum verificador PhoneAuth encontrado por BLE');
  }
}

class FallbackTransportException implements Exception {
  const FallbackTransportException(this.primaryError, this.fallbackError);

  final Object primaryError;
  final Object fallbackError;

  @override
  String toString() =>
      'Nenhum transporte alcançou o computador '
      '(rede: $primaryError; Bluetooth: $fallbackError)';
}

/// Releases the single native Android GATT client when its session closes.
class _ReleasingSession implements SecureTransportSession {
  _ReleasingSession(this._inner, this._release);

  final SecureTransportSession _inner;
  final void Function() _release;
  bool _closed = false;

  @override
  String get originLabel => _inner.originLabel;

  @override
  Uint8List get sessionBinding => _inner.sessionBinding;

  @override
  TransportSecurityProperties get securityProperties =>
      _inner.securityProperties;

  @override
  Stream<Uint8List> get incomingFrames => _inner.incomingFrames;

  @override
  Future<void> send(Uint8List frame) => _inner.send(frame);

  @override
  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    try {
      await _inner.close();
    } finally {
      _release();
    }
  }
}

/// How long a connection waits for the one before it to give the radio back.
///
/// Not a queueing policy -- it is a deadlock breaker, and it is sized to never
/// fire in normal use. A session legitimately holds the client for as long as it
/// may sit idle waiting for a request plus as long as a person may take to
/// answer one, so anything shorter would cut off working sessions. What it is
/// for is the holder that never gives it back: releasing happens after the
/// native disconnect returns, and a wedged GATT stack is a real thing on
/// Android. Without a bound that is not a slow connection, it is every future
/// Bluetooth connection on this phone hanging forever, with nothing raised and
/// nothing logged, until the app is restarted.
const _gateWait = Duration(minutes: 10);

/// Serializes use of the plugin's one active Android GATT connection.
class _SerialGate {
  Future<void> _tail = Future.value();

  Future<void Function()> acquire() async {
    final previous = _tail;
    final released = Completer<void>();
    _tail = released.future;

    var didRelease = false;
    void release() {
      if (didRelease) return;
      didRelease = true;
      released.complete();
    }

    try {
      await previous.timeout(_gateWait);
    } on TimeoutException {
      // Give up this slot on the way out, so whoever is queued behind gets the
      // same chance instead of inheriting the wedge.
      release();
      throw StateError(
        'A conexão Bluetooth anterior não foi liberada. Reinicie o aplicativo.',
      );
    }
    return release;
  }
}
