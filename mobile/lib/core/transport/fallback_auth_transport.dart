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

    final release = await _fallbackGate.acquire();
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

/// Serializes use of the plugin's one active Android GATT connection.
class _SerialGate {
  Future<void> _tail = Future.value();

  Future<void Function()> acquire() async {
    final previous = _tail;
    final released = Completer<void>();
    _tail = released.future;
    await previous;

    var didRelease = false;
    return () {
      if (didRelease) return;
      didRelease = true;
      released.complete();
    };
  }
}
